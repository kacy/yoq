// service load balancing at tc ingress, with reverse nat at tc egress.
//
// a source-address hash chooses a backend for each new flow. conntrack
// keeps the choice stable and records the service address for replies.
// both directions leave ipv4 options and fragments unchanged.

#include "common.h"

// service backends: service vip (virtual ip) → list of backend ips.
// key: 4-byte ipv4 address (the service's vip / first backend ip)
// value: struct with count + up to 64 backend ips
struct service_backends {
    __u32 count;
    __u32 ips[64]; // network byte order
};

struct bpf_map_def SEC("maps") backends_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 4,
    .value_size = sizeof(struct service_backends),
    .max_entries = 256,
    .map_flags = 0,
};

// connection tracking: 5-tuple → selected backend ip.
// ensures all packets in a flow go to the same backend.
// uses lru hash to auto-evict old connections.
struct conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 _pad[3];
};

struct bpf_map_def SEC("maps") conntrack_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct conn_key),
    .value_size = 4, // backend ip (network byte order)
    .max_entries = 65536,
    .map_flags = 0,
};

// reverse conntrack: maps return-traffic tuples → original vip.
// populated on ingress alongside the forward conntrack entry.
// key: reversed 5-tuple (backend=src, client=dst) matching return traffic.
// value: original service vip (u32, network byte order).
struct bpf_map_def SEC("maps") rev_conntrack_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct conn_key),
    .value_size = 4,
    .max_entries = 65536,
    .map_flags = 0,
};

// hash the client address so it returns to the same backend while the
// backend list stays unchanged, even after its conntrack entry is evicted.
// changing the list can move clients; this is not consistent hashing.
static __attribute__((always_inline)) __u32
select_backend(__u32 src_ip, struct service_backends *svc)
{
    __u32 count = svc->count;
    if (count == 0 || count > 64)
        return 0;

    if (count == 1)
        return svc->ips[0];

    // fnv-1a hash of source ip
    __u32 hash = 2166136261U;
    hash ^= (src_ip & 0xFF);
    hash *= 16777619U;
    hash ^= ((src_ip >> 8) & 0xFF);
    hash *= 16777619U;
    hash ^= ((src_ip >> 16) & 0xFF);
    hash *= 16777619U;
    hash ^= ((src_ip >> 24) & 0xFF);
    hash *= 16777619U;

    __u32 idx = hash % count;
    // clang can prove the remainder is below 64 and otherwise removes the
    // mask. the kernel verifier needs this explicit bound after variable modulo.
    asm volatile("" : "+r"(idx));
    idx &= 0x3F;
    return svc->ips[idx];
}

// fixed offsets for ethernet followed by an ipv4 header without options.
#define IP_CSUM_OFF  24
#define TCP_CSUM_OFF 50
#define UDP_CSUM_OFF 40

// only the headers need to be linear in an skb. use skb->len to check
// the declared datagram length, and data_end for each header we access.
static __attribute__((always_inline)) struct iphdr *
parse_flow(struct __sk_buff *skb, struct conn_key *key)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != htons(ETH_P_IP))
        return 0;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;
    if (ip->ihl_version != 0x45 || (ip->frag_off & htons(IPV4_FRAGMENT_MASK)))
        return 0;

    __u16 ip_len = ntohs(ip->tot_len);
    if (skb->len < sizeof(*eth) || ip_len < sizeof(*ip) ||
        ip_len > skb->len - sizeof(*eth) || ip->ttl == 0)
        return 0;

    __u32 src_ip = ntohl(ip->saddr);
    if (src_ip == 0 || src_ip == 0xffffffff ||
        (src_ip & 0xf0000000) == 0xe0000000 ||
        (src_ip & 0xff000000) == 0x7f000000)
        return 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((char *)ip + sizeof(*ip));
        if (ip_len < sizeof(*ip) + sizeof(*tcp) || (void *)(tcp + 1) > data_end)
            return 0;
        __u16 tcp_len = (ntohs(tcp->flags) >> 12) * 4;
        if (tcp_len < sizeof(*tcp) || tcp_len > ip_len - sizeof(*ip))
            return 0;
        key->src_port = tcp->source;
        key->dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)((char *)ip + sizeof(*ip));
        if (ip_len < sizeof(*ip) + sizeof(*udp) || (void *)(udp + 1) > data_end)
            return 0;
        __u16 udp_len = ntohs(udp->len);
        if (udp_len < sizeof(*udp) || udp_len > ip_len - sizeof(*ip))
            return 0;
        key->src_port = udp->source;
        key->dst_port = udp->dest;
    } else {
        return 0;
    }

    key->src_ip = ip->saddr;
    key->dst_ip = ip->daddr;
    key->protocol = ip->protocol;
    return ip;
}

// checksum helpers can invalidate packet pointers. callers must finish
// reading and writing packet headers before calling this function.
static __attribute__((always_inline)) int
update_address_checksums(struct __sk_buff *skb, __u8 protocol,
                         __u32 old_address, __u32 new_address)
{
    if (bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_address, new_address, 4) < 0)
        return TC_ACT_SHOT;

    __u32 offset = TCP_CSUM_OFF;
    __u64 flags = 4 | BPF_F_PSEUDO_HDR;
    if (protocol == IPPROTO_UDP) {
        offset = UDP_CSUM_OFF;
        // preserve disabled udp checksums and encode a calculated zero
        // as 0xffff, as required for ipv4 udp.
        flags |= BPF_F_MARK_MANGLED_0;
    }
    if (bpf_l4_csum_replace(skb, offset, old_address, new_address, flags) < 0)
        return TC_ACT_SHOT;
    return TC_ACT_UNSPEC;
}

SEC("tc_ingress")
int lb_ingress(struct __sk_buff *skb)
{
    struct conn_key key = {};
    struct iphdr *ip = parse_flow(skb, &key);
    if (!ip)
        return TC_ACT_UNSPEC;

    // dns queries are handled by the dns interceptor.
    if (key.protocol == IPPROTO_UDP && key.dst_port == htons(53))
        return TC_ACT_UNSPEC;

    struct service_backends *svc = bpf_map_lookup_elem(&backends_map, &key.dst_ip);
    if (!svc)
        return TC_ACT_UNSPEC;
    if (svc->count == 0)
        return TC_ACT_SHOT;

    __u32 backend_ip;
    __u32 *existing = bpf_map_lookup_elem(&conntrack_map, &key);
    if (existing) {
        backend_ip = *existing;
    } else {
        backend_ip = select_backend(key.src_ip, svc);
        if (backend_ip == 0)
            return TC_ACT_SHOT;

        // another cpu may have created this flow after our lookup. keep
        // its choice rather than replacing it with a newly selected backend.
        if (bpf_map_update_elem(&conntrack_map, &key, &backend_ip, BPF_NOEXIST) < 0) {
            existing = bpf_map_lookup_elem(&conntrack_map, &key);
            if (!existing)
                return TC_ACT_SHOT;
            backend_ip = *existing;
        }
    }

    struct conn_key reverse_key = {
        .src_ip = backend_ip,
        .dst_ip = key.src_ip,
        .src_port = key.dst_port,
        .dst_port = key.src_port,
        .protocol = key.protocol,
        ._pad = {0, 0, 0},
    };

    // establish the reply mapping before forwarding. two service addresses
    // can otherwise select the same backend tuple and overwrite each other's
    // return address. a conflicting flow must be dropped, even when this
    // packet's destination already equals the backend address.
    __u32 *existing_vip = bpf_map_lookup_elem(&rev_conntrack_map, &reverse_key);
    if (!existing_vip) {
        if (bpf_map_update_elem(&rev_conntrack_map, &reverse_key, &key.dst_ip,
                                BPF_NOEXIST) < 0) {
            existing_vip = bpf_map_lookup_elem(&rev_conntrack_map, &reverse_key);
            if (!existing_vip || *existing_vip != key.dst_ip)
                return TC_ACT_SHOT;
        }
    } else if (*existing_vip != key.dst_ip) {
        return TC_ACT_SHOT;
    }

    if (backend_ip == key.dst_ip)
        return TC_ACT_UNSPEC;

    ip->daddr = backend_ip;
    return update_address_checksums(skb, key.protocol, key.dst_ip, backend_ip);
}

SEC("tc_egress")
int lb_egress(struct __sk_buff *skb)
{
    struct conn_key key = {};
    struct iphdr *ip = parse_flow(skb, &key);
    if (!ip)
        return TC_ACT_UNSPEC;

    __u32 *vip = bpf_map_lookup_elem(&rev_conntrack_map, &key);
    if (!vip || *vip == key.src_ip)
        return TC_ACT_UNSPEC;

    __u32 service_ip = *vip;
    ip->saddr = service_ip;
    return update_address_checksums(skb, key.protocol, key.src_ip, service_ip);
}

char _license[] SEC("license") = "GPL";
