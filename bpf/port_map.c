// port mapping for inbound ipv4 tcp and udp traffic.
//
// exact destination mappings take precedence over wildcard host ports.
// after dnat, xdp passes the packet to the kernel for normal routing.
// ipv4 options and fragments are left unchanged because the transport
// header is not always present at the fixed offset used here.

#include "common.h"

// xdp action used by this program
#define XDP_PASS 2

// xdp context; field order follows the kernel abi
struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

// port mapping key
struct port_key {
    __u32 dst_ip;    // destination ip to match (network byte order), 0 = wildcard
    __u16 port;      // host port (network byte order)
    __u8 protocol;   // IPPROTO_TCP or IPPROTO_UDP
    __u8 _pad;
};

// port mapping value
struct port_target {
    __u32 dst_ip;    // container ip (network byte order)
    __u16 dst_port;  // container port (network byte order)
    __u16 _pad;
};

struct bpf_map_def SEC("maps") port_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct port_key),
    .value_size = sizeof(struct port_target),
    .max_entries = 1024,
    .map_flags = 0,
};

// xdp has no checksum replacement helpers. update the affected words
// directly, using the same byte order as the checksum field.
static __attribute__((always_inline)) __u16
csum_fold(__u32 csum)
{
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    return (__u16)~csum;
}

static __attribute__((always_inline)) __u16
update_csum(__u16 csum, __u32 old_val, __u32 new_val)
{
    __u32 s = (~((__u32)csum) & 0xFFFF);
    s += (~old_val & 0xFFFF) + (new_val & 0xFFFF);
    s += (~(old_val >> 16) & 0xFFFF) + (new_val >> 16);
    return csum_fold(s);
}

static __attribute__((always_inline)) __u16
update_csum16(__u16 csum, __u16 old_val, __u16 new_val)
{
    __u32 s = (~((__u32)csum) & 0xFFFF);
    s += (~((__u32)old_val) & 0xFFFF) + ((__u32)new_val);
    return csum_fold(s);
}

SEC("xdp")
int xdp_port_map(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // require ipv4 without options and a complete, unfragmented datagram.
    if (ip->ihl_version != 0x45 || (ip->frag_off & htons(IPV4_FRAGMENT_MASK)))
        return XDP_PASS;

    __u16 ip_len = ntohs(ip->tot_len);
    __u32 available_ip_len = (char *)data_end - (char *)ip;
    if (ip_len < sizeof(*ip) || ip_len > available_ip_len)
        return XDP_PASS;

    if (ip->ttl == 0)
        return XDP_PASS;

    __u32 src_ip = ntohl(ip->saddr);
    if (src_ip == 0 || src_ip == 0xffffffff ||
        (src_ip & 0xf0000000) == 0xe0000000 ||
        (src_ip & 0xff000000) == 0x7f000000)
        return XDP_PASS;

    // build the lookup key only after validating the transport header
    struct port_key key = {};
    key.dst_ip = ip->daddr;
    key.protocol = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((char *)ip + sizeof(*ip));
        if (ip_len < sizeof(*ip) + sizeof(*tcp) || (void *)(tcp + 1) > data_end)
            return XDP_PASS;
        __u16 tcp_len = (ntohs(tcp->flags) >> 12) * 4;
        if (tcp_len < sizeof(*tcp) || tcp_len > ip_len - sizeof(*ip))
            return XDP_PASS;
        key.port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)((char *)ip + sizeof(*ip));
        if (ip_len < sizeof(*ip) + sizeof(*udp) || (void *)(udp + 1) > data_end)
            return XDP_PASS;
        __u16 udp_len = ntohs(udp->len);
        if (udp_len < sizeof(*udp) || udp_len > ip_len - sizeof(*ip))
            return XDP_PASS;
        key.port = udp->dest;
    } else {
        return XDP_PASS;
    }

    // look up exact destination mapping first
    struct port_target *target = bpf_map_lookup_elem(&port_map, &key);
    if (!target) {
        key.dst_ip = 0;
        target = bpf_map_lookup_elem(&port_map, &key);
        if (!target)
            return XDP_PASS;
    }

    __u32 new_daddr = target->dst_ip;
    __u16 new_port = target->dst_port;
    if (new_daddr == 0 || new_daddr == 0xffffffff || new_port == 0)
        return XDP_PASS;

    __u32 old_daddr = ip->daddr;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((char *)ip + sizeof(*ip));
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        __u16 old_port = tcp->dest;
        tcp->dest = new_port;
        __u16 checksum = update_csum(tcp->check, old_daddr, new_daddr);
        tcp->check = update_csum16(checksum, old_port, new_port);
    } else {
        struct udphdr *udp = (void *)((char *)ip + sizeof(*ip));
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        __u16 old_port = udp->dest;
        udp->dest = new_port;
        // a zero ipv4 udp checksum means disabled. preserve that choice;
        // a calculated zero checksum is transmitted as all ones instead.
        if (udp->check != 0) {
            __u16 checksum = update_csum(udp->check, old_daddr, new_daddr);
            checksum = update_csum16(checksum, old_port, new_port);
            udp->check = checksum == 0 ? 0xffff : checksum;
        }
    }

    ip->daddr = new_daddr;
    ip->check = update_csum(ip->check, old_daddr, new_daddr);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
