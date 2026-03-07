// port_map — eBPF XDP port mapping
//
// XDP program that rewrites destination IP and port for inbound
// traffic based on a port mapping table. replaces iptables DNAT
// rules for container port forwarding.
//
// key: {protocol, port} -> value: {dst_ip, dst_port}
//
// uses XDP_FLAGS_SKB_MODE for compatibility with virtual interfaces.
// after rewriting, returns XDP_PASS to let the kernel route the
// packet to the correct bridge/veth via normal forwarding.
//
// SECURITY HARDENING:
//   - All packet accesses validated against data_end
//   - IP header length (IHL) validated before use
//   - Checksum calculations protected against overflow
//   - Maximum packet size enforced
//
// BPF verifier constraints:
//   - IHL forced to 5 (no IP options) for fixed-offset access
//   - all packet access uses constant offsets
//
// compile: clang -target bpf -O2 -g -c -o port_map.o port_map.c

#include "common.h"

// XDP return codes
#define XDP_ABORTED 0
#define XDP_DROP    1
#define XDP_PASS    2
#define XDP_TX      3

// XDP context (different from __sk_buff)
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
    __u16 port;      // host port (network byte order)
    __u8 protocol;   // IPPROTO_TCP or IPPROTO_UDP
    __u8 _pad;
};

// port mapping value
struct port_target {
    __u32 dst_ip;    // container IP (network byte order)
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

// XDP doesn't have bpf_l3_csum_replace / bpf_l4_csum_replace.
// we need to compute checksums manually.
static __attribute__((always_inline)) __u16
csum_fold(__u32 csum)
{
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    return (__u16)~csum;
}

static __attribute__((always_inline)) void
update_csum(__u16 *csum, __u32 old_val, __u32 new_val)
{
    // SECURITY: Ensure csum pointer is valid before dereferencing
    if (!csum) return;
    
    __u32 s = (~((__u32)*csum) & 0xFFFF);
    s += (~old_val & 0xFFFF) + (new_val & 0xFFFF);
    s += (~(old_val >> 16) & 0xFFFF) + (new_val >> 16);
    *csum = csum_fold(s);
}

static __attribute__((always_inline)) void
update_csum16(__u16 *csum, __u16 old_val, __u16 new_val)
{
    // SECURITY: Ensure csum pointer is valid before dereferencing
    if (!csum) return;
    
    __u32 s = (~((__u32)*csum) & 0xFFFF);
    s += (~((__u32)old_val) & 0xFFFF) + ((__u32)new_val);
    *csum = csum_fold(s);
}

SEC("xdp")
int xdp_port_map(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // SECURITY: Enforce reasonable packet size limits
    __u32 pkt_len = (long)data_end - (long)data;
    if (pkt_len < 60 || pkt_len > 1500) // Min: eth+ip+tcp/udp headers, Max: typical MTU
        return XDP_PASS;

    // parse ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    // parse IP
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // SECURITY: Validate IP total length
    __u16 ip_tot_len = ntohs(ip->tot_len);
    if (ip_tot_len < 40 || ip_tot_len > 1500)
        return XDP_PASS;

    // require IHL=5 (no options) for fixed-offset transport header access
    __u8 ihl = ip->ihl_version & 0x0F;
    if (ihl != 5)
        return XDP_PASS;

    // extract destination port and protocol
    struct port_key key = {};
    key.protocol = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((char *)ip + 20);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)((char *)ip + 20);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        key.port = udp->dest;
    } else {
        return XDP_PASS;
    }

    // look up port mapping
    struct port_target *target = bpf_map_lookup_elem(&port_map, &key);
    if (!target)
        return XDP_PASS;

    // SECURITY: Validate target IP is not 0.0.0.0 or broadcast
    if (target->dst_ip == 0 || target->dst_ip == 0xFFFFFFFF)
        return XDP_PASS;
    
    // SECURITY: Validate target port is valid (1-65535)
    if (target->dst_port == 0)
        return XDP_PASS;

    // rewrite destination IP
    __u32 old_daddr = ip->daddr;
    ip->daddr = target->dst_ip;

    // update IP checksum (incremental, inline — no helper call)
    update_csum(&ip->check, old_daddr, target->dst_ip);

    // rewrite destination port and update L4 checksum
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((char *)ip + 20);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        __u16 old_port = tcp->dest;
        tcp->dest = target->dst_port;
        // update TCP checksum for IP change and port change
        update_csum(&tcp->check, old_daddr, target->dst_ip);
        update_csum16(&tcp->check, old_port, target->dst_port);
    } else {
        struct udphdr *udp = (void *)((char *)ip + 20);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        udp->dest = target->dst_port;
        // UDP checksum is optional for IPv4 -- zero it
        udp->check = 0;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
