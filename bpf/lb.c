// lb — eBPF round-robin load balancer
//
// TC program for distributing traffic across multiple backends
// registered under the same service name. works in tandem with
// the DNS interceptor — DNS resolves a service name to a virtual
// IP (the first backend), and this program distributes connections
// across all backends via DNAT.
//
// two hooks:
//   TC ingress on yoq0: intercept new connections to service IPs,
//     select a backend via round-robin, DNAT to backend IP.
//   TC egress on yoq0: reverse NAT for return traffic (SNAT
//     backend IP back to service VIP).
//
// connection tracking ensures that all packets in a flow go to
// the same backend (connection affinity).
//
// compile: clang -target bpf -O2 -g -c -o lb.o lb.c

#include "common.h"

// -- BPF maps --

// service backends: service VIP (virtual IP) → list of backend IPs.
// key: 4-byte IPv4 address (the service's VIP / first backend IP)
// value: struct with count + up to 16 backend IPs
struct service_backends {
    __u32 count;
    __u32 ips[16]; // network byte order
};

struct bpf_map_def SEC("maps") backends_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 4,
    .value_size = sizeof(struct service_backends),
    .max_entries = 256,
    .map_flags = 0,
};

// connection tracking: 5-tuple → selected backend IP.
// ensures all packets in a flow go to the same backend.
// uses LRU hash to auto-evict old connections.
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
    .value_size = 4, // backend IP (network byte order)
    .max_entries = 65536,
    .map_flags = 0,
};

// round-robin counter: single-element array for atomic increment.
struct bpf_map_def SEC("maps") rr_counter = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = 4,
    .value_size = 4,
    .max_entries = 1,
    .map_flags = 0,
};

// reverse conntrack: maps return-traffic tuples → original VIP.
// populated on ingress alongside the forward conntrack entry.
// key: reversed 5-tuple (backend=src, client=dst) matching return traffic.
// value: original service VIP (u32, network byte order).
struct bpf_map_def SEC("maps") rev_conntrack_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct conn_key),
    .value_size = 4,
    .max_entries = 65536,
    .map_flags = 0,
};

// -- helpers --

// select a backend IP for a service using round-robin.
// returns the backend IP in network byte order, or 0 on failure.
static __attribute__((always_inline)) __u32
select_backend(struct service_backends *svc)
{
    if (svc->count == 0 || svc->count > 16)
        return 0;

    // if only one backend, skip the counter
    if (svc->count == 1)
        return svc->ips[0];

    // atomic increment of round-robin counter
    __u32 zero = 0;
    __u32 *counter = bpf_map_lookup_elem(&rr_counter, &zero);
    if (!counter)
        return svc->ips[0]; // fallback to first

    __sync_fetch_and_add(counter, 1);
    __u32 idx = *counter % svc->count;
    return svc->ips[idx];
}

SEC("tc_ingress")
int lb_ingress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // -- parse headers --
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    __u8 ihl = (ip->ihl_version & 0x0F) * 4;
    if (ihl < 20)
        return TC_ACT_OK;

    // only handle TCP and UDP
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    // extract ports based on protocol
    __u16 src_port = 0, dst_port = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((char *)ip + ihl);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        src_port = tcp->source;
        dst_port = tcp->dest;
    } else {
        struct udphdr *udp = (void *)((char *)ip + ihl);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        // skip DNS queries (port 53) — handled by dns_intercept
        if (udp->dest == htons(53))
            return TC_ACT_OK;
        src_port = udp->source;
        dst_port = udp->dest;
    }

    // -- check if dst IP is a service VIP --
    struct service_backends *svc = bpf_map_lookup_elem(&backends_map, &ip->daddr);
    if (!svc)
        return TC_ACT_OK; // not a service IP

    // -- connection tracking --
    struct conn_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = ip->protocol,
    };

    __u32 *existing = bpf_map_lookup_elem(&conntrack_map, &key);
    __u32 backend_ip;

    if (existing) {
        // existing connection — use the same backend
        backend_ip = *existing;
    } else {
        // new connection — select a backend
        backend_ip = select_backend(svc);
        if (backend_ip == 0)
            return TC_ACT_OK;

        // store in conntrack for future packets
        bpf_map_update_elem(&conntrack_map, &key, &backend_ip, 0);
    }

    // -- DNAT: rewrite dst IP to backend --
    if (backend_ip == ip->daddr)
        return TC_ACT_OK; // already pointing at the right backend

    __u32 old_daddr = ip->daddr;
    ip->daddr = backend_ip;

    // update IP checksum (incremental)
    bpf_l3_csum_replace(skb, (char *)&ip->check - (char *)data,
                        old_daddr, backend_ip, 4);

    // update L4 checksum (TCP/UDP both have checksum in same relative position concept)
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((char *)ip + ihl);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        bpf_l4_csum_replace(skb, (char *)&tcp->check - (char *)data,
                            old_daddr, backend_ip, 4 | 0x10);
    } else {
        struct udphdr *udp = (void *)((char *)ip + ihl);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        // UDP checksum is optional for IPv4 — zero it
        udp->check = 0;
    }

    // populate reverse conntrack for egress SNAT.
    // the reverse key matches what return traffic from the backend
    // will look like: src=backend, dst=client.
    struct conn_key rev_key = {
        .src_ip = backend_ip,     // return traffic src = backend
        .dst_ip = ip->saddr,      // return traffic dst = client (unchanged)
        .src_port = dst_port,     // return traffic src_port = service port
        .dst_port = src_port,     // return traffic dst_port = client port
        .protocol = ip->protocol,
    };
    __u32 vip = old_daddr;        // the original VIP before DNAT
    bpf_map_update_elem(&rev_conntrack_map, &rev_key, &vip, 0);

    return TC_ACT_OK;
}

SEC("tc_egress")
int lb_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // -- parse headers --
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    __u8 ihl = (ip->ihl_version & 0x0F) * 4;
    if (ihl < 20)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    __u16 src_port = 0, dst_port = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((char *)ip + ihl);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        src_port = tcp->source;
        dst_port = tcp->dest;
    } else {
        struct udphdr *udp = (void *)((char *)ip + ihl);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        src_port = udp->source;
        dst_port = udp->dest;
    }

    // -- reverse conntrack lookup --
    // look up the reverse conntrack map to find the original VIP.
    // the key matches the return traffic tuple exactly as populated
    // by lb_ingress after DNAT.
    struct conn_key rev_key = {
        .src_ip = ip->saddr,      // backend IP (source in return traffic)
        .dst_ip = ip->daddr,      // client IP (destination in return traffic)
        .src_port = src_port,     // service port
        .dst_port = dst_port,     // client port
        .protocol = ip->protocol,
    };

    __u32 *vip = bpf_map_lookup_elem(&rev_conntrack_map, &rev_key);
    if (!vip)
        return TC_ACT_OK; // not a tracked connection

    // SNAT: rewrite source IP from backend back to VIP
    if (*vip == ip->saddr)
        return TC_ACT_OK; // already correct, nothing to do

    __u32 old_saddr = ip->saddr;
    ip->saddr = *vip;

    // update IP checksum (incremental)
    bpf_l3_csum_replace(skb, (char *)&ip->check - (char *)data,
                        old_saddr, *vip, 4);

    // update L4 checksum
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((char *)ip + ihl);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        bpf_l4_csum_replace(skb, (char *)&tcp->check - (char *)data,
                            old_saddr, *vip, 4 | 0x10);
    } else {
        struct udphdr *udp = (void *)((char *)ip + ihl);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        // UDP checksum is optional for IPv4 — zero it
        udp->check = 0;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
