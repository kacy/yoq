// packet and payload-byte counters for bridge ingress.
//
// source counters include all valid ipv4 traffic. tcp pair counters also
// track connection attempts and resets. this observer leaves packets alone
// and returns tc_act_unspec so later filters can run.

#include "common.h"

// -- source counters --

struct ip_metrics {
    __u64 packets;
    __u64 bytes;
};

// -- tcp pair counters --

struct pair_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 dst_port;
    __u16 pad;
}; // 12 bytes

struct pair_metrics {
    __u64 packets;
    __u64 bytes;
    __u64 connections;
    __u64 errors;
}; // 32 bytes

// -- maps --

// map order and layouts must match the userspace metrics collector.
struct bpf_map_def SEC("maps") metrics_map = {
    .type        = BPF_MAP_TYPE_LRU_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct ip_metrics),
    .max_entries = 1024,
    .map_flags   = 0,
};

// map 1: per-pair counters (src_ip, dst_ip, dst_port)
struct bpf_map_def SEC("maps") pair_metrics_map = {
    .type        = BPF_MAP_TYPE_LRU_HASH,
    .key_size    = sizeof(struct pair_key),
    .value_size  = sizeof(struct pair_metrics),
    .max_entries = 4096,
    .map_flags   = 0,
};

static __inline __attribute__((always_inline)) void count_source(__u32 src_ip, __u32 payload_bytes)
{
    struct ip_metrics *metrics = bpf_map_lookup_elem(&metrics_map, &src_ip);
    if (!metrics) {
        // another cpu may create this key between lookup and insertion.
        struct ip_metrics empty = {};
        bpf_map_update_elem(&metrics_map, &src_ip, &empty, BPF_NOEXIST);
        metrics = bpf_map_lookup_elem(&metrics_map, &src_ip);
        if (!metrics)
            return;
    }

    __sync_fetch_and_add(&metrics->packets, 1);
    __sync_fetch_and_add(&metrics->bytes, payload_bytes);
}

static __inline __attribute__((always_inline)) void count_pair(const struct pair_key *key,
                               __u32 payload_bytes, __u16 tcp_flags)
{
    struct pair_metrics *metrics = bpf_map_lookup_elem(&pair_metrics_map, key);
    if (!metrics) {
        struct pair_metrics empty = {};
        bpf_map_update_elem(&pair_metrics_map, key, &empty, BPF_NOEXIST);
        metrics = bpf_map_lookup_elem(&pair_metrics_map, key);
        if (!metrics)
            return;
    }

    __sync_fetch_and_add(&metrics->packets, 1);
    __sync_fetch_and_add(&metrics->bytes, payload_bytes);

    // a syn without ack starts a connection; a reset counts as an error.
    if ((tcp_flags & 0x12) == 0x02)
        __sync_fetch_and_add(&metrics->connections, 1);
    if (tcp_flags & 0x04)
        __sync_fetch_and_add(&metrics->errors, 1);
}

SEC("tc_ingress")
int metrics_count(struct __sk_buff *skb)
{
    void *data     = (void *)(__u64)skb->data;
    void *data_end = (void *)(__u64)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_UNSPEC;
    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_UNSPEC;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_UNSPEC;
    if ((iph->ihl_version >> 4) != 4 || iph->ttl == 0)
        return TC_ACT_UNSPEC;

    __u32 ip_header_len = (iph->ihl_version & 0x0f) * 4;
    if (ip_header_len < sizeof(*iph))
        return TC_ACT_UNSPEC;
    if ((void *)iph + ip_header_len > data_end)
        return TC_ACT_UNSPEC;

    // skb->len includes payload stored outside the linear packet buffer.
    __u32 ip_total_len = ntohs(iph->tot_len);
    if (ip_total_len < ip_header_len || sizeof(*eth) + ip_total_len > skb->len)
        return TC_ACT_UNSPEC;
    __u32 payload_bytes = ip_total_len - ip_header_len;
    count_source(iph->saddr, payload_bytes);

    // fragments cannot reliably identify a complete transport header.
    if (iph->protocol != IPPROTO_TCP ||
        (ntohs(iph->frag_off) & IPV4_FRAGMENT_MASK))
        return TC_ACT_UNSPEC;
    if (payload_bytes < sizeof(struct tcphdr))
        return TC_ACT_UNSPEC;

    struct tcphdr *tcp = (void *)iph + ip_header_len;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_UNSPEC;
    __u16 tcp_flags = ntohs(tcp->flags);
    __u32 tcp_header_len = (tcp_flags >> 12) * 4;
    if (tcp_header_len < sizeof(*tcp) || tcp_header_len > payload_bytes)
        return TC_ACT_UNSPEC;
    if ((void *)tcp + tcp_header_len > data_end)
        return TC_ACT_UNSPEC;

    struct pair_key key = {
        .src_ip   = iph->saddr,
        .dst_ip   = iph->daddr,
        .dst_port = tcp->dest,
        .pad      = 0,
    };
    count_pair(&key, payload_bytes, tcp_flags);
    return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
