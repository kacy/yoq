// metrics.c — per-IP packet and byte counters
//
// attached to the bridge ingress at priority 2 (after DNS interceptor
// and load balancer). counts packets and bytes per source IP using an
// LRU hash map. always returns TC_ACT_OK — this is a passive observer
// that never drops or modifies packets.
//
// the userspace MetricsCollector reads the map to report per-container
// traffic stats via `yoq metrics`.
//
// compile with:
//   clang -target bpf -O2 -g -c bpf/metrics.c -o bpf/metrics.o

#include "common.h"

// -- per-IP metrics value --

struct ip_metrics {
    __u64 packets;
    __u64 bytes;
};

// -- BPF map --
//
// LRU hash: source IP (u32, network order) → ip_metrics.
// LRU automatically evicts cold entries when full, so we don't
// need to worry about cleanup for short-lived containers.

struct bpf_map_def SEC("maps") metrics_map = {
    .type        = BPF_MAP_TYPE_LRU_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct ip_metrics),
    .max_entries = 1024,
    .map_flags   = 0,
};

// -- TC ingress program --

SEC("tc_ingress")
int metrics_count(struct __sk_buff *skb)
{
    void *data     = (void *)(__u64)skb->data;
    void *data_end = (void *)(__u64)skb->data_end;

    // parse ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // only count IPv4 packets
    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    // parse IP header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    // key is source IP in network byte order
    __u32 src_ip = iph->saddr;

    // calculate IP payload size (total length from IP header)
    __u64 pkt_bytes = ntohs(iph->tot_len);

    // look up existing entry or create a new one
    struct ip_metrics *existing = bpf_map_lookup_elem(&metrics_map, &src_ip);
    if (existing) {
        // atomically increment counters
        __sync_fetch_and_add(&existing->packets, 1);
        __sync_fetch_and_add(&existing->bytes, pkt_bytes);
    } else {
        // first packet from this IP — create entry
        struct ip_metrics new_entry = {
            .packets = 1,
            .bytes   = pkt_bytes,
        };
        bpf_map_update_elem(&metrics_map, &src_ip, &new_entry, 0);
    }

    return TC_ACT_OK;
}
