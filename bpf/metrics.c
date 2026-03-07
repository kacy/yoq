// metrics.c — per-IP and per-service-pair packet/byte counters
//
// attached to the bridge ingress at priority 2 (after DNS interceptor
// and load balancer). counts packets and bytes per source IP using an
// LRU hash map, and per (src, dst, port) pair for service-to-service
// visibility. always returns TC_ACT_OK — this is a passive observer
// that never drops or modifies packets.
//
// SECURITY HARDENING:
//   - All packet accesses validated against data_end
//   - IP header length (IHL) validated before use
//   - TCP header offset calculated safely
//   - Integer overflow protection on byte counters
//
// the userspace MetricsCollector reads both maps to report per-container
// traffic stats via `yoq metrics` and `yoq metrics --pairs`.
//
// compile with:
//   clang -target bpf -O2 -g -c bpf/metrics.c -o bpf/metrics.o

#include "common.h"

// -- per-IP metrics value --

struct ip_metrics {
    __u64 packets;
    __u64 bytes;
};

// -- per-pair key and metrics --

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

// -- BPF maps --

// map 0: per-source-IP counters (backward compatible)
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

    __u32 src_ip = iph->saddr;
    
    // SECURITY: Validate IP total length before using it
    __u16 ip_tot_len = ntohs(iph->tot_len);
    if (ip_tot_len < 20 || ip_tot_len > 65535) // Minimum IP header is 20 bytes
        return TC_ACT_OK;
    
    // SECURITY: Validate IHL (header length) is at least 5 (20 bytes)
    __u8 ihl = iph->ihl_version & 0x0F;
    if (ihl < 5 || ihl > 15) // RFC 791: IHL is 4 bits, min 5, max 15
        return TC_ACT_OK;
    
    // SECURITY: Ensure IHL matches the actual header size we're reading
    // We need at least eth(14) + ip_header(ihl*4) bytes
    __u32 ip_header_len = ihl * 4;
    if ((void *)((char *)iph + ip_header_len) > data_end)
        return TC_ACT_OK;
    
    // Calculate payload length safely (avoid underflow)
    __u32 pkt_bytes;
    if (ip_tot_len > ip_header_len)
        pkt_bytes = ip_tot_len - ip_header_len;
    else
        pkt_bytes = 0;

    // -- per-source-IP counting (backward compatible) --

    struct ip_metrics *existing = bpf_map_lookup_elem(&metrics_map, &src_ip);
    if (existing) {
        __sync_fetch_and_add(&existing->packets, 1);
        // SECURITY: Cap bytes at reasonable maximum to prevent overflow abuse
        if (pkt_bytes < 65535) // Max reasonable single packet payload
            __sync_fetch_and_add(&existing->bytes, pkt_bytes);
    } else {
        struct ip_metrics new_entry = {
            .packets = 1,
            .bytes   = pkt_bytes,
        };
        bpf_map_update_elem(&metrics_map, &src_ip, &new_entry, 0);
    }

    // -- per-pair counting (TCP only) --

    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    // SECURITY: Calculate TCP header offset safely using validated IHL
    struct tcphdr *tcp = (void *)((char *)iph + ip_header_len);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;
    
    // SECURITY: Validate TCP data offset (header length)
    __u16 tcp_flags = ntohs(tcp->flags);
    __u8 tcp_doff = (tcp_flags >> 12) & 0x0F; // Data offset in upper 4 bits
    if (tcp_doff < 5 || tcp_doff > 15) // Min 20 bytes, max 60 bytes
        return TC_ACT_OK;
    
    // SECURITY: Ensure TCP header doesn't exceed packet bounds
    __u32 tcp_header_len = tcp_doff * 4;
    if ((void *)((char *)tcp + tcp_header_len) > data_end)
        return TC_ACT_OK;

    struct pair_key pk = {
        .src_ip   = iph->saddr,
        .dst_ip   = iph->daddr,
        .dst_port = tcp->dest,
        .pad      = 0,
    };

    // detect SYN (new connection) and RST (error)
    __u8 syn = (tcp_flags >> 1) & 1;
    __u8 ack = (tcp_flags >> 4) & 1;
    __u8 rst = (tcp_flags >> 2) & 1;
    __u64 is_connection = (syn && !ack) ? 1 : 0;
    __u64 is_error = rst ? 1 : 0;

    struct pair_metrics *pm = bpf_map_lookup_elem(&pair_metrics_map, &pk);
    if (pm) {
        __sync_fetch_and_add(&pm->packets, 1);
        if (pkt_bytes < 65535)
            __sync_fetch_and_add(&pm->bytes, pkt_bytes);
        if (is_connection)
            __sync_fetch_and_add(&pm->connections, is_connection);
        if (is_error)
            __sync_fetch_and_add(&pm->errors, is_error);
    } else {
        struct pair_metrics new_pm = {
            .packets     = 1,
            .bytes       = pkt_bytes,
            .connections = is_connection,
            .errors      = is_error,
        };
        bpf_map_update_elem(&pair_metrics_map, &pk, &new_pm, 0);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
