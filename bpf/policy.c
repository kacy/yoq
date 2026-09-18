// enforce source/destination ipv4 policy at bridge ingress, before dns and nat.
// an explicit deny always drops the packet. isolated sources need an explicit
// allow; other sources pass when no rule matches. fragments use the same ip pair.

#include "common.h"

// -- policy key: source + destination IP pair --

struct policy_key {
    __u32 src_ip;
    __u32 dst_ip;
};

// -- BPF maps --

// per-pair policy rules. key is (src_ip, dst_ip) in network byte order.
// value is a u8 action: 0 = deny, 1 = allow.
struct bpf_map_def SEC("maps") policy_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct policy_key),
    .value_size  = sizeof(__u8),
    .max_entries = 4096,
    .map_flags   = 0,
};

// an entry marks a source as isolated. only explicit allow rules can pass.
struct bpf_map_def SEC("maps") isolation_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u8),
    .max_entries = 1024,
    .map_flags   = 0,
};

// -- TC ingress program --

SEC("tc_ingress")
int policy_enforce(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // parse ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_UNSPEC;

    // only enforce on IPv4
    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_UNSPEC;

    // parse IP header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_SHOT;

    // apply policy regardless of ttl or source address. malformed ipv4 headers
    // must not bypass rules, but payload bytes may be outside the linear skb.
    __u32 header_len = (iph->ihl_version & 0x0f) * 4;
    __u32 total_len = ntohs(iph->tot_len);
    if ((iph->ihl_version >> 4) != 4 || header_len < sizeof(*iph) ||
        (void *)iph + header_len > data_end || total_len < header_len ||
        sizeof(*eth) + total_len > skb->len)
        return TC_ACT_SHOT;

    // addresses stay in network byte order, matching the userspace map keys.
    struct policy_key key = {
        .src_ip = iph->saddr,
        .dst_ip = iph->daddr,
    };

    // check for explicit deny
    __u8 *action = bpf_map_lookup_elem(&policy_map, &key);
    if (action && *action == 0)
        return TC_ACT_SHOT;

    // check if source is isolated (allow-only mode)
    __u8 *isolated = bpf_map_lookup_elem(&isolation_map, &key.src_ip);
    if (isolated) {
        // only action 1 allows traffic from an isolated source.
        if (!action || *action != 1)
            return TC_ACT_SHOT;
    }

    return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
