// policy.c — network policy enforcement (allow/deny between services)
//
// attached to the bridge ingress at priority 0 (before DNS interceptor,
// load balancer, and metrics). enforces per-IP pair allow/deny rules
// set by `yoq policy`. drops denied packets before any other processing.
//
// two BPF maps:
//   policy_map  — (src_ip, dst_ip) → action (0=deny, 1=allow)
//   isolation_map — src_ip → flag (1=isolated, only allow-listed destinations)
//
// logic:
//   1. parse eth → IP, extract src/dst
//   2. if (src, dst) has a deny entry → drop
//   3. if src is isolated and (src, dst) has no allow entry → drop
//   4. default: pass
//
// SECURITY HARDENING:
//   - All packet accesses validated against data_end
//   - IP header length (IHL) validated before use
//   - Policy lookup keys fully initialized
//   - Maximum packet size enforced
//
// compile with:
//   clang -target bpf -O2 -g -c bpf/policy.c -o bpf/policy.o

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

// IPs in "isolated" mode (have allow-only rules).
// if an IP is in this map, only explicitly allowed destinations are reachable.
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
    
    // SECURITY: Enforce minimum packet size for parsing
    if (data + 34 > data_end) // eth(14) + ip(20)
        return TC_ACT_OK;

    // parse ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // only enforce on IPv4
    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    // parse IP header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;
    
    // SECURITY: Validate IP total length is reasonable
    __u16 ip_tot_len = ntohs(iph->tot_len);
    if (ip_tot_len < 20 || ip_tot_len > 65535)
        return TC_ACT_OK;
    
    // SECURITY: Validate IHL is correct
    __u8 ihl = iph->ihl_version & 0x0F;
    if (ihl < 5 || ihl > 15) // Min 20 bytes, max 60 bytes
        return TC_ACT_OK;

    // SECURITY: Fully initialize the key to prevent info leaks
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
        // source is isolated — only pass if there's an explicit allow entry
        if (!action || *action != 1)
            return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
