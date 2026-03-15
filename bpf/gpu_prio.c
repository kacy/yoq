// gpu_prio.c — TC egress classifier for GPU mesh traffic prioritization
//
// marks packets destined for GPU mesh ports (29500-29600) with
// TC_PRIO_INTERACTIVE (6) so the kernel qdisc schedules them ahead
// of bulk traffic. attached to the wg-yoq interface when training
// jobs start, detached when they stop.
//
// compile with:
//   clang -target bpf -O2 -g -c bpf/gpu_prio.c -o bpf/gpu_prio.o

#include "common.h"

// TC priority class for interactive traffic
#define TC_PRIO_INTERACTIVE 6

// GPU mesh port range (NCCL default)
#define GPU_PORT_MIN 29500
#define GPU_PORT_MAX 29600

SEC("classifier/gpu_prio")
int gpu_prio_mark(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // only handle IPv4
    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    // IP header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    __u16 dst_port = 0;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)iph + sizeof(*iph);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        dst_port = ntohs(tcp->dest);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)iph + sizeof(*iph);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        dst_port = ntohs(udp->dest);
    } else {
        return TC_ACT_OK;
    }

    // mark GPU mesh traffic with interactive priority
    if (dst_port >= GPU_PORT_MIN && dst_port <= GPU_PORT_MAX) {
        skb->priority = TC_PRIO_INTERACTIVE;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
