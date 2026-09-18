// prioritize gpu mesh traffic on wg-yoq egress.
//
// destination ports 29500 through 29600 receive interactive priority.
// wireguard carries raw ip packets, so there is no ethernet header here.

#include "common.h"

#define TC_PRIO_INTERACTIVE 6
#define GPU_PORT_MIN 29500
#define GPU_PORT_MAX 29600

SEC("classifier/gpu_prio")
int gpu_prio_mark(struct __sk_buff *skb)
{
    if (skb->protocol != htons(ETH_P_IP))
        return TC_ACT_OK;

    void *data     = (void *)(__u64)skb->data;
    void *data_end = (void *)(__u64)skb->data_end;
    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;
    if ((iph->ihl_version >> 4) != 4)
        return TC_ACT_OK;

    __u32 ip_header_len = (iph->ihl_version & 0x0f) * 4;
    if (ip_header_len < sizeof(*iph))
        return TC_ACT_OK;
    if ((void *)iph + ip_header_len > data_end)
        return TC_ACT_OK;

    __u32 ip_total_len = ntohs(iph->tot_len);
    if (ip_total_len < ip_header_len || ip_total_len > skb->len)
        return TC_ACT_OK;
    if (ntohs(iph->frag_off) & IPV4_FRAGMENT_MASK)
        return TC_ACT_OK;

    // use the declared ip payload length so padding cannot supply a port.
    __u32 payload_len = ip_total_len - ip_header_len;
    __u16 dst_port;
    if (iph->protocol == IPPROTO_TCP) {
        if (payload_len < sizeof(struct tcphdr))
            return TC_ACT_OK;
        struct tcphdr *tcp = (void *)iph + ip_header_len;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        __u32 tcp_header_len = (ntohs(tcp->flags) >> 12) * 4;
        if (tcp_header_len < sizeof(*tcp) || tcp_header_len > payload_len)
            return TC_ACT_OK;
        if ((void *)tcp + tcp_header_len > data_end)
            return TC_ACT_OK;
        dst_port = ntohs(tcp->dest);
    } else if (iph->protocol == IPPROTO_UDP) {
        if (payload_len < sizeof(struct udphdr))
            return TC_ACT_OK;
        struct udphdr *udp = (void *)iph + ip_header_len;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        __u32 udp_len = ntohs(udp->len);
        if (udp_len < sizeof(*udp) || udp_len > payload_len)
            return TC_ACT_OK;
        dst_port = ntohs(udp->dest);
    } else {
        return TC_ACT_OK;
    }

    if (dst_port >= GPU_PORT_MIN && dst_port <= GPU_PORT_MAX)
        skb->priority = TC_PRIO_INTERACTIVE;
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
