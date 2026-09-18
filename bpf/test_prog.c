// minimal tc program for build and attachment smoke tests.
// returns tc_act_ok without inspecting or changing the packet.

#include "common.h"

SEC("tc_ingress")
int test_prog(struct __sk_buff *skb)
{
    (void)skb;
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
