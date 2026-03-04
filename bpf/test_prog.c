// test_prog — minimal TC program for testing the BPF build pipeline
//
// accepts all packets (returns TC_ACT_OK). this proves that the full
// chain works end-to-end: clang compilation, ELF extraction, bytecode
// embedding, kernel loading, and TC attachment.
//
// compile: clang -target bpf -O2 -g -c -o test_prog.o test_prog.c

#include "common.h"

SEC("tc_ingress")
int test_prog(struct __sk_buff *skb)
{
    (void)skb;
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
