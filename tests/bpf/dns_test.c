#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#include "../../bpf/dns_intercept.c"
#pragma GCC diagnostic pop

#define BUFFER_SIZE 4096
#define QUERY_SIZE 63
#define RESPONSE_SIZE 79

static unsigned char *packet;
static struct __sk_buff skb;
static __u32 resolved_ip;
static struct {
    unsigned reads;
    unsigned fail_read;
    unsigned resizes;
    unsigned checksums;
    unsigned writes;
    unsigned redirects;
    int cache_miss;
    int fail_resize;
    int short_resize;
    int fail_checksum;
    int fail_write;
} calls;

static long load_bytes(const void *context, __u32 offset, void *out, __u32 len)
{
    assert(context == &skb);
    calls.reads++;
    if (calls.reads == calls.fail_read)
        return -1;
    assert(offset <= skb.len && len <= skb.len - offset);
    memcpy(out, packet + offset, len);
    return 0;
}

static void *lookup_service(void *map, const void *key)
{
    const unsigned char expected[64] = { 3, 'w', 'e', 'b', 0 };
    assert(map == &service_names);
    assert(memcmp(key, expected, sizeof(expected)) == 0);
    return calls.cache_miss ? NULL : &resolved_ip;
}

static long change_tail(void *context, __u32 new_len, __u64 flags)
{
    assert(context == &skb && flags == 0);
    assert(new_len == RESPONSE_SIZE);
    calls.resizes++;
    if (calls.fail_resize)
        return -1;
    skb.len = new_len;
    skb.data_end = skb.data + (calls.short_resize ? 54 : new_len);
    return 0;
}

static long replace_checksum(void *context, __u32 offset, __u64 old_value,
                             __u64 new_value, __u64 size)
{
    assert(context == &skb && offset == 24 && size == 2);
    assert(old_value == htons(QUERY_SIZE - 14));
    assert(new_value == htons(RESPONSE_SIZE - 14));
    calls.checksums++;
    // packet tests in the kernel cover checksum arithmetic. this stub controls
    // whether response construction can continue after the helper call.
    return calls.fail_checksum ? -1 : 0;
}

static long store_bytes(void *context, __u32 offset, const void *in,
                        __u32 len, __u64 flags)
{
    assert(context == &skb && flags == 0);
    assert(offset == QUERY_SIZE && len == DNS_ANSWER_SIZE);
    calls.writes++;
    if (calls.fail_write)
        return -1;
    assert(offset <= skb.len && len <= skb.len - offset);
    memcpy(packet + offset, in, len);
    return 0;
}

static long redirect_packet(int ifindex, __u64 flags)
{
    assert(ifindex == 7 && flags == 0);
    calls.redirects++;
    return TC_ACT_REDIRECT;
}

static void reset_query(void)
{
    memset(packet, 0, BUFFER_SIZE);
    memset(&calls, 0, sizeof(calls));
    skb = (struct __sk_buff) {
        .len = QUERY_SIZE,
        .data = (__u32)(uintptr_t)packet,
        .data_end = (__u32)(uintptr_t)packet + QUERY_SIZE,
        .ifindex = 7,
    };
    struct ethhdr *eth = (void *)packet;
    memset(eth->h_source, 0x11, 6);
    memset(eth->h_dest, 0x22, 6);
    eth->h_proto = htons(ETH_P_IP);
    struct iphdr *ip = (void *)(packet + 14);
    ip->ihl_version = 0x45;
    ip->tot_len = htons(QUERY_SIZE - 14);
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = htonl(0x0a2a0003);
    ip->daddr = htonl(0x0a2b0002);
    struct udphdr *udp = (void *)(packet + 34);
    udp->source = htons(40000);
    udp->dest = htons(53);
    udp->len = htons(QUERY_SIZE - 34);
    unsigned char *dns = packet + DNS_HEADER_OFFSET;
    dns[0] = 0x12;
    dns[1] = 0x34;
    dns[2] = 1; // recursion desired
    dns[5] = 1;
    const unsigned char question[] = { 3, 'w', 'e', 'b', 0, 0, 1, 0, 1 };
    memcpy(packet + DNS_QUESTION_OFFSET, question, sizeof(question));
    resolved_ip = htonl(0x0a2a0005);
}

static void test_read_failure_and_cache_miss(void)
{
    for (unsigned fail_read = 0; fail_read <= 2; fail_read++) {
        reset_query();
        calls.fail_read = fail_read;
        calls.cache_miss = fail_read == 0;
        unsigned char original[QUERY_SIZE];
        memcpy(original, packet, sizeof(original));
        assert(dns_intercept(&skb) == TC_ACT_UNSPEC);
        assert(skb.len == QUERY_SIZE);
        assert(memcmp(packet, original, sizeof(original)) == 0);
        assert(calls.resizes == 0 && calls.checksums == 0);
        assert(calls.writes == 0 && calls.redirects == 0);
    }
}

static void test_response_failures_drop(void)
{
    reset_query();
    calls.fail_resize = 1;
    assert(dns_intercept(&skb) == TC_ACT_SHOT);
    assert(calls.resizes == 1 && calls.checksums == 0);
    assert(calls.writes == 0 && calls.redirects == 0);

    reset_query();
    calls.short_resize = 1;
    assert(dns_intercept(&skb) == TC_ACT_SHOT);
    assert(calls.resizes == 1 && calls.checksums == 0);
    assert(calls.writes == 0 && calls.redirects == 0);

    reset_query();
    calls.fail_checksum = 1;
    assert(dns_intercept(&skb) == TC_ACT_SHOT);
    assert(calls.resizes == 1 && calls.checksums == 1);
    assert(calls.writes == 0 && calls.redirects == 0);

    reset_query();
    calls.fail_write = 1;
    assert(dns_intercept(&skb) == TC_ACT_SHOT);
    assert(calls.resizes == 1 && calls.checksums == 1);
    assert(calls.writes == 1 && calls.redirects == 0);
}

static void test_cache_hit_response(void)
{
    reset_query();
    assert(dns_intercept(&skb) == TC_ACT_REDIRECT);
    assert(calls.reads == 2 && calls.resizes == 1 && calls.checksums == 1);
    assert(calls.writes == 1 && calls.redirects == 1);
    assert(skb.len == RESPONSE_SIZE);

    const struct ethhdr *eth = (void *)packet;
    const unsigned char source_mac[6] = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };
    const unsigned char dest_mac[6] = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
    assert(memcmp(eth->h_source, source_mac, 6) == 0);
    assert(memcmp(eth->h_dest, dest_mac, 6) == 0);
    const struct iphdr *ip = (void *)(packet + 14);
    assert(ip->saddr == htonl(0x0a2b0002) && ip->daddr == htonl(0x0a2a0003));
    assert(ip->tot_len == htons(RESPONSE_SIZE - 14));
    const struct udphdr *udp = (void *)(packet + 34);
    assert(udp->source == htons(53) && udp->dest == htons(40000));
    assert(udp->len == htons(RESPONSE_SIZE - 34) && udp->check == 0);
    const unsigned char expected_dns[] = {
        0x12, 0x34, 0x85, 0, 0, 1, 0, 1, 0, 0, 0, 0,
        3, 'w', 'e', 'b', 0, 0, 1, 0, 1,
        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4, 10, 42, 0, 5,
    };
    assert(memcmp(packet + DNS_HEADER_OFFSET, expected_dns, sizeof(expected_dns)) == 0);
}

int main(void)
{
    // skb packet addresses are 32-bit fields, even in this host executable.
    packet = mmap(NULL, BUFFER_SIZE, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    assert(packet != MAP_FAILED);
    assert((uintptr_t)packet <= UINT32_MAX - BUFFER_SIZE);
    bpf_skb_load_bytes = load_bytes;
    bpf_map_lookup_elem = lookup_service;
    bpf_skb_change_tail = change_tail;
    bpf_l3_csum_replace = replace_checksum;
    bpf_skb_store_bytes = store_bytes;
    bpf_redirect = redirect_packet;

    test_read_failure_and_cache_miss();
    test_response_failures_drop();
    test_cache_hit_response();
    assert(munmap(packet, BUFFER_SIZE) == 0);
    puts("dns helper failure tests passed");
    return 0;
}
