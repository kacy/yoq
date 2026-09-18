#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

// shared headers declare helpers that these programs do not use.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#define _license storage_license
#include "../../bpf/storage_metrics.c"
#undef _license
#define _license gpu_license
#include "../../bpf/gpu_prio.c"
#undef _license
#pragma GCC diagnostic pop

static struct io_metrics counters;
static int key_exists;
static int race_on_insert;
static int reject_insert;
static __u64 current_cgroup = 42;

static __u64 mock_cgroup_id(void)
{
    return current_cgroup;
}

static void *mock_lookup(void *map, const void *key)
{
    assert(map == &storage_metrics_map);
    assert(*(__u64 *)key == current_cgroup);
    return key_exists ? &counters : NULL;
}

static long mock_update(void *map, const void *key, const void *value, __u64 flags)
{
    assert(map == &storage_metrics_map);
    assert(*(__u64 *)key == current_cgroup);
    if (reject_insert)
        return -1;
    if (race_on_insert) {
        // another cpu records a completion after our initial lookup misses.
        counters = (struct io_metrics){ .read_bytes = 1024, .read_ops = 2 };
        key_exists = 1;
        race_on_insert = 0;
    }
    if (key_exists && flags == BPF_NOEXIST)
        return -1;
    counters = *(const struct io_metrics *)value;
    key_exists = 1;
    return 0;
}

static void complete_io(const char *operation, __u32 sectors)
{
    struct tp_block_rq_complete event = { .nr_sector = sectors };
    assert(strlen(operation) < sizeof(event.rwbs));
    strcpy(event.rwbs, operation);
    assert(storage_metrics_count(&event) == 0);
}

static void test_storage_counters(void)
{
    bpf_get_current_cgroup_id = mock_cgroup_id;
    bpf_map_lookup_elem = mock_lookup;
    bpf_map_update_elem = mock_update;

    complete_io("R", 2);
    complete_io("W", 3);
    complete_io("FR", 4);
    complete_io("FWF", 5);
    complete_io("F", 10);
    complete_io("FF", 10);
    complete_io("D", 10);
    assert(counters.read_bytes == 6 * 512 && counters.read_ops == 2);
    assert(counters.write_bytes == 8 * 512 && counters.write_ops == 2);

    current_cgroup = 0;
    complete_io("R", 10);
    assert(counters.read_ops == 2);
    current_cgroup = 42;

    key_exists = 0;
    race_on_insert = 1;
    complete_io("R", 3);
    assert(counters.read_bytes == 5 * 512 && counters.read_ops == 3);

    key_exists = 0;
    complete_io("W", UINT32_MAX);
    assert(counters.write_bytes == (__u64)UINT32_MAX * 512);
    assert(counters.write_ops == 1 && counters.read_ops == 0);

    key_exists = 0;
    reject_insert = 1;
    complete_io("R", 1);
    assert(!key_exists && counters.read_ops == 0);
    reject_insert = 0;
}

static struct __sk_buff make_gpu_packet(void *packet, __u8 protocol, __u16 port)
{
    memset(packet, 0, 256);
    struct iphdr *ip = packet;
    // four option bytes put the transport header beyond the minimum ip header.
    ip->ihl_version = 0x46;
    ip->protocol = protocol;
    __u32 packet_len;
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = packet + 24;
        tcp->dest = htons(port);
        tcp->flags = htons(0x5002);
        packet_len = 24 + sizeof(*tcp);
    } else {
        struct udphdr *udp = packet + 24;
        udp->dest = htons(port);
        udp->len = htons(sizeof(*udp));
        packet_len = 24 + sizeof(*udp);
    }
    ip->tot_len = htons(packet_len);
    return (struct __sk_buff){
        .len = packet_len,
        .protocol = htons(ETH_P_IP),
        .data = (__u32)(uintptr_t)packet,
        .data_end = (__u32)(uintptr_t)packet + packet_len,
        .priority = 123,
    };
}

static void expect_gpu_priority(struct __sk_buff packet, __u32 expected)
{
    assert(gpu_prio_mark(&packet) == TC_ACT_OK);
    assert(packet.priority == expected);
}

static void test_gpu_packets(void *data)
{
    const __u16 ports[] = {29500, 29600, 29499, 29601};
    for (size_t i = 0; i < sizeof(ports) / sizeof(ports[0]); i++) {
        __u32 priority = i < 2 ? TC_PRIO_INTERACTIVE : 123;
        expect_gpu_priority(make_gpu_packet(data, IPPROTO_TCP, ports[i]), priority);
        expect_gpu_priority(make_gpu_packet(data, IPPROTO_UDP, ports[i]), priority);
    }

    struct iphdr *ip = data;
    struct __sk_buff packet = make_gpu_packet(data, IPPROTO_TCP, 29500);
    ip->frag_off = htons(0x2000);
    expect_gpu_priority(packet, 123);
    ip->frag_off = htons(1);
    expect_gpu_priority(packet, 123);
    ip->frag_off = htons(0x4000);
    expect_gpu_priority(packet, TC_PRIO_INTERACTIVE);

    packet = make_gpu_packet(data, IPPROTO_TCP, 29500);
    ip->tot_len = htons(24);
    expect_gpu_priority(packet, 123);
    ip->tot_len = htons(packet.len + 1);
    expect_gpu_priority(packet, 123);

    packet = make_gpu_packet(data, IPPROTO_TCP, 29500);
    packet.data_end--;
    expect_gpu_priority(packet, 123);
    packet.data_end++;
    struct tcphdr *tcp = data + 24;
    tcp->flags = htons(0x4002);
    expect_gpu_priority(packet, 123);
    tcp->flags = htons(0xf002);
    expect_gpu_priority(packet, 123);

    packet = make_gpu_packet(data, IPPROTO_UDP, 29500);
    struct udphdr *udp = data + 24;
    udp->len = htons(7);
    expect_gpu_priority(packet, 123);
    udp->len = htons(9);
    expect_gpu_priority(packet, 123);

    packet = make_gpu_packet(data, IPPROTO_TCP, 29500);
    ip->ihl_version = 0x66;
    expect_gpu_priority(packet, 123);
    ip->ihl_version = 0x44;
    expect_gpu_priority(packet, 123);
    packet.protocol = htons(0x86dd);
    expect_gpu_priority(packet, 123);
}

int main(void)
{
    test_storage_counters();

    // the bpf context stores packet pointers in 32-bit fields.
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
#ifdef MAP_32BIT
    flags |= MAP_32BIT;
#endif
    void *packet = mmap((void *)0x10000000, 4096, PROT_READ | PROT_WRITE,
                        flags, -1, 0);
    if (packet == MAP_FAILED || (uintptr_t)packet > UINT32_MAX - 4096) {
        fputs("could not allocate a packet buffer below 4 gib\n", stderr);
        return 1;
    }
    test_gpu_packets(packet);
    assert(munmap(packet, 4096) == 0);
    puts("storage counters and gpu packet regressions passed");
    return 0;
}
