// dns_intercept — eBPF DNS resolution for container service discovery
//
// TC ingress program attached to the yoq0 bridge. intercepts DNS A
// record queries and resolves known service names directly in the
// kernel, avoiding the round-trip to the userspace resolver.
//
// flow:
//   1. parse eth → IP → UDP headers at fixed offsets, check dst port 53
//   2. parse DNS header: verify QR=0 (query), QDCOUNT=1
//   3. bpf_skb_load_bytes: copy question section to stack key buffer
//   4. look up wire-format name in service_names BPF hash map
//   5. HIT: validate QTYPE=A QCLASS=IN, build DNS response, redirect
//   6. MISS: pass to userspace dns.zig resolver (TC_ACT_OK)
//
// BPF verifier constraints this program respects:
//   - all packet access uses fixed offsets (IHL forced to 5)
//   - all stack reads use compile-time constant offsets (unrolled loops)
//   - no variable-offset packet or stack access
//   - uses bpf_skb_load_bytes/bpf_skb_store_bytes for variable offsets
//   - stays within 512-byte stack limit
//
// map key format: raw DNS wire-format name (length-prefixed labels),
// null-padded to 64 bytes. e.g. "mydb" → "\x04mydb\x00" + 58 zero bytes.
// the userspace side (dns.zig / ebpf.zig) converts dot-separated names
// to wire format when updating the map.
//
// compile: clang -target bpf -O2 -g -c -o dns_intercept.o dns_intercept.c

#include "common.h"

// -- BPF maps --

// service name → IPv4 address
// key: 64-byte wire-format DNS name (length-prefixed labels, null-padded)
// value: 4-byte IPv4 address in network byte order
struct bpf_map_def SEC("maps") service_names = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 64,
    .value_size = 4,
    .max_entries = 256,
    .map_flags = 0,
};

// -- helpers --

static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset,
                                   void *to, __u32 len) = (void *)26;
static long (*bpf_skb_store_bytes)(void *skb, __u32 offset, const void *from,
                                   __u32 len, __u64 flags) = (void *)9;
static long (*bpf_skb_change_tail)(void *skb, __u32 new_len,
                                   __u64 flags) = (void *)38;
static long (*bpf_redirect)(int ifindex, __u64 flags) = (void *)23;

#define DNS_PORT 53
#define DNS_HEADER_SIZE 12

SEC("tc_ingress")
int dns_intercept(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // -- parse ethernet header (offset 0, 14 bytes) --
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    // -- parse IP header (offset 14, 20 bytes) --
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    // require IHL=5 (20 bytes, no options) for fixed offsets
    if ((ip->ihl_version & 0x0F) != 5)
        return TC_ACT_OK;

    // -- parse UDP header (offset 34, 8 bytes) --
    struct udphdr *udp = (void *)((char *)ip + 20);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;

    if (udp->dest != htons(DNS_PORT))
        return TC_ACT_OK;

    // -- parse DNS header (offset 42, 12 bytes) --
    __u8 *dns = data + 42;
    if ((void *)(dns + DNS_HEADER_SIZE) > data_end)
        return TC_ACT_OK;

    // QR=0 (query)
    if (dns[2] & 0x80)
        return TC_ACT_OK;

    // QDCOUNT=1
    __u16 qdcount = (dns[4] << 8) | dns[5];
    if (qdcount != 1)
        return TC_ACT_OK;

    // -- copy question name to stack (offset 54, 64 bytes) --
    // the map key is the raw wire-format DNS name, so we just copy
    // the question section directly. no parsing needed.
    char key_buf[64] = {};
    if (bpf_skb_load_bytes(skb, 54, key_buf, 64) != 0)
        return TC_ACT_OK;

    // -- map lookup --
    __u32 *ip_addr = bpf_map_lookup_elem(&service_names, key_buf);
    if (!ip_addr)
        return TC_ACT_OK; // miss — pass to userspace

    // save resolved IP before any packet modifications
    __u32 resolved_ip = *ip_addr;

    // -- find name length by scanning for null terminator --
    // each key_buf[i] is a fixed-offset stack read (i is unrolled)
    int wire_len = 0;
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        if (wire_len == 0 && key_buf[i] == 0)
            wire_len = i + 1; // include the null terminator
    }

    if (wire_len < 2 || wire_len > 63)
        return TC_ACT_OK;

    // -- validate QTYPE=A and QCLASS=IN --
    // read 4 bytes from packet at the variable offset after the name.
    // bpf_skb_load_bytes takes a scalar offset — no pointer arithmetic.
    __u8 qtqc[4] = {};
    if (bpf_skb_load_bytes(skb, 54 + wire_len, qtqc, 4) != 0)
        return TC_ACT_OK;

    __u16 qtype = (qtqc[0] << 8) | qtqc[1];
    __u16 qclass = (qtqc[2] << 8) | qtqc[3];
    if (qtype != 1 || qclass != 1) // A / IN
        return TC_ACT_OK;

    // -- save header fields before resize --
    // all at fixed offsets, no variable access
    __u8 src_mac[6], dst_mac[6];
    __builtin_memcpy(dst_mac, eth->h_dest, 6);
    __builtin_memcpy(src_mac, eth->h_source, 6);

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u16 old_ip_len = ip->tot_len;
    __u16 src_port = udp->source;
    __u16 dst_port = udp->dest;

    // -- compute response layout --
    __u32 answer_offset = 54 + wire_len + 4; // past name + qtype + qclass
    __u32 new_pkt_len = answer_offset + 16;  // 16-byte answer RR

    // -- resize packet --
    if (bpf_skb_change_tail(skb, new_pkt_len, 0) != 0)
        return TC_ACT_OK;

    // re-read data pointers after resize
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    // use a fixed minimum size for the bounds check so the verifier
    // can prove all fixed-offset header access is safe.
    // minimum response: eth(14) + ip(20) + udp(8) + dns(12) + name(2) + qt/qc(4) + answer(16) = 76
    if (data + 76 > data_end)
        return TC_ACT_OK;
    if (data + new_pkt_len > data_end)
        return TC_ACT_OK;

    eth = data;
    ip = (void *)(eth + 1);
    udp = (void *)((char *)ip + 20);
    dns = data + 42;

    // 1. swap MACs
    __builtin_memcpy(eth->h_dest, src_mac, 6);
    __builtin_memcpy(eth->h_source, dst_mac, 6);

    // 2. swap IPs
    ip->saddr = dst_ip;
    ip->daddr = src_ip;

    // 3. update IP total length (save new value for checksum update)
    __u16 new_ip_len = htons(new_pkt_len - 14);
    ip->tot_len = new_ip_len;

    // 4. swap UDP ports, update length, zero checksum
    udp->source = dst_port;
    udp->dest = src_port;
    udp->len = htons(new_pkt_len - 34);
    udp->check = 0;

    // 5. set DNS response flags
    dns[2] = 0x84; // QR=1, AA=1
    dns[3] = 0x00;
    dns[6] = 0x00; // ANCOUNT = 1
    dns[7] = 0x01;

    // 6. update IP checksum AFTER all direct packet writes,
    //    because bpf_l3_csum_replace invalidates packet pointers
    bpf_l3_csum_replace(skb, 24, old_ip_len, new_ip_len, 2);

    // 7. write answer RR at variable offset via bpf_skb_store_bytes
    __u8 answer[16] = {
        0xC0, 0x0C,                   // name pointer (offset 12 in DNS msg)
        0x00, 0x01,                   // TYPE = A
        0x00, 0x01,                   // CLASS = IN
        0x00, 0x00, 0x00, 0x05,       // TTL = 5 seconds
        0x00, 0x04,                   // RDLENGTH = 4
        0, 0, 0, 0                    // RDATA (filled below)
    };
    __builtin_memcpy(&answer[12], &resolved_ip, 4);

    if (bpf_skb_store_bytes(skb, answer_offset, answer, 16, 0) != 0)
        return TC_ACT_OK;

    return bpf_redirect(skb->ifindex, 0);
}

char _license[] SEC("license") = "GPL";
