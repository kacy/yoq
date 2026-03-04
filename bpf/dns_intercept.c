// dns_intercept — eBPF DNS resolution for container service discovery
//
// TC ingress program attached to the yoq0 bridge. intercepts DNS A
// record queries and resolves known service names directly in the
// kernel, avoiding the round-trip to the userspace resolver.
//
// flow:
//   1. parse eth → IP → UDP headers, check dst port 53
//   2. parse DNS header: verify QR=0 (query), QDCOUNT=1, type=A
//   3. extract query name from DNS wire format (length-prefixed labels)
//   4. look up name in service_names BPF hash map
//   5. HIT: rewrite packet into DNS A response, redirect back
//   6. MISS: pass to userspace dns.zig resolver (TC_ACT_OK)
//
// the service_names map is kept in sync by userspace — dns.zig calls
// mapUpdate/mapDelete on register/unregister.
//
// compile: clang -target bpf -O2 -g -c -o dns_intercept.o dns_intercept.c

#include "common.h"

// -- BPF maps --

// service name → IPv4 address
// key: 64-byte null-padded service name
// value: 4-byte IPv4 address in network byte order
struct bpf_map_def SEC("maps") service_names = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 64,
    .value_size = 4,
    .max_entries = 256,
    .map_flags = 0,
};

// -- helpers --

// BPF skb helpers needed for packet modification
static long (*bpf_skb_store_bytes)(void *skb, __u32 offset, const void *from,
                                   __u32 len, __u64 flags) = (void *)9;
static long (*bpf_skb_change_tail)(void *skb, __u32 new_len,
                                   __u64 flags) = (void *)38;
static long (*bpf_redirect)(int ifindex, __u64 flags) = (void *)23;
static int (*bpf_csum_diff)(__u32 *from, __u32 from_size, __u32 *to,
                            __u32 to_size, int seed) = (void *)28;
static long (*bpf_l3_csum_replace)(void *skb, __u32 offset, __u64 from,
                                   __u64 to, __u64 size) = (void *)10;
static long (*bpf_l4_csum_replace)(void *skb, __u32 offset, __u64 from,
                                   __u64 to, __u64 flags) = (void *)11;

// DNS constants
#define DNS_PORT 53
#define DNS_HEADER_SIZE 12
#define DNS_MAX_NAME_LEN 63

// DNS header flags
#define DNS_QR_QUERY 0
#define DNS_QR_RESPONSE (1 << 15)
#define DNS_AA_FLAG (1 << 10)
#define DNS_RCODE_OK 0
#define DNS_TYPE_A 1
#define DNS_CLASS_IN 1

// extract the query name from a DNS packet into a fixed-size key buffer.
// DNS names use length-prefixed labels: 3www6google3com0
// we convert to dot-separated: www.google.com
// returns the total name wire length (including labels + null terminator),
// or 0 on parse error.
static __attribute__((always_inline)) int
extract_dns_name(void *data, void *data_end, __u32 dns_offset, char *key_buf)
{
    // zero the key buffer for consistent map lookups
    #pragma unroll
    for (int i = 0; i < 64; i++)
        key_buf[i] = 0;

    __u32 pos = dns_offset + DNS_HEADER_SIZE; // skip DNS header
    int key_pos = 0;
    int wire_len = 0;

    // read up to 4 labels (enough for "service.namespace.svc.local")
    #pragma unroll
    for (int label = 0; label < 4; label++) {
        if (pos + 1 > (__u32)(data_end - data))
            return 0;

        __u8 label_len = *(__u8 *)(data + pos);
        pos += 1;
        wire_len += 1;

        if (label_len == 0)
            break; // end of name

        if (label_len > DNS_MAX_NAME_LEN)
            return 0; // invalid label

        // add dot separator between labels
        if (key_pos > 0 && key_pos < 63) {
            key_buf[key_pos] = '.';
            key_pos++;
        }

        // copy label bytes
        if (pos + label_len > (__u32)(data_end - data))
            return 0; // truncated

        #pragma unroll
        for (int j = 0; j < DNS_MAX_NAME_LEN; j++) {
            if (j >= label_len)
                break;
            if (key_pos >= 63)
                break;
            key_buf[key_pos] = *(__u8 *)(data + pos + j);
            key_pos++;
        }

        pos += label_len;
        wire_len += label_len;
    }

    return wire_len;
}

SEC("tc_ingress")
int dns_intercept(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // -- parse ethernet header --
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // only handle IPv4
    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    // -- parse IP header --
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // only handle UDP
    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    // IP header length (lower 4 bits of ihl_version, in 4-byte units)
    __u8 ihl = (ip->ihl_version & 0x0F) * 4;
    if (ihl < 20)
        return TC_ACT_OK;

    // -- parse UDP header --
    struct udphdr *udp = (void *)((char *)ip + ihl);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;

    // only handle DNS queries (dst port 53)
    if (udp->dest != htons(DNS_PORT))
        return TC_ACT_OK;

    // -- parse DNS header --
    __u32 dns_offset = (char *)udp - (char *)data + sizeof(struct udphdr);
    if (dns_offset + DNS_HEADER_SIZE > (__u32)(data_end - data))
        return TC_ACT_OK;

    __u8 *dns = data + dns_offset;

    // check QR=0 (query) — QR is the high bit of byte 2
    __u16 flags = (dns[2] << 8) | dns[3];
    if (flags & DNS_QR_RESPONSE)
        return TC_ACT_OK; // not a query

    // check QDCOUNT=1 (single question)
    __u16 qdcount = (dns[4] << 8) | dns[5];
    if (qdcount != 1)
        return TC_ACT_OK;

    // -- extract query name --
    char key_buf[64];
    int wire_len = extract_dns_name(data, data_end, dns_offset, key_buf);
    if (wire_len == 0)
        return TC_ACT_OK; // parse error

    // check QTYPE=A and QCLASS=IN after the name
    __u32 qtype_offset = dns_offset + DNS_HEADER_SIZE + wire_len;
    if (qtype_offset + 4 > (__u32)(data_end - data))
        return TC_ACT_OK;

    __u8 *qtype_ptr = data + qtype_offset;
    __u16 qtype = (qtype_ptr[0] << 8) | qtype_ptr[1];
    __u16 qclass = (qtype_ptr[2] << 8) | qtype_ptr[3];

    if (qtype != DNS_TYPE_A || qclass != DNS_CLASS_IN)
        return TC_ACT_OK; // not an A/IN query — pass to userspace

    // -- look up service name --
    __u32 *ip_addr = bpf_map_lookup_elem(&service_names, key_buf);
    if (!ip_addr)
        return TC_ACT_OK; // miss — pass to userspace resolver

    // -- build DNS response in-place --
    //
    // we need to:
    // 1. swap src/dst MACs
    // 2. swap src/dst IPs
    // 3. swap src/dst UDP ports
    // 4. set DNS flags: QR=1, AA=1, ANCOUNT=1
    // 5. append answer RR after the question section
    // 6. update lengths and checksums
    //
    // the answer RR is 16 bytes:
    //   name pointer (2) + type (2) + class (2) + TTL (4) + rdlength (2) + rdata (4)

    // answer section starts right after the question
    __u32 answer_offset = qtype_offset + 4; // past QTYPE + QCLASS
    __u32 new_pkt_len = answer_offset + 16; // 16 bytes for the answer RR

    // resize packet to fit the answer
    if (bpf_skb_change_tail(skb, new_pkt_len, 0) != 0)
        return TC_ACT_OK; // resize failed

    // re-read data pointers after resize (they may have changed)
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    // bounds check the full packet
    if (data + new_pkt_len > data_end)
        return TC_ACT_OK;

    eth = data;
    ip = (void *)(eth + 1);
    udp = (void *)((char *)ip + ihl);

    // 1. swap MACs
    __u8 tmp_mac[6];
    __builtin_memcpy(tmp_mac, eth->h_dest, 6);
    __builtin_memcpy(eth->h_dest, eth->h_source, 6);
    __builtin_memcpy(eth->h_source, tmp_mac, 6);

    // 2. swap IPs
    __u32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;

    // 3. swap UDP ports
    __u16 tmp_port = udp->source;
    udp->source = udp->dest;
    udp->dest = tmp_port;

    // 4. set DNS response flags
    dns = data + dns_offset;
    // QR=1, AA=1, RCODE=0
    dns[2] = 0x84; // QR=1, opcode=0, AA=1
    dns[3] = 0x00; // RA=0, RCODE=0
    // ANCOUNT=1
    dns[6] = 0x00;
    dns[7] = 0x01;

    // 5. write answer RR
    __u8 *answer = data + answer_offset;
    // name: pointer to offset 12 in DNS section (where question name starts)
    __u16 name_ptr = htons(0xC000 | (dns_offset - ((char *)udp + sizeof(struct udphdr) - (char *)data) + DNS_HEADER_SIZE));
    // actually, the pointer is relative to the DNS message start.
    // the question name starts at DNS header offset 12 within the DNS message.
    // DNS pointer: 0xC00C (offset 12 from start of DNS message)
    answer[0] = 0xC0;
    answer[1] = 0x0C;
    // TYPE = A (1)
    answer[2] = 0x00;
    answer[3] = 0x01;
    // CLASS = IN (1)
    answer[4] = 0x00;
    answer[5] = 0x01;
    // TTL = 5 seconds
    answer[6] = 0x00;
    answer[7] = 0x00;
    answer[8] = 0x00;
    answer[9] = 0x05;
    // RDLENGTH = 4
    answer[10] = 0x00;
    answer[11] = 0x04;
    // RDATA = IPv4 address (already in network byte order from map)
    __builtin_memcpy(&answer[12], ip_addr, 4);

    // 6. update IP total length
    __u16 old_ip_len = ip->tot_len;
    ip->tot_len = htons(new_pkt_len - sizeof(struct ethhdr));

    // update IP checksum (incremental)
    bpf_l3_csum_replace(skb, (char *)&ip->check - (char *)data,
                        old_ip_len, ip->tot_len, 2);

    // update UDP length
    udp->len = htons(new_pkt_len - sizeof(struct ethhdr) - ihl);
    // zero UDP checksum (optional for IPv4)
    udp->check = 0;

    // redirect packet back out the ingress interface
    return bpf_redirect(skb->ifindex, 0);
}

char _license[] SEC("license") = "GPL";
