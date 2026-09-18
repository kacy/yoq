// answer cached service-name queries at tc ingress on the yoq0 bridge.
// unsupported packets and cache misses continue to the userspace resolver.
// packet headers use fixed offsets; name reads use unrolled stack accesses.

#include "common.h"

// keys are wire-format dns names, padded with zeros to 64 bytes.
// values are ipv4 addresses in network byte order.
struct bpf_map_def SEC("maps") service_names = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 64,
    .value_size = 4,
    .max_entries = 1024,
    .map_flags = 0,
};

static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset,
                                 void *to, __u32 len) = (void *)26;
static long (*bpf_skb_store_bytes)(void *skb, __u32 offset, const void *from,
                                  __u32 len, __u64 flags) = (void *)9;
static long (*bpf_skb_change_tail)(void *skb, __u32 new_len,
                                  __u64 flags) = (void *)38;
static long (*bpf_redirect)(int ifindex, __u64 flags) = (void *)23;

#define DNS_PORT 53
#define DNS_HEADER_SIZE 12
#define DNS_HEADER_OFFSET 42
#define DNS_QUESTION_FIELDS_SIZE 4
#define DNS_ANSWER_SIZE 16

// return the wire-name length, including the root terminator. zero bytes inside
// a label are data. compression and extended labels fall back to userspace.
static __attribute__((always_inline)) __u32
find_name_length(const char *name, __u32 max_len)
{
    if (max_len < 2 || max_len > 64)
        return 0;

    __u32 next_label = 0;
    // explicit expansion keeps stack offsets constant. clang does not fully
    // unroll a loop with these early returns.
#define CHECK_LABEL_AT(offset)                                      \
    if ((offset) >= max_len) return 0;                               \
    if ((offset) == next_label) {                                    \
        __u8 label_len = name[offset];                               \
        if (label_len == 0) return (offset) == 0 ? 0 : (offset) + 1;  \
        if (label_len > 63 || label_len >= max_len - (offset))        \
            return 0;                                               \
        next_label = (offset) + 1 + label_len;                       \
    }
    CHECK_LABEL_AT(0); CHECK_LABEL_AT(1); CHECK_LABEL_AT(2); CHECK_LABEL_AT(3);
    CHECK_LABEL_AT(4); CHECK_LABEL_AT(5); CHECK_LABEL_AT(6); CHECK_LABEL_AT(7);
    CHECK_LABEL_AT(8); CHECK_LABEL_AT(9); CHECK_LABEL_AT(10); CHECK_LABEL_AT(11);
    CHECK_LABEL_AT(12); CHECK_LABEL_AT(13); CHECK_LABEL_AT(14); CHECK_LABEL_AT(15);
    CHECK_LABEL_AT(16); CHECK_LABEL_AT(17); CHECK_LABEL_AT(18); CHECK_LABEL_AT(19);
    CHECK_LABEL_AT(20); CHECK_LABEL_AT(21); CHECK_LABEL_AT(22); CHECK_LABEL_AT(23);
    CHECK_LABEL_AT(24); CHECK_LABEL_AT(25); CHECK_LABEL_AT(26); CHECK_LABEL_AT(27);
    CHECK_LABEL_AT(28); CHECK_LABEL_AT(29); CHECK_LABEL_AT(30); CHECK_LABEL_AT(31);
    CHECK_LABEL_AT(32); CHECK_LABEL_AT(33); CHECK_LABEL_AT(34); CHECK_LABEL_AT(35);
    CHECK_LABEL_AT(36); CHECK_LABEL_AT(37); CHECK_LABEL_AT(38); CHECK_LABEL_AT(39);
    CHECK_LABEL_AT(40); CHECK_LABEL_AT(41); CHECK_LABEL_AT(42); CHECK_LABEL_AT(43);
    CHECK_LABEL_AT(44); CHECK_LABEL_AT(45); CHECK_LABEL_AT(46); CHECK_LABEL_AT(47);
    CHECK_LABEL_AT(48); CHECK_LABEL_AT(49); CHECK_LABEL_AT(50); CHECK_LABEL_AT(51);
    CHECK_LABEL_AT(52); CHECK_LABEL_AT(53); CHECK_LABEL_AT(54); CHECK_LABEL_AT(55);
    CHECK_LABEL_AT(56); CHECK_LABEL_AT(57); CHECK_LABEL_AT(58); CHECK_LABEL_AT(59);
    CHECK_LABEL_AT(60); CHECK_LABEL_AT(61); CHECK_LABEL_AT(62); CHECK_LABEL_AT(63);
#undef CHECK_LABEL_AT
    return 0;
}

SEC("tc_ingress")
int dns_intercept(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (data + DNS_QUESTION_OFFSET > data_end)
        return TC_ACT_UNSPEC;

    struct ethhdr *eth = data;
    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_UNSPEC;

    struct iphdr *ip = (void *)(eth + 1);
    // fixed offsets require ipv4 without options. fragmented datagrams must be
    // reassembled before their dns question can be interpreted.
    if (ip->ihl_version != 0x45 || ip->protocol != IPPROTO_UDP ||
        (ntohs(ip->frag_off) & 0x3fff) != 0 || ip->ttl == 0)
        return TC_ACT_UNSPEC;

    __u16 ip_len = ntohs(ip->tot_len);
    if (ip_len < 20 + 8 + DNS_HEADER_SIZE || ip_len > skb->len - 14)
        return TC_ACT_UNSPEC;

    __u32 src_ip = ip->saddr;
    __u32 src_host = ntohl(src_ip);
    // unspecified, broadcast, multicast, and loopback addresses are not peers.
    if (src_host == 0 || src_host == 0xffffffff ||
        (src_host & 0xf0000000) == 0xe0000000 ||
        (src_host & 0xff000000) == 0x7f000000)
        return TC_ACT_UNSPEC;

    struct udphdr *udp = (void *)((char *)ip + 20);
    if (udp->dest != htons(DNS_PORT))
        return TC_ACT_UNSPEC;

    __u16 udp_len = ntohs(udp->len);
    if (udp_len < 8 + DNS_HEADER_SIZE + 2 + DNS_QUESTION_FIELDS_SIZE ||
        udp_len > 512 || udp_len != ip_len - 20)
        return TC_ACT_UNSPEC;

    __u8 *dns = data + DNS_HEADER_OFFSET;
    // handle standard queries with one question and no other sections.
    if ((dns[2] & 0xf8) != 0 || dns[4] != 0 || dns[5] != 1 ||
        dns[6] != 0 || dns[7] != 0 || dns[8] != 0 || dns[9] != 0 ||
        dns[10] != 0 || dns[11] != 0)
        return TC_ACT_UNSPEC;

    // leave room for qtype and qclass inside the declared udp payload. ethernet
    // padding and bytes beyond the ip datagram cannot complete the question.
    __u32 question_len = udp_len - 8 - DNS_HEADER_SIZE;
    __u32 read_len = question_len - DNS_QUESTION_FIELDS_SIZE;
    if (read_len > 64)
        read_len = 64;
    char key_buf[64] = {};
    if (bpf_skb_load_bytes(skb, DNS_QUESTION_OFFSET, key_buf, read_len) != 0)
        return TC_ACT_UNSPEC;

    __u32 wire_len = find_name_length(key_buf, read_len);
    if (wire_len == 0 || wire_len > 63 ||
        wire_len + DNS_QUESTION_FIELDS_SIZE != question_len)
        return TC_ACT_UNSPEC;

    // the first read can include question fields. map keys contain only the
    // name and zero padding, so reload exactly the validated name.
    __builtin_memset(key_buf, 0, sizeof(key_buf));
    if (bpf_skb_load_bytes(skb, DNS_QUESTION_OFFSET, key_buf, wire_len) != 0)
        return TC_ACT_UNSPEC;

    __u8 question_fields[DNS_QUESTION_FIELDS_SIZE] = {};
    __u32 fields_offset = DNS_QUESTION_OFFSET + wire_len;
    if (bpf_skb_load_bytes(skb, fields_offset, question_fields,
                           sizeof(question_fields)) != 0)
        return TC_ACT_UNSPEC;
    if (question_fields[0] != 0 || question_fields[1] != 1 ||
        question_fields[2] != 0 || question_fields[3] != 1)
        return TC_ACT_UNSPEC; // only a records in the internet class

    __u32 *ip_addr = bpf_map_lookup_elem(&service_names, key_buf);
    if (!ip_addr)
        return TC_ACT_UNSPEC;

    __u32 resolved_ip = *ip_addr;

    // -- save header fields before resize --
    __u8 src_mac[6], dst_mac[6];
    __builtin_memcpy(dst_mac, eth->h_dest, 6);
    __builtin_memcpy(src_mac, eth->h_source, 6);

    // src_ip already validated above
    __u32 dst_ip = ip->daddr;
    __u16 old_ip_len = ip->tot_len;
    __u16 src_port = udp->source;
    __u16 dst_port = udp->dest;

    // -- compute response layout --
    // SECURITY: Check for integer overflow in offset calculation
    __u32 answer_offset = fields_offset + 4; // past name + qtype + qclass
    __u32 new_pkt_len = answer_offset + 16;  // 16-byte answer RR
    
    // Validate sizes are reasonable
    if (answer_offset < DNS_QUESTION_OFFSET || new_pkt_len > 512 || new_pkt_len < answer_offset)
        return TC_ACT_UNSPEC;

    // -- resize packet --
    if (bpf_skb_change_tail(skb, new_pkt_len, 0) != 0)
        return TC_ACT_UNSPEC;

    // re-read data pointers after resize
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    // SECURITY: Validate new packet size
    if (data + MIN_DNS_PACKET_SIZE > data_end)
        return TC_ACT_UNSPEC;
    if (data + new_pkt_len > data_end)
        return TC_ACT_UNSPEC;

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

    // 6. update IP checksum AFTER all direct packet writes
    bpf_l3_csum_replace(skb, 24, old_ip_len, new_ip_len, 2);

    // 7. write answer RR at validated offset
    __u8 answer[16] = {
        0xC0, 0x0C,                   // name pointer (offset 12 in DNS msg)
        0x00, 0x01,                   // TYPE = A
        0x00, 0x01,                   // CLASS = IN
        0x00, 0x00, 0x00, 0x05,       // TTL = 5 seconds
        0x00, 0x04,                   // RDLENGTH = 4
        0, 0, 0, 0                    // RDATA (filled below)
    };
    __builtin_memcpy(&answer[12], &resolved_ip, 4);

    // SECURITY: Verify answer_offset is still valid after resize
    if (answer_offset + 16 > new_pkt_len)
        return TC_ACT_UNSPEC;

    if (bpf_skb_store_bytes(skb, answer_offset, answer, 16, 0) != 0)
        return TC_ACT_UNSPEC;

    return bpf_redirect(skb->ifindex, 0);
}

char _license[] SEC("license") = "GPL";
