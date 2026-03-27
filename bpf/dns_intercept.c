// dns_intercept — eBPF DNS resolution for container service discovery
//
// TC ingress program attached to the yoq0 bridge. intercepts DNS A
// record queries and resolves known service names directly in the
// kernel, avoiding the round-trip to the userspace resolver.
//
// SECURITY HARDENING:
//   - All packet accesses validated against data_end
//   - Minimum packet size checks prevent out-of-bounds reads
//   - DNS name length validated using bounded fixed-offset checks only
//   - Integer overflow protection on offset calculations
//   - All variable-length reads use bpf_skb_load_bytes
//
// BPF verifier constraints:
//   - all packet access uses fixed offsets (IHL forced to 5)
//   - all stack reads use compile-time constant offsets (no variable offsets)
//   - no loops with variable bounds for stack access
//   - uses bpf_skb_load_bytes/bpf_skb_store_bytes for variable offsets
//   - stays within 512-byte stack limit
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
    .max_entries = 1024,
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

// Simple DNS name length finder - returns position of null terminator + 1
// Uses fully unrolled checks to satisfy BPF verifier
static __attribute__((always_inline)) __u32
find_name_length(const char *name, __u32 max_len)
{
    // Bounds check for verifier
    if (max_len < 2 || max_len > 64) return 0;
    
    // Check first byte
    if (name[0] == 0) return 0; // Empty name
    if (((__u8)name[0] & 0xC0) == 0xC0) return 0; // Compression pointer
    
    // Fully unrolled null terminator search
    // Each check uses a compile-time constant offset
    if (1 < max_len && name[1] == 0) return 2;
    if (2 < max_len && name[2] == 0) return 3;
    if (3 < max_len && name[3] == 0) return 4;
    if (4 < max_len && name[4] == 0) return 5;
    if (5 < max_len && name[5] == 0) return 6;
    if (6 < max_len && name[6] == 0) return 7;
    if (7 < max_len && name[7] == 0) return 8;
    if (8 < max_len && name[8] == 0) return 9;
    if (9 < max_len && name[9] == 0) return 10;
    if (10 < max_len && name[10] == 0) return 11;
    if (11 < max_len && name[11] == 0) return 12;
    if (12 < max_len && name[12] == 0) return 13;
    if (13 < max_len && name[13] == 0) return 14;
    if (14 < max_len && name[14] == 0) return 15;
    if (15 < max_len && name[15] == 0) return 16;
    if (16 < max_len && name[16] == 0) return 17;
    if (17 < max_len && name[17] == 0) return 18;
    if (18 < max_len && name[18] == 0) return 19;
    if (19 < max_len && name[19] == 0) return 20;
    if (20 < max_len && name[20] == 0) return 21;
    if (21 < max_len && name[21] == 0) return 22;
    if (22 < max_len && name[22] == 0) return 23;
    if (23 < max_len && name[23] == 0) return 24;
    if (24 < max_len && name[24] == 0) return 25;
    if (25 < max_len && name[25] == 0) return 26;
    if (26 < max_len && name[26] == 0) return 27;
    if (27 < max_len && name[27] == 0) return 28;
    if (28 < max_len && name[28] == 0) return 29;
    if (29 < max_len && name[29] == 0) return 30;
    if (30 < max_len && name[30] == 0) return 31;
    if (31 < max_len && name[31] == 0) return 32;
    if (32 < max_len && name[32] == 0) return 33;
    if (33 < max_len && name[33] == 0) return 34;
    if (34 < max_len && name[34] == 0) return 35;
    if (35 < max_len && name[35] == 0) return 36;
    if (36 < max_len && name[36] == 0) return 37;
    if (37 < max_len && name[37] == 0) return 38;
    if (38 < max_len && name[38] == 0) return 39;
    if (39 < max_len && name[39] == 0) return 40;
    if (40 < max_len && name[40] == 0) return 41;
    if (41 < max_len && name[41] == 0) return 42;
    if (42 < max_len && name[42] == 0) return 43;
    if (43 < max_len && name[43] == 0) return 44;
    if (44 < max_len && name[44] == 0) return 45;
    if (45 < max_len && name[45] == 0) return 46;
    if (46 < max_len && name[46] == 0) return 47;
    if (47 < max_len && name[47] == 0) return 48;
    if (48 < max_len && name[48] == 0) return 49;
    if (49 < max_len && name[49] == 0) return 50;
    if (50 < max_len && name[50] == 0) return 51;
    if (51 < max_len && name[51] == 0) return 52;
    if (52 < max_len && name[52] == 0) return 53;
    if (53 < max_len && name[53] == 0) return 54;
    if (54 < max_len && name[54] == 0) return 55;
    if (55 < max_len && name[55] == 0) return 56;
    if (56 < max_len && name[56] == 0) return 57;
    if (57 < max_len && name[57] == 0) return 58;
    if (58 < max_len && name[58] == 0) return 59;
    if (59 < max_len && name[59] == 0) return 60;
    if (60 < max_len && name[60] == 0) return 61;
    if (61 < max_len && name[61] == 0) return 62;
    if (62 < max_len && name[62] == 0) return 63;
    if (63 < max_len && name[63] == 0) return 64;
    
    return 0; // No null terminator found
}

SEC("tc_ingress")
int dns_intercept(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // SECURITY: Check minimum packet size before any parsing
    // We need at least: eth(14) + ip(20) + udp(8) + dns(12) = 54 bytes
    if (data + DNS_QUESTION_OFFSET > data_end)
        return TC_ACT_OK;

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
    
    // SECURITY: Validate IP total length makes sense
    __u16 ip_tot_len = ntohs(ip->tot_len);
    if (ip_tot_len < 40 || ip_tot_len > 1500) // min: IP(20)+UDP(8)+payload, max: typical MTU
        return TC_ACT_OK;
    
    // SECURITY: Validate TTL is reasonable (prevent routing loops and suspicious packets)
    // Normal DNS queries should have TTL >= 1, but very high TTL (>128) might be suspicious
    if (ip->ttl < 1 || ip->ttl > 128)
        return TC_ACT_OK;
    
    // SECURITY: Reject obviously spoofed or invalid source IPs
    // 0.0.0.0, broadcast, multicast, loopback as source
    __u32 src_ip = ip->saddr;
    if (src_ip == 0 || src_ip == 0xFFFFFFFF ||          // 0.0.0.0, 255.255.255.255
        (src_ip & 0xF0000000) == 0xE0000000 ||          // 224.0.0.0/4 multicast
        (src_ip & 0xFF000000) == 0x7F000000)           // 127.0.0.0/8 loopback
        return TC_ACT_OK;

    // -- parse UDP header (offset 34, 8 bytes) --
    struct udphdr *udp = (void *)((char *)ip + 20);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;

    if (udp->dest != htons(DNS_PORT))
        return TC_ACT_OK;
    
    // SECURITY: Validate UDP length
    __u16 udp_len = ntohs(udp->len);
    if (udp_len < 8 || udp_len > 512) // min UDP header, max DNS over UDP
        return TC_ACT_OK;

    // -- parse DNS header (offset 42, 12 bytes) --
    __u8 *dns = data + 42;
    if ((void *)(dns + DNS_HEADER_SIZE) > data_end)
        return TC_ACT_OK;

    // QR=0 (query)
    if (dns[2] & 0x80)
        return TC_ACT_OK;

    // QDCOUNT=1 (we only handle single queries)
    __u16 qdcount = (dns[4] << 8) | dns[5];
    if (qdcount != 1)
        return TC_ACT_OK;
    
    // SECURITY: Check for additional sections that could indicate malformed packets
    __u16 ancount = (dns[6] << 8) | dns[7];
    __u16 nscount = (dns[8] << 8) | dns[9];
    __u16 arcount = (dns[10] << 8) | dns[11];
    if (ancount != 0 || nscount != 0 || arcount != 0)
        return TC_ACT_OK; // Only accept pure queries, not responses

    // -- copy question name to stack (offset 54, up to 64 bytes) --
    // SECURITY: Read only what we need (64 bytes max for key buffer)
    // The packet might be shorter, bpf_skb_load_bytes will handle it
    char key_buf[64] = {};
    
    // Calculate safe read length - don't exceed packet bounds
    // Use unsigned arithmetic and explicit bounds for verifier
    __u32 pkt_len = (long)data_end - (long)data;
    if (pkt_len > 1500) return TC_ACT_OK; // Sanity check
    
    __u32 read_len = 64;
    if (DNS_QUESTION_OFFSET + 64 > pkt_len) {
        read_len = pkt_len - DNS_QUESTION_OFFSET;
        // Explicitly bound read_len for verifier - ensure it's at least 2
        if (read_len > 64) read_len = 64;
        if (read_len > 512) read_len = 64; // Sanity cap
    }
    
    // Final bounds check: must be 2-64 bytes (ensures positive, verifier-safe value)
    if (read_len < 2 || read_len > 64)
        return TC_ACT_OK;
    
    if (bpf_skb_load_bytes(skb, DNS_QUESTION_OFFSET, key_buf, read_len) != 0)
        return TC_ACT_OK;

    // -- validate the DNS name is well-formed --
    __u32 wire_len = find_name_length(key_buf, read_len);
    if (wire_len == 0 || wire_len > 63) // 63 = max we can handle in our 64-byte key
        return TC_ACT_OK;

    // -- map lookup --
    __u32 *ip_addr = bpf_map_lookup_elem(&service_names, key_buf);
    if (!ip_addr)
        return TC_ACT_OK; // miss — pass to userspace

    // save resolved IP before any packet modifications
    __u32 resolved_ip = *ip_addr;

    // -- validate QTYPE=A and QCLASS=IN --
    __u8 qtqc[4] = {};
    __u32 qtqc_offset = DNS_QUESTION_OFFSET + wire_len;
    
    // SECURITY: Ensure we can read 4 bytes for QTYPE+QCLASS
    if (qtqc_offset + 4 > pkt_len)
        return TC_ACT_OK;
    
    if (bpf_skb_load_bytes(skb, qtqc_offset, qtqc, 4) != 0)
        return TC_ACT_OK;

    __u16 qtype = (qtqc[0] << 8) | qtqc[1];
    __u16 qclass = (qtqc[2] << 8) | qtqc[3];
    if (qtype != 1 || qclass != 1) // A / IN
        return TC_ACT_OK;

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
    __u32 answer_offset = qtqc_offset + 4; // past name + qtype + qclass
    __u32 new_pkt_len = answer_offset + 16;  // 16-byte answer RR
    
    // Validate sizes are reasonable
    if (answer_offset < DNS_QUESTION_OFFSET || new_pkt_len > 512 || new_pkt_len < answer_offset)
        return TC_ACT_OK;

    // -- resize packet --
    if (bpf_skb_change_tail(skb, new_pkt_len, 0) != 0)
        return TC_ACT_OK;

    // re-read data pointers after resize
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    // SECURITY: Validate new packet size
    if (data + MIN_DNS_PACKET_SIZE > data_end)
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
        return TC_ACT_OK;

    if (bpf_skb_store_bytes(skb, answer_offset, answer, 16, 0) != 0)
        return TC_ACT_OK;

    return bpf_redirect(skb->ifindex, 0);
}

char _license[] SEC("license") = "GPL";
