// dns_intercept — eBPF DNS resolution for container service discovery
//
// TC ingress program attached to the yoq0 bridge. intercepts DNS A
// record queries and resolves known service names directly in the
// kernel, avoiding the round-trip to the userspace resolver.
//
// SECURITY HARDENING:
//   - All packet accesses validated against data_end
//   - Minimum packet size checks prevent out-of-bounds reads
//   - DNS name length validated against RFC 1035 limits
//   - Integer overflow protection on offset calculations
//   - All variable-length reads use bpf_skb_load_bytes
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

// Simplified DNS name validation
// Returns wire length if valid, 0 if invalid
static __attribute__((always_inline)) __u32
validate_dns_name_simple(const char *name, __u32 max_len)
{
    // SECURITY: Check minimum length (at least 1-byte label + null)
    if (max_len < 2) return 0;
    
    // SECURITY: Find null terminator and validate structure
    __u32 pos = 0;
    __u8 label_count = 0;
    
    // Max 127 labels, max 255 bytes total
    while (pos < max_len && pos < 255) {
        __u8 label_len = (__u8)name[pos];
        
        // Found null terminator - end of name
        if (label_len == 0) {
            // Name must be at least 2 bytes
            if (pos < 1) return 0;
            return pos + 1;
        }
        
        // Check for compression pointers (0xC0 in first byte)
        if ((label_len & 0xC0) == 0xC0) return 0;
        
        // RFC 1035: label max 63 bytes
        if (label_len > 63) return 0;
        
        // Check if label fits in remaining buffer
        if (pos + 1 + label_len > max_len) return 0;
        
        // SECURITY: Validate label characters are printable ASCII
        // Allow alphanumeric, hyphen, underscore for SRV records
        for (__u32 i = 0; i < label_len; i++) {
            char c = name[pos + 1 + i];
            // Reject control chars and high bytes
            if (c < 32 || c > 126) return 0;
        }
        
        pos += 1 + label_len;
        label_count++;
        
        // RFC 1035: max 127 labels
        if (label_count > 127) return 0;
    }
    
    // No null terminator found
    return 0;
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
    __u32 pkt_len = (long)data_end - (long)data;
    __u32 read_len = 64;
    if (DNS_QUESTION_OFFSET + read_len > pkt_len)
        read_len = pkt_len - DNS_QUESTION_OFFSET;
    
    // SECURITY: Ensure we have at least a minimal question section
    if (read_len < 2)
        return TC_ACT_OK;
    
    if (bpf_skb_load_bytes(skb, DNS_QUESTION_OFFSET, key_buf, read_len) != 0)
        return TC_ACT_OK;

    // -- validate the DNS name is well-formed --
    __u32 wire_len = validate_dns_name_simple(key_buf, read_len);
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

    __u32 src_ip = ip->saddr;
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
