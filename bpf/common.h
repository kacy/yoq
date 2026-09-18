// shared types and helpers for bpf programs
//
// provides the minimal subset of kernel types needed by yoq's bpf
// programs. we define these ourselves
// rather than pulling in vmlinux.h or kernel headers to keep the bpf
// build self-contained and reproducible.
//
// compiled with: clang -target bpf -O2 -g -c

#ifndef __YOQ_BPF_COMMON_H
#define __YOQ_BPF_COMMON_H

// -- fixed-width types --

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

// -- section macros --

#define SEC(name) __attribute__((section(name), used))

// -- tc action return codes --

#define TC_ACT_UNSPEC  -1
#define TC_ACT_OK       0
#define TC_ACT_SHOT     2
#define TC_ACT_REDIRECT 7

// -- bpf map types --

#define BPF_MAP_TYPE_HASH     1
#define BPF_MAP_TYPE_ARRAY    2
#define BPF_MAP_TYPE_LRU_HASH 9

// map update modes
#define BPF_ANY     0
#define BPF_NOEXIST 1

// checksum replacement flags
#define BPF_F_PSEUDO_HDR      0x10
#define BPF_F_MARK_MANGLED_0  0x20

// -- bpf map definition --
//
// classic bpf_map_def style (pre-btf). maps defined with this struct
// in a SEC("maps") section are picked up by our ELF extractor tool
// (tools/bpf_gen.zig) and turned into comptime zig arrays.

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

// -- bpf helper functions --
//
// these are function pointer casts to bpf helper ids. the verifier
// resolves them to actual kernel helpers at load time.

static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
    (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key,
                                   const void *value, __u64 flags) =
    (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) =
    (void *)3;

// -- checksum helpers --
//
// used by both dns interceptor (ip length rewrite) and load balancer
// (dnat address rewrite) to incrementally update l3/l4 checksums.

static long (*bpf_l3_csum_replace)(void *skb, __u32 offset, __u64 from,
                                   __u64 to, __u64 size) = (void *)10;
static long (*bpf_l4_csum_replace)(void *skb, __u32 offset, __u64 from,
                                   __u64 to, __u64 flags) = (void *)11;

// -- tc sk_buff context --
//
// subset of __sk_buff fields used by our programs. the kernel maps
// this to the real sk_buff at runtime; field order and widths must match.

struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
    __u32 napi_id;
};

// -- network header helpers --
//
// ethernet, ipv4, udp header structs for packet parsing.
// packed to match wire format exactly.

struct ethhdr {
    __u8 h_dest[6];
    __u8 h_source[6];
    __u16 h_proto;
} __attribute__((packed));

struct iphdr {
    __u8 ihl_version; // upper nibble: version; lower nibble: header length in 32-bit words
    __u8 tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
} __attribute__((packed));

struct udphdr {
    __u16 source;
    __u16 dest;
    __u16 len;
    __u16 check;
} __attribute__((packed));

struct tcphdr {
    __u16 source;
    __u16 dest;
    __u32 seq;
    __u32 ack_seq;
    __u16 flags; // data offset:4, reserved:3, flags:9
    __u16 window;
    __u16 check;
    __u16 urg_ptr;
} __attribute__((packed));

// protocol numbers
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// useful macros
#define htons(x) __builtin_bswap16(x)
#define ntohs(x) __builtin_bswap16(x)
#define htonl(x) __builtin_bswap32(x)
#define ntohl(x) __builtin_bswap32(x)

// the more-fragments flag and fragment offset; the don't-fragment flag is allowed.
#define IPV4_FRAGMENT_MASK 0x3fff

// dns wire limits and offsets for an ethernet frame with a 20-byte ipv4 header

#define MIN_DNS_PACKET_SIZE   76   // eth(14) + ip(20) + udp(8) + dns(12) + name(2) + qt/qc(4) + answer(16)
#define MAX_DNS_NAME_LEN      63   // RFC 1035: max single label length
#define MAX_DNS_WIRE_LEN      255 // RFC 1035: max wire format name length (including length bytes)
#define DNS_QUESTION_OFFSET   54  // eth(14) + ip(20) + udp(8) + dns(12)

#endif // __YOQ_BPF_COMMON_H
