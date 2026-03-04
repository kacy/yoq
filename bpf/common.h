// common.h — shared types and helpers for BPF C programs
//
// provides the minimal subset of kernel types needed by yoq's BPF
// programs (DNS interceptor, load balancer). we define these ourselves
// rather than pulling in vmlinux.h or kernel headers to keep the BPF
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

// -- TC action return codes --

#define TC_ACT_OK       0
#define TC_ACT_SHOT     2
#define TC_ACT_REDIRECT 7

// -- BPF map types --

#define BPF_MAP_TYPE_HASH     1
#define BPF_MAP_TYPE_ARRAY    2
#define BPF_MAP_TYPE_LRU_HASH 9

// -- BPF map definition --
//
// classic bpf_map_def style (pre-BTF). maps defined with this struct
// in a SEC("maps") section are picked up by our ELF extractor tool
// (tools/bpf_gen.zig) and turned into comptime Zig arrays.

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

// -- BPF helper functions --
//
// these are function pointer casts to BPF helper IDs. the verifier
// resolves them to actual kernel helpers at load time.

static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
    (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key,
                                   const void *value, __u64 flags) =
    (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) =
    (void *)3;

// -- TC sk_buff context --
//
// subset of __sk_buff fields used by our programs. the kernel maps
// this to the real sk_buff at runtime — field order matters.

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
// ethernet, IPv4, UDP header structs for packet parsing.
// packed to match wire format exactly.

struct ethhdr {
    __u8 h_dest[6];
    __u8 h_source[6];
    __u16 h_proto;
} __attribute__((packed));

struct iphdr {
    __u8 ihl_version; // version:4, ihl:4 (we combine since BPF can't do bitfields)
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

#endif // __YOQ_BPF_COMMON_H
