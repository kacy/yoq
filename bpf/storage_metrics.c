// storage_metrics.c — per-cgroup block I/O tracking
//
// attached to tracepoint block:block_rq_complete to count read/write
// bytes and IOPS per cgroup ID. passive observer — never modifies or
// drops requests.
//
// the userspace StorageMetricsCollector reads the map to report
// per-container I/O stats via /v1/metrics?mode=storage_io.
//
// compile with:
//   clang -target bpf -O2 -g -c bpf/storage_metrics.c -o bpf/storage_metrics.o

#include "common.h"

// -- BPF helpers not in common.h --

static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)80;

// -- per-cgroup I/O metrics --

struct io_metrics {
    __u64 read_bytes;
    __u64 write_bytes;
    __u64 read_ops;
    __u64 write_ops;
};

// -- BPF map: cgroup_id -> io_metrics --

struct bpf_map_def SEC("maps") storage_metrics_map = {
    .type        = BPF_MAP_TYPE_LRU_HASH,
    .key_size    = sizeof(__u64),
    .value_size  = sizeof(struct io_metrics),
    .max_entries = 1024,
    .map_flags   = 0,
};

// -- tracepoint context for block:block_rq_complete --
//
// fields from /sys/kernel/debug/tracing/events/block/block_rq_complete/format:
//   dev, sector, nr_sector, errors, rwbs
// we use a raw tracepoint context (array of __u64) to access these fields.

struct tp_block_rq_complete {
    // common fields (padding)
    __u64 __pad;
    // dev_t
    __u32 dev;
    // sector
    __u64 sector;
    // nr_sectors
    __u32 nr_sector;
    // errors
    __s32 errors;
    // rwbs[8] — R/W/D/F/S flags
    char rwbs[8];
};

SEC("tracepoint/block/block_rq_complete")
int storage_metrics_count(struct tp_block_rq_complete *ctx)
{
    // get cgroup ID for the current task
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (cgroup_id == 0)
        return 0;

    // determine if read or write from rwbs flags
    // R = read, W = write, D = discard (ignore), F = flush (ignore)
    char rw = ctx->rwbs[0];
    __u8 is_read = (rw == 'R') ? 1 : 0;
    __u8 is_write = (rw == 'W') ? 1 : 0;

    if (!is_read && !is_write)
        return 0;

    // calculate bytes (nr_sector * 512)
    __u64 bytes = (__u64)ctx->nr_sector * 512;

    // cap at reasonable maximum to prevent overflow abuse
    if (bytes > 1073741824) // 1 GiB max per request
        return 0;

    struct io_metrics *existing = bpf_map_lookup_elem(&storage_metrics_map, &cgroup_id);
    if (existing) {
        if (is_read) {
            __sync_fetch_and_add(&existing->read_bytes, bytes);
            __sync_fetch_and_add(&existing->read_ops, 1);
        } else {
            __sync_fetch_and_add(&existing->write_bytes, bytes);
            __sync_fetch_and_add(&existing->write_ops, 1);
        }
    } else {
        struct io_metrics new_entry = {};
        if (is_read) {
            new_entry.read_bytes = bytes;
            new_entry.read_ops = 1;
        } else {
            new_entry.write_bytes = bytes;
            new_entry.write_ops = 1;
        }
        bpf_map_update_elem(&storage_metrics_map, &cgroup_id, &new_entry, 0);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
