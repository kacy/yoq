// block read/write completion events, grouped by the current task's cgroup.
//
// completion can run in an interrupt or worker context. that cgroup may
// differ from the request's origin, so these counters cannot identify the
// originating container reliably. partial completions count as separate events.

#include "common.h"

static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)80;

struct io_metrics {
    __u64 read_bytes;
    __u64 write_bytes;
    __u64 read_ops;
    __u64 write_ops;
};

struct bpf_map_def SEC("maps") storage_metrics_map = {
    .type        = BPF_MAP_TYPE_LRU_HASH,
    .key_size    = sizeof(__u64),
    .value_size  = sizeof(struct io_metrics),
    .max_entries = 1024,
    .map_flags   = 0,
};

// layout of the formatted block:block_rq_complete tracepoint event.
// offsets must match tracing/events/block/block_rq_complete/format.
struct tp_block_rq_complete {
    __u64 common_fields;
    __u32 dev;
    __u32 alignment_padding;
    __u64 sector;
    __u32 nr_sector;
    __s32 errors;
    char rwbs[8];
};

_Static_assert(__builtin_offsetof(struct tp_block_rq_complete, nr_sector) == 24,
               "block completion sector count offset changed");
_Static_assert(__builtin_offsetof(struct tp_block_rq_complete, rwbs) == 32,
               "block completion operation flags offset changed");

SEC("tracepoint/block/block_rq_complete")
int storage_metrics_count(struct tp_block_rq_complete *ctx)
{
    // discard, flush, and other operations have no read/write counters.
    char operation = ctx->rwbs[0];
    // blk_fill_rwbs places an optional preflush flag before the operation.
    if (operation == 'F')
        operation = ctx->rwbs[1];
    if (operation != 'R' && operation != 'W')
        return 0;

    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (cgroup_id == 0)
        return 0;

    // widen before converting 512-byte sectors to bytes.
    __u64 bytes = (__u64)ctx->nr_sector * 512;
    struct io_metrics *metrics = bpf_map_lookup_elem(&storage_metrics_map, &cgroup_id);
    if (!metrics) {
        // preserve a counter inserted by another cpu after the lookup.
        struct io_metrics empty = {};
        bpf_map_update_elem(&storage_metrics_map, &cgroup_id, &empty, BPF_NOEXIST);
        metrics = bpf_map_lookup_elem(&storage_metrics_map, &cgroup_id);
        if (!metrics)
            return 0;
    }

    if (operation == 'R') {
        __sync_fetch_and_add(&metrics->read_bytes, bytes);
        __sync_fetch_and_add(&metrics->read_ops, 1);
    } else {
        __sync_fetch_and_add(&metrics->write_bytes, bytes);
        __sync_fetch_and_add(&metrics->write_ops, 1);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
