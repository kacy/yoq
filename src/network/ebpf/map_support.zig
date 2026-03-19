const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;
const BPF = linux.BPF;
const log = @import("../../lib/log.zig");
const common = @import("common.zig");
const resource_support = @import("resource_support.zig");

pub fn createMap(
    map_type: BPF.MapType,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
) common.EbpfError!posix.fd_t {
    if (comptime builtin.os.tag != .linux) return common.EbpfError.NotSupported;

    try resource_support.validateMapCreate(key_size, value_size, max_entries);
    try resource_support.reserveBpfFd();

    const fd = BPF.map_create(map_type, key_size, value_size, max_entries) catch |e| {
        resource_support.releaseBpfFd();
        log.warn("ebpf: map_create failed (type={d}, key={d}, val={d}): {}", .{
            @intFromEnum(map_type), key_size, value_size, e,
        });
        return common.EbpfError.MapCreateFailed;
    };

    return fd;
}

pub fn mapLookup(map_fd: posix.fd_t, key: []const u8, value: []u8) bool {
    if (comptime builtin.os.tag != .linux) return false;

    if (key.len == 0 or key.len > resource_support.max_key_size) {
        log.warn("ebpf: mapLookup invalid key size {d}", .{key.len});
        return false;
    }
    if (value.len == 0 or value.len > resource_support.max_value_size) {
        log.warn("ebpf: mapLookup invalid value size {d}", .{value.len});
        return false;
    }

    BPF.map_lookup_elem(map_fd, key, value) catch return false;
    return true;
}

pub fn mapGetNextKey(map_fd: posix.fd_t, key: []const u8, next_key: []u8) bool {
    if (comptime builtin.os.tag != .linux) return false;

    if (key.len > resource_support.max_key_size) {
        log.warn("ebpf: mapGetNextKey invalid key size {d}", .{key.len});
        return false;
    }
    if (next_key.len == 0 or next_key.len > resource_support.max_key_size) {
        log.warn("ebpf: mapGetNextKey invalid next_key size {d}", .{next_key.len});
        return false;
    }

    const found = BPF.map_get_next_key(map_fd, key, next_key) catch return false;
    return found;
}

pub fn mapUpdate(map_fd: posix.fd_t, key: []const u8, value: []const u8) common.EbpfError!void {
    if (comptime builtin.os.tag != .linux) return common.EbpfError.NotSupported;

    if (!resource_support.allowMapOp()) {
        log.warn("ebpf: mapUpdate circuit breaker open - skipping update", .{});
        return common.EbpfError.MapUpdateFailed;
    }

    if (key.len == 0 or key.len > resource_support.max_key_size) {
        log.err("ebpf: mapUpdate invalid key size {d}, must be 1-{d}", .{ key.len, resource_support.max_key_size });
        resource_support.recordMapOpFailure();
        return common.EbpfError.InvalidParameter;
    }

    if (value.len == 0 or value.len > resource_support.max_value_size) {
        log.err("ebpf: mapUpdate invalid value size {d}, must be 1-{d}", .{ value.len, resource_support.max_value_size });
        resource_support.recordMapOpFailure();
        return common.EbpfError.InvalidParameter;
    }

    BPF.map_update_elem(map_fd, key, value, BPF.ANY) catch |e| {
        resource_support.recordMapOpFailure();
        const err_name = @errorName(e);
        if (std.mem.indexOf(u8, err_name, "NoSpace")) |_| {
            log.warn("ebpf: map_update failed: map is full", .{});
            return common.EbpfError.MapFull;
        }
        log.warn("ebpf: map_update failed: {} ({s})", .{ e, err_name });
        return common.EbpfError.MapUpdateFailed;
    };

    resource_support.recordMapOpSuccess();
}

pub fn mapDelete(map_fd: posix.fd_t, key: []const u8) bool {
    if (comptime builtin.os.tag != .linux) return false;

    if (key.len == 0 or key.len > resource_support.max_key_size) {
        log.warn("ebpf: mapDelete invalid key size {d}", .{key.len});
        return false;
    }

    BPF.map_delete_elem(map_fd, key) catch |e| {
        log.debug("ebpf: map_delete failed: {s}", .{@errorName(e)});
        return false;
    };
    return true;
}
