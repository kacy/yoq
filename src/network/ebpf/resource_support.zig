const std = @import("std");
const log = @import("../../lib/log.zig");
const common = @import("common.zig");

pub const max_key_size = 512;
pub const max_value_size = 4096;
pub const max_map_entries = 1048576;
pub const max_total_fds = 128;

var total_bpf_fds: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

const CircuitBreaker = struct {
    mutex: @import("compat").Mutex,
    failures: u32,
    last_failure_time: i64,
    threshold: u32,
    reset_timeout_ms: i64,

    fn init(threshold: u32, reset_timeout_ms: i64) CircuitBreaker {
        return .{
            .mutex = .{},
            .failures = 0,
            .last_failure_time = 0,
            .threshold = threshold,
            .reset_timeout_ms = reset_timeout_ms,
        };
    }

    fn allow(self: *CircuitBreaker) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.failures < self.threshold) return true;

        const now = @import("compat").milliTimestamp();
        if (now - self.last_failure_time > self.reset_timeout_ms) {
            self.failures = 0;
            self.last_failure_time = 0;
            return true;
        }

        return false;
    }

    fn recordSuccess(self: *CircuitBreaker) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.failures > 0) {
            self.failures = 0;
        }
    }

    fn recordFailure(self: *CircuitBreaker) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.failures += 1;
        self.last_failure_time = @import("compat").milliTimestamp();
    }
};

var map_op_circuit_breaker = CircuitBreaker.init(5, 30000);

pub fn validateMapCreate(key_size: u32, value_size: u32, max_entries: u32) common.EbpfError!void {
    if (key_size == 0 or key_size > max_key_size) {
        log.err("ebpf: invalid key size {d}, must be 1-{d}", .{ key_size, max_key_size });
        return common.EbpfError.InvalidParameter;
    }

    if (value_size == 0 or value_size > max_value_size) {
        log.err("ebpf: invalid value size {d}, must be 1-{d}", .{ value_size, max_value_size });
        return common.EbpfError.InvalidParameter;
    }

    if (max_entries == 0 or max_entries > max_map_entries) {
        log.err("ebpf: invalid max_entries {d}, must be 1-{d}", .{ max_entries, max_map_entries });
        return common.EbpfError.InvalidParameter;
    }
}

pub fn reserveBpfFd() common.EbpfError!void {
    const prev = total_bpf_fds.fetchAdd(1, .acq_rel);
    if (prev >= max_total_fds) {
        _ = total_bpf_fds.fetchSub(1, .acq_rel);
        log.err("ebpf: too many BPF resources in use ({d}/{d})", .{ prev, max_total_fds });
        return common.EbpfError.ResourceExhausted;
    }
}

pub fn releaseBpfFd() void {
    const current = total_bpf_fds.load(.acquire);
    if (current == 0) {
        log.warn("ebpf: attempted to release untracked BPF fd", .{});
        return;
    }
    _ = total_bpf_fds.fetchSub(1, .acq_rel);
}

pub fn allowMapOp() bool {
    return map_op_circuit_breaker.allow();
}

pub fn recordMapOpSuccess() void {
    map_op_circuit_breaker.recordSuccess();
}

pub fn recordMapOpFailure() void {
    map_op_circuit_breaker.recordFailure();
}
