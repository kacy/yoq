const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;
const log = @import("../../lib/log.zig");
const attach_support = @import("attach_support.zig");
const common = @import("common.zig");
const map_support = @import("map_support.zig");
const program_support = @import("program_support.zig");
const resource_support = @import("resource_support.zig");

const policy_prog = @import("../bpf/policy.zig");

pub const PolicyKey = extern struct {
    src_ip: u32,
    dst_ip: u32,
};

pub const PolicyEnforcer = struct {
    prog_fd: posix.fd_t,
    policy_fd: posix.fd_t,
    isolation_fd: posix.fd_t,
    if_index: u32,

    pub fn addDeny(self: *const PolicyEnforcer, src_ip: u32, dst_ip: u32) void {
        var key = PolicyKey{ .src_ip = src_ip, .dst_ip = dst_ip };
        var action: u8 = 0;
        map_support.mapUpdate(self.policy_fd, std.mem.asBytes(&key), std.mem.asBytes(&action)) catch |e| {
            log.warn("ebpf: failed to add deny rule for {x} -> {x}: {}", .{ src_ip, dst_ip, e });
        };
    }

    pub fn removeDeny(self: *const PolicyEnforcer, src_ip: u32, dst_ip: u32) void {
        var key = PolicyKey{ .src_ip = src_ip, .dst_ip = dst_ip };
        _ = map_support.mapDelete(self.policy_fd, std.mem.asBytes(&key));
    }

    pub fn addAllow(self: *const PolicyEnforcer, src_ip: u32, dst_ip: u32) void {
        var key = PolicyKey{ .src_ip = src_ip, .dst_ip = dst_ip };
        var action: u8 = 1;
        map_support.mapUpdate(self.policy_fd, std.mem.asBytes(&key), std.mem.asBytes(&action)) catch |e| {
            log.warn("ebpf: failed to add allow rule for {x} -> {x}: {}", .{ src_ip, dst_ip, e });
        };
    }

    pub fn removeAllow(self: *const PolicyEnforcer, src_ip: u32, dst_ip: u32) void {
        var key = PolicyKey{ .src_ip = src_ip, .dst_ip = dst_ip };
        _ = map_support.mapDelete(self.policy_fd, std.mem.asBytes(&key));
    }

    pub fn isolate(self: *const PolicyEnforcer, src_ip: u32) void {
        var key = src_ip;
        var flag: u8 = 1;
        map_support.mapUpdate(self.isolation_fd, std.mem.asBytes(&key), std.mem.asBytes(&flag)) catch |e| {
            log.warn("ebpf: failed to isolate IP {x}: {}", .{ src_ip, e });
        };
    }

    pub fn unisolate(self: *const PolicyEnforcer, src_ip: u32) void {
        var key = src_ip;
        _ = map_support.mapDelete(self.isolation_fd, std.mem.asBytes(&key));
    }

    pub fn clear(self: *const PolicyEnforcer) void {
        clearMap(PolicyKey, self.policy_fd, policy_prog.maps[0].max_entries);
        clearMap(u32, self.isolation_fd, policy_prog.maps[1].max_entries);
    }

    pub fn deinit(self: *PolicyEnforcer) void {
        attach_support.detachTC(self.if_index) catch |e| {
            log.debug("ebpf: failed to detach policy enforcer: {}", .{e});
        };
        if (self.prog_fd >= 0) {
            linux_platform.posix.close(self.prog_fd);
            resource_support.releaseBpfFd();
        }
        if (self.policy_fd >= 0) {
            linux_platform.posix.close(self.policy_fd);
            resource_support.releaseBpfFd();
        }
        if (self.isolation_fd >= 0) {
            linux_platform.posix.close(self.isolation_fd);
            resource_support.releaseBpfFd();
        }
    }
};

pub fn load(bridge_if_index: u32) common.EbpfError!PolicyEnforcer {
    const policy_fd = try map_support.createMap(
        @enumFromInt(policy_prog.maps[0].map_type),
        policy_prog.maps[0].key_size,
        policy_prog.maps[0].value_size,
        policy_prog.maps[0].max_entries,
    );
    errdefer {
        linux_platform.posix.close(policy_fd);
        resource_support.releaseBpfFd();
    }

    const isolation_fd = try map_support.createMap(
        @enumFromInt(policy_prog.maps[1].map_type),
        policy_prog.maps[1].key_size,
        policy_prog.maps[1].value_size,
        policy_prog.maps[1].max_entries,
    );
    errdefer {
        linux_platform.posix.close(isolation_fd);
        resource_support.releaseBpfFd();
    }

    var map_fds = [_]posix.fd_t{ policy_fd, isolation_fd };
    const prog_fd = try program_support.loadProgram(policy_prog, &map_fds);
    errdefer {
        linux_platform.posix.close(prog_fd);
        resource_support.releaseBpfFd();
    }

    try attach_support.attachTC(bridge_if_index, .ingress, prog_fd, 0);

    return .{
        .prog_fd = prog_fd,
        .policy_fd = policy_fd,
        .isolation_fd = isolation_fd,
        .if_index = bridge_if_index,
    };
}

fn clearMap(comptime Key: type, map_fd: posix.fd_t, max_entries: u32) void {
    var next_key: Key = std.mem.zeroes(Key);
    var removed: u32 = 0;

    while (removed <= max_entries) : (removed += 1) {
        var start_key: Key = std.mem.zeroes(Key);
        if (!map_support.mapGetNextKey(map_fd, std.mem.asBytes(&start_key), std.mem.asBytes(&next_key))) return;
        _ = map_support.mapDelete(map_fd, std.mem.asBytes(&next_key));
    }

    log.warn("ebpf: stopped clearing policy map after {d} entries", .{max_entries});
}
