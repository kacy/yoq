const std = @import("std");
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

    pub fn deinit(self: *PolicyEnforcer) void {
        attach_support.detachTC(self.if_index) catch |e| {
            log.debug("ebpf: failed to detach policy enforcer: {}", .{e});
        };
        if (self.prog_fd >= 0) {
            @import("compat").posix.close(self.prog_fd);
            resource_support.releaseBpfFd();
        }
        if (self.policy_fd >= 0) {
            @import("compat").posix.close(self.policy_fd);
            resource_support.releaseBpfFd();
        }
        if (self.isolation_fd >= 0) {
            @import("compat").posix.close(self.isolation_fd);
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
        @import("compat").posix.close(policy_fd);
        resource_support.releaseBpfFd();
    }

    const isolation_fd = try map_support.createMap(
        @enumFromInt(policy_prog.maps[1].map_type),
        policy_prog.maps[1].key_size,
        policy_prog.maps[1].value_size,
        policy_prog.maps[1].max_entries,
    );
    errdefer {
        @import("compat").posix.close(isolation_fd);
        resource_support.releaseBpfFd();
    }

    var map_fds = [_]posix.fd_t{ policy_fd, isolation_fd };
    const prog_fd = try program_support.loadProgram(policy_prog, &map_fds);
    errdefer {
        @import("compat").posix.close(prog_fd);
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
