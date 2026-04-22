const std = @import("std");
const posix = std.posix;
const log = @import("../../lib/log.zig");
const attach_support = @import("attach_support.zig");
const common = @import("common.zig");
const map_support = @import("map_support.zig");
const program_support = @import("program_support.zig");
const resource_support = @import("resource_support.zig");

const dns_intercept = @import("../bpf/dns_intercept.zig");

pub const DnsInterceptor = struct {
    prog_fd: posix.fd_t,
    map_fd: posix.fd_t,
    if_index: u32,

    pub fn updateService(self: *const DnsInterceptor, name: []const u8, ip_addr: [4]u8) void {
        var key = makeKey(name) orelse return;

        map_support.mapUpdate(self.map_fd, &key, &ip_addr) catch |e| {
            log.warn("ebpf: dns map update failed for '{s}': {}", .{ name, e });
        };
    }

    pub fn deleteService(self: *const DnsInterceptor, name: []const u8) bool {
        var key = makeKey(name) orelse return false;
        return map_support.mapDelete(self.map_fd, &key);
    }

    pub fn lookupService(self: *const DnsInterceptor, name: []const u8) ?[4]u8 {
        var key = makeKey(name) orelse return null;
        var ip_addr: [4]u8 = undefined;
        if (!map_support.mapLookup(self.map_fd, &key, &ip_addr)) return null;
        return ip_addr;
    }

    pub fn deinit(self: *DnsInterceptor) void {
        attach_support.detachTC(self.if_index) catch |e| {
            log.debug("ebpf: failed to detach DNS interceptor: {}", .{e});
        };
        if (self.prog_fd >= 0) {
            @import("compat").posix.close(self.prog_fd);
            resource_support.releaseBpfFd();
            self.prog_fd = -1;
        }
        if (self.map_fd >= 0) {
            @import("compat").posix.close(self.map_fd);
            resource_support.releaseBpfFd();
            self.map_fd = -1;
        }
    }
};

pub fn makeKey(name: []const u8) ?[64]u8 {
    if (name.len == 0 or name.len > 62) return null;

    var key: [64]u8 = [_]u8{0} ** 64;
    var pos: usize = 0;
    var label_start: usize = 0;

    for (name, 0..) |c, i| {
        if (c == '.') {
            const label_len = i - label_start;
            if (label_len == 0 or label_len > 63) return null;
            if (pos + 1 + label_len >= 63) return null;
            key[pos] = @intCast(label_len);
            pos += 1;
            @memcpy(key[pos .. pos + label_len], name[label_start..i]);
            pos += label_len;
            label_start = i + 1;
        }
    }

    const label_len = name.len - label_start;
    if (label_len == 0 or label_len > 63) return null;
    if (pos + 1 + label_len >= 63) return null;
    key[pos] = @intCast(label_len);
    pos += 1;
    @memcpy(key[pos .. pos + label_len], name[label_start..name.len]);
    pos += label_len;
    key[pos] = 0;
    return key;
}

pub fn load(bridge_if_index: u32) common.EbpfError!DnsInterceptor {
    const map_def = dns_intercept.maps[0];
    const map_fd = try map_support.createMap(
        @enumFromInt(map_def.map_type),
        map_def.key_size,
        map_def.value_size,
        map_def.max_entries,
    );
    errdefer {
        @import("compat").posix.close(map_fd);
        resource_support.releaseBpfFd();
    }

    var map_fds = [_]posix.fd_t{map_fd};
    const prog_fd = try program_support.loadProgram(dns_intercept, &map_fds);
    errdefer {
        @import("compat").posix.close(prog_fd);
        resource_support.releaseBpfFd();
    }

    try attach_support.attachTC(bridge_if_index, .ingress, prog_fd, 1);

    return .{
        .prog_fd = prog_fd,
        .map_fd = map_fd,
        .if_index = bridge_if_index,
    };
}
