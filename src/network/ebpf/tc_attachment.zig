//! Replace only owned TC filters. Namespace inode locks serialize runtimes
//! sharing an interface, including processes using different local data paths.
const std = @import("std");
const linux = std.os.linux;
const platform = @import("linux_platform");
const nl = @import("../netlink.zig");
const common = @import("common.zig");
const attach_support = @import("attach_support.zig");
const alloc = std.heap.page_allocator;

pub const Component = enum(u32) {
    policy = 10,
    dns = 20,
    load_balancer = 30,
    metrics = 40,

    fn name(self: Component) []const u8 {
        return switch (self) {
            .policy => "yoq-policy",
            .dns => "yoq-dns",
            .load_balancer => "yoq-lb",
            .metrics => "yoq-metrics",
        };
    }
};

pub const Attachment = struct {
    if_index: u32,
    direction: common.Direction,
    component: Component,
    program_id: u32,

    pub fn isCurrent(self: Attachment) common.EbpfError!bool {
        const lock = acquireLock() catch return error.AttachFailed;
        defer platform.posix.close(lock);
        var filters = listFilters(self.if_index, self.direction) catch return error.AttachFailed;
        defer filters.deinit(alloc);
        for (filters.items) |filter| {
            if (self.matches(filter)) return true;
        }
        return false;
    }

    fn matches(self: Attachment, filter: Filter) bool {
        return filter.priority == @intFromEnum(self.component) and filter.handle == 1 and
            filter.program_id == self.program_id and std.mem.eql(u8, filter.name(), self.component.name());
    }

    pub fn detach(self: Attachment) common.EbpfError!void {
        const lock = acquireLock() catch return error.DetachFailed;
        defer platform.posix.close(lock);
        var filters = listFilters(self.if_index, self.direction) catch return error.DetachFailed;
        defer filters.deinit(alloc);
        for (filters.items) |filter| {
            if (self.matches(filter)) {
                deleteFilter(self.if_index, self.direction, filter) catch return error.DetachFailed;
            }
        }
    }
};

pub const AttachResult = struct {
    attachment: Attachment,
    legacy_cleanup_pending: bool,
};

pub fn attach(if_index: u32, direction: common.Direction, program_fd: std.posix.fd_t, component: Component) common.EbpfError!Attachment {
    const result = try attachWithStatus(if_index, direction, program_fd, component);
    if (result.legacy_cleanup_pending) return error.LegacyCleanupFailed;
    return result.attachment;
}

/// Preserve ownership after publication even when legacy cleanup needs a retry.
pub fn attachWithStatus(if_index: u32, direction: common.Direction, program_fd: std.posix.fd_t, component: Component) common.EbpfError!AttachResult {
    const lock = acquireLock() catch return error.AttachFailed;
    defer platform.posix.close(lock);
    const program_id = programId(program_fd) catch |err| {
        @import("../../lib/log.zig").warn("ebpf: failed to identify TC program: {}", .{err});
        return error.AttachFailed;
    };
    var filters = listFilters(if_index, direction) catch |err| {
        @import("../../lib/log.zig").warn("ebpf: failed to list TC filters: {}", .{err});
        return error.AttachFailed;
    };
    defer filters.deinit(alloc);
    var replace = false;
    for (filters.items) |filter| {
        if (filter.priority == @intFromEnum(component) and filter.handle == 1) {
            // A colliding administrator-owned filter must remain untouched.
            if (!std.mem.eql(u8, filter.name(), component.name())) return error.AttachFailed;
            replace = true;
        }
    }
    try attach_support.attachTCWithOptions(if_index, direction, program_fd, @intFromEnum(component), .{
        .handle = 1,
        .name = component.name(),
        .replace = replace,
    });
    // Only installing policy can retire the legacy ingress chain: DNS/LB
    // startup alone must not remove an old deny program. Install first so
    // attach failure preserves prior enforcement. Never delete clsact.
    var legacy_cleanup_pending = false;
    for (filters.items) |filter| {
        if (std.mem.eql(u8, filter.name(), "yoq") and
            ((direction == .ingress and component == .policy) or
                (direction == .egress and component == .load_balancer)))
        {
            deleteFilter(if_index, direction, filter) catch |err| {
                // The kernel retains this stable filter and its maps even if
                // the caller closes its FDs. A later load can rediscover it.
                // Rollback here could remove enforcement after partial cleanup.
                @import("../../lib/log.zig").warn("ebpf: legacy TC cleanup failed; replacement {s} remains installed: {}", .{ component.name(), err });
                legacy_cleanup_pending = true;
            };
        }
    }
    return .{
        .attachment = .{ .if_index = if_index, .direction = direction, .component = component, .program_id = program_id },
        .legacy_cleanup_pending = legacy_cleanup_pending,
    };
}

fn acquireLock() !std.posix.fd_t {
    const fd = try platform.posix.open("/proc/thread-self/ns/net", .{ .CLOEXEC = true }, 0);
    errdefer platform.posix.close(fd);
    // Another process must not stall startup or periodic policy refresh forever.
    const pause: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
    for (0..100) |_| {
        switch (linux.errno(linux.flock(fd, 2 | 4))) { // LOCK_EX | LOCK_NB
            .SUCCESS => return fd,
            .AGAIN, .INTR => {},
            else => return error.LockFailed,
        }
        _ = linux.nanosleep(&pause, null);
    }
    return error.Timeout;
}

fn programId(fd: std.posix.fd_t) !u32 {
    var info: extern struct { program_type: u32 = 0, id: u32 = 0 } = .{};
    var attr: linux.BPF.Attr = .{ .info = .{ .bpf_fd = fd, .info_len = @sizeOf(@TypeOf(info)), .info = @intFromPtr(&info) } };
    if (linux.errno(linux.bpf(.obj_get_info_by_fd, &attr, @sizeOf(linux.BPF.InfoAttr))) != .SUCCESS or info.id == 0) return error.InvalidProgram;
    return info.id;
}

const Filter = struct {
    priority: u32,
    handle: u32,
    program_id: u32,
    name_bytes: [32]u8 = @splat(0),
    name_len: usize = 0,

    fn name(self: *const Filter) []const u8 {
        return self.name_bytes[0..self.name_len];
    }
};

fn parent(direction: common.Direction) u32 {
    return nl.TC_H.CLSACT | switch (direction) {
        .ingress => nl.TC_H.MIN_INGRESS,
        .egress => nl.TC_H.MIN_EGRESS,
    };
}

fn listFilters(if_index: u32, direction: common.Direction) !std.ArrayList(Filter) {
    var filters: std.ArrayList(Filter) = .empty;
    errdefer filters.deinit(alloc);
    const socket = try nl.openSocket();
    defer platform.posix.close(socket);
    var storage: [nl.buf_size]u8 align(4) = undefined;
    var message = nl.MessageBuilder.init(&storage);
    const header = try message.putHeader(.RTM_GETTFILTER, nl.NLM_F.REQUEST | nl.NLM_F.DUMP, nl.TcMsg);
    const query = message.getPayload(header, nl.TcMsg);
    query.ifindex = @intCast(if_index);
    query.parent = parent(direction);
    try nl.sendOnly(socket, message.message());
    while (true) {
        const count = try platform.posix.recv(socket, &storage, linux.MSG.TRUNC);
        if (count == 0 or count > storage.len) return error.InvalidResponse;
        var offset: usize = 0;
        while (offset + @sizeOf(linux.nlmsghdr) <= count) {
            const reply: *const linux.nlmsghdr = @ptrCast(@alignCast(&storage[offset]));
            if ((reply.flags & 0x10) != 0) return error.InvalidResponse; // NLM_F_DUMP_INTR
            if (reply.len < @sizeOf(linux.nlmsghdr) or reply.len > count - offset) return error.InvalidResponse;
            const payload = storage[offset + @sizeOf(linux.nlmsghdr) .. offset + reply.len];
            offset += nl.nlmsgAlign(reply.len);
            if (reply.type == .DONE) {
                // Multipart dumps can finish with an error in NLMSG_DONE.
                if (payload.len != 0 and (payload.len < 4 or
                    std.mem.bytesToValue(i32, payload[0..4]) != 0)) return error.InvalidResponse;
                return filters;
            }
            if (reply.type == .ERROR) return error.InvalidResponse;
            if (reply.type != .RTM_NEWTFILTER or payload.len < @sizeOf(nl.TcMsg)) continue;
            const tc = std.mem.bytesAsValue(nl.TcMsg, payload[0..@sizeOf(nl.TcMsg)]);
            const attributes = payload[@sizeOf(nl.TcMsg)..];
            const kind = attribute(attributes, nl.TCA.KIND) orelse continue;
            if (!std.mem.eql(u8, std.mem.sliceTo(kind, 0), "bpf")) continue;
            const options = attribute(attributes, nl.TCA.OPTIONS) orelse continue;
            const filter_name = std.mem.sliceTo(attribute(options, nl.TCA_BPF.NAME) orelse continue, 0);
            const id = attribute(options, 11) orelse continue; // TCA_BPF_ID
            if (id.len != 4 or filter_name.len > 32) return error.InvalidResponse;
            var filter: Filter = .{ .priority = tc.info >> 16, .handle = tc.handle, .program_id = std.mem.bytesToValue(u32, id[0..4]) };
            @memcpy(filter.name_bytes[0..filter_name.len], filter_name);
            filter.name_len = filter_name.len;
            try filters.append(alloc, filter);
        }
    }
}

fn attribute(bytes: []const u8, kind: u16) ?[]const u8 {
    var offset: usize = 0;
    while (offset + @sizeOf(nl.RtAttr) <= bytes.len) {
        const attr = std.mem.bytesAsValue(nl.RtAttr, bytes[offset..][0..@sizeOf(nl.RtAttr)]);
        if (attr.len < @sizeOf(nl.RtAttr) or attr.len > bytes.len - offset) return null;
        if ((attr.type & 0x3fff) == kind) return bytes[offset + @sizeOf(nl.RtAttr) .. offset + attr.len];
        offset += nl.nlmsgAlign(attr.len);
    }
    return null;
}

fn deleteFilter(if_index: u32, direction: common.Direction, filter: Filter) !void {
    const socket = try nl.openSocket();
    defer platform.posix.close(socket);
    var storage: [nl.buf_size]u8 align(4) = undefined;
    var message = nl.MessageBuilder.init(&storage);
    const header = try message.putHeader(.RTM_DELTFILTER, nl.NLM_F.REQUEST | nl.NLM_F.ACK, nl.TcMsg);
    const tc = message.getPayload(header, nl.TcMsg);
    tc.ifindex = @intCast(if_index);
    tc.parent = parent(direction);
    tc.handle = filter.handle;
    tc.info = (filter.priority << 16) | @as(u32, std.mem.nativeToBig(u16, 3)); // ETH_P_ALL
    try message.putAttrStr(header, nl.TCA.KIND, "bpf");
    try nl.sendAndCheck(socket, message.message());
}
