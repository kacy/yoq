const std = @import("std");
const linux = std.os.linux;
const platform = @import("linux_platform");

pub const max_pending = 4096;
pub const max_path_bytes = 4 * 1024 * 1024;
pub const max_resolution_attempts = 1024 * 1024;

pub const Pending = struct {
    allocator: std.mem.Allocator = std.heap.page_allocator,
    links: std.ArrayList(Link) = .empty,
    path_bytes: usize = 0,
    attempts: usize = 0,

    const Link = struct { name: []u8, target: []u8 };

    pub fn deinit(self: *Pending) void {
        while (self.links.items.len > 0) self.remove(self.links.items.len - 1);
        self.links.deinit(self.allocator);
    }

    pub fn cancel(self: *Pending, name: []const u8) void {
        for (self.links.items, 0..) |link, index| {
            if (std.mem.eql(u8, link.name, name)) {
                self.remove(index);
                return;
            }
        }
    }

    pub fn add(self: *Pending, name: []const u8, target: []const u8) !void {
        if (self.links.items.len == max_pending or name.len + target.len > max_path_bytes - self.path_bytes)
            return error.HardLinkMetadataTooLarge;
        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        const owned_target = try self.allocator.dupe(u8, target);
        errdefer self.allocator.free(owned_target);
        try self.links.append(self.allocator, .{ .name = owned_name, .target = owned_target });
        self.path_bytes += name.len + target.len;
    }

    // resolve after each entry, so a forward reference binds when its target
    // first appears. later replacement of the target does not change that inode.
    pub fn resolve(self: *Pending, root: std.Io.Dir, comptime ensureParent: anytype, comptime openTarget: anytype) !void {
        var progress = true;
        while (progress) {
            progress = false;
            var index: usize = 0;
            while (index < self.links.items.len) {
                if (self.attempts == max_resolution_attempts) return error.HardLinkResolutionLimit;
                self.attempts += 1;
                const link = self.links.items[index];
                if (try create(root, link.name, link.target, ensureParent, openTarget)) {
                    self.remove(index);
                    progress = true;
                } else index += 1;
            }
        }
    }

    pub fn finish(self: *const Pending) !void {
        if (self.links.items.len != 0) return error.UnresolvedHardLinks;
    }

    fn remove(self: *Pending, index: usize) void {
        const link = self.links.swapRemove(index);
        self.path_bytes -= link.name.len + link.target.len;
        self.allocator.free(link.name);
        self.allocator.free(link.target);
    }
};

pub fn create(root: std.Io.Dir, name: []const u8, target: []const u8, comptime ensureParent: anytype, comptime openTarget: anytype) !bool {
    const source = openTarget(root, target) catch |err| {
        if (err == error.FileNotFound) return false;
        return err;
    };
    defer source.close(std.Options.debug_io);
    if ((try source.stat(std.Options.debug_io)).kind != .file) return error.UnsafeHardLinkTarget;
    var parent = try ensureParent(root, name);
    defer parent.close(std.Options.debug_io);

    // link from a pinned descriptor, never a second lookup of an archive path.
    // /proc/self/fd also works without the capability required by AT_EMPTY_PATH.
    var source_buffer: [64]u8 = undefined;
    const source_path = try std.fmt.bufPrintZ(&source_buffer, "/proc/self/fd/{d}", .{source.handle});
    var random: [16]u8 = undefined;
    platform.randomBytes(&random);
    var temporary_buffer: [64]u8 = undefined;
    const temporary = try std.fmt.bufPrintZ(&temporary_buffer, ".yoq-hardlink-{s}", .{std.fmt.bytesToHex(random, .lower)});
    const result = linux.linkat(linux.AT.FDCWD, source_path, parent.handle, temporary, linux.AT.SYMLINK_FOLLOW);
    if (linux.errno(result) != .SUCCESS) return error.HardLinkFailed;
    defer parent.deleteFile(std.Options.debug_io, temporary) catch {};
    try parent.rename(temporary, parent, std.fs.path.basename(name), std.Options.debug_io);
    return true;
}

test "tar pending hard links bound storage and resolution work" {
    var pending: Pending = .{ .allocator = std.testing.allocator };
    defer pending.deinit();
    for (0..max_pending) |_| try pending.add("name", "target");
    try std.testing.expectError(error.HardLinkMetadataTooLarge, pending.add("one", "more"));
    pending.attempts = max_resolution_attempts;
    const Missing = struct {
        fn parent(_: std.Io.Dir, _: []const u8) !std.Io.Dir {
            return error.FileNotFound;
        }
        fn file(_: std.Io.Dir, _: []const u8) !std.Io.File {
            return error.FileNotFound;
        }
    };
    try std.testing.expectError(error.HardLinkResolutionLimit, pending.resolve(std.Io.Dir.cwd(), Missing.parent, Missing.file));
}

test "tar pending hard links release partial allocation failures" {
    const Probe = struct {
        fn allocate(alloc: std.mem.Allocator) !void {
            var pending: Pending = .{ .allocator = alloc };
            defer pending.deinit();
            try pending.add("alias", "target");
            pending.cancel("alias");
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Probe.allocate, .{});
}
