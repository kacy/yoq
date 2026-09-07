//! OCI deletion metadata becomes native OverlayFS metadata only in an
//! unpublished image layer. Generic archives never interpret .wh.* names.
const std = @import("std");
const linux = std.os.linux;
pub const opaque_attribute = "trusted.overlay.opaque";

pub const Pending = struct {
    names: std.StringHashMap(void) = .init(std.heap.page_allocator),
    path_bytes: usize = 0,

    pub fn deinit(self: *Pending) void {
        var keys = self.names.keyIterator();
        while (keys.next()) |key| std.heap.page_allocator.free(key.*);
        self.names.deinit();
    }

    pub fn add(self: *Pending, name: []const u8, entry: std.tar.Iterator.File) !bool {
        const basename = std.fs.path.basename(name);
        if (!std.mem.startsWith(u8, basename, ".wh.")) return false;
        if (entry.kind != .file or entry.size != 0) return error.InvalidWhiteout;
        const target = basename[4..];
        if (target.len == 0 or std.mem.eql(u8, target, ".") or std.mem.eql(u8, target, "..")) return error.InvalidWhiteout;
        if (linux.geteuid() != 0) return error.WhiteoutRequiresPrivilege;
        if (self.names.contains(name)) return true;
        if (self.names.count() >= 65536 or name.len > 16 * 1024 * 1024 - self.path_bytes) return error.WhiteoutMetadataTooLarge;
        const owned = try std.heap.page_allocator.dupe(u8, name);
        errdefer std.heap.page_allocator.free(owned);
        try self.names.put(owned, {});
        self.path_bytes += name.len;
        return true;
    }

    pub fn apply(self: *Pending, root: std.Io.Dir, comptime ensureDirectory: anytype) !void {
        var keys = self.names.keyIterator();
        while (keys.next()) |key| {
            const basename = std.fs.path.basename(key.*);
            var parent = try ensureDirectory(root, std.fs.path.dirname(key.*) orelse "");
            defer parent.close(std.Options.debug_io);
            if (std.mem.eql(u8, basename, ".wh..wh..opq")) {
                if (linux.errno(linux.fsetxattr(parent.handle, opaque_attribute, "y", 1, 0)) != .SUCCESS) return error.WhiteoutFailed;
            } else {
                // A whiteout hides only older layers. An entry recreated in
                // this layer wins, regardless of archive entry ordering.
                const target = try std.posix.toPosixPath(basename[4..]);
                const result = linux.mknodat(parent.handle, &target, std.posix.S.IFCHR, 0);
                switch (linux.errno(result)) {
                    .SUCCESS => {},
                    .EXIST => {
                        // Recreating a deleted directory must also hide its
                        // old children; files and symlinks already hide them.
                        const opened = linux.openat(parent.handle, &target, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
                        switch (linux.errno(opened)) {
                            .SUCCESS => {
                                const dir: std.Io.Dir = .{ .handle = @intCast(opened) };
                                defer dir.close(std.Options.debug_io);
                                if (linux.errno(linux.fsetxattr(dir.handle, opaque_attribute, "y", 1, 0)) != .SUCCESS) return error.WhiteoutFailed;
                            },
                            .NOTDIR, .LOOP => {},
                            else => return error.WhiteoutFailed,
                        }
                    },
                    else => return error.WhiteoutFailed,
                }
            }
        }
    }
};

pub fn isOpaque(dir: std.Io.Dir) !bool {
    var value: [1]u8 = undefined;
    const result = linux.fgetxattr(dir.handle, opaque_attribute, &value, value.len);
    return switch (linux.errno(result)) {
        .SUCCESS => result == 1 and value[0] == 'y',
        .NODATA, .OPNOTSUPP => false,
        else => error.WhiteoutFailed,
    };
}

pub fn isDeviceWhiteout(dir: std.Io.Dir, path: []const u8) !bool {
    const name = try std.posix.toPosixPath(path);
    var stat: linux.Statx = undefined;
    if (linux.errno(linux.statx(dir.handle, &name, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true }, &stat)) != .SUCCESS) return error.StatFailed;
    return stat.mode & std.posix.S.IFMT == std.posix.S.IFCHR and stat.rdev_major == 0 and stat.rdev_minor == 0;
}
