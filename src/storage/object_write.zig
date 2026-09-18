const std = @import("std");
const platform = @import("linux_platform");
const paths = @import("../lib/paths.zig");
const io = std.Options.debug_io;

/// stage writes outside the bucket tree so listings never expose partial files.
/// the staging and destination directories must be on the same filesystem.
pub const Pending = struct {
    staging: std.Io.Dir,
    destination: std.Io.Dir,
    file: std.Io.File,
    name: [32]u8,
    basename: []const u8,
    published: bool = false,

    pub fn init(path: []const u8) !Pending {
        var staging_buf: [paths.max_path]u8 = undefined;
        const staging_path = try paths.dataPath(&staging_buf, "s3-pending");
        var staging = try openDurableDirectory(staging_path);
        errdefer staging.close(io);
        const parent = std.fs.path.dirname(path) orelse ".";
        var destination = try openDurableDirectory(parent);
        errdefer destination.close(io);

        for (0..8) |_| {
            var random: [16]u8 = undefined;
            platform.randomBytes(&random);
            const name = std.fmt.bytesToHex(random, .lower);
            const file = staging.createFile(io, &name, .{ .exclusive = true, .permissions = .fromMode(0o600) }) catch |err| switch (err) {
                error.PathAlreadyExists => continue,
                else => return err,
            };
            return .{ .staging = staging, .destination = destination, .file = file, .name = name, .basename = std.fs.path.basename(path) };
        }
        return error.PathAlreadyExists;
    }

    pub fn deinit(self: *Pending) void {
        self.file.close(io);
        if (!self.published) self.staging.deleteFile(io, &self.name) catch {};
        self.staging.close(io);
        self.destination.close(io);
    }

    pub fn publish(self: *Pending) !void {
        try self.file.sync(io);
        try self.staging.rename(&self.name, self.destination, self.basename, io);
        self.published = true;
        // after rename, a sync failure means durability is uncertain; readers
        // still see a complete object, never the partially written candidate.
        try (platform.File{ .handle = self.destination.handle }).sync();
        try (platform.File{ .handle = self.staging.handle }).sync();
    }
};

fn openDurableDirectory(path: []const u8) !std.Io.Dir {
    return std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => {
            try std.Io.Dir.cwd().createDirPath(io, path);
            // newly created ancestors must survive a crash too. existing
            // directories take the fast path above and need no extra syncs.
            var ancestor = path;
            while (true) {
                var dir = try std.Io.Dir.cwd().openDir(io, ancestor, .{ .iterate = true });
                defer dir.close(io);
                try (platform.File{ .handle = dir.handle }).sync();
                const parent = std.fs.path.dirname(ancestor) orelse ".";
                if (std.mem.eql(u8, ancestor, parent)) break;
                ancestor = parent;
            }
            return std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
        },
        else => return err,
    };
}
