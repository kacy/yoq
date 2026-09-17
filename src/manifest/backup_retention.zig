const std = @import("std");

pub const Policy = struct {
    keep_count: usize = 7,
    max_age: u64 = 0,
    max_bytes: u64 = 0,
};
pub fn parseAge(value: []const u8) ?u64 {
    if (value.len < 2) return null;
    const amount = std.fmt.parseInt(u64, value[0 .. value.len - 1], 10) catch return null;
    const multiplier: u64 = switch (value[value.len - 1]) {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        else => return null,
    };
    return std.math.mul(u64, amount, multiplier) catch null;
}

const Artifact = struct {
    name: []const u8,
    timestamp: i64,
    size: u64,
};

const RetainedBackups = struct {
    count: usize = 1,
    bytes: u64,

    fn canKeep(self: RetainedBackups, artifact: Artifact, now: i64, policy: Policy) bool {
        if (self.count >= policy.keep_count) return false;
        // a future timestamp has age zero if the clock moved backwards.
        const age: u64 = @intCast(@max(@as(i128, now) - artifact.timestamp, 0));
        if (policy.max_age != 0 and age > policy.max_age) return false;
        if (policy.max_bytes != 0) {
            if (self.bytes > policy.max_bytes) return false;
            if (artifact.size > policy.max_bytes - self.bytes) return false;
        }
        return true;
    }

    fn keep(self: *RetainedBackups, artifact: Artifact) void {
        self.count += 1;
        self.bytes +|= artifact.size;
    }
};

/// prune completed scheduler backups, always keeping the named successful backup.
/// that backup counts toward the limits even when it exceeds them on its own.
pub fn prune(alloc: std.mem.Allocator, dir: std.Io.Dir, newest: []const u8, now: i64, policy: Policy) !void {
    if (policy.keep_count == 0) return error.InvalidRetention;
    var artifacts: std.ArrayList(Artifact) = .empty;
    defer {
        for (artifacts.items) |artifact| alloc.free(artifact.name);
        artifacts.deinit(alloc);
    }
    var iter = dir.iterate();
    while (try iter.next(std.Options.debug_io)) |entry| {
        if (entry.kind != .file) continue;
        const ts = timestamp(entry.name) orelse continue;
        const stat = try dir.statFile(std.Options.debug_io, entry.name, .{ .follow_symlinks = false });
        if (stat.kind != .file) continue;
        const name = try alloc.dupe(u8, entry.name);
        errdefer alloc.free(name);
        try artifacts.append(alloc, .{ .name = name, .timestamp = ts, .size = stat.size });
    }
    std.mem.sort(Artifact, artifacts.items, {}, struct {
        fn newer(_: void, a: Artifact, b: Artifact) bool {
            if (a.timestamp != b.timestamp) return a.timestamp > b.timestamp;
            return std.mem.order(u8, a.name, b.name) == .gt;
        }
    }.newer);
    // account for the new backup before deciding which older files to keep.
    var retained = RetainedBackups{ .bytes = try newestBackupSize(artifacts.items, newest) };
    for (artifacts.items) |artifact| {
        if (std.mem.eql(u8, artifact.name, newest)) continue;
        if (retained.canKeep(artifact, now, policy)) {
            retained.keep(artifact);
        } else {
            try dir.deleteFile(std.Options.debug_io, artifact.name);
        }
    }
}

fn newestBackupSize(artifacts: []const Artifact, newest: []const u8) !u64 {
    for (artifacts) |artifact| {
        if (std.mem.eql(u8, artifact.name, newest)) return artifact.size;
    }
    return error.MissingNewestBackup;
}

fn timestamp(name: []const u8) ?i64 {
    const prefix = "yoq-backup-";
    if (!std.mem.startsWith(u8, name, prefix)) return null;
    const suffix = if (std.mem.endsWith(u8, name, ".yoqbackup")) @as(usize, 10) else if (std.mem.endsWith(u8, name, ".db")) @as(usize, 3) else return null;
    if (name.len <= prefix.len + suffix) return null;
    const body = name[prefix.len .. name.len - suffix];
    const dash = std.mem.indexOfScalar(u8, body, '-');
    const seconds = if (dash) |i| body[0..i] else body;
    if (seconds.len == 0) return null;
    for (seconds) |c| if (!std.ascii.isDigit(c)) return null;
    if (dash) |i| {
        const nonce = body[i + 1 ..];
        if (nonce.len != 32) return null;
        for (nonce) |c| if (!std.ascii.isHex(c)) return null;
    }
    return std.fmt.parseInt(i64, seconds, 10) catch null;
}

test "backup retention combines count age and bytes without touching incomplete or unrelated files" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    for ([_][]const u8{ "yoq-backup-10.db", "yoq-backup-20.yoqbackup", "yoq-backup-30.db", "yoq-backup-40.db", "manual.db", ".pending", "yoq-backup-1.db.partial" }) |name|
        try tmp.dir.writeFile(io, .{ .sub_path = name, .data = "1234" });
    try tmp.dir.symLink(io, "manual.db", "yoq-backup-5.db", .{});
    try prune(std.testing.allocator, tmp.dir, "yoq-backup-40.db", 40, .{ .keep_count = 3, .max_age = 25, .max_bytes = 8 });
    for ([_][]const u8{ "yoq-backup-10.db", "yoq-backup-20.yoqbackup" }) |name|
        try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, name, .{}));
    for ([_][]const u8{ "yoq-backup-30.db", "yoq-backup-40.db", "manual.db", ".pending", "yoq-backup-1.db.partial", "yoq-backup-5.db" }) |name|
        try tmp.dir.access(io, name, .{});
    try prune(std.testing.allocator, tmp.dir, "yoq-backup-40.db", 100, .{ .keep_count = 1, .max_bytes = 1 });
    try tmp.dir.access(io, "yoq-backup-40.db", .{});
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "yoq-backup-30.db", .{}));
}

test "backup retention keeps exact age and byte limits" {
    var retained = RetainedBackups{ .bytes = 4 };
    const artifact = Artifact{ .name = "yoq-backup-10.db", .timestamp = 10, .size = 4 };
    const policy = Policy{ .keep_count = 2, .max_age = 20, .max_bytes = 8 };
    try std.testing.expect(retained.canKeep(artifact, 30, policy));
    try std.testing.expect(!retained.canKeep(artifact, 31, policy));
    try std.testing.expect(retained.canKeep(artifact, 0, policy));
    retained.keep(artifact);
    try std.testing.expect(!retained.canKeep(artifact, 30, policy));
}

test "backup retention leaves files intact when the newest backup is missing" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "yoq-backup-10.db", .data = "backup" });
    try std.testing.expectError(error.MissingNewestBackup, prune(
        std.testing.allocator,
        tmp.dir,
        "yoq-backup-20.db",
        20,
        .{ .keep_count = 1 },
    ));
    try tmp.dir.access(std.testing.io, "yoq-backup-10.db", .{});
}
