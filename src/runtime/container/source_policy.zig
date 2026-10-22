const std = @import("std");
const paths = @import("../../lib/paths.zig");

pub fn isAllowed(source: []const u8) bool {
    var configured: [paths.max_path]u8 = undefined;
    var canonical: [paths.max_path]u8 = undefined;
    const root = paths.dataPath(&configured, "") catch return allowedAt(source, null);
    const len = std.Io.Dir.cwd().realPathFile(std.Options.debug_io, root, &canonical) catch return allowedAt(source, null);
    return allowedAt(source, canonical[0..len]);
}

/// whether a cluster agent may mount the host path `source`. agents refuse
/// every host path unless the operator listed a root it may come from with
/// `yoq join --host-path-root`. both sides are resolved first, so a symlink
/// cannot lead out of an allowed root. a path that does not exist yet is
/// refused, since nothing can be said about where it will point.
pub fn underHostRoot(source: []const u8, roots: []const []const u8) bool {
    var source_buf: [paths.max_path]u8 = undefined;
    const resolved = source_buf[0 .. std.Io.Dir.cwd().realPathFile(std.Options.debug_io, source, &source_buf) catch return false];
    for (roots) |root| {
        var root_buf: [paths.max_path]u8 = undefined;
        const resolved_root = root_buf[0 .. std.Io.Dir.cwd().realPathFile(std.Options.debug_io, root, &root_buf) catch continue];
        if (within(resolved, resolved_root)) return true;
    }
    return false;
}

fn within(path: []const u8, root: []const u8) bool {
    return std.mem.eql(u8, path, root) or (std.mem.startsWith(u8, path, root) and
        (std.mem.eql(u8, root, "/") or (path.len > root.len and path[root.len] == '/')));
}

fn canonicalSyntax(path: []const u8) bool {
    if (path.len == 0 or path[0] != '/' or std.mem.indexOfScalar(u8, path, 0) != null) return false;
    if (path.len == 1) return true;
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return false;
    }
    return true;
}

/// Canonical named-volume roots are the only exceptions under protected home
/// and state directories. Ancestors expose the protected tree just as directly.
fn allowedAt(source: []const u8, data_root: ?[]const u8) bool {
    if (!canonicalSyntax(source)) return false;
    if (data_root) |root| {
        var volume_buf: [paths.max_path]u8 = undefined;
        for ([_][]const u8{ "volumes", "mounts/nfs" }) |subdir| {
            const volume_root = std.fmt.bufPrint(&volume_buf, "{s}/{s}", .{ root, subdir }) catch return false;
            if (within(source, volume_root)) return true;
        }
        if (within(source, root) or within(root, source)) return false;
    }
    for ([_][]const u8{ "/etc", "/root", "/var/lib", "/home", "/proc", "/sys", "/dev", "/boot", "/usr/sbin", "/sbin" }) |protected| {
        if (within(source, protected) or within(protected, source)) return false;
    }
    return true;
}

test "bind source policy rejects protected ancestors and fake managed roots" {
    const root = "/home/alice/.local/share/yoq";
    for ([_][]const u8{ "/", "/var", "/usr", "/home", "/etc/shadow", root, "/home/alice/.local/share/yoq/secrets.key", "/home/bob/.local/share/yoq/volumes/app/data", "/root/fake/.local/share/yoq/volumes/app/data", "/home/alice/.local/share/yoq/volumes-other", "/home/alice/.local/share/yoq/mounts", "/home/alice/.local/share/yoq/volumes/../secrets.key", "/tmp/../etc", "relative", "/tmp//data" }) |source| {
        try std.testing.expect(!allowedAt(source, root));
    }
    for ([_][]const u8{ "/home/alice/.local/share/yoq/volumes/app/data", "/home/alice/.local/share/yoq/mounts/nfs/app/data", "/tmp/data", "/srv/data", "/usr/local/share", "/etcetera", "/homework" }) |source| {
        try std.testing.expect(allowedAt(source, root));
    }
}

test "bind source policy protects relocated state and root-owned named volumes" {
    try std.testing.expect(!allowedAt("/srv", "/srv/yoq"));
    try std.testing.expect(!allowedAt("/srv/yoq/secrets.key", "/srv/yoq"));
    try std.testing.expect(allowedAt("/srv/yoq/volumes/app/data", "/srv/yoq"));
    try std.testing.expect(allowedAt("/root/.local/share/yoq/volumes/app/data", "/root/.local/share/yoq"));
    try std.testing.expect(!allowedAt("/root/.local/share/yoq/volumes/app/data", "/home/alice/.local/share/yoq"));
}

test "agents mount host paths only below an allowed root" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.Options.debug_io, "allowed/data");
    try tmp.dir.createDirPath(std.Options.debug_io, "other");
    try tmp.dir.symLink(std.Options.debug_io, "../other", "allowed/escape", .{});
    var buf: [paths.max_path]u8 = undefined;
    const base = buf[0..try tmp.dir.realPath(std.Options.debug_io, &buf)];
    var a: [paths.max_path]u8 = undefined;
    var b: [paths.max_path]u8 = undefined;
    const allowed = try std.fmt.bufPrint(&a, "{s}/allowed", .{base});

    try std.testing.expect(underHostRoot(try std.fmt.bufPrint(&b, "{s}/allowed/data", .{base}), &.{allowed}));
    try std.testing.expect(underHostRoot(allowed, &.{allowed}));
    // nothing is allowed without a configured root
    try std.testing.expect(!underHostRoot(try std.fmt.bufPrint(&b, "{s}/allowed/data", .{base}), &.{}));
    try std.testing.expect(!underHostRoot(try std.fmt.bufPrint(&b, "{s}/other", .{base}), &.{allowed}));
    // a link inside the root that points out of it
    try std.testing.expect(!underHostRoot(try std.fmt.bufPrint(&b, "{s}/allowed/escape", .{base}), &.{allowed}));
    try std.testing.expect(!underHostRoot(try std.fmt.bufPrint(&b, "{s}/allowed/missing", .{base}), &.{allowed}));
}
