const std = @import("std");
const paths = @import("../../lib/paths.zig");

pub fn isAllowed(source: []const u8) bool {
    var configured: [paths.max_path]u8 = undefined;
    var canonical: [paths.max_path]u8 = undefined;
    const root = paths.dataPath(&configured, "") catch return allowedAt(source, null);
    const len = std.Io.Dir.cwd().realPathFile(std.Options.debug_io, root, &canonical) catch return allowedAt(source, null);
    return allowedAt(source, canonical[0..len]);
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
