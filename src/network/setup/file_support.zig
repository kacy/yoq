const std = @import("std");
const ip = @import("../ip.zig");
const log = @import("../../lib/log.zig");

pub fn isValidHostname(name: []const u8) bool {
    if (name.len == 0 or name.len > 253) return false;
    for (name) |c| {
        if (c < 0x21 or c > 0x7e) return false;
    }
    return true;
}

pub fn writeNetworkFiles(rootfs_path: []const u8, container_ip: [4]u8, gateway_ip: [4]u8, hostname: []const u8) !void {
    const valid_hostname = isValidHostname(hostname);
    if (!valid_hostname) {
        log.warn("invalid hostname, using container ID prefix instead", .{});
    }

    var gateway_buf: [16]u8 = undefined;
    const gateway_str = ip.formatIp(gateway_ip, &gateway_buf);
    var resolv_buf: [128]u8 = undefined;
    const resolv = std.fmt.bufPrint(&resolv_buf,
        \\nameserver {s}
        \\nameserver 8.8.8.8
        \\
    , .{gateway_str}) catch return error.PathTooLong;
    try writeFileInRootfs(rootfs_path, "etc/resolv.conf", resolv);

    if (valid_hostname) {
        var hosts_buf: [512]u8 = undefined;
        var ip_buf: [16]u8 = undefined;
        const ip_str = ip.formatIp(container_ip, &ip_buf);
        const hosts = std.fmt.bufPrint(
            &hosts_buf,
            "127.0.0.1\tlocalhost\n{s}\t{s}\n",
            .{ ip_str, hostname },
        ) catch return error.PathTooLong;

        try writeFileInRootfs(rootfs_path, "etc/hosts", hosts);
    } else {
        try writeFileInRootfs(rootfs_path, "etc/hosts", "127.0.0.1\tlocalhost\n");
    }
}

fn writeFileInRootfs(rootfs: []const u8, rel_path: []const u8, content: []const u8) !void {
    if (std.mem.indexOf(u8, rel_path, "..") != null) return error.InvalidPath;
    if (rel_path.len > 0 and rel_path[0] == '/') return error.InvalidPath;

    var path_buf: [512]u8 = undefined;
    const full_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ rootfs, rel_path }) catch return error.PathTooLong;

    if (std.fs.path.dirname(full_path)) |dir| {
        try std.Io.Dir.cwd().createDirPath(std.Options.debug_io, dir);
    }

    var file = try std.Io.Dir.cwd().createFile(std.Options.debug_io, full_path, .{});
    defer file.close(std.Options.debug_io);
    try file.writeStreamingAll(std.Options.debug_io, content);
}

test "required network files reject an unusable etc directory" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "etc", .data = "sentinel" });
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(std.testing.io, &root_buf);
    if (writeNetworkFiles(root_buf[0..length], .{ 10, 42, 0, 2 }, .{ 10, 42, 0, 1 }, "worker")) |_| {
        return error.ExpectedNetworkFileFailure;
    } else |_| {}
    var buffer: [32]u8 = undefined;
    try std.testing.expectEqualStrings("sentinel", try tmp.dir.readFile(std.testing.io, "etc", &buffer));
}

test "required network files report write failures and accept maximum hostname" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "etc", .default_dir);
    try tmp.dir.symLink(std.testing.io, "/dev/full", "etc/resolv.conf", .{});
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(std.testing.io, &root_buf);
    if (writeNetworkFiles(root_buf[0..length], .{ 10, 42, 0, 2 }, .{ 10, 42, 0, 1 }, "worker")) |_| {
        return error.ExpectedNetworkWriteFailure;
    } else |_| {}
    try tmp.dir.deleteFile(std.testing.io, "etc/resolv.conf");
    try writeNetworkFiles(root_buf[0..length], .{ 10, 42, 0, 2 }, .{ 10, 42, 0, 1 }, "a" ** 253);
    var buffer: [512]u8 = undefined;
    const hosts = try tmp.dir.readFile(std.testing.io, "etc/hosts", &buffer);
    try std.testing.expect(std.mem.indexOf(u8, hosts, "a" ** 253) != null);
}
