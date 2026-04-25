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

pub fn writeNetworkFiles(rootfs_path: []const u8, container_ip: [4]u8, gateway_ip: [4]u8, hostname: []const u8) void {
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
    , .{gateway_str}) catch return;
    writeFileInRootfs(rootfs_path, "etc/resolv.conf", resolv);

    if (valid_hostname) {
        var hosts_buf: [256]u8 = undefined;
        var ip_buf: [16]u8 = undefined;
        const ip_str = ip.formatIp(container_ip, &ip_buf);
        const hosts = std.fmt.bufPrint(
            &hosts_buf,
            "127.0.0.1\tlocalhost\n{s}\t{s}\n",
            .{ ip_str, hostname },
        ) catch return;

        writeFileInRootfs(rootfs_path, "etc/hosts", hosts);
    } else {
        writeFileInRootfs(rootfs_path, "etc/hosts", "127.0.0.1\tlocalhost\n");
    }
}

fn writeFileInRootfs(rootfs: []const u8, rel_path: []const u8, content: []const u8) void {
    if (std.mem.indexOf(u8, rel_path, "..") != null) return;
    if (rel_path.len > 0 and rel_path[0] == '/') return;

    var path_buf: [512]u8 = undefined;
    const full_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ rootfs, rel_path }) catch return;

    if (std.fs.path.dirname(full_path)) |dir| {
        std.Io.Dir.cwd().createDirPath(std.Options.debug_io, dir) catch {};
    }

    var file = std.Io.Dir.cwd().createFile(std.Options.debug_io, full_path, .{}) catch |e| {
        log.warn("failed to create {s}: {}", .{ full_path, e });
        return;
    };
    defer file.close(std.Options.debug_io);
    file.writeStreamingAll(std.Options.debug_io, content) catch |e| {
        log.warn("failed to write {s}: {}", .{ full_path, e });
    };
}
