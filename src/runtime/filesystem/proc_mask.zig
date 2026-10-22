//! Hide the host-global parts of a freshly mounted /proc.
//!
//! A rootful container maps its uid 0 to the host's uid 0, and the kernel
//! checks many /proc files by euid and file mode, not by capability. Without
//! this, container root could write /proc/sysrq-trigger or global sysctls
//! such as kernel.core_pattern. This follows the masked and read-only paths
//! that OCI runtimes apply by default.
//!
//! Call it after mounting proc and before pivot_root and seccomp, while the
//! host's /dev/null is still reachable and mount is still allowed.
const std = @import("std");
const linux = std.os.linux;

/// Directories that stay readable but become read-only.
const read_only_dirs = [_][]const u8{ "sys", "bus", "fs", "irq" };

/// Files replaced with /dev/null.
const masked_files = [_][]const u8{ "sysrq-trigger", "kcore", "keys", "timer_list", "latency_stats" };

/// Directories replaced with an empty read-only tmpfs.
const masked_dirs = [_][]const u8{ "acpi", "scsi" };

const proc_flags = linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC;

pub fn harden(proc_path: []const u8) error{ PathTooLong, MountFailed }!void {
    for (read_only_dirs) |name| {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const path = try entryPath(&buf, proc_path, name);
        if (!try mountOrMissing(path, path, null, linux.MS.BIND | linux.MS.REC, null)) continue;
        // the remount must repeat proc's own flags, or a user namespace
        // refuses it for clearing locked flags
        _ = try mountOrMissing(null, path, null, linux.MS.BIND | linux.MS.REMOUNT | linux.MS.RDONLY | proc_flags, null);
    }
    for (masked_files) |name| {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        _ = try mountOrMissing("/dev/null", try entryPath(&buf, proc_path, name), null, linux.MS.BIND, null);
    }
    for (masked_dirs) |name| {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        _ = try mountOrMissing("tmpfs", try entryPath(&buf, proc_path, name), "tmpfs", linux.MS.RDONLY | proc_flags, "mode=555");
    }
}

fn entryPath(buf: []u8, proc_path: []const u8, name: []const u8) error{PathTooLong}![:0]const u8 {
    return std.fmt.bufPrintZ(buf, "{s}/{s}", .{ proc_path, name }) catch error.PathTooLong;
}

/// Mount, treating a target the kernel does not provide as nothing to hide.
/// Returns whether the mount happened.
fn mountOrMissing(
    source: ?[*:0]const u8,
    target: [*:0]const u8,
    kind: ?[*:0]const u8,
    flags: u32,
    data: ?[*:0]const u8,
) error{MountFailed}!bool {
    const rc = linux.mount(source, target, kind, flags, if (data) |d| @intFromPtr(d) else 0);
    return switch (linux.errno(rc)) {
        .SUCCESS => true,
        .NOENT => false,
        else => error.MountFailed,
    };
}
