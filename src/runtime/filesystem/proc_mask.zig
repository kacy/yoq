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

test "harden masks host-global entries in a proc-like tree" {
    // mounting needs a private user and mount namespace, so run in a child
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.ForkFailed;
    if (rc == 0) linux.exit_group(hardenFakeProc());

    var status: u32 = 0;
    _ = linux.waitpid(@intCast(rc), &status, 0);
    try std.testing.expect(linux.W.IFEXITED(status));
    switch (linux.W.EXITSTATUS(status)) {
        0 => {},
        77 => return error.SkipZigTest, // no unprivileged user namespaces here
        else => |code| {
            std.debug.print("hardenFakeProc failed at step {d}\n", .{code});
            return error.TestUnexpectedResult;
        },
    }
}

/// Exit status: 0 on success, 77 when namespaces are unavailable, otherwise
/// the number of the check that failed.
fn hardenFakeProc() u8 {
    const uid = linux.getuid();
    const gid = linux.getgid();
    if (linux.errno(linux.unshare(linux.CLONE.NEWUSER | linux.CLONE.NEWNS)) != .SUCCESS) return 77;
    // map ourselves to root so the new mount namespace is ours to change
    var map_buf: [32]u8 = undefined;
    writeProcFile("/proc/self/setgroups", "deny") catch return 77;
    writeProcFile("/proc/self/uid_map", std.fmt.bufPrint(&map_buf, "0 {d} 1", .{uid}) catch return 77) catch return 77;
    writeProcFile("/proc/self/gid_map", std.fmt.bufPrint(&map_buf, "0 {d} 1", .{gid}) catch return 77) catch return 77;
    const root = "/tmp";
    if (linux.errno(linux.mount("tmpfs", root, "tmpfs", 0, 0)) != .SUCCESS) return 77;

    const proc = "/tmp/proc";
    for ([_][*:0]const u8{ proc, proc ++ "/sys", proc ++ "/acpi" }) |dir| {
        if (linux.errno(linux.mkdir(dir, 0o755)) != .SUCCESS) return 1;
    }
    // sysrq-trigger exists; the other masked files are missing and skipped
    const trigger = linux.open(proc ++ "/sysrq-trigger", .{ .CREAT = true, .ACCMODE = .WRONLY, .CLOEXEC = true }, 0o600);
    if (linux.errno(trigger) != .SUCCESS) return 2;
    _ = linux.close(@intCast(trigger));

    harden(proc) catch return 3;

    // writes to the trigger land in /dev/null
    const fd = linux.open(proc ++ "/sysrq-trigger", .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return 4;
    _ = linux.write(@intCast(fd), "b", 1);
    _ = linux.close(@intCast(fd));
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(linux.AT.FDCWD, proc ++ "/sysrq-trigger", 0, .{ .TYPE = true }, &st)) != .SUCCESS) return 5;
    if (st.mode & linux.S.IFMT != linux.S.IFCHR) return 6;

    // sys is read-only and acpi is an empty read-only tmpfs
    for ([_][*:0]const u8{ proc ++ "/sys/new", proc ++ "/acpi/new" }) |path| {
        if (linux.errno(linux.mkdir(path, 0o755)) != .ROFS) return 7;
    }
    return 0;
}

fn writeProcFile(path: [*:0]const u8, data: []const u8) !void {
    const fd = linux.open(path, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return error.OpenFailed;
    defer _ = linux.close(@intCast(fd));
    if (linux.errno(linux.write(@intCast(fd), data.ptr, data.len)) != .SUCCESS) return error.WriteFailed;
}
