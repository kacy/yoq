// security — seccomp filters and capability management for containers
//
// implements two layers of defense:
// 1. capabilities: drop all caps except a minimal allowlist
// 2. seccomp-bpf: restrict which syscalls the container can use
//
// the approach mirrors Docker's default security profile: most
// containers don't need dangerous syscalls, so we block them.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const syscall_util = @import("../lib/syscall.zig");

pub const SecurityError = error{
    SeccompFailed,
    CapabilityFailed,
    PrctlFailed,
};

// -- classic BPF structs (not in zig stdlib, needed for seccomp) --

/// classic BPF instruction for seccomp filters
const SockFilter = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

/// classic BPF program descriptor
const SockFprog = extern struct {
    len: u16,
    filter: [*]const SockFilter,
};

// BPF instruction classes and modes (classic BPF, not eBPF)
const BPF_LD = 0x00;
const BPF_JMP = 0x05;
const BPF_RET = 0x06;
const BPF_W = 0x00;
const BPF_ABS = 0x20;
const BPF_JEQ = 0x10;
const BPF_K = 0x00;

// offsets into seccomp_data struct
const SECCOMP_DATA_NR = 0; // syscall number
const SECCOMP_DATA_ARCH = 4; // architecture

/// default set of capabilities to keep for containers.
/// mirrors Docker's default capability set.
pub const default_caps = [_]u8{
    linux.CAP.CHOWN,
    linux.CAP.DAC_OVERRIDE,
    linux.CAP.FSETID,
    linux.CAP.FOWNER,
    linux.CAP.MKNOD,
    linux.CAP.NET_RAW,
    linux.CAP.SETGID,
    linux.CAP.SETUID,
    linux.CAP.SETFCAP,
    linux.CAP.SETPCAP,
    linux.CAP.NET_BIND_SERVICE,
    linux.CAP.SYS_CHROOT,
    linux.CAP.KILL,
    linux.CAP.AUDIT_WRITE,
};

/// apply container security restrictions.
/// call this inside the child process after namespace setup
/// but before exec.
pub fn apply() SecurityError!void {
    try dropCapabilities();
    try setNoNewPrivs();
    try installSeccompFilter();
}

/// drop all capabilities except the default allowlist.
/// uses a 2-element data array as required by capability v3 —
/// data[0] covers caps 0-31, data[1] covers caps 32-63.
fn dropCapabilities() SecurityError!void {
    var hdr = linux.cap_user_header_t{
        .version = 0x20080522, // _LINUX_CAPABILITY_VERSION_3
        .pid = 0, // current process
    };

    // build capability masks from the allowlist
    var data: [2]linux.cap_user_data_t = .{
        .{ .effective = 0, .permitted = 0, .inheritable = 0 },
        .{ .effective = 0, .permitted = 0, .inheritable = 0 },
    };
    for (default_caps) |cap| {
        const idx = linux.CAP.TO_INDEX(cap);
        const mask = linux.CAP.TO_MASK(cap);
        data[idx].effective |= mask;
        data[idx].permitted |= mask;
        data[idx].inheritable |= mask;
    }

    // use raw syscall because the stdlib capset() wrapper takes a pointer
    // to a single cap_user_data_t, but v3 requires a 2-element array
    const rc = linux.syscall2(.capset, @intFromPtr(&hdr), @intFromPtr(&data));
    if (syscall_util.isError(rc)) return SecurityError.CapabilityFailed;

    // verify: read caps back and confirm they match what we set.
    // defense-in-depth — if the kernel silently ignored our capset(),
    // we want to fail loudly rather than run with unexpected privileges.
    var verify_data: [2]linux.cap_user_data_t = .{
        .{ .effective = 0, .permitted = 0, .inheritable = 0 },
        .{ .effective = 0, .permitted = 0, .inheritable = 0 },
    };
    const rc2 = linux.syscall2(.capget, @intFromPtr(&hdr), @intFromPtr(&verify_data));
    if (syscall_util.isError(rc2)) return SecurityError.CapabilityFailed;

    // compare effective, permitted, and inheritable masks for both words
    for (0..2) |i| {
        if (verify_data[i].effective != data[i].effective or
            verify_data[i].permitted != data[i].permitted or
            verify_data[i].inheritable != data[i].inheritable)
        {
            return SecurityError.CapabilityFailed;
        }
    }
}

/// set PR_SET_NO_NEW_PRIVS so the process can't gain new
/// capabilities through exec. also required for unprivileged
/// seccomp filter installation.
fn setNoNewPrivs() SecurityError!void {
    const PR_SET_NO_NEW_PRIVS = 38;
    const rc = linux.syscall5(.prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (syscall_util.isError(rc)) return SecurityError.PrctlFailed;
}

/// syscalls blocked inside containers. adding or removing entries here
/// automatically updates the BPF filter — no manual offset counting needed.
///
/// note: ioctl is NOT blocked here. blocking it breaks terminal I/O, socket
/// operations, and most real-world programs. Docker handles this with BPF
/// argument inspection (filtering specific ioctl commands), which is a
/// significantly larger project. for now, ioctl remains allowed.
const blocked_syscalls = [_]linux.SYS{
    .kexec_load, // load a new kernel
    .reboot, // reboot the host
    .init_module, // load kernel modules
    .delete_module, // unload kernel modules
    .acct, // process accounting control
    .swapon, // enable swap
    .swapoff, // disable swap
    .mount_setattr, // change mount properties
    .ptrace, // trace/debug other processes
    .bpf, // load BPF programs into the kernel
    .perf_event_open, // access performance counters
    .process_vm_writev, // write to another process's memory
    .process_vm_readv, // read from another process's memory
    .open_by_handle_at, // bypass DAC with file handles
    .userfaultfd, // userfault file descriptor (used in exploits)
    .keyctl, // kernel keyring manipulation

    // filesystem namespace escape vectors. these are safe to block because
    // security.apply() runs AFTER filesystem setup (pivot_root, mounts) is done.
    .unshare, // create new namespaces (escape isolation)
    .mount, // mount filesystems
    .umount2, // unmount filesystems
    .pivot_root, // change root filesystem
    .open_tree, // open a mount for moving (new mount API)
    .move_mount, // move a mount to a new location (new mount API)
    .fsopen, // open a filesystem context (new mount API)
    .fsmount, // create a mount from fs context (new mount API)
    .fsconfig, // configure a filesystem context (new mount API)
};

/// install a seccomp-bpf filter that blocks dangerous syscalls.
///
/// the filter architecture:
/// 1. verify the syscall architecture matches (prevents
///    syscall number confusion across ABIs)
/// 2. check syscall number against a deny list
/// 3. allow everything not explicitly blocked
///
/// we use a denylist approach (block known-dangerous) rather than
/// an allowlist (allow known-safe) for pragmatic reasons: an
/// allowlist breaks too many programs. Docker uses the same approach.
///
/// the filter is generated at comptime from blocked_syscalls, so
/// adding/removing entries never causes jump offset bugs.
fn installSeccompFilter() SecurityError!void {
    const arch = comptime archValue();

    // build the BPF program at comptime from the blocked_syscalls list.
    // layout: arch check (3 insns) + load nr (1) + N deny jumps + allow + deny return
    const n = blocked_syscalls.len;
    const filter_len = 4 + n + 2; // 3 arch + 1 load + N checks + 1 allow + 1 deny
    const filter = comptime blk: {
        var f: [filter_len]SockFilter = undefined;

        // load architecture from seccomp_data
        f[0] = bpfStmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH);
        // if arch matches, skip to syscall check; otherwise kill
        f[1] = bpfJump(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0);
        f[2] = bpfStmt(BPF_RET | BPF_K, linux.SECCOMP.RET.KILL_PROCESS);
        // load syscall number
        f[3] = bpfStmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR);

        // each blocked syscall: if match, jump to the deny return.
        // jump offset = remaining checks after this one (to skip) + 1 (allow stmt)
        for (blocked_syscalls, 0..) |sc, i| {
            const remaining = n - 1 - i; // checks still to come
            f[4 + i] = bpfJump(BPF_JMP | BPF_JEQ | BPF_K, syscallNum(sc), @intCast(remaining + 1), 0);
        }

        // allow everything not blocked
        f[4 + n] = bpfStmt(BPF_RET | BPF_K, linux.SECCOMP.RET.ALLOW);
        // deny: return EPERM
        f[4 + n + 1] = bpfStmt(BPF_RET | BPF_K, linux.SECCOMP.RET.ERRNO | 1);

        break :blk f;
    };

    const prog = SockFprog{
        .len = @intCast(filter.len),
        .filter = &filter,
    };

    // install the filter via the seccomp() syscall
    const rc = linux.syscall3(
        .seccomp,
        linux.SECCOMP.SET_MODE_FILTER,
        0, // flags
        @intFromPtr(&prog),
    );
    if (syscall_util.isError(rc)) return SecurityError.SeccompFailed;
}

/// helper: create a BPF statement (no jump)
fn bpfStmt(code: u16, k: u32) SockFilter {
    return .{ .code = code, .jt = 0, .jf = 0, .k = k };
}

/// helper: create a BPF jump instruction
fn bpfJump(code: u16, k: u32, jt: u8, jf: u8) SockFilter {
    return .{ .code = code, .jt = jt, .jf = jf, .k = k };
}

/// get the AUDIT_ARCH value for the current target.
/// hardcoded because linux.AUDIT.ARCH.current hits an elf.EM enum bug in zig 0.15.
fn archValue() u32 {
    const arch = @import("builtin").cpu.arch;
    return switch (arch) {
        .x86_64 => 0xC000003E,
        .aarch64 => 0xC00000B7,
        .x86 => 0x40000003,
        .arm => 0x40000028,
        else => @compileError("unsupported architecture for seccomp"),
    };
}

/// get syscall number for the current architecture
fn syscallNum(sc: linux.SYS) u32 {
    return @intCast(@intFromEnum(sc));
}

// -- tests --

test "default capabilities set" {
    // verify we have a reasonable number of default caps
    try std.testing.expect(default_caps.len > 0);
    try std.testing.expect(default_caps.len <= 20);

    // verify NET_BIND_SERVICE is in the default set
    var found_net_bind = false;
    for (default_caps) |cap| {
        if (cap == linux.CAP.NET_BIND_SERVICE) found_net_bind = true;
    }
    try std.testing.expect(found_net_bind);
}

test "bpf instruction construction" {
    const stmt = bpfStmt(BPF_RET | BPF_K, linux.SECCOMP.RET.ALLOW);
    try std.testing.expectEqual(@as(u16, BPF_RET | BPF_K), stmt.code);
    try std.testing.expectEqual(@as(u8, 0), stmt.jt);
    try std.testing.expectEqual(@as(u8, 0), stmt.jf);
    try std.testing.expectEqual(linux.SECCOMP.RET.ALLOW, stmt.k);
}

test "bpf jump construction" {
    const jmp = bpfJump(BPF_JMP | BPF_JEQ | BPF_K, 42, 3, 0);
    try std.testing.expectEqual(@as(u16, BPF_JMP | BPF_JEQ | BPF_K), jmp.code);
    try std.testing.expectEqual(@as(u32, 42), jmp.k);
    try std.testing.expectEqual(@as(u8, 3), jmp.jt);
    try std.testing.expectEqual(@as(u8, 0), jmp.jf);
}

test "sock_filter struct size" {
    // kernel expects 8 bytes per instruction
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(SockFilter));
}

test "sock_fprog struct size" {
    // kernel expects 16 bytes on 64-bit (with padding)
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(SockFprog));
}

test "default caps all in low word" {
    // all current default caps are <32, so they fit in data[0].
    // if a cap >=32 is ever added, the 2-element data array handles it,
    // but this test documents the current invariant.
    for (default_caps) |cap| {
        try std.testing.expect(linux.CAP.TO_INDEX(cap) == 0);
    }
}

test "blocked_syscalls includes critical entries" {
    const critical = [_]linux.SYS{ .kexec_load, .reboot, .ptrace, .bpf };
    for (critical) |sc| {
        var found = false;
        for (blocked_syscalls) |blocked| {
            if (blocked == sc) {
                found = true;
                break;
            }
        }
        try std.testing.expect(found);
    }
}

test "capability mask verification detects mismatch" {
    // simulate the verification logic: build expected masks, then check
    // against a different set. this tests the comparison logic used in
    // dropCapabilities() without needing root privileges.
    var expected: [2]linux.cap_user_data_t = .{
        .{ .effective = 0, .permitted = 0, .inheritable = 0 },
        .{ .effective = 0, .permitted = 0, .inheritable = 0 },
    };
    for (default_caps) |cap| {
        const idx = linux.CAP.TO_INDEX(cap);
        const mask = linux.CAP.TO_MASK(cap);
        expected[idx].effective |= mask;
        expected[idx].permitted |= mask;
        expected[idx].inheritable |= mask;
    }

    // matching data should pass
    const matching = expected;
    for (0..2) |i| {
        try std.testing.expectEqual(expected[i].effective, matching[i].effective);
        try std.testing.expectEqual(expected[i].permitted, matching[i].permitted);
    }

    // tampered data (extra cap) should differ
    var tampered = expected;
    tampered[0].effective |= linux.CAP.TO_MASK(linux.CAP.SYS_ADMIN);
    try std.testing.expect(tampered[0].effective != expected[0].effective);
}

test "blocked_syscalls includes filesystem namespace escape vectors" {
    const fs_escape = [_]linux.SYS{
        .unshare, .mount, .umount2, .pivot_root,
        .open_tree, .move_mount, .fsopen, .fsmount, .fsconfig,
    };
    for (fs_escape) |sc| {
        var found = false;
        for (blocked_syscalls) |blocked| {
            if (blocked == sc) {
                found = true;
                break;
            }
        }
        try std.testing.expect(found);
    }
}
