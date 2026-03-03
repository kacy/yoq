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
fn dropCapabilities() SecurityError!void {
    var hdr = linux.cap_user_header_t{
        .version = 0x20080522, // _LINUX_CAPABILITY_VERSION_3
        .pid = 0, // current process
    };

    // build capability masks from the allowlist
    var effective: u32 = 0;
    var permitted: u32 = 0;
    var inheritable: u32 = 0;
    for (default_caps) |cap| {
        const mask = linux.CAP.TO_MASK(cap);
        effective |= mask;
        permitted |= mask;
        inheritable |= mask;
    }

    var data = linux.cap_user_data_t{
        .effective = effective,
        .permitted = permitted,
        .inheritable = inheritable,
    };

    const rc = linux.capset(&hdr, &data);
    if (syscall_util.isError(rc)) return SecurityError.CapabilityFailed;
}

/// set PR_SET_NO_NEW_PRIVS so the process can't gain new
/// capabilities through exec. also required for unprivileged
/// seccomp filter installation.
fn setNoNewPrivs() SecurityError!void {
    const PR_SET_NO_NEW_PRIVS = 38;
    const rc = linux.syscall5(.prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (syscall_util.isError(rc)) return SecurityError.PrctlFailed;
}

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
fn installSeccompFilter() SecurityError!void {
    const arch = comptime archValue();

    // BPF program instructions
    const filter = [_]SockFilter{
        // load architecture from seccomp_data
        bpfStmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH),

        // if arch != expected, kill the process
        // jt=0 means fall through (arch matches), jf=jump to kill
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0),
        bpfStmt(BPF_RET | BPF_K, linux.SECCOMP.RET.KILL_PROCESS),

        // load syscall number
        bpfStmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR),

        // block dangerous syscalls. for each: if match, jump to errno return.
        // the jump offsets count from the NEXT instruction.
        // we have N blocked syscalls, each takes 1 instruction, then 1 allow + 1 errno.
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, syscallNum(.kexec_load), deny_count, 0),
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, syscallNum(.reboot), deny_count - 1, 0),
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, syscallNum(.init_module), deny_count - 2, 0),
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, syscallNum(.delete_module), deny_count - 3, 0),
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, syscallNum(.acct), deny_count - 4, 0),
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, syscallNum(.swapon), deny_count - 5, 0),
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, syscallNum(.swapoff), deny_count - 6, 0),
        bpfJump(BPF_JMP | BPF_JEQ | BPF_K, syscallNum(.mount_setattr), deny_count - 7, 0),

        // allow everything else
        bpfStmt(BPF_RET | BPF_K, linux.SECCOMP.RET.ALLOW),

        // deny: return EPERM
        bpfStmt(BPF_RET | BPF_K, linux.SECCOMP.RET.ERRNO | 1), // EPERM = 1
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

// number of deny rules in the filter (must match the actual count above)
const deny_count = 8;

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
