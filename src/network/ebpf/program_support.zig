const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;
const BPF = linux.BPF;
const log = @import("../../lib/log.zig");
const common = @import("common.zig");
const resource_support = @import("resource_support.zig");

const max_insns = 4096;

pub fn loadProgram(comptime prog: type, map_fds: []posix.fd_t) common.EbpfError!posix.fd_t {
    return loadBpfProgramInner(prog.insns, prog.relocs, map_fds, .sched_cls, "");
}

pub fn loadProgramWithType(
    comptime prog: type,
    map_fds: []posix.fd_t,
    prog_type: BPF.ProgType,
) common.EbpfError!posix.fd_t {
    return loadBpfProgramInner(prog.insns, prog.relocs, map_fds, prog_type, "");
}

pub fn loadEgressProgram(comptime prog: type, map_fds: []posix.fd_t) common.EbpfError!posix.fd_t {
    return loadBpfProgramInner(prog.egress_insns, prog.egress_relocs, map_fds, .sched_cls, "egress ");
}

pub fn patchMapFd(insn: *BPF.Insn, fd: posix.fd_t) void {
    insn.src = BPF.PSEUDO_MAP_FD;
    insn.imm = @intCast(fd);
}

fn loadBpfProgramInner(
    insns: anytype,
    relocs: anytype,
    map_fds: []posix.fd_t,
    prog_type: BPF.ProgType,
    comptime label: []const u8,
) common.EbpfError!posix.fd_t {
    if (comptime builtin.os.tag != .linux) return common.EbpfError.NotSupported;
    if (insns.len == 0 or insns.len > max_insns) return common.EbpfError.ProgramLoadFailed;

    var mutable_insns: [insns.len]BPF.Insn = insns;
    for (relocs) |reloc| {
        if (reloc.insn_idx >= insns.len) {
            log.warn("ebpf: " ++ label ++ "skipping relocation with out-of-bounds insn_idx={d} (max={d})", .{ reloc.insn_idx, insns.len });
            continue;
        }
        if (reloc.map_idx >= map_fds.len) {
            log.warn("ebpf: " ++ label ++ "skipping relocation with out-of-bounds map_idx={d} (max={d})", .{ reloc.map_idx, map_fds.len });
            continue;
        }
        patchMapFd(&mutable_insns[reloc.insn_idx], map_fds[reloc.map_idx]);
    }

    try resource_support.reserveBpfFd();
    const prog_fd = BPF.prog_load(prog_type, &mutable_insns, null, "GPL", 0, 0) catch |e| {
        resource_support.releaseBpfFd();

        var log_buf: [65536]u8 = undefined;
        var bpf_log = BPF.Log{
            .level = 1,
            .buf = &log_buf,
        };
        _ = BPF.prog_load(prog_type, &mutable_insns, &bpf_log, "GPL", 0, 0) catch {};

        const log_end = std.mem.indexOfScalar(u8, &log_buf, 0) orelse log_buf.len;
        if (log_end > 0) {
            log.warn("ebpf: " ++ label ++ "verifier output: {s}", .{log_buf[0..log_end]});
        }
        log.warn("ebpf: " ++ label ++ "prog_load failed: {}", .{e});
        return common.EbpfError.ProgramLoadFailed;
    };

    return prog_fd;
}
