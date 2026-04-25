const builtin = @import("builtin");
const std = @import("std");
const linux_platform = @import("linux_platform");
const log = std.log;
const types = @import("types.zig");

const DetectResult = types.DetectResult;
const DetectSource = types.DetectSource;
const GpuInfo = types.GpuInfo;
const NvmlHandle = types.NvmlHandle;
const SysfsContent = types.SysfsContent;
const max_gpus = types.max_gpus;

pub const ProbeRoots = struct {
    procfs_gpus: []const u8 = "/proc/driver/nvidia/gpus",
    drm_root: []const u8 = "/sys/class/drm",
};

var probe_roots = ProbeRoots{};

pub fn setTestProbeRoots(roots: ProbeRoots) void {
    if (!builtin.is_test) @panic("setTestProbeRoots is test-only");
    probe_roots = roots;
}

pub fn resetTestProbeRoots() void {
    if (!builtin.is_test) @panic("resetTestProbeRoots is test-only");
    probe_roots = .{};
}

pub fn detectProcfs() ?DetectResult {
    var dir = linux_platform.openDirAbsolute(probe_roots.procfs_gpus, .{ .iterate = true }) catch return null;
    defer dir.close();

    var result = emptyDetectResult(.procfs, null);
    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (result.count >= max_gpus) break;
        if (entry.kind != .directory) continue;

        var gpu = GpuInfo{ .index = result.count };
        const name = entry.name;
        const len: u8 = @intCast(@min(name.len, 16));
        @memcpy(gpu.pci_bus_id[0..len], name[0..len]);
        gpu.pci_bus_id_len = len;

        result.gpus[result.count] = gpu;
        result.count += 1;
    }

    if (result.count > 0) {
        sortGpusByPciBusId(result.gpus[0..result.count]);
        log.info("GPU: detected {d} GPU(s) via procfs", .{result.count});
        return result;
    }
    return null;
}

pub fn detectSysfs() ?DetectResult {
    var result = emptyDetectResult(.sysfs, null);
    var drm_dir = linux_platform.openDirAbsolute(probe_roots.drm_root, .{ .iterate = true }) catch return null;
    defer drm_dir.close();

    var iter = drm_dir.iterate();
    while (iter.next() catch null) |entry| {
        if (result.count >= max_gpus) break;

        const name = entry.name;
        if (!std.mem.startsWith(u8, name, "card")) continue;
        if (std.mem.indexOfScalar(u8, name, '-') != null) continue;

        var path_buf: [256]u8 = undefined;
        const vendor_path = std.fmt.bufPrint(&path_buf, "{s}/{s}/device/vendor", .{ probe_roots.drm_root, name }) catch continue;
        const vendor_content = readSysfsFile(vendor_path) orelse continue;
        const trimmed = std.mem.trim(u8, vendor_content.slice(), " \t\n\r");
        if (!std.mem.eql(u8, trimmed, "0x10de")) continue;

        var gpu = GpuInfo{ .index = result.count };

        var uevent_buf: [256]u8 = undefined;
        const uevent_path = std.fmt.bufPrint(&uevent_buf, "{s}/{s}/device/uevent", .{ probe_roots.drm_root, name }) catch {
            result.gpus[result.count] = gpu;
            result.count += 1;
            continue;
        };
        if (readSysfsFile(uevent_path)) |uevent_content| {
            if (parsePciBusIdFromUevent(uevent_content.slice())) |pci| {
                const pci_len: u8 = @intCast(@min(pci.len, 16));
                @memcpy(gpu.pci_bus_id[0..pci_len], pci[0..pci_len]);
                gpu.pci_bus_id_len = pci_len;
            }
        }

        result.gpus[result.count] = gpu;
        result.count += 1;
    }

    if (result.count > 0) {
        log.info("GPU: detected {d} GPU(s) via sysfs", .{result.count});
        return result;
    }
    return null;
}

fn sortGpusByPciBusId(gpus: []GpuInfo) void {
    std.mem.sort(GpuInfo, gpus, {}, struct {
        fn lessThan(_: void, a: GpuInfo, b: GpuInfo) bool {
            return std.mem.order(u8, a.getPciBusId(), b.getPciBusId()) == .lt;
        }
    }.lessThan);
}

pub fn emptyDetectResult(source: DetectSource, nvml: ?NvmlHandle) DetectResult {
    return .{
        .gpus = undefined,
        .count = 0,
        .source = source,
        .nvml = nvml,
    };
}

pub fn readSysfsFile(path: []const u8) ?SysfsContent {
    var result = SysfsContent{ .buf = undefined, .len = 0 };
    const content = std.Io.Dir.cwd().readFile(std.Options.debug_io, path, &result.buf) catch return null;
    result.len = content.len;
    return result;
}

pub fn parsePciBusIdFromUevent(content: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "PCI_SLOT_NAME=")) {
            return line["PCI_SLOT_NAME=".len..];
        }
    }
    return null;
}
