const std = @import("std");
const posix = std.posix;
const gpu_detect = @import("../../gpu/detect.zig");
const gpu_health = @import("../../gpu/health.zig");
const gpu_mig = @import("../../gpu/mig.zig");
const log = @import("../../lib/log.zig");
const agent_types = @import("../agent_types.zig");

const AgentResources = agent_types.AgentResources;

pub fn getSystemResources() AgentResources {
    const cpu_cores: u32 = @intCast(std.Thread.getCpuCount() catch 1);

    var memory_mb: u64 = 0;
    const meminfo = std.fs.cwd().readFileAlloc(std.heap.page_allocator, "/proc/meminfo", 8192) catch "";
    defer if (meminfo.len > 0) std.heap.page_allocator.free(meminfo);

    if (meminfo.len > 0) {
        if (std.mem.indexOf(u8, meminfo, "MemTotal:")) |pos| {
            var start = pos + "MemTotal:".len;
            while (start < meminfo.len and meminfo[start] == ' ') start += 1;
            var end = start;
            while (end < meminfo.len and meminfo[end] >= '0' and meminfo[end] <= '9') end += 1;
            if (end > start) {
                const kb = std.fmt.parseInt(u64, meminfo[start..end], 10) catch 0;
                memory_mb = kb / 1024;
            }
        }
    }

    const gpu_info = cachedGpuDetect();
    return .{
        .cpu_cores = cpu_cores,
        .memory_mb = memory_mb,
        .gpu_count = gpu_info.count,
        .gpu_model = gpu_info.model,
        .gpu_vram_mb = gpu_info.vram_mb,
    };
}

pub fn detectLocalIp(target: [4]u8, buf: *[16]u8) []const u8 {
    const addr = std.net.Address.initIp4(target, 80);

    const sock = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch {
        return std.fmt.bufPrint(buf, "127.0.0.1", .{}) catch "127.0.0.1";
    };
    defer posix.close(sock);

    posix.connect(sock, &addr.any, addr.getOsSockLen()) catch {
        return std.fmt.bufPrint(buf, "127.0.0.1", .{}) catch "127.0.0.1";
    };

    var local_addr: posix.sockaddr.storage = undefined;
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    posix.getsockname(sock, @ptrCast(&local_addr), &addr_len) catch {
        return std.fmt.bufPrint(buf, "127.0.0.1", .{}) catch "127.0.0.1";
    };

    const sa_in: *const posix.sockaddr.in = @ptrCast(@alignCast(&local_addr));
    const ip_bytes: [4]u8 = @bitCast(sa_in.addr);
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3] }) catch "127.0.0.1";
}

pub fn overlayIpForNode(node_id: u16) [4]u8 {
    if (node_id <= 254) return .{ 10, 40, 0, @intCast(node_id) };
    return .{ 10, 40, @intCast(node_id >> 8), @intCast(node_id & 0xFF) };
}

pub const CachedGpuInfo = struct {
    count: u32,
    model: ?[]const u8,
    vram_mb: u64,
    detect_result: ?*gpu_detect.DetectResult,
    mig_inventories: [gpu_detect.max_gpus]gpu_mig.MigInventory = .{gpu_mig.MigInventory{}} ** gpu_detect.max_gpus,
    mig_gpu_count: u32 = 0,
};

var cached_gpu_info: ?CachedGpuInfo = null;
var cached_detect_storage: gpu_detect.DetectResult = undefined;

pub fn cachedGpuDetect() CachedGpuInfo {
    if (cached_gpu_info) |info| return info;
    cached_detect_storage = gpu_detect.detect();
    const count = @as(u32, cached_detect_storage.count);

    var model: ?[]const u8 = null;
    var vram_mb: u64 = 0;
    if (count > 0) {
        const gpu = &cached_detect_storage.gpus[0];
        const name = gpu.getName();
        if (name.len > 0) model = name;
        vram_mb = gpu.vram_mb;
    }

    var mig_inventories: [gpu_detect.max_gpus]gpu_mig.MigInventory = .{gpu_mig.MigInventory{}} ** gpu_detect.max_gpus;
    var mig_gpu_count: u32 = 0;
    if (cached_detect_storage.nvml) |*nvml| {
        for (0..count) |i| {
            const gpu = &cached_detect_storage.gpus[i];
            if (gpu.mig_capable) {
                const inventory = gpu_mig.discoverInstances(nvml, @intCast(i));
                mig_inventories[i] = inventory;
                if (inventory.count > 0) {
                    mig_gpu_count += 1;
                    log.info("GPU {d}: MIG mode active, {d} instance(s)", .{ i, inventory.count });
                }
            }
        }
    }

    const info = CachedGpuInfo{
        .count = count,
        .model = model,
        .vram_mb = vram_mb,
        .detect_result = if (count > 0) &cached_detect_storage else null,
        .mig_inventories = mig_inventories,
        .mig_gpu_count = mig_gpu_count,
    };
    cached_gpu_info = info;
    return info;
}
