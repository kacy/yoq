const std = @import("std");
const platform = @import("platform");

const gpu_detect = @import("../gpu/detect.zig");
const gpu_mesh = @import("../gpu/mesh.zig");
const gpu_passthrough = @import("../gpu/passthrough.zig");
const log = @import("../lib/log.zig");

const Allocator = std.mem.Allocator;

pub const MeshSupport = struct {
    alloc: Allocator,
    ib_result: gpu_mesh.IbDetectResult,
    topo_file_path: ?[]const u8,

    pub fn init(alloc: Allocator) MeshSupport {
        const ib_result = gpu_mesh.detectInfiniband();
        return .{
            .alloc = alloc,
            .ib_result = ib_result,
            .topo_file_path = createTopologyFile(alloc, ib_result),
        };
    }

    pub fn deinit(self: *MeshSupport) void {
        if (self.topo_file_path) |path| {
            platform.deleteFileAbsolute(path) catch {};
            self.alloc.free(path);
            self.topo_file_path = null;
        }
    }

    pub fn appendEnv(
        self: *const MeshSupport,
        alloc: Allocator,
        env_list: anytype,
        master_addr: []const u8,
        master_port: u16,
        world_size: u32,
        rank: u32,
        local_rank: u32,
    ) void {
        var mesh_env_buf: [1024]u8 = undefined;
        const env_data = gpu_mesh.generateMeshEnv(
            &mesh_env_buf,
            self.ib_result,
            master_addr,
            master_port,
            world_size,
            rank,
            local_rank,
            self.topo_file_path,
        ) catch |err| {
            log.warn("failed to generate mesh env: {}", .{err});
            return;
        };
        appendEnvEntries(alloc, env_list, env_data);
    }
};

pub fn appendGpuPassthroughEnv(alloc: Allocator, env_list: anytype, gpu_indices: []const u32) void {
    var gpu_env_buf: [4096]u8 = undefined;
    const env_data = gpu_passthrough.generateGpuEnv(gpu_indices, &gpu_env_buf) catch |err| {
        log.warn("failed to generate GPU env: {}", .{err});
        return;
    };
    appendEnvEntries(alloc, env_list, env_data);
}

pub fn appendEnvEntries(alloc: Allocator, env_list: anytype, env_data: []const u8) void {
    var env_pos: usize = 0;
    while (env_pos < env_data.len) {
        const end = std.mem.indexOfScalarPos(u8, env_data, env_pos, 0) orelse env_data.len;
        if (end > env_pos) {
            const duped = alloc.dupe(u8, env_data[env_pos..end]) catch {
                log.warn("failed to duplicate env entry", .{});
                return;
            };
            env_list.append(alloc, duped) catch {
                alloc.free(duped);
                log.warn("failed to append env entry", .{});
                return;
            };
        }
        env_pos = end + 1;
    }
}

fn createTopologyFile(alloc: Allocator, ib_result: gpu_mesh.IbDetectResult) ?[]const u8 {
    const gpu_result = gpu_detect.detect();
    if (gpu_result.count == 0) return null;

    const topo_xml = gpu_mesh.generateNcclTopology(
        alloc,
        gpu_result.gpus[0..gpu_result.count],
        &ib_result.devices,
        ib_result.count,
    ) catch |err| {
        log.warn("failed to generate NCCL topology: {}", .{err});
        return null;
    };
    defer alloc.free(topo_xml);

    var path_buf: [128]u8 = undefined;
    for (0..8) |_| {
        const path = std.fmt.bufPrint(
            &path_buf,
            "/tmp/yoq-nccl-topology-{x}.xml",
            .{randomU64()},
        ) catch return null;

        var file = platform.createFileAbsolute(path, .{ .exclusive = true }) catch |err| switch (err) {
            error.PathAlreadyExists => continue,
            else => {
                log.warn("failed to create NCCL topology file: {}", .{err});
                return null;
            },
        };
        defer file.close();

        file.writeAll(topo_xml) catch |err| {
            log.warn("failed to write NCCL topology file: {}", .{err});
            platform.deleteFileAbsolute(path) catch {};
            return null;
        };

        return alloc.dupe(u8, path) catch {
            platform.deleteFileAbsolute(path) catch {};
            return null;
        };
    }

    log.warn("failed to reserve unique NCCL topology file path", .{});
    return null;
}

fn randomU64() u64 {
    var bytes: [8]u8 = undefined;
    platform.randomBytes(&bytes);
    return std.mem.readInt(u64, &bytes, .little);
}

test "appendEnvEntries parses null-separated env data" {
    const alloc = std.testing.allocator;

    var envs: std.ArrayList([]const u8) = .empty;
    defer {
        for (envs.items) |entry| alloc.free(entry);
        envs.deinit(alloc);
    }

    appendEnvEntries(alloc, &envs, "A=1\x00B=two\x00");

    try std.testing.expectEqual(@as(usize, 2), envs.items.len);
    try std.testing.expectEqualStrings("A=1", envs.items[0]);
    try std.testing.expectEqualStrings("B=two", envs.items[1]);
}
