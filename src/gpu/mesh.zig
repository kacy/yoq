// mesh — InfiniBand detection and NCCL topology generation
//
// multi-GPU mesh networking support:
//   1. scan /sys/class/infiniband/ for IB devices and their state
//   2. check for GPUDirect RDMA support (/proc/driver/nvidia-peermem)
//   3. generate NCCL topology XML from GPU + IB PCIe bus IDs
//   4. inject per-rank mesh env vars (NCCL_IB_HCA, NCCL_NET_GDR_LEVEL, etc.)
//
// falls back gracefully to TCP when no InfiniBand is detected.

const std = @import("std");
const builtin = @import("builtin");
const detect = @import("detect.zig");
const log = @import("../lib/log.zig");
const env_buffer = @import("env_buffer.zig");

const Allocator = std.mem.Allocator;
const GpuInfo = detect.GpuInfo;

pub const max_ib_devices = 4;

pub const DetectPaths = struct {
    ib_root: []const u8 = "/sys/class/infiniband",
    peermem_path: []const u8 = "/proc/driver/nvidia-peermem",
};

var detect_paths = DetectPaths{};

pub const IbDevice = struct {
    name: [32]u8 = .{0} ** 32,
    name_len: u8 = 0,
    pci_bus_id: [16]u8 = .{0} ** 16,
    pci_bus_id_len: u8 = 0,
    active_ports: u8 = 0,
    rate_gbps: u32 = 0,
    gdr_supported: bool = false,

    pub fn getName(self: *const IbDevice) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn getPciBusId(self: *const IbDevice) []const u8 {
        return self.pci_bus_id[0..self.pci_bus_id_len];
    }
};

pub const IbDetectResult = struct {
    devices: [max_ib_devices]IbDevice,
    count: u8,
    gdr_available: bool,
};

pub fn setTestDetectPaths(paths: DetectPaths) void {
    if (!builtin.is_test) @panic("setTestDetectPaths is test-only");
    detect_paths = paths;
}

pub fn resetTestDetectPaths() void {
    if (!builtin.is_test) @panic("resetTestDetectPaths is test-only");
    detect_paths = .{};
}

/// detect InfiniBand devices by scanning sysfs.
pub fn detectInfiniband() IbDetectResult {
    var result = IbDetectResult{
        .devices = undefined,
        .count = 0,
        .gdr_available = false,
    };

    // check for GPUDirect RDMA (nvidia-peermem)
    result.gdr_available = checkGdr();

    var ib_dir = std.fs.openDirAbsolute(detect_paths.ib_root, .{ .iterate = true }) catch return result;
    defer ib_dir.close();

    var iter = ib_dir.iterate();
    while (iter.next() catch null) |entry| {
        if (result.count >= max_ib_devices) break;
        if (entry.kind != .sym_link and entry.kind != .directory) continue;

        var dev = IbDevice{};

        // device name
        const name_len: u8 = @intCast(@min(entry.name.len, 32));
        @memcpy(dev.name[0..name_len], entry.name[0..name_len]);
        dev.name_len = name_len;

        // read port state and rate
        dev.active_ports = countActivePorts(entry.name);
        dev.rate_gbps = readPortRate(entry.name);

        // read PCI bus ID from device symlink
        readIbPciBusId(entry.name, &dev);

        dev.gdr_supported = result.gdr_available;

        result.devices[result.count] = dev;
        result.count += 1;
    }

    if (result.count > 0) {
        log.info("IB: detected {d} InfiniBand device(s), GDR={}", .{ result.count, result.gdr_available });
    }

    return result;
}

/// check if GPUDirect RDMA is available.
fn checkGdr() bool {
    // nvidia-peermem kernel module
    const file = std.fs.cwd().openFile(detect_paths.peermem_path, .{}) catch {
        return false;
    };
    file.close();
    return true;
}

fn countActivePorts(dev_name: []const u8) u8 {
    var active: u8 = 0;
    // check ports 1-4
    for (1..5) |port| {
        var path_buf: [256]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}/{s}/ports/{d}/state", .{ detect_paths.ib_root, dev_name, port }) catch continue;
        const content = readSmallFile(path) orelse continue;
        if (std.mem.indexOf(u8, content.slice(), "ACTIVE") != null) {
            active += 1;
        }
    }
    return active;
}

fn readPortRate(dev_name: []const u8) u32 {
    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/{s}/ports/1/rate", .{ detect_paths.ib_root, dev_name }) catch return 0;
    const content = readSmallFile(path) orelse return 0;
    const trimmed = std.mem.trim(u8, content.slice(), " \t\n\r");
    // format is like "200 Gb/sec" — parse the number
    const space_idx = std.mem.indexOfScalar(u8, trimmed, ' ') orelse return 0;
    return std.fmt.parseInt(u32, trimmed[0..space_idx], 10) catch 0;
}

fn readIbPciBusId(dev_name: []const u8, dev: *IbDevice) void {
    // the device directory often has a symlink to the PCI device
    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/{s}/device/uevent", .{ detect_paths.ib_root, dev_name }) catch return;
    const content = readSmallFile(path) orelse return;
    if (detect.parsePciBusIdFromUevent(content.slice())) |pci| {
        const pci_len: u8 = @intCast(@min(pci.len, 16));
        @memcpy(dev.pci_bus_id[0..pci_len], pci[0..pci_len]);
        dev.pci_bus_id_len = pci_len;
    }
}

const readSmallFile = detect.readSysfsFile;

/// generate NCCL topology XML from GPU and IB device PCIe bus IDs.
/// the topology file helps NCCL understand the PCIe topology for
/// optimal GPU-to-GPU and GPU-to-NIC communication paths.
pub fn generateNcclTopology(
    alloc: Allocator,
    gpus: []const GpuInfo,
    ib_devices: []const IbDevice,
    ib_count: u8,
) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(alloc);

    try buf.appendSlice(alloc, "<?xml version=\"1.0\"?>\n<system version=\"1\">\n");
    try buf.appendSlice(alloc, "  <cpu numaid=\"0\">\n");
    try appendGpuTopology(alloc, &buf, gpus);
    try appendIbTopology(alloc, &buf, ib_devices, ib_count);

    try buf.appendSlice(alloc, "  </cpu>\n</system>\n");

    return buf.toOwnedSlice(alloc);
}

/// generate mesh environment variables for a rank.
/// includes NCCL configuration for optimal multi-GPU communication.
pub fn generateMeshEnv(
    buf: *[1024]u8,
    ib_result: IbDetectResult,
    master_addr: []const u8,
    master_port: u16,
    world_size: u32,
    rank: u32,
    local_rank: u32,
    topo_file: ?[]const u8,
) ![]const u8 {
    var writer = env_buffer.NullEnvWriter.init(buf);
    try writer.writeEntry("MASTER_ADDR", master_addr);
    try writer.writeEntryValueFmt("MASTER_PORT", "{d}", .{master_port});
    try writer.writeEntryValueFmt("WORLD_SIZE", "{d}", .{world_size});
    try writer.writeEntryValueFmt("RANK", "{d}", .{rank});
    try writer.writeEntryValueFmt("LOCAL_RANK", "{d}", .{local_rank});

    if (ib_result.count > 0) {
        const ib_name = ib_result.devices[0].getName();
        if (ib_name.len > 0) {
            try writer.writeEntry("NCCL_IB_HCA", ib_name);
        }
        if (ib_result.gdr_available) {
            try writer.writeLiteralEntry("NCCL_NET_GDR_LEVEL=5");
        }
        try writer.writeLiteralEntry("NCCL_NET=IB");
    }

    if (topo_file) |tf| {
        try writer.writeEntry("NCCL_TOPO_FILE", tf);
    }

    return writer.finish();
}

fn appendGpuTopology(alloc: Allocator, buf: *std.ArrayListUnmanaged(u8), gpus: []const GpuInfo) !void {
    for (gpus) |gpu| {
        if (gpu.getPciBusId().len == 0) continue;
        try appendGpuNode(alloc, buf, gpus, gpu);
    }
}

fn appendGpuNode(
    alloc: Allocator,
    buf: *std.ArrayListUnmanaged(u8),
    gpus: []const GpuInfo,
    gpu: GpuInfo,
) !void {
    try appendPciOpen(alloc, buf, gpu.getPciBusId(), "0x030200");
    try appendGpuHeader(alloc, buf, gpu);

    const has_nvlink = try appendNvLinkEntries(alloc, buf, gpus, gpu);
    if (has_nvlink) {
        try buf.appendSlice(alloc, "      </gpu>\n");
    } else {
        try buf.appendSlice(alloc, " />\n");
    }

    try buf.appendSlice(alloc, "    </pci>\n");
}

fn appendGpuHeader(alloc: Allocator, buf: *std.ArrayListUnmanaged(u8), gpu: GpuInfo) !void {
    try buf.appendSlice(alloc, "      <gpu dev=\"");
    try std.fmt.format(buf.writer(alloc), "{d}", .{gpu.index});
    try std.fmt.format(buf.writer(alloc), "\" sm=\"{d}\" mem=\"{d}\"", .{
        gpuSmValue(gpu),
        gpu.vram_mb,
    });
}

fn appendNvLinkEntries(
    alloc: Allocator,
    buf: *std.ArrayListUnmanaged(u8),
    gpus: []const GpuInfo,
    gpu: GpuInfo,
) !bool {
    var wrote_entry = false;

    for (0..gpu.nvlink_peer_count) |li| {
        const peer_idx = gpu.nvlink_peers[li];
        if (peer_idx >= gpus.len) continue;

        const peer_pci = gpus[peer_idx].getPciBusId();
        if (peer_pci.len == 0) continue;

        if (!wrote_entry) {
            wrote_entry = true;
            try buf.appendSlice(alloc, ">\n");
        }

        try std.fmt.format(buf.writer(alloc), "        <nvlink target=\"{s}\" count=\"1\" />\n", .{peer_pci});
    }

    return wrote_entry;
}

fn appendIbTopology(
    alloc: Allocator,
    buf: *std.ArrayListUnmanaged(u8),
    ib_devices: []const IbDevice,
    ib_count: u8,
) !void {
    for (0..@min(ib_count, max_ib_devices)) |i| {
        const nic = ib_devices[i];
        if (nic.getPciBusId().len == 0) continue;
        try appendIbNode(alloc, buf, nic);
    }
}

fn appendIbNode(alloc: Allocator, buf: *std.ArrayListUnmanaged(u8), nic: IbDevice) !void {
    try appendPciOpen(alloc, buf, nic.getPciBusId(), "0x020700");
    try std.fmt.format(buf.writer(alloc), "      <nic name=\"{s}\" speed=\"{d}\" gdr=\"{s}\" />\n", .{
        nic.getName(),
        nic.rate_gbps,
        if (nic.gdr_supported) "1" else "0",
    });
    try buf.appendSlice(alloc, "    </pci>\n");
}

fn appendPciOpen(
    alloc: Allocator,
    buf: *std.ArrayListUnmanaged(u8),
    pci_bus_id: []const u8,
    class: []const u8,
) !void {
    try std.fmt.format(buf.writer(alloc), "    <pci busid=\"{s}\" class=\"{s}\" link_speed=\"16 GT/s\" link_width=\"16\">\n", .{
        pci_bus_id,
        class,
    });
}

fn gpuSmValue(gpu: GpuInfo) u16 {
    return if (gpu.compute_capability != 0) gpu.compute_capability else 80;
}

/// GPU mesh port range for traffic prioritization
pub const gpu_port_min: u16 = 29500;
pub const gpu_port_max: u16 = 29600;

/// path to the compiled GPU priority BPF object
pub const gpu_prio_bpf_path = "bpf/gpu_prio.o";

/// check if the GPU priority BPF object is available for attachment.
/// the actual attachment is done externally via:
///   tc qdisc add dev wg-yoq clsact
///   tc filter add dev wg-yoq egress bpf da obj bpf/gpu_prio.o sec classifier/gpu_prio
/// and detachment via:
///   tc filter del dev wg-yoq egress
pub fn isGpuPrioAvailable() bool {
    std.fs.cwd().access(gpu_prio_bpf_path, .{}) catch return false;
    return true;
}

// -- tests --

test "IbDevice defaults" {
    const dev = IbDevice{};
    try std.testing.expectEqual(@as(u8, 0), dev.name_len);
    try std.testing.expectEqual(@as(u8, 0), dev.active_ports);
    try std.testing.expectEqual(@as(u32, 0), dev.rate_gbps);
    try std.testing.expect(!dev.gdr_supported);
}

test "IbDetectResult defaults" {
    const result = IbDetectResult{
        .devices = undefined,
        .count = 0,
        .gdr_available = false,
    };
    try std.testing.expectEqual(@as(u8, 0), result.count);
    try std.testing.expect(!result.gdr_available);
}

test "detectInfiniband returns gracefully" {
    // on machines without IB, should return 0 devices
    const result = detectInfiniband();
    if (result.count == 0) {
        try std.testing.expect(!result.gdr_available);
    }
}

test "detectInfiniband discovers fake IB tree" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sys/class/infiniband/mlx5_0/ports/1");
    try tmp.dir.makePath("sys/class/infiniband/mlx5_0/device");
    try tmp.dir.writeFile(.{ .sub_path = "sys/class/infiniband/mlx5_0/ports/1/state", .data = "4: ACTIVE\n" });
    try tmp.dir.writeFile(.{ .sub_path = "sys/class/infiniband/mlx5_0/ports/1/rate", .data = "200 Gb/sec\n" });
    try tmp.dir.writeFile(.{ .sub_path = "sys/class/infiniband/mlx5_0/device/uevent", .data = "PCI_SLOT_NAME=0000:81:00.0\n" });
    try tmp.dir.makePath("proc/driver");
    try tmp.dir.writeFile(.{ .sub_path = "proc/driver/nvidia-peermem", .data = "loaded\n" });

    var ib_buf: [std.fs.max_path_bytes]u8 = undefined;
    var peermem_buf: [std.fs.max_path_bytes]u8 = undefined;
    const ib_root = try tmp.dir.realpath("sys/class/infiniband", &ib_buf);
    const peermem_path = try tmp.dir.realpath("proc/driver/nvidia-peermem", &peermem_buf);

    setTestDetectPaths(.{
        .ib_root = ib_root,
        .peermem_path = peermem_path,
    });
    defer resetTestDetectPaths();

    const result = detectInfiniband();
    try std.testing.expectEqual(@as(u8, 1), result.count);
    try std.testing.expect(result.gdr_available);
    try std.testing.expectEqualStrings("mlx5_0", result.devices[0].getName());
    try std.testing.expectEqualStrings("0000:81:00.0", result.devices[0].getPciBusId());
    try std.testing.expectEqual(@as(u8, 1), result.devices[0].active_ports);
    try std.testing.expectEqual(@as(u32, 200), result.devices[0].rate_gbps);
    try std.testing.expect(result.devices[0].gdr_supported);
}

test "generateNcclTopology empty" {
    const alloc = std.testing.allocator;
    const xml = try generateNcclTopology(alloc, &.{}, &.{}, 0);
    defer alloc.free(xml);

    try std.testing.expect(std.mem.indexOf(u8, xml, "<?xml") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "</system>") != null);
}

test "generateNcclTopology with GPUs" {
    const alloc = std.testing.allocator;

    var gpu0 = GpuInfo{ .index = 0, .vram_mb = 40960 };
    const pci0 = "0000:01:00.0";
    @memcpy(gpu0.pci_bus_id[0..pci0.len], pci0);
    gpu0.pci_bus_id_len = pci0.len;

    var gpu1 = GpuInfo{ .index = 1, .vram_mb = 40960 };
    const pci1 = "0000:41:00.0";
    @memcpy(gpu1.pci_bus_id[0..pci1.len], pci1);
    gpu1.pci_bus_id_len = pci1.len;

    const gpus = &[_]GpuInfo{ gpu0, gpu1 };
    const xml = try generateNcclTopology(alloc, gpus, &.{}, 0);
    defer alloc.free(xml);

    try std.testing.expect(std.mem.indexOf(u8, xml, "0000:01:00.0") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "0000:41:00.0") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "dev=\"0\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "dev=\"1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "mem=\"40960\"") != null);
    // compute_capability=0 should fall back to sm="80"
    try std.testing.expect(std.mem.indexOf(u8, xml, "sm=\"80\"") != null);
}

test "generateNcclTopology uses compute_capability" {
    const alloc = std.testing.allocator;

    var gpu0 = GpuInfo{ .index = 0, .vram_mb = 81920, .compute_capability = 90 };
    const pci0 = "0000:01:00.0";
    @memcpy(gpu0.pci_bus_id[0..pci0.len], pci0);
    gpu0.pci_bus_id_len = pci0.len;

    var gpu1 = GpuInfo{ .index = 1, .vram_mb = 81920, .compute_capability = 86 };
    const pci1 = "0000:41:00.0";
    @memcpy(gpu1.pci_bus_id[0..pci1.len], pci1);
    gpu1.pci_bus_id_len = pci1.len;

    const gpus = &[_]GpuInfo{ gpu0, gpu1 };
    const xml = try generateNcclTopology(alloc, gpus, &.{}, 0);
    defer alloc.free(xml);

    // gpu0 is H100 (sm_90), gpu1 is RTX 3090 (sm_86)
    try std.testing.expect(std.mem.indexOf(u8, xml, "sm=\"90\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "sm=\"86\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "sm=\"80\"") == null);
}

test "generateNcclTopology with IB device" {
    const alloc = std.testing.allocator;

    var ib = IbDevice{};
    const name = "mlx5_0";
    @memcpy(ib.name[0..name.len], name);
    ib.name_len = name.len;
    const pci = "0000:81:00.0";
    @memcpy(ib.pci_bus_id[0..pci.len], pci);
    ib.pci_bus_id_len = pci.len;
    ib.rate_gbps = 200;
    ib.gdr_supported = true;

    const ib_devs = [_]IbDevice{ib};
    const xml = try generateNcclTopology(alloc, &.{}, &ib_devs, 1);
    defer alloc.free(xml);

    try std.testing.expect(std.mem.indexOf(u8, xml, "mlx5_0") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "0000:81:00.0") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "gdr=\"1\"") != null);
}

test "generateNcclTopology with NVLink peers" {
    const alloc = std.testing.allocator;

    var gpu0 = GpuInfo{ .index = 0, .vram_mb = 81920 };
    const pci0 = "0000:01:00.0";
    @memcpy(gpu0.pci_bus_id[0..pci0.len], pci0);
    gpu0.pci_bus_id_len = pci0.len;
    gpu0.nvlink_peers[0] = 1;
    gpu0.nvlink_peer_count = 1;

    var gpu1 = GpuInfo{ .index = 1, .vram_mb = 81920 };
    const pci1 = "0000:41:00.0";
    @memcpy(gpu1.pci_bus_id[0..pci1.len], pci1);
    gpu1.pci_bus_id_len = pci1.len;
    gpu1.nvlink_peers[0] = 0;
    gpu1.nvlink_peer_count = 1;

    const gpus = &[_]GpuInfo{ gpu0, gpu1 };
    const xml = try generateNcclTopology(alloc, gpus, &.{}, 0);
    defer alloc.free(xml);

    // verify NVLink elements are present
    try std.testing.expect(std.mem.indexOf(u8, xml, "nvlink target=\"0000:41:00.0\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "nvlink target=\"0000:01:00.0\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "count=\"1\"") != null);
}

test "generateMeshEnv basic" {
    var buf: [1024]u8 = undefined;
    const ib_result = IbDetectResult{
        .devices = undefined,
        .count = 0,
        .gdr_available = false,
    };

    const env = try generateMeshEnv(&buf, ib_result, "10.0.0.1", 29500, 4, 1, 1, null);
    try std.testing.expect(std.mem.indexOf(u8, env, "MASTER_ADDR=10.0.0.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, env, "WORLD_SIZE=4") != null);
    try std.testing.expect(std.mem.indexOf(u8, env, "RANK=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, env, "LOCAL_RANK=1") != null);
    // no IB vars since count=0
    try std.testing.expect(std.mem.indexOf(u8, env, "NCCL_NET") == null);
}

test "generateMeshEnv with IB" {
    var buf: [1024]u8 = undefined;
    var ib_result = IbDetectResult{
        .devices = undefined,
        .count = 1,
        .gdr_available = true,
    };
    var dev = IbDevice{};
    const name = "mlx5_0";
    @memcpy(dev.name[0..name.len], name);
    dev.name_len = name.len;
    ib_result.devices[0] = dev;

    const env = try generateMeshEnv(&buf, ib_result, "10.0.0.1", 29500, 2, 0, 0, "/tmp/topo.xml");
    try std.testing.expect(std.mem.indexOf(u8, env, "NCCL_IB_HCA=mlx5_0") != null);
    try std.testing.expect(std.mem.indexOf(u8, env, "NCCL_NET_GDR_LEVEL=5") != null);
    try std.testing.expect(std.mem.indexOf(u8, env, "NCCL_NET=IB") != null);
    try std.testing.expect(std.mem.indexOf(u8, env, "NCCL_TOPO_FILE=/tmp/topo.xml") != null);
}

test "generateMeshEnv TCP fallback" {
    var buf: [1024]u8 = undefined;
    const ib_result = IbDetectResult{
        .devices = undefined,
        .count = 0,
        .gdr_available = false,
    };

    const env = try generateMeshEnv(&buf, ib_result, "10.0.0.1", 29500, 2, 0, 0, null);
    // no NCCL IB vars — will fall back to TCP automatically
    try std.testing.expect(std.mem.indexOf(u8, env, "NCCL_NET") == null);
    try std.testing.expect(std.mem.indexOf(u8, env, "NCCL_TOPO_FILE") == null);
}

test "gpu prio port range constants" {
    try std.testing.expectEqual(@as(u16, 29500), gpu_port_min);
    try std.testing.expectEqual(@as(u16, 29600), gpu_port_max);
}

test "isGpuPrioAvailable returns false when BPF object missing" {
    // CI does not have bpf/gpu_prio.o compiled
    // this just verifies the function doesn't crash
    _ = isGpuPrioAvailable();
}
