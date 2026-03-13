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
const detect = @import("detect.zig");
const log = @import("../lib/log.zig");

const Allocator = std.mem.Allocator;
const GpuInfo = detect.GpuInfo;

pub const max_ib_devices = 4;

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

/// detect InfiniBand devices by scanning sysfs.
pub fn detectInfiniband() IbDetectResult {
    var result = IbDetectResult{
        .devices = undefined,
        .count = 0,
        .gdr_available = false,
    };

    // check for GPUDirect RDMA (nvidia-peermem)
    result.gdr_available = checkGdr();

    var ib_dir = std.fs.openDirAbsolute("/sys/class/infiniband", .{ .iterate = true }) catch return result;
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
    const file = std.fs.cwd().openFile("/proc/driver/nvidia-peermem", .{}) catch {
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
        const path = std.fmt.bufPrint(&path_buf, "/sys/class/infiniband/{s}/ports/{d}/state", .{ dev_name, port }) catch continue;
        const content = readSmallFile(path) orelse continue;
        if (std.mem.indexOf(u8, content.slice(), "ACTIVE") != null) {
            active += 1;
        }
    }
    return active;
}

fn readPortRate(dev_name: []const u8) u32 {
    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/sys/class/infiniband/{s}/ports/1/rate", .{dev_name}) catch return 0;
    const content = readSmallFile(path) orelse return 0;
    const trimmed = std.mem.trim(u8, content.slice(), " \t\n\r");
    // format is like "200 Gb/sec" — parse the number
    const space_idx = std.mem.indexOfScalar(u8, trimmed, ' ') orelse return 0;
    return std.fmt.parseInt(u32, trimmed[0..space_idx], 10) catch 0;
}

fn readIbPciBusId(dev_name: []const u8, dev: *IbDevice) void {
    // the device directory often has a symlink to the PCI device
    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/sys/class/infiniband/{s}/device/uevent", .{dev_name}) catch return;
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

    // GPUs
    for (gpus) |gpu| {
        const pci = gpu.getPciBusId();
        if (pci.len == 0) continue;
        try buf.appendSlice(alloc, "    <pci busid=\"");
        try buf.appendSlice(alloc, pci);
        try buf.appendSlice(alloc, "\" class=\"0x030200\" link_speed=\"16 GT/s\" link_width=\"16\">\n");
        try buf.appendSlice(alloc, "      <gpu dev=\"");
        try std.fmt.format(buf.writer(alloc), "{d}", .{gpu.index});
        try buf.appendSlice(alloc, "\" sm=\"80\" mem=\"");
        try std.fmt.format(buf.writer(alloc), "{d}", .{gpu.vram_mb});
        try buf.appendSlice(alloc, "\" />\n");
        try buf.appendSlice(alloc, "    </pci>\n");
    }

    // NICs
    for (0..@min(ib_count, max_ib_devices)) |i| {
        const nic = ib_devices[i];
        const pci = nic.getPciBusId();
        if (pci.len == 0) continue;
        try buf.appendSlice(alloc, "    <pci busid=\"");
        try buf.appendSlice(alloc, pci);
        try buf.appendSlice(alloc, "\" class=\"0x020700\" link_speed=\"16 GT/s\" link_width=\"16\">\n");
        try buf.appendSlice(alloc, "      <nic name=\"");
        try buf.appendSlice(alloc, nic.getName());
        try buf.appendSlice(alloc, "\" speed=\"");
        try std.fmt.format(buf.writer(alloc), "{d}", .{nic.rate_gbps});
        try buf.appendSlice(alloc, "\" gdr=\"");
        try buf.appendSlice(alloc, if (nic.gdr_supported) "1" else "0");
        try buf.appendSlice(alloc, "\" />\n");
        try buf.appendSlice(alloc, "    </pci>\n");
    }

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
    var pos: usize = 0;

    // core distributed training vars
    pos += (std.fmt.bufPrint(buf[pos..], "MASTER_ADDR={s}", .{master_addr}) catch return error.BufferTooSmall).len;
    buf[pos] = 0;
    pos += 1;

    pos += (std.fmt.bufPrint(buf[pos..], "MASTER_PORT={d}", .{master_port}) catch return error.BufferTooSmall).len;
    buf[pos] = 0;
    pos += 1;

    pos += (std.fmt.bufPrint(buf[pos..], "WORLD_SIZE={d}", .{world_size}) catch return error.BufferTooSmall).len;
    buf[pos] = 0;
    pos += 1;

    pos += (std.fmt.bufPrint(buf[pos..], "RANK={d}", .{rank}) catch return error.BufferTooSmall).len;
    buf[pos] = 0;
    pos += 1;

    pos += (std.fmt.bufPrint(buf[pos..], "LOCAL_RANK={d}", .{local_rank}) catch return error.BufferTooSmall).len;
    buf[pos] = 0;
    pos += 1;

    // NCCL IB configuration
    if (ib_result.count > 0) {
        // set IB HCA name
        const ib_name = ib_result.devices[0].getName();
        if (ib_name.len > 0) {
            pos += (std.fmt.bufPrint(buf[pos..], "NCCL_IB_HCA={s}", .{ib_name}) catch return error.BufferTooSmall).len;
            buf[pos] = 0;
            pos += 1;
        }

        // enable GPUDirect RDMA if available
        if (ib_result.gdr_available) {
            const gdr = "NCCL_NET_GDR_LEVEL=5";
            @memcpy(buf[pos..][0..gdr.len], gdr);
            pos += gdr.len;
            buf[pos] = 0;
            pos += 1;
        }

        const net = "NCCL_NET=IB";
        @memcpy(buf[pos..][0..net.len], net);
        pos += net.len;
        buf[pos] = 0;
        pos += 1;
    }

    // topology file
    if (topo_file) |tf| {
        pos += (std.fmt.bufPrint(buf[pos..], "NCCL_TOPO_FILE={s}", .{tf}) catch return error.BufferTooSmall).len;
        buf[pos] = 0;
        pos += 1;
    }

    return buf[0..pos];
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
