// gpu commands — CLI frontend for GPU topology, diagnostics, and benchmarking
//
// exposes internal GPU detection, InfiniBand info, and NCCL benchmarking
// through the `yoq gpu <topo|bench>` commands.

const std = @import("std");
const platform = @import("platform");
const AppContext = @import("../lib/app_context.zig").AppContext;
const cli_output = @import("../lib/cli_output.zig");
const json_out = @import("../lib/json_output.zig");
const detect = @import("detect.zig");
const mesh = @import("mesh.zig");

const write = cli_output.write;
const writeErr = cli_output.writeErr;

const GpuCommandsError = error{
    InvalidArgument,
};

const GpuSubcommand = enum {
    topo,
    bench,
};

const ParsedGpuCommand = struct {
    subcommand: GpuSubcommand,
    bench_opts: BenchOpts = .{},
};

const Snapshot = struct {
    gpu: detect.DetectResult,
    ib: mesh.IbDetectResult,

    fn collect() Snapshot {
        return .{
            .gpu = detect.detect(),
            .ib = mesh.detectInfiniband(),
        };
    }

    fn deinit(self: *Snapshot) void {
        self.gpu.deinit();
    }
};

pub fn gpu(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    const parsed = try parseGpuCommand(args);

    switch (parsed.subcommand) {
        .topo => topo(),
        .bench => bench(ctx.alloc, parsed.bench_opts),
    }
}

const BenchOpts = struct {
    gpu_count: ?u32 = null,
    message_size: u64 = 33554432, // 32MB default (standard NCCL benchmark size)
    iterations: u32 = 100,
};

fn bench(alloc: std.mem.Allocator, opts: BenchOpts) void {
    var snapshot = Snapshot.collect();
    defer snapshot.deinit();

    benchWithSnapshot(alloc, opts, &snapshot);
}

fn benchWithSnapshot(alloc: std.mem.Allocator, opts: BenchOpts, snapshot: *Snapshot) void {
    const gpu_count = validateBenchSnapshot(opts, snapshot) orelse return;

    if (cli_output.output_mode == .json) {
        benchJson(alloc, gpu_count, opts, snapshot);
        return;
    }

    renderBenchHuman(alloc, gpu_count, opts, snapshot);
}

fn validateBenchSnapshot(opts: BenchOpts, snapshot: *const Snapshot) ?u32 {
    if (snapshot.gpu.count == 0) {
        writeErr("no GPUs detected — cannot run benchmark\n", .{});
        return null;
    }

    const gpu_count = opts.gpu_count orelse @as(u32, snapshot.gpu.count);
    if (gpu_count > snapshot.gpu.count) {
        writeErr("requested {d} GPUs but only {d} detected\n", .{ gpu_count, snapshot.gpu.count });
        return null;
    }

    if (gpu_count < 2) {
        writeErr("NCCL all-reduce benchmark requires at least 2 GPUs\n", .{});
        return null;
    }

    return gpu_count;
}

fn renderBenchHuman(alloc: std.mem.Allocator, gpu_count: u32, opts: BenchOpts, snapshot: *Snapshot) void {
    write("NCCL All-Reduce Benchmark\n", .{});
    write("========================\n\n", .{});
    write("GPUs:         {d}\n", .{gpu_count});
    write("Message size: {d} bytes ({d} MB)\n", .{ opts.message_size, opts.message_size / (1024 * 1024) });
    write("Iterations:   {d}\n", .{opts.iterations});
    write("Transport:    {s}\n", .{transportName(snapshot.ib)});

    if (snapshot.ib.count > 0) {
        write("IB device:    {s}\n", .{snapshot.ib.devices[0].getName()});
        write("GDR:          {s}\n", .{if (snapshot.ib.gdr_available) "enabled" else "disabled"});
    }

    const topo_xml = mesh.generateNcclTopology(
        alloc,
        snapshot.gpu.gpus[0..gpu_count],
        &snapshot.ib.devices,
        snapshot.ib.count,
    ) catch {
        writeErr("\nfailed to generate NCCL topology\n", .{});
        return;
    };
    defer alloc.free(topo_xml);

    write("\nNCCL topology generated ({d} bytes)\n", .{topo_xml.len});
    write("\nPer-rank NCCL configuration:\n", .{});
    for (0..gpu_count) |rank| {
        var env_buf: [1024]u8 = undefined;
        const env = mesh.generateMeshEnv(
            &env_buf,
            snapshot.ib,
            "127.0.0.1",
            mesh.gpu_port_min,
            gpu_count,
            @intCast(rank),
            @intCast(rank),
            null,
        ) catch {
            writeErr("  rank {d}: failed to generate env\n", .{rank});
            continue;
        };
        _ = env;
        write("  rank {d}: NCCL env ready\n", .{rank});
    }

    write("\nbenchmark ready — launch with:\n", .{});
    write("  torchrun --nproc_per_node={d} -m torch.distributed.all_reduce_bench \\\n", .{gpu_count});
    write("    --size {d} --iterations {d}\n", .{ opts.message_size, opts.iterations });

    if (snapshot.ib.count > 0) {
        write("\nrecommended NCCL env:\n", .{});
        write("  NCCL_IB_HCA={s}\n", .{snapshot.ib.devices[0].getName()});
        write("  NCCL_NET=IB\n", .{});
        if (snapshot.ib.gdr_available) {
            write("  NCCL_NET_GDR_LEVEL=5\n", .{});
        }
    }
}

fn benchJson(alloc: std.mem.Allocator, gpu_count: u32, opts: BenchOpts, snapshot: *Snapshot) void {
    var w = json_out.JsonWriter{};
    w.beginObject();

    w.uintField("gpu_count", gpu_count);
    w.uintField("message_size_bytes", opts.message_size);
    w.uintField("iterations", opts.iterations);
    w.stringField("transport", if (snapshot.ib.count > 0) "infiniband" else "tcp");
    w.boolField("gdr_available", snapshot.ib.gdr_available);

    w.beginArrayField("gpus");
    for (0..gpu_count) |i| {
        const g = &snapshot.gpu.gpus[i];
        w.beginObject();
        w.uintField("index", g.index);
        w.stringField("name", g.getName());
        w.uintField("vram_mb", g.vram_mb);
        w.stringField("pci_bus_id", g.getPciBusId());
        w.endObject();
    }
    w.endArray();

    if (snapshot.ib.count > 0) {
        w.beginArrayField("infiniband");
        for (0..snapshot.ib.count) |i| {
            const dev = &snapshot.ib.devices[i];
            w.beginObject();
            w.stringField("name", dev.getName());
            w.uintField("rate_gbps", dev.rate_gbps);
            w.endObject();
        }
        w.endArray();
    }

    // include NCCL topology info
    const topo_xml = mesh.generateNcclTopology(
        alloc,
        snapshot.gpu.gpus[0..gpu_count],
        &snapshot.ib.devices,
        snapshot.ib.count,
    ) catch {
        w.uintField("topology_size_bytes", 0);
        w.endObject();
        w.flush();
        return;
    };
    defer alloc.free(topo_xml);

    w.uintField("topology_size_bytes", topo_xml.len);
    w.stringField("status", "ready");

    w.endObject();
    w.flush();
}

fn topo() void {
    var snapshot = Snapshot.collect();
    defer snapshot.deinit();

    if (cli_output.output_mode == .json) {
        topoJson(&snapshot);
        return;
    }

    if (snapshot.gpu.count == 0) {
        write("no GPUs detected\n", .{});
    } else {
        write("{s:<6} {s:<24} {s:<10} {s:<16} {s:<8} {s:<6} {s}\n", .{
            "INDEX", "NAME", "VRAM", "PCI BDF", "NUMA", "SM", "NVLINK PEERS",
        });
        write("{s:->6} {s:->24} {s:->10} {s:->16} {s:->8} {s:->6} {s:->12}\n", .{
            "", "", "", "", "", "", "",
        });

        renderGpuTable(&snapshot.gpu);
    }

    renderIbTable(&snapshot.ib);
}

fn topoJson(snapshot: *Snapshot) void {
    var w = json_out.JsonWriter{};
    w.beginObject();

    w.beginArrayField("gpus");
    for (0..snapshot.gpu.count) |i| {
        const g = &snapshot.gpu.gpus[i];
        w.beginObject();
        w.uintField("index", g.index);
        w.stringField("name", g.getName());
        w.uintField("vram_mb", g.vram_mb);
        w.stringField("pci_bus_id", g.getPciBusId());
        w.intField("numa_node", g.numa_node);
        w.uintField("compute_capability", g.compute_capability);
        w.uintField("nvlink_peers", g.nvlink_peer_count);
        w.endObject();
    }
    w.endArray();

    w.beginArrayField("infiniband");
    for (0..snapshot.ib.count) |i| {
        const dev = &snapshot.ib.devices[i];
        w.beginObject();
        w.stringField("name", dev.getName());
        w.uintField("rate_gbps", dev.rate_gbps);
        w.boolField("gdr_supported", dev.gdr_supported);
        w.endObject();
    }
    w.endArray();

    w.stringField("source", @tagName(snapshot.gpu.source));
    w.endObject();
    w.flush();
}

fn parseGpuCommand(args: *std.process.Args.Iterator) !ParsedGpuCommand {
    var subcmd: ?[]const u8 = null;
    var bench_opts = BenchOpts{};

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            cli_output.output_mode = .json;
            continue;
        }

        if (std.mem.eql(u8, arg, "--gpus")) {
            bench_opts.gpu_count = try parseRequiredValue(args, "--gpus", u32, "invalid GPU count: {s}\n");
            continue;
        }

        if (std.mem.eql(u8, arg, "--size")) {
            bench_opts.message_size = try parseRequiredValue(args, "--size", u64, "invalid message size: {s}\n");
            continue;
        }

        if (std.mem.eql(u8, arg, "--iterations")) {
            bench_opts.iterations = try parseRequiredValue(args, "--iterations", u32, "invalid iteration count: {s}\n");
            continue;
        }

        if (subcmd == null) {
            subcmd = arg;
        }
    }

    const name = subcmd orelse {
        writeErr("usage: yoq gpu <topo|bench> [--json]\n", .{});
        return GpuCommandsError.InvalidArgument;
    };

    const subcommand = if (std.mem.eql(u8, name, "topo"))
        GpuSubcommand.topo
    else if (std.mem.eql(u8, name, "bench"))
        GpuSubcommand.bench
    else {
        writeErr("unknown gpu subcommand: {s}\n", .{name});
        return GpuCommandsError.InvalidArgument;
    };

    return .{
        .subcommand = subcommand,
        .bench_opts = bench_opts,
    };
}

fn parseRequiredValue(
    args: *std.process.Args.Iterator,
    flag: []const u8,
    comptime T: type,
    comptime invalid_fmt: []const u8,
) !T {
    const raw = args.next() orelse {
        if (std.mem.eql(u8, flag, "--size")) {
            writeErr("--size requires a byte count (e.g. 33554432 for 32MB)\n", .{});
        } else {
            writeErr("{s} requires a number\n", .{flag});
        }
        return GpuCommandsError.InvalidArgument;
    };

    return std.fmt.parseInt(T, raw, 10) catch {
        writeErr(invalid_fmt, .{raw});
        return GpuCommandsError.InvalidArgument;
    };
}

fn renderGpuTable(gpu_result: *const detect.DetectResult) void {
    for (0..gpu_result.count) |i| {
        const g = &gpu_result.gpus[i];
        var vram_buf: [16]u8 = undefined;
        var numa_buf: [8]u8 = undefined;
        var sm_buf: [8]u8 = undefined;
        var peers_buf: [48]u8 = undefined;

        write("{d:<6} {s:<24} {s:<10} {s:<16} {s:<8} {s:<6} {s}\n", .{
            g.index,
            g.getName(),
            formatGpuVram(g, &vram_buf),
            g.getPciBusId(),
            formatGpuNuma(g, &numa_buf),
            formatGpuSm(g, &sm_buf),
            formatGpuPeers(g, &peers_buf),
        });
    }
}

fn renderIbTable(ib_result: *const mesh.IbDetectResult) void {
    if (ib_result.count == 0) return;

    write("\nInfiniBand devices:\n", .{});
    write("{s:<16} {s:<12} {s}\n", .{ "DEVICE", "RATE", "GDR" });
    write("{s:->16} {s:->12} {s:->5}\n", .{ "", "", "" });

    for (0..ib_result.count) |i| {
        const dev = &ib_result.devices[i];
        var rate_buf: [16]u8 = undefined;
        const rate = std.fmt.bufPrint(&rate_buf, "{d} Gb/s", .{dev.rate_gbps}) catch "?";
        write("{s:<16} {s:<12} {s}\n", .{
            dev.getName(),
            rate,
            if (dev.gdr_supported) "yes" else "no",
        });
    }
}

fn transportName(ib_result: mesh.IbDetectResult) []const u8 {
    return if (ib_result.count > 0) "InfiniBand" else "TCP";
}

fn formatGpuVram(info: *const detect.GpuInfo, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d} MB", .{info.vram_mb}) catch "?";
}

fn formatGpuNuma(info: *const detect.GpuInfo, buf: []u8) []const u8 {
    if (info.numa_node < 0) return "-";
    return std.fmt.bufPrint(buf, "{d}", .{info.numa_node}) catch "?";
}

fn formatGpuSm(info: *const detect.GpuInfo, buf: []u8) []const u8 {
    if (info.compute_capability == 0) return "-";
    return std.fmt.bufPrint(buf, "{d}", .{info.compute_capability}) catch "?";
}

fn formatGpuPeers(info: *const detect.GpuInfo, buf: []u8) []const u8 {
    var stream: std.Io.Writer = .fixed(buf);

    for (0..info.nvlink_peer_count) |i| {
        if (i > 0) {
            stream.writeByte(',') catch break;
        }
        stream.print("{d}", .{info.nvlink_peers[i]}) catch break;
    }

    const written = stream.buffered();
    return if (written.len > 0) written else "-";
}

// -- tests --

test "topo json output format" {
    // save and restore output mode
    const saved = cli_output.output_mode;
    defer cli_output.output_mode = saved;
    cli_output.output_mode = .json;

    const gpu_result = detect.DetectResult{
        .gpus = undefined,
        .count = 0,
        .source = .none,
        .nvml = null,
    };

    const ib_result = mesh.IbDetectResult{
        .devices = undefined,
        .count = 0,
        .gdr_available = false,
    };

    // should not crash with zero GPUs and zero IB devices
    var snapshot = Snapshot{
        .gpu = gpu_result,
        .ib = ib_result,
    };

    topoJson(&snapshot);
}

test "bench with zero GPUs does not crash" {
    const saved = cli_output.output_mode;
    defer cli_output.output_mode = saved;
    cli_output.output_mode = .human;

    var snapshot = Snapshot{
        .gpu = .{
            .gpus = undefined,
            .count = 0,
            .source = .none,
            .nvml = null,
        },
        .ib = .{
            .devices = undefined,
            .count = 0,
            .gdr_available = false,
        },
    };

    benchWithSnapshot(std.testing.allocator, .{}, &snapshot);
}

test "bench json with zero GPUs does not crash" {
    const saved = cli_output.output_mode;
    defer cli_output.output_mode = saved;
    cli_output.output_mode = .json;

    var snapshot = Snapshot{
        .gpu = .{
            .gpus = undefined,
            .count = 0,
            .source = .none,
            .nvml = null,
        },
        .ib = .{
            .devices = undefined,
            .count = 0,
            .gdr_available = false,
        },
    };

    benchWithSnapshot(std.testing.allocator, .{}, &snapshot);
}

test "bench opts defaults" {
    const opts = BenchOpts{};
    try std.testing.expect(opts.gpu_count == null);
    try std.testing.expectEqual(@as(u64, 33554432), opts.message_size);
    try std.testing.expectEqual(@as(u32, 100), opts.iterations);
}
