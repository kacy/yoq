// gpu commands — CLI frontend for GPU topology, diagnostics, and benchmarking
//
// exposes internal GPU detection, InfiniBand info, and NCCL benchmarking
// through the `yoq gpu <topo|bench>` commands.

const std = @import("std");
const cli = @import("../lib/cli.zig");
const json_out = @import("../lib/json_output.zig");
const detect = @import("detect.zig");
const mesh = @import("mesh.zig");

const write = cli.write;
const writeErr = cli.writeErr;

const GpuCommandsError = error{
    InvalidArgument,
};

pub fn gpu(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var subcmd: ?[]const u8 = null;
    var bench_opts = BenchOpts{};

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            cli.output_mode = .json;
        } else if (std.mem.eql(u8, arg, "--gpus")) {
            const n = args.next() orelse {
                writeErr("--gpus requires a number\n", .{});
                return GpuCommandsError.InvalidArgument;
            };
            bench_opts.gpu_count = std.fmt.parseInt(u32, n, 10) catch {
                writeErr("invalid GPU count: {s}\n", .{n});
                return GpuCommandsError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--size")) {
            const n = args.next() orelse {
                writeErr("--size requires a byte count (e.g. 33554432 for 32MB)\n", .{});
                return GpuCommandsError.InvalidArgument;
            };
            bench_opts.message_size = std.fmt.parseInt(u64, n, 10) catch {
                writeErr("invalid message size: {s}\n", .{n});
                return GpuCommandsError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--iterations")) {
            const n = args.next() orelse {
                writeErr("--iterations requires a number\n", .{});
                return GpuCommandsError.InvalidArgument;
            };
            bench_opts.iterations = std.fmt.parseInt(u32, n, 10) catch {
                writeErr("invalid iteration count: {s}\n", .{n});
                return GpuCommandsError.InvalidArgument;
            };
        } else if (subcmd == null) {
            subcmd = arg;
        }
    }

    const cmd = subcmd orelse {
        writeErr("usage: yoq gpu <topo|bench> [--json]\n", .{});
        return GpuCommandsError.InvalidArgument;
    };

    if (std.mem.eql(u8, cmd, "topo")) {
        topo();
    } else if (std.mem.eql(u8, cmd, "bench")) {
        bench(alloc, bench_opts);
    } else {
        writeErr("unknown gpu subcommand: {s}\n", .{cmd});
        return GpuCommandsError.InvalidArgument;
    }
}

const BenchOpts = struct {
    gpu_count: ?u32 = null,
    message_size: u64 = 33554432, // 32MB default (standard NCCL benchmark size)
    iterations: u32 = 100,
};

fn bench(alloc: std.mem.Allocator, opts: BenchOpts) void {
    var gpu_result = detect.detect();
    defer gpu_result.deinit();

    const ib_result = mesh.detectInfiniband();

    if (gpu_result.count == 0) {
        writeErr("no GPUs detected — cannot run benchmark\n", .{});
        return;
    }

    const gpu_count = opts.gpu_count orelse @as(u32, gpu_result.count);
    if (gpu_count > gpu_result.count) {
        writeErr("requested {d} GPUs but only {d} detected\n", .{ gpu_count, gpu_result.count });
        return;
    }

    if (gpu_count < 2) {
        writeErr("NCCL all-reduce benchmark requires at least 2 GPUs\n", .{});
        return;
    }

    if (cli.output_mode == .json) {
        benchJson(alloc, gpu_count, opts, &gpu_result, &ib_result);
        return;
    }

    write("NCCL All-Reduce Benchmark\n", .{});
    write("========================\n\n", .{});
    write("GPUs:         {d}\n", .{gpu_count});
    write("Message size: {d} bytes ({d} MB)\n", .{ opts.message_size, opts.message_size / (1024 * 1024) });
    write("Iterations:   {d}\n", .{opts.iterations});
    write("Transport:    {s}\n", .{if (ib_result.count > 0) "InfiniBand" else "TCP"});

    if (ib_result.count > 0) {
        write("IB device:    {s}\n", .{ib_result.devices[0].getName()});
        write("GDR:          {s}\n", .{if (ib_result.gdr_available) "enabled" else "disabled"});
    }

    // generate NCCL topology and mesh env for the benchmark
    const topo_xml = mesh.generateNcclTopology(
        alloc,
        gpu_result.gpus[0..gpu_count],
        &ib_result.devices,
        ib_result.count,
    ) catch {
        writeErr("\nfailed to generate NCCL topology\n", .{});
        return;
    };
    defer alloc.free(topo_xml);

    write("\nNCCL topology generated ({d} bytes)\n", .{topo_xml.len});

    // generate per-rank environment variables
    write("\nPer-rank NCCL configuration:\n", .{});
    for (0..gpu_count) |rank| {
        var env_buf: [1024]u8 = undefined;
        const env = mesh.generateMeshEnv(
            &env_buf,
            ib_result,
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

    if (ib_result.count > 0) {
        write("\nrecommended NCCL env:\n", .{});
        write("  NCCL_IB_HCA={s}\n", .{ib_result.devices[0].getName()});
        write("  NCCL_NET=IB\n", .{});
        if (ib_result.gdr_available) {
            write("  NCCL_NET_GDR_LEVEL=5\n", .{});
        }
    }
}

fn benchJson(alloc: std.mem.Allocator, gpu_count: u32, opts: BenchOpts, gpu_result: *detect.DetectResult, ib_result: *const mesh.IbDetectResult) void {
    var w = json_out.JsonWriter{};
    w.beginObject();

    w.uintField("gpu_count", gpu_count);
    w.uintField("message_size_bytes", opts.message_size);
    w.uintField("iterations", opts.iterations);
    w.stringField("transport", if (ib_result.count > 0) "infiniband" else "tcp");
    w.boolField("gdr_available", ib_result.gdr_available);

    w.beginArrayField("gpus");
    for (0..gpu_count) |i| {
        const g = &gpu_result.gpus[i];
        w.beginObject();
        w.uintField("index", g.index);
        w.stringField("name", g.getName());
        w.uintField("vram_mb", g.vram_mb);
        w.stringField("pci_bus_id", g.getPciBusId());
        w.endObject();
    }
    w.endArray();

    if (ib_result.count > 0) {
        w.beginArrayField("infiniband");
        for (0..ib_result.count) |i| {
            const dev = &ib_result.devices[i];
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
        gpu_result.gpus[0..gpu_count],
        &ib_result.devices,
        ib_result.count,
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
    var gpu_result = detect.detect();
    defer gpu_result.deinit();

    const ib_result = mesh.detectInfiniband();

    if (cli.output_mode == .json) {
        topoJson(&gpu_result, &ib_result);
        return;
    }

    if (gpu_result.count == 0) {
        write("no GPUs detected\n", .{});
    } else {
        write("{s:<6} {s:<24} {s:<10} {s:<16} {s:<8} {s:<6} {s}\n", .{
            "INDEX", "NAME", "VRAM", "PCI BDF", "NUMA", "SM", "NVLINK PEERS",
        });
        write("{s:->6} {s:->24} {s:->10} {s:->16} {s:->8} {s:->6} {s:->12}\n", .{
            "", "", "", "", "", "", "",
        });

        for (0..gpu_result.count) |i| {
            const g = &gpu_result.gpus[i];

            var vram_buf: [16]u8 = undefined;
            const vram_str = std.fmt.bufPrint(&vram_buf, "{d} MB", .{g.vram_mb}) catch "?";

            var numa_buf: [8]u8 = undefined;
            const numa_str = if (g.numa_node >= 0)
                std.fmt.bufPrint(&numa_buf, "{d}", .{g.numa_node}) catch "?"
            else
                "-";

            var sm_buf: [8]u8 = undefined;
            const sm_str = if (g.compute_capability != 0)
                std.fmt.bufPrint(&sm_buf, "{d}", .{g.compute_capability}) catch "?"
            else
                "-";

            var peers_buf: [48]u8 = undefined;
            var peers_len: usize = 0;
            for (0..g.nvlink_peer_count) |p| {
                if (peers_len > 0) {
                    if (peers_len < peers_buf.len) {
                        peers_buf[peers_len] = ',';
                        peers_len += 1;
                    }
                }
                const s = std.fmt.bufPrint(peers_buf[peers_len..], "{d}", .{g.nvlink_peers[p]}) catch break;
                peers_len += s.len;
            }
            const peers_str = if (peers_len > 0) peers_buf[0..peers_len] else "-";

            write("{d:<6} {s:<24} {s:<10} {s:<16} {s:<8} {s:<6} {s}\n", .{
                g.index,
                g.getName(),
                vram_str,
                g.getPciBusId(),
                numa_str,
                sm_str,
                peers_str,
            });
        }
    }

    // InfiniBand section
    if (ib_result.count > 0) {
        write("\nInfiniBand devices:\n", .{});
        write("{s:<16} {s:<12} {s}\n", .{ "DEVICE", "RATE", "GDR" });
        write("{s:->16} {s:->12} {s:->5}\n", .{ "", "", "" });

        for (0..ib_result.count) |i| {
            const dev = &ib_result.devices[i];
            var rate_buf: [16]u8 = undefined;
            const rate_str = std.fmt.bufPrint(&rate_buf, "{d} Gb/s", .{dev.rate_gbps}) catch "?";
            write("{s:<16} {s:<12} {s}\n", .{
                dev.getName(),
                rate_str,
                if (dev.gdr_supported) "yes" else "no",
            });
        }
    }
}

fn topoJson(gpu_result: *detect.DetectResult, ib_result: *const mesh.IbDetectResult) void {
    var w = json_out.JsonWriter{};
    w.beginObject();

    w.beginArrayField("gpus");
    for (0..gpu_result.count) |i| {
        const g = &gpu_result.gpus[i];
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
    for (0..ib_result.count) |i| {
        const dev = &ib_result.devices[i];
        w.beginObject();
        w.stringField("name", dev.getName());
        w.uintField("rate_gbps", dev.rate_gbps);
        w.boolField("gdr_supported", dev.gdr_supported);
        w.endObject();
    }
    w.endArray();

    w.stringField("source", @tagName(gpu_result.source));
    w.endObject();
    w.flush();
}

// -- tests --

test "topo json output format" {
    // save and restore output mode
    const saved = cli.output_mode;
    defer cli.output_mode = saved;
    cli.output_mode = .json;

    var gpu_result = detect.DetectResult{
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
    topoJson(&gpu_result, &ib_result);
}

test "bench with zero GPUs does not crash" {
    const saved = cli.output_mode;
    defer cli.output_mode = saved;
    cli.output_mode = .human;

    // bench should print an error and return gracefully
    bench(std.testing.allocator, .{});
}

test "bench json with zero GPUs does not crash" {
    const saved = cli.output_mode;
    defer cli.output_mode = saved;
    cli.output_mode = .json;

    bench(std.testing.allocator, .{});
}

test "bench opts defaults" {
    const opts = BenchOpts{};
    try std.testing.expect(opts.gpu_count == null);
    try std.testing.expectEqual(@as(u64, 33554432), opts.message_size);
    try std.testing.expectEqual(@as(u32, 100), opts.iterations);
}
