// gpu commands — CLI frontend for GPU topology and diagnostics
//
// exposes internal GPU detection and InfiniBand info to operators
// through the `yoq gpu topo` command.

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
    _ = alloc;
    var subcmd: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            cli.output_mode = .json;
        } else if (subcmd == null) {
            subcmd = arg;
        }
    }

    const cmd = subcmd orelse {
        writeErr("usage: yoq gpu <topo>\n", .{});
        return GpuCommandsError.InvalidArgument;
    };

    if (std.mem.eql(u8, cmd, "topo")) {
        topo();
    } else {
        writeErr("unknown gpu subcommand: {s}\n", .{cmd});
        return GpuCommandsError.InvalidArgument;
    }
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
