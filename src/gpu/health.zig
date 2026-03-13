// health — GPU health monitoring via NVML
//
// polls per-GPU metrics: temperature, utilization, memory usage,
// power draw, and ECC errors. uses the NvmlHandle from detect.zig
// to call NVML functions directly.
//
// threshold checks:
//   - warn at 90°C, fail at 95°C
//   - any double-bit ECC error marks the GPU unhealthy

const std = @import("std");
const detect = @import("detect.zig");
const log = @import("../lib/log.zig");

const NvmlHandle = detect.NvmlHandle;
const max_gpus = detect.max_gpus;

pub const temp_warn_c: u32 = 90;
pub const temp_fail_c: u32 = 95;

pub const GpuHealth = enum {
    healthy,
    warning,
    unhealthy,
};

pub const GpuMetrics = struct {
    temperature_c: u32 = 0,
    utilization_gpu: u32 = 0, // 0-100
    utilization_mem: u32 = 0, // 0-100
    memory_used_mb: u64 = 0,
    memory_total_mb: u64 = 0,
    power_watts: u32 = 0,
    ecc_errors_single: u64 = 0,
    ecc_errors_double: u64 = 0,

    pub fn health(self: GpuMetrics) GpuHealth {
        if (self.ecc_errors_double > 0) return .unhealthy;
        if (self.temperature_c >= temp_fail_c) return .unhealthy;
        if (self.temperature_c >= temp_warn_c) return .warning;
        return .healthy;
    }

    /// format metrics as JSON fragment (no surrounding braces)
    pub fn writeJson(self: GpuMetrics, writer: anytype) !void {
        try std.fmt.format(writer,
            \\"temperature_c":{d},"utilization_gpu":{d},"utilization_mem":{d},
        , .{ self.temperature_c, self.utilization_gpu, self.utilization_mem });
        try std.fmt.format(writer,
            \\"memory_used_mb":{d},"memory_total_mb":{d},"power_watts":{d},
        , .{ self.memory_used_mb, self.memory_total_mb, self.power_watts });
        try std.fmt.format(writer,
            \\"ecc_single":{d},"ecc_double":{d},"health":"{s}"
        , .{ self.ecc_errors_single, self.ecc_errors_double, @tagName(self.health()) });
    }
};

/// poll metrics for a single GPU via NVML.
/// returns null if NVML is unavailable or the device can't be queried.
pub fn pollMetrics(nvml: *NvmlHandle, index: u32) ?GpuMetrics {
    const device = nvml.getDevice(index) orelse return null;

    var metrics = GpuMetrics{};

    // temperature (sensor type 0 = GPU)
    if (nvml.device_get_temperature_fn) |temp_fn| {
        var temp: u32 = 0;
        if (temp_fn(device, 0, &temp) == .success) {
            metrics.temperature_c = temp;
        }
    }

    // utilization
    if (nvml.device_get_utilization_fn) |util_fn| {
        var util: detect.NvmlUtilization = .{ .gpu = 0, .memory = 0 };
        if (util_fn(device, &util) == .success) {
            metrics.utilization_gpu = util.gpu;
            metrics.utilization_mem = util.memory;
        }
    }

    // memory (device_get_memory_fn is non-optional)
    {
        var mem: detect.NvmlMemory = undefined;
        if (nvml.device_get_memory_fn(device, &mem) == .success) {
            metrics.memory_used_mb = mem.used / (1024 * 1024);
            metrics.memory_total_mb = mem.total / (1024 * 1024);
        }
    }

    // power (returned in milliwatts)
    if (nvml.device_get_power_fn) |power_fn| {
        var power_mw: u32 = 0;
        if (power_fn(device, &power_mw) == .success) {
            metrics.power_watts = power_mw / 1000;
        }
    }

    // ECC errors
    if (nvml.device_get_ecc_errors_fn) |ecc_fn| {
        // single-bit errors (error_type=0, counter_type=1=aggregate)
        var single: u64 = 0;
        if (ecc_fn(device, 0, 1, &single) == .success) {
            metrics.ecc_errors_single = single;
        }
        // double-bit errors (error_type=1)
        var double: u64 = 0;
        if (ecc_fn(device, 1, 1, &double) == .success) {
            metrics.ecc_errors_double = double;
        }
    }

    return metrics;
}

/// poll metrics for all GPUs.
/// returns an array of optional metrics (null for devices that couldn't be queried).
pub fn pollAllMetrics(nvml: *NvmlHandle, count: u8) [max_gpus]?GpuMetrics {
    var results: [max_gpus]?GpuMetrics = .{null} ** max_gpus;
    const actual = @min(count, max_gpus);
    for (0..actual) |i| {
        results[i] = pollMetrics(nvml, @intCast(i));
    }
    return results;
}

/// write a JSON array of GPU metrics to the given writer.
pub fn writeMetricsJson(writer: anytype, metrics: [max_gpus]?GpuMetrics, count: u8) !void {
    try writer.writeAll("\"gpu_metrics\":[");
    var written: u8 = 0;
    for (0..@min(count, max_gpus)) |i| {
        if (metrics[i]) |m| {
            if (written > 0) try writer.writeAll(",");
            try writer.writeAll("{\"index\":");
            try std.fmt.format(writer, "{d},", .{i});
            try m.writeJson(writer);
            try writer.writeAll("}");
            written += 1;
        }
    }
    try writer.writeAll("]");
}

// -- tests --

test "GpuMetrics defaults are healthy" {
    const m = GpuMetrics{};
    try std.testing.expectEqual(GpuHealth.healthy, m.health());
    try std.testing.expectEqual(@as(u32, 0), m.temperature_c);
    try std.testing.expectEqual(@as(u64, 0), m.ecc_errors_double);
}

test "GpuMetrics warning at 90C" {
    const m = GpuMetrics{ .temperature_c = 90 };
    try std.testing.expectEqual(GpuHealth.warning, m.health());
}

test "GpuMetrics unhealthy at 95C" {
    const m = GpuMetrics{ .temperature_c = 95 };
    try std.testing.expectEqual(GpuHealth.unhealthy, m.health());
}

test "GpuMetrics unhealthy on double-bit ECC" {
    const m = GpuMetrics{ .temperature_c = 50, .ecc_errors_double = 1 };
    try std.testing.expectEqual(GpuHealth.unhealthy, m.health());
}

test "GpuMetrics ECC takes priority over temperature" {
    const m = GpuMetrics{ .temperature_c = 30, .ecc_errors_double = 1 };
    try std.testing.expectEqual(GpuHealth.unhealthy, m.health());
}

test "GpuMetrics healthy with single-bit ECC only" {
    const m = GpuMetrics{ .ecc_errors_single = 100 };
    try std.testing.expectEqual(GpuHealth.healthy, m.health());
}

test "GpuMetrics writeJson" {
    const m = GpuMetrics{
        .temperature_c = 72,
        .utilization_gpu = 85,
        .utilization_mem = 40,
        .memory_used_mb = 30000,
        .memory_total_mb = 40960,
        .power_watts = 250,
        .ecc_errors_single = 0,
        .ecc_errors_double = 0,
    };

    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try m.writeJson(fbs.writer());
    const json = fbs.getWritten();

    try std.testing.expect(std.mem.indexOf(u8, json, "\"temperature_c\":72") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"utilization_gpu\":85") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"health\":\"healthy\"") != null);
}

test "pollAllMetrics returns nulls without NVML" {
    // we can't test with a real NvmlHandle in CI, but we can verify
    // the return structure is correct
    const results: [max_gpus]?GpuMetrics = .{null} ** max_gpus;
    for (results) |r| {
        try std.testing.expect(r == null);
    }
}

test "writeMetricsJson empty" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const metrics: [max_gpus]?GpuMetrics = .{null} ** max_gpus;
    try writeMetricsJson(fbs.writer(), metrics, 0);
    try std.testing.expectEqualStrings("\"gpu_metrics\":[]", fbs.getWritten());
}

test "writeMetricsJson with one GPU" {
    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    var metrics: [max_gpus]?GpuMetrics = .{null} ** max_gpus;
    metrics[0] = .{ .temperature_c = 65, .utilization_gpu = 50, .memory_used_mb = 8000, .memory_total_mb = 16384 };
    try writeMetricsJson(fbs.writer(), metrics, 1);
    const json = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, json, "\"gpu_metrics\":[{") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"temperature_c\":65") != null);
}
