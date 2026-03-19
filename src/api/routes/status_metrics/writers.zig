const monitor = @import("../../../runtime/monitor.zig");

pub fn writeSnapshotJson(writer: anytype, snap: monitor.ServiceSnapshot) !void {
    try writer.print("{{\"name\":\"{s}\",\"status\":\"{s}\",", .{ snap.name, monitor.formatStatus(snap.status) });

    if (snap.health_status) |health_status| {
        try writer.print("\"health\":\"{s}\",", .{monitor.formatHealth(health_status)});
    } else {
        try writer.writeAll("\"health\":null,");
    }

    try writer.print(
        "\"cpu_pct\":{d:.1},\"memory_bytes\":{d},\"running\":{d},\"desired\":{d},\"uptime_secs\":{d}",
        .{ snap.cpu_pct, snap.memory_bytes, snap.running_count, snap.desired_count, snap.uptime_secs },
    );

    if (snap.psi_cpu) |psi| {
        try writer.print(",\"psi_cpu_some\":{d:.2},\"psi_cpu_full\":{d:.2}", .{ psi.some_avg10, psi.full_avg10 });
    }
    if (snap.psi_memory) |psi| {
        try writer.print(",\"psi_mem_some\":{d:.2},\"psi_mem_full\":{d:.2}", .{ psi.some_avg10, psi.full_avg10 });
    }

    if (snap.io_read_bytes > 0 or snap.io_write_bytes > 0) {
        try writer.print(",\"io_read_bytes\":{d},\"io_write_bytes\":{d}", .{ snap.io_read_bytes, snap.io_write_bytes });
    }

    try writer.writeByte('}');
}
