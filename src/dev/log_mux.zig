// log_mux — colored terminal log multiplexing for dev mode
//
// routes log output from multiple services to the terminal with
// colored service name prefixes. a mutex prevents interleaving
// when multiple capture threads write simultaneously.
//
// format: "\x1b[36m[web]     \x1b[0m | log line here"

const std = @import("std");
const platform = @import("platform");
const log = @import("../lib/log.zig");

/// ansi colors for service name prefixes
const colors = [_][]const u8{
    "\x1b[36m", // cyan
    "\x1b[33m", // yellow
    "\x1b[32m", // green
    "\x1b[35m", // magenta
    "\x1b[34m", // blue
    "\x1b[31m", // red
    "\x1b[96m", // bright cyan
    "\x1b[93m", // bright yellow
};
const reset = "\x1b[0m";

/// atomic counter for thread-safe write failure tracking
pub var write_failures: std.atomic.Value(usize) = .init(0);

/// mutex for thread-safe output. initialized explicitly to avoid
/// relying on compile-time zero initialization.
var write_mutex: platform.Mutex = platform.Mutex{};

/// maximum formatted line length (excluding null terminator)
const max_line_len = 8192;

/// write a single log line to stderr with a colored service name prefix.
/// thread-safe — uses a mutex to prevent interleaved output.
/// tracks write failures in atomic write_failures counter.
/// handles long lines by truncating with a suffix indicator.
pub fn writeLine(service_name: []const u8, color_idx: usize, line: []const u8) void {
    const color = colors[color_idx % colors.len];

    // format the line with prefix
    var format_buf: [max_line_len]u8 = undefined;
    const formatted = std.fmt.bufPrint(&format_buf, "{s}[{s}]{s} | {s}\n", .{
        color, service_name, reset, line,
    }) catch blk: {
        // line too long - truncate with indicator
        const truncated_indicator = "... [truncated]";
        const available = max_line_len - truncated_indicator.len - 1; // -1 for newline
        const truncated_line = if (line.len > available) line[0..available] else line;
        break :blk std.fmt.bufPrint(&format_buf, "{s}[{s}]{s} | {s}{s}\n", .{
            color, service_name, reset, truncated_line, truncated_indicator,
        }) catch {
            // even truncation failed - skip this line entirely
            log.warn("log_mux: failed to format/truncate log line for service '{s}' (line too long)", .{service_name});
            return;
        };
    };

    write_mutex.lock();
    defer write_mutex.unlock();

    // write to stderr (stdout is reserved for machine-readable output)
    // use a separate buffer for the writer to avoid reuse confusion
    var write_buf: [max_line_len]u8 = undefined;
    var w = platform.File.stderr().writer(&write_buf);
    const out = &w.interface;

    out.writeAll(formatted) catch |e| {
        _ = write_failures.fetchAdd(1, .monotonic);
        log.warn("log_mux: failed to write log line for '{s}': {}", .{ service_name, e });
        return;
    };
    out.flush() catch |e| {
        _ = write_failures.fetchAdd(1, .monotonic);
        log.warn("log_mux: failed to flush log for '{s}': {}", .{ service_name, e });
    };
}

// -- tests --

test "writeLine format" {
    // just verify it doesn't crash — actual output goes to stderr
    writeLine("web", 0, "hello world");
    writeLine("db", 1, "starting up");
    writeLine("worker", 7, "processing job");
}

test "color cycling" {
    // verify colors cycle correctly (idx beyond array length wraps)
    writeLine("svc", 0, "cyan");
    writeLine("svc", colors.len, "wraps to cyan");
    writeLine("svc", colors.len + 1, "wraps to yellow");
}
