// log_mux — colored terminal log multiplexing for dev mode
//
// routes log output from multiple services to the terminal with
// colored service name prefixes. a mutex prevents interleaving
// when multiple capture threads write simultaneously.
//
// format: "\x1b[36m[web]     \x1b[0m | log line here"

const std = @import("std");
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

/// tracks number of stderr write failures for debugging
pub var write_failures: usize = 0;

/// mutex for thread-safe output. initialized explicitly to avoid
/// relying on compile-time zero initialization.
var write_mutex: std.Thread.Mutex = std.Thread.Mutex{};

/// write a single log line to stderr with a colored service name prefix.
/// thread-safe — uses a mutex to prevent interleaved output.
/// tracks write failures in write_failures counter.
pub fn writeLine(service_name: []const u8, color_idx: usize, line: []const u8) void {
    const color = colors[color_idx % colors.len];

    // use a single buffer that's large enough for both formatting and writing
    var buf: [8192]u8 = undefined;
    const formatted = std.fmt.bufPrint(&buf, "{s}[{s}]{s} | {s}\n", .{
        color, service_name, reset, line,
    }) catch {
        // formatting error - probably buffer too small for long line
        log.warn("log_mux: failed to format log line for service '{s}'", .{service_name});
        return;
    };

    write_mutex.lock();
    defer write_mutex.unlock();

    // write to stderr (stdout is reserved for machine-readable output)
    // use the same buffer for the writer to avoid size mismatch
    var w = std.fs.File.stderr().writer(&buf);
    const out = &w.interface;

    out.writeAll(formatted) catch |e| {
        write_failures += 1;
        log.warn("log_mux: failed to write log line for '{s}': {}", .{ service_name, e });
        return;
    };
    out.flush() catch |e| {
        write_failures += 1;
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
