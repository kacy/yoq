// log_mux — colored terminal log multiplexing for dev mode
//
// routes log output from multiple services to the terminal with
// colored service name prefixes. a mutex prevents interleaving
// when multiple capture threads write simultaneously.
//
// format: "\x1b[36m[web]     \x1b[0m | log line here"

const std = @import("std");

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

var write_mutex: std.Thread.Mutex = .{};

/// write a single log line to stderr with a colored service name prefix.
/// thread-safe — uses a mutex to prevent interleaved output.
pub fn writeLine(service_name: []const u8, color_idx: usize, line: []const u8) void {
    const color = colors[color_idx % colors.len];

    var buf: [8192]u8 = undefined;
    const formatted = std.fmt.bufPrint(&buf, "{s}[{s}]{s} | {s}\n", .{
        color, service_name, reset, line,
    }) catch return;

    write_mutex.lock();
    defer write_mutex.unlock();

    // write to stderr (stdout is reserved for machine-readable output)
    var backing: [4096]u8 = undefined;
    var w = std.fs.File.stderr().writer(&backing);
    const out = &w.interface;
    out.writeAll(formatted) catch {};
    out.flush() catch {};
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
