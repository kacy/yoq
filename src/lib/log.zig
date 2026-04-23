// log — structured logging for yoq
//
// leveled logging to stderr with text and JSON output formats.
// text mode: [INF] message (human-readable, default for CLI)
// json mode: {"ts":...,"level":"info","msg":"...","trace_id":"..."} (default for server)
//
// trace IDs correlate log lines across a single API request.

const std = @import("std");
const platform = @import("platform");

pub const Level = enum {
    debug,
    info,
    warn,
    err,

    pub fn label(self: Level) []const u8 {
        return switch (self) {
            .debug => "DBG",
            .info => "INF",
            .warn => "WRN",
            .err => "ERR",
        };
    }

    pub fn jsonLabel(self: Level) []const u8 {
        return switch (self) {
            .debug => "debug",
            .info => "info",
            .warn => "warn",
            .err => "error",
        };
    }
};

pub const LogFormat = enum {
    text,
    json,
};

var min_level: Level = .info;
var log_format: LogFormat = .text;

/// per-request trace ID (hex string, up to 16 bytes = 32 hex chars)
var trace_id_buf: [32]u8 = .{0} ** 32;
var trace_id_len: u8 = 0;

/// tracks number of stderr write failures (for debugging)
pub var log_write_failures: usize = 0;

pub fn setLevel(level: Level) void {
    min_level = level;
}

pub fn setFormat(fmt: LogFormat) void {
    log_format = fmt;
}

pub fn setTraceId(id: []const u8) void {
    const len: u8 = @intCast(@min(id.len, 32));
    @memcpy(trace_id_buf[0..len], id[0..len]);
    trace_id_len = len;
}

pub fn clearTraceId() void {
    trace_id_len = 0;
}

pub fn getTraceId() ?[]const u8 {
    if (trace_id_len == 0) return null;
    return trace_id_buf[0..trace_id_len];
}

pub fn debug(comptime fmt: []const u8, args: anytype) void {
    logMsg(.debug, fmt, args);
}

pub fn info(comptime fmt: []const u8, args: anytype) void {
    logMsg(.info, fmt, args);
}

pub fn warn(comptime fmt: []const u8, args: anytype) void {
    logMsg(.warn, fmt, args);
}

pub fn err(comptime fmt: []const u8, args: anytype) void {
    logMsg(.err, fmt, args);
}

fn logMsg(level: Level, comptime fmt: []const u8, args: anytype) void {
    if (@intFromEnum(level) < @intFromEnum(min_level)) return;

    const io = std.Options.debug_io;
    const prev = io.swapCancelProtection(.blocked);
    defer _ = io.swapCancelProtection(prev);

    var buf: [8192]u8 = undefined;
    var w = std.Io.File.stderr().writer(io, &buf);
    const out = &w.interface;

    switch (log_format) {
        .text => {
            out.print("[{s}] " ++ fmt ++ "\n", .{level.label()} ++ args) catch {
                log_write_failures += 1;
                return;
            };
        },
        .json => {
            // format the message into a temp buffer
            var msg_buf: [4096]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, fmt, args) catch {
                log_write_failures += 1;
                return;
            };

            // get timestamp
            const ts = platform.timestamp();

            out.writeAll("{\"ts\":") catch {
                log_write_failures += 1;
                return;
            };
            out.print("{d}", .{ts}) catch {
                log_write_failures += 1;
                return;
            };
            out.writeAll(",\"level\":\"") catch {
                log_write_failures += 1;
                return;
            };
            out.writeAll(level.jsonLabel()) catch {
                log_write_failures += 1;
                return;
            };
            out.writeAll("\",\"msg\":\"") catch {
                log_write_failures += 1;
                return;
            };
            // escape JSON special chars in message
            writeJsonEscaped(out, msg) catch {
                log_write_failures += 1;
                return;
            };
            out.writeByte('"') catch {
                log_write_failures += 1;
                return;
            };

            if (trace_id_len > 0) {
                out.writeAll(",\"trace_id\":\"") catch {
                    log_write_failures += 1;
                    return;
                };
                out.writeAll(trace_id_buf[0..trace_id_len]) catch {
                    log_write_failures += 1;
                    return;
                };
                out.writeByte('"') catch {
                    log_write_failures += 1;
                    return;
                };
            }

            out.writeAll("}\n") catch {
                log_write_failures += 1;
                return;
            };
        },
    }

    out.flush() catch {
        log_write_failures += 1;
    };
}

fn writeJsonEscaped(out: anytype, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try out.writeAll("\\\""),
            '\\' => try out.writeAll("\\\\"),
            '\n' => try out.writeAll("\\n"),
            '\r' => try out.writeAll("\\r"),
            '\t' => try out.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    try out.print("\\u{x:0>4}", .{c});
                } else {
                    try out.writeByte(c);
                }
            },
        }
    }
}

/// generate a random trace ID as hex string. writes 16 hex chars.
pub fn generateTraceId(out: *[16]u8) void {
    var random_bytes: [8]u8 = undefined;
    platform.randomBytes(&random_bytes);
    const hex = "0123456789abcdef";
    for (random_bytes, 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0x0f];
    }
}

// -- tests --

test "log level filtering" {
    setLevel(.warn);
    defer setLevel(.info);

    // these should not crash — just verifying they compile and don't panic
    debug("this should be filtered", .{});
    info("this should be filtered", .{});
    warn("this should appear", .{});
    err("this should appear", .{});
}

test "log failure tracking" {
    // Reset counter
    log_write_failures = 0;

    // Normal log writes should not increment counter
    info("test message", .{});
    warn("test warning", .{});
    err("test error", .{});
    debug("test debug", .{});

    // Note: In normal operation, this should remain 0
    // We can't easily test actual failures without mocking stderr
    _ = log_write_failures;
}

test "log format switching" {
    const saved = log_format;
    defer log_format = saved;

    setFormat(.json);
    info("json message", .{});
    setFormat(.text);
    info("text message", .{});
}

test "trace id set and clear" {
    clearTraceId();
    try std.testing.expect(getTraceId() == null);

    setTraceId("abc123");
    try std.testing.expectEqualStrings("abc123", getTraceId().?);

    clearTraceId();
    try std.testing.expect(getTraceId() == null);
}

test "trace id truncation" {
    const long_id = "0123456789abcdef0123456789abcdef0000";
    setTraceId(long_id);
    defer clearTraceId();
    try std.testing.expectEqual(@as(u8, 32), trace_id_len);
}

test "json format with trace id" {
    const saved_fmt = log_format;
    defer log_format = saved_fmt;

    setFormat(.json);
    setTraceId("test-trace-123");
    defer clearTraceId();

    // should not crash
    info("request processed", .{});
}

test "generateTraceId produces hex" {
    var id: [16]u8 = undefined;
    generateTraceId(&id);

    // verify all chars are hex
    for (id) |c| {
        try std.testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

test "Level jsonLabel" {
    try std.testing.expectEqualStrings("debug", Level.debug.jsonLabel());
    try std.testing.expectEqualStrings("info", Level.info.jsonLabel());
    try std.testing.expectEqualStrings("warn", Level.warn.jsonLabel());
    try std.testing.expectEqualStrings("error", Level.err.jsonLabel());
}
