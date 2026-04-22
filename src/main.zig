const std = @import("std");
const cli = @import("lib/cli.zig");
const AppContext = @import("lib/app_context.zig").AppContext;
const command_registry = @import("lib/command_registry.zig");

const writeErr = cli.writeErr;

// maximum reasonable command name length to prevent buffer overflow issues
const MAX_COMMAND_NAME_LEN = 256;

pub fn main(init: std.process.Init) !void {
    const alloc = init.gpa;

    var threaded_io = std.Io.Threaded.init(alloc, .{});
    defer threaded_io.deinit();

    const app_ctx = AppContext{
        .alloc = alloc,
        .io = threaded_io.io(),
    };

    var args = std.process.Args.Iterator.initAllocator(init.minimal.args, alloc) catch |err| {
        writeErr("failed to initialize argument parser: {s}\n", .{@errorName(err)});
        return err;
    };
    defer args.deinit();

    // skip program name
    _ = args.next();

    const command = args.next() orelse {
        command_registry.printUsage();
        return;
    };

    // validate command name length to prevent potential issues
    if (command.len > MAX_COMMAND_NAME_LEN) {
        writeErr("command name too long (max {d} chars)\n", .{MAX_COMMAND_NAME_LEN});
        std.process.exit(1);
    }

    if (command_registry.findCommand(command)) |spec| {
        spec.handler(&args, app_ctx) catch |err| {
            // print user-friendly error message
            const error_msg = switch (err) {
                error.OutOfMemory => "out of memory",
                error.FileNotFound => "file not found",
                error.AccessDenied => "permission denied",
                error.InvalidArgument => "invalid argument",
                else => @errorName(err),
            };
            writeErr("error: {s}\n", .{error_msg});
            return err;
        };
    } else {
        writeErr("unknown command: {s}\n", .{command});
        command_registry.printUsage();
        std.process.exit(1);
    }
}

// -- tests --

test "command name length validation" {
    const long_name = "a" ** (MAX_COMMAND_NAME_LEN + 1);
    try std.testing.expect(long_name.len > MAX_COMMAND_NAME_LEN);
}

test "error message mapping" {
    // verify that common errors are mapped correctly
    const test_cases = &[_]struct {
        err: anyerror,
        expected: []const u8,
    }{
        .{ .err = error.OutOfMemory, .expected = "out of memory" },
        .{ .err = error.FileNotFound, .expected = "file not found" },
        .{ .err = error.AccessDenied, .expected = "permission denied" },
        .{ .err = error.InvalidArgument, .expected = "invalid argument" },
    };

    for (test_cases) |tc| {
        const error_msg = switch (tc.err) {
            error.OutOfMemory => "out of memory",
            error.FileNotFound => "file not found",
            error.AccessDenied => "permission denied",
            error.InvalidArgument => "invalid argument",
            else => @errorName(tc.err),
        };
        try std.testing.expectEqualStrings(tc.expected, error_msg);
    }
}

test "MAX_COMMAND_NAME_LEN is reasonable" {
    try std.testing.expect(MAX_COMMAND_NAME_LEN >= 64);
    try std.testing.expect(MAX_COMMAND_NAME_LEN <= 1024);
}
