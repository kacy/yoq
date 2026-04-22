// doctor_commands — CLI handler for `yoq doctor`
//
// runs pre-flight system checks and displays results as a table
// or JSON. exits with code 1 if any check fails.

const std = @import("std");
const cli = @import("cli.zig");
const json_out = @import("json_output.zig");
const doctor = @import("doctor.zig");

const write = cli.write;

pub fn doctorCmd(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    _ = alloc;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            cli.output_mode = .json;
        }
    }

    const result = doctor.runAllChecks();

    if (cli.output_mode == .json) {
        var w = json_out.JsonWriter{};
        w.beginArray();
        for (0..result.count) |i| {
            const c = &result.checks[i];
            w.beginObject();
            w.stringField("name", c.getName());
            w.stringField("status", c.statusLabel());
            w.stringField("message", c.getMessage());
            w.endObject();
        }
        w.endArray();
        w.flush();
        return;
    }

    write("{s:<16} {s:<6} {s}\n", .{ "CHECK", "STATUS", "MESSAGE" });
    write("{s:->16} {s:->6} {s:->40}\n", .{ "", "", "" });

    var has_fail = false;
    for (0..result.count) |i| {
        const c = &result.checks[i];
        if (c.status == .fail) has_fail = true;
        write("{s:<16} {s:<6} {s}\n", .{ c.getName(), c.statusLabel(), c.getMessage() });
    }

    if (has_fail) {
        write("\nsome checks failed — see messages above\n", .{});
    } else {
        write("\nall checks passed\n", .{});
    }
}

// -- tests --

test "doctorCmd handler has correct signature" {
    // verify the function signature matches CommandHandler
    const handler: @import("../lib/command_registry.zig").CommandHandler = doctorCmd;
    _ = handler;
}
