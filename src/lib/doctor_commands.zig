// doctor_commands — CLI handler for `yoq doctor`
//
// runs pre-flight system checks and displays results as a table
// or JSON. exits with code 1 if any check fails.

const std = @import("std");
const AppContext = @import("app_context.zig").AppContext;
const cli = @import("cli.zig");
const json_out = @import("json_output.zig");
const doctor = @import("doctor.zig");
const doctor_manifest = @import("doctor_manifest.zig");

const write = cli.write;
const writeErr = cli.writeErr;

const DoctorCommandError = error{
    InvalidArgument,
    ValidationFailed,
    OutOfMemory,
};

pub fn doctorCmd(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    var manifest_path: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            cli.output_mode = .json;
        } else if (std.mem.eql(u8, arg, "-f")) {
            manifest_path = args.next() orelse {
                writeErr("-f requires a manifest path\n", .{});
                return DoctorCommandError.InvalidArgument;
            };
        } else {
            writeErr("unknown option: {s}\n", .{arg});
            return DoctorCommandError.InvalidArgument;
        }
    }

    const system_result = doctor.runAllChecks();
    var manifest_result: ?doctor_manifest.ManifestCheckResult = if (manifest_path) |path|
        try doctor_manifest.run(ctx.alloc, path)
    else
        null;
    defer if (manifest_result) |*result| result.deinit();

    if (cli.output_mode == .json) {
        var w = json_out.JsonWriter{};
        if (manifest_result) |result| {
            w.beginObject();
            w.beginArrayField("system");
            writeSystemChecksJson(&w, &system_result);
            w.endArray();
            w.beginArrayField("manifest");
            writeCheckSliceJson(&w, result.checks);
            w.endArray();
            w.endObject();
        } else {
            w.beginArray();
            writeSystemChecksJson(&w, &system_result);
            w.endArray();
        }
        w.flush();
    } else {
        writeCheckTable("system checks", systemChecksSlice(&system_result));
        if (manifest_result) |result| {
            write("\n", .{});
            writeCheckTable("manifest checks", result.checks);
        }

        if (doctor.resultHasFailures(&system_result) or (manifest_result != null and manifest_result.?.hasFailures())) {
            write("\nsome checks failed — see messages above\n", .{});
        } else {
            write("\nall checks passed\n", .{});
        }
    }

    if (doctor.resultHasFailures(&system_result) or (manifest_result != null and manifest_result.?.hasFailures())) {
        return DoctorCommandError.ValidationFailed;
    }
}

fn writeCheckTable(title: []const u8, checks: []const doctor.Check) void {
    write("{s}\n", .{title});
    write("{s:<16} {s:<6} {s}\n", .{ "CHECK", "STATUS", "MESSAGE" });
    write("{s:->16} {s:->6} {s:->40}\n", .{ "", "", "" });

    for (checks) |*c| {
        write("{s:<16} {s:<6} {s}\n", .{ c.getName(), c.statusLabel(), c.getMessage() });
    }
}

fn writeSystemChecksJson(w: *json_out.JsonWriter, result: *const doctor.CheckResult) void {
    for (0..result.count) |i| {
        writeCheckJson(w, &result.checks[i]);
    }
}

fn writeCheckSliceJson(w: *json_out.JsonWriter, checks: []const doctor.Check) void {
    for (checks) |*check| {
        writeCheckJson(w, check);
    }
}

fn writeCheckJson(w: *json_out.JsonWriter, c: *const doctor.Check) void {
    w.beginObject();
    w.stringField("name", c.getName());
    w.stringField("status", c.statusLabel());
    w.stringField("message", c.getMessage());
    w.endObject();
}

fn systemChecksSlice(result: *const doctor.CheckResult) []const doctor.Check {
    return result.checks[0..result.count];
}

// -- tests --

test "doctorCmd handler has correct signature" {
    // verify the function signature matches CommandHandler
    const handler: @import("../lib/command_registry.zig").CommandHandler = doctorCmd;
    _ = handler;
}
