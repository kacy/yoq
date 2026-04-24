const std = @import("std");
const cli = @import("../../lib/cli.zig");
const init_mod = @import("../init.zig");
const manifest_loader = @import("../loader.zig");
const validator = @import("../validate.zig");

const write = cli.write;
const writeErr = cli.writeErr;

const InitValidateError = error{
    InvalidArgument,
    ManifestLoadFailed,
    ValidationFailed,
};

pub fn init(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    var opts: init_mod.Options = .{};

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-f")) {
            opts.output_path = args.next() orelse {
                writeErr("-f requires an output path\n", .{});
                return InitValidateError.InvalidArgument;
            };
        } else {
            writeErr("unknown option: {s}\n", .{arg});
            return InitValidateError.InvalidArgument;
        }
    }

    init_mod.run(alloc, opts) catch |err| switch (err) {
        init_mod.InitError.FileExists => return InitValidateError.InvalidArgument,
        init_mod.InitError.WriteFailed => {
            writeErr("failed to write manifest file\n", .{});
            return InitValidateError.ManifestLoadFailed;
        },
        init_mod.InitError.CwdFailed => {
            writeErr("failed to resolve working directory\n", .{});
            return InitValidateError.ManifestLoadFailed;
        },
    };
}

pub fn validate(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    var manifest_path: []const u8 = manifest_loader.default_filename;
    var quiet = false;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-f")) {
            manifest_path = args.next() orelse {
                writeErr("-f requires a manifest path\n", .{});
                return InitValidateError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "-q") or std.mem.eql(u8, arg, "--quiet")) {
            quiet = true;
        } else {
            writeErr("unknown option: {s}\n", .{arg});
            return InitValidateError.InvalidArgument;
        }
    }

    var manifest = manifest_loader.load(alloc, manifest_path) catch |err| {
        if (!quiet) {
            writeErr("failed to load manifest: {s} ({})", .{ manifest_path, err });
            writeErr("hint: create one with 'yoq init'\n", .{});
        }
        return InitValidateError.ManifestLoadFailed;
    };
    defer manifest.deinit();

    var result = validator.check(alloc, &manifest) catch |err| {
        if (!quiet) writeErr("validation failed: {}\n", .{err});
        return InitValidateError.ValidationFailed;
    };
    defer result.deinit();

    if (!quiet) {
        for (result.diagnostics) |d| {
            switch (d.severity) {
                .@"error" => writeErr("error: {s}\n", .{d.message}),
                .warning => writeErr("warning: {s}\n", .{d.message}),
            }
        }
    }

    if (result.hasErrors()) {
        if (!quiet) writeErr("validation failed\n", .{});
        return InitValidateError.ValidationFailed;
    }

    if (!quiet) {
        write("{s} is valid", .{manifest_path});

        var has_count = false;
        if (manifest.services.len > 0) {
            write(" ({d} service{s}", .{ manifest.services.len, if (manifest.services.len != 1) "s" else "" });
            has_count = true;
        }
        if (manifest.workers.len > 0) {
            if (has_count) write(",", .{}) else write(" (", .{});
            write(" {d} worker{s}", .{ manifest.workers.len, if (manifest.workers.len != 1) "s" else "" });
            has_count = true;
        }
        if (manifest.crons.len > 0) {
            if (has_count) write(",", .{}) else write(" (", .{});
            write(" {d} cron{s}", .{ manifest.crons.len, if (manifest.crons.len != 1) "s" else "" });
            has_count = true;
        }
        if (manifest.training_jobs.len > 0) {
            if (has_count) write(",", .{}) else write(" (", .{});
            write(" {d} training job{s}", .{ manifest.training_jobs.len, if (manifest.training_jobs.len != 1) "s" else "" });
            has_count = true;
        }
        if (has_count) write(")", .{});
        write("\n", .{});
    }
}
