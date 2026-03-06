const std = @import("std");
const cli = @import("lib/cli.zig");
const command_registry = @import("lib/command_registry.zig");

const writeErr = cli.writeErr;

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var args = try std.process.argsWithAllocator(alloc);
    defer args.deinit();

    // skip program name
    _ = args.next();

    const command = args.next() orelse {
        command_registry.printUsage();
        return;
    };

    if (command_registry.findCommand(command)) |spec| {
        spec.handler(&args, alloc);
    } else {
        writeErr("unknown command: {s}\n", .{command});
        command_registry.printUsage();
        std.process.exit(1);
    }
}
