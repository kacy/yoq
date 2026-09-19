const std = @import("std");
const cli = @import("../../lib/cli.zig");
const AppContext = @import("../../lib/app_context.zig").AppContext;
const volumes = @import("../local_volumes.zig");

pub fn volume(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    dispatch(args, ctx.alloc) catch |err| {
        switch (err) {
            error.InUse => cli.writeErr("volume is referenced by a container; remove the container first\n", .{}),
            error.NotFound => cli.writeErr("volume not found\n", .{}),
            error.InvalidName => cli.writeErr("volume names must start with a letter or digit and contain only letters, digits, dots, underscores, or hyphens\n", .{}),
            error.InvalidArgument => cli.writeErr("usage: yoq volume create [name] | ls | inspect <name> | rm <name>\n", .{}),
            else => cli.writeErr("volume operation failed: {}\n", .{err}),
        }
        return err;
    };
}

fn dispatch(args: anytype, alloc: std.mem.Allocator) !void {
    const action = args.next() orelse return error.InvalidArgument;
    if (std.mem.eql(u8, action, "create")) {
        const name = args.next();
        if (args.next() != null) return error.InvalidArgument;
        const record = try volumes.create(alloc, name);
        defer record.deinit(alloc);
        cli.write("{s}\n", .{record.name});
    } else if (std.mem.eql(u8, action, "ls")) {
        if (args.next() != null) return error.InvalidArgument;
        const records = try volumes.list(alloc);
        defer {
            for (records) |record| record.deinit(alloc);
            alloc.free(records);
        }
        cli.write("NAME  DRIVER  KIND  REFERENCES\n", .{});
        for (records) |record| cli.write("{s}  local  {s}  {d}\n", .{ record.name, if (record.anonymous) "anonymous" else "named", record.references });
    } else if (std.mem.eql(u8, action, "inspect")) {
        const name = args.next() orelse return error.InvalidArgument;
        if (args.next() != null) return error.InvalidArgument;
        const record = try volumes.inspect(alloc, name);
        defer record.deinit(alloc);
        cli.write("name: {s}\ndriver: local\nkind: {s}\npath: {s}\nreferences: {d}\ncreated: {d}\n", .{ record.name, if (record.anonymous) "anonymous" else "named", record.path, record.references, record.created_at });
    } else if (std.mem.eql(u8, action, "rm")) {
        const name = args.next() orelse return error.InvalidArgument;
        if (args.next() != null) return error.InvalidArgument;
        try volumes.remove(name);
        cli.write("{s}\n", .{name});
    } else return error.InvalidArgument;
}
