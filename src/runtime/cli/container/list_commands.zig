const std = @import("std");
const cli = @import("../../../lib/cli.zig");
const AppContext = @import("../../../lib/app_context.zig").AppContext;
const store = @import("../../../state/store.zig");
const control = @import("../../local_control.zig");
const run_state = @import("../../run_state.zig");
const state = @import("state_support.zig");

const Filter = struct {
    key: []const u8,
    value: []const u8,

    fn parse(text: []const u8) !Filter {
        const eq = std.mem.indexOfScalar(u8, text, '=') orelse return error.InvalidFilter;
        const key = text[0..eq];
        if (!std.mem.eql(u8, key, "status") and !std.mem.eql(u8, key, "name") and !std.mem.eql(u8, key, "id")) return error.InvalidFilter;
        if (eq + 1 == text.len) return error.InvalidFilter;
        return .{ .key = key, .value = text[eq + 1 ..] };
    }

    fn matches(self: Filter, id: []const u8, name: []const u8, status: []const u8) bool {
        if (std.mem.eql(u8, self.key, "status")) return std.mem.eql(u8, status, self.value);
        if (std.mem.eql(u8, self.key, "id")) return std.mem.startsWith(u8, id, self.value);
        return std.mem.indexOf(u8, name, self.value) != null;
    }
};

pub fn ps(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    var all = false;
    var quiet = false;
    var filters: std.ArrayList(Filter) = .empty;
    defer filters.deinit(ctx.alloc);
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-a") or std.mem.eql(u8, arg, "--all")) {
            all = true;
        } else if (std.mem.eql(u8, arg, "-q") or std.mem.eql(u8, arg, "--quiet")) {
            quiet = true;
        } else if (std.mem.eql(u8, arg, "-aq") or std.mem.eql(u8, arg, "-qa")) {
            all = true;
            quiet = true;
        } else if (std.mem.eql(u8, arg, "--json")) {
            cli.output_mode = .json;
        } else if (std.mem.eql(u8, arg, "--filter") or std.mem.eql(u8, arg, "-f")) {
            try filters.append(ctx.alloc, try Filter.parse(args.next() orelse return error.MissingValue));
        } else if (std.mem.startsWith(u8, arg, "--filter=")) {
            try filters.append(ctx.alloc, try Filter.parse(arg[9..]));
        } else return error.InvalidArgument;
    }
    if (quiet and cli.output_mode == .json) return error.InvalidArgument;
    var ids = try store.listIds(ctx.alloc);
    defer {
        for (ids.items) |id| ctx.alloc.free(id);
        ids.deinit(ctx.alloc);
    }
    const json = cli.output_mode == .json;
    if (json) cli.write("[", .{}) else if (!quiet) cli.write("{s:<14} {s:<16} {s:<24} {s:<8} {s}\n", .{ "container id", "status", "name", "exit", "command" });
    var first = true;
    for (ids.items) |id| {
        const record = try store.load(ctx.alloc, id);
        defer record.deinit(ctx.alloc);
        const status = state.reconcileLiveness(id, record.status, record.pid);
        const active = std.mem.eql(u8, status, "running") or std.mem.eql(u8, status, "paused") or std.mem.eql(u8, status, "restarting");
        if (!all and !active) continue;
        const owned_name = try control.nameForId(ctx.alloc, id);
        defer if (owned_name) |name| ctx.alloc.free(name);
        const name = owned_name orelse record.hostname;
        var matches = true;
        for (filters.items) |filter| if (!filter.matches(id, name, status)) {
            matches = false;
            break;
        };
        if (!matches) continue;
        if (quiet) {
            cli.write("{s}\n", .{id});
        } else if (json) {
            const cfg = run_state.loadConfig(ctx.alloc, id) catch |err| switch (err) {
                error.NotFound => null,
                else => return err,
            };
            defer if (cfg) |value| value.deinit(ctx.alloc);
            const value = try std.json.Stringify.valueAlloc(ctx.alloc, .{
                .id = id,
                .name = name,
                .hostname = record.hostname,
                .status = status,
                .ip = record.ip_address,
                .command = record.command,
                .pid = if (active) record.pid else null,
                .exit_code = record.exit_code,
                .created_at = record.created_at,
                .restart_count = try control.restartCount(id),
                .health = try @import("../../local_health.zig").read(ctx.alloc, record.id),
                .ports = if (cfg) |value| value.port_maps else &.{},
                .mounts = if (cfg) |value| value.mounts else &.{},
                .image = if (cfg) |value| value.image_reference else null,
            }, .{});
            defer ctx.alloc.free(value);
            if (!first) cli.write(",", .{});
            cli.write("{s}", .{value});
        } else {
            var exit_buf: [8]u8 = undefined;
            const code = if (record.exit_code) |exit| try std.fmt.bufPrint(&exit_buf, "{d}", .{exit}) else "-";
            cli.write("{s:<14} {s:<16} {s:<24} {s:<8} {s}\n", .{ id, status, name, code, record.command });
        }
        first = false;
    }
    if (json) cli.write("]\n", .{});
}

pub fn rename(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    const ref = cli.requireArg(args, "usage: yoq rename <id|name> <new-name>\n");
    const name = cli.requireArg(args, "missing new name\n");
    if (args.next() != null) return error.InvalidArgument;
    const record = try state.resolveContainerRef(ctx.alloc, ref);
    defer record.deinit(ctx.alloc);
    // A running process keeps its hostname and current network alias.
    const command_lock = try control.lock(record.id, .command, true);
    defer command_lock.deinit();
    const current = try store.load(ctx.alloc, record.id);
    defer current.deinit(ctx.alloc);
    if (std.mem.eql(u8, current.status, "removing")) return error.InvalidStatus;
    try control.rename(record.id, name);
}

test "container listing filters have explicit matching rules" {
    try std.testing.expect((try Filter.parse("name=web")).matches("012345", "my-web", "running"));
    try std.testing.expect(!(try Filter.parse("status=run")).matches("012345", "web", "running"));
    try std.testing.expect((try Filter.parse("id=012")).matches("012345", "web", "stopped"));
    try std.testing.expectError(error.InvalidFilter, Filter.parse("label=foo"));
    try std.testing.expectError(error.InvalidFilter, Filter.parse("name="));
}
