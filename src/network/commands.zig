const std = @import("std");
const AppContext = @import("../lib/app_context.zig").AppContext;
const cli = @import("../lib/cli.zig");
const json_out = @import("../lib/json_output.zig");
const store = @import("../state/store.zig");
const net_policy = @import("policy.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const formatTimestamp = cli.formatTimestamp;

const PolicyCommandsError = error{
    InvalidArgument,
    PolicyNotFound,
    StoreFailed,
    SyncFailed,
    OutOfMemory,
};

// -- network policy commands --

pub fn policy(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    const alloc = ctx.alloc;
    var subcmd: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            cli.output_mode = .json;
        } else {
            subcmd = arg;
            break;
        }
    }

    const cmd = subcmd orelse {
        writeErr(
            \\usage: yoq policy <command> [options]
            \\
            \\commands:
            \\  deny <source> <target>   block traffic from source to target
            \\  allow <source> <target>  allow only this destination for source
            \\  rm <source> <target>     remove a policy rule
            \\  list                     list all policy rules
            \\
        , .{});
        return PolicyCommandsError.InvalidArgument;
    };

    if (std.mem.eql(u8, cmd, "deny") or std.mem.eql(u8, cmd, "allow")) {
        policyAddRule(args, alloc, cmd) catch |e| return e;
    } else if (std.mem.eql(u8, cmd, "rm")) {
        policyRm(args, alloc) catch |e| return e;
    } else if (std.mem.eql(u8, cmd, "list")) {
        // also check remaining args for --json
        while (args.next()) |arg| {
            if (std.mem.eql(u8, arg, "--json")) cli.output_mode = .json;
        }
        policyList(alloc) catch |e| return e;
    } else {
        writeErr("unknown policy command: {s}\n", .{cmd});
        return PolicyCommandsError.InvalidArgument;
    }
}

fn policyAddRule(args: *std.process.Args.Iterator, alloc: std.mem.Allocator, action: []const u8) PolicyCommandsError!void {
    const source = args.next() orelse {
        writeErr("usage: yoq policy {s} <source> <target>\n", .{action});
        return PolicyCommandsError.InvalidArgument;
    };
    const target = args.next() orelse {
        writeErr("usage: yoq policy {s} <source> <target>\n", .{action});
        return PolicyCommandsError.InvalidArgument;
    };

    store.addNetworkPolicy(source, target, action) catch {
        writeErr("failed to add {s} rule\n", .{action});
        return PolicyCommandsError.StoreFailed;
    };

    net_policy.syncPolicies(alloc);

    write("{s} -> {s}: {s}\n", .{ source, target, action });
}

fn policyRm(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) PolicyCommandsError!void {
    const source = args.next() orelse {
        writeErr("usage: yoq policy rm <source> <target>\n", .{});
        return PolicyCommandsError.InvalidArgument;
    };
    const target = args.next() orelse {
        writeErr("usage: yoq policy rm <source> <target>\n", .{});
        return PolicyCommandsError.InvalidArgument;
    };

    store.removeNetworkPolicy(source, target) catch {
        writeErr("failed to remove policy rule\n", .{});
        return PolicyCommandsError.StoreFailed;
    };

    // sync BPF maps with updated rules
    net_policy.syncPolicies(alloc);

    write("{s} -> {s}: removed\n", .{ source, target });
}

fn policyList(alloc: std.mem.Allocator) PolicyCommandsError!void {
    var policies = store.listNetworkPolicies(alloc) catch {
        writeErr("failed to list policies\n", .{});
        return PolicyCommandsError.StoreFailed;
    };
    defer {
        for (policies.items) |p| p.deinit(alloc);
        policies.deinit(alloc);
    }

    if (cli.output_mode == .json) {
        var w = json_out.JsonWriter{};
        w.beginArray();
        for (policies.items) |pol| {
            w.beginObject();
            w.stringField("source", pol.source_service);
            w.stringField("target", pol.target_service);
            w.stringField("action", pol.action);
            w.intField("created_at", pol.created_at);
            w.endObject();
        }
        w.endArray();
        w.flush();
        return;
    }

    if (policies.items.len == 0) {
        write("no network policies\n", .{});
        return;
    }

    write("{s:<16} {s:<16} {s:<8} {s}\n", .{
        "SOURCE", "TARGET", "ACTION", "CREATED",
    });

    for (policies.items) |pol| {
        // format timestamp as simple date
        var time_buf: [20]u8 = undefined;
        const time_str = formatTimestamp(&time_buf, pol.created_at);

        write("{s:<16} {s:<16} {s:<8} {s}\n", .{
            pol.source_service, pol.target_service, pol.action, time_str,
        });
    }
}
