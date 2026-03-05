const std = @import("std");
const cli = @import("../lib/cli.zig");
const store = @import("../state/store.zig");
const net_policy = @import("policy.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const formatTimestamp = cli.formatTimestamp;

// -- network policy commands --

pub fn policy(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const subcmd = args.next() orelse {
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
        std.process.exit(1);
    };

    if (std.mem.eql(u8, subcmd, "deny")) {
        policyDeny(args, alloc);
    } else if (std.mem.eql(u8, subcmd, "allow")) {
        policyAllow(args, alloc);
    } else if (std.mem.eql(u8, subcmd, "rm")) {
        policyRm(args, alloc);
    } else if (std.mem.eql(u8, subcmd, "list")) {
        policyList(alloc);
    } else {
        writeErr("unknown policy command: {s}\n", .{subcmd});
        std.process.exit(1);
    }
}

fn policyDeny(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const source = args.next() orelse {
        writeErr("usage: yoq policy deny <source> <target>\n", .{});
        std.process.exit(1);
    };
    const target = args.next() orelse {
        writeErr("usage: yoq policy deny <source> <target>\n", .{});
        std.process.exit(1);
    };

    store.addNetworkPolicy(source, target, "deny") catch {
        writeErr("failed to add deny rule\n", .{});
        std.process.exit(1);
    };

    // sync BPF maps with updated rules
    net_policy.syncPolicies(alloc);

    write("{s} -> {s}: deny\n", .{ source, target });
}

fn policyAllow(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const source = args.next() orelse {
        writeErr("usage: yoq policy allow <source> <target>\n", .{});
        std.process.exit(1);
    };
    const target = args.next() orelse {
        writeErr("usage: yoq policy allow <source> <target>\n", .{});
        std.process.exit(1);
    };

    store.addNetworkPolicy(source, target, "allow") catch {
        writeErr("failed to add allow rule\n", .{});
        std.process.exit(1);
    };

    // sync BPF maps with updated rules
    net_policy.syncPolicies(alloc);

    write("{s} -> {s}: allow\n", .{ source, target });
}

fn policyRm(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const source = args.next() orelse {
        writeErr("usage: yoq policy rm <source> <target>\n", .{});
        std.process.exit(1);
    };
    const target = args.next() orelse {
        writeErr("usage: yoq policy rm <source> <target>\n", .{});
        std.process.exit(1);
    };

    store.removeNetworkPolicy(source, target) catch {
        writeErr("failed to remove policy rule\n", .{});
        std.process.exit(1);
    };

    // sync BPF maps with updated rules
    net_policy.syncPolicies(alloc);

    write("{s} -> {s}: removed\n", .{ source, target });
}

fn policyList(alloc: std.mem.Allocator) void {
    var policies = store.listNetworkPolicies(alloc) catch {
        writeErr("failed to list policies\n", .{});
        std.process.exit(1);
    };
    defer {
        for (policies.items) |p| p.deinit(alloc);
        policies.deinit(alloc);
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
