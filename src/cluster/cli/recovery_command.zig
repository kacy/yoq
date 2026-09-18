const std = @import("std");
const cli = @import("../../lib/cli.zig");
const paths = @import("../../lib/paths.zig");
const bundle = @import("../recovery/bundle.zig");
const databases = @import("../recovery/databases.zig");

pub fn run(command: []const u8, args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    var source: ?[]const u8 = null;
    var data_dir: ?[]const u8 = null;
    var join_token_file: ?[]const u8 = null;
    var set_id: ?[]const u8 = null;
    var fingerprint: ?[]const u8 = null;
    var node_id: ?u64 = null;
    var voters: ?[]const u8 = null;
    var bundles: std.ArrayList([]const u8) = .empty;
    defer bundles.deinit(alloc);
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--data-dir")) {
            if (data_dir != null) return invalid();
            data_dir = args.next() orelse return invalid();
        } else if (std.mem.eql(u8, arg, "--join-token-file")) {
            if (join_token_file != null) return invalid();
            join_token_file = args.next() orelse return invalid();
        } else if (std.mem.eql(u8, arg, "--set")) {
            if (set_id != null) return invalid();
            set_id = args.next() orelse return invalid();
        } else if (std.mem.eql(u8, arg, "--cluster")) {
            if (fingerprint != null) return invalid();
            fingerprint = args.next() orelse return invalid();
        } else if (std.mem.eql(u8, arg, "--node-id")) {
            if (node_id != null) return invalid();
            node_id = std.fmt.parseInt(u64, args.next() orelse return invalid(), 10) catch return invalid();
        } else if (std.mem.eql(u8, arg, "--voters")) {
            if (voters != null) return invalid();
            voters = args.next() orelse return invalid();
        } else if (std.mem.startsWith(u8, arg, "--")) {
            return invalid();
        } else {
            if (std.mem.eql(u8, command, "verify-set")) {
                if (bundles.items.len >= 64) return invalid();
                try bundles.append(alloc, arg);
            } else {
                if (source != null) return invalid();
                source = arg;
            }
        }
    }
    if (std.mem.eql(u8, command, "verify-set")) {
        if (data_dir != null or join_token_file != null or node_id != null or voters != null or fingerprint != null) return invalid();
        const id = set_id orelse return invalid();
        const cluster = bundle.verifySet(alloc, bundles.items, id) catch |err| return failed(err);
        cli.write("verified set {s}: {d} voters, cluster {s}\n", .{ id, bundles.items.len, cluster });
        return;
    }
    const artifact = source orelse return invalid();
    if (std.mem.eql(u8, command, "verify")) {
        if (data_dir != null or join_token_file != null or node_id != null or voters != null or fingerprint != null or set_id != null) return invalid();
        const boundary = bundle.verify(alloc, artifact) catch |err| return failed(err);
        defer boundary.deinit(alloc);
        printBoundary("verified", boundary);
    } else if (std.mem.eql(u8, command, "backup")) {
        if (node_id != null or voters != null or fingerprint != null) return invalid();
        var path_buf: [paths.max_path]u8 = undefined;
        const root = data_dir orelse try paths.dataPath(&path_buf, "");
        const boundary = bundle.capture(alloc, .{ .data_dir = root, .destination = artifact, .join_token_file = join_token_file orelse return invalid(), .set_id = set_id orelse return invalid() }) catch |err| return failed(err);
        defer boundary.deinit(alloc);
        printBoundary("captured", boundary);
    } else if (std.mem.eql(u8, command, "restore")) {
        if (join_token_file != null) return invalid();
        const canonical = try canonicalVoters(alloc, voters orelse return invalid(), node_id orelse return invalid());
        defer alloc.free(canonical);
        const boundary = bundle.restore(alloc, .{ .source = artifact, .destination = data_dir orelse return invalid(), .node_id = node_id.?, .voters = canonical, .set_id = set_id orelse return invalid(), .cluster_fingerprint = fingerprint orelse return invalid() }) catch |err| return failed(err);
        defer boundary.deinit(alloc);
        printBoundary("restored", boundary);
    } else return invalid();
}

fn canonicalVoters(alloc: std.mem.Allocator, input: []const u8, node_id: u64) ![]u8 {
    const canonical = if (std.mem.endsWith(u8, input, ",")) try alloc.dupe(u8, input) else try std.fmt.allocPrint(alloc, "{s},", .{input});
    errdefer alloc.free(canonical);
    try databases.validateVoters(canonical, node_id);
    return canonical;
}

fn printBoundary(action: []const u8, boundary: databases.Boundary) void {
    cli.write("{s} voter {d}: term {d}, applied {d}, last log {d}, snapshot {d}\n", .{ action, boundary.node_id, boundary.current_term, boundary.last_applied, boundary.last_log_index, boundary.snapshot_index });
}

fn failed(err: anyerror) error{RecoveryFailed} {
    cli.writeErr("cluster recovery failed: {}\n", .{err});
    return error.RecoveryFailed;
}

fn invalid() error{InvalidArgument} {
    cli.writeErr(
        "usage: yoq cluster backup <bundle> --set <id> --join-token-file <file> [--data-dir <root>]\n" ++
            "       yoq cluster verify <bundle>\n" ++
            "       yoq cluster verify-set --set <id> <bundle>...\n" ++
            "       yoq cluster restore <bundle> --data-dir <fresh-root> --node-id <id> --voters <sorted-ids> --set <id> --cluster <fingerprint>\n",
        .{},
    );
    return error.InvalidArgument;
}
