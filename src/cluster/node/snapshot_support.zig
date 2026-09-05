const std = @import("std");
const types = @import("../raft_types.zig");
const bootstrap = @import("bootstrap.zig");
const artifact = @import("../state_machine/snapshot_support.zig");
const logger = @import("../../lib/log.zig");

const LogIndex = types.LogIndex;
const SnapshotMeta = types.SnapshotMeta;
const snapshot_threshold: u64 = 1000;
pub const NodeId = types.NodeId;

pub fn generationPath(buf: []u8, data_dir: []const u8, meta: SnapshotMeta) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}/snapshot-{d}-{d}.dat", .{ data_dir, meta.last_included_index, meta.last_included_term });
}

fn sameBoundary(a: SnapshotMeta, b: SnapshotMeta) bool {
    return a.last_included_index == b.last_included_index and a.last_included_term == b.last_included_term;
}

/// Read the selected generation, not the newest file in the directory. An
/// unselected generation can be left behind by a crash before activation.
fn readSelected(alloc: std.mem.Allocator, data_dir: []const u8, selected: SnapshotMeta) ![]u8 {
    var path_buf: [512]u8 = undefined;
    const path = try generationPath(&path_buf, data_dir, selected);
    const data = std.Io.Dir.cwd().readFileAlloc(std.Options.debug_io, path, alloc, .limited(artifact.max_snapshot_file_size)) catch |err| blk: {
        if (err != error.FileNotFound) return err;
        // Older releases wrote one snapshot.dat and recorded a zero length.
        // Only that legacy record may migrate, and its boundary must match.
        if (selected.data_len != 0) return error.MissingSnapshot;
        var legacy_buf: [512]u8 = undefined;
        const legacy = bootstrap.snapshotPath(&legacy_buf, data_dir) orelse return error.NameTooLong;
        break :blk try artifact.readBytes(alloc, legacy);
    };
    errdefer alloc.free(data);
    const actual = try artifact.parseSnapshotMeta(data);
    if (!sameBoundary(actual, selected) or (selected.data_len != 0 and selected.data_len != actual.data_len)) return error.SnapshotMismatch;
    return data;
}

/// Called before Raft and transport initialization. Activation can commit just
/// before a crash, leaving the state database behind its durable snapshot.
pub fn recover(alloc: std.mem.Allocator, data_dir: []const u8, log: anytype, state_machine: anytype) !void {
    const selected = (try log.readSnapshotMeta()) orelse return;
    const data = try readSelected(alloc, data_dir, selected);
    defer alloc.free(data);
    var prepared = try artifact.PreparedSnapshot.init(data);
    defer prepared.deinit();
    if (selected.data_len == 0) {
        var path_buf: [512]u8 = undefined;
        const path = try generationPath(&path_buf, data_dir, prepared.meta);
        try artifact.publishBytes(path, data);
        try log.activateSnapshot(prepared.meta);
    }
    if (state_machine.last_applied < selected.last_included_index) try prepared.restore(state_machine);
}

pub fn maybeSnapshot(self: anytype) void {
    if (self.snapshot_failed.load(.acquire)) return;
    const applied = self.state_machine.last_applied;
    if (applied <= self.last_snapshot_index) return;
    if (applied - self.last_snapshot_index < snapshot_threshold) return;
    takeSnapshot(self, applied, self.log.termAt(applied));
}

pub fn takeSnapshot(self: anytype, index: LogIndex, term: types.Term) void {
    if (self.snapshot_failed.load(.acquire) or index != self.state_machine.last_applied or index <= self.last_snapshot_index) return;
    if (term == 0 or term != self.log.termAt(index)) return;
    const requested: SnapshotMeta = .{ .last_included_index = index, .last_included_term = term, .data_len = 0 };
    var path_buf: [512]u8 = undefined;
    const path = generationPath(&path_buf, self.config.data_dir, requested) catch return;
    self.state_machine.takeSnapshot(path, requested) catch |err| {
        logger.warn("snapshot: failed to publish index {}: {}", .{ index, err });
        return;
    };
    const meta = artifact.readSnapshotMeta(path) catch return;
    self.log.activateSnapshot(meta) catch |err| {
        logger.warn("snapshot: failed to activate index {}: {}", .{ index, err });
        return;
    };
    self.raft.snapshot_meta = meta;
    self.last_snapshot_index = index;
    logger.info("snapshot: completed at index {}, term {}", .{ index, term });
}

/// Publication precedes the log transaction; restore precedes acknowledgement.
/// If restore fails after activation, restart recovery owns completion and the
/// node must not participate with an older state database.
pub fn install(self: anytype, data: []const u8, expected: ?SnapshotMeta) !void {
    if (self.snapshot_failed.load(.acquire)) return error.SnapshotRecoveryRequired;
    var prepared = try artifact.PreparedSnapshot.init(data);
    defer prepared.deinit();
    const meta = prepared.meta;
    if (expected) |want| {
        if (!sameBoundary(meta, want)) return error.SnapshotMismatch;
    }
    if (meta.last_included_index <= self.state_machine.last_applied) return;
    var path_buf: [512]u8 = undefined;
    const path = try generationPath(&path_buf, self.config.data_dir, meta);
    try artifact.publishBytes(path, data);
    try self.log.activateSnapshot(meta);
    prepared.restore(&self.state_machine) catch |err| {
        self.snapshot_failed.store(true, .release);
        self.running.store(false, .release);
        self.raft.role = .follower;
        logger.err("snapshot: restore failed after activation; restart required: {}", .{err});
        return error.SnapshotRecoveryRequired;
    };
    self.raft.snapshot_meta = meta;
    self.raft.commit_index = @max(self.raft.commit_index, meta.last_included_index);
    self.raft.last_applied = @max(self.raft.last_applied, meta.last_included_index);
    self.last_snapshot_index = meta.last_included_index;
}

pub fn sendSnapshot(self: anytype, target: NodeId, args: types.InstallSnapshotArgs) void {
    if (self.snapshot_failed.load(.acquire)) return;
    const selected: SnapshotMeta = .{
        .last_included_index = args.last_included_index,
        .last_included_term = args.last_included_term,
        .data_len = 0,
    };
    const data = readSelected(self.alloc, self.config.data_dir, selected) catch |err| {
        logger.warn("snapshot: failed to read generation for node {}: {}", .{ target, err });
        return;
    };
    defer self.alloc.free(data);
    self.transport.send(target, .{
        .install_snapshot = .{
            .term = args.term,
            .leader_id = args.leader_id,
            .last_included_index = args.last_included_index,
            .last_included_term = args.last_included_term,
            .data = data,
        },
    }) catch |err| logger.warn("failed to send snapshot to node {}: {}", .{ target, err });
}

const TestNode = struct {
    alloc: std.mem.Allocator = std.testing.allocator,
    config: struct { data_dir: []const u8 },
    log: @import("../log.zig").Log,
    state_machine: @import("../state_machine.zig").StateMachine,
    raft: struct {
        snapshot_meta: ?SnapshotMeta = null,
        commit_index: u64 = 0,
        last_applied: u64 = 0,
        role: enum { follower, leader } = .leader,
    } = .{},
    last_snapshot_index: u64 = 0,
    snapshot_failed: std.atomic.Value(bool) = .init(false),
    running: std.atomic.Value(bool) = .init(true),

    fn init(data_dir: []const u8) !TestNode {
        var log = try @import("../log.zig").Log.initMemory();
        errdefer log.deinit();
        return .{ .config = .{ .data_dir = data_dir }, .log = log, .state_machine = try @import("../state_machine.zig").StateMachine.initMemory() };
    }

    fn deinit(self: *TestNode) void {
        self.state_machine.deinit();
        self.log.deinit();
    }
};

fn testSnapshot(data_dir: []const u8) ![]u8 {
    var source = try @import("../state_machine.zig").StateMachine.initMemory();
    defer source.deinit();
    source.apply(.{ .index = 1, .term = 3, .data = "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at) VALUES ('snapshot-probe', 'local', 'active', 1, 1024, 0, 0, 0, 1, 1);" });
    source.apply(.{ .index = 2, .term = 3, .data = "UPDATE agents SET cpu_used = 42 WHERE id = 'snapshot-probe';" });
    try std.testing.expectEqual(@as(u64, 2), source.last_applied);
    var path_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/source.dat", .{data_dir});
    try source.takeSnapshot(path, .{ .last_included_index = 2, .last_included_term = 3, .data_len = 0 });
    return artifact.readBytes(std.testing.allocator, path);
}

test "snapshot received artifact survives activation and can be forwarded after restart" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const path_len = try tmp.dir.realPath(std.testing.io, &path_buf);
    const path = path_buf[0..path_len];
    const data = try testSnapshot(path);
    defer std.testing.allocator.free(data);
    const meta = try artifact.parseSnapshotMeta(data);
    var node = try TestNode.init(path);
    defer node.deinit();
    try node.log.append(.{ .index = 2, .term = 3, .data = "boundary" });
    try node.log.append(.{ .index = 3, .term = 3, .data = "suffix" });
    try install(&node, data, meta);
    try std.testing.expectEqual(@as(u64, 2), node.state_machine.last_applied);
    const forwarded = try readSelected(std.testing.allocator, path, (try node.log.readSnapshotMeta()).?);
    defer std.testing.allocator.free(forwarded);
    try std.testing.expectEqualSlices(u8, data, forwarded);
    var recovered = try @import("../state_machine.zig").StateMachine.initMemory();
    defer recovered.deinit();
    try recover(std.testing.allocator, path, &node.log, &recovered);
    const row = (try recovered.db.one(struct { value: i64 }, "SELECT cpu_used AS value FROM agents WHERE id = 'snapshot-probe';", .{}, .{})).?;
    try std.testing.expectEqual(@as(i64, 42), row.value);
    try std.testing.expectEqual(@as(u64, 3), node.log.lastIndex());
}

test "snapshot restore failure stops participation and selected generation recovers" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const path_len = try tmp.dir.realPath(std.testing.io, &path_buf);
    const path = path_buf[0..path_len];
    const data = try testSnapshot(path);
    defer std.testing.allocator.free(data);
    var node = try TestNode.init(path);
    defer node.deinit();
    try node.state_machine.db.exec("BEGIN IMMEDIATE;", .{}, .{});
    try std.testing.expectError(error.SnapshotRecoveryRequired, install(&node, data, null));
    try std.testing.expect(node.snapshot_failed.load(.acquire));
    try std.testing.expect(!node.running.load(.acquire));
    try std.testing.expectEqual(.follower, node.raft.role);
    try std.testing.expectEqual(@as(u64, 0), node.state_machine.last_applied);
    try std.testing.expectEqual(@as(u64, 2), (try node.log.readSnapshotMeta()).?.last_included_index);
    try node.state_machine.db.exec("ROLLBACK;", .{}, .{});
    try recover(std.testing.allocator, path, &node.log, &node.state_machine);
    try std.testing.expectEqual(@as(u64, 2), node.state_machine.last_applied);
}

test "snapshot validation and publication failures leave state and log unchanged" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const path_len = try tmp.dir.realPath(std.testing.io, &path_buf);
    const path = path_buf[0..path_len];
    const data = try testSnapshot(path);
    defer std.testing.allocator.free(data);
    var node = try TestNode.init(path);
    defer node.deinit();
    try node.log.append(.{ .index = 1, .term = 1, .data = "unchanged" });
    try std.testing.expectError(error.SnapshotMismatch, install(&node, data, .{ .last_included_index = 99, .last_included_term = 3, .data_len = 0 }));
    const saved = data[artifact.snapshot_header_size];
    data[artifact.snapshot_header_size] = 0;
    try std.testing.expectError(error.CorruptSnapshot, install(&node, data, null));
    data[artifact.snapshot_header_size] = saved;
    try tmp.dir.createDir(std.testing.io, "snapshot-2-3.dat", .default_dir);
    if (install(&node, data, null)) |_| return error.ExpectedPublicationFailure else |_| {}
    try std.testing.expectEqual(@as(u64, 0), node.state_machine.last_applied);
    try std.testing.expectEqual(@as(u64, 1), node.log.lastIndex());
    try std.testing.expect((try node.log.readSnapshotMeta()) == null);
    try std.testing.expect(!node.snapshot_failed.load(.acquire));
    try tmp.dir.deleteDir(std.testing.io, "snapshot-2-3.dat");
    try node.log.db.exec("CREATE TRIGGER refuse_snapshot BEFORE UPDATE ON snapshot_meta BEGIN SELECT RAISE(ABORT, 'injected activation failure'); END;", .{}, .{});
    try std.testing.expectError(error.WriteFailed, install(&node, data, null));
    try std.testing.expect((try node.log.readSnapshotMeta()) == null);
    try std.testing.expectEqual(@as(u64, 1), node.log.lastIndex());
    try recover(std.testing.allocator, path, &node.log, &node.state_machine);
    try std.testing.expectEqual(@as(u64, 0), node.state_machine.last_applied);
}

test "snapshot recovery ignores unselected generations and rejects a missing selected artifact" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const path_len = try tmp.dir.realPath(std.testing.io, &path_buf);
    const path = path_buf[0..path_len];
    const data = try testSnapshot(path);
    defer std.testing.allocator.free(data);
    const meta = try artifact.parseSnapshotMeta(data);
    var generation_buf: [512]u8 = undefined;
    try artifact.publishBytes(try generationPath(&generation_buf, path, meta), data);
    var node = try TestNode.init(path);
    defer node.deinit();
    try recover(std.testing.allocator, path, &node.log, &node.state_machine);
    try std.testing.expectEqual(@as(u64, 0), node.state_machine.last_applied);
    try node.log.activateSnapshot(meta);
    try tmp.dir.deleteFile(std.testing.io, "snapshot-2-3.dat");
    try std.testing.expectError(error.MissingSnapshot, recover(std.testing.allocator, path, &node.log, &node.state_machine));
}

test "snapshot recovery validates and migrates the exact legacy boundary" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const path_len = try tmp.dir.realPath(std.testing.io, &path_buf);
    const path = path_buf[0..path_len];
    const data = try testSnapshot(path);
    defer std.testing.allocator.free(data);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "snapshot.dat", .data = data });
    var node = try TestNode.init(path);
    defer node.deinit();
    try std.testing.expect(node.log.setSnapshotMeta(.{ .last_included_index = 2, .last_included_term = 9, .data_len = 0 }));
    try std.testing.expectError(error.SnapshotMismatch, recover(std.testing.allocator, path, &node.log, &node.state_machine));
    try std.testing.expect(node.log.setSnapshotMeta(.{ .last_included_index = 2, .last_included_term = 3, .data_len = 0 }));
    try recover(std.testing.allocator, path, &node.log, &node.state_machine);
    try std.testing.expect((try node.log.readSnapshotMeta()).?.data_len > 0);
    try std.testing.expectEqual(@as(u64, 2), node.state_machine.last_applied);
    try tmp.dir.access(std.testing.io, "snapshot-2-3.dat", .{});
}

test "snapshot restart repairs activation before restore and preserves later applied entries" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [512]u8 = undefined;
    const dir_len = try tmp.dir.realPath(std.testing.io, &dir_buf);
    const dir = dir_buf[0..dir_len];
    const data = try testSnapshot(dir);
    defer std.testing.allocator.free(data);
    const meta = try artifact.parseSnapshotMeta(data);
    var generation_buf: [512]u8 = undefined;
    try artifact.publishBytes(try generationPath(&generation_buf, dir, meta), data);
    var log_buf: [512]u8 = undefined;
    const log_path = try std.fmt.bufPrintZ(&log_buf, "{s}/raft.db", .{dir});
    var state_buf: [512]u8 = undefined;
    const state_path = try std.fmt.bufPrintZ(&state_buf, "{s}/state.db", .{dir});
    const Log = @import("../log.zig").Log;
    const StateMachine = @import("../state_machine.zig").StateMachine;
    {
        var log = try Log.init(log_path);
        defer log.deinit();
        var state = try StateMachine.init(state_path);
        defer state.deinit();
        // This is the durable crash seam: activation committed, restore has
        // not run. No volatile marker is available to the next process.
        try log.activateSnapshot(meta);
    }
    {
        var log = try Log.init(log_path);
        defer log.deinit();
        var state = try StateMachine.init(state_path);
        defer state.deinit();
        try recover(std.testing.allocator, dir, &log, &state);
        try std.testing.expectEqual(@as(u64, 2), state.last_applied);
        state.apply(.{ .index = 3, .term = 3, .data = "UPDATE agents SET cpu_used = 99 WHERE id = 'snapshot-probe';" });
        try std.testing.expectEqual(@as(u64, 3), state.last_applied);
    }
    {
        var log = try Log.init(log_path);
        defer log.deinit();
        var state = try StateMachine.init(state_path);
        defer state.deinit();
        try recover(std.testing.allocator, dir, &log, &state);
        try std.testing.expectEqual(@as(u64, 3), state.last_applied);
        const row = (try state.db.one(struct { value: i64 }, "SELECT cpu_used AS value FROM agents WHERE id = 'snapshot-probe';", .{}, .{})).?;
        try std.testing.expectEqual(@as(i64, 99), row.value);
    }
}
