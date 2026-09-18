const std = @import("std");
const bundle = @import("bundle.zig");
const files = @import("files.zig");
const manifest = @import("manifest.zig");
const databases = @import("databases.zig");
const Log = @import("../log.zig").Log;
const StateMachine = @import("../state_machine.zig").StateMachine;
const raft_mod = @import("../raft.zig");
const io = std.testing.io;
const alloc = std.testing.allocator;
const join_token = "private-test-join-token";
const set_id = "recovery-drill";
const voters = "1,2,3,";
const Peer = struct { id: u64, addr: [4]u8 = .{ 127, 0, 0, 1 }, port: u16 };

fn joinPath(root: []const u8, name: []const u8) ![:0]u8 {
    return std.fmt.allocPrintSentinel(alloc, "{s}/{s}", .{ root, name }, 0);
}

const Ca = struct {
    sql: []u8,
    identity: [32]u8,

    fn init() !Ca {
        const minted = try @import("../../tls/x509_gen.zig").generateCa(io, alloc, "recovery-test-ca", 1700000000, 2000000000);
        defer alloc.free(minted.cert_pem);
        var raw = minted.key_pair.secret_key.toBytes();
        defer std.crypto.secureZero(u8, &raw);
        var key: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(join_token, &key, .{});
        const encrypted = try @import("../../state/secrets.zig").encrypt(alloc, &raw, key);
        defer alloc.free(encrypted.ciphertext);
        const sql = try @import("../../state/store/cluster_ca.zig").buildInsertSql(alloc, minted.cert_pem, encrypted.ciphertext, &encrypted.nonce, &encrypted.tag, 1700000000, 2000000000);
        const der = try @import("../../tls/pem.zig").parseCertDer(alloc, minted.cert_pem);
        defer alloc.free(der);
        var identity: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(der, &identity, .{});
        return .{ .sql = sql, .identity = identity };
    }

    fn deinit(self: Ca) void {
        alloc.free(self.sql);
    }
};

fn fixture(root: []const u8, node_id: u64, selected_snapshot: bool, ca: Ca) !void {
    try std.Io.Dir.cwd().createDir(io, root, .fromMode(0o700));
    const dir = try files.openDir(root);
    defer dir.close(io);
    try dir.createDir(io, "cluster", .fromMode(0o700));
    try files.write(dir, "api_token", "a" ** 64);
    try files.write(dir, "join_token", join_token);
    try files.write(dir, "secrets.key", "k" ** 32);
    const raft_path = try joinPath(root, "cluster/raft.db");
    defer alloc.free(raft_path);
    var log = try Log.init(raft_path);
    defer log.deinit();
    var peers: [2]Peer = undefined;
    var count: usize = 0;
    for (1..4) |id| {
        if (id == node_id) continue;
        peers[count] = .{ .id = id, .port = @intCast(9700 + id) };
        count += 1;
    }
    try @import("../static_membership.zig").check(alloc, &log.db, node_id, &peers);
    try std.testing.expect(log.setElectionState(3, 1));
    const state_path = try joinPath(root, "cluster/state.db");
    defer alloc.free(state_path);
    var state = try StateMachine.init(state_path);
    defer state.deinit();
    const command = try std.fmt.allocPrint(alloc, "{s}INSERT INTO agents (id,address,status,last_heartbeat,registered_at) VALUES ('joined-worker','127.0.0.1','active',1,1);", .{ca.sql});
    defer alloc.free(command);
    const entry = @import("../raft_types.zig").LogEntry{ .index = 1, .term = 3, .data = command };
    try log.append(entry);
    state.apply(entry);
    try std.testing.expectEqual(@as(u64, 1), state.last_applied);
    if (selected_snapshot) {
        const cluster_path = try joinPath(root, "cluster");
        defer alloc.free(cluster_path);
        var generation = try @import("../snapshot_lifecycle.zig").Generation.capture(&state, cluster_path, .{ .last_included_index = 1, .last_included_term = 3, .data_len = 0 });
        defer generation.deinit();
        try generation.select(&log);
    }
    // a captured suffix may include entries that were not committed yet.
    try log.append(.{ .index = 2, .term = 3, .data = "" });
    const local_path = try joinPath(root, "yoq.db");
    defer alloc.free(local_path);
    var local = try @import("sqlite").Db.init(.{ .mode = .{ .File = local_path }, .open_flags = .{ .write = true, .create = true } });
    defer local.deinit();
    try @import("../../state/schema.zig").init(&local);
    var secrets = try @import("../../state/secrets.zig").SecretsStore.initWithKey(&local, alloc, ("k" ** 32).*);
    try secrets.set("database_password", "preserved-secret");
}

fn capture(root: []const u8, destination: []const u8) !void {
    const token = try joinPath(root, "join_token");
    defer alloc.free(token);
    const boundary = try bundle.capture(alloc, .{ .data_dir = root, .destination = destination, .join_token_file = token, .set_id = set_id });
    defer boundary.deinit(alloc);
    try std.testing.expectEqual(@as(u64, 1), boundary.last_applied);
}

fn restoreOptions(source: []const u8, destination: []const u8, node_id: u64, fingerprint: []const u8) bundle.RestoreOptions {
    return .{ .source = source, .destination = destination, .node_id = node_id, .voters = voters, .set_id = set_id, .cluster_fingerprint = fingerprint };
}

test "cluster bundle restores three fixed voters and elects a leader with existing state" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const ca = try Ca.init();
    defer ca.deinit();
    const base = try tmp.dir.realPathFileAlloc(io, ".", alloc);
    defer alloc.free(base);
    var roots: [3][:0]u8 = undefined;
    var bundles: [3][]const u8 = undefined;
    var restored: [3][:0]u8 = undefined;
    var initialized: usize = 0;
    defer for (0..initialized) |i| {
        alloc.free(roots[i]);
        alloc.free(bundles[i]);
        alloc.free(restored[i]);
    };
    for (0..3) |i| {
        roots[i] = try std.fmt.allocPrintSentinel(alloc, "{s}/source-{d}", .{ base, i + 1 }, 0);
        bundles[i] = try std.fmt.allocPrint(alloc, "{s}/bundle-{d}", .{ base, i + 1 });
        restored[i] = try std.fmt.allocPrintSentinel(alloc, "{s}/restored-{d}", .{ base, i + 1 }, 0);
        initialized += 1;
        try fixture(roots[i], i + 1, true, ca);
        try capture(roots[i], bundles[i]);
    }
    const fingerprint = try bundle.verifySet(alloc, &bundles, set_id);
    try std.testing.expectEqualSlices(u8, &manifest.fingerprint(voters, join_token, &ca.identity), &fingerprint);
    var logs: [3]Log = undefined;
    var log_count: usize = 0;
    defer for (logs[0..log_count]) |*log| log.deinit();
    for (0..3) |i| {
        const boundary = try bundle.restore(alloc, restoreOptions(bundles[i], restored[i], i + 1, &fingerprint));
        defer boundary.deinit(alloc);
        const log_path = try joinPath(restored[i], "cluster/raft.db");
        defer alloc.free(log_path);
        logs[i] = try Log.init(log_path);
        log_count += 1;
        try std.testing.expectEqual(@as(u64, 3), try logs[i].getCurrentTerm());
        const state_path = try joinPath(restored[i], "cluster/state.db");
        defer alloc.free(state_path);
        var state = try StateMachine.init(state_path);
        defer state.deinit();
        const cluster_path = try joinPath(restored[i], "cluster");
        defer alloc.free(cluster_path);
        var selected = (try @import("../snapshot_lifecycle.zig").Generation.recoverSelected(alloc, cluster_path, &logs[i])).?;
        defer selected.deinit();
        try selected.restore(&state);
        try state.validateAppliedHistory(&logs[i], alloc);
        const agents = (try state.db.one(struct { count: i64 }, "SELECT COUNT(*) FROM agents WHERE id='joined-worker';", .{}, .{})).?;
        try std.testing.expectEqual(@as(i64, 1), agents.count);
        const local_path = try joinPath(restored[i], "yoq.db");
        defer alloc.free(local_path);
        var local = try @import("sqlite").Db.init(.{ .mode = .{ .File = local_path }, .open_flags = .{ .write = true } });
        defer local.deinit();
        var secrets = try @import("../../state/secrets.zig").SecretsStore.initWithKey(&local, alloc, ("k" ** 32).*);
        const password = try secrets.get("database_password");
        defer alloc.free(password);
        try std.testing.expectEqualStrings("preserved-secret", password);
    }
    var first = try raft_mod.Raft.init(alloc, 1, &.{ 2, 3 }, &logs[0]);
    defer first.deinit();
    var second = try raft_mod.Raft.init(alloc, 2, &.{ 1, 3 }, &logs[1]);
    defer second.deinit();
    var third = try raft_mod.Raft.init(alloc, 3, &.{ 1, 2 }, &logs[2]);
    defer third.deinit();
    first.election_timeout = 1;
    first.tick();
    const actions = try first.drainActions();
    defer @import("../raft/test_support.zig").deinitOwnedActions(raft_mod.Action, alloc, actions);
    for (actions) |action| if (action == .send_request_vote) {
        const request = action.send_request_vote;
        const reply = if (request.target == 2) second.handleRequestVote(request.args) else third.handleRequestVote(request.args);
        first.handleRequestVoteReply(request.target, reply);
    };
    try std.testing.expectEqual(@import("../raft_types.zig").Role.leader, first.role);
    try std.testing.expectEqual(@as(u64, 4), first.currentTerm());
}

test "cluster bundle rejects active sources changed membership and existing destinations" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const ca = try Ca.init();
    defer ca.deinit();
    const base = try tmp.dir.realPathFileAlloc(io, ".", alloc);
    defer alloc.free(base);
    const root = try joinPath(base, "source");
    defer alloc.free(root);
    const destination = try joinPath(base, "bundle");
    defer alloc.free(destination);
    try fixture(root, 1, false, ca);
    const cluster_path = try joinPath(root, "cluster");
    defer alloc.free(cluster_path);
    const lock = try @import("../data_lock.zig").Lock.acquire(cluster_path);
    try std.testing.expectError(error.ServerRunning, capture(root, destination));
    lock.release();
    // older servers do not hold the lifetime lock. an open wal reader must
    // still prevent capture through the exclusive sqlite admission check.
    const state_path = try joinPath(root, "cluster/state.db");
    defer alloc.free(state_path);
    {
        var live = try StateMachine.init(state_path);
        defer live.deinit();
        try live.db.exec("BEGIN;", .{}, .{});
        _ = try live.db.one(struct { count: i64 }, "SELECT COUNT(*) FROM agents;", .{}, .{});
        try std.testing.expectError(error.ServerRunning, capture(root, destination));
    }
    try capture(root, destination);
    try std.testing.expectError(error.DestinationExists, capture(root, destination));
    const target = try joinPath(base, "restored");
    defer alloc.free(target);
    const fingerprint = manifest.fingerprint(voters, join_token, &ca.identity);
    try std.testing.expectError(error.MembershipMismatch, bundle.restore(alloc, restoreOptions(destination, target, 2, &fingerprint)));
    var wrong_set = restoreOptions(destination, target, 1, &fingerprint);
    wrong_set.set_id = "older-backup";
    try std.testing.expectError(error.BackupSetMismatch, bundle.restore(alloc, wrong_set));
    const restored = try bundle.restore(alloc, restoreOptions(destination, target, 1, &fingerprint));
    restored.deinit(alloc);
    try std.testing.expectError(error.DestinationExists, bundle.restore(alloc, restoreOptions(destination, target, 1, &fingerprint)));
    try std.testing.expectError(error.MissingVoter, bundle.verifySet(alloc, &.{destination}, set_id));
    try std.testing.expectError(error.DuplicateVoter, bundle.verifySet(alloc, &.{ destination, destination, destination }, set_id));
}

test "cluster bundle rejects corruption unsafe entries and incompatible database schemas" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const ca = try Ca.init();
    defer ca.deinit();
    const base = try tmp.dir.realPathFileAlloc(io, ".", alloc);
    defer alloc.free(base);
    const root = try joinPath(base, "source");
    defer alloc.free(root);
    const destination = try joinPath(base, "bundle");
    defer alloc.free(destination);
    try fixture(root, 1, false, ca);
    try capture(root, destination);
    const dir = try files.openDir(destination);
    defer dir.close(io);
    const description = try manifest.read(alloc, dir);
    defer description.deinit();
    // a corrupt private file fails its digest before sqlite opens it.
    try dir.deleteFile(io, "state.db");
    try files.write(dir, "state.db", "broken sqlite database");
    try std.testing.expectError(error.DigestMismatch, bundle.verify(alloc, destination));
    try dir.deleteFile(io, "state.db");
    try dir.symLink(io, "/etc/passwd", "state.db", .{});
    try std.testing.expectError(error.UnsafeFile, bundle.verify(alloc, destination));
    try dir.deleteFile(io, "state.db");
    // even an updated digest cannot make an unrelated sqlite database a valid
    // cluster state database or silently manufacture its missing applied row.
    const empty_file = try files.create(dir, "state.db");
    empty_file.close(io);
    {
        var empty = try databases.open(alloc, dir, "state.db", true);
        defer empty.deinit();
        try empty.exec("CREATE TABLE unrelated (id INTEGER);", .{}, .{});
    }
    const digest = try files.digest(dir, "state.db", files.max_database_size);
    const entries = try alloc.dupe(manifest.Entry, description.value.files);
    defer alloc.free(entries);
    for (entries) |*entry| if (std.mem.eql(u8, entry.name, "state.db")) {
        entry.size = digest.size;
        entry.sha256 = &digest.sha256;
    };
    var modified = description.value;
    modified.files = entries;
    try dir.deleteFile(io, "manifest.json");
    try manifest.write(alloc, dir, modified);
    try std.testing.expectError(error.InvalidStateSchema, bundle.verify(alloc, destination));
}

test "cluster bundle finishes selected snapshot recovery only in its private copy" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const ca = try Ca.init();
    defer ca.deinit();
    const base = try tmp.dir.realPathFileAlloc(io, ".", alloc);
    defer alloc.free(base);
    const root = try joinPath(base, "source");
    defer alloc.free(root);
    const destination = try joinPath(base, "bundle");
    defer alloc.free(destination);
    try fixture(root, 1, true, ca);
    const state_path = try joinPath(root, "cluster/state.db");
    defer alloc.free(state_path);
    {
        var state = try StateMachine.init(state_path);
        defer state.deinit();
        try state.db.exec("DELETE FROM agents;", .{}, .{});
        try state.db.exec("DELETE FROM cluster_ca;", .{}, .{});
        try state.db.exec("UPDATE state_machine_meta SET last_applied=0;", .{}, .{});
    }
    const token = try joinPath(root, "join_token");
    defer alloc.free(token);
    const captured = try bundle.capture(alloc, .{ .data_dir = root, .destination = destination, .join_token_file = token, .set_id = set_id });
    defer captured.deinit(alloc);
    try std.testing.expectEqual(@as(u64, 0), captured.last_applied);
    const verified = try bundle.verify(alloc, destination);
    defer verified.deinit(alloc);
    try std.testing.expectEqual(@as(u64, 1), verified.last_applied);
    const target = try joinPath(base, "restored");
    defer alloc.free(target);
    const fingerprint = manifest.fingerprint(voters, join_token, &ca.identity);
    const restored = try bundle.restore(alloc, restoreOptions(destination, target, 1, &fingerprint));
    restored.deinit(alloc);
    const restored_path = try joinPath(target, "cluster/state.db");
    defer alloc.free(restored_path);
    var state = try StateMachine.init(restored_path);
    defer state.deinit();
    try std.testing.expectEqual(@as(u64, 1), state.last_applied);
    try std.testing.expectEqual(@as(i64, 1), (try state.db.one(struct { count: i64 }, "SELECT COUNT(*) FROM agents;", .{}, .{})).?.count);
    var source = try StateMachine.init(state_path);
    defer source.deinit();
    try std.testing.expectEqual(@as(u64, 0), source.last_applied);
    try std.testing.expectEqual(@as(i64, 0), (try source.db.one(struct { count: i64 }, "SELECT COUNT(*) FROM agents;", .{}, .{})).?.count);
}

test "cluster bundle rejects wrong secret keys invalid ca keys and reused token cluster identities" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const ca = try Ca.init();
    defer ca.deinit();
    const other_ca = try Ca.init();
    defer other_ca.deinit();
    const base = try tmp.dir.realPathFileAlloc(io, ".", alloc);
    defer alloc.free(base);
    const root = try joinPath(base, "source");
    defer alloc.free(root);
    const destination = try joinPath(base, "bundle");
    defer alloc.free(destination);
    try fixture(root, 1, false, ca);
    const dir = try files.openDir(root);
    defer dir.close(io);
    try dir.deleteFile(io, "secrets.key");
    try files.write(dir, "secrets.key", "w" ** 32);
    try std.testing.expectError(error.InvalidSecretsKey, capture(root, destination));
    try dir.deleteFile(io, "secrets.key");
    try files.write(dir, "secrets.key", "k" ** 32);
    try capture(root, destination);
    const other_root = try joinPath(base, "other-source");
    defer alloc.free(other_root);
    const other_bundle = try joinPath(base, "other-bundle");
    defer alloc.free(other_bundle);
    try fixture(other_root, 2, false, other_ca);
    try capture(other_root, other_bundle);
    try std.testing.expectError(error.BackupSetMismatch, bundle.verifySet(alloc, &.{ destination, other_bundle }, set_id));
    const state_path = try joinPath(root, "cluster/state.db");
    defer alloc.free(state_path);
    var derived: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(join_token, &derived, .{});
    const encrypted = try @import("../../state/secrets.zig").encrypt(alloc, &(@as([32]u8, @splat(0))), derived);
    defer alloc.free(encrypted.ciphertext);
    {
        var state = try StateMachine.init(state_path);
        defer state.deinit();
        const Blob = @import("sqlite").Blob;
        try state.db.exec("UPDATE cluster_ca SET encrypted_key=?,key_nonce=?,key_tag=?;", .{}, .{ Blob{ .data = encrypted.ciphertext }, Blob{ .data = &encrypted.nonce }, Blob{ .data = &encrypted.tag } });
    }
    const invalid = try joinPath(base, "invalid-ca");
    defer alloc.free(invalid);
    try std.testing.expectError(error.InvalidClusterCa, capture(root, invalid));
    {
        var state = try StateMachine.init(state_path);
        defer state.deinit();
        try state.db.exec("DELETE FROM cluster_ca;", .{}, .{});
    }
    try std.testing.expectError(error.ClusterIdentityUnavailable, capture(root, invalid));
}

test "cluster bundle requires the encryption key for stored certificates without secrets" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const ca = try Ca.init();
    defer ca.deinit();
    const base = try tmp.dir.realPathFileAlloc(io, ".", alloc);
    defer alloc.free(base);
    const root = try joinPath(base, "source");
    defer alloc.free(root);
    const destination = try joinPath(base, "bundle");
    defer alloc.free(destination);
    try fixture(root, 1, false, ca);
    const local_path = try joinPath(root, "yoq.db");
    defer alloc.free(local_path);
    {
        var db = try @import("sqlite").Db.init(.{ .mode = .{ .File = local_path }, .open_flags = .{ .write = true } });
        defer db.deinit();
        try db.exec("DELETE FROM secrets;", .{}, .{});
        const encrypted = try @import("../../state/secrets.zig").encrypt(alloc, "stored certificate key", ("k" ** 32).*);
        defer alloc.free(encrypted.ciphertext);
        const Blob = @import("sqlite").Blob;
        try db.exec("INSERT INTO certificates (domain,cert_pem,encrypted_key,key_nonce,key_tag,not_after,source,created_at,updated_at) VALUES ('app.example','certificate',?,?,?,2000000000,'manual',1,1);", .{}, .{ Blob{ .data = encrypted.ciphertext }, Blob{ .data = &encrypted.nonce }, Blob{ .data = &encrypted.tag } });
    }
    const dir = try files.openDir(root);
    defer dir.close(io);
    try dir.deleteFile(io, "secrets.key");
    try std.testing.expectError(error.MissingSecretsKey, capture(root, destination));
    try files.write(dir, "secrets.key", "w" ** 32);
    try std.testing.expectError(error.InvalidSecretsKey, capture(root, destination));
}
