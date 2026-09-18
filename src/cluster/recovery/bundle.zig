//! offline recovery preserves one voter's identity and durable history. every
//! voter must be stopped before the operator starts capturing the first bundle.
const std = @import("std");
const sqlite = @import("sqlite");
const files = @import("files.zig");
const databases = @import("databases.zig");
const manifest = @import("manifest.zig");
const DataLock = @import("../data_lock.zig").Lock;
const snapshot = @import("../state_machine/snapshot_support.zig");
const io = std.Options.debug_io;

pub const CaptureOptions = struct {
    data_dir: []const u8,
    destination: []const u8,
    join_token_file: []const u8,
    set_id: []const u8,
};

pub fn capture(alloc: std.mem.Allocator, options: CaptureOptions) !databases.Boundary {
    try manifest.validateSetId(options.set_id);
    const root = try files.openDir(options.data_dir);
    defer root.close(io);
    const cluster_path = try std.fs.path.join(alloc, &.{ options.data_dir, "cluster" });
    defer alloc.free(cluster_path);
    const cluster = try files.openDir(cluster_path);
    defer cluster.close(io);
    const ownership = try DataLock.acquireAt(cluster);
    defer ownership.release();
    var raft = try databases.open(alloc, cluster, "raft.db", true);
    defer raft.deinit();
    try databases.lock(&raft);
    var state = try databases.open(alloc, cluster, "state.db", true);
    defer state.deinit();
    try databases.lock(&state);
    var local: ?sqlite.Db = databases.open(alloc, root, "yoq.db", true) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    defer if (local) |*db| db.deinit();
    if (local) |*db| try databases.lock(db);
    const boundary = try databases.readBoundary(alloc, &raft, &state);
    errdefer boundary.deinit(alloc);
    var stage = try files.Stage.init(options.destination);
    defer stage.deinit();
    var entries: [7]manifest.Entry = undefined;
    var digests: [7]files.Digest = undefined;
    var count: usize = 0;
    add(&entries, &digests, &count, "raft.db", try databases.copy(alloc, &raft, stage.dir, "raft.db"));
    add(&entries, &digests, &count, "state.db", try databases.copy(alloc, &state, stage.dir, "state.db"));
    if (local) |*db| add(&entries, &digests, &count, "yoq.db", try databases.copy(alloc, db, stage.dir, "yoq.db"));
    add(&entries, &digests, &count, "api_token", try files.copy(root, "api_token", stage.dir, "api_token", true, 4096));
    if (files.copy(root, "secrets.key", stage.dir, "secrets.key", true, 32)) |digest| {
        add(&entries, &digests, &count, "secrets.key", digest);
    } else |err| if (err != error.FileNotFound) return err;
    const token_dir = try files.openDir(std.fs.path.dirname(options.join_token_file) orelse ".");
    defer token_dir.close(io);
    add(&entries, &digests, &count, "join_token", try files.copy(token_dir, std.fs.path.basename(options.join_token_file), stage.dir, "join_token", true, 4096));
    if (boundary.snapshot_index > 0) {
        var name_buf: [96]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "snapshot-{d}-{d}.dat", .{ boundary.snapshot_index, boundary.snapshot_term });
        const digest = files.copy(cluster, name, stage.dir, "snapshot.dat", false, snapshot.max_snapshot_file_size) catch |err| blk: {
            if (err != error.FileNotFound or boundary.snapshot_size != 0) return err;
            break :blk try files.copy(cluster, "snapshot.dat", stage.dir, "snapshot.dat", false, snapshot.max_snapshot_file_size);
        };
        add(&entries, &digests, &count, "snapshot.dat", digest);
    }
    const token = try readJoinToken(alloc, stage.dir, "join_token");
    defer {
        std.crypto.secureZero(u8, token);
        alloc.free(token);
    }
    const identity = if (boundary.last_applied < boundary.snapshot_index) blk: {
        const data = try files.readSmall(alloc, stage.dir, "snapshot.dat", snapshot.max_snapshot_file_size);
        defer alloc.free(data);
        var selected = try snapshot.PreparedSnapshot.init(data);
        defer selected.deinit();
        var db = sqlite.Db{ .db = selected.db.? };
        break :blk try validateJoinKey(alloc, &db, token);
    } else try validateJoinKey(alloc, &state, token);
    const fingerprint = manifest.fingerprint(boundary.voters, token, &identity);
    const description = manifest.Manifest.fromBoundary(boundary, entries[0..count], options.set_id, &fingerprint);
    // validation may migrate its input. use a second private copy so the
    // published hashes still describe the exact captured database bytes.
    try manifest.write(alloc, stage.dir, description);
    const path = try stage.path(alloc);
    defer alloc.free(path);
    const verified = try verify(alloc, path);
    verified.deinit(alloc);
    try stage.publish();
    return boundary;
}

fn add(entries: *[7]manifest.Entry, digests: *[7]files.Digest, count: *usize, name: []const u8, digest: files.Digest) void {
    digests[count.*] = digest;
    entries[count.*] = .{ .name = name, .size = digest.size, .sha256 = &digests[count.*].sha256 };
    count.* += 1;
}

pub fn verify(alloc: std.mem.Allocator, source: []const u8) !databases.Boundary {
    const input = try files.openDir(source);
    defer input.close(io);
    const description = try manifest.read(alloc, input);
    defer description.deinit();
    var stage = try verificationStage();
    defer stage.deinit();
    try copyVerified(input, stage.dir, description.value);
    return validateContents(alloc, stage.dir, description.value);
}

pub const RestoreOptions = struct {
    source: []const u8,
    destination: []const u8,
    node_id: u64,
    voters: []const u8,
    set_id: []const u8,
    cluster_fingerprint: []const u8,
};

pub fn restore(alloc: std.mem.Allocator, options: RestoreOptions) !databases.Boundary {
    const input = try files.openDir(options.source);
    defer input.close(io);
    const description = try manifest.read(alloc, input);
    defer description.deinit();
    if (!std.mem.eql(u8, description.value.set_id, options.set_id) or !std.mem.eql(u8, description.value.cluster_fingerprint, options.cluster_fingerprint)) return error.BackupSetMismatch;
    if (description.value.node_id != options.node_id or !std.mem.eql(u8, description.value.voters, options.voters)) return error.MembershipMismatch;
    var stage = try files.Stage.init(options.destination);
    defer stage.deinit();
    try stage.dir.createDir(io, "cluster", .fromMode(0o700));
    const cluster = try stage.dir.openDir(io, "cluster", .{ .iterate = true });
    defer cluster.close(io);
    // first validate a flat private copy. restoring relocates only allowlisted
    // files after all hashes, credentials, schemas and boundaries agree.
    var candidate = try verificationStage();
    defer candidate.deinit();
    try copyVerified(input, candidate.dir, description.value);
    const boundary = try validateContents(alloc, candidate.dir, description.value);
    errdefer boundary.deinit(alloc);
    for (description.value.files) |entry| {
        const is_cluster = std.mem.eql(u8, entry.name, "raft.db") or std.mem.eql(u8, entry.name, "state.db") or std.mem.eql(u8, entry.name, "snapshot.dat");
        var name_buf: [96]u8 = undefined;
        const name = if (std.mem.eql(u8, entry.name, "snapshot.dat"))
            try std.fmt.bufPrint(&name_buf, "snapshot-{d}-{d}.dat", .{ boundary.snapshot_index, boundary.snapshot_term })
        else
            entry.name;
        _ = try files.copy(candidate.dir, entry.name, if (is_cluster) cluster else stage.dir, name, true, manifest.limit(entry.name));
    }
    try files.syncDir(cluster);
    try stage.publish();
    return boundary;
}

fn verificationStage() !files.Stage {
    var random: [16]u8 = undefined;
    @import("linux_platform").randomBytes(&random);
    var destination: [96]u8 = undefined;
    return files.Stage.init(try std.fmt.bufPrint(&destination, "/tmp/yoq-verify-{s}", .{std.fmt.bytesToHex(random, .lower)}));
}

fn copyVerified(input: std.Io.Dir, output: std.Io.Dir, description: manifest.Manifest) !void {
    for (description.files) |entry| {
        const digest = try files.copy(input, entry.name, output, entry.name, true, manifest.limit(entry.name));
        if (digest.size != entry.size or !std.mem.eql(u8, &digest.sha256, entry.sha256)) return error.DigestMismatch;
    }
}

fn validateContents(alloc: std.mem.Allocator, dir: std.Io.Dir, description: manifest.Manifest) !databases.Boundary {
    var raft = try databases.open(alloc, dir, "raft.db", true);
    defer raft.deinit();
    var state = try databases.open(alloc, dir, "state.db", true);
    defer state.deinit();
    try databases.validateState(&state);
    var boundary = try databases.readBoundary(alloc, &raft, &state);
    errdefer boundary.deinit(alloc);
    if (!description.matches(boundary)) return error.BoundaryMismatch;
    var validator = try @import("../state_machine/command.zig").Validator.init();
    defer validator.deinit();
    var machine = @import("../state_machine.zig").StateMachine{ .db = state, .last_applied = boundary.last_applied, .validator = validator };
    var log = @import("../log.zig").Log{ .db = raft };
    if (description.contains("snapshot.dat")) {
        const bytes = try files.readSmall(alloc, dir, "snapshot.dat", snapshot.max_snapshot_file_size);
        defer alloc.free(bytes);
        _ = try snapshot.parseSnapshotMeta(bytes);
        try files.write(dir, "snapshot-check.db", bytes[snapshot.snapshot_header_size..]);
        defer dir.deleteFile(io, "snapshot-check.db") catch {};
        {
            var snapshot_db = try databases.open(alloc, dir, "snapshot-check.db", false);
            defer snapshot_db.deinit();
            try @import("../../state/backup_schema.zig").validateExistingTriggers(snapshot_db.db);
        }
        var prepared = try snapshot.PreparedSnapshot.init(bytes);
        defer prepared.deinit();
        if (prepared.meta.last_included_index != boundary.snapshot_index or prepared.meta.last_included_term != boundary.snapshot_term or
            (boundary.snapshot_size != 0 and prepared.meta.data_len != boundary.snapshot_size)) return error.BoundaryMismatch;
        try @import("../../state/backup_schema.zig").validate(prepared.db.?);
        if (boundary.last_applied < boundary.snapshot_index) {
            try prepared.restore(&machine);
            boundary.last_applied = machine.last_applied;
        }
    }
    try machine.validateAppliedHistory(&log, alloc);
    try validateSecrets(alloc, dir, description, &state);
    // schema.init enables wal; collapse every candidate database before the
    // caller copies it into the restored root without sidecars.
    try databases.finishCopy(&state);
    if (description.contains("yoq.db")) {
        var local = try databases.open(alloc, dir, "yoq.db", true);
        defer local.deinit();
        try databases.validateState(&local);
        try validateSecrets(alloc, dir, description, &local);
        try databases.finishCopy(&local);
    }
    const token = try files.readSmall(alloc, dir, "api_token", 4096);
    defer alloc.free(token);
    const trimmed = std.mem.trimEnd(u8, token, "\r\n");
    if (trimmed.len != 64) return error.InvalidApiToken;
    for (trimmed) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return error.InvalidApiToken;
    const join = try readJoinToken(alloc, dir, "join_token");
    defer {
        std.crypto.secureZero(u8, join);
        alloc.free(join);
    }
    const identity = try validateJoinKey(alloc, &state, join);
    const fingerprint = manifest.fingerprint(boundary.voters, join, &identity);
    if (!std.mem.eql(u8, description.cluster_fingerprint, &fingerprint)) return error.ClusterFingerprintMismatch;
    return boundary;
}

fn validateSecrets(alloc: std.mem.Allocator, dir: std.Io.Dir, description: manifest.Manifest, db: *sqlite.Db) !void {
    const encrypted = (try db.one(struct { count: i64 }, "SELECT COUNT(*) FROM secrets;", .{}, .{})).?;
    if (!description.contains("secrets.key")) {
        if (encrypted.count != 0) return error.MissingSecretsKey;
        return;
    }
    const key = try files.readSmall(alloc, dir, "secrets.key", 32);
    defer {
        std.crypto.secureZero(u8, key);
        alloc.free(key);
    }
    if (key.len != 32) return error.InvalidSecretsKey;
    var secrets = try @import("../../state/secrets.zig").SecretsStore.initWithKey(db, alloc, key[0..32].*);
    defer std.crypto.secureZero(u8, &secrets.key);
    var query = try db.prepare("SELECT name FROM secrets;");
    defer query.deinit();
    var rows = try query.iterator(struct { name: sqlite.Text }, .{});
    while (try rows.nextAlloc(alloc, .{})) |row| {
        defer alloc.free(row.name.data);
        const plaintext = secrets.get(row.name.data) catch return error.InvalidSecretsKey;
        defer {
            std.crypto.secureZero(u8, plaintext);
            alloc.free(plaintext);
        }
    }
}

pub fn readJoinToken(alloc: std.mem.Allocator, dir: std.Io.Dir, name: []const u8) ![]u8 {
    const contents = try files.readSmall(alloc, dir, name, 4096);
    defer {
        std.crypto.secureZero(u8, contents);
        alloc.free(contents);
    }
    const token = std.mem.trim(u8, contents, "\r\n");
    if (token.len == 0) return error.InvalidJoinToken;
    for (token) |byte| if (byte < 0x21 or byte > 0x7e) return error.InvalidJoinToken;
    return alloc.dupe(u8, token);
}

fn validateJoinKey(alloc: std.mem.Allocator, db: *sqlite.Db, token: []const u8) ![32]u8 {
    const record = (try @import("../../state/store/cluster_ca.zig").getClusterCaInDb(db, alloc)) orelse return error.ClusterIdentityUnavailable;
    defer record.deinit(alloc);
    const secrets = @import("../../state/secrets.zig");
    if (record.key_nonce.len != secrets.nonce_length or record.key_tag.len != secrets.tag_length) return error.InvalidJoinToken;
    var key: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(token, &key, .{});
    defer std.crypto.secureZero(u8, &key);
    const plaintext = secrets.decrypt(alloc, record.encrypted_key, record.key_nonce[0..secrets.nonce_length].*, record.key_tag[0..secrets.tag_length].*, key) catch return error.InvalidJoinToken;
    defer {
        std.crypto.secureZero(u8, plaintext);
        alloc.free(plaintext);
    }
    if (plaintext.len != 32) return error.InvalidJoinToken;
    const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    var secret = P256.SecretKey.fromBytes(plaintext[0..32].*) catch return error.InvalidClusterCa;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&secret));
    var pair = P256.KeyPair.fromSecretKey(secret) catch return error.InvalidClusterCa;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&pair.secret_key));
    const der = @import("../../tls/pem.zig").parseCertDer(alloc, record.cert_pem) catch return error.InvalidClusterCa;
    defer alloc.free(der);
    const x509 = @import("../../tls/x509_verify.zig");
    var sans: [x509.max_san_uris][]const u8 = undefined;
    const parsed = x509.parseDer(der, &sans) catch return error.InvalidClusterCa;
    if (!std.mem.eql(u8, parsed.public_key_point, &pair.public_key.toUncompressedSec1())) return error.InvalidClusterCa;
    // authenticate the self-signed identity without rejecting an old backup
    // solely because its CA expired since capture. expiry remains operational.
    x509.verifyLeafAgainstCa(alloc, record.cert_pem, record.cert_pem, null, parsed.not_before) catch return error.InvalidClusterCa;
    var identity: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(der, &identity, .{});
    return identity;
}

/// verify every fixed voter once before any node is restored. the set id records
/// the operator's coordinated stop; the fingerprint prevents mixing clusters.
pub fn verifySet(alloc: std.mem.Allocator, sources: []const []const u8, set_id: []const u8) ![64]u8 {
    try manifest.validateSetId(set_id);
    if (sources.len == 0 or sources.len > 64) return error.InvalidBackupSet;
    var expected_voters: ?[]u8 = null;
    defer if (expected_voters) |voters| alloc.free(voters);
    var expected_fingerprint: [64]u8 = undefined;
    var members: [64]u64 = undefined;
    for (sources, 0..) |source, i| {
        const dir = try files.openDir(source);
        defer dir.close(io);
        const description = try manifest.read(alloc, dir);
        defer description.deinit();
        if (!std.mem.eql(u8, description.value.set_id, set_id)) return error.BackupSetMismatch;
        if (i == 0) {
            expected_voters = try alloc.dupe(u8, description.value.voters);
            @memcpy(&expected_fingerprint, description.value.cluster_fingerprint);
        } else if (!std.mem.eql(u8, expected_voters.?, description.value.voters) or !std.mem.eql(u8, &expected_fingerprint, description.value.cluster_fingerprint)) return error.BackupSetMismatch;
        const boundary = try verify(alloc, source);
        defer boundary.deinit(alloc);
        for (members[0..i]) |previous| if (previous == boundary.node_id) return error.DuplicateVoter;
        members[i] = boundary.node_id;
    }
    var voters = std.mem.tokenizeScalar(u8, expected_voters.?, ',');
    var count: usize = 0;
    while (voters.next()) |_| count += 1;
    if (count != sources.len) return error.MissingVoter;
    return expected_fingerprint;
}
