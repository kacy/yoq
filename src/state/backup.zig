// backup — SQLite online backup and restore for yoq state
//
// uses the SQLite Online Backup API (sqlite3_backup_init/step/finish) to make
// consistent snapshots of the yoq database while the server may still be
// running. by default the artifact is encrypted at rest with the secrets-store
// key and carries a SHA256 of the plaintext database, so a tampered or
// truncated backup is rejected on restore. restores validate the schema before
// replacing the active database.
//
// only metadata is backed up — volume data (which can be very large) is NOT
// included.
//
// artifact format (encrypted): an 8-byte magic, the 32-byte SHA256 of the
// plaintext database, a 24-byte nonce, a 16-byte tag, then the ciphertext.
// a raw SQLite file (no magic) is still accepted on restore for backward
// compatibility and via `backup --plain`.

const std = @import("std");
const sqlite = @import("sqlite");
const schema = @import("schema.zig");
const paths = @import("../lib/paths.zig");
const secrets = @import("secrets.zig");

const c = sqlite.c;
const io = std.Options.debug_io;

/// magic prefix identifying an encrypted yoq backup artifact.
const magic = "YOQBKP1\n";
const sha_len = 32;
const header_len = magic.len + sha_len + secrets.nonce_length + secrets.tag_length;
/// generous cap so a corrupt or hostile file cannot exhaust memory. the
/// metadata database is small (well under this).
const max_backup_bytes = 512 * 1024 * 1024;

pub const BackupError = error{
    DbOpenFailed,
    BackupFailed,
    RestoreFailed,
    PathError,
    ServerRunning,
    SchemaValidationFailed,
    IntegrityCheckFailed,
    KeyUnavailable,
    IoFailed,
    OutOfMemory,
};

/// create a backup of the yoq database at output_path. encrypted and
/// checksummed by default; pass encrypt_artifact=false for a raw SQLite copy.
/// safe to call while the server is running — uses SQLite online backup.
pub fn backup(alloc: std.mem.Allocator, output_path: [:0]const u8, encrypt_artifact: bool) BackupError!void {
    if (!encrypt_artifact) return snapshotDbTo(output_path);

    // snapshot to a temp file, then encrypt it into the final artifact.
    const tmp_path = std.fmt.allocPrintSentinel(alloc, "{s}.tmp", .{output_path}, 0) catch return BackupError.OutOfMemory;
    defer alloc.free(tmp_path);

    try snapshotDbTo(tmp_path);
    defer deleteFileQuiet(tmp_path);

    const plaintext = readWholeFile(alloc, tmp_path) catch return BackupError.IoFailed;
    defer alloc.free(plaintext);

    var digest: [sha_len]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(plaintext, &digest, .{});

    const key = secrets.loadOrCreateKey() catch return BackupError.KeyUnavailable;
    const artifact = try encodeArtifact(alloc, plaintext, key);
    defer alloc.free(artifact);

    writeFileBytes(output_path, artifact) catch return BackupError.IoFailed;
}

/// build an encrypted, checksummed backup artifact from a plaintext database.
/// layout: magic ++ sha256(plaintext) ++ nonce ++ tag ++ ciphertext.
fn encodeArtifact(alloc: std.mem.Allocator, plaintext: []const u8, key: [secrets.key_length]u8) BackupError![]u8 {
    var digest: [sha_len]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(plaintext, &digest, .{});

    var enc = secrets.encrypt(alloc, plaintext, key) catch return BackupError.OutOfMemory;
    defer alloc.free(enc.ciphertext);

    const artifact = alloc.alloc(u8, header_len + enc.ciphertext.len) catch return BackupError.OutOfMemory;
    @memcpy(artifact[0..magic.len], magic);
    @memcpy(artifact[magic.len..][0..sha_len], &digest);
    @memcpy(artifact[magic.len + sha_len ..][0..secrets.nonce_length], &enc.nonce);
    @memcpy(artifact[magic.len + sha_len + secrets.nonce_length ..][0..secrets.tag_length], &enc.tag);
    @memcpy(artifact[header_len..], enc.ciphertext);
    return artifact;
}

/// decrypt and integrity-check an encrypted artifact, returning the plaintext
/// database. caller owns the returned slice. fails closed on any mismatch.
fn decodeArtifact(alloc: std.mem.Allocator, artifact: []const u8, key: [secrets.key_length]u8) BackupError![]u8 {
    if (artifact.len < header_len or !std.mem.startsWith(u8, artifact, magic)) {
        return BackupError.IntegrityCheckFailed;
    }
    const stored_sha = artifact[magic.len..][0..sha_len];
    var nonce: [secrets.nonce_length]u8 = undefined;
    var tag: [secrets.tag_length]u8 = undefined;
    @memcpy(&nonce, artifact[magic.len + sha_len ..][0..secrets.nonce_length]);
    @memcpy(&tag, artifact[magic.len + sha_len + secrets.nonce_length ..][0..secrets.tag_length]);
    const ciphertext = artifact[header_len..];

    const plaintext = secrets.decrypt(alloc, ciphertext, nonce, tag, key) catch return BackupError.IntegrityCheckFailed;
    errdefer alloc.free(plaintext);

    var digest: [sha_len]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(plaintext, &digest, .{});
    if (!std.mem.eql(u8, &digest, stored_sha)) return BackupError.IntegrityCheckFailed;
    return plaintext;
}

/// restore a backup to the yoq data directory, decrypting and verifying its
/// checksum first when the artifact is encrypted. validates the schema before
/// replacing the active database. with verify_only=true, performs every check
/// but does not touch the live database.
pub fn restore(alloc: std.mem.Allocator, input_path: [:0]const u8, verify_only: bool) BackupError!void {
    const contents = readWholeFile(alloc, input_path) catch return BackupError.RestoreFailed;
    defer alloc.free(contents);

    // raw SQLite file (legacy / --plain): no magic header.
    if (!std.mem.startsWith(u8, contents, magic)) {
        if (verify_only) return validateDbFile(input_path);
        return restoreDbFrom(input_path);
    }

    const key = secrets.loadOrCreateKey() catch return BackupError.KeyUnavailable;
    const plaintext = try decodeArtifact(alloc, contents, key);
    defer alloc.free(plaintext);

    // materialize the decrypted database to a temp file for SQLite to read.
    const tmp_path = std.fmt.allocPrintSentinel(alloc, "{s}.restore.tmp", .{input_path}, 0) catch return BackupError.OutOfMemory;
    defer alloc.free(tmp_path);
    writeFileBytes(tmp_path, plaintext) catch return BackupError.IoFailed;
    defer deleteFileQuiet(tmp_path);

    if (verify_only) return validateDbFile(tmp_path);
    return restoreDbFrom(tmp_path);
}

// -- internal sqlite helpers --

/// online-backup the live database into dest_path (a fresh SQLite file).
fn snapshotDbTo(output_path: [:0]const u8) BackupError!void {
    var src_path_buf: [paths.max_path]u8 = undefined;
    const src_path = schema.defaultDbPath(&src_path_buf) catch return BackupError.PathError;

    var src_db: ?*c.sqlite3 = null;
    if (c.sqlite3_open(src_path.ptr, &src_db) != c.SQLITE_OK or src_db == null) {
        if (src_db) |db| _ = c.sqlite3_close(db);
        return BackupError.DbOpenFailed;
    }
    defer _ = c.sqlite3_close(src_db);

    var dest_db: ?*c.sqlite3 = null;
    if (c.sqlite3_open(output_path.ptr, &dest_db) != c.SQLITE_OK or dest_db == null) {
        if (dest_db) |db| _ = c.sqlite3_close(db);
        return BackupError.BackupFailed;
    }
    defer _ = c.sqlite3_close(dest_db);

    const bk = c.sqlite3_backup_init(dest_db, "main", src_db, "main");
    if (bk == null) return BackupError.BackupFailed;

    const step_rc = c.sqlite3_backup_step(bk, -1);
    const finish_rc = c.sqlite3_backup_finish(bk);

    if (step_rc != c.SQLITE_DONE) return BackupError.BackupFailed;
    if (finish_rc != c.SQLITE_OK) return BackupError.BackupFailed;
}

/// validate and restore a SQLite file at src_path into the live database.
fn restoreDbFrom(input_path: [:0]const u8) BackupError!void {
    var dest_path_buf: [paths.max_path]u8 = undefined;
    const dest_path = schema.defaultDbPath(&dest_path_buf) catch return BackupError.PathError;

    var src_db: ?*c.sqlite3 = null;
    if (c.sqlite3_open_v2(input_path.ptr, &src_db, c.SQLITE_OPEN_READONLY, null) != c.SQLITE_OK or src_db == null) {
        if (src_db) |db| _ = c.sqlite3_close(db);
        return BackupError.RestoreFailed;
    }
    defer _ = c.sqlite3_close(src_db);
    try validateBackupSchema(src_db.?);

    var dest_db: ?*c.sqlite3 = null;
    if (c.sqlite3_open_v2(dest_path.ptr, &dest_db, c.SQLITE_OPEN_READWRITE | c.SQLITE_OPEN_CREATE, null) != c.SQLITE_OK or dest_db == null) {
        if (dest_db) |db| _ = c.sqlite3_close(db);
        return BackupError.RestoreFailed;
    }
    defer _ = c.sqlite3_close(dest_db);
    try beginExclusiveRestore(dest_db.?);
    var transaction_open = true;
    defer {
        if (transaction_open) _ = c.sqlite3_exec(dest_db, "ROLLBACK;", null, null, null);
    }

    const bk = c.sqlite3_backup_init(dest_db, "main", src_db, "main");
    if (bk == null) return BackupError.RestoreFailed;

    const step_rc = c.sqlite3_backup_step(bk, -1);
    const finish_rc = c.sqlite3_backup_finish(bk);

    if (step_rc != c.SQLITE_DONE) return BackupError.RestoreFailed;
    if (finish_rc != c.SQLITE_OK) return BackupError.RestoreFailed;
    if (c.sqlite3_exec(dest_db, "COMMIT;", null, null, null) != c.SQLITE_OK) {
        return BackupError.RestoreFailed;
    }
    transaction_open = false;
}

/// open a SQLite file read-only and validate its schema without restoring.
fn validateDbFile(path: [:0]const u8) BackupError!void {
    var db: ?*c.sqlite3 = null;
    if (c.sqlite3_open_v2(path.ptr, &db, c.SQLITE_OPEN_READONLY, null) != c.SQLITE_OK or db == null) {
        if (db) |handle| _ = c.sqlite3_close(handle);
        return BackupError.RestoreFailed;
    }
    defer _ = c.sqlite3_close(db);
    try validateBackupSchema(db.?);
}

fn beginExclusiveRestore(db: *c.sqlite3) BackupError!void {
    _ = c.sqlite3_busy_timeout(db, 0);
    if (c.sqlite3_exec(db, "PRAGMA locking_mode=EXCLUSIVE;", null, null, null) != c.SQLITE_OK) {
        return BackupError.RestoreFailed;
    }
    const rc = c.sqlite3_exec(db, "BEGIN IMMEDIATE;", null, null, null);
    if (rc == c.SQLITE_BUSY or rc == c.SQLITE_LOCKED) return BackupError.ServerRunning;
    if (rc != c.SQLITE_OK) return BackupError.RestoreFailed;
}

fn validateBackupSchema(db: *c.sqlite3) BackupError!void {
    const required_tables_sql =
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN (" ++
        "'containers','images','ip_allocations','build_cache','service_names','services','service_endpoints'," ++
        "'agents','assignments','deployments','secrets','network_policies'," ++
        "'wireguard_peers','volumes','certificates','s3_multipart_uploads'," ++
        "'s3_upload_parts','training_jobs','training_checkpoints','audit_log','tokens'" ++
        ");";
    const required_table_count = 21;

    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, required_tables_sql, @intCast(required_tables_sql.len), &stmt, null) != c.SQLITE_OK) {
        return BackupError.SchemaValidationFailed;
    }
    defer _ = c.sqlite3_finalize(stmt);
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return BackupError.SchemaValidationFailed;
    if (c.sqlite3_column_int(stmt, 0) != required_table_count) return BackupError.SchemaValidationFailed;

    var integrity_stmt: ?*c.sqlite3_stmt = null;
    const integrity_sql = "PRAGMA integrity_check;";
    if (c.sqlite3_prepare_v2(db, integrity_sql, @intCast(integrity_sql.len), &integrity_stmt, null) != c.SQLITE_OK) {
        return BackupError.SchemaValidationFailed;
    }
    defer _ = c.sqlite3_finalize(integrity_stmt);
    if (c.sqlite3_step(integrity_stmt) != c.SQLITE_ROW) return BackupError.SchemaValidationFailed;
    const result = c.sqlite3_column_text(integrity_stmt, 0) orelse return BackupError.SchemaValidationFailed;
    const text = std.mem.span(@as([*:0]const u8, @ptrCast(result)));
    if (!std.mem.eql(u8, text, "ok")) return BackupError.SchemaValidationFailed;
}

// -- file helpers --

fn readWholeFile(alloc: std.mem.Allocator, path: [:0]const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .limited(max_backup_bytes));
}

fn writeFileBytes(path: [:0]const u8, bytes: []const u8) !void {
    const file = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true, .permissions = @enumFromInt(0o600) });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
}

fn deleteFileQuiet(path: [:0]const u8) void {
    std.Io.Dir.cwd().deleteFile(io, path) catch {};
}

// -- tests --

test "backup error types compile" {
    try std.testing.expect(@TypeOf(backup) == fn (std.mem.Allocator, [:0]const u8, bool) BackupError!void);
    try std.testing.expect(@TypeOf(restore) == fn (std.mem.Allocator, [:0]const u8, bool) BackupError!void);
}

test "validateBackupSchema rejects incomplete database" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var tmp_path_buf: [paths.max_path]u8 = undefined;
    const path_len = try tmp.dir.realPathFile(std.testing.io, ".", &tmp_path_buf);
    const path = tmp_path_buf[0..path_len];

    var path_buf: [paths.max_path]u8 = undefined;
    const db_path = try std.fmt.bufPrintZ(&path_buf, "{s}/bad.db", .{path});

    var db: ?*c.sqlite3 = null;
    try std.testing.expectEqual(@as(c_int, c.SQLITE_OK), c.sqlite3_open(db_path.ptr, &db));
    defer _ = c.sqlite3_close(db);
    _ = c.sqlite3_exec(db, "CREATE TABLE containers (id TEXT);", null, null, null);

    try std.testing.expectError(BackupError.SchemaValidationFailed, validateBackupSchema(db.?));
}

test "artifact encode/decode round-trips the plaintext" {
    const alloc = std.testing.allocator;
    const key = [_]u8{7} ** secrets.key_length;
    const plaintext = "SQLite format 3\x00 ... pretend database bytes ...";

    const artifact = try encodeArtifact(alloc, plaintext, key);
    defer alloc.free(artifact);
    try std.testing.expect(std.mem.startsWith(u8, artifact, magic));

    const decoded = try decodeArtifact(alloc, artifact, key);
    defer alloc.free(decoded);
    try std.testing.expectEqualStrings(plaintext, decoded);
}

test "decodeArtifact rejects a tampered checksum, body, and wrong key" {
    const alloc = std.testing.allocator;
    const key = [_]u8{7} ** secrets.key_length;
    const plaintext = "pretend database bytes";

    const artifact = try encodeArtifact(alloc, plaintext, key);
    defer alloc.free(artifact);

    // flip a byte in the stored sha256 → checksum mismatch.
    {
        const tampered = try alloc.dupe(u8, artifact);
        defer alloc.free(tampered);
        tampered[magic.len] ^= 0xff;
        try std.testing.expectError(BackupError.IntegrityCheckFailed, decodeArtifact(alloc, tampered, key));
    }

    // flip a byte in the ciphertext → AEAD auth fails.
    {
        const tampered = try alloc.dupe(u8, artifact);
        defer alloc.free(tampered);
        tampered[tampered.len - 1] ^= 0xff;
        try std.testing.expectError(BackupError.IntegrityCheckFailed, decodeArtifact(alloc, tampered, key));
    }

    // wrong key → AEAD auth fails.
    {
        const wrong_key = [_]u8{9} ** secrets.key_length;
        try std.testing.expectError(BackupError.IntegrityCheckFailed, decodeArtifact(alloc, artifact, wrong_key));
    }
}

test "decodeArtifact rejects a too-short or unmagicked buffer" {
    const alloc = std.testing.allocator;
    const key = [_]u8{7} ** secrets.key_length;
    try std.testing.expectError(BackupError.IntegrityCheckFailed, decodeArtifact(alloc, magic ++ "tooshort", key));
    try std.testing.expectError(BackupError.IntegrityCheckFailed, decodeArtifact(alloc, "not a backup at all", key));
}
