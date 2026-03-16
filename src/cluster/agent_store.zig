// agent_store — local assignment cache for agent resilience
//
// caches assignment state in a local SQLite database so the agent
// can survive restarts and server disconnections. follows the same
// global-db pattern as state/store.zig.

const std = @import("std");
const sqlite = @import("sqlite");
const paths = @import("../lib/paths.zig");

const Allocator = std.mem.Allocator;

pub const CachedAssignment = struct {
    id: []const u8,
    image: []const u8,
    command: []const u8,
    status: []const u8,
    cpu_limit: i64,
    memory_limit_mb: i64,
    synced_at: i64,

    pub fn deinit(self: CachedAssignment, alloc: Allocator) void {
        alloc.free(self.id);
        alloc.free(self.image);
        alloc.free(self.command);
        alloc.free(self.status);
    }
};

var global_db: ?sqlite.Db = null;
var db_mutex: std.Thread.Mutex = .{};

const create_table_sql =
    \\CREATE TABLE IF NOT EXISTS cached_assignments (
    \\    id TEXT PRIMARY KEY,
    \\    image TEXT NOT NULL,
    \\    command TEXT NOT NULL DEFAULT '',
    \\    status TEXT NOT NULL DEFAULT 'pending',
    \\    cpu_limit INTEGER NOT NULL DEFAULT 1000,
    \\    memory_limit_mb INTEGER NOT NULL DEFAULT 256,
    \\    synced_at INTEGER NOT NULL
    \\);
;

/// initialize the agent cache database at data_dir/agent-cache.db.
/// creates the database file and schema if needed.
pub fn init(data_dir: []const u8) !void {
    var path_buf: [paths.max_path]u8 = undefined;
    const path_slice = std.fmt.bufPrint(&path_buf, "{s}/agent-cache.db", .{data_dir}) catch
        return error.PathTooLong;
    return initWithPath(path_slice);
}

/// initialize the agent cache database at a specific file path.
pub fn initWithPath(file_path: []const u8) !void {
    db_mutex.lock();
    defer db_mutex.unlock();

    if (global_db != null) return;

    // null-terminate for SQLite
    var path_buf: [paths.max_path]u8 = undefined;
    if (file_path.len >= path_buf.len) return error.PathTooLong;
    @memcpy(path_buf[0..file_path.len], file_path);
    path_buf[file_path.len] = 0;
    const path: [:0]const u8 = path_buf[0..file_path.len :0];

    var db = sqlite.Db.init(.{
        .mode = .{ .File = path },
        .open_flags = .{ .write = true, .create = true },
    }) catch return error.InitFailed;
    errdefer db.deinit();

    // create schema
    db.exec(create_table_sql, .{}, .{}) catch return error.InitFailed;

    // WAL mode for concurrent reads
    _ = sqlite.c.sqlite3_exec(db.db, "PRAGMA journal_mode=WAL;", null, null, null);
    _ = sqlite.c.sqlite3_exec(db.db, "PRAGMA synchronous=NORMAL;", null, null, null);
    _ = sqlite.c.sqlite3_exec(db.db, "PRAGMA busy_timeout=5000;", null, null, null);

    global_db = db;
}

/// initialize with an in-memory database for testing.
pub fn initTestDb() !void {
    db_mutex.lock();
    defer db_mutex.unlock();

    var db = sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{ .write = true },
    }) catch return error.InitFailed;

    db.exec(create_table_sql, .{}, .{}) catch return error.InitFailed;

    global_db = db;
}

fn getDb() !*sqlite.Db {
    return &(global_db orelse return error.NotInitialized);
}

/// insert or update a cached assignment.
pub fn upsertAssignment(assignment: CachedAssignment) !void {
    db_mutex.lock();
    defer db_mutex.unlock();

    const db = try getDb();
    db.exec(
        "INSERT OR REPLACE INTO cached_assignments (id, image, command, status, cpu_limit, memory_limit_mb, synced_at) VALUES (?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{
            assignment.id,
            assignment.image,
            assignment.command,
            assignment.status,
            assignment.cpu_limit,
            assignment.memory_limit_mb,
            assignment.synced_at,
        },
    ) catch return error.WriteFailed;
}

/// list all cached assignments.
pub fn listAssignments(alloc: Allocator) ![]CachedAssignment {
    return queryAssignments(
        alloc,
        "SELECT id, image, command, status, cpu_limit, memory_limit_mb, synced_at FROM cached_assignments;",
    );
}

/// list only pending cached assignments.
pub fn listPendingAssignments(alloc: Allocator) ![]CachedAssignment {
    return queryAssignments(
        alloc,
        "SELECT id, image, command, status, cpu_limit, memory_limit_mb, synced_at FROM cached_assignments WHERE status = 'pending';",
    );
}

fn queryAssignments(alloc: Allocator, comptime query: []const u8) ![]CachedAssignment {
    db_mutex.lock();
    defer db_mutex.unlock();

    const db = try getDb();

    const Row = struct {
        id: sqlite.Text,
        image: sqlite.Text,
        command: sqlite.Text,
        status: sqlite.Text,
        cpu_limit: i64,
        memory_limit_mb: i64,
        synced_at: i64,
    };

    var stmt = db.prepare(query) catch return error.QueryFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(Row, .{}) catch return error.QueryFailed;

    var results: std.ArrayListUnmanaged(CachedAssignment) = .empty;
    errdefer {
        for (results.items) |a| a.deinit(alloc);
        results.deinit(alloc);
    }

    while (iter.nextAlloc(alloc, .{}) catch null) |row| {
        try results.append(alloc, .{
            .id = row.id.data,
            .image = row.image.data,
            .command = row.command.data,
            .status = row.status.data,
            .cpu_limit = row.cpu_limit,
            .memory_limit_mb = row.memory_limit_mb,
            .synced_at = row.synced_at,
        });
    }

    return results.toOwnedSlice(alloc);
}

/// remove a cached assignment by ID.
pub fn removeAssignment(id: []const u8) !void {
    db_mutex.lock();
    defer db_mutex.unlock();

    const db = try getDb();
    db.exec(
        "DELETE FROM cached_assignments WHERE id = ?;",
        .{},
        .{id},
    ) catch return error.WriteFailed;
}

/// update the status of a cached assignment.
pub fn updateStatus(id: []const u8, status: []const u8) !void {
    db_mutex.lock();
    defer db_mutex.unlock();

    const db = try getDb();
    db.exec(
        "UPDATE cached_assignments SET status = ? WHERE id = ?;",
        .{},
        .{ status, id },
    ) catch return error.WriteFailed;
}

/// close the database connection.
pub fn closeDb() void {
    db_mutex.lock();
    defer db_mutex.unlock();

    if (global_db) |*db| {
        db.deinit();
        global_db = null;
    }
}

// -- tests --

test "agent_store init and upsert" {
    try initTestDb();
    defer closeDb();

    try upsertAssignment(.{
        .id = "assign001",
        .image = "nginx:latest",
        .command = "/bin/sh",
        .status = "pending",
        .cpu_limit = 1000,
        .memory_limit_mb = 256,
        .synced_at = 1000,
    });

    const alloc = std.testing.allocator;
    const assignments = try listAssignments(alloc);
    defer {
        for (assignments) |a| a.deinit(alloc);
        alloc.free(assignments);
    }

    try std.testing.expectEqual(@as(usize, 1), assignments.len);
    try std.testing.expectEqualStrings("assign001", assignments[0].id);
    try std.testing.expectEqualStrings("nginx:latest", assignments[0].image);
}

test "agent_store upsert deduplicates" {
    try initTestDb();
    defer closeDb();

    try upsertAssignment(.{
        .id = "assign001",
        .image = "nginx:latest",
        .command = "",
        .status = "pending",
        .cpu_limit = 1000,
        .memory_limit_mb = 256,
        .synced_at = 1000,
    });

    try upsertAssignment(.{
        .id = "assign001",
        .image = "nginx:latest",
        .command = "",
        .status = "running",
        .cpu_limit = 1000,
        .memory_limit_mb = 256,
        .synced_at = 2000,
    });

    const alloc = std.testing.allocator;
    const assignments = try listAssignments(alloc);
    defer {
        for (assignments) |a| a.deinit(alloc);
        alloc.free(assignments);
    }

    try std.testing.expectEqual(@as(usize, 1), assignments.len);
    try std.testing.expectEqualStrings("running", assignments[0].status);
}

test "agent_store remove" {
    try initTestDb();
    defer closeDb();

    try upsertAssignment(.{
        .id = "assign001",
        .image = "nginx:latest",
        .command = "",
        .status = "pending",
        .cpu_limit = 1000,
        .memory_limit_mb = 256,
        .synced_at = 1000,
    });

    try removeAssignment("assign001");

    const alloc = std.testing.allocator;
    const assignments = try listAssignments(alloc);
    defer {
        for (assignments) |a| a.deinit(alloc);
        alloc.free(assignments);
    }

    try std.testing.expectEqual(@as(usize, 0), assignments.len);
}

test "agent_store update status" {
    try initTestDb();
    defer closeDb();

    try upsertAssignment(.{
        .id = "assign001",
        .image = "nginx:latest",
        .command = "",
        .status = "pending",
        .cpu_limit = 1000,
        .memory_limit_mb = 256,
        .synced_at = 1000,
    });

    try updateStatus("assign001", "running");

    const alloc = std.testing.allocator;
    const assignments = try listAssignments(alloc);
    defer {
        for (assignments) |a| a.deinit(alloc);
        alloc.free(assignments);
    }

    try std.testing.expectEqual(@as(usize, 1), assignments.len);
    try std.testing.expectEqualStrings("running", assignments[0].status);
}

test "agent_store list empty" {
    try initTestDb();
    defer closeDb();

    const alloc = std.testing.allocator;
    const assignments = try listAssignments(alloc);
    defer alloc.free(assignments);

    try std.testing.expectEqual(@as(usize, 0), assignments.len);
}
