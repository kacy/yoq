const sqlite = @import("sqlite");

pub fn initSchema(db: *sqlite.Db) !void {
    db.exec(
        \\CREATE TABLE IF NOT EXISTS raft_state (
        \\    id INTEGER PRIMARY KEY CHECK (id = 1),
        \\    current_term INTEGER NOT NULL DEFAULT 0,
        \\    voted_for INTEGER
        \\);
    , .{}, .{}) catch return error.InitFailed;

    db.exec(
        "INSERT OR IGNORE INTO raft_state (id, current_term) VALUES (1, 0);",
        .{},
        .{},
    ) catch return error.InitFailed;

    db.exec(
        \\CREATE TABLE IF NOT EXISTS raft_log (
        \\    log_index INTEGER PRIMARY KEY,
        \\    term INTEGER NOT NULL,
        \\    data BLOB NOT NULL
        \\);
    , .{}, .{}) catch return error.InitFailed;

    db.exec(
        \\CREATE TABLE IF NOT EXISTS snapshot_meta (
        \\    id INTEGER PRIMARY KEY CHECK (id = 1),
        \\    last_included_index INTEGER NOT NULL DEFAULT 0,
        \\    last_included_term INTEGER NOT NULL DEFAULT 0,
        \\    data_len INTEGER NOT NULL DEFAULT 0
        \\);
    , .{}, .{}) catch return error.InitFailed;

    db.exec(
        "INSERT OR IGNORE INTO snapshot_meta (id) VALUES (1);",
        .{},
        .{},
    ) catch return error.InitFailed;
}
