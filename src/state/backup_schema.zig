//! compare a migrated restore candidate with a freshly initialized schema.
//! column order can differ after additive migrations; names and constraints
//! must still agree before the candidate replaces a working database.
const std = @import("std");
const sqlite = @import("sqlite");
const schema = @import("schema.zig");
const c = sqlite.c;
const log = @import("../lib/log.zig");

const Error = error{SchemaValidationFailed};

pub fn validate(candidate: *c.sqlite3) Error!void {
    var expected = sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } }) catch return error.SchemaValidationFailed;
    defer expected.deinit();
    schema.init(&expected) catch return error.SchemaValidationFailed;
    try compareRows(expected.db, candidate, "PRAGMA user_version;", null);

    const tables = try prepare(expected.db, "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;", null);
    defer _ = c.sqlite3_finalize(tables);
    while (true) {
        const result = c.sqlite3_step(tables);
        if (result == c.SQLITE_DONE) break;
        if (result != c.SQLITE_ROW) return error.SchemaValidationFailed;
        const table = columnText(tables, 0);
        try compareRows(
            expected.db,
            candidate,
            "SELECT name, upper(type), \"notnull\", dflt_value, pk, hidden FROM pragma_table_xinfo(?) ORDER BY name;",
            table,
        );
        try compareRows(
            expected.db,
            candidate,
            "SELECT p.name, p.origin, p.partial, x.seqno, x.name, x.desc, x.coll " ++
                "FROM pragma_index_list(?) p JOIN pragma_index_xinfo(p.name) x " ++
                "WHERE p.\"unique\"=1 AND x.key=1 ORDER BY p.name, x.seqno;",
            table,
        );
        try compareRows(
            expected.db,
            candidate,
            "SELECT seq, \"table\", \"from\", \"to\", on_update, on_delete, match " ++
                "FROM pragma_foreign_key_list(?) ORDER BY \"table\", \"from\", seq;",
            table,
        );
        // sqlite does not expose check expressions through a pragma. these
        // tables have no legacy column-order variants, so compare their ddl.
        const definition = columnText(tables, 1);
        if (std.ascii.indexOfIgnoreCase(definition, "CHECK") != null) {
            const actual = try prepare(candidate, "SELECT sql FROM sqlite_master WHERE type='table' AND name=?;", table);
            defer _ = c.sqlite3_finalize(actual);
            if (c.sqlite3_step(actual) != c.SQLITE_ROW or !sameDefinition(definition, columnText(actual, 0))) {
                log.warn("backup: incompatible check constraints in {s}", .{table});
                return error.SchemaValidationFailed;
            }
        }
    }
    try compareRows(expected.db, candidate, "SELECT name, tbl_name, sql FROM sqlite_master WHERE type='trigger' ORDER BY name;", null);
    const foreign_keys = try prepare(candidate, "PRAGMA foreign_key_check;", null);
    defer _ = c.sqlite3_finalize(foreign_keys);
    if (c.sqlite3_step(foreign_keys) != c.SQLITE_DONE) return error.SchemaValidationFailed;
}

/// reject unknown trigger behavior before migrations write candidate rows.
/// older backups may omit current triggers; initialization adds them later.
pub fn validateExistingTriggers(candidate: *c.sqlite3) Error!void {
    var expected = sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } }) catch return error.SchemaValidationFailed;
    defer expected.deinit();
    schema.init(&expected) catch return error.SchemaValidationFailed;
    const actual = try prepare(candidate, "SELECT name, sql FROM sqlite_master WHERE type='trigger';", null);
    defer _ = c.sqlite3_finalize(actual);
    while (true) {
        const result = c.sqlite3_step(actual);
        if (result == c.SQLITE_DONE) return;
        if (result != c.SQLITE_ROW) return error.SchemaValidationFailed;
        const known = try prepare(expected.db, "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?;", columnText(actual, 0));
        defer _ = c.sqlite3_finalize(known);
        if (c.sqlite3_step(known) != c.SQLITE_ROW or !sameDefinition(columnText(actual, 1), columnText(known, 0)))
            return error.SchemaValidationFailed;
    }
}

fn compareRows(expected: *c.sqlite3, actual: *c.sqlite3, query: [:0]const u8, table: ?[]const u8) Error!void {
    const left = try prepare(expected, query, table);
    defer _ = c.sqlite3_finalize(left);
    const right = try prepare(actual, query, table);
    defer _ = c.sqlite3_finalize(right);
    while (true) {
        const a = c.sqlite3_step(left);
        const b = c.sqlite3_step(right);
        if (a != b) {
            log.warn("backup: incompatible schema rows in {s}", .{table orelse "database"});
            return error.SchemaValidationFailed;
        }
        if (a == c.SQLITE_DONE) return;
        if (a != c.SQLITE_ROW) return error.SchemaValidationFailed;
        const columns = c.sqlite3_column_count(left);
        if (columns != c.sqlite3_column_count(right)) return error.SchemaValidationFailed;
        var column: c_int = 0;
        while (column < columns) : (column += 1) {
            if (c.sqlite3_column_type(left, column) != c.sqlite3_column_type(right, column) or
                !std.mem.eql(u8, columnText(left, column), columnText(right, column)))
            {
                log.warn("backup: incompatible schema metadata in {s} at field {d}", .{ table orelse "database", column });
                return error.SchemaValidationFailed;
            }
        }
    }
}

fn prepare(db: *c.sqlite3, query: [:0]const u8, table: ?[]const u8) Error!*c.sqlite3_stmt {
    var statement: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, query.ptr, -1, &statement, null) != c.SQLITE_OK or statement == null) {
        log.warn("backup: cannot inspect schema for {s}", .{table orelse "database"});
        return error.SchemaValidationFailed;
    }
    errdefer _ = c.sqlite3_finalize(statement);
    if (table) |name| {
        if (c.sqlite3_bind_text(statement, 1, name.ptr, @intCast(name.len), null) != c.SQLITE_OK)
            return error.SchemaValidationFailed;
    }
    return statement.?;
}

fn columnText(statement: *c.sqlite3_stmt, column: c_int) []const u8 {
    const text = c.sqlite3_column_text(statement, column) orelse return "";
    return text[0..@intCast(c.sqlite3_column_bytes(statement, column))];
}

fn sameDefinition(left: []const u8, right: []const u8) bool {
    var a: Definition = .{ .text = left };
    var b: Definition = .{ .text = right };
    while (true) {
        const next = a.next();
        if (next != b.next()) return false;
        if (next == null) return true;
    }
}

const Definition = struct {
    text: []const u8,
    position: usize = 0,
    quote: ?u8 = null,

    fn next(self: *Definition) ?u8 {
        while (self.position < self.text.len) {
            const byte = self.text[self.position];
            self.position += 1;
            if (self.quote) |quote| {
                if (byte == quote) self.quote = null;
                return byte;
            }
            if (byte == '\'' or byte == '"' or byte == '`') {
                self.quote = byte;
                return byte;
            }
            if (std.ascii.isWhitespace(byte)) continue;
            return std.ascii.toLower(byte);
        }
        return null;
    }
};
