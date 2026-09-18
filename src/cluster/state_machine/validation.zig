// prepare against a private, empty copy of the supported schema. validation
// never depends on a replica's rows, temporary tables, or connection history.
const std = @import("std");
const sqlite = @import("sqlite");
const schema = @import("../../state/schema.zig");
const db_runtime = @import("db_runtime.zig");
const sql_guard = @import("sql_guard.zig");
const c = sqlite.c;

pub const Error = error{ InvalidCommand, ValidationUnavailable };

pub const Validator = struct {
    db: sqlite.Db,

    pub fn init() !Validator {
        var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
        errdefer db.deinit();
        try schema.init(&db);
        try db_runtime.initMeta(&db);
        try db_runtime.execStatement(&db, @import("../placement_transaction.zig").schema_sql, .{});
        return .{ .db = db };
    }

    pub fn deinit(self: *Validator) void {
        self.db.deinit();
    }

    pub fn validate(self: *Validator, sql: []const u8) Error!void {
        if (!sql_guard.isAllowedStatement(sql)) return error.InvalidCommand;
        var context: Authorization = .{};
        if (c.sqlite3_set_authorizer(self.db.db, authorize, &context) != c.SQLITE_OK) return error.ValidationUnavailable;
        defer _ = c.sqlite3_set_authorizer(self.db.db, null, null);

        var statements = sql_guard.StatementIterator{ .sql = sql };
        while (statements.next()) |statement| {
            context.ddl = std.mem.startsWith(u8, statement, "CREATE ");
            var prepared: ?*c.sqlite3_stmt = null;
            defer {
                if (prepared) |handle| _ = c.sqlite3_finalize(handle);
            }
            var tail: [*c]const u8 = null;
            const size = std.math.cast(c_int, statement.len) orelse return error.InvalidCommand;
            const result = c.sqlite3_prepare_v2(self.db.db, statement.ptr, size, &prepared, &tail);
            if (result != c.SQLITE_OK) {
                // only errors determined by these bytes and the fixed schema
                // are permanent. allocation and other local failures must retry.
                return switch (result) {
                    c.SQLITE_ERROR, c.SQLITE_AUTH, c.SQLITE_TOOBIG => error.InvalidCommand,
                    else => error.ValidationUnavailable,
                };
            }
            const handle = prepared orelse return error.InvalidCommand;
            if (c.sqlite3_bind_parameter_count(handle) != 0) return error.InvalidCommand;
            if (tail != statement.ptr + statement.len) return error.InvalidCommand;
        }
    }
};

const Authorization = struct { ddl: bool = false };

fn replicatedTable(name: []const u8) bool {
    const tables = [_][]const u8{
        "training_jobs",        "assignment_claims", "deployments",     "cron_schedules",
        "agents",               "assignments",       "wireguard_peers", "volumes",
        "s3_multipart_uploads", "s3_upload_parts",   "services",        "service_endpoints",
        "cluster_ca",           "certificates",
    };
    for (tables) |table| if (std.mem.eql(u8, name, table)) return true;
    return false;
}

fn deterministicFunction(name: []const u8) bool {
    // keep this list limited to functions used by replicated mutations.
    // date/time, random, changes and version functions depend on the node.
    const functions = [_][]const u8{ "coalesce", "ifnull", "nullif", "min", "max", "sum", "count", "printf" };
    for (functions) |function| if (std.ascii.eqlIgnoreCase(name, function)) return true;
    return false;
}

fn text(value: [*c]const u8) []const u8 {
    return if (value == null) "" else std.mem.span(value);
}

fn authorize(raw: ?*anyopaque, action: c_int, first: [*c]const u8, second: [*c]const u8, database: [*c]const u8, trigger: [*c]const u8) callconv(.c) c_int {
    const context: *const Authorization = @ptrCast(@alignCast(raw.?));
    if (trigger != null) return c.SQLITE_DENY;
    if (database != null and !std.mem.eql(u8, text(database), "main")) return c.SQLITE_DENY;
    const table = text(first);
    const permitted = switch (action) {
        c.SQLITE_SELECT => true,
        c.SQLITE_FUNCTION => deterministicFunction(text(second)),
        c.SQLITE_READ => replicatedTable(table) or std.mem.eql(u8, table, "state_machine_meta") or
            (context.ddl and std.mem.eql(u8, table, "sqlite_master")),
        c.SQLITE_INSERT, c.SQLITE_UPDATE, c.SQLITE_DELETE => replicatedTable(table) or
            (context.ddl and std.mem.eql(u8, table, "sqlite_master")),
        c.SQLITE_CREATE_TABLE => context.ddl and replicatedTable(table),
        c.SQLITE_CREATE_INDEX => context.ddl and replicatedTable(text(second)),
        // creating an index also authorizes its initial rebuild. its table
        // and expressions were checked by the callbacks above.
        c.SQLITE_REINDEX => context.ddl,
        else => false,
    };
    return if (permitted) c.SQLITE_OK else c.SQLITE_DENY;
}
