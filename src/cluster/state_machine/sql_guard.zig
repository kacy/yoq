const std = @import("std");

pub fn isAllowedStatement(sql: []const u8) bool {
    var scanner = SqlStatementScanner{ .sql = sql };
    var saw_statement = false;

    while (scanner.next()) |statement| {
        saw_statement = true;
        if (!isAllowedSingleStatement(statement)) return false;
    }

    return saw_statement and scanner.isValid();
}

fn isAllowedSingleStatement(sql: []const u8) bool {
    const allowed_prefixes = [_][]const u8{
        "INSERT INTO agents ",
        "UPDATE agents SET ",
        "DELETE FROM agents ",
        "INSERT INTO assignments ",
        "UPDATE assignments SET ",
        "DELETE FROM assignments ",
        "INSERT INTO wireguard_peers ",
        "UPDATE wireguard_peers SET ",
        "DELETE FROM wireguard_peers ",
        "INSERT INTO volumes ",
        "UPDATE volumes SET ",
        "DELETE FROM volumes ",
        "INSERT INTO s3_multipart_uploads ",
        "UPDATE s3_multipart_uploads SET ",
        "DELETE FROM s3_multipart_uploads ",
        "INSERT INTO s3_upload_parts ",
        "DELETE FROM s3_upload_parts ",
        "CREATE TABLE IF NOT EXISTS ",
        "CREATE INDEX IF NOT EXISTS ",
    };

    for (allowed_prefixes) |prefix| {
        if (sql.len >= prefix.len and std.mem.eql(u8, sql[0..prefix.len], prefix)) {
            return true;
        }
    }

    return false;
}

const SqlStatementScanner = struct {
    sql: []const u8,
    pos: usize = 0,
    valid: bool = true,

    fn next(self: *SqlStatementScanner) ?[]const u8 {
        while (self.pos < self.sql.len and std.ascii.isWhitespace(self.sql[self.pos])) {
            self.pos += 1;
        }
        if (self.pos >= self.sql.len or !self.valid) return null;

        const start = self.pos;
        var in_quote = false;

        while (self.pos < self.sql.len) : (self.pos += 1) {
            const ch = self.sql[self.pos];
            if (ch == '\'') {
                if (in_quote and self.pos + 1 < self.sql.len and self.sql[self.pos + 1] == '\'') {
                    self.pos += 1;
                    continue;
                }
                in_quote = !in_quote;
                continue;
            }

            if (!in_quote and ch == ';') {
                const statement = std.mem.trim(u8, self.sql[start..self.pos], " \t\r\n");
                self.pos += 1;
                return if (statement.len == 0) self.next() else statement;
            }
        }

        if (in_quote) {
            self.valid = false;
            return null;
        }

        const statement = std.mem.trim(u8, self.sql[start..self.pos], " \t\r\n");
        return if (statement.len == 0) null else statement;
    }

    fn isValid(self: *const SqlStatementScanner) bool {
        return self.valid;
    }
};
