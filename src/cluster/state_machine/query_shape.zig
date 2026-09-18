// replicated sql supports the query forms emitted by the control plane.
// sqlite permits unordered scalar reads and correlated updates whose results
// depend on scan order, so arbitrary subqueries are not safe raft commands.
const std = @import("std");

pub fn allowed(statement: []const u8) bool {
    if (matches(statement, cleanup) or matches(statement, allocate_node) or matches(statement, insert_peer) or matches(statement, refresh_peer)) return true;
    var tokens = Tokens{ .input = statement };
    var previous: []const u8 = "";
    while (tokens.next()) |token| {
        defer previous = token.text;
        if (token.quoted) continue;
        if (keyword(token.text, "FROM") and !keyword(previous, "DELETE")) return false;
        if (keyword(token.text, "SELECT")) {
            // the metadata table has exactly one immutable identity. commands
            // may read its apply position, but the authorizer forbids writes.
            if (!consume(&tokens, "last_applied FROM state_machine_meta WHERE id = 1 )")) return false;
        }
        for ([_][]const u8{ "LIMIT", "OFFSET", "ORDER", "GROUP", "WINDOW", "OVER", "RETURNING" }) |word| {
            if (keyword(token.text, word)) return false;
        }
    }
    return true;
}

pub fn isBarrier(statement: []const u8) bool {
    return matches(statement, "UPDATE agents SET id = id WHERE 0");
}

const refresh_peer = "UPDATE wireguard_peers SET endpoint = $string WHERE agent_id = $string AND EXISTS ( SELECT 1 FROM agents WHERE id = $string AND credential_hash = $string AND wg_public_key = $string )";
const cleanup = "DELETE FROM assignment_claims WHERE assignment_id NOT IN ( SELECT id FROM assignments )";
const allocate_node =
    "UPDATE agents SET node_id = ( " ++
    "SELECT MIN ( candidate ) FROM ( " ++
    "SELECT id + 1 AS candidate FROM ( $reserved ) UNION SELECT node_id + 1 FROM agents WHERE node_id IS NOT NULL " ++
    "UNION SELECT node_id + 1 FROM wireguard_peers " ++
    ") WHERE candidate BETWEEN 1 AND 54783 " ++
    "AND candidate NOT IN ( SELECT node_id FROM agents WHERE node_id IS NOT NULL ) " ++
    "AND candidate NOT IN ( SELECT node_id FROM wireguard_peers ) " ++
    "AND candidate NOT IN ( $reserved ) " ++
    ") WHERE id = $string";
const insert_peer =
    "INSERT INTO wireguard_peers ( node_id , agent_id , public_key , endpoint , overlay_ip , container_subnet ) " ++
    "SELECT node_id , id , wg_public_key , $string , overlay_ip , " ++
    "printf ( $string , 42 + ( node_id > > 8 ) , node_id & 255 ) " ++
    "FROM agents WHERE id = $string";

fn matches(statement: []const u8, pattern: []const u8) bool {
    var tokens = Tokens{ .input = statement };
    return consume(&tokens, pattern) and tokens.next() == null;
}

fn consume(tokens: *Tokens, pattern: []const u8) bool {
    var expected = Tokens{ .input = pattern };
    while (expected.next()) |want| {
        if (std.mem.eql(u8, want.text, "$reserved")) {
            if (!consume(tokens, "SELECT 0 AS id")) return false;
            while (true) {
                const saved = tokens.*;
                const next = tokens.next() orelse return false;
                if (!keyword(next.text, "UNION")) {
                    tokens.* = saved;
                    break;
                }
                if (!consume(tokens, "SELECT")) return false;
                const number = tokens.next() orelse return false;
                if (number.quoted or number.text.len == 0) return false;
                for (number.text) |ch| if (!std.ascii.isDigit(ch)) return false;
            }
            continue;
        }
        const actual = tokens.next() orelse return false;
        if (std.mem.eql(u8, want.text, "$string")) {
            if (!actual.quoted) return false;
        } else if (actual.quoted or !keyword(actual.text, want.text)) return false;
    }
    return true;
}

fn keyword(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

const Token = struct { text: []const u8, quoted: bool = false };
const Tokens = struct {
    input: []const u8,
    offset: usize = 0,

    fn next(self: *Tokens) ?Token {
        while (self.offset < self.input.len and std.ascii.isWhitespace(self.input[self.offset])) self.offset += 1;
        if (self.offset == self.input.len) return null;
        const start = self.offset;
        const quoted = self.input[start] == '\'';
        self.offset += 1;
        if (quoted) {
            while (self.offset < self.input.len) : (self.offset += 1) {
                if (self.input[self.offset] != '\'') continue;
                self.offset += 1;
                if (self.offset < self.input.len and self.input[self.offset] == '\'') continue;
                break;
            }
        } else if (word(self.input[start])) {
            while (self.offset < self.input.len and word(self.input[self.offset])) self.offset += 1;
        }
        return .{ .text = self.input[start..self.offset], .quoted = quoted };
    }

    fn word(ch: u8) bool {
        return std.ascii.isAlphanumeric(ch) or ch == '_' or ch == '$';
    }
};
