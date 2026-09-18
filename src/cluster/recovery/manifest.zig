const std = @import("std");
const files = @import("files.zig");
const databases = @import("databases.zig");

pub const Entry = struct {
    name: []const u8,
    size: u64,
    sha256: []const u8,
};

pub const Manifest = struct {
    format: u32 = 1,
    set_id: []const u8,
    cluster_fingerprint: []const u8,
    node_id: u64,
    voters: []const u8,
    current_term: u64,
    last_applied: u64,
    last_log_index: u64,
    snapshot_index: u64,
    snapshot_term: u64,
    snapshot_size: u64,
    files: []const Entry,

    pub fn fromBoundary(boundary: databases.Boundary, entries: []const Entry, set_id: []const u8, fingerprint: []const u8) Manifest {
        return .{ .set_id = set_id, .cluster_fingerprint = fingerprint, .node_id = boundary.node_id, .voters = boundary.voters, .current_term = boundary.current_term, .last_applied = boundary.last_applied, .last_log_index = boundary.last_log_index, .snapshot_index = boundary.snapshot_index, .snapshot_term = boundary.snapshot_term, .snapshot_size = boundary.snapshot_size, .files = entries };
    }

    pub fn validate(self: Manifest) !void {
        if (self.format != 1 or self.files.len < 4 or self.files.len > 7) return error.InvalidManifest;
        try validateSetId(self.set_id);
        if (self.cluster_fingerprint.len != 64) return error.InvalidManifest;
        for (self.cluster_fingerprint) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return error.InvalidManifest;
        try databases.validateVoters(self.voters, self.node_id);
        for (self.files, 0..) |entry, i| {
            if (!allowed(entry.name) or entry.size == 0 or entry.size > limit(entry.name) or entry.sha256.len != 64) return error.InvalidManifest;
            for (entry.sha256) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return error.InvalidManifest;
            for (self.files[0..i]) |previous| if (std.mem.eql(u8, previous.name, entry.name)) return error.InvalidManifest;
        }
        for ([_][]const u8{ "raft.db", "state.db", "api_token", "join_token" }) |name| if (!self.contains(name)) return error.InvalidManifest;
        if ((self.snapshot_index > 0) != self.contains("snapshot.dat")) return error.InvalidManifest;
    }

    pub fn contains(self: Manifest, name: []const u8) bool {
        for (self.files) |entry| if (std.mem.eql(u8, entry.name, name)) return true;
        return false;
    }

    pub fn matches(self: Manifest, boundary: databases.Boundary) bool {
        return self.node_id == boundary.node_id and std.mem.eql(u8, self.voters, boundary.voters) and
            self.current_term == boundary.current_term and self.last_applied == boundary.last_applied and
            self.last_log_index == boundary.last_log_index and self.snapshot_index == boundary.snapshot_index and
            self.snapshot_term == boundary.snapshot_term and self.snapshot_size == boundary.snapshot_size;
    }
};

pub fn allowed(name: []const u8) bool {
    for ([_][]const u8{ "raft.db", "state.db", "yoq.db", "snapshot.dat", "api_token", "secrets.key", "join_token" }) |known| {
        if (std.mem.eql(u8, name, known)) return true;
    }
    return false;
}

pub fn limit(name: []const u8) u64 {
    if (std.mem.endsWith(u8, name, ".db")) return files.max_database_size;
    if (std.mem.eql(u8, name, "snapshot.dat")) return @import("../state_machine/snapshot_support.zig").max_snapshot_file_size;
    return 4096;
}

pub fn read(alloc: std.mem.Allocator, dir: std.Io.Dir) !std.json.Parsed(Manifest) {
    const data = try files.readSmall(alloc, dir, "manifest.json", 16384);
    defer alloc.free(data);
    const parsed = try std.json.parseFromSlice(Manifest, alloc, data, .{ .allocate = .alloc_always });
    errdefer parsed.deinit();
    try parsed.value.validate();
    return parsed;
}

pub fn write(alloc: std.mem.Allocator, dir: std.Io.Dir, value: Manifest) !void {
    try value.validate();
    const json = try std.json.Stringify.valueAlloc(alloc, value, .{ .whitespace = .indent_2 });
    defer alloc.free(json);
    try files.write(dir, "manifest.json", json);
}

pub fn validateSetId(id: []const u8) !void {
    if (id.len == 0 or id.len > 64) return error.InvalidSetId;
    for (id) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return error.InvalidSetId;
}

pub fn fingerprint(voters: []const u8, token: []const u8) [64]u8 {
    var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(token);
    hmac.update("yoq-offline-cluster-v1:");
    hmac.update(voters);
    var hash: [32]u8 = undefined;
    hmac.final(&hash);
    return std.fmt.bytesToHex(hash, .lower);
}
