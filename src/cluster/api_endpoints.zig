//! api failover targets come from the configured seed or a membership list
//! authenticated with the enrollment token. a leader hint alone grants no trust.
const std = @import("std");
const json = @import("../lib/json_helpers.zig");
const paths = @import("../lib/paths.zig");
const identity = @import("agent/enrollment_identity.zig");
const http = @import("http_client.zig");

pub const max_endpoints = 32;
pub const Endpoint = struct {
    address: [4]u8,
    port: u16,

    pub fn eql(a: Endpoint, b: Endpoint) bool {
        return a.port == b.port and std.mem.eql(u8, &a.address, &b.address);
    }
};

pub const Set = struct {
    entries: [max_endpoints]Endpoint = undefined,
    len: usize = 0,
    cursor: usize = 0,

    pub fn add(self: *Set, endpoint: Endpoint) !void {
        if (endpoint.port == 0 or endpoint.address[0] == 0 or endpoint.address[0] >= 224) return error.InvalidEndpoint;
        for (self.entries[0..self.len]) |existing| if (existing.eql(endpoint)) return;
        if (self.len == max_endpoints) return error.TooManyEndpoints;
        self.entries[self.len] = endpoint;
        self.len += 1;
    }

    pub fn select(self: *Set, endpoint: Endpoint) bool {
        for (self.entries[0..self.len], 0..) |entry, i| {
            if (entry.eql(endpoint)) {
                self.cursor = i;
                return true;
            }
        }
        return false;
    }

    pub fn current(self: *const Set) Endpoint {
        return self.entries[self.cursor];
    }

    pub fn advance(self: *Set) void {
        self.cursor = (self.cursor + 1) % self.len;
    }

    pub fn learn(self: *Set, alloc: std.mem.Allocator, response: []const u8, token: []const u8) !bool {
        const wire = json.extractJsonArray(response, "api_servers") orelse return false;
        const signature = json.extractJsonString(response, "api_servers_mac") orelse return error.UntrustedEndpoints;
        const parsed = try std.json.parseFromSlice([]Endpoint, alloc, wire, .{});
        defer parsed.deinit();
        if (parsed.value.len > max_endpoints) return error.TooManyEndpoints;
        var supplied: [32]u8 = undefined;
        if (signature.len != 64) return error.UntrustedEndpoints;
        _ = std.fmt.hexToBytes(&supplied, signature) catch return error.UntrustedEndpoints;
        const expected = mac(parsed.value, token);
        if (!std.crypto.timing_safe.eql([32]u8, supplied, expected)) return error.UntrustedEndpoints;
        // validate the complete update before replacing any trusted state.
        var updated: Set = .{};
        try updated.add(self.entries[0]);
        const previous = self.current();
        try updated.add(previous);
        for (parsed.value) |endpoint| try updated.add(endpoint);
        _ = updated.select(previous);
        self.* = updated;
        return true;
    }
};

pub fn mac(endpoints: []const Endpoint, token: []const u8) [32]u8 {
    var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(token);
    hmac.update("yoq-api-endpoints-v1");
    for (endpoints) |endpoint| {
        hmac.update(&endpoint.address);
        var port: [2]u8 = undefined;
        std.mem.writeInt(u16, &port, endpoint.port, .big);
        hmac.update(&port);
    }
    var digest: [32]u8 = undefined;
    hmac.final(&digest);
    return digest;
}

pub fn writeFields(writer: *std.Io.Writer, endpoints: []const Endpoint, token: []const u8) !void {
    try writer.writeAll("\"api_servers\":[");
    for (endpoints, 0..) |endpoint, i| {
        if (i > 0) try writer.writeByte(',');
        try writer.print("{{\"address\":[{d},{d},{d},{d}],\"port\":{d}}}", .{ endpoint.address[0], endpoint.address[1], endpoint.address[2], endpoint.address[3], endpoint.port });
    }
    try writer.print("],\"api_servers_mac\":\"{s}\"", .{std.fmt.bytesToHex(mac(endpoints, token), .lower)});
}

fn filename(buf: []u8, seed: Endpoint, token: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}.api-servers", .{identity.scopeName(seed.address, seed.port, token)});
}

pub fn load(alloc: std.mem.Allocator, seed: Endpoint, token: []const u8) !Set {
    var set: Set = .{};
    try set.add(seed);
    var path_buf: [paths.max_path]u8 = undefined;
    const directory = try paths.dataPath(&path_buf, "enrollment");
    var dir = try std.Io.Dir.cwd().openDir(std.Options.debug_io, directory, .{ .iterate = true });
    defer dir.close(std.Options.debug_io);
    try loadAt(&set, alloc, dir, seed, token);
    return set;
}

fn loadAt(set: *Set, alloc: std.mem.Allocator, dir: std.Io.Dir, seed: Endpoint, token: []const u8) !void {
    var name_buf: [96]u8 = undefined;
    const name = try filename(&name_buf, seed, token);
    const contents = dir.readFileAlloc(std.Options.debug_io, name, alloc, .limited(8192)) catch |err| {
        if (err == error.FileNotFound) return;
        return err;
    };
    defer alloc.free(contents);
    _ = try set.learn(alloc, contents, token);
}

pub fn save(set: *const Set, seed: Endpoint, token: []const u8) !void {
    var path_buf: [paths.max_path]u8 = undefined;
    const directory = try paths.dataPath(&path_buf, "enrollment");
    var dir = try std.Io.Dir.cwd().openDir(std.Options.debug_io, directory, .{ .iterate = true });
    defer dir.close(std.Options.debug_io);
    try saveAt(set, dir, seed, token);
}

fn saveAt(set: *const Set, dir: std.Io.Dir, seed: Endpoint, token: []const u8) !void {
    var name_buf: [96]u8 = undefined;
    const name = try filename(&name_buf, seed, token);
    var buffer: [8192]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try writer.writeByte('{');
    try writeFields(&writer, set.entries[0..set.len], token);
    try writer.writeByte('}');
    var pending = try dir.createFileAtomic(std.Options.debug_io, name, .{ .permissions = .fromMode(0o600), .replace = true });
    defer pending.deinit(std.Options.debug_io);
    try pending.file.writeStreamingAll(std.Options.debug_io, writer.buffered());
    try pending.file.sync(std.Options.debug_io);
    try pending.replace(std.Options.debug_io);
    try (@import("linux_platform").File{ .handle = dir.handle }).sync();
}

pub const Method = enum { get, post };

pub fn request(self: anytype, method: Method, path: []const u8, body: []const u8, credential: ?[]const u8) !http.Response {
    return requestWithOptions(self, method, path, body, credential, .{});
}

pub fn requestWithOptions(self: anytype, method: Method, path: []const u8, body: []const u8, credential: ?[]const u8, options: http.RequestOptions) !http.Response {
    if (self.api_endpoints.len == 0) try self.api_endpoints.add(.{ .address = self.server_addr, .port = self.server_port });
    // each operation tries at most three servers. the cursor survives failed
    // rounds, so a large cluster cannot trap every retry on its first peers.
    var attempts: usize = 0;
    while (attempts < @min(self.api_endpoints.len, 3)) : (attempts += 1) {
        try options.check();
        const target = self.api_endpoints.current();
        var response = (if (method == .get)
            http.getWithOptions(self.alloc, target.address, target.port, path, credential, options)
        else
            http.postWithOptions(self.alloc, target.address, target.port, path, body, credential, options)) catch |err| {
            switch (err) {
                error.Canceled, error.OutOfMemory, error.InvalidResponse, error.ResponseTooLarge, error.RequestTooLarge => return err,
                else => {},
            }
            self.api_endpoints.advance();
            continue;
        };
        self.server_addr = target.address;
        self.server_port = target.port;
        if (self.api_endpoints.learn(self.alloc, response.body, self.token) catch false) {
            if (self.enrollment_target) |seed| save(&self.api_endpoints, seed, self.token) catch |err| {
                @import("../lib/log.zig").warn("could not persist api failover targets: {}", .{err});
            };
        }
        if (json.extractJsonString(response.body, "leader")) |leader| {
            if (@import("agent/request_support.zig").parseHostPort(leader)) |hint| {
                const endpoint: Endpoint = .{ .address = hint.addr, .port = hint.port };
                if (!target.eql(endpoint) and self.api_endpoints.select(endpoint)) {
                    response.deinit(self.alloc);
                    continue;
                }
            }
        }
        if ((response.status_code == 503 or (response.status_code == 400 and json.extractJsonString(response.body, "leader") != null)) and attempts + 1 < @min(self.api_endpoints.len, 3)) {
            response.deinit(self.alloc);
            self.api_endpoints.advance();
            continue;
        }
        return response;
    }
    return error.ServersUnavailable;
}

test "agent recovery endpoint membership requires proof and survives restart" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const seed: Endpoint = .{ .address = .{ 127, 0, 0, 1 }, .port = 7700 };
    const peer: Endpoint = .{ .address = .{ 127, 0, 0, 2 }, .port = 8800 };
    var set: Set = .{};
    try set.add(seed);
    var text = std.Io.Writer.Allocating.init(alloc);
    defer text.deinit();
    try text.writer.writeByte('{');
    try writeFields(&text.writer, &.{peer}, "cluster-token");
    try text.writer.writeByte('}');
    try std.testing.expectError(error.UntrustedEndpoints, set.learn(alloc, text.written(), "wrong-token"));
    try std.testing.expectEqual(@as(usize, 1), set.len);
    try std.testing.expect(try set.learn(alloc, text.written(), "cluster-token"));
    try saveAt(&set, tmp.dir, seed, "cluster-token");
    try saveAt(&set, tmp.dir, seed, "cluster-token");
    var restored: Set = .{};
    try restored.add(seed);
    try loadAt(&restored, alloc, tmp.dir, seed, "cluster-token");
    try std.testing.expect(restored.select(peer));
    try std.testing.expectEqual(@as(u16, 8800), restored.current().port);
    try std.testing.expect(!restored.select(.{ .address = .{ 127, 0, 0, 3 }, .port = 8800 }));
}
