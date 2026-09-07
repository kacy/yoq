const std = @import("std");
const mutation = @import("mutation_session.zig");
const registry = @import("registry.zig");
const credentials = @import("agent_credentials.zig");
const sql = @import("sql_command.zig");

pub fn parseKey(alloc: std.mem.Allocator, body: []const u8) !?[64]u8 {
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, body, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidKey;
    const value = parsed.value.object.get("registration_key") orelse return null;
    if (value != .string or value.string.len != 64) return error.InvalidKey;
    for (value.string) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return error.InvalidKey;
    var key: [64]u8 = undefined;
    @memcpy(&key, value.string);
    return key;
}

pub const Refresh = struct {
    address: []const u8,
    endpoint: []const u8,
    public_key: []const u8,
    resources: registry.AgentResources,
    options: registry.RegisterOpts,
    now: i64,
};

/// A retry can refresh its own endpoint and capacities without replacing its
/// assigned node or reviving a revoked credential. The credential predicate is
/// evaluated at application time, inside the same transaction as the peer edit.
pub fn refresh(alloc: std.mem.Allocator, session: mutation.Session, id: []const u8, key: []const u8, request: Refresh) mutation.Error!void {
    const digest = credentials.hash(key);
    var batch = std.Io.Writer.Allocating.init(alloc);
    defer batch.deinit();
    sql.write(
        &batch.writer,
        "UPDATE agents SET address = CASE WHEN credential_hash = ? AND wg_public_key = ? THEN ? ELSE NULL END, agent_api_port = ?, cpu_cores = ?, memory_mb = ?, gpu_count = ?, gpu_model = ?, gpu_vram_mb = ?, role = ?, region = ?, labels = ?, last_heartbeat = ? WHERE id = ?;",
        .{ digest, request.public_key, request.address, request.options.agent_api_port, request.resources.cpu_cores, request.resources.memory_mb, request.resources.gpu_count, request.resources.gpu_model, request.resources.gpu_vram_mb, request.options.role orelse "both", request.options.region orelse "", request.options.labels orelse "", request.now, id },
    ) catch return error.InternalError;
    sql.write(&batch.writer, "UPDATE wireguard_peers SET endpoint = ? WHERE agent_id = ? AND EXISTS (SELECT 1 FROM agents WHERE id = ? AND credential_hash = ? AND wg_public_key = ?);", .{ request.endpoint, id, id, digest, request.public_key }) catch return error.InternalError;
    try session.commit(batch.written());
}

pub fn readRegistered(alloc: std.mem.Allocator, session: mutation.Session, id: []const u8, credential: []const u8, public_key: ?[]const u8) mutation.Error!?registry.AgentRecord {
    const node = session.node;
    node.mu.lockUncancelable(std.Options.debug_io);
    defer node.mu.unlock(std.Options.debug_io);
    try session.checkLocked();
    const record = (registry.getAgent(alloc, node.stateMachineDb(), id) catch return error.InternalError) orelse return null;
    errdefer record.deinit(alloc);
    if (!(credentials.authenticates(node.stateMachineDb(), credential, id) catch return error.InternalError)) return error.Conflict;
    if (public_key) |expected| {
        if (record.wg_public_key == null or !std.mem.eql(u8, record.wg_public_key.?, expected)) return error.Conflict;
    }
    return record;
}
