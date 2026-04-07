const std = @import("std");
const sqlite = @import("sqlite");
const store = @import("../../state/store.zig");
const common = @import("common.zig");

pub fn generateDeploymentId(alloc: std.mem.Allocator) ![]const u8 {
    const chars = "0123456789abcdef";
    var bytes: [6]u8 = undefined;
    std.crypto.random.bytes(&bytes);

    const hex = try alloc.alloc(u8, 12);
    for (bytes, 0..) |b, i| {
        hex[i * 2] = chars[b >> 4];
        hex[i * 2 + 1] = chars[b & 0x0f];
    }
    return hex;
}

pub fn computeManifestHash(alloc: std.mem.Allocator, payload: []const u8) ![]const u8 {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(payload, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    return std.fmt.allocPrint(alloc, "sha256:{s}", .{hex});
}

pub fn recordDeployment(
    id: []const u8,
    app_name: ?[]const u8,
    service_name: []const u8,
    manifest_hash: []const u8,
    config_snapshot: []const u8,
    status: common.DeploymentStatus,
    message: ?[]const u8,
) !void {
    store.saveDeployment(.{
        .id = id,
        .app_name = app_name,
        .service_name = service_name,
        .manifest_hash = manifest_hash,
        .config_snapshot = config_snapshot,
        .status = status.toString(),
        .message = message,
        .created_at = std.time.timestamp(),
    }) catch return error.StoreFailed;
}

pub fn recordDeploymentInDb(
    db: *sqlite.Db,
    id: []const u8,
    app_name: ?[]const u8,
    service_name: []const u8,
    manifest_hash: []const u8,
    config_snapshot: []const u8,
    status: common.DeploymentStatus,
    message: ?[]const u8,
) !void {
    store.saveDeploymentInDb(db, .{
        .id = id,
        .app_name = app_name,
        .service_name = service_name,
        .manifest_hash = manifest_hash,
        .config_snapshot = config_snapshot,
        .status = status.toString(),
        .message = message,
        .created_at = std.time.timestamp(),
    }) catch return error.StoreFailed;
}

pub fn updateDeploymentStatus(
    id: []const u8,
    status: common.DeploymentStatus,
    message: ?[]const u8,
) !void {
    store.updateDeploymentStatus(id, status.toString(), message) catch return error.StoreFailed;
}

pub fn updateDeploymentStatusInDb(
    db: *sqlite.Db,
    id: []const u8,
    status: common.DeploymentStatus,
    message: ?[]const u8,
) !void {
    store.updateDeploymentStatusInDb(db, id, status.toString(), message) catch return error.StoreFailed;
}
