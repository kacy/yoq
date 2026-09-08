//! exercise registry transfers without starting containers or a control plane.
const std = @import("std");
const registry = @import("image/registry.zig");
const spec = @import("image/spec.zig");
const blob_store = @import("image/store.zig");
const upload = @import("image/registry/upload.zig");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len == 6) {
        uploadFixture(init, args[1..]) catch |err| {
            std.debug.print("registry upload rejected: {s}\n", .{@errorName(err)});
            std.process.exit(2);
        };
        return;
    }
    if (args.len != 2) return error.MissingImage;
    const reference = spec.parseImageRef(args[1]);
    var result = registry.pull(init.io, init.gpa, reference) catch |err| {
        std.debug.print("registry pull rejected: {s}\n", .{@errorName(err)});
        std.process.exit(2);
    };
    defer result.deinit();
    if (result.layer_digests.len != 3) return error.IncompletePull;
    std.debug.print("registry pull verified all three layers\n", .{});
}

fn uploadFixture(init: std.process.Init, args: []const []const u8) !void {
    const mode = args[0];
    const host = args[1];
    const repository = args[2];
    const digest = args[3];
    const path = args[4];
    var client: std.http.Client = .{ .io = init.io, .allocator = init.gpa };
    defer client.deinit();
    const token: @import("image/registry/common.zig").Token = .{ .value = "fixture-token" };

    if (std.mem.eql(u8, mode, "upload-bytes")) {
        const data = try std.Io.Dir.cwd().readFileAlloc(init.io, path, init.gpa, .limited(1024 * 1024));
        defer init.gpa.free(data);
        try registry.uploadBlob(init.gpa, &client, host, repository, digest, data, token);
    } else if (std.mem.eql(u8, mode, "upload-file")) {
        const file = try std.Io.Dir.cwd().openFile(init.io, path, .{});
        defer file.close(init.io);
        const stat = try file.stat(init.io);
        var blob = blob_store.BlobHandle{ .file = file, .size = stat.size };
        try upload.uploadBlobFile(&client, host, repository, digest, &blob, token);
    } else return error.InvalidUploadMode;
}
