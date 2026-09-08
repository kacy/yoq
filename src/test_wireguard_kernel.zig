const std = @import("std");
const wireguard = @import("network/wireguard.zig");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) return error.MissingOperation;
    if (std.mem.eql(u8, args[1], "create")) {
        if (args.len != 4) return error.MissingKeys;
        try wireguard.createInterface("yoq-fixture", args[2], 51900);
        try wireguard.addPeer("yoq-fixture", .{
            .public_key = args[3],
            .endpoint = "127.0.0.1:51901",
            .allowed_ips = "10.77.0.0/24",
        });
    } else if (std.mem.eql(u8, args[1], "remove-peer")) {
        if (args.len != 3) return error.MissingKey;
        try wireguard.removePeer("yoq-fixture", args[2]);
    } else if (std.mem.eql(u8, args[1], "delete")) {
        try wireguard.deleteInterface("yoq-fixture");
    } else return error.UnknownOperation;
}
