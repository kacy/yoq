// fuzz_gossip_msg — fuzz gossip message decoding
//
// validates that decode() and decodeUpdates() never crash on arbitrary
// byte sequences. the @enumFromInt panic (fixed in gossip.zig) was the
// original motivation for this target.

const std = @import("std");
const gossip = @import("gossip");

test "fuzz gossip decode with arbitrary bytes" {
    try std.testing.fuzz({}, struct {
        fn testOne(_: void, input: []const u8) anyerror!void {
            const msg = gossip.Gossip.decode(std.testing.allocator, input) catch {
                // any decode error is fine — just no crashes
                return;
            };
            // if decode succeeded, verify we can access fields without crashing
            switch (msg) {
                .ping => |p| {
                    _ = p.from;
                    _ = p.sequence;
                    for (p.updates.slice()) |u| {
                        _ = u.id;
                        _ = u.state;
                    }
                },
                .ping_ack => |p| {
                    _ = p.from;
                    _ = p.sequence;
                    for (p.updates.slice()) |u| {
                        _ = u.id;
                        _ = u.state;
                    }
                },
                .ping_req => |p| {
                    _ = p.from;
                    _ = p.target;
                    _ = p.sequence;
                    for (p.updates.slice()) |u| {
                        _ = u.id;
                        _ = u.state;
                    }
                },
            }
        }
    }.testOne, .{
        .corpus = &.{
            // ping (type 0x10 + 17 bytes header + 0 updates)
            &[_]u8{0x10} ++ &[_]u8{0} ** 17,
            // ping_ack (type 0x11 + 17 bytes header + 0 updates)
            &[_]u8{0x11} ++ &[_]u8{0} ** 17,
            // ping_req (type 0x12 + 25 bytes header + 0 updates)
            &[_]u8{0x12} ++ &[_]u8{0} ** 25,
            // ping with 1 update (17 + 23 = 40 bytes after type)
            &[_]u8{0x10} ++ &[_]u8{0} ** 16 ++ &[_]u8{1} ++ &[_]u8{0} ** 23,
            // ping with invalid state byte in update
            &[_]u8{0x10} ++ &[_]u8{0} ** 16 ++ &[_]u8{1} ++ &[_]u8{0} ** 14 ++ &[_]u8{0xFF} ++ &[_]u8{0} ** 8,
            // too short
            "",
            // invalid type
            &[_]u8{0xFF},
        },
    });
}
