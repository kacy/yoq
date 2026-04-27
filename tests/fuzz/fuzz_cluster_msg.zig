// fuzz_cluster_msg — fuzz raft transport message decoding
//
// validates that decode() never crashes on arbitrary byte sequences
// and always returns either a valid Message or an error.

const std = @import("std");
const transport = @import("transport");

fn fuzzInput(smith: *std.testing.Smith, buffer: []u8) []const u8 {
    if (smith.in) |input| return input;
    return buffer[0..smith.slice(buffer)];
}

test "fuzz transport decode with arbitrary bytes" {
    try std.testing.fuzz({}, struct {
        fn testOne(_: void, smith: *std.testing.Smith) anyerror!void {
            var buffer: [4096]u8 = undefined;
            const input = fuzzInput(smith, &buffer);

            const msg = transport.decode(std.testing.allocator, input) catch {
                // any decode error is fine — just no crashes
                return;
            };
            // if decode succeeded, free any allocated entries
            switch (msg) {
                .append_entries => |ae| {
                    for (ae.entries) |entry| {
                        std.testing.allocator.free(entry.data);
                    }
                    std.testing.allocator.free(ae.entries);
                },
                .install_snapshot => |is| {
                    std.testing.allocator.free(is.data);
                },
                else => {},
            }
        }
    }.testOne, .{
        .corpus = &.{
            // RequestVote (type 0x01 + 32 bytes payload)
            &[_]u8{0x01} ++ &[_]u8{0} ** 32,
            // RequestVoteReply (type 0x02 + 9 bytes)
            &[_]u8{0x02} ++ &[_]u8{0} ** 9,
            // AppendEntries (type 0x03 + 44 bytes, 0 entries)
            &[_]u8{0x03} ++ &[_]u8{0} ** 44,
            // too short
            "",
            // invalid type
            &[_]u8{0xFF},
        },
    });
}
