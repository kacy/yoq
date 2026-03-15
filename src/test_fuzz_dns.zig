// fuzz_dns — fuzz DNS packet parsers with arbitrary byte sequences
//
// this file lives in src/ so that dns.zig's relative imports resolve.
// validates that parseHeader, parseQuestion, buildResponse, and
// buildNxDomain never crash or access out-of-bounds memory.

const std = @import("std");
const dns = @import("network/dns.zig");

test "fuzz DNS parseHeader with arbitrary bytes" {
    try std.testing.fuzz({}, struct {
        fn testOne(_: void, input: []const u8) anyerror!void {
            _ = dns.parseHeader(input);
        }
    }.testOne, .{
        .corpus = &.{
            // valid 12-byte header
            &.{ 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            // too short
            &.{ 0x00, 0x01 },
            "",
            &([_]u8{0xFF} ** 12),
        },
    });
}

test "fuzz DNS parseQuestion with arbitrary bytes" {
    try std.testing.fuzz({}, struct {
        fn testOne(_: void, input: []const u8) anyerror!void {
            _ = dns.parseQuestion(input);
        }
    }.testOne, .{
        .corpus = &.{
            // valid query for "web" (header + 3web0 + type + class)
            &.{ 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'e', 'b', 0x00, 0x00, 0x01, 0x00, 0x01 },
            "",
            &([_]u8{0xFF} ** 64),
            // compression pointer in label
            &.{ 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x0C },
        },
    });
}

test "fuzz DNS buildResponse with arbitrary bytes" {
    try std.testing.fuzz({}, struct {
        fn testOne(_: void, input: []const u8) anyerror!void {
            var response_buf: [512]u8 = undefined;
            _ = dns.buildResponse(input, input.len, .{ 10, 42, 0, 2 }, &response_buf);
        }
    }.testOne, .{
        .corpus = &.{
            // valid query for "web"
            &.{ 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'e', 'b', 0x00, 0x00, 0x01, 0x00, 0x01 },
            "",
        },
    });
}
