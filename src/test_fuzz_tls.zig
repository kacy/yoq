// test_fuzz_tls — fuzz the TLS attack surface with arbitrary byte sequences.
//
// the X.509 DER verifier and the handshake message parsers consume bytes from
// a remote peer during the mTLS handshake. they must never crash (panic /
// out-of-bounds) on malformed input — only return an error or a parsed value.
//
// lives in src/ so the tls modules' relative imports resolve. driven via
// `zig build fuzz-tls` (corpus mode) or `zig build fuzz-tls -- --fuzz`.

const std = @import("std");
const x509_verify = @import("tls/x509_verify.zig");
const message_parse = @import("tls/handshake/message_parse.zig");

fn fuzzInput(smith: *std.testing.Smith, buffer: []u8) []const u8 {
    if (smith.in) |input| return input;
    return buffer[0..smith.slice(buffer)];
}

test "fuzz x509_verify.parseDer with arbitrary bytes" {
    try std.testing.fuzz({}, struct {
        fn testOne(_: void, smith: *std.testing.Smith) anyerror!void {
            var buffer: [4096]u8 = undefined;
            const input = fuzzInput(smith, &buffer);

            // parseDer must never crash — only return error or a Parsed whose
            // slices all reference within `input`.
            var san_buf: [x509_verify.max_san_uris][]const u8 = undefined;
            const parsed = x509_verify.parseDer(input, &san_buf) catch return;

            // every returned slice must lie inside the input buffer.
            assertSubslice(parsed.tbs, input);
            assertSubslice(parsed.sig_der, input);
            assertSubslice(parsed.subject_cn, input);
            assertSubslice(parsed.issuer_cn, input);
            assertSubslice(parsed.public_key_point, input);
            for (parsed.san_uris) |uri| assertSubslice(uri, input);
        }
    }.testOne, .{
        .corpus = &.{
            "",
            "\x30\x00",
            "\x30\x82\x01\x00",
            "\x30\x03\x02\x01\x00",
            &[_]u8{0xff} ** 64,
        },
    });
}

test "fuzz handshake message stream with arbitrary bytes" {
    try std.testing.fuzz({}, struct {
        fn testOne(_: void, smith: *std.testing.Smith) anyerror!void {
            var buffer: [4096]u8 = undefined;
            const input = fuzzInput(smith, &buffer);

            // walk the message stream; each step must return error or a
            // bounded message — never crash.
            var pos: usize = 0;
            while (true) {
                const msg = message_parse.nextMessage(input, &pos) catch break;
                const m = msg orelse break;
                assertSubslice(m.body, input);
                assertSubslice(m.raw, input);

                // feed each message body into the matching sub-parser; all of
                // these must tolerate arbitrary bytes.
                switch (m.msg_type) {
                    @intFromEnum(message_parse.HandshakeType.server_hello) => _ = message_parse.parseServerHello(m.body) catch {},
                    @intFromEnum(message_parse.HandshakeType.encrypted_extensions) => _ = message_parse.parseEncryptedExtensions(m.body) catch {},
                    @intFromEnum(message_parse.HandshakeType.certificate) => _ = message_parse.parseCertificateMessage(m.body) catch {},
                    @intFromEnum(message_parse.HandshakeType.certificate_request) => _ = message_parse.parseCertificateRequest(m.body) catch {},
                    @intFromEnum(message_parse.HandshakeType.certificate_verify) => _ = message_parse.parseCertificateVerify(m.body) catch {},
                    @intFromEnum(message_parse.HandshakeType.finished) => _ = message_parse.parseFinished(m.body) catch {},
                    else => {},
                }
            }
        }
    }.testOne, .{
        .corpus = &.{
            "",
            "\x02\x00\x00\x00",
            "\x0b\x00\x00\x00",
            &[_]u8{0xaa} ** 32,
        },
    });
}

/// assert `sub` is a subslice of `parent` (or empty). a parser returning a
/// slice that points outside its input would be a real bug.
fn assertSubslice(sub: []const u8, parent: []const u8) void {
    if (sub.len == 0) return;
    const sub_start = @intFromPtr(sub.ptr);
    const sub_end = sub_start + sub.len;
    const par_start = @intFromPtr(parent.ptr);
    const par_end = par_start + parent.len;
    std.debug.assert(sub_start >= par_start and sub_end <= par_end);
}
