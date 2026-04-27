// fuzz_http — fuzz the HTTP request parser with arbitrary byte sequences
//
// validates that parseRequest never crashes, never accesses out-of-bounds
// memory, and always returns either a valid Request or an error/null.

const std = @import("std");
const http = @import("http");

fn fuzzInput(smith: *std.testing.Smith, buffer: []u8) []const u8 {
    if (smith.in) |input| return input;
    return buffer[0..smith.slice(buffer)];
}

test "fuzz parseRequest with arbitrary bytes" {
    try std.testing.fuzz({}, struct {
        fn testOne(_: void, smith: *std.testing.Smith) anyerror!void {
            var buffer: [4096]u8 = undefined;
            const input = fuzzInput(smith, &buffer);

            // parseRequest must never crash — only return null, error, or valid request
            const result = http.parseRequest(input) catch |err| {
                // all errors must be HttpError variants
                switch (err) {
                    error.BadMethod,
                    error.BadRequest,
                    error.UriTooLong,
                    error.HeadersTooLarge,
                    error.BodyTooLarge,
                    => return,
                }
            };

            if (result) |req| {
                // if we got a valid request, all slices must be within input bounds
                try std.testing.expect(req.path.len > 0);
                try std.testing.expect(req.path_only.len > 0);
                try std.testing.expect(req.body.len == req.content_length);
            }
        }
    }.testOne, .{
        .corpus = &.{
            "GET / HTTP/1.1\r\n\r\n",
            "POST /api HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello",
            "DELETE /containers/abc123 HTTP/1.1\r\n\r\n",
            "",
            "\x00\x00\x00\x00",
        },
    });
}

test "fuzz findContentLength with arbitrary headers" {
    try std.testing.fuzz({}, struct {
        fn testOne(_: void, smith: *std.testing.Smith) anyerror!void {
            var buffer: [2048]u8 = undefined;
            const input = fuzzInput(smith, &buffer);

            // findContentLength must never crash
            _ = http.findContentLength(input) catch {};
        }
    }.testOne, .{
        .corpus = &.{
            "Content-Length: 42\r\n",
            "content-length: 0\r\n",
            "",
            "\xff\xff\xff\xff",
        },
    });
}
