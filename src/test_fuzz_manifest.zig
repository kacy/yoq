// fuzz_manifest — fuzz the TOML parser and manifest loader
//
// this file lives in src/ so that relative imports from modules under
// test (e.g. loader.zig → ../lib/toml.zig) resolve correctly.
//
// validates that arbitrary TOML-ish strings never crash the parser
// or loader. every input must either parse successfully or return
// a well-defined error.

const std = @import("std");
const loader = @import("manifest/loader.zig");

test "fuzz manifest loadFromString with arbitrary bytes" {
    try std.testing.fuzz({}, struct {
        fn testOne(_: void, input: []const u8) anyerror!void {
            var manifest = loader.loadFromString(std.testing.allocator, input) catch {
                return;
            };
            manifest.deinit();
        }
    }.testOne, .{
        .corpus = &.{
            "[service.web]\nimage = \"nginx\"\n",
            "[training.bert]\nimage = \"pytorch\"\ngpus = 4\ncommand = \"train.py\"\n",
            "",
            "[service.a]\nimage = \"x\"\ndepends_on = [\"b\"]\n[service.b]\nimage = \"y\"\n",
            "[[[[[[",
            "\x00\x00\x00",
            "[service.web]\nimage = \"nginx\"\nreplicas = 3\nports = [\"8080:80\"]\n",
        },
    });
}
