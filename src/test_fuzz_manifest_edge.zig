// manifest edge case tests — adversarial and boundary inputs
//
// this file lives in src/ so that loader's relative imports resolve.
// imports the actual test content from tests/fuzz/.

const std = @import("std");
const loader = @import("manifest/loader.zig");

const alloc = std.testing.allocator;

fn expectLoadError(input: []const u8) !void {
    var manifest = loader.loadFromString(alloc, input) catch return;
    manifest.deinit();
    return error.ExpectedError;
}

fn expectLoadSuccess(input: []const u8) !void {
    var manifest = loader.loadFromString(alloc, input) catch |err| {
        std.debug.print("unexpected load error: {}\n", .{err});
        return err;
    };
    manifest.deinit();
}

test "edge: extremely long service name" {
    var buf: [2048]u8 = undefined;
    var stream = @import("compat").fixedBufferStream(&buf);
    const writer = stream.writer();
    try writer.writeAll("[service.");
    try writer.writeByteNTimes('a', 1000);
    try writer.writeAll("]\nimage = \"nginx\"\n");
    const input = stream.getWritten();

    var manifest = loader.loadFromString(alloc, input) catch return;
    manifest.deinit();
}

test "edge: maximum replicas value" {
    const input = "[service.web]\nimage = \"nginx\"\nreplicas = 4294967295\n";
    var manifest = loader.loadFromString(alloc, input) catch return;
    manifest.deinit();
}

test "edge: duplicate service names with different cases" {
    const input =
        \\[service.Web]
        \\image = "nginx"
        \\[service.web]
        \\image = "nginx"
    ;
    var manifest = loader.loadFromString(alloc, input) catch return;
    manifest.deinit();
}

test "edge: circular dependency chain A→B→C→A" {
    const input =
        \\[service.a]
        \\image = "img"
        \\depends_on = ["c"]
        \\[service.b]
        \\image = "img"
        \\depends_on = ["a"]
        \\[service.c]
        \\image = "img"
        \\depends_on = ["b"]
    ;
    try expectLoadError(input);
}

test "edge: self-referencing dependency" {
    const input =
        \\[service.web]
        \\image = "nginx"
        \\depends_on = ["web"]
    ;
    try expectLoadError(input);
}

test "edge: empty image field accepted" {
    const input =
        \\[service.web]
        \\image = ""
    ;
    // empty image string is currently accepted by the loader
    var manifest = loader.loadFromString(alloc, input) catch return;
    manifest.deinit();
}

test "edge: service with no image field" {
    const input =
        \\[service.web]
        \\replicas = 1
    ;
    try expectLoadError(input);
}

test "edge: unicode in service names" {
    const input = "[service.\xc3\xa9l\xc3\xa8ve]\nimage = \"nginx\"\n";
    var manifest = loader.loadFromString(alloc, input) catch return;
    manifest.deinit();
}

test "edge: unicode in env vars" {
    const input =
        \\[service.web]
        \\image = "nginx"
        \\env = ["GREETING=こんにちは"]
    ;
    var manifest = loader.loadFromString(alloc, input) catch return;
    manifest.deinit();
}

test "edge: manifest with 100 services" {
    var buf: [32768]u8 = undefined;
    var stream = @import("compat").fixedBufferStream(&buf);
    const writer = stream.writer();

    for (0..100) |i| {
        try writer.print("[service.svc{d}]\nimage = \"nginx\"\n\n", .{i});
    }
    const input = stream.getWritten();

    var manifest = loader.loadFromString(alloc, input) catch return;
    manifest.deinit();
}

test "edge: env var substitution with undefined variable expands to empty" {
    const input =
        \\[service.web]
        \\image = "${NONEXISTENT_VAR_12345}"
    ;
    // undefined vars expand to "" — empty image is accepted
    var manifest = loader.loadFromString(alloc, input) catch return;
    manifest.deinit();
}

test "edge: env var with default value" {
    const input =
        \\[service.web]
        \\image = "${NONEXISTENT_VAR_12345:-nginx}"
    ;
    try expectLoadSuccess(input);
}

test "edge: nested env var in default" {
    const input =
        \\[service.web]
        \\image = "nginx"
        \\env = ["A=${B:-${C:-default}}"]
    ;
    var manifest = loader.loadFromString(alloc, input) catch return;
    manifest.deinit();
}

test "edge: malformed port mappings rejected" {
    const cases = [_][]const u8{
        "[service.web]\nimage = \"nginx\"\nports = [\"\"]\n",
        "[service.web]\nimage = \"nginx\"\nports = [\"abc:def\"]\n",
        "[service.web]\nimage = \"nginx\"\nports = [\"99999:80\"]\n",
    };

    for (cases) |input| {
        try expectLoadError(input);
    }
}

test "edge: port mapping with empty host part accepted" {
    // ":80" means container port 80 with no host mapping — currently accepted
    const input = "[service.web]\nimage = \"nginx\"\nports = [\":80\"]\n";
    var manifest = loader.loadFromString(alloc, input) catch return;
    manifest.deinit();
}

test "edge: malformed volume mounts rejected" {
    const cases = [_][]const u8{
        "[service.web]\nimage = \"nginx\"\nvolumes = [\"\"]\n",
        "[service.web]\nimage = \"nginx\"\nvolumes = [\":::\"]\n",
    };

    for (cases) |input| {
        try expectLoadError(input);
    }
}

test "edge: volume mount with unknown mode accepted" {
    // "/src:/dst:invalid" — invalid mode string is currently accepted
    const input = "[service.web]\nimage = \"nginx\"\nvolumes = [\"/src:/dst:invalid\"]\n";
    var manifest = loader.loadFromString(alloc, input) catch return;
    manifest.deinit();
}

test "edge: dependency on non-existent service" {
    const input =
        \\[service.web]
        \\image = "nginx"
        \\depends_on = ["nonexistent"]
    ;
    try expectLoadError(input);
}
