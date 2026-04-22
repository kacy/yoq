// init — interactive manifest scaffolding
//
// creates a manifest.toml with sensible defaults via simple prompts.
// every question has a default so the user can press Enter through
// all of them. when stdin is not a TTY (piped), uses all defaults
// silently.

const std = @import("std");
const platform = @import("platform");
const loader = @import("loader.zig");

pub const Options = struct {
    output_path: []const u8 = loader.default_filename,
    force: bool = false,
};

pub const Answers = struct {
    project: []const u8,
    service: []const u8,
    image: []const u8,
    port: ?u16,
};

pub const InitError = error{
    FileExists,
    WriteFailed,
    CwdFailed,
};

/// entry point — checks file existence, detects TTY, gathers answers,
/// generates and writes the manifest file.
pub fn run(alloc: std.mem.Allocator, opts: Options) InitError!void {
    // check if file already exists (unless --force)
    if (!opts.force) {
        if (platform.cwd().statFile(opts.output_path)) |_| {
            const stderr = platform.File.stderr().textWriter();
            stderr.print("{s} already exists (use -f to specify a different path)\n", .{opts.output_path}) catch {};
            return InitError.FileExists;
        } else |_| {
            // file doesn't exist — good
        }
    }

    const is_tty = platform.isatty(std.posix.STDIN_FILENO);

    const answers = if (is_tty)
        gatherInteractive(alloc) orelse return InitError.CwdFailed
    else
        gatherDefaults(alloc) orelse return InitError.CwdFailed;

    const content = generateManifest(alloc, answers) catch return InitError.WriteFailed;
    defer alloc.free(content);

    platform.cwd().writeFile(.{
        .sub_path = opts.output_path,
        .data = content,
    }) catch return InitError.WriteFailed;

    if (is_tty) {
        const stderr = platform.File.stderr().textWriter();
        stderr.print("\ncreated {s}\n\n  yoq up        start services\n  yoq up --dev  start with hot reload\n", .{opts.output_path}) catch {};
    } else {
        // non-interactive: just print the path to stdout
        const stdout = platform.File.stdout().textWriter();
        stdout.print("{s}\n", .{opts.output_path}) catch {};
    }
}

/// derive default project name from basename of cwd
fn defaultProjectName(alloc: std.mem.Allocator) ?[]const u8 {
    var buf: [4096]u8 = undefined;
    const cwd = platform.cwd().realpath(".", &buf) catch return null;
    const basename = std.fs.path.basename(cwd);
    return alloc.dupe(u8, basename) catch null;
}

/// run the 4 interactive prompts
fn gatherInteractive(alloc: std.mem.Allocator) ?Answers {
    const default_project = defaultProjectName(alloc) orelse return null;
    var buf: [256]u8 = undefined;
    const stdin = platform.File.stdin().textReader();

    const project = prompt(stdin, &buf, "project name", default_project);
    const service = prompt(stdin, &buf, "service name", "app");
    const image = prompt(stdin, &buf, "image", "nginx:latest");
    const port = promptPort(stdin, &buf, "port", "none");

    // dupe answers so they outlive the read buffer
    return .{
        .project = alloc.dupe(u8, project) catch return null,
        .service = alloc.dupe(u8, service) catch return null,
        .image = alloc.dupe(u8, image) catch return null,
        .port = port,
    };
}

/// return all defaults for non-interactive (piped) mode
fn gatherDefaults(alloc: std.mem.Allocator) ?Answers {
    const default_project = defaultProjectName(alloc) orelse return null;
    return .{
        .project = default_project,
        .service = alloc.dupe(u8, "app") catch return null,
        .image = alloc.dupe(u8, "nginx:latest") catch return null,
        .port = null,
    };
}

/// display `? label (default): `, read a line, return default on empty/EOF
fn prompt(reader: anytype, buf: []u8, label: []const u8, default: []const u8) []const u8 {
    const stderr = platform.File.stderr().textWriter();
    stderr.print("? {s} ({s}): ", .{ label, default }) catch {};

    const line = reader.readUntilDelimiterOrEof(buf, '\n') catch return default;
    if (line) |l| {
        const trimmed = std.mem.trim(u8, l, " \t\r");
        if (trimmed.len == 0) return default;
        return trimmed;
    }
    return default;
}

/// prompt that parses a port number, returns null for "none"
fn promptPort(reader: anytype, buf: []u8, label: []const u8, default: []const u8) ?u16 {
    const stderr = platform.File.stderr().textWriter();
    stderr.print("? {s} ({s}): ", .{ label, default }) catch {};

    const line = reader.readUntilDelimiterOrEof(buf, '\n') catch return null;
    if (line) |l| {
        const trimmed = std.mem.trim(u8, l, " \t\r");
        if (trimmed.len == 0) return null; // user pressed Enter → "none"
        return std.fmt.parseInt(u16, trimmed, 10) catch {
            stderr.print("  invalid port, using none\n", .{}) catch {};
            return null;
        };
    }
    return null;
}

/// build the TOML manifest string from gathered answers
pub fn generateManifest(alloc: std.mem.Allocator, answers: Answers) error{OutOfMemory}![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(alloc);
    const writer = platform.arrayListWriter(&buf, alloc);

    try writer.print(
        \\# yoq manifest — {s}
        \\#
        \\# start:  yoq up
        \\# stop:   yoq down
        \\
        \\[service.{s}]
        \\image = "{s}"
        \\
    , .{ answers.project, answers.service, answers.image });

    if (answers.port) |port| {
        try writer.print("ports = [\"{d}:{d}\"]\n", .{ port, port });
    }

    try writer.writeAll("restart = \"on_failure\"\n");

    return buf.toOwnedSlice(alloc);
}

// -- tests --

const testing = std.testing;

test "generateManifest with port" {
    const content = try generateManifest(testing.allocator, .{
        .project = "my-app",
        .service = "api",
        .image = "node:20",
        .port = 3000,
    });
    defer testing.allocator.free(content);

    // check key lines are present
    try testing.expect(std.mem.indexOf(u8, content, "# yoq manifest — my-app") != null);
    try testing.expect(std.mem.indexOf(u8, content, "[service.api]") != null);
    try testing.expect(std.mem.indexOf(u8, content, "image = \"node:20\"") != null);
    try testing.expect(std.mem.indexOf(u8, content, "ports = [\"3000:3000\"]") != null);
    try testing.expect(std.mem.indexOf(u8, content, "restart = \"on_failure\"") != null);
}

test "generateManifest without port" {
    const content = try generateManifest(testing.allocator, .{
        .project = "my-app",
        .service = "web",
        .image = "nginx:latest",
        .port = null,
    });
    defer testing.allocator.free(content);

    try testing.expect(std.mem.indexOf(u8, content, "[service.web]") != null);
    try testing.expect(std.mem.indexOf(u8, content, "image = \"nginx:latest\"") != null);
    // no ports line when port is null
    try testing.expect(std.mem.indexOf(u8, content, "ports") == null);
    try testing.expect(std.mem.indexOf(u8, content, "restart = \"on_failure\"") != null);
}

test "generateManifest round-trip through loader" {
    const content = try generateManifest(testing.allocator, .{
        .project = "test-app",
        .service = "api",
        .image = "node:20",
        .port = 8080,
    });
    defer testing.allocator.free(content);

    // parse through the real TOML loader
    var manifest = loader.loadFromString(testing.allocator, content) catch |err| {
        std.debug.print("loader failed: {}\n", .{err});
        return error.TestUnexpectedResult;
    };
    defer manifest.deinit();

    // verify parsed correctly
    try testing.expectEqual(@as(usize, 1), manifest.services.len);
    try testing.expectEqualStrings("api", manifest.services[0].name);
    try testing.expectEqualStrings("node:20", manifest.services[0].image);
    try testing.expectEqual(@as(usize, 1), manifest.services[0].ports.len);
    try testing.expectEqual(@as(u16, 8080), manifest.services[0].ports[0].host_port);
    try testing.expectEqual(@as(u16, 8080), manifest.services[0].ports[0].container_port);
}
