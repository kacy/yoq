const std = @import("std");
const add = @import("fs/add.zig");
const base = @import("fs/base.zig");
const copy = @import("fs/copy.zig");
const copy_args = @import("fs/copy_args.zig");

pub const processFrom = base.processFrom;
pub const processRun = base.processRun;
pub const parseCopyArgs = copy_args.parseCopyArgs;
pub const processCopy = copy.processCopy;
pub const processCopyFromStage = copy.processCopyFromStage;
pub const processCopyMultiStage = copy.processCopyMultiStage;
pub const isTarArchive = copy_args.isTarArchive;
pub const processAdd = add.processAdd;
pub const processAddMultiStage = add.processAddMultiStage;

test {
    _ = copy;
}

test "parse copy args" {
    const result = try parseCopyArgs("package.json /app/");
    try std.testing.expectEqual(@as(usize, 1), result.sources().len);
    try std.testing.expectEqualStrings("package.json", result.sources()[0]);
    try std.testing.expectEqualStrings("/app/", result.dest);
}

test "parseCopyArgs — with --from flag" {
    const result = try parseCopyArgs("--from=builder /app/dist /usr/share/nginx/html");
    try std.testing.expectEqualStrings("builder", result.from_stage.?);
}

test "parseCopyArgs — several sources need a directory destination" {
    const two = try parseCopyArgs("build.zig build.zig.zon ./");
    try std.testing.expectEqual(@as(usize, 2), two.sources().len);
    try std.testing.expectEqualStrings("build.zig.zon", two.sources()[1]);
    try std.testing.expectEqualStrings("./", two.dest);

    const three = try parseCopyArgs("go.mod  go.sum\tmain.go .");
    try std.testing.expectEqual(@as(usize, 3), three.sources().len);
    try std.testing.expectEqualStrings(".", three.dest);

    try std.testing.expectError(error.DestinationNotDirectory, parseCopyArgs("a b /app"));
}

test "parseCopyArgs — options in any order" {
    const linked = try parseCopyArgs("--link --from=builder /out /app/");
    try std.testing.expectEqualStrings("builder", linked.from_stage.?);
    try std.testing.expectEqualStrings("/out", linked.sources()[0]);

    try std.testing.expectError(error.UnsupportedCopyFlag, parseCopyArgs("--chown=app:app src /app"));
    try std.testing.expectError(error.UnsupportedCopyFlag, parseCopyArgs("--from=b --chmod=755 a /b"));
    try std.testing.expectError(error.UnsupportedCopyFlag, parseCopyArgs("--exclude=*.md . /app"));
}

test "parseCopyArgs — json form" {
    const result = try parseCopyArgs("--from=builder [\"/out/a b\", \"/out/c\", \"/app/\"]");
    try std.testing.expectEqualStrings("builder", result.from_stage.?);
    try std.testing.expectEqual(@as(usize, 2), result.sources().len);
    try std.testing.expectEqualStrings("/out/a b", result.sources()[0]);
    try std.testing.expectEqualStrings("/app/", result.dest);

    try std.testing.expectError(error.InvalidCopyArgs, parseCopyArgs("[\"a\", \"b\""));
    try std.testing.expectError(error.InvalidCopyArgs, parseCopyArgs("[\"a\\\"b\", \"c\"]"));
}

test "parseCopyArgs — a lone path is refused" {
    try std.testing.expectError(error.InvalidCopyArgs, parseCopyArgs("foo"));
    try std.testing.expectError(error.InvalidCopyArgs, parseCopyArgs(""));
}

test "isTarArchive detects tar extensions" {
    try std.testing.expect(isTarArchive("archive.tar"));
    try std.testing.expect(isTarArchive("archive.tar.gz"));
}
