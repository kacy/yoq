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

test "parse copy args" {
    const result = parseCopyArgs("package.json /app/");
    try std.testing.expectEqualStrings("package.json", result.src);
    try std.testing.expectEqualStrings("/app/", result.dest);
}

test "parseCopyArgs — with --from flag" {
    const result = parseCopyArgs("--from=builder /app/dist /usr/share/nginx/html");
    try std.testing.expectEqualStrings("builder", result.from_stage.?);
}

test "isTarArchive detects tar extensions" {
    try std.testing.expect(isTarArchive("archive.tar"));
    try std.testing.expect(isTarArchive("archive.tar.gz"));
}
