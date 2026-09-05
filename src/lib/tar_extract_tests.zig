const std = @import("std");
const extract = @import("tar_extract.zig");

const io = std.testing.io;
const alloc = std.testing.allocator;

const Entry = struct {
    name: []const u8,
    kind: enum { file, directory, symlink } = .file,
    content: []const u8 = "",
};

fn archiveBytes(entries: []const Entry) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(alloc);
    defer output.deinit();
    var tar: std.tar.Writer = .{ .underlying_writer = &output.writer };
    for (entries) |entry| {
        switch (entry.kind) {
            .file => try tar.writeFileBytes(entry.name, entry.content, .{}),
            .directory => try tar.writeDir(entry.name, .{}),
            .symlink => try tar.writeLink(entry.name, entry.content, .{}),
        }
    }
    try tar.finishPedantically();
    return output.toOwnedSlice();
}

fn extractBytes(tmp: std.testing.TmpDir, bytes: []const u8) !void {
    try tmp.dir.writeFile(io, .{ .sub_path = "input.tar", .data = bytes });
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_len = try tmp.dir.realPathFile(io, "input.tar", &archive_buf);
    var dest_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dest_len = try tmp.dir.realPathFile(io, "dest", &dest_buf);
    try extract.extractTarFile(archive_buf[0..archive_len], dest_buf[0..dest_len], "archive containment test");
}

fn extractEntries(tmp: std.testing.TmpDir, entries: []const Entry) !void {
    const bytes = try archiveBytes(entries);
    defer alloc.free(bytes);
    try extractBytes(tmp, bytes);
}

fn expectContents(dir: std.Io.Dir, path: []const u8, expected: []const u8) !void {
    const actual = try dir.readFileAlloc(io, path, alloc, .limited(64 * 1024));
    defer alloc.free(actual);
    try std.testing.expectEqualStrings(expected, actual);
}

fn expectLink(dir: std.Io.Dir, path: []const u8, expected: []const u8) !void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const len = try dir.readLink(io, path, &buf);
    try std.testing.expectEqualStrings(expected, buf[0..len]);
}

fn expectFailure(result: anyerror!void) !void {
    if (result) |_| return error.ExpectedExtractionFailure else |_| {}
}

fn prepareDest(tmp: std.testing.TmpDir) !void {
    try tmp.dir.createDir(io, "dest", .default_dir);
    try tmp.dir.createDir(io, "outside", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "outside/marker", .data = "outside remains intact" });
}

// The malformed fixtures need declared sizes and PAX records that the regular
// tar writer intentionally does not expose. Binary size encoding avoids an
// enormous allocation when testing the extractor's per-file size limit.
fn writeRawHeader(writer: *std.Io.Writer, name: []const u8, kind: u8, size: u64) !void {
    var header: [512]u8 = @splat(0);
    std.debug.assert(name.len <= 100);
    @memcpy(header[0..name.len], name);
    @memcpy(header[100..108], "0000644\x00");
    header[124] = 0x80;
    std.mem.writeInt(u64, header[128..136], size, .big);
    @memset(header[148..156], ' ');
    header[156] = kind;
    @memcpy(header[257..263], "ustar\x00");
    @memcpy(header[263..265], "00");
    var checksum: u32 = 0;
    for (header) |byte| checksum += byte;
    _ = try std.fmt.bufPrint(header[148..156], "{o:0>6}\x00 ", .{checksum});
    try writer.writeAll(&header);
}

test "tar extraction confines archive-created absolute and chained symlink parents" {
    for ([_]bool{ false, true }) |chained| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try prepareDest(tmp);
        var outside_buf: [std.fs.max_path_bytes]u8 = undefined;
        const outside_len = try tmp.dir.realPathFile(io, "outside", &outside_buf);
        const entries = [_]Entry{
            .{ .name = "anchor", .kind = .symlink, .content = outside_buf[0..outside_len] },
            .{ .name = "jump", .kind = .symlink, .content = "anchor" },
            .{ .name = if (chained) "jump/marker" else "anchor/marker", .content = "must not escape" },
        };
        const result = extractEntries(tmp, &entries);
        try expectContents(tmp.dir, "outside/marker", "outside remains intact");
        try expectFailure(result);
        try expectLink(tmp.dir, "dest/anchor", outside_buf[0..outside_len]);
    }
}

test "tar extraction confines relative symlink chains whose physical depth differs" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try prepareDest(tmp);
    // Both links pass the lexical depth check, but 'jump' removes a path
    // component: 'jump/escape' is created at the extraction root itself.
    const result = extractEntries(tmp, &.{
        .{ .name = "jump", .kind = .symlink, .content = "." },
        .{ .name = "jump/escape", .kind = .symlink, .content = "../outside" },
        .{ .name = "jump/escape/marker", .content = "must not escape" },
    });
    try expectContents(tmp.dir, "outside/marker", "outside remains intact");
    try expectFailure(result);
}

test "tar extraction confines a preexisting parent symlink" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try prepareDest(tmp);
    try tmp.dir.symLink(io, "../outside", "dest/jump", .{});
    try expectFailure(extractEntries(tmp, &.{.{ .name = "jump/marker", .content = "must not escape" }}));
    try expectContents(tmp.dir, "outside/marker", "outside remains intact");
    try expectLink(tmp.dir, "dest/jump", "../outside");
}

test "tar regular files replace final symlinks and hardlinks without changing their targets" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try prepareDest(tmp);
    try tmp.dir.symLink(io, "../outside/marker", "dest/symbolic", .{});
    try tmp.dir.hardLink("outside/marker", tmp.dir, "dest/hard", io, .{});
    try extractEntries(tmp, &.{
        .{ .name = "symbolic", .content = "new symbolic destination" },
        .{ .name = "hard", .content = "new hardlink destination" },
    });
    try expectContents(tmp.dir, "dest/symbolic", "new symbolic destination");
    try expectContents(tmp.dir, "dest/hard", "new hardlink destination");
    try expectContents(tmp.dir, "outside/marker", "outside remains intact");
    // A later write proves the extracted file no longer aliases the old inode.
    try tmp.dir.writeFile(io, .{ .sub_path = "dest/hard", .data = "changed again" });
    try expectContents(tmp.dir, "outside/marker", "outside remains intact");
}

test "tar extraction follows internal relative and absolute directory symlinks" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try prepareDest(tmp);
    try extractEntries(tmp, &.{
        .{ .name = "real", .kind = .directory },
        .{ .name = "relative", .kind = .symlink, .content = "real" },
        .{ .name = "absolute", .kind = .symlink, .content = "/real" },
        .{ .name = "nested/up", .kind = .symlink, .content = "../real" },
        .{ .name = "relative/one", .content = "relative content" },
        .{ .name = "absolute/two", .content = "absolute content" },
        .{ .name = "nested/up/three", .content = "parent-relative content" },
    });
    try expectContents(tmp.dir, "dest/real/one", "relative content");
    try expectContents(tmp.dir, "dest/real/two", "absolute content");
    try expectContents(tmp.dir, "dest/real/three", "parent-relative content");
    try expectLink(tmp.dir, "dest/relative", "real");
    try expectLink(tmp.dir, "dest/absolute", "/real");
    try expectLink(tmp.dir, "dest/nested/up", "../real");
}

test "tar extraction supports duplicate files and ordinary normalized parent paths" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try prepareDest(tmp);
    try extractEntries(tmp, &.{
        .{ .name = ".", .kind = .directory },
        .{ .name = "./nested//dir/./file", .content = "first contents are longer" },
        .{ .name = "nested/dir/file", .content = "last" },
        .{ .name = "missing/parents/link", .kind = .symlink, .content = "/nested/dir/file" },
    });
    try expectContents(tmp.dir, "dest/nested/dir/file", "last");
    try expectLink(tmp.dir, "dest/missing/parents/link", "/nested/dir/file");
}

test "tar extraction rejects unsafe entry paths rather than silently skipping them" {
    for ([_][]const u8{ "/absolute", "../outside/marker", "safe/../../outside/marker" }) |name| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try prepareDest(tmp);
        try std.testing.expectError(error.UnsafeArchivePath, extractEntries(tmp, &.{.{ .name = name, .content = "unsafe" }}));
        try expectContents(tmp.dir, "outside/marker", "outside remains intact");
    }
}

test "tar extraction rejects relative symlink targets escaping the logical root" {
    const links = [_]Entry{
        .{ .name = "jump", .kind = .symlink, .content = "../outside" },
        .{ .name = "nested/jump", .kind = .symlink, .content = "../../outside" },
        .{ .name = "./jump", .kind = .symlink, .content = "../outside" },
        .{ .name = "nested//jump", .kind = .symlink, .content = "../../outside" },
    };
    for (links) |entry| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try prepareDest(tmp);
        try std.testing.expectError(error.UnsafeArchivePath, extractEntries(tmp, &.{entry}));
        try expectContents(tmp.dir, "outside/marker", "outside remains intact");
    }
}

test "tar extraction rejects NUL in a PAX path before filesystem access" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try prepareDest(tmp);
    var output: std.Io.Writer.Allocating = .init(alloc);
    defer output.deinit();
    const record = "17 path=bad\x00tail\n";
    // PAX lengths include the decimal length and trailing newline.
    try std.testing.expectEqual(@as(usize, 17), record.len);
    try writeRawHeader(&output.writer, "pax", 'x', record.len);
    try output.writer.writeAll(record);
    const padding: [512]u8 = @splat(0);
    try output.writer.writeAll(padding[0 .. 512 - record.len]);
    var tar: std.tar.Writer = .{ .underlying_writer = &output.writer };
    try tar.writeFileBytes("fallback", "must not be written", .{});
    try tar.finishPedantically();
    // std.tar rejects embedded NUL before it returns the PAX entry.
    try std.testing.expectError(error.PaxNullInValue, extractBytes(tmp, output.written()));
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "dest/bad", .{}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "dest/fallback", .{}));
}

test "tar truncated and oversized entries preserve the previous destination" {
    for ([_]u64{ 16384, extract.max_file_size + 1 }) |size| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try prepareDest(tmp);
        try tmp.dir.writeFile(io, .{ .sub_path = "dest/existing", .data = "previous complete file" });
        var output: std.Io.Writer.Allocating = .init(alloc);
        defer output.deinit();
        try writeRawHeader(&output.writer, "existing", '0', size);
        // Deliver one complete copy chunk before EOF, so rollback must also
        // discard a temporary file that already received replacement bytes.
        const partial_body: [8192 + 23]u8 = @splat('x');
        try output.writer.writeAll(&partial_body);
        if (size > extract.max_file_size) {
            try std.testing.expectError(error.FileTooBig, extractBytes(tmp, output.written()));
        } else {
            try expectFailure(extractBytes(tmp, output.written()));
        }
        try expectContents(tmp.dir, "dest/existing", "previous complete file");
        var dest = try tmp.dir.openDir(io, "dest", .{ .iterate = true });
        defer dest.close(io);
        var it = dest.iterate();
        var count: usize = 0;
        while (try it.next(io)) |entry| {
            try std.testing.expectEqualStrings("existing", entry.name);
            count += 1;
        }
        try std.testing.expectEqual(@as(usize, 1), count);
    }
}

test "tar symlink cycles and dangling parents fail without creating their targets" {
    for ([_]bool{ false, true }) |cycle| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try prepareDest(tmp);
        try expectFailure(extractEntries(tmp, &.{
            .{ .name = "a", .kind = .symlink, .content = "b" },
            .{ .name = "b", .kind = .symlink, .content = if (cycle) "a" else "missing" },
            .{ .name = "a/file", .content = "not reachable" },
        }));
        try expectLink(tmp.dir, "dest/a", "b");
        try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "dest/missing", .{}));
        try expectContents(tmp.dir, "outside/marker", "outside remains intact");
    }
}

test "gzip tar extraction uses the same confinement for archive-created symlinks" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try prepareDest(tmp);
    var outside_buf: [std.fs.max_path_bytes]u8 = undefined;
    const outside_len = try tmp.dir.realPathFile(io, "outside", &outside_buf);
    const tar_bytes = try archiveBytes(&.{
        .{ .name = "jump", .kind = .symlink, .content = outside_buf[0..outside_len] },
        .{ .name = "jump/marker", .content = "must not escape" },
    });
    defer alloc.free(tar_bytes);
    var output: std.Io.Writer.Allocating = .init(alloc);
    defer output.deinit();
    try output.ensureUnusedCapacity(64);
    const compressor = try alloc.create(std.compress.flate.Compress);
    defer alloc.destroy(compressor);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    compressor.* = try .init(&output.writer, &window, .gzip, .default);
    try compressor.writer.writeAll(tar_bytes);
    try compressor.finish();
    try tmp.dir.writeFile(io, .{ .sub_path = "input.tar.gz", .data = output.written() });
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_len = try tmp.dir.realPathFile(io, "input.tar.gz", &archive_buf);
    var dest_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dest_len = try tmp.dir.realPathFile(io, "dest", &dest_buf);
    try expectFailure(extract.extractTarGzFile(archive_buf[0..archive_len], dest_buf[0..dest_len], "gzip containment test"));
    try expectContents(tmp.dir, "outside/marker", "outside remains intact");
}
