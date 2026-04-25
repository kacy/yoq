const std = @import("std");

const log = @import("log.zig");

pub const max_file_size: u64 = 10 * 1024 * 1024 * 1024;

fn cwd() std.Io.Dir {
    return std.Io.Dir.cwd();
}

pub fn extractTarFile(tar_path: []const u8, dest_path: []const u8, context: []const u8) !void {
    var tar_file = try cwd().openFile(std.Options.debug_io, tar_path, .{});
    defer tar_file.close(std.Options.debug_io);

    var tar_read_buf: [4096]u8 = undefined;
    var tar_reader = tar_file.reader(std.Options.debug_io, &tar_read_buf);
    try extractTarReader(&tar_reader.interface, dest_path, context);
}

pub fn extractTarGzFile(gz_path: []const u8, dest_path: []const u8, context: []const u8) !void {
    var gz_file = try cwd().openFile(std.Options.debug_io, gz_path, .{});
    defer gz_file.close(std.Options.debug_io);

    var read_buf: [4096]u8 = undefined;
    var gz_reader = gz_file.reader(std.Options.debug_io, &read_buf);

    var decompress_buf: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress = std.compress.flate.Decompress.init(
        &gz_reader.interface,
        .gzip,
        &decompress_buf,
    );

    try extractTarReader(&decompress.reader, dest_path, context);

    // Drain the rest of the gzip stream so footer validation still runs
    // after the tar iterator stops at the logical end of archive entries.
    _ = try decompress.reader.discardRemaining();
}

fn extractTarReader(reader: *std.Io.Reader, dest_path: []const u8, context: []const u8) !void {
    var dest_dir = try cwd().openDir(std.Options.debug_io, dest_path, .{});
    defer dest_dir.close(std.Options.debug_io);

    var file_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(reader, .{
        .file_name_buffer = &file_name_buffer,
        .link_name_buffer = &link_name_buffer,
    });

    while (try it.next()) |entry| {
        if (!isSafeTarPath(entry.name)) {
            log.warn("{s}: skipping unsafe archive path '{s}'", .{ context, entry.name });
            continue;
        }

        switch (entry.kind) {
            .directory => {
                if (entry.name.len > 0) try dest_dir.createDirPath(std.Options.debug_io, entry.name);
            },
            .file => {
                const permissions = std.Io.File.Permissions.fromMode(@intCast(entry.mode & 0o777));
                var fs_file = try createDirAndFile(dest_dir, entry.name, permissions);
                defer fs_file.close(std.Options.debug_io);
                try copyTarEntryToFile(&it, entry, fs_file);
            },
            .sym_link => {
                if (!isSafeSymlinkTarget(entry.name, entry.link_name)) {
                    log.warn("{s}: skipping unsafe symlink '{s}' -> '{s}'", .{
                        context,
                        entry.name,
                        entry.link_name,
                    });
                    continue;
                }
                try createDirAndSymlink(dest_dir, entry.link_name, entry.name);
            },
        }
    }
}

pub fn isSafeTarPath(name: []const u8) bool {
    if (name.len == 0) return true;
    if (name[0] == '/') return false;

    var it = std.mem.splitScalar(u8, name, '/');
    while (it.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return false;
    }

    return true;
}

pub fn isSafeSymlinkTarget(entry_path: []const u8, link_target: []const u8) bool {
    if (link_target.len > 0 and link_target[0] == '/') return true;

    var parent_depth: isize = 0;
    var entry_it = std.mem.splitScalar(u8, entry_path, '/');
    var component_count: usize = 0;
    while (entry_it.next()) |_| {
        component_count += 1;
    }
    if (component_count > 0) {
        parent_depth = @intCast(component_count - 1);
    }

    var depth = parent_depth;
    var link_it = std.mem.splitScalar(u8, link_target, '/');
    while (link_it.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".")) continue;
        if (std.mem.eql(u8, component, "..")) {
            depth -= 1;
            if (depth < 0) return false;
        } else {
            depth += 1;
        }
    }

    return true;
}

fn copyTarEntryToFile(it: *std.tar.Iterator, entry: std.tar.Iterator.File, fs_file: std.Io.File) !void {
    if (entry.size > max_file_size) {
        log.warn("tar entry exceeds max file size ({d} bytes): skipping", .{entry.size});
        return error.FileTooBig;
    }

    var remaining = entry.size;
    var buf: [8192]u8 = undefined;
    while (remaining > 0) {
        const chunk_len: usize = @intCast(@min(remaining, buf.len));
        try it.reader.readSliceAll(buf[0..chunk_len]);
        try fs_file.writeStreamingAll(std.Options.debug_io, buf[0..chunk_len]);
        remaining -= chunk_len;
    }

    it.unread_file_bytes = 0;
}

fn createDirAndFile(dir: std.Io.Dir, name: []const u8, permissions: std.Io.File.Permissions) !std.Io.File {
    return dir.createFile(std.Options.debug_io, name, .{ .permissions = permissions }) catch |err| {
        if (err == error.FileNotFound) {
            if (std.fs.path.dirname(name)) |dir_name| {
                try dir.createDirPath(std.Options.debug_io, dir_name);
                return try dir.createFile(std.Options.debug_io, name, .{ .permissions = permissions });
            }
        }
        return err;
    };
}

fn createDirAndSymlink(dir: std.Io.Dir, link_name: []const u8, file_name: []const u8) !void {
    dir.symLink(std.Options.debug_io, link_name, file_name, .{}) catch |err| {
        if (err == error.FileNotFound) {
            if (std.fs.path.dirname(file_name)) |dir_name| {
                try dir.createDirPath(std.Options.debug_io, dir_name);
                return try dir.symLink(std.Options.debug_io, link_name, file_name, .{});
            }
        }
        return err;
    };
}
