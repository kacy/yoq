const std = @import("std");

const linux = std.os.linux;

const log = @import("log.zig");
const syscall = @import("syscall.zig");
const Metadata = @import("tar_metadata.zig").Metadata;

pub const max_file_size: u64 = 10 * 1024 * 1024 * 1024;

fn cwd() std.Io.Dir {
    return std.Io.Dir.cwd();
}

pub fn extractTarFile(tar_path: []const u8, dest_path: []const u8, context: []const u8) !void {
    var tar_file = try cwd().openFile(std.Options.debug_io, tar_path, .{});
    defer tar_file.close(std.Options.debug_io);

    var tar_read_buf: [4096]u8 = undefined;
    var tar_reader = tar_file.reader(std.Options.debug_io, &tar_read_buf);
    try extractTarReader(&tar_reader.interface, dest_path, context, false);
}

pub fn extractTarGzFile(gz_path: []const u8, dest_path: []const u8, context: []const u8) !void {
    return extractGzip(gz_path, dest_path, context, false);
}

/// Image layers carry container identities. Generic ADD archives deliberately
/// retain the caller's ownership policy instead of adopting archive owners.
pub fn extractImageLayer(gz_path: []const u8, dest_path: []const u8) !void {
    return extractGzip(gz_path, dest_path, "image layer", true);
}

fn extractGzip(gz_path: []const u8, dest_path: []const u8, context: []const u8, image_layer: bool) !void {
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

    try extractTarReader(&decompress.reader, dest_path, context, image_layer);

    // Drain the rest of the gzip stream so footer validation still runs
    // after the tar iterator stops at the logical end of archive entries.
    _ = try decompress.reader.discardRemaining();
}

fn extractTarReader(reader: *std.Io.Reader, dest_path: []const u8, context: []const u8, image_layer: bool) !void {
    // Rootless extraction cannot adopt arbitrary numeric owners. Preserve its
    // existing caller ownership; explicit USER still requires a usable mapping.
    const restore_owner = image_layer and linux.geteuid() == 0;
    var directory_path_bytes: usize = 0;
    var directories: std.StringHashMap(Metadata) = .init(std.heap.page_allocator);
    defer {
        var keys = directories.keyIterator();
        while (keys.next()) |key| std.heap.page_allocator.free(key.*);
        directories.deinit();
    }
    var dest_dir = try cwd().openDir(std.Options.debug_io, dest_path, .{});
    defer dest_dir.close(std.Options.debug_io);

    var file_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var normalized_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(reader, .{
        .file_name_buffer = &file_name_buffer,
        .link_name_buffer = &link_name_buffer,
    });

    while (try it.next()) |entry| {
        const name = normalizeTarPath(entry.name, &normalized_buffer) catch |err| {
            log.warn("{s}: rejecting unsafe archive path '{s}'", .{ context, entry.name });
            return err;
        };

        // Empty names and './' describe the archive root, never a file.
        if (name.len == 0) {
            if (entry.kind == .directory) continue;
            return error.UnsafeArchivePath;
        }

        switch (entry.kind) {
            .directory => {
                var dir = try ensureDirectory(dest_dir, name);
                dir.close(std.Options.debug_io);
                if (image_layer) {
                    const value = try Metadata.fromHeader(&it.header_buffer, entry.mode);
                    if (!directories.contains(name)) {
                        if (directories.count() >= 65536 or name.len > 16 * 1024 * 1024 - directory_path_bytes)
                            return error.DirectoryMetadataTooLarge;
                    }
                    const found = try directories.getOrPut(name);
                    if (!found.found_existing) {
                        found.key_ptr.* = std.heap.page_allocator.dupe(u8, name) catch |err| {
                            _ = directories.remove(name);
                            return err;
                        };
                    }
                    if (!found.found_existing) directory_path_bytes += name.len;
                    found.value_ptr.* = value;
                }
            },
            .file => {
                if (entry.size > max_file_size) return error.FileTooBig;
                const permissions = std.Io.File.Permissions.fromMode(@intCast(entry.mode & 0o777));
                var parent = try ensureParentDir(dest_dir, name);
                defer parent.close(std.Options.debug_io);

                // Never truncate an existing inode: it may be a symlink or a
                // hardlink to a file outside the extraction directory. Rename
                // replaces only the directory entry after a complete write.
                var file = try parent.createFileAtomic(std.Options.debug_io, std.fs.path.basename(name), .{
                    .permissions = permissions,
                    .replace = true,
                });
                defer file.deinit(std.Options.debug_io);
                try copyTarEntryToFile(&it, entry, file.file);
                if (image_layer) try (try Metadata.fromHeader(&it.header_buffer, entry.mode)).apply(file.file, restore_owner);
                try file.replace(std.Options.debug_io);
            },
            .sym_link => {
                if (!isSafeSymlinkTarget(name, entry.link_name)) {
                    log.warn("{s}: rejecting unsafe symlink '{s}' -> '{s}'", .{
                        context,
                        entry.name,
                        entry.link_name,
                    });
                    return error.UnsafeArchivePath;
                }
                var parent = try ensureParentDir(dest_dir, name);
                defer parent.close(std.Options.debug_io);
                try parent.symLink(std.Options.debug_io, entry.link_name, std.fs.path.basename(name), .{});
                if (restore_owner) {
                    const owner = try Metadata.fromHeader(&it.header_buffer, entry.mode);
                    const basename = try std.posix.toPosixPath(std.fs.path.basename(name));
                    if (linux.errno(linux.fchownat(parent.handle, &basename, owner.uid, owner.gid, linux.AT.SYMLINK_NOFOLLOW)) != .SUCCESS)
                        return error.SetOwnerFailed;
                }
            },
        }
    }
    // Apply directories deepest-first after contents are complete, so a mode
    // such as 0500 or 0000 cannot prevent extraction of its children. Keeping
    // only the last record gives duplicate directory headers their usual meaning.
    var names: std.ArrayList([]const u8) = .empty;
    defer names.deinit(std.heap.page_allocator);
    var keys = directories.keyIterator();
    while (keys.next()) |key| try names.append(std.heap.page_allocator, key.*);
    std.mem.sort([]const u8, names.items, {}, struct {
        fn deeper(_: void, left: []const u8, right: []const u8) bool {
            return left.len > right.len;
        }
    }.deeper);
    for (names.items) |name| {
        var dir = try openRootedDir(dest_dir, name);
        defer dir.close(std.Options.debug_io);
        try directories.get(name).?.apply(.{ .handle = dir.handle, .flags = .{ .nonblocking = false } }, restore_owner);
    }
}

pub fn isSafeTarPath(name: []const u8) bool {
    if (std.mem.indexOfScalar(u8, name, 0) != null) return false;
    if (name.len == 0) return true;
    if (name[0] == '/') return false;

    var it = std.mem.splitScalar(u8, name, '/');
    while (it.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return false;
    }

    return true;
}

pub fn isSafeSymlinkTarget(entry_path: []const u8, link_target: []const u8) bool {
    if (!isSafeTarPath(entry_path)) return false;
    if (link_target.len == 0 or std.mem.indexOfScalar(u8, link_target, 0) != null) return false;
    // Absolute links are normal in container images. Only rooted directory
    // resolution below may follow them, so '/' means the extraction root.
    if (link_target.len > 0 and link_target[0] == '/') return true;

    var parent_depth: isize = 0;
    var entry_it = std.mem.splitScalar(u8, entry_path, '/');
    var component_count: usize = 0;
    while (entry_it.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".")) continue;
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

fn normalizeTarPath(name: []const u8, buffer: []u8) ![]const u8 {
    if (!isSafeTarPath(name)) return error.UnsafeArchivePath;
    var len: usize = 0;
    var components = std.mem.tokenizeScalar(u8, name, '/');
    while (components.next()) |component| {
        if (std.mem.eql(u8, component, ".")) continue;
        const separator: usize = if (len == 0) 0 else 1;
        if (component.len + separator > buffer.len - len) return error.NameTooLong;
        if (separator != 0) {
            buffer[len] = '/';
            len += 1;
        }
        @memcpy(buffer[len..][0..component.len], component);
        len += component.len;
    }
    return buffer[0..len];
}

fn ensureParentDir(root: std.Io.Dir, name: []const u8) !std.Io.Dir {
    return ensureDirectory(root, std.fs.path.dirname(name) orelse "");
}

/// All paths here are normalized archive paths. Resolve each prefix against
/// the original root, not the previous directory: relative symlinks containing
/// '..' must keep their meaning, and absolute links must stay inside the root.
fn ensureDirectory(root: std.Io.Dir, path: []const u8) !std.Io.Dir {
    if (openRootedDir(root, if (path.len == 0) "." else path)) |dir| {
        return dir;
    } else |err| {
        if (err != error.FileNotFound) return err;
    }

    var dir = try openRootedDir(root, ".");
    errdefer dir.close(std.Options.debug_io);

    var components = std.mem.tokenizeScalar(u8, path, '/');
    while (components.next()) |component| {
        const prefix = path[0..components.index];
        const next = openRootedDir(root, prefix) catch |err| blk: {
            if (err != error.FileNotFound) return err;
            // mkdir receives a basename and a pinned parent, never an
            // unchecked multi-component archive path. A dangling symlink
            // causes the following rooted open to fail safely.
            dir.createDir(std.Options.debug_io, component, .default_dir) catch |mkdir_err| {
                if (mkdir_err != error.PathAlreadyExists) return mkdir_err;
            };
            break :blk try openRootedDir(root, prefix);
        };
        dir.close(std.Options.debug_io);
        dir = next;
    }
    return dir;
}

/// Linux 6.1+ is required by the runtime. Do not fall back to ordinary openat:
/// it would follow archive-controlled symlinks against the host filesystem.
fn openRootedDir(root: std.Io.Dir, path: []const u8) !std.Io.Dir {
    if (@import("builtin").os.tag != .linux) return error.OperationUnsupported;

    const OpenHow = extern struct { flags: u64, mode: u64 = 0, resolve: u64 };
    const resolve_no_magiclinks = 0x02;
    const resolve_in_root = 0x10;
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true };
    const how: OpenHow = .{
        .flags = @as(u32, @bitCast(flags)),
        .resolve = resolve_in_root | resolve_no_magiclinks,
    };
    const path_z = try std.posix.toPosixPath(path);
    while (true) {
        const rc = linux.syscall4(.openat2, @intCast(root.handle), @intFromPtr(&path_z), @intFromPtr(&how), @sizeOf(OpenHow));
        if (!syscall.isError(rc)) return .{ .handle = @intCast(rc) };
        switch (@as(linux.E, @enumFromInt(syscall.getErrno(rc)))) {
            .INTR => continue,
            .NOENT => return error.FileNotFound,
            .LOOP, .XDEV, .AGAIN => return error.UnsafeArchivePath,
            .NOSYS, .INVAL => return error.OperationUnsupported,
            else => return error.DirectoryOpenFailed,
        }
    }
}

test {
    _ = @import("tar_extract_tests.zig");
}
