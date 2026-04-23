const std = @import("std");

/// Linux platform boundary for blocking OS primitives and filesystem adapters.
/// Generic formatting or buffer-writing helpers belong in library support
/// modules, not here.
pub const net = struct {
    pub const Address = extern union {
        any: std.posix.sockaddr,
        in: std.posix.sockaddr.in,
        in6: std.posix.sockaddr.in6,

        pub fn initIp4(addr: [4]u8, port: u16) Address {
            return .{ .in = .{
                .family = std.posix.AF.INET,
                .port = std.mem.nativeToBig(u16, port),
                .addr = @bitCast(addr),
                .zero = [_]u8{0} ** 8,
            } };
        }

        pub fn getOsSockLen(self: Address) std.posix.socklen_t {
            return switch (self.any.family) {
                std.posix.AF.INET => @sizeOf(std.posix.sockaddr.in),
                std.posix.AF.INET6 => @sizeOf(std.posix.sockaddr.in6),
                else => @sizeOf(std.posix.sockaddr),
            };
        }
    };
};

pub fn timestamp() i64 {
    return @intCast(@divTrunc(realTimeNanos(), std.time.ns_per_s));
}

pub fn milliTimestamp() i64 {
    return @intCast(@divTrunc(realTimeNanos(), std.time.ns_per_ms));
}

pub fn nanoTimestamp() i128 {
    return realTimeNanos();
}

pub fn sleep(ns: u64) void {
    var remaining = std.os.linux.timespec{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    while (true) {
        var next: std.os.linux.timespec = undefined;
        const rc = std.os.linux.nanosleep(&remaining, &next);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => return,
            .INTR => remaining = next,
            else => return,
        }
    }
}

pub fn randomBytes(buffer: []u8) void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        const rc = std.os.linux.getrandom(buffer.ptr + offset, buffer.len - offset, 0);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) unreachable;
                offset += rc;
            },
            .INTR => {},
            else => unreachable,
        }
    }
}

pub fn randomInt(comptime T: type) T {
    var bytes: [@sizeOf(T)]u8 = undefined;
    randomBytes(&bytes);
    return @bitCast(bytes);
}

pub fn intToEnum(comptime T: type, value: anytype) !T {
    const int_value = @as(std.meta.Int(.unsigned, @bitSizeOf(@typeInfo(T).@"enum".tag_type)), @intCast(value));
    inline for (@typeInfo(T).@"enum".fields) |field| {
        if (field.value == int_value) return @enumFromInt(field.value);
    }
    return error.InvalidEnumTag;
}

pub fn isatty(fd: std.posix.fd_t) bool {
    _ = std.posix.tcgetattr(fd) catch return false;
    return true;
}

pub fn getenv(name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (std.c.environ[i]) |entry| : (i += 1) {
        const raw = std.mem.span(entry);
        const eq = std.mem.indexOfScalar(u8, raw, '=') orelse continue;
        if (std.mem.eql(u8, raw[0..eq], name)) return raw[eq + 1 ..];
    }
    return null;
}

pub fn getEnvVarOwned(alloc: std.mem.Allocator, name: []const u8) (std.mem.Allocator.Error || error{ EnvironmentVariableNotFound, Unexpected })![]u8 {
    const value = getenv(name) orelse return error.EnvironmentVariableNotFound;
    return alloc.dupe(u8, value);
}

pub fn getCwd(buffer: []u8) ![]u8 {
    const rc = std.os.linux.getcwd(buffer.ptr, buffer.len);
    return switch (std.os.linux.errno(rc)) {
        .SUCCESS => if (rc > 0) buffer[0 .. rc - 1] else error.CurrentDirUnlinked,
        .RANGE => error.NameTooLong,
        .NOENT => error.CurrentDirUnlinked,
        else => error.Unexpected,
    };
}

pub fn selfExePathAlloc(alloc: std.mem.Allocator) ![:0]u8 {
    var size: usize = 256;
    while (size <= 64 * 1024) : (size *= 2) {
        const buffer = try alloc.alloc(u8, size);
        defer alloc.free(buffer);

        const rc = std.os.linux.readlink("/proc/self/exe", buffer.ptr, buffer.len);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {
                if (rc < buffer.len) {
                    return alloc.dupeZ(u8, buffer[0..rc]);
                }
            },
            .NOENT => return error.FileNotFound,
            .ACCES, .PERM => return error.AccessDenied,
            else => return error.Unexpected,
        }
    }
    return error.NameTooLong;
}

fn realTimeNanos() i128 {
    var ts: std.os.linux.timespec = undefined;
    const rc = std.os.linux.clock_gettime(.REALTIME, &ts);
    if (std.os.linux.errno(rc) != .SUCCESS) return 0;
    return (@as(i128, ts.sec) * std.time.ns_per_s) + ts.nsec;
}

pub const Mutex = struct {
    inner: std.c.pthread_mutex_t = std.c.PTHREAD_MUTEX_INITIALIZER,

    pub fn lock(self: *Mutex) void {
        if (std.c.pthread_mutex_lock(&self.inner) != .SUCCESS) unreachable;
    }

    pub fn unlock(self: *Mutex) void {
        if (std.c.pthread_mutex_unlock(&self.inner) != .SUCCESS) unreachable;
    }
};

pub const Semaphore = struct {
    mutex: std.c.pthread_mutex_t = std.c.PTHREAD_MUTEX_INITIALIZER,
    cond: std.c.pthread_cond_t = std.c.PTHREAD_COND_INITIALIZER,
    permits: usize = 0,

    pub fn post(self: *Semaphore) void {
        if (std.c.pthread_mutex_lock(&self.mutex) != .SUCCESS) unreachable;
        self.permits += 1;
        if (std.c.pthread_cond_signal(&self.cond) != .SUCCESS) unreachable;
        if (std.c.pthread_mutex_unlock(&self.mutex) != .SUCCESS) unreachable;
    }

    pub fn wait(self: *Semaphore) void {
        if (std.c.pthread_mutex_lock(&self.mutex) != .SUCCESS) unreachable;
        defer if (std.c.pthread_mutex_unlock(&self.mutex) != .SUCCESS) unreachable;

        while (self.permits == 0) {
            if (std.c.pthread_cond_wait(&self.cond, &self.mutex) != .SUCCESS) unreachable;
        }
        self.permits -= 1;
    }
};

fn linuxVoid(rc: usize) !void {
    return switch (std.os.linux.errno(rc)) {
        .SUCCESS => {},
        .ACCES => error.AccessDenied,
        .AGAIN => error.WouldBlock,
        .BADF => error.FileNotFound,
        .EXIST => error.PathAlreadyExists,
        .INVAL => error.InvalidArgument,
        .ISDIR => error.IsDir,
        .LOOP => error.SymLinkLoop,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NAMETOOLONG => error.NameTooLong,
        .NFILE => error.SystemFdQuotaExceeded,
        .NOENT => error.FileNotFound,
        .NOMEM => error.SystemResources,
        .NOTEMPTY => error.DirNotEmpty,
        .NOSPC => error.NoSpaceLeft,
        .NOTDIR => error.NotDir,
        .PERM => error.PermissionDenied,
        .ROFS => error.ReadOnlyFileSystem,
        else => error.Unexpected,
    };
}

fn linuxUsize(rc: usize) !usize {
    return switch (std.os.linux.errno(rc)) {
        .SUCCESS => rc,
        .ACCES => error.AccessDenied,
        .AGAIN => error.WouldBlock,
        .BADF => error.FileNotFound,
        .EXIST => error.PathAlreadyExists,
        .INVAL => error.InvalidArgument,
        .ISDIR => error.IsDir,
        .LOOP => error.SymLinkLoop,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NAMETOOLONG => error.NameTooLong,
        .NFILE => error.SystemFdQuotaExceeded,
        .NOENT => error.FileNotFound,
        .NOMEM => error.SystemResources,
        .NOTEMPTY => error.DirNotEmpty,
        .NOSPC => error.NoSpaceLeft,
        .NOTDIR => error.NotDir,
        .PERM => error.PermissionDenied,
        .ROFS => error.ReadOnlyFileSystem,
        else => error.Unexpected,
    };
}

fn fileStat(fd: std.posix.fd_t) !File.Stat {
    var statx: std.os.linux.Statx = undefined;
    try linuxVoid(std.os.linux.statx(
        fd,
        "",
        std.os.linux.AT.EMPTY_PATH,
        .{ .TYPE = true, .MODE = true, .SIZE = true, .MTIME = true },
        &statx,
    ));
    return statFromLinux(&statx);
}

fn statFromLinux(statx: *const std.os.linux.Statx) File.Stat {
    return .{
        .size = statx.size,
        .mode = statx.mode,
        .mtime = (@as(i128, statx.mtime.sec) * std.time.ns_per_s) + statx.mtime.nsec,
        .kind = kindFromMode(statx.mode),
        .permissions = .fromMode(statx.mode & 0o777),
    };
}

fn realpathFd(fd: std.posix.fd_t, buffer: []u8) ![]u8 {
    var proc_path_buf: [64]u8 = undefined;
    const proc_path = try std.fmt.bufPrintZ(&proc_path_buf, "/proc/self/fd/{d}", .{fd});
    const len = try linuxUsize(std.os.linux.readlink(proc_path, buffer.ptr, buffer.len));
    if (len == buffer.len) return error.NameTooLong;
    return buffer[0..len];
}

fn realpathFdAlloc(alloc: std.mem.Allocator, fd: std.posix.fd_t) ![:0]u8 {
    var size: usize = 256;
    while (size <= 64 * 1024) : (size *= 2) {
        const buffer = try alloc.alloc(u8, size);
        defer alloc.free(buffer);
        const path = realpathFd(fd, buffer) catch |err| switch (err) {
            error.NameTooLong => {
                continue;
            },
            else => |e| return e,
        };
        return alloc.dupeZ(u8, path);
    }
    return error.NameTooLong;
}

fn kindFromMode(mode: std.posix.mode_t) std.Io.File.Kind {
    return switch (mode & std.os.linux.S.IFMT) {
        std.os.linux.S.IFBLK => .block_device,
        std.os.linux.S.IFCHR => .character_device,
        std.os.linux.S.IFDIR => .directory,
        std.os.linux.S.IFIFO => .named_pipe,
        std.os.linux.S.IFLNK => .sym_link,
        std.os.linux.S.IFREG => .file,
        std.os.linux.S.IFSOCK => .unix_domain_socket,
        else => .unknown,
    };
}

pub const File = struct {
    pub const Mode = std.posix.mode_t;
    pub const Stat = struct {
        size: u64,
        mode: std.posix.mode_t,
        mtime: i128,
        kind: std.Io.File.Kind,
        permissions: std.Io.File.Permissions,
    };

    handle: std.Io.File.Handle,
    flags: std.Io.File.Flags = .{ .nonblocking = false },

    pub fn from(file: std.Io.File) File {
        return .{ .handle = file.handle, .flags = file.flags };
    }

    fn inner(self: File) std.Io.File {
        return .{ .handle = self.handle, .flags = self.flags };
    }

    pub fn stdin() File {
        return from(std.Io.File.stdin());
    }

    pub fn stdout() File {
        return from(std.Io.File.stdout());
    }

    pub fn stderr() File {
        return from(std.Io.File.stderr());
    }

    pub fn close(self: File) void {
        if (self.handle >= 0 and self.handle > 2) posix.close(self.handle);
    }

    pub fn writer(self: File, buffer: []u8) Writer {
        return Writer.init(self, buffer);
    }

    pub fn reader(self: File, buffer: []u8) Reader {
        return Reader.init(self, buffer);
    }

    pub fn writeAll(self: File, bytes: []const u8) !void {
        var offset: usize = 0;
        while (offset < bytes.len) {
            const written = try posix.write(self.handle, bytes[offset..]);
            if (written == 0) return error.WriteFailed;
            offset += written;
        }
    }

    pub fn read(self: File, buffer: []u8) !usize {
        return posix.read(self.handle, buffer);
    }

    pub fn readToEndAlloc(self: File, alloc: std.mem.Allocator, max_bytes: usize) ![]u8 {
        var result: std.ArrayList(u8) = .empty;
        errdefer result.deinit(alloc);

        var buffer: [4096]u8 = undefined;
        while (true) {
            const bytes_read = try self.read(&buffer);
            if (bytes_read == 0) break;
            if (result.items.len + bytes_read > max_bytes) return error.StreamTooLong;
            try result.appendSlice(alloc, buffer[0..bytes_read]);
        }

        return result.toOwnedSlice(alloc);
    }

    pub fn readAll(self: File, buffer: []u8) !usize {
        var total: usize = 0;
        while (total < buffer.len) {
            const n = try self.read(buffer[total..]);
            if (n == 0) break;
            total += n;
        }
        return total;
    }

    pub fn sync(self: File) !void {
        return linuxVoid(std.os.linux.fsync(self.handle));
    }

    pub fn stat(self: File) !Stat {
        return fileStat(self.handle);
    }

    pub fn getEndPos(self: File) !u64 {
        return (try self.stat()).size;
    }

    pub fn seekTo(self: File, offset: u64) !void {
        _ = try posix.lseek(self.handle, @intCast(offset), std.os.linux.SEEK.SET);
    }

    pub fn getPos(self: File) !u64 {
        return @intCast(try posix.lseek(self.handle, 0, std.os.linux.SEEK.CUR));
    }

    pub fn textWriter(self: File) TextWriter {
        return .{ .file = self };
    }

    pub fn textReader(self: File) TextReader {
        return .{ .file = self };
    }

    pub const TextWriter = struct {
        file: File,

        pub fn print(self: TextWriter, comptime fmt: []const u8, args: anytype) !void {
            var buffer: [4096]u8 = undefined;
            var out = self.file.writer(&buffer);
            try out.interface.print(fmt, args);
            try out.flush();
        }
    };

    pub const TextReader = struct {
        file: File,

        pub fn readUntilDelimiterOrEof(self: TextReader, buffer: []u8, delimiter: u8) !?[]u8 {
            var len: usize = 0;
            while (len < buffer.len) {
                var byte: [1]u8 = undefined;
                const n = try self.file.read(&byte);
                if (n == 0) break;
                if (byte[0] == delimiter) break;
                buffer[len] = byte[0];
                len += 1;
            }
            if (len == 0) return null;
            return buffer[0..len];
        }
    };

    pub const Writer = struct {
        file: File,
        interface: std.Io.Writer,

        fn init(file: File, buffer: []u8) Writer {
            return .{
                .file = file,
                .interface = .{
                    .vtable = &.{
                        .drain = drain,
                        .sendFile = sendFile,
                    },
                    .buffer = buffer,
                },
            };
        }

        pub fn flush(self: *Writer) std.Io.Writer.Error!void {
            return self.interface.flush();
        }

        fn drain(io_writer: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            const self: *Writer = @alignCast(@fieldParentPtr("interface", io_writer));
            const buffered = io_writer.buffered();
            self.file.writeAll(buffered) catch return error.WriteFailed;
            io_writer.end = 0;

            var consumed: usize = 0;
            if (data.len == 0) return consumed;
            for (data, 0..) |chunk, i| {
                const repeats: usize = if (i == data.len - 1) splat else 1;
                for (0..repeats) |_| {
                    self.file.writeAll(chunk) catch return error.WriteFailed;
                    consumed += chunk.len;
                }
            }
            return consumed;
        }

        fn sendFile(io_writer: *std.Io.Writer, file_reader: *std.Io.File.Reader, limit: std.Io.Limit) std.Io.Writer.FileError!usize {
            _ = io_writer;
            _ = file_reader;
            _ = limit;
            return error.Unimplemented;
        }
    };

    pub const Reader = struct {
        file: File,
        interface: std.Io.Reader,

        fn init(file: File, buffer: []u8) Reader {
            return .{
                .file = file,
                .interface = .{
                    .vtable = &.{
                        .stream = stream,
                        .readVec = readVec,
                    },
                    .buffer = buffer,
                    .seek = 0,
                    .end = 0,
                },
            };
        }

        fn stream(io_reader: *std.Io.Reader, sink: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
            const self: *Reader = @alignCast(@fieldParentPtr("interface", io_reader));
            var scratch: [8192]u8 = undefined;
            const target = limit.slice(&scratch);
            if (target.len == 0) return 0;

            const bytes_read = self.file.read(target) catch return error.ReadFailed;
            if (bytes_read == 0) return error.EndOfStream;
            sink.writeAll(target[0..bytes_read]) catch return error.WriteFailed;
            return bytes_read;
        }

        fn readVec(io_reader: *std.Io.Reader, data: [][]u8) std.Io.Reader.Error!usize {
            const self: *Reader = @alignCast(@fieldParentPtr("interface", io_reader));
            if (data.len == 0) return 0;

            if (data[0].len == 0) {
                const bytes_read = self.file.read(io_reader.buffer) catch return error.ReadFailed;
                if (bytes_read == 0) return error.EndOfStream;
                io_reader.seek = 0;
                io_reader.end = bytes_read;
                return 0;
            }

            var total: usize = 0;
            for (data) |buffer| {
                if (buffer.len == 0) continue;
                const bytes_read = self.file.read(buffer) catch return error.ReadFailed;
                if (bytes_read == 0) {
                    if (total == 0) return error.EndOfStream;
                    break;
                }
                total += bytes_read;
                if (bytes_read < buffer.len) break;
            }
            return total;
        }
    };
};

pub const Dir = struct {
    pub const Walker = struct {
        stack: std.ArrayList(StackItem),
        name_buffer: std.ArrayList(u8),
        allocator: std.mem.Allocator,

        const StackItem = struct {
            iter: Iterator,
            dirname_len: usize,
            close_on_deinit: bool,
        };

        pub const Entry = struct {
            dir: Dir,
            basename: [:0]const u8,
            path: [:0]const u8,
            kind: std.Io.File.Kind,

            pub fn depth(self: Walker.Entry) usize {
                return std.mem.countScalar(u8, self.path, std.fs.path.sep) + 1;
            }
        };

        pub fn deinit(self: *Walker) void {
            for (self.stack.items) |item| {
                if (item.close_on_deinit) item.iter.dir.close();
            }
            self.name_buffer.deinit(self.allocator);
            self.stack.deinit(self.allocator);
        }

        pub fn next(self: *Walker) !?Walker.Entry {
            while (self.stack.items.len > 0) {
                const top = &self.stack.items[self.stack.items.len - 1];
                var dirname_len = top.dirname_len;
                if (try top.iter.next()) |entry| {
                    self.name_buffer.shrinkRetainingCapacity(dirname_len);
                    if (self.name_buffer.items.len != 0) {
                        try self.name_buffer.append(self.allocator, std.fs.path.sep);
                        dirname_len += 1;
                    }
                    try self.name_buffer.ensureUnusedCapacity(self.allocator, entry.name.len + 1);
                    self.name_buffer.appendSliceAssumeCapacity(entry.name);
                    self.name_buffer.appendAssumeCapacity(0);
                    const walker_entry: Walker.Entry = .{
                        .dir = top.iter.dir,
                        .basename = self.name_buffer.items[dirname_len .. self.name_buffer.items.len - 1 :0],
                        .path = self.name_buffer.items[0 .. self.name_buffer.items.len - 1 :0],
                        .kind = entry.kind,
                    };
                    if (entry.kind == .directory) {
                        var subdir = try walker_entry.dir.openDir(walker_entry.basename, .{ .iterate = true });
                        errdefer subdir.close();
                        try self.stack.append(self.allocator, .{
                            .iter = subdir.iterate(),
                            .dirname_len = self.name_buffer.items.len - 1,
                            .close_on_deinit = true,
                        });
                    }
                    return walker_entry;
                }

                const item = self.stack.pop().?;
                if (item.close_on_deinit) item.iter.dir.close();
            }
            return null;
        }
    };
    pub const Entry = std.Io.Dir.Entry;
    pub const Stat = File.Stat;
    pub const OpenOptions = std.Io.Dir.OpenOptions;
    pub const OpenFileOptions = std.Io.Dir.OpenFileOptions;
    pub const AccessOptions = std.Io.Dir.AccessOptions;
    pub const CreateFileOptions = struct {
        read: bool = false,
        truncate: bool = true,
        exclusive: bool = false,
        mode: File.Mode = 0o666,
    };

    inner: std.Io.Dir,

    pub fn from(dir: std.Io.Dir) Dir {
        return .{ .inner = dir };
    }

    pub fn close(self: Dir) void {
        if (self.inner.handle != std.posix.AT.FDCWD) posix.close(self.inner.handle);
    }

    pub fn access(self: Dir, path: []const u8, options: std.Io.Dir.AccessOptions) !void {
        _ = options;
        _ = try self.statFile(path);
    }

    pub fn makeDir(self: Dir, path: []const u8) !void {
        const path_z = try std.posix.toPosixPath(path);
        try linuxVoid(std.os.linux.mkdirat(self.inner.handle, &path_z, 0o777));
    }

    pub fn makePath(self: Dir, path: []const u8) !void {
        if (path.len == 0) return;
        var i: usize = 0;
        while (i < path.len) {
            while (i < path.len and path[i] == std.fs.path.sep) i += 1;
            const start = i;
            while (i < path.len and path[i] != std.fs.path.sep) i += 1;
            if (i == start) continue;
            const sub_path = path[0..i];
            self.makeDir(sub_path) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => |e| return e,
            };
        }
    }

    pub fn deleteDir(self: Dir, path: []const u8) !void {
        const path_z = try std.posix.toPosixPath(path);
        try linuxVoid(std.os.linux.unlinkat(self.inner.handle, &path_z, std.os.linux.AT.REMOVEDIR));
    }

    pub fn deleteFile(self: Dir, path: []const u8) !void {
        const path_z = try std.posix.toPosixPath(path);
        try linuxVoid(std.os.linux.unlinkat(self.inner.handle, &path_z, 0));
    }

    pub fn deleteTree(self: Dir, path: []const u8) !void {
        const stat = self.statFile(path) catch |err| switch (err) {
            error.FileNotFound => return,
            else => |e| return e,
        };
        if (stat.kind != .directory) return self.deleteFile(path);

        var dir = try self.openDir(path, .{ .iterate = true });
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .directory) {
                try dir.deleteTree(entry.name);
            } else {
                try dir.deleteFile(entry.name);
            }
        }
        try self.deleteDir(path);
    }

    pub fn openFile(self: Dir, path: []const u8, options: std.Io.Dir.OpenFileOptions) !File {
        var flags: std.posix.O = .{
            .ACCMODE = switch (options.mode) {
                .read_only => .RDONLY,
                .write_only => .WRONLY,
                .read_write => .RDWR,
            },
            .NOFOLLOW = !options.follow_symlinks,
        };
        if (@hasField(std.posix.O, "CLOEXEC")) flags.CLOEXEC = true;
        if (@hasField(std.posix.O, "LARGEFILE")) flags.LARGEFILE = true;
        if (@hasField(std.posix.O, "NOCTTY")) flags.NOCTTY = !options.allow_ctty;
        if (@hasField(std.posix.O, "PATH")) flags.PATH = options.path_only;
        const fd = try std.posix.openat(self.inner.handle, path, flags, 0);
        return .{ .handle = fd, .flags = .{ .nonblocking = false } };
    }

    pub fn createFile(self: Dir, path: []const u8, options: CreateFileOptions) !File {
        var flags: std.posix.O = .{
            .ACCMODE = if (options.read) .RDWR else .WRONLY,
            .CREAT = true,
            .TRUNC = options.truncate,
            .EXCL = options.exclusive,
        };
        if (@hasField(std.posix.O, "CLOEXEC")) flags.CLOEXEC = true;
        if (@hasField(std.posix.O, "LARGEFILE")) flags.LARGEFILE = true;
        const fd = try std.posix.openat(self.inner.handle, path, flags, options.mode);
        return .{ .handle = fd, .flags = .{ .nonblocking = false } };
    }

    pub fn writeFile(self: Dir, args: anytype) !void {
        const file = try self.createFile(args.sub_path, .{});
        defer file.close();
        try file.writeAll(args.data);
    }

    pub fn openDir(self: Dir, path: []const u8, options: std.Io.Dir.OpenOptions) !Dir {
        var flags: std.posix.O = .{
            .ACCMODE = .RDONLY,
            .DIRECTORY = true,
            .NOFOLLOW = !options.follow_symlinks,
        };
        if (@hasField(std.posix.O, "CLOEXEC")) flags.CLOEXEC = true;
        if (@hasField(std.posix.O, "PATH") and !options.iterate) flags.PATH = true;
        const fd = try std.posix.openat(self.inner.handle, path, flags, 0);
        return .{ .inner = .{ .handle = fd } };
    }

    pub fn statFile(self: Dir, path: []const u8) !Stat {
        const path_z = try std.posix.toPosixPath(path);
        var statx: std.os.linux.Statx = undefined;
        try linuxVoid(std.os.linux.statx(
            self.inner.handle,
            &path_z,
            std.os.linux.AT.SYMLINK_NOFOLLOW,
            .{ .TYPE = true, .MODE = true, .SIZE = true, .MTIME = true },
            &statx,
        ));
        return statFromLinux(&statx);
    }

    pub fn readFile(self: Dir, path: []const u8, buffer: []u8) ![]u8 {
        const file = try self.openFile(path, .{});
        defer file.close();
        const len = try file.readAll(buffer);
        return buffer[0..len];
    }

    pub fn readFileAlloc(self: Dir, alloc: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
        const file = try self.openFile(path, .{});
        defer file.close();
        return file.readToEndAlloc(alloc, max_bytes);
    }

    pub fn readLink(self: Dir, path: []const u8, buffer: []u8) ![]u8 {
        const path_z = try std.posix.toPosixPath(path);
        const len = try linuxUsize(std.os.linux.readlinkat(self.inner.handle, &path_z, buffer.ptr, buffer.len));
        return buffer[0..len];
    }

    pub fn copyFile(self: Dir, source_path: []const u8, dest_dir: Dir, dest_path: []const u8, options: std.Io.Dir.CopyFileOptions) !void {
        const source = try self.openFile(source_path, .{});
        defer source.close();
        const mode = if (options.permissions) |permissions| permissions.toMode() else 0o666;
        const dest = try dest_dir.createFile(dest_path, .{ .mode = mode });
        defer dest.close();
        var buffer: [64 * 1024]u8 = undefined;
        while (true) {
            const n = try source.read(&buffer);
            if (n == 0) break;
            try dest.writeAll(buffer[0..n]);
        }
    }

    pub fn symLink(self: Dir, target_path: []const u8, sym_link_path: []const u8, flags: std.Io.Dir.SymLinkFlags) !void {
        _ = flags;
        const target_z = try std.posix.toPosixPath(target_path);
        const link_z = try std.posix.toPosixPath(sym_link_path);
        try linuxVoid(std.os.linux.symlinkat(&target_z, self.inner.handle, &link_z));
    }

    pub fn realpath(self: Dir, path: []const u8, buffer: []u8) ![]u8 {
        const file = try self.openFile(path, .{ .path_only = true });
        defer file.close();
        return realpathFd(file.handle, buffer);
    }

    pub fn realpathAlloc(self: Dir, alloc: std.mem.Allocator, path: []const u8) ![:0]u8 {
        const file = try self.openFile(path, .{ .path_only = true });
        defer file.close();
        return realpathFdAlloc(alloc, file.handle);
    }

    pub fn rename(self: Dir, old_path: []const u8, new_path: []const u8) !void {
        const old_z = try std.posix.toPosixPath(old_path);
        const new_z = try std.posix.toPosixPath(new_path);
        try linuxVoid(std.os.linux.renameat(self.inner.handle, &old_z, self.inner.handle, &new_z));
    }

    pub fn iterate(self: Dir) Iterator {
        return .{ .dir = self };
    }

    pub fn walk(self: Dir, alloc: std.mem.Allocator) !Walker {
        var stack: std.ArrayList(Walker.StackItem) = .empty;
        try stack.append(alloc, .{
            .iter = self.iterate(),
            .dirname_len = 0,
            .close_on_deinit = false,
        });
        return .{
            .stack = stack,
            .name_buffer = .empty,
            .allocator = alloc,
        };
    }

    pub const Iterator = struct {
        dir: Dir,
        state: enum { reset, reading, finished } = .reset,
        buffer: [2048]u8 align(@alignOf(usize)) = undefined,
        index: usize = 0,
        end: usize = 0,

        pub fn next(self: *Iterator) !?std.Io.Dir.Entry {
            while (true) {
                if (self.end - self.index == 0) {
                    if (self.state == .finished) return null;
                    if (self.state == .reset) {
                        _ = posix.lseek(self.dir.inner.handle, 0, std.os.linux.SEEK.SET) catch {};
                        self.state = .reading;
                    }
                    const n = try linuxUsize(std.os.linux.getdents64(self.dir.inner.handle, &self.buffer, self.buffer.len));
                    if (n == 0) {
                        self.state = .finished;
                        return null;
                    }
                    self.index = 0;
                    self.end = n;
                }

                const linux_entry: *align(1) std.os.linux.dirent64 = @ptrCast(&self.buffer[self.index]);
                self.index += linux_entry.reclen;
                const name_ptr: [*]u8 = &linux_entry.name;
                const padded_name = name_ptr[0 .. linux_entry.reclen - @offsetOf(std.os.linux.dirent64, "name")];
                const name_len = std.mem.findScalar(u8, padded_name, 0).?;
                const name = name_ptr[0..name_len :0];
                if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;

                return .{
                    .name = name,
                    .kind = switch (linux_entry.type) {
                        std.os.linux.DT.BLK => .block_device,
                        std.os.linux.DT.CHR => .character_device,
                        std.os.linux.DT.DIR => .directory,
                        std.os.linux.DT.FIFO => .named_pipe,
                        std.os.linux.DT.LNK => .sym_link,
                        std.os.linux.DT.REG => .file,
                        std.os.linux.DT.SOCK => .unix_domain_socket,
                        else => .unknown,
                    },
                    .inode = linux_entry.ino,
                };
            }
        }
    };
};

pub fn cwd() Dir {
    return Dir.from(std.Io.Dir.cwd());
}

pub fn openDirAbsolute(path: []const u8, options: std.Io.Dir.OpenOptions) !Dir {
    return cwd().openDir(path, options);
}

pub fn openFileAbsolute(path: []const u8, options: std.Io.Dir.OpenFileOptions) !File {
    return cwd().openFile(path, options);
}

pub fn createFileAbsolute(path: []const u8, options: Dir.CreateFileOptions) !File {
    return cwd().createFile(path, options);
}

pub fn accessAbsolute(path: []const u8, options: std.Io.Dir.AccessOptions) !void {
    return cwd().access(path, options);
}

pub fn deleteFileAbsolute(path: []const u8) !void {
    return cwd().deleteFile(path);
}

pub const posix = struct {
    pub const socket_t = std.posix.socket_t;

    pub fn close(fd: std.posix.fd_t) void {
        _ = std.os.linux.close(fd);
    }

    pub fn getuid() std.posix.uid_t {
        return std.os.linux.getuid();
    }

    pub fn socket(domain: anytype, socket_type: anytype, protocol: anytype) !std.posix.fd_t {
        const rc = std.os.linux.socket(int(u32, domain), int(u32, socket_type), int(u32, protocol));
        return fdResult(rc);
    }

    pub fn accept(fd: std.posix.fd_t, addr: ?*std.posix.sockaddr, len: ?*std.posix.socklen_t, flags: anytype) !std.posix.fd_t {
        const rc = std.os.linux.accept4(fd, addr, len, int(u32, flags));
        return fdResult(rc);
    }

    pub fn bind(fd: std.posix.fd_t, addr: *const std.posix.sockaddr, len: std.posix.socklen_t) !void {
        try voidResult(std.os.linux.bind(fd, addr, len));
    }

    pub fn listen(fd: std.posix.fd_t, backlog: u32) !void {
        try voidResult(std.os.linux.listen(fd, backlog));
    }

    pub fn open(path: []const u8, flags: std.posix.O, mode: std.posix.mode_t) !std.posix.fd_t {
        const path_z = try std.posix.toPosixPath(path);
        return fdResult(std.os.linux.open(&path_z, flags, mode));
    }

    pub fn fstat(fd: std.posix.fd_t) !File.Stat {
        return fileStat(fd);
    }

    pub fn fstatat(dirfd: std.posix.fd_t, path: []const u8, flags: anytype) !File.Stat {
        const path_z = try std.posix.toPosixPath(path);
        var statx: std.os.linux.Statx = undefined;
        try voidResult(std.os.linux.statx(
            dirfd,
            &path_z,
            int(u32, flags),
            .{ .TYPE = true, .MODE = true, .SIZE = true, .MTIME = true },
            &statx,
        ));
        return .{
            .size = statx.size,
            .mode = statx.mode,
            .mtime = (@as(i128, statx.mtime.sec) * std.time.ns_per_s) + statx.mtime.nsec,
            .kind = .unknown,
            .permissions = .fromMode(statx.mode & 0o777),
        };
    }

    pub fn getsockname(fd: std.posix.fd_t, addr: *std.posix.sockaddr, len: *std.posix.socklen_t) !void {
        try voidResult(std.os.linux.getsockname(fd, addr, len));
    }

    pub fn getsockoptError(fd: std.posix.fd_t) !void {
        var value: i32 = 0;
        var len: std.posix.socklen_t = @sizeOf(i32);
        try voidResult(std.os.linux.getsockopt(
            fd,
            std.os.linux.SOL.SOCKET,
            std.os.linux.SO.ERROR,
            std.mem.asBytes(&value).ptr,
            &len,
        ));
        if (value == 0) return;
        return switch (@as(std.os.linux.E, @enumFromInt(value))) {
            .TIMEDOUT => error.ConnectionTimedOut,
            .CONNREFUSED => error.ConnectionRefused,
            .HOSTUNREACH, .NETUNREACH => error.NetworkUnreachable,
            else => error.Unexpected,
        };
    }

    pub fn fcntl(fd: std.posix.fd_t, cmd: anytype, arg: usize) !usize {
        return usizeResult(std.os.linux.fcntl(fd, int(i32, cmd), arg));
    }

    pub fn ftruncate(fd: std.posix.fd_t, length: u64) !void {
        try voidResult(std.os.linux.ftruncate(fd, @intCast(length)));
    }

    pub fn lseek(fd: std.posix.fd_t, offset: i64, whence: usize) !usize {
        return usizeResult(std.os.linux.lseek(fd, offset, whence));
    }

    pub fn dup2(old_fd: std.posix.fd_t, new_fd: std.posix.fd_t) !void {
        try voidResult(std.os.linux.dup2(old_fd, new_fd));
    }

    pub fn chdir(path: []const u8) !void {
        const path_z = try std.posix.toPosixPath(path);
        try voidResult(std.os.linux.chdir(&path_z));
    }

    pub fn connect(fd: std.posix.fd_t, addr: *const std.posix.sockaddr, len: std.posix.socklen_t) !void {
        try connectResult(std.os.linux.connect(fd, addr, len));
    }

    pub fn pipe() ![2]std.posix.fd_t {
        var fds: [2]std.posix.fd_t = undefined;
        try voidResult(std.os.linux.pipe(&fds));
        return fds;
    }

    pub fn read(fd: std.posix.fd_t, buffer: []u8) !usize {
        if (buffer.len == 0) return 0;
        return usizeResult(std.os.linux.read(fd, buffer.ptr, buffer.len));
    }

    pub fn write(fd: std.posix.fd_t, buffer: []const u8) !usize {
        if (buffer.len == 0) return 0;
        return usizeResult(std.os.linux.write(fd, buffer.ptr, buffer.len));
    }

    pub fn send(fd: std.posix.fd_t, buffer: []const u8, flags: anytype) !usize {
        return usizeResult(std.os.linux.sendto(fd, buffer.ptr, buffer.len, int(u32, flags), null, 0));
    }

    pub fn recv(fd: std.posix.fd_t, buffer: []u8, flags: anytype) !usize {
        return usizeResult(std.os.linux.recvfrom(fd, buffer.ptr, buffer.len, int(u32, flags), null, null));
    }

    pub fn sendto(fd: std.posix.fd_t, buffer: []const u8, flags: anytype, addr: *const std.posix.sockaddr, len: std.posix.socklen_t) !usize {
        return usizeResult(std.os.linux.sendto(fd, buffer.ptr, buffer.len, int(u32, flags), addr, len));
    }

    pub fn recvfrom(fd: std.posix.fd_t, buffer: []u8, flags: anytype, addr: ?*std.posix.sockaddr, len: ?*std.posix.socklen_t) !usize {
        return usizeResult(std.os.linux.recvfrom(fd, buffer.ptr, buffer.len, int(u32, flags), addr, len));
    }

    fn int(comptime T: type, value: anytype) T {
        return switch (@typeInfo(@TypeOf(value))) {
            .@"enum" => @intCast(@intFromEnum(value)),
            else => @intCast(value),
        };
    }

    fn fdResult(rc: usize) !std.posix.fd_t {
        return switch (syscallErrno(rc)) {
            .SUCCESS => @intCast(rc),
            .AGAIN => error.WouldBlock,
            .CONNABORTED => error.ConnectionAborted,
            .LOOP => error.SymLinkLoop,
            .NOENT => error.FileNotFound,
            .NOTDIR => error.NotDir,
            else => error.Unexpected,
        };
    }

    fn usizeResult(rc: usize) !usize {
        return switch (syscallErrno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            .CONNRESET => error.ConnectionResetByPeer,
            .TIMEDOUT => error.ConnectionTimedOut,
            else => error.Unexpected,
        };
    }

    fn voidResult(rc: usize) !void {
        return switch (syscallErrno(rc)) {
            .SUCCESS => {},
            .NOENT => error.FileNotFound,
            .NOTDIR => error.NotDir,
            else => error.Unexpected,
        };
    }

    fn connectResult(rc: usize) !void {
        return switch (syscallErrno(rc)) {
            .SUCCESS => {},
            .ACCES, .PERM => error.PermissionDenied,
            .ADDRINUSE => error.AddressInUse,
            .ADDRNOTAVAIL => error.AddressNotAvailable,
            .AFNOSUPPORT => error.AddressFamilyNotSupported,
            .AGAIN => error.WouldBlock,
            .ALREADY, .INPROGRESS => error.ConnectionPending,
            .CONNREFUSED => error.ConnectionRefused,
            .HOSTUNREACH => error.NetworkUnreachable,
            .NETUNREACH => error.NetworkUnreachable,
            .TIMEDOUT => error.ConnectionTimedOut,
            else => error.Unexpected,
        };
    }

    fn syscallErrno(rc: usize) std.os.linux.E {
        const err = std.os.linux.errno(rc);
        if (err != .SUCCESS) return err;

        // Some raw syscall wrappers produce zero-extended 32-bit negative
        // errno values. Normalize those before deciding the call succeeded.
        const low_error_base = (@as(usize, 1) << 32) - 4096;
        if (rc >= low_error_base and rc <= std.math.maxInt(u32)) {
            return @enumFromInt((@as(usize, 1) << 32) - rc);
        }
        return .SUCCESS;
    }
};
