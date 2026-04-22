const std = @import("std");

/// Linux platform boundary for blocking OS primitives and temporary Zig 0.16
/// filesystem adapters. New command/runtime entrypoints should pass std.Io
/// explicitly instead of adding more implicit IO here.
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
        const buffer = try alloc.allocSentinel(u8, size, 0);
        errdefer alloc.free(buffer);

        const rc = std.os.linux.readlink("/proc/self/exe", buffer.ptr, buffer.len);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {
                if (rc < buffer.len) {
                    buffer[rc] = 0;
                    return buffer[0..rc :0];
                }
            },
            .NOENT => return error.FileNotFound,
            .ACCES, .PERM => return error.AccessDenied,
            else => return error.Unexpected,
        }

        alloc.free(buffer);
    }
    return error.NameTooLong;
}

fn realTimeNanos() i128 {
    var ts: std.os.linux.timespec = undefined;
    const rc = std.os.linux.clock_gettime(.REALTIME, &ts);
    if (std.os.linux.errno(rc) != .SUCCESS) return 0;
    return (@as(i128, ts.sec) * std.time.ns_per_s) + ts.nsec;
}

fn legacyFilesystemIo() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

pub fn format(writer: anytype, comptime fmt: []const u8, args: anytype) !void {
    switch (@typeInfo(@TypeOf(writer))) {
        .pointer => |ptr| {
            if (@hasDecl(ptr.child, "print")) return writer.print(fmt, args);
            if (@hasField(ptr.child, "interface")) return writer.interface.print(fmt, args);
        },
        else => {
            var copy = writer;
            if (@hasDecl(@TypeOf(copy), "print")) return copy.print(fmt, args);
            if (@hasField(@TypeOf(copy), "interface")) return copy.interface.print(fmt, args);
        },
    }
    @compileError("unsupported writer type");
}

pub fn fixedBufferStream(buffer: anytype) FixedBufferStream {
    return .init(writableSlice(buffer));
}

pub fn arrayListWriter(list: anytype, alloc: std.mem.Allocator) ArrayListWriter(@TypeOf(list)) {
    return .{ .list = list, .alloc = alloc };
}

pub fn ArrayListWriter(comptime ListPtr: type) type {
    return struct {
        list: ListPtr,
        alloc: std.mem.Allocator,

        pub fn writeAll(self: @This(), bytes: []const u8) !void {
            try self.list.appendSlice(self.alloc, bytes);
        }

        pub fn writeByte(self: @This(), byte: u8) !void {
            try self.list.append(self.alloc, byte);
        }

        pub fn print(self: @This(), comptime fmt: []const u8, args: anytype) !void {
            try self.list.print(self.alloc, fmt, args);
        }
    };
}

pub const FixedBufferStream = struct {
    writer_impl: std.Io.Writer,

    fn init(buffer: []u8) FixedBufferStream {
        return .{ .writer_impl = .fixed(buffer) };
    }

    pub fn writer(self: *FixedBufferStream) *std.Io.Writer {
        return &self.writer_impl;
    }

    pub fn getWritten(self: *FixedBufferStream) []u8 {
        return self.writer_impl.buffered();
    }
};

fn writableSlice(buffer: anytype) []u8 {
    return switch (@typeInfo(@TypeOf(buffer))) {
        .pointer => |ptr| switch (ptr.size) {
            .one => buffer[0..],
            .slice => buffer,
            else => @compileError("unsupported fixed buffer type"),
        },
        else => @compileError("unsupported fixed buffer type"),
    };
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

    fn from(file: std.Io.File) File {
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
        self.inner().close(legacyFilesystemIo());
    }

    pub fn writer(self: File, buffer: []u8) std.Io.File.Writer {
        return self.inner().writer(legacyFilesystemIo(), buffer);
    }

    pub fn reader(self: File, buffer: []u8) std.Io.File.Reader {
        return self.inner().reader(legacyFilesystemIo(), buffer);
    }

    pub fn writeAll(self: File, bytes: []const u8) !void {
        try self.inner().writeStreamingAll(legacyFilesystemIo(), bytes);
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
        try self.inner().sync(legacyFilesystemIo());
    }

    pub fn stat(self: File) !Stat {
        const file_stat = try self.inner().stat(legacyFilesystemIo());
        return .{
            .size = file_stat.size,
            .mode = file_stat.permissions.toMode(),
            .mtime = file_stat.mtime.toNanoseconds(),
            .kind = file_stat.kind,
            .permissions = file_stat.permissions,
        };
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
};

pub const Dir = struct {
    pub const Walker = struct {
        inner: std.Io.Dir.Walker,

        pub const Entry = std.Io.Dir.Walker.Entry;

        pub fn next(self: *Walker) !?Walker.Entry {
            return self.inner.next(legacyFilesystemIo());
        }

        pub fn deinit(self: *Walker) void {
            self.inner.deinit();
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
        self.inner.close(legacyFilesystemIo());
    }

    pub fn access(self: Dir, path: []const u8, options: std.Io.Dir.AccessOptions) !void {
        try self.inner.access(legacyFilesystemIo(), path, options);
    }

    pub fn makeDir(self: Dir, path: []const u8) !void {
        try self.inner.createDir(legacyFilesystemIo(), path, .default_dir);
    }

    pub fn makePath(self: Dir, path: []const u8) !void {
        try self.inner.createDirPath(legacyFilesystemIo(), path);
    }

    pub fn deleteDir(self: Dir, path: []const u8) !void {
        try self.inner.deleteDir(legacyFilesystemIo(), path);
    }

    pub fn deleteFile(self: Dir, path: []const u8) !void {
        try self.inner.deleteFile(legacyFilesystemIo(), path);
    }

    pub fn deleteTree(self: Dir, path: []const u8) !void {
        try self.inner.deleteTree(legacyFilesystemIo(), path);
    }

    pub fn openFile(self: Dir, path: []const u8, options: std.Io.Dir.OpenFileOptions) !File {
        return File.from(try self.inner.openFile(legacyFilesystemIo(), path, options));
    }

    pub fn createFile(self: Dir, path: []const u8, options: CreateFileOptions) !File {
        return File.from(try self.inner.createFile(legacyFilesystemIo(), path, .{
            .read = options.read,
            .truncate = options.truncate,
            .exclusive = options.exclusive,
            .permissions = .fromMode(options.mode),
        }));
    }

    pub fn writeFile(self: Dir, args: anytype) !void {
        const file = try self.createFile(args.sub_path, .{});
        defer file.close();
        try file.writeAll(args.data);
    }

    pub fn openDir(self: Dir, path: []const u8, options: std.Io.Dir.OpenOptions) !Dir {
        return Dir.from(try self.inner.openDir(legacyFilesystemIo(), path, options));
    }

    pub fn statFile(self: Dir, path: []const u8) !Stat {
        const file_stat = try self.inner.statFile(legacyFilesystemIo(), path, .{});
        return .{
            .size = file_stat.size,
            .mode = file_stat.permissions.toMode(),
            .mtime = file_stat.mtime.toNanoseconds(),
            .kind = file_stat.kind,
            .permissions = file_stat.permissions,
        };
    }

    pub fn readFile(self: Dir, path: []const u8, buffer: []u8) ![]u8 {
        return self.inner.readFile(legacyFilesystemIo(), path, buffer);
    }

    pub fn readFileAlloc(self: Dir, alloc: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
        return self.inner.readFileAlloc(legacyFilesystemIo(), path, alloc, .limited(max_bytes));
    }

    pub fn readLink(self: Dir, path: []const u8, buffer: []u8) ![]u8 {
        const len = try self.inner.readLink(legacyFilesystemIo(), path, buffer);
        return buffer[0..len];
    }

    pub fn copyFile(self: Dir, source_path: []const u8, dest_dir: Dir, dest_path: []const u8, options: std.Io.Dir.CopyFileOptions) !void {
        try self.inner.copyFile(source_path, dest_dir.inner, dest_path, legacyFilesystemIo(), options);
    }

    pub fn symLink(self: Dir, target_path: []const u8, sym_link_path: []const u8, flags: std.Io.Dir.SymLinkFlags) !void {
        try self.inner.symLink(legacyFilesystemIo(), target_path, sym_link_path, flags);
    }

    pub fn realpath(self: Dir, path: []const u8, buffer: []u8) ![]u8 {
        const len = try self.inner.realPathFile(legacyFilesystemIo(), path, buffer);
        return buffer[0..len];
    }

    pub fn realpathAlloc(self: Dir, alloc: std.mem.Allocator, path: []const u8) ![:0]u8 {
        return self.inner.realPathFileAlloc(legacyFilesystemIo(), path, alloc);
    }

    pub fn rename(self: Dir, old_path: []const u8, new_path: []const u8) !void {
        try self.inner.rename(old_path, self.inner, new_path, legacyFilesystemIo());
    }

    pub fn iterate(self: Dir) Iterator {
        return .{ .inner = self.inner.iterate() };
    }

    pub fn walk(self: Dir, alloc: std.mem.Allocator) !Walker {
        return .{ .inner = try self.inner.walk(alloc) };
    }

    pub const Iterator = struct {
        inner: std.Io.Dir.Iterator,

        pub fn next(self: *Iterator) !?std.Io.Dir.Entry {
            return self.inner.next(legacyFilesystemIo());
        }
    };
};

pub fn cwd() Dir {
    return Dir.from(std.Io.Dir.cwd());
}

pub fn openDirAbsolute(path: []const u8, options: std.Io.Dir.OpenOptions) !Dir {
    return Dir.from(try std.Io.Dir.openDirAbsolute(legacyFilesystemIo(), path, options));
}

pub fn openFileAbsolute(path: []const u8, options: std.Io.Dir.OpenFileOptions) !File {
    return File.from(try std.Io.Dir.openFileAbsolute(legacyFilesystemIo(), path, options));
}

pub fn createFileAbsolute(path: []const u8, options: Dir.CreateFileOptions) !File {
    return cwd().createFile(path, options);
}

pub fn accessAbsolute(path: []const u8, options: std.Io.Dir.AccessOptions) !void {
    return std.Io.Dir.accessAbsolute(legacyFilesystemIo(), path, options);
}

pub fn deleteFileAbsolute(path: []const u8) !void {
    return std.Io.Dir.deleteFileAbsolute(legacyFilesystemIo(), path);
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
        return File.from(.{ .handle = fd, .flags = .{ .nonblocking = false } }).stat();
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
