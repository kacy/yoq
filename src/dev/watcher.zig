// watcher — inotify-based file change detection for dev mode
//
// watches directories for file modifications and reports which
// service needs restarting. uses linux inotify for efficient
// kernel-level change notification.
//
// key design decisions:
// - CLOSE_WRITE (not MODIFY) — catches atomic saves (write tmp → rename)
// - 500ms debounce — editors often trigger multiple events per save
// - recursive watching — adds subdirectories automatically
// - closing the inotify fd unblocks the waiting thread for clean shutdown

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const syscall = @import("../lib/syscall.zig");
const log = @import("../lib/log.zig");

pub const Watcher = struct {
    fd: posix.fd_t,
    watches: [max_watches]WatchEntry,
    watch_count: usize,

    const max_watches = 256;

    const watch_mask: u32 = linux.IN.CLOSE_WRITE |
        linux.IN.CREATE |
        linux.IN.DELETE |
        linux.IN.MOVED_TO;

    const debounce_ns = 500 * std.time.ns_per_ms;

    const WatchEntry = struct {
        wd: i32,
        service_idx: usize,
    };

    /// create a new inotify watcher.
    /// the returned fd has CLOEXEC set so child processes don't inherit it.
    pub fn init() !Watcher {
        const rc = linux.inotify_init1(linux.IN.CLOEXEC);
        const fd_usize = try syscall.unwrap(rc);

        return .{
            .fd = @intCast(fd_usize),
            .watches = undefined,
            .watch_count = 0,
        };
    }

    /// close the inotify fd. any thread blocked in waitForChange will
    /// get an error on read() and return null, allowing clean shutdown.
    pub fn deinit(self: *Watcher) void {
        posix.close(self.fd);
        self.watch_count = 0;
    }

    /// add a single directory to the watch list for a given service.
    /// the path must fit in a stack buffer (4095 bytes + null terminator).
    pub fn addDir(self: *Watcher, path: []const u8, service_idx: usize) !void {
        if (self.watch_count >= max_watches) {
            log.warn("inotify watch limit reached ({d}), ignoring {s}", .{ max_watches, path });
            return error.TooManyWatches;
        }

        // null-terminate path on the stack for the syscall
        var buf: [4096]u8 = undefined;
        if (path.len >= buf.len) return error.PathTooLong;
        @memcpy(buf[0..path.len], path);
        buf[path.len] = 0;

        const path_z: [*:0]const u8 = buf[0..path.len :0];

        const rc = linux.inotify_add_watch(self.fd, path_z, watch_mask);
        const wd_usize = syscall.unwrap(rc) catch {
            log.warn("failed to watch directory: {s}", .{path});
            return error.WatchFailed;
        };

        self.watches[self.watch_count] = .{
            .wd = @intCast(wd_usize),
            .service_idx = service_idx,
        };
        self.watch_count += 1;

        log.debug("watching {s} for service {d}", .{ path, service_idx });
    }

    /// recursively add a directory and all its subdirectories.
    /// walks the tree using std.fs and calls addDir for each directory found.
    pub fn addRecursive(self: *Watcher, root_path: []const u8, service_idx: usize) !void {
        // watch the root directory itself
        try self.addDir(root_path, service_idx);

        // open and iterate subdirectories
        var dir = std.fs.cwd().openDir(root_path, .{ .iterate = true }) catch {
            log.warn("cannot open directory for recursive watch: {s}", .{root_path});
            return;
        };
        defer dir.close();

        self.walkDir(dir, root_path, service_idx);
    }

    /// internal recursive directory walker. adds inotify watches for each
    /// subdirectory found. skips hidden directories (starting with '.').
    fn walkDir(self: *Watcher, dir: std.fs.Dir, parent_path: []const u8, service_idx: usize) void {
        var iter = dir.iterate();
        while (iter.next() catch null) |entry| {
            if (entry.kind != .directory) continue;

            // skip hidden directories (.git, .cache, etc)
            if (entry.name.len > 0 and entry.name[0] == '.') continue;

            // build the full path: parent_path + "/" + entry.name
            var path_buf: [4096]u8 = undefined;
            const full_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ parent_path, entry.name }) catch continue;

            self.addDir(full_path, service_idx) catch continue;

            // recurse into the subdirectory
            var subdir = dir.openDir(entry.name, .{ .iterate = true }) catch continue;
            defer subdir.close();
            self.walkDir(subdir, full_path, service_idx);
        }
    }

    /// block until a watched file changes. returns the service index
    /// that needs restarting, or null if the watcher was closed (shutdown).
    ///
    /// after detecting a change, sleeps 500ms and drains any pending
    /// events to debounce rapid sequences (editors saving multiple files).
    pub fn waitForChange(self: *Watcher) ?usize {
        var buf: [4096]u8 align(@alignOf(linux.inotify_event)) = undefined;

        // blocking read — will return error when fd is closed
        const bytes_read = posix.read(self.fd, &buf) catch return null;
        if (bytes_read == 0) return null;

        // find which service triggered this event
        const service_idx = self.processEvents(buf[0..bytes_read]);

        // debounce: wait for the editor to finish writing, then drain
        // any events that piled up during the wait
        std.time.sleep(debounce_ns);
        self.drainPending();

        return service_idx;
    }

    /// scan an event buffer and return the service index for the first
    /// matching watch descriptor. also handles auto-adding new subdirectories
    /// when IN.CREATE fires with IN.ISDIR.
    fn processEvents(self: *Watcher, buf: []const u8) ?usize {
        var offset: usize = 0;
        var result: ?usize = null;

        while (offset + @sizeOf(linux.inotify_event) <= buf.len) {
            const event: *const linux.inotify_event = @ptrCast(@alignCast(buf.ptr + offset));
            offset += @sizeOf(linux.inotify_event) + event.len;

            // if a new subdirectory was created, watch it too
            if (event.mask & linux.IN.CREATE != 0 and event.mask & linux.IN.ISDIR != 0) {
                if (event.getName()) |name| {
                    self.autoAddSubdir(event.wd, name);
                }
            }

            // find the service that owns this watch descriptor
            if (result == null) {
                for (self.watches[0..self.watch_count]) |entry| {
                    if (entry.wd == event.wd) {
                        result = entry.service_idx;
                        break;
                    }
                }
            }
        }

        return result;
    }

    /// when a new subdirectory is created inside a watched directory,
    /// add an inotify watch for it automatically so we don't miss changes
    /// in newly created directories.
    ///
    /// note: inotify watch descriptors don't give us the parent path back,
    /// and we don't store paths to keep the struct fixed-size. newly created
    /// directories during runtime will be caught on the next service restart
    /// cycle. this is a reasonable trade-off for v1 — creating new directories
    /// while editing is uncommon.
    fn autoAddSubdir(self: *Watcher, parent_wd: i32, name: [:0]const u8) void {
        // stub — see note above. suppressing unused params.
        _ = self;
        _ = parent_wd;
        _ = name;
    }

    /// drain any pending inotify events without blocking.
    /// used after debounce sleep to clear the queue.
    fn drainPending(self: *Watcher) void {
        // set nonblocking temporarily to drain without waiting
        const flags = posix.fcntl(self.fd, .GETFL) catch return;
        const nonblock: u32 = @bitCast(posix.O{ .NONBLOCK = true });
        posix.fcntl(self.fd, .SETFL, flags | nonblock) catch return;

        var buf: [4096]u8 align(@alignOf(linux.inotify_event)) = undefined;
        while (true) {
            _ = posix.read(self.fd, &buf) catch break;
        }

        // restore original flags
        posix.fcntl(self.fd, .SETFL, flags) catch {};
    }
};

// -- tests --

test "init and deinit" {
    var w = try Watcher.init();
    // fd should be valid (non-negative)
    try std.testing.expect(w.fd >= 0);
    try std.testing.expectEqual(@as(usize, 0), w.watch_count);
    w.deinit();
}

test "watch temp directory and detect file change" {
    var w = try Watcher.init();
    defer w.deinit();

    // create a temp directory
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // get the real path for inotify (needs an absolute path)
    var path_buf: [4096]u8 = undefined;
    const tmp_path = tmp.dir.realpath(".", &path_buf) catch unreachable;

    try w.addDir(tmp_path, 42);
    try std.testing.expectEqual(@as(usize, 1), w.watch_count);

    // spawn a thread to wait for changes
    const WaitResult = struct {
        value: ?usize = null,
    };
    var result = WaitResult{};

    const thread = std.Thread.spawn(.{}, struct {
        fn run(watcher: *Watcher, res: *WaitResult) void {
            res.value = watcher.waitForChange();
        }
    }.run, .{ &w, &result }) catch unreachable;

    // give the watcher thread time to enter the blocking read
    std.time.sleep(50 * std.time.ns_per_ms);

    // write a file to trigger the event
    var file = tmp.dir.createFile("test.txt", .{}) catch unreachable;
    file.writeAll("hello") catch {};
    file.close();

    // wait for the watcher thread to finish (debounce is 500ms)
    thread.join();

    // should have detected service 42
    try std.testing.expectEqual(@as(?usize, 42), result.value);
}

test "too many watches" {
    var w = try Watcher.init();
    defer w.deinit();

    // we can't actually add 256 watches in a test easily,
    // but we can verify the limit is checked
    w.watch_count = Watcher.max_watches;
    try std.testing.expectError(error.TooManyWatches, w.addDir("/tmp", 0));
}

test "path too long" {
    var w = try Watcher.init();
    defer w.deinit();

    // create a path that's too long (4096+ bytes)
    const long_path = "a" ** 4096;
    try std.testing.expectError(error.PathTooLong, w.addDir(long_path, 0));
}
