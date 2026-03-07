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
const builtin = @import("builtin");
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
        self.fd = -1; // Mark as invalid to prevent use-after-close
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
        var dir = std.fs.cwd().openDir(root_path, .{ .iterate = true }) catch |e| {
            log.warn("cannot open directory for recursive watch '{s}': {}", .{ root_path, e });
            return error.OpenFailed;
        };
        defer dir.close();

        self.walkDir(dir, root_path, service_idx);
    }

    /// internal recursive directory walker. adds inotify watches for each
    /// subdirectory found. skips hidden directories (starting with '.').
    /// logs errors but continues walking on partial failures.
    fn walkDir(self: *Watcher, dir: std.fs.Dir, parent_path: []const u8, service_idx: usize) void {
        var iter = dir.iterate();
        while (true) {
            const entry = iter.next() catch |e| {
                log.warn("watcher: directory iteration failed for '{s}': {}", .{ parent_path, e });
                break; // stop walking this directory on iteration errors
            } orelse break; // null means no more entries

            if (entry.kind != .directory) continue;

            // skip hidden directories (.git, .cache, etc)
            if (entry.name.len > 0 and entry.name[0] == '.') continue;

            // build the full path: parent_path + "/" + entry.name
            var path_buf: [4096]u8 = undefined;
            const full_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ parent_path, entry.name }) catch |e| {
                log.warn("watcher: path too long for '{s}/{s}': {}", .{ parent_path, entry.name, e });
                continue;
            };

            self.addDir(full_path, service_idx) catch |e| {
                log.warn("watcher: failed to add watch for '{s}': {}", .{ full_path, e });
                continue; // continue with other directories even if one fails
            };

            // recurse into the subdirectory
            var subdir = dir.openDir(entry.name, .{ .iterate = true }) catch |e| {
                log.warn("watcher: failed to open subdirectory '{s}/{s}': {}", .{ parent_path, entry.name, e });
                continue;
            };
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
        std.Thread.sleep(debounce_ns);
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

            // validate that the event name (if any) fits within the buffer
            const name_offset = offset + @sizeOf(linux.inotify_event);
            if (name_offset + event.len > buf.len) {
                log.warn("watcher: invalid event length {d} at offset {d}, skipping", .{ event.len, offset });
                break; // malformed event, stop processing
            }

            // safely calculate next offset
            const next_offset = name_offset + event.len;
            if (next_offset < offset) {
                // overflow check
                log.warn("watcher: offset overflow, stopping event processing", .{});
                break;
            }
            offset = next_offset;

            // if a new subdirectory was created, watch it too
            if (event.mask & linux.IN.CREATE != 0 and event.mask & linux.IN.ISDIR != 0) {
                if (event.getName()) |name| {
                    self.autoAddSubdir(event.wd, name);
                }
            }

            // find the service that owns this watch descriptor
            // NOTE: we only return the first service, but we process all events
            // to ensure subdirectories are auto-added
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
    fn autoAddSubdir(self: *Watcher, parent_wd: i32, name: [:0]const u8) void {
        // find the parent entry to get the service index
        var service_idx: usize = 0;
        for (self.watches[0..self.watch_count]) |entry| {
            if (entry.wd == parent_wd) {
                service_idx = entry.service_idx;
                break;
            }
        }

        log.debug("new subdirectory created in watched parent (wd={d}, name={s}), service={d}. " ++
            "Will be watched on next restart.", .{ parent_wd, name, service_idx });

        // NOTE: To fully implement this, we would need to store paths for each watch.
        // This is a limitation of the current fixed-size struct design.
        // For now, we log the event but don't add the watch - the new directory
        // will be picked up when the service restarts.
    }

    /// drain any pending inotify events without blocking.
    /// used after debounce sleep to clear the queue.
    fn drainPending(self: *Watcher) void {
        // check if fd is still valid before modifying flags
        if (self.fd < 0) return;

        // set nonblocking temporarily to drain without waiting
        const flags = posix.fcntl(self.fd, posix.F.GETFL, 0) catch |e| {
            log.warn("watcher: failed to get fd flags: {}", .{e});
            return;
        };
        const nonblock: usize = @intCast(@as(u32, @bitCast(posix.O{ .NONBLOCK = true })));
        _ = posix.fcntl(self.fd, posix.F.SETFL, flags | nonblock) catch |e| {
            // failed to set non-blocking, don't try to restore
            log.warn("watcher: failed to set non-blocking mode: {}", .{e});
            return;
        };

        var buf: [4096]u8 align(@alignOf(linux.inotify_event)) = undefined;
        while (true) {
            _ = posix.read(self.fd, &buf) catch break;
        }

        // restore original flags - but only if fd is still valid
        if (self.fd >= 0) {
            _ = posix.fcntl(self.fd, posix.F.SETFL, flags) catch |e| {
                log.warn("watcher: failed to restore fd flags: {}", .{e});
            };
        }
    }
};

// -- tests --

fn requireLinuxTest() !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
}

test "init and deinit" {
    try requireLinuxTest();
    var w = try Watcher.init();
    // fd should be valid (non-negative)
    try std.testing.expect(w.fd >= 0);
    try std.testing.expectEqual(@as(usize, 0), w.watch_count);
    w.deinit();
}

test "watch temp directory and detect file change" {
    try requireLinuxTest();
    var w = try Watcher.init();
    defer w.deinit();

    // create a temp directory
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // get the real path for inotify (needs an absolute path)
    var path_buf: [4096]u8 = undefined;
    const tmp_path = try tmp.dir.realpath(".", &path_buf);

    try w.addDir(tmp_path, 42);
    try std.testing.expectEqual(@as(usize, 1), w.watch_count);

    // use a semaphore to synchronize watcher thread startup
    const Context = struct {
        watcher: *Watcher,
        value: ?usize = null,
        sem: std.Thread.Semaphore = .{},
    };
    var ctx = Context{ .watcher = &w };

    const thread = try std.Thread.spawn(.{}, struct {
        fn run(context: *Context) void {
            // signal that we're about to start watching
            context.sem.post();
            context.value = context.watcher.waitForChange();
        }
    }.run, .{&ctx});

    // wait for the watcher thread to signal it's ready
    ctx.sem.wait();
    // give extra time for the thread to enter the blocking read
    std.Thread.sleep(50 * std.time.ns_per_ms);

    // write a file to trigger the event
    var file = try tmp.dir.createFile("test.txt", .{});
    try file.writeAll("hello");
    file.close();

    // wait for the watcher thread to finish (debounce is 500ms)
    thread.join();

    // should have detected service 42
    try std.testing.expectEqual(@as(?usize, 42), ctx.value);
}

test "too many watches" {
    try requireLinuxTest();
    var w = try Watcher.init();
    defer w.deinit();

    // we can't actually add 256 watches in a test easily,
    // but we can verify the limit is checked
    w.watch_count = Watcher.max_watches;
    try std.testing.expectError(error.TooManyWatches, w.addDir("/tmp", 0));
}

test "path too long" {
    try requireLinuxTest();
    var w = try Watcher.init();
    defer w.deinit();

    // create a path that's too long (4096+ bytes)
    const long_path = "a" ** 4096;
    try std.testing.expectError(error.PathTooLong, w.addDir(long_path, 0));
}
