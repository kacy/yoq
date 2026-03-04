// agent — cluster agent runtime
//
// an agent is a worker node that connects to the cluster server,
// reports its capacity, and runs assigned containers. the agent
// uses a pull-based model: it polls the server every few seconds
// for heartbeat updates and work assignments.
//
// flow:
//   1. register with server (POST /agents/register)
//   2. enter loop: heartbeat + reconcile assignments every 5s
//   3. for each pending assignment: pull image, start container, report status
//   4. on shutdown, stop local containers and exit
//
// the agent reuses the existing container runtime for actually
// running containers — same code path as the local orchestrator.

const std = @import("std");
const posix = std.posix;
const http_client = @import("http_client.zig");
const agent_types = @import("agent_types.zig");
const cli = @import("../lib/cli.zig");
const json_helpers = @import("../lib/json_helpers.zig");
const log = @import("../lib/log.zig");
const container = @import("../runtime/container.zig");
const image_registry = @import("../image/registry.zig");
const image_layer = @import("../image/layer.zig");
const image_spec = @import("../image/spec.zig");
const store = @import("../state/store.zig");
const logs = @import("../runtime/logs.zig");

const Allocator = std.mem.Allocator;
const AgentResources = agent_types.AgentResources;

const write = cli.write;
const writeErr = cli.writeErr;

pub const AgentError = error{
    RegisterFailed,
    InvalidResponse,
};

/// tracks the local state of a container spawned from an assignment.
pub const ContainerState = enum {
    starting,
    running,
    stopped,
    failed,
};

pub const Agent = struct {
    alloc: Allocator,
    id: [12]u8,
    server_addr: [4]u8,
    server_port: u16,
    token: []const u8,
    running: std.atomic.Value(bool),
    loop_thread: ?std.Thread,

    /// tracks assignment_id → local container state.
    /// protected by mutex since container threads update it.
    local_containers: std.StringHashMap(ContainerState),
    container_lock: std.Thread.Mutex,

    pub fn init(alloc: Allocator, server_addr: [4]u8, server_port: u16, token: []const u8) Agent {
        return .{
            .alloc = alloc,
            .id = undefined,
            .server_addr = server_addr,
            .server_port = server_port,
            .token = token,
            .running = std.atomic.Value(bool).init(false),
            .loop_thread = null,
            .local_containers = std.StringHashMap(ContainerState).init(alloc),
            .container_lock = .{},
        };
    }

    /// register this agent with the cluster server.
    /// on success, self.id is set to the server-assigned agent ID.
    pub fn register(self: *Agent) AgentError!void {
        const resources = getSystemResources();

        // build registration JSON
        var body_buf: [512]u8 = undefined;
        const body = std.fmt.bufPrint(&body_buf,
            "{{\"token\":\"{s}\",\"address\":\"localhost:0\",\"cpu_cores\":{d},\"memory_mb\":{d}}}",
            .{ self.token, resources.cpu_cores, resources.memory_mb },
        ) catch return AgentError.RegisterFailed;

        var resp = http_client.postWithAuth(
            self.alloc,
            self.server_addr,
            self.server_port,
            "/agents/register",
            body,
            self.token,
        ) catch return AgentError.RegisterFailed;
        defer resp.deinit(self.alloc);

        if (resp.status_code != 200) {
            writeErr("registration failed (status {d}): {s}\n", .{ resp.status_code, resp.body });
            return AgentError.RegisterFailed;
        }

        // parse agent ID from response: {"id":"xxxxxxxxxxxx"}
        const id_str = extractJsonString(resp.body, "id") orelse {
            writeErr("invalid registration response\n", .{});
            return AgentError.InvalidResponse;
        };

        if (id_str.len != 12) {
            writeErr("unexpected agent ID length: {d}\n", .{id_str.len});
            return AgentError.InvalidResponse;
        }

        @memcpy(&self.id, id_str);
    }

    /// start the agent loop in a background thread.
    pub fn start(self: *Agent) !void {
        self.running.store(true, .release);
        self.loop_thread = std.Thread.spawn(.{}, agentLoop, .{self}) catch {
            self.running.store(false, .release);
            return error.ThreadSpawnFailed;
        };
    }

    /// signal the agent to stop and wait for the loop thread to exit.
    pub fn stop(self: *Agent) void {
        self.running.store(false, .release);
        if (self.loop_thread) |t| {
            t.join();
            self.loop_thread = null;
        }

        // clean up the local containers map
        self.container_lock.lock();
        defer self.container_lock.unlock();

        var it = self.local_containers.iterator();
        while (it.next()) |entry| {
            self.alloc.free(entry.key_ptr.*);
        }
        self.local_containers.deinit();
    }

    /// block until the agent stops (used by cmdJoin).
    pub fn wait(self: *Agent) void {
        if (self.loop_thread) |t| {
            t.join();
            self.loop_thread = null;
        }
    }

    fn agentLoop(self: *Agent) void {
        while (self.running.load(.acquire)) {
            self.doHeartbeat();
            self.reconcile();

            // sleep 5 seconds between cycles
            var remaining: u32 = 50; // 50 * 100ms = 5s
            while (remaining > 0 and self.running.load(.acquire)) : (remaining -= 1) {
                std.Thread.sleep(100 * std.time.ns_per_ms);
            }
        }
    }

    fn doHeartbeat(self: *Agent) void {
        const resources = getSystemResources();

        var body_buf: [256]u8 = undefined;
        const body = std.fmt.bufPrint(&body_buf,
            "{{\"cpu_cores\":{d},\"memory_mb\":{d},\"cpu_used\":{d},\"memory_used_mb\":{d},\"containers\":{d}}}",
            .{
                resources.cpu_cores,
                resources.memory_mb,
                resources.cpu_used,
                resources.memory_used_mb,
                resources.containers,
            },
        ) catch return;

        var path_buf: [64]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/agents/{s}/heartbeat", .{self.id}) catch return;

        var resp = http_client.postWithAuth(
            self.alloc,
            self.server_addr,
            self.server_port,
            path,
            body,
            self.token,
        ) catch return;
        defer resp.deinit(self.alloc);

        // check if server says we're being drained
        if (resp.status_code == 200) {
            const status = extractJsonString(resp.body, "status");
            if (status) |s| {
                if (std.mem.eql(u8, s, "draining")) {
                    writeErr("agent is being drained, stopping...\n", .{});
                    self.running.store(false, .release);
                }
            }
        }
    }

    /// fetch assignments from the server and start containers for any
    /// new pending assignments. this is the core reconciliation loop.
    fn reconcile(self: *Agent) void {
        var resp = self.fetchAssignments() orelse return;
        defer resp.deinit(self.alloc);

        var iter = json_helpers.extractJsonObjects(resp.body);
        while (iter.next()) |obj| {
            const assignment_id = extractJsonString(obj, "id") orelse continue;
            const status = extractJsonString(obj, "status") orelse continue;

            // only act on pending assignments
            if (!std.mem.eql(u8, status, "pending")) continue;

            // skip if we're already tracking this assignment
            self.container_lock.lock();
            const already_tracked = self.local_containers.contains(assignment_id);
            self.container_lock.unlock();
            if (already_tracked) continue;

            const image = extractJsonString(obj, "image") orelse continue;
            const command = extractJsonString(obj, "command") orelse "";

            // allocate copies for the thread (the response buffer will be freed)
            const id_copy = self.alloc.dupe(u8, assignment_id) catch continue;
            const image_copy = self.alloc.dupe(u8, image) catch {
                self.alloc.free(id_copy);
                continue;
            };
            const command_copy = self.alloc.dupe(u8, command) catch {
                self.alloc.free(id_copy);
                self.alloc.free(image_copy);
                continue;
            };

            // mark as starting before spawning thread
            self.container_lock.lock();
            self.local_containers.put(id_copy, .starting) catch {
                self.container_lock.unlock();
                self.alloc.free(id_copy);
                self.alloc.free(image_copy);
                self.alloc.free(command_copy);
                continue;
            };
            self.container_lock.unlock();

            log.info("starting assignment {s} (image: {s})", .{ id_copy, image_copy });

            _ = std.Thread.spawn(.{}, runAssignment, .{
                self, id_copy, image_copy, command_copy,
            }) catch {
                log.warn("failed to spawn thread for assignment {s}", .{id_copy});
                self.container_lock.lock();
                _ = self.local_containers.remove(id_copy);
                self.container_lock.unlock();
                self.alloc.free(id_copy);
                self.alloc.free(image_copy);
                self.alloc.free(command_copy);
            };
        }
    }

    /// GET /agents/{id}/assignments from the server.
    fn fetchAssignments(self: *Agent) ?http_client.Response {
        var path_buf: [64]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/agents/{s}/assignments", .{self.id}) catch return null;

        return http_client.getWithAuth(
            self.alloc,
            self.server_addr,
            self.server_port,
            path,
            self.token,
        ) catch return null;
    }

    /// run a single assignment in its own thread.
    /// pulls the image, starts the container, and blocks until it exits.
    /// reports status back to the server at each stage.
    fn runAssignment(self: *Agent, assignment_id: []const u8, image: []const u8, command: []const u8) void {
        defer {
            self.alloc.free(image);
            self.alloc.free(command);
            // note: assignment_id stays in local_containers map (key is owned by the map)
        }

        // report running status to server
        self.reportStatus(assignment_id, "running");

        self.container_lock.lock();
        if (self.local_containers.getPtr(assignment_id)) |state| {
            state.* = .running;
        }
        self.container_lock.unlock();

        // pull image
        const ref = image_spec.parseImageRef(image);
        var pull_result = image_registry.pull(self.alloc, ref) catch {
            log.warn("failed to pull image {s} for assignment {s}", .{ image, assignment_id });
            self.setContainerState(assignment_id, .failed);
            self.reportStatus(assignment_id, "failed");
            return;
        };
        defer pull_result.deinit();

        // assemble rootfs from layers
        const layer_paths = image_layer.assembleRootfs(self.alloc, pull_result.layer_digests) catch {
            log.warn("failed to assemble rootfs for assignment {s}", .{assignment_id});
            self.setContainerState(assignment_id, .failed);
            self.reportStatus(assignment_id, "failed");
            return;
        };
        defer {
            for (layer_paths) |p| self.alloc.free(p);
            self.alloc.free(layer_paths);
        }

        // determine rootfs path (topmost layer)
        const rootfs = if (layer_paths.len > 0) layer_paths[layer_paths.len - 1] else "/";

        // generate a local container ID
        var id_buf: [12]u8 = undefined;
        container.generateId(&id_buf);
        const container_id = id_buf[0..];

        // save container record to local store
        store.save(.{
            .id = container_id,
            .rootfs = rootfs,
            .command = if (command.len > 0) command else "/bin/sh",
            .hostname = "agent",
            .status = "created",
            .pid = null,
            .exit_code = null,
            .created_at = std.time.timestamp(),
        }) catch {
            log.warn("failed to save container record for assignment {s}", .{assignment_id});
            self.setContainerState(assignment_id, .failed);
            self.reportStatus(assignment_id, "failed");
            return;
        };

        // create and start the container (blocks until exit)
        var c = container.Container{
            .config = .{
                .id = container_id,
                .rootfs = rootfs,
                .command = if (command.len > 0) command else "/bin/sh",
                .lower_dirs = layer_paths,
            },
            .status = .created,
            .pid = null,
            .exit_code = null,
            .created_at = std.time.timestamp(),
        };

        log.info("starting container {s} for assignment {s}", .{ container_id, assignment_id });
        c.start() catch {
            log.warn("container {s} failed to start for assignment {s}", .{ container_id, assignment_id });
            self.setContainerState(assignment_id, .failed);
            self.reportStatus(assignment_id, "failed");
            cleanup(container_id);
            return;
        };

        // container exited normally
        log.info("container {s} exited for assignment {s}", .{ container_id, assignment_id });
        self.setContainerState(assignment_id, .stopped);
        self.reportStatus(assignment_id, "stopped");
        cleanup(container_id);
    }

    /// report assignment status to the server. best-effort — log on failure.
    fn reportStatus(self: *Agent, assignment_id: []const u8, status: []const u8) void {
        var path_buf: [128]u8 = undefined;
        const path = std.fmt.bufPrint(
            &path_buf,
            "/agents/{s}/assignments/{s}/status",
            .{ self.id, assignment_id },
        ) catch return;

        var body_buf: [64]u8 = undefined;
        const body = std.fmt.bufPrint(&body_buf, "{{\"status\":\"{s}\"}}", .{status}) catch return;

        var resp = http_client.postWithAuth(
            self.alloc,
            self.server_addr,
            self.server_port,
            path,
            body,
            self.token,
        ) catch {
            log.warn("failed to report status '{s}' for assignment {s}", .{ status, assignment_id });
            return;
        };
        resp.deinit(self.alloc);
    }

    /// update the local container state (thread-safe).
    fn setContainerState(self: *Agent, assignment_id: []const u8, state: ContainerState) void {
        self.container_lock.lock();
        defer self.container_lock.unlock();
        if (self.local_containers.getPtr(assignment_id)) |s| {
            s.* = state;
        }
    }

    /// clean up container files after exit.
    fn cleanup(container_id: []const u8) void {
        logs.deleteLogFile(container_id);
        container.cleanupContainerDirs(container_id);
        store.remove(container_id) catch {};
    }
};

/// read system resources from /proc/meminfo and cpu count.
pub fn getSystemResources() AgentResources {
    const cpu_cores: u32 = @intCast(std.Thread.getCpuCount() catch 1);

    // read total memory from /proc/meminfo
    var memory_mb: u64 = 0;
    const meminfo = std.fs.cwd().readFileAlloc(std.heap.page_allocator, "/proc/meminfo", 8192) catch "";
    defer if (meminfo.len > 0) std.heap.page_allocator.free(meminfo);

    if (meminfo.len > 0) {
        // find "MemTotal:" line and parse the value
        if (std.mem.indexOf(u8, meminfo, "MemTotal:")) |pos| {
            var start = pos + "MemTotal:".len;
            // skip whitespace
            while (start < meminfo.len and meminfo[start] == ' ') start += 1;
            // find end of number
            var end = start;
            while (end < meminfo.len and meminfo[end] >= '0' and meminfo[end] <= '9') end += 1;
            if (end > start) {
                const kb = std.fmt.parseInt(u64, meminfo[start..end], 10) catch 0;
                memory_mb = kb / 1024;
            }
        }
    }

    return .{
        .cpu_cores = cpu_cores,
        .memory_mb = memory_mb,
    };
}

// use shared JSON extraction helper
const extractJsonString = json_helpers.extractJsonString;

// -- tests --

test "getSystemResources returns reasonable values" {
    const res = getSystemResources();
    try std.testing.expect(res.cpu_cores >= 1);
    try std.testing.expect(res.memory_mb >= 1);
}

test "ContainerState enum values" {
    const s: ContainerState = .starting;
    try std.testing.expect(s == .starting);
    try std.testing.expect(s != .running);
    try std.testing.expect(s != .stopped);
    try std.testing.expect(s != .failed);
}

test "Agent init creates empty local_containers" {
    const alloc = std.testing.allocator;
    var agent = Agent.init(alloc, .{ 127, 0, 0, 1 }, 7700, "test-token");
    defer agent.local_containers.deinit();

    try std.testing.expectEqual(@as(u32, 0), agent.local_containers.count());
    try std.testing.expect(!agent.running.load(.acquire));
}
