// agent — cluster agent runtime
//
// an agent is a worker node that connects to the cluster server,
// reports its capacity, and runs assigned containers. the agent
// uses a pull-based model: it polls the server every few seconds
// for heartbeat updates and work assignments.
//
// flow:
//   1. register with server (POST /agents/register)
//   2. enter loop: heartbeat + poll for assignments every 5s
//   3. reconcile local containers with server assignments
//   4. on shutdown, stop local containers and exit
//
// the agent reuses the existing container runtime for actually
// running containers. for now, images must be pre-pulled on
// the agent node — automatic pulling is deferred.

const std = @import("std");
const posix = std.posix;
const http_client = @import("http_client.zig");
const agent_types = @import("agent_types.zig");
const cli = @import("../lib/cli.zig");
const json_helpers = @import("../lib/json_helpers.zig");

const Allocator = std.mem.Allocator;
const AgentResources = agent_types.AgentResources;

const write = cli.write;
const writeErr = cli.writeErr;

pub const AgentError = error{
    RegisterFailed,
    InvalidResponse,
};

pub const Agent = struct {
    alloc: Allocator,
    id: [12]u8,
    server_addr: [4]u8,
    server_port: u16,
    token: []const u8,
    running: std.atomic.Value(bool),
    loop_thread: ?std.Thread,

    pub fn init(alloc: Allocator, server_addr: [4]u8, server_port: u16, token: []const u8) Agent {
        return .{
            .alloc = alloc,
            .id = undefined,
            .server_addr = server_addr,
            .server_port = server_port,
            .token = token,
            .running = std.atomic.Value(bool).init(false),
            .loop_thread = null,
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

        var resp = http_client.post(
            self.alloc,
            self.server_addr,
            self.server_port,
            "/agents/register",
            body,
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
            // sleep 5 seconds between heartbeats
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

        var resp = http_client.post(
            self.alloc,
            self.server_addr,
            self.server_port,
            path,
            body,
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

// extractJsonString tests are in json_helpers.zig
