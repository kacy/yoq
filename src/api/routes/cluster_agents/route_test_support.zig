const std = @import("std");

const cluster_node = @import("../../../cluster/node.zig");
const store = @import("../../../state/store.zig");
const common = @import("../common.zig");
const http = @import("../../http.zig");
const app_routes = @import("app_routes.zig");
const deploy_routes = @import("deploy_routes.zig");

pub const Response = common.Response;
pub const RouteContext = common.RouteContext;

const HarnessOptions = struct {
    init_runtime_store: bool = false,
    skip_on_agent_seed_failure: bool = false,
};

pub const Harness = struct {
    alloc: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    node: *cluster_node.Node,
    runtime_store_initialized: bool,

    pub fn init(alloc: std.mem.Allocator) !Harness {
        return initWithOptions(alloc, .{});
    }

    pub fn initWithRuntimeStore(alloc: std.mem.Allocator) !Harness {
        return initWithOptions(alloc, .{
            .init_runtime_store = true,
            .skip_on_agent_seed_failure = true,
        });
    }

    pub fn initWithOptions(alloc: std.mem.Allocator, options: HarnessOptions) !Harness {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();

        if (options.init_runtime_store) {
            try store.initTestDb();
            errdefer store.deinitTestDb();
        }

        var path_buf: [512]u8 = undefined;
        const tmp_path_len = try tmp.dir.realPathFile(std.testing.io, ".", &path_buf);
        const tmp_path = path_buf[0..tmp_path_len];

        const node = try alloc.create(cluster_node.Node);
        errdefer alloc.destroy(node);

        node.* = try cluster_node.Node.initForTests(alloc, .{
            .id = 1,
            .port = 0,
            .peers = &.{},
            .data_dir = tmp_path,
        });
        errdefer node.deinit();
        node.fixPointers();

        node.raft.role = .leader;
        node.leader_id = node.config.id;

        var harness = Harness{
            .alloc = alloc,
            .tmp = tmp,
            .node = node,
            .runtime_store_initialized = options.init_runtime_store,
        };
        harness.seedActiveAgent() catch |err| {
            if (options.skip_on_agent_seed_failure) return error.SkipZigTest;
            return err;
        };
        return harness;
    }

    pub fn deinit(self: *Harness) void {
        self.node.deinit();
        self.alloc.destroy(self.node);
        if (self.runtime_store_initialized) store.deinitTestDb();
        self.tmp.cleanup();
    }

    pub fn ctx(self: *Harness) RouteContext {
        return .{ .cluster = self.node, .join_token = null };
    }

    pub fn applyCommitted(self: *Harness) void {
        self.node.state_machine.applyUpTo(&self.node.log, self.alloc, self.node.log.lastIndex());
        self.node.raft.role = .leader;
        self.node.leader_id = self.node.config.id;
    }

    pub fn seedActiveAgent(self: *Harness) !void {
        try self.node.stateMachineDb().exec(
            "INSERT INTO agents (id, address, agent_api_port, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at, role, labels, gpu_count, gpu_used, gpu_model, gpu_vram_mb) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            .{},
            .{ "abc123def456", "10.0.0.2", @as(i64, 7701), "active", @as(i64, 8), @as(i64, 16384), @as(i64, 0), @as(i64, 0), @as(i64, 0), @as(i64, 100), @as(i64, 100), "agent", "", @as(i64, 4), @as(i64, 0), "L4", @as(i64, 24576) },
        );
    }

    pub fn seedLatestRelease(self: *Harness, app_name: []const u8, snapshot: []const u8) !void {
        try store.saveDeploymentInDb(self.node.stateMachineDb(), .{
            .id = "dep-seed",
            .app_name = app_name,
            .service_name = app_name,
            .trigger = "apply",
            .manifest_hash = "sha256:seed",
            .config_snapshot = snapshot,
            .status = "completed",
            .message = "apply completed",
            .created_at = 100,
        });
    }

    pub fn appApply(self: *Harness, body: []const u8) Response {
        return deploy_routes.handleAppApply(self.alloc, makeRequest(.POST, "/apps/apply", body), self.ctx());
    }

    pub fn rollback(self: *Harness, app_name: []const u8, release_id: []const u8) !Response {
        const body = try std.fmt.allocPrint(self.alloc, "{{\"release_id\":\"{s}\"}}", .{release_id});
        defer self.alloc.free(body);
        const path = try std.fmt.allocPrint(self.alloc, "/apps/{s}/rollback", .{app_name});
        defer self.alloc.free(path);
        return app_routes.handleAppRollback(self.alloc, app_name, makeRequest(.POST, path, body), self.ctx());
    }

    pub fn rollbackDefault(self: *Harness, app_name: []const u8) !Response {
        const path = try std.fmt.allocPrint(self.alloc, "/apps/{s}/rollback", .{app_name});
        defer self.alloc.free(path);
        return app_routes.handleAppRollback(self.alloc, app_name, makeRequest(.POST, path, "{\"print\":false}"), self.ctx());
    }

    pub fn rollbackPrint(self: *Harness, app_name: []const u8) !Response {
        const path = try std.fmt.allocPrint(self.alloc, "/apps/{s}/rollback", .{app_name});
        defer self.alloc.free(path);
        return app_routes.handleAppRollback(self.alloc, app_name, makeRequest(.POST, path, "{\"print\":true}"), self.ctx());
    }

    pub fn status(self: *Harness, app_name: []const u8) Response {
        return app_routes.handleAppStatus(self.alloc, app_name, self.ctx());
    }

    pub fn history(self: *Harness, app_name: []const u8) Response {
        return app_routes.handleAppHistory(self.alloc, app_name, self.ctx());
    }

    pub fn listApps(self: *Harness) Response {
        return app_routes.handleListApps(self.alloc, self.ctx());
    }

    pub fn rolloutControl(self: *Harness, app_name: []const u8, action: []const u8) !Response {
        const path = try std.fmt.allocPrint(self.alloc, "/apps/{s}/rollout/{s}", .{ app_name, action });
        defer self.alloc.free(path);
        return app_routes.route(makeRequest(.POST, path, "{}"), self.alloc, self.ctx()).?;
    }
};

pub fn makeRequest(method: http.Method, path: []const u8, body: []const u8) http.Request {
    return makeRequestWithQuery(method, path, body, "");
}

pub fn makeRequestWithQuery(method: http.Method, path: []const u8, body: []const u8, query: []const u8) http.Request {
    return .{
        .method = method,
        .path = path,
        .path_only = path,
        .query = query,
        .headers_raw = "",
        .body = body,
        .content_length = body.len,
    };
}

pub fn freeResponse(alloc: std.mem.Allocator, response: Response) void {
    if (response.allocated) alloc.free(response.body);
}

pub fn expectJsonContains(json: []const u8, needle: []const u8) !void {
    try std.testing.expect(std.mem.indexOf(u8, json, needle) != null);
}

pub fn expectResponseOk(response: Response) !void {
    try std.testing.expectEqual(http.StatusCode.ok, response.status);
}
