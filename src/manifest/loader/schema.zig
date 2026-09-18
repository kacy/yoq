const std = @import("std");
const toml = @import("../../lib/toml.zig");
const log = @import("../../lib/log.zig");
const common = @import("common.zig");

const Kind = enum {
    root,
    services,
    workers,
    crons,
    volumes,
    training_jobs,
    routes,
    service,
    worker,
    cron,
    volume,
    training,
    backup,
    health,
    rollout,
    tls,
    acme,
    dns,
    route,
    gpu,
    gpu_mesh,
    alerts,
    data,
    checkpoint,
    resources,
    fault_tolerance,
};

const ValueType = enum { string, integer, number, boolean, array, table };
const Rule = struct {
    value_type: ValueType,
    child: ?Kind = null,
};

pub const Issue = struct {
    path: []const u8,
    expected: ?ValueType,

    pub fn deinit(self: Issue, alloc: std.mem.Allocator) void {
        alloc.free(self.path);
    }
};

pub fn validate(alloc: std.mem.Allocator, root: *const toml.Table) common.LoadError!void {
    if (try findIssue(alloc, root)) |issue| {
        defer issue.deinit(alloc);
        if (issue.expected) |expected| {
            log.err("manifest: '{s}' must be a {s}", .{ issue.path, @tagName(expected) });
            return error.InvalidFieldType;
        }
        log.err("manifest: unknown field '{s}'", .{issue.path});
        return error.UnknownField;
    }
}

pub fn findIssue(alloc: std.mem.Allocator, root: *const toml.Table) error{OutOfMemory}!?Issue {
    return inspect(alloc, root, .root, "");
}

fn inspect(alloc: std.mem.Allocator, table: *const toml.Table, kind: Kind, prefix: []const u8) error{OutOfMemory}!?Issue {
    for (table.entries.keys(), table.entries.values()) |key, value| {
        const path = if (prefix.len == 0) try alloc.dupe(u8, key) else try std.fmt.allocPrint(alloc, "{s}.{s}", .{ prefix, key });
        defer alloc.free(path);
        const rule = fieldRule(kind, key) orelse return Issue{ .path = try alloc.dupe(u8, path), .expected = null };
        if (!matches(value, rule.value_type)) {
            return Issue{ .path = try alloc.dupe(u8, path), .expected = rule.value_type };
        }
        if (rule.child) |child| {
            if (try inspect(alloc, value.table, child, path)) |issue| return issue;
        }
    }
    return null;
}

fn matches(value: toml.Value, expected: ValueType) bool {
    return switch (expected) {
        .string => value == .string,
        .integer => value == .integer,
        .number => value == .integer or value == .float,
        .boolean => value == .boolean,
        .array => value == .array,
        .table => value == .table,
    };
}

fn namedTable(child: Kind) Rule {
    return .{ .value_type = .table, .child = child };
}

fn fieldRule(kind: Kind, key: []const u8) ?Rule {
    switch (kind) {
        .root => {
            const sections = .{ .{ "service", Kind.services }, .{ "worker", Kind.workers }, .{ "cron", Kind.crons }, .{ "volume", Kind.volumes }, .{ "training", Kind.training_jobs }, .{ "backup", Kind.backup } };
            inline for (sections) |section| if (std.mem.eql(u8, key, section[0])) return namedTable(section[1]);
            return null;
        },
        .services => return namedTable(.service),
        .workers => return namedTable(.worker),
        .crons => return namedTable(.cron),
        .volumes => return namedTable(.volume),
        .training_jobs => return namedTable(.training),
        .routes => return namedTable(.route),
        else => {},
    }

    if (kind == .service or kind == .worker or kind == .cron or kind == .training) {
        if (oneOf(key, &.{ "image", "working_dir" })) return .{ .value_type = .string };
        if (oneOf(key, &.{ "command", "env", "volumes" })) return .{ .value_type = .array };
    }
    if (kind == .service or kind == .worker) {
        if (std.mem.eql(u8, key, "depends_on")) return .{ .value_type = .array };
        if (std.mem.eql(u8, key, "required_labels")) return .{ .value_type = .string };
        if (std.mem.eql(u8, key, "gpu")) return namedTable(.gpu);
        if (std.mem.eql(u8, key, "gpu_mesh")) return namedTable(.gpu_mesh);
    }

    switch (kind) {
        .service => {
            if (std.mem.eql(u8, key, "ports")) return .{ .value_type = .array };
            if (std.mem.eql(u8, key, "restart")) return .{ .value_type = .string };
            if (oneOf(key, &.{ "replicas", "cpu_limit", "memory_limit_mb" })) return .{ .value_type = .integer };
            const sections = .{ .{ "health_check", Kind.health }, .{ "rollout", Kind.rollout }, .{ "tls", Kind.tls }, .{ "http_proxy", Kind.route }, .{ "http_routes", Kind.routes }, .{ "alerts", Kind.alerts } };
            inline for (sections) |section| if (std.mem.eql(u8, key, section[0])) return namedTable(section[1]);
        },
        .worker => {},
        .cron => if (std.mem.eql(u8, key, "every")) return .{ .value_type = .string },
        .training => {
            if (std.mem.eql(u8, key, "gpus")) return .{ .value_type = .integer };
            if (std.mem.eql(u8, key, "gpu_type")) return .{ .value_type = .string };
            const sections = .{ .{ "data", Kind.data }, .{ "checkpoint", Kind.checkpoint }, .{ "resources", Kind.resources }, .{ "fault_tolerance", Kind.fault_tolerance } };
            inline for (sections) |section| if (std.mem.eql(u8, key, section[0])) return namedTable(section[1]);
        },
        .volume => if (oneOf(key, &.{ "type", "driver", "path", "mount_path", "server", "options" })) return .{ .value_type = .string },
        .backup => {
            if (oneOf(key, &.{ "every", "output_dir", "max_age" })) return .{ .value_type = .string };
            if (oneOf(key, &.{ "keep_count", "max_bytes" })) return .{ .value_type = .integer };
            if (std.mem.eql(u8, key, "encrypt")) return .{ .value_type = .boolean };
        },
        .health => {
            if (oneOf(key, &.{ "type", "path", "service" })) return .{ .value_type = .string };
            if (oneOf(key, &.{ "port", "interval", "timeout", "retries", "start_period" })) return .{ .value_type = .integer };
            if (std.mem.eql(u8, key, "command")) return .{ .value_type = .array };
        },
        .rollout => {
            if (oneOf(key, &.{ "strategy", "failure_action", "delay_between_batches", "health_check_timeout" })) return .{ .value_type = .string };
            if (std.mem.eql(u8, key, "parallelism")) return .{ .value_type = .integer };
        },
        .tls => {
            if (oneOf(key, &.{ "domain", "peer" })) return .{ .value_type = .string };
            if (std.mem.eql(u8, key, "acme")) return namedTable(.acme);
        },
        .acme => {
            if (oneOf(key, &.{ "email", "directory_url", "challenge" })) return .{ .value_type = .string };
            if (std.mem.eql(u8, key, "staging")) return .{ .value_type = .boolean };
            if (std.mem.eql(u8, key, "dns")) return namedTable(.dns);
        },
        .dns => {
            if (std.mem.eql(u8, key, "provider")) return .{ .value_type = .string };
            if (oneOf(key, &.{ "secrets", "config", "hook" })) return .{ .value_type = .array };
            if (oneOf(key, &.{ "propagation_timeout_secs", "poll_interval_secs" })) return .{ .value_type = .integer };
        },
        .route => {
            if (oneOf(key, &.{ "host", "path_prefix", "rewrite_prefix", "mirror_service" })) return .{ .value_type = .string };
            if (oneOf(key, &.{ "match_methods", "match_headers", "backend_services" })) return .{ .value_type = .array };
            if (oneOf(key, &.{ "retries", "connect_timeout_ms", "request_timeout_ms", "http2_idle_timeout_ms", "circuit_breaker_threshold", "circuit_breaker_timeout_ms" })) return .{ .value_type = .integer };
            if (oneOf(key, &.{ "preserve_host", "retry_on_5xx" })) return .{ .value_type = .boolean };
        },
        .gpu => {
            if (oneOf(key, &.{ "count", "vram_min_mb" })) return .{ .value_type = .integer };
            if (std.mem.eql(u8, key, "model")) return .{ .value_type = .string };
        },
        .gpu_mesh => if (oneOf(key, &.{ "world_size", "gpus_per_rank", "master_port" })) return .{ .value_type = .integer },
        .alerts => {
            if (oneOf(key, &.{ "cpu_percent", "memory_percent", "latency_p99_ms", "error_rate_percent" })) return .{ .value_type = .number };
            if (std.mem.eql(u8, key, "restart_count")) return .{ .value_type = .integer };
            if (std.mem.eql(u8, key, "webhook")) return .{ .value_type = .string };
        },
        .data => if (oneOf(key, &.{ "dataset", "sharding", "preprocessing" })) return .{ .value_type = .string },
        .checkpoint => {
            if (oneOf(key, &.{ "path", "interval" })) return .{ .value_type = .string };
            if (oneOf(key, &.{ "interval_secs", "keep" })) return .{ .value_type = .integer };
        },
        .resources => {
            if (oneOf(key, &.{ "cpu", "memory_mb" })) return .{ .value_type = .integer };
            if (std.mem.eql(u8, key, "ib_required")) return .{ .value_type = .boolean };
        },
        .fault_tolerance => {
            if (oneOf(key, &.{ "spare_ranks", "max_restarts" })) return .{ .value_type = .integer };
            if (std.mem.eql(u8, key, "auto_restart")) return .{ .value_type = .boolean };
        },
        else => unreachable,
    }
    return null;
}

fn oneOf(key: []const u8, choices: []const []const u8) bool {
    for (choices) |choice| if (std.mem.eql(u8, key, choice)) return true;
    return false;
}

test "unknown manifest keys report the complete path" {
    const alloc = std.testing.allocator;
    const examples = .{
        .{ "[services.web]\nimage = \"nginx\"", "services", false },
        .{ "[service.web]\nrepilcas = 3", "service.web.repilcas", false },
        .{ "[service.web.http_routes.api]\nrequest_timout_ms = 1", "service.web.http_routes.api.request_timout_ms", false },
        .{ "[service.web.tls.acme.dns]\nprovidre = \"exec\"", "service.web.tls.acme.dns.providre", false },
        .{ "[service.web]\nreplicas = \"3\"", "service.web.replicas", true },
        .{ "service = false", "service", true },
    };
    inline for (examples) |example| {
        var parsed = try toml.parse(alloc, example[0]);
        defer parsed.deinit();
        const issue = (try findIssue(alloc, &parsed.root)) orelse return error.ExpectedDiagnostic;
        defer issue.deinit(alloc);
        try std.testing.expectEqualStrings(example[1], issue.path);
        try std.testing.expectEqual(example[2], issue.expected != null);
    }
}
