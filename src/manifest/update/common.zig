const std = @import("std");

pub const FailureAction = enum {
    rollback,
    pause,
};

pub const DeploymentStatus = enum {
    pending,
    in_progress,
    completed,
    failed,
    rolled_back,

    pub fn toString(self: DeploymentStatus) []const u8 {
        return switch (self) {
            .pending => "pending",
            .in_progress => "in_progress",
            .completed => "completed",
            .failed => "failed",
            .rolled_back => "rolled_back",
        };
    }

    pub fn fromString(s: []const u8) ?DeploymentStatus {
        if (std.mem.eql(u8, s, "pending")) return .pending;
        if (std.mem.eql(u8, s, "in_progress")) return .in_progress;
        if (std.mem.eql(u8, s, "completed")) return .completed;
        if (std.mem.eql(u8, s, "failed")) return .failed;
        if (std.mem.eql(u8, s, "rolled_back")) return .rolled_back;
        return null;
    }
};

pub const UpdateStrategy = struct {
    parallelism: u32 = 1,
    delay_between_batches: u32 = 0,
    failure_action: FailureAction = .rollback,
    health_check_timeout: u32 = 60,
};

pub const Deployment = struct {
    id: []const u8,
    service_name: []const u8,
    manifest_hash: []const u8,
    config_snapshot: []const u8,
    status: DeploymentStatus,
    message: ?[]const u8,
    created_at: i64,
};

pub const UpdateProgress = struct {
    total_containers: usize,
    replaced: usize,
    failed: usize,
    status: DeploymentStatus,
    message: ?[]const u8,
};

pub const UpdateError = error{
    BatchFailed,
    UpdatePaused,
    NoPreviousDeployment,
    StoreFailed,
    ContainerOperationFailed,
};

pub const UpdateCallbacks = struct {
    stopContainer: *const fn (id: []const u8) bool,
    startContainer: *const fn (config: []const u8, index: usize) ?[12]u8,
    isHealthy: *const fn (id: []const u8) bool,
};

pub const UpdateContext = struct {
    service_name: []const u8,
    manifest_hash: []const u8,
    config_snapshot: []const u8,
    old_container_ids: []const []const u8,
    callbacks: UpdateCallbacks,
};
