// audit — append-only trail of sensitive operations, keyed by actor.
//
// records who did what: secret changes, app apply/rollback, agent join/drain,
// policy changes, backup/restore. entries are written to the audit_log table
// via the store and read back through GET /v1/audit and `yoq audit`.
//
// the actor is coarse today (there is no RBAC yet): a request authenticated
// with the api token is "api-token", a join-token request is "join-token", and
// a local CLI process is "local". the API server sets the actor per request in
// dispatch(); a CLI process leaves the default "local". because the server
// handles requests concurrently, current_actor is `threadlocal` so two requests
// on different threads never clobber each other's actor.

const std = @import("std");
const store = @import("store.zig");
const log = @import("../lib/log.zig");

pub const Actor = enum {
    api_token,
    join_token,
    local,
    unauthenticated,

    pub fn label(self: Actor) []const u8 {
        return switch (self) {
            .api_token => "api-token",
            .join_token => "join-token",
            .local => "local",
            .unauthenticated => "unauthenticated",
        };
    }
};

pub const Action = enum {
    secret_set,
    secret_delete,
    secret_list,
    secret_rotate,
    app_apply,
    app_rollback,
    agent_register,
    agent_drain,
    policy_add,
    policy_delete,
    backup,
    restore,

    pub fn label(self: Action) []const u8 {
        return switch (self) {
            .secret_set => "secret_set",
            .secret_delete => "secret_delete",
            .secret_list => "secret_list",
            .secret_rotate => "secret_rotate",
            .app_apply => "app_apply",
            .app_rollback => "app_rollback",
            .agent_register => "agent_register",
            .agent_drain => "agent_drain",
            .policy_add => "policy_add",
            .policy_delete => "policy_delete",
            .backup => "backup",
            .restore => "restore",
        };
    }
};

pub const Outcome = enum {
    ok,
    failed,

    pub fn label(self: Outcome) []const u8 {
        return switch (self) {
            .ok => "ok",
            .failed => "failed",
        };
    }
};

/// the actor for operations performed on this thread. defaults to local so a
/// short-lived CLI process records correctly without any setup; the API server
/// overrides it per request.
threadlocal var current_actor: Actor = .local;

pub fn setActor(actor: Actor) void {
    current_actor = actor;
}

pub fn resetActor() void {
    current_actor = .local;
}

pub fn currentActor() Actor {
    return current_actor;
}

fn nowSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}

/// record a sensitive operation under the current thread's actor. best-effort:
/// a storage failure is logged but never propagated, so auditing can't break
/// the operation it is recording.
pub fn record(action: Action, target: ?[]const u8, outcome: Outcome) void {
    store.appendAuditEntry(current_actor.label(), action.label(), target, outcome.label(), nowSeconds()) catch |err| {
        log.warn("audit: failed to record {s} ({s}): {}", .{ action.label(), outcome.label(), err });
    };
}

// -- tests --

test "record writes an entry under the current actor" {
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();

    setActor(.api_token);
    defer resetActor();

    record(.secret_set, "db-password", .ok);

    var entries = try store.listAuditEntries(alloc, 10);
    defer {
        for (entries.items) |e| e.deinit(alloc);
        entries.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 1), entries.items.len);
    try std.testing.expectEqualStrings("api-token", entries.items[0].actor);
    try std.testing.expectEqualStrings("secret_set", entries.items[0].action);
    try std.testing.expectEqualStrings("db-password", entries.items[0].target.?);
    try std.testing.expectEqualStrings("ok", entries.items[0].outcome);
}

test "actor defaults to local and resets" {
    try std.testing.expectEqual(Actor.local, currentActor());
    setActor(.join_token);
    try std.testing.expectEqual(Actor.join_token, currentActor());
    resetActor();
    try std.testing.expectEqual(Actor.local, currentActor());
}
