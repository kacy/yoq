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
    token_create,
    token_revoke,

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
            .token_create => "token_create",
            .token_revoke => "token_revoke",
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

// an explicit actor name (e.g. an API token name) takes precedence over the
// enum when set. len 0 means "use the enum label".
threadlocal var actor_name_buf: [64]u8 = undefined;
threadlocal var actor_name_len: usize = 0;

pub fn setActor(actor: Actor) void {
    current_actor = actor;
    actor_name_len = 0;
}

/// set a free-text actor name (overrides the enum until reset). used by the API
/// dispatch to record the authenticated token's name.
pub fn setActorName(name: []const u8) void {
    const n = @min(name.len, actor_name_buf.len);
    @memcpy(actor_name_buf[0..n], name[0..n]);
    actor_name_len = n;
}

pub fn resetActor() void {
    current_actor = .local;
    actor_name_len = 0;
}

fn actorLabel() []const u8 {
    if (actor_name_len > 0) return actor_name_buf[0..actor_name_len];
    return current_actor.label();
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
    store.appendAuditEntry(actorLabel(), action.label(), target, outcome.label(), nowSeconds()) catch |err| {
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

test "setActorName overrides the enum label until reset" {
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();
    defer resetActor();

    setActorName("deploy-token");
    record(.app_apply, "web", .ok);

    var entries = try store.listAuditEntries(alloc, 1);
    defer {
        for (entries.items) |e| e.deinit(alloc);
        entries.deinit(alloc);
    }
    try std.testing.expectEqualStrings("deploy-token", entries.items[0].actor);

    // setActor clears the name override.
    setActor(.local);
    record(.app_apply, "web", .ok);
    var again = try store.listAuditEntries(alloc, 1);
    defer {
        for (again.items) |e| e.deinit(alloc);
        again.deinit(alloc);
    }
    try std.testing.expectEqualStrings("local", again.items[0].actor);
}

test "actor defaults to local and resets" {
    try std.testing.expectEqual(Actor.local, currentActor());
    setActor(.join_token);
    try std.testing.expectEqual(Actor.join_token, currentActor());
    resetActor();
    try std.testing.expectEqual(Actor.local, currentActor());
}
