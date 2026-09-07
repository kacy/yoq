// An operation keeps the leadership term it began in. Re-election of the same
// server must not revive an older in-flight rollout.
const std = @import("std");
const node_mod = @import("node.zig");

pub const Error = error{ NotLeader, InternalError, CommitUnknown, Conflict };
pub fn mapError(err: anyerror) Error {
    return switch (err) {
        error.NotLeader, error.LeadershipLost => error.NotLeader,
        error.CommitTimeout, error.CommitUnknown => error.CommitUnknown,
        error.CommandRejected, error.Conflict => error.Conflict,
        else => error.InternalError,
    };
}

pub const Session = struct {
    node: *node_mod.Node,
    term: u64,

    pub fn begin(node: *node_mod.Node) Error!Session {
        node.mu.lockUncancelable(std.Options.debug_io);
        defer node.mu.unlock(std.Options.debug_io);
        if (node.raft.role != .leader) return error.NotLeader;
        return .{ .node = node, .term = node.raft.persistent_state.current_term };
    }

    /// Call with the node lock held before reading operation state.
    pub fn checkLocked(self: Session) Error!void {
        if (self.node.raft.role != .leader or self.node.raft.persistent_state.current_term != self.term)
            return error.NotLeader;
        if (self.node.snapshot_failed.load(.acquire) or self.node.raft.storage_failed) return error.InternalError;
    }

    /// Apply an entry in this term before making a decision from local state.
    /// This includes inherited proposals that a new leader has not applied yet.
    pub fn synchronize(self: Session) Error!void {
        try self.commit("UPDATE agents SET id = id WHERE 0;");
    }

    pub fn check(self: Session) Error!void {
        self.node.mu.lockUncancelable(std.Options.debug_io);
        defer self.node.mu.unlock(std.Options.debug_io);
        try self.checkLocked();
    }

    pub fn commit(self: Session, sql: []const u8) Error!void {
        _ = self.node.proposeCommittedInTerm(sql, self.term, 5000) catch |err| return mapError(err);
    }
};
