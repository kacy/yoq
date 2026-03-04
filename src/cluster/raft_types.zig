// raft_types — core types for the raft consensus protocol
//
// defines the fundamental types used across all raft modules:
// node identity, log entries, and RPC message structures.
// these follow the raft paper (Ongaro & Ousterhout, 2014) closely.

const std = @import("std");

pub const NodeId = u64;
pub const Term = u64;
pub const LogIndex = u64;

pub const Role = enum {
    follower,
    candidate,
    leader,
};

/// a single entry in the replicated log.
/// data is opaque bytes — the state machine interprets them.
pub const LogEntry = struct {
    index: LogIndex,
    term: Term,
    data: []const u8,
};

// -- RPC types --
//
// these map directly to the two RPCs in the raft protocol.
// keeping request/reply as separate structs makes serialization simple.

pub const RequestVoteArgs = struct {
    term: Term,
    candidate_id: NodeId,
    last_log_index: LogIndex,
    last_log_term: Term,
};

pub const RequestVoteReply = struct {
    term: Term,
    vote_granted: bool,
};

pub const AppendEntriesArgs = struct {
    term: Term,
    leader_id: NodeId,
    prev_log_index: LogIndex,
    prev_log_term: Term,
    entries: []const LogEntry,
    leader_commit: LogIndex,
};

pub const AppendEntriesReply = struct {
    term: Term,
    success: bool,
    match_index: LogIndex,
};

// -- tests --

test "role default" {
    const role: Role = .follower;
    try std.testing.expect(role == .follower);
}

test "log entry creation" {
    const entry = LogEntry{
        .index = 1,
        .term = 1,
        .data = "SET x 42",
    };
    try std.testing.expectEqual(@as(LogIndex, 1), entry.index);
    try std.testing.expectEqual(@as(Term, 1), entry.term);
    try std.testing.expectEqualStrings("SET x 42", entry.data);
}

test "request vote args" {
    const args = RequestVoteArgs{
        .term = 3,
        .candidate_id = 1,
        .last_log_index = 10,
        .last_log_term = 2,
    };
    try std.testing.expectEqual(@as(Term, 3), args.term);
    try std.testing.expectEqual(@as(NodeId, 1), args.candidate_id);
}

test "append entries args with empty entries" {
    const args = AppendEntriesArgs{
        .term = 5,
        .leader_id = 2,
        .prev_log_index = 0,
        .prev_log_term = 0,
        .entries = &.{},
        .leader_commit = 0,
    };
    try std.testing.expectEqual(@as(usize, 0), args.entries.len);
}
