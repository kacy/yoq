const std = @import("std");
const types = @import("../raft_types.zig");

pub const Term = types.Term;
pub const LogIndex = types.LogIndex;
pub const NodeId = types.NodeId;
pub const LogEntry = types.LogEntry;
pub const SnapshotMeta = types.SnapshotMeta;

pub const LogError = error{
    DbOpenFailed,
    WriteFailed,
    ReadFailed,
    CorruptedLog,
};

pub inline fn safeU64(val: i64) LogError!u64 {
    return std.math.cast(u64, val) orelse LogError.CorruptedLog;
}
