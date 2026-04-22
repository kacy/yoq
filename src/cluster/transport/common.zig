const std = @import("std");
const posix = std.posix;
const types = @import("../raft_types.zig");

pub const NodeId = types.NodeId;
pub const LogEntry = types.LogEntry;
pub const RequestVoteArgs = types.RequestVoteArgs;
pub const RequestVoteReply = types.RequestVoteReply;
pub const AppendEntriesArgs = types.AppendEntriesArgs;
pub const AppendEntriesReply = types.AppendEntriesReply;
pub const InstallSnapshotArgs = types.InstallSnapshotArgs;
pub const InstallSnapshotReply = types.InstallSnapshotReply;

pub const TransportError = error{
    ConnectFailed,
    SendFailed,
    ReceiveFailed,
    InvalidMessage,
    AuthenticationFailed,
    PeerNotFound,
};

pub const Message = union(enum) {
    request_vote: RequestVoteArgs,
    request_vote_reply: RequestVoteReply,
    append_entries: AppendEntriesArgs,
    append_entries_reply: AppendEntriesReply,
    install_snapshot: InstallSnapshotArgs,
    install_snapshot_reply: InstallSnapshotReply,
};

pub const ReceivedMessage = struct {
    from_addr: @import("compat").net.Address,
    sender_id: ?NodeId,
    message: Message,
};

pub const PeerAddr = struct {
    addr: @import("compat").net.Address,
};

pub const VerifiedBody = struct {
    sender_id: ?NodeId,
    payload: []const u8,
};

pub const GossipReceiveResult = struct {
    sender_id: u64,
    from_addr: @import("compat").net.Address,
    payload: []const u8,
};

pub const msg_request_vote: u8 = 0x01;
pub const msg_request_vote_reply: u8 = 0x02;
pub const msg_append_entries: u8 = 0x03;
pub const msg_append_entries_reply: u8 = 0x04;
pub const msg_install_snapshot: u8 = 0x05;
pub const msg_install_snapshot_reply: u8 = 0x06;

pub const max_receive_size: u32 = 64 * 1024 * 1024;

pub fn samePeerIp(expected: @import("compat").net.Address, actual: @import("compat").net.Address) bool {
    if (expected.any.family != actual.any.family) return false;
    return std.mem.eql(u8, std.mem.asBytes(&expected.in.addr), std.mem.asBytes(&actual.in.addr));
}

pub fn writeU64(buf: []u8, val: u64) void {
    std.mem.writeInt(u64, buf[0..8], val, .little);
}

pub fn writeU32(buf: []u8, val: u32) void {
    std.mem.writeInt(u32, buf[0..4], val, .little);
}

pub fn readU64(buf: []const u8) u64 {
    return std.mem.readInt(u64, buf[0..8], .little);
}

pub fn readU32(buf: []const u8) u32 {
    return std.mem.readInt(u32, buf[0..4], .little);
}

pub fn readExact(fd: @import("compat").posix.socket_t, buf: []u8) !void {
    var total: usize = 0;
    while (total < buf.len) {
        const bytes_read = posix.read(fd, buf[total..]) catch return error.ReadFailed;
        if (bytes_read == 0) return error.ReadFailed;
        total += bytes_read;
    }
}
