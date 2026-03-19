const std = @import("std");

pub fn currentTerm(self: anytype) @TypeOf(self.raft.currentTerm()) {
    self.mu.lock();
    defer self.mu.unlock();
    return self.raft.currentTerm();
}

pub fn role(self: anytype) @TypeOf(self.raft.role) {
    self.mu.lock();
    defer self.mu.unlock();
    return self.raft.role;
}

pub fn leaderId(self: anytype) @TypeOf(self.leader_id) {
    self.mu.lock();
    defer self.mu.unlock();
    return self.leader_id;
}

pub fn leaderAddrBuf(self: anytype, buf: []u8) ?[]const u8 {
    self.mu.lock();
    defer self.mu.unlock();

    const lid = self.leader_id orelse return null;
    if (lid == self.config.id) return null;

    for (self.config.peers) |p| {
        if (p.id == lid) {
            return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}:{d}", .{
                p.addr[0], p.addr[1], p.addr[2], p.addr[3], self.config.api_port,
            }) catch null;
        }
    }

    return null;
}

pub fn gossipMemberCount(self: anytype) usize {
    self.mu.lock();
    defer self.mu.unlock();
    const g = self.gossip orelse return 0;
    return g.members.count();
}
