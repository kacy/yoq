const types = @import("../raft_types.zig");

const NodeId = types.NodeId;
const Term = types.Term;

pub fn stepDown(self: anytype, new_term: Term, min_election_ticks: u32, max_election_ticks: u32) bool {
    if (!self.log.setCurrentTerm(new_term)) return false;
    if (!self.log.setVotedFor(null)) return false;
    self.role = .follower;
    self.ticks_since_event = 0;
    resetElectionTimeout(self, min_election_ticks, max_election_ticks);
    return true;
}

pub fn resetElectionTimeout(self: anytype, min_election_ticks: u32, max_election_ticks: u32) void {
    const range = max_election_ticks - min_election_ticks;
    self.election_timeout = min_election_ticks + self.rng.random().intRangeAtMost(u32, 0, range);
}

pub fn peerIndex(self: anytype, id: NodeId) ?usize {
    for (self.peers, 0..) |peer, i| {
        if (peer == id) return i;
    }
    return null;
}
