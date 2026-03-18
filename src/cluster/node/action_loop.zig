const std = @import("std");
const transport_mod = @import("../transport.zig");
const types = @import("../raft_types.zig");
const agent_registry = @import("../registry.zig");
const membership_sync = @import("membership_sync.zig");
const snapshot_support = @import("snapshot_support.zig");
const logger = @import("../../lib/log.zig");

const NodeId = types.NodeId;
const SnapshotMeta = types.SnapshotMeta;

fn freeEntries(alloc: std.mem.Allocator, entries: []const types.LogEntry) void {
    for (entries) |entry| alloc.free(entry.data);
    if (entries.len > 0) alloc.free(entries);
}

pub fn tickLoop(self: anytype) void {
    while (self.running.load(.acquire)) {
        var agents: ?[]agent_registry.AgentRecord = null;
        var reconcile_orphans: ?[]agent_registry.Assignment = null;
        var heartbeat_batch: ?[]const u8 = null;
        var do_health = false;
        var do_reconcile = false;
        var do_cleanup = false;

        {
            self.mu.lock();
            const is_leader = self.raft.role == .leader;
            const tick = self.tick_count +% 1;
            self.mu.unlock();

            if (is_leader) {
                do_health = tick % 300 == 0;
                do_reconcile = tick % 100 == 0;
                do_cleanup = tick % 3600 == 0;
                if (do_health or do_reconcile or do_cleanup)
                    agents = agent_registry.listAgents(self.alloc, &self.state_machine.db) catch null;
                if (do_reconcile)
                    reconcile_orphans = agent_registry.getOrphanedAssignments(self.alloc, &self.state_machine.db) catch null;
                if (tick % 20 == 0)
                    heartbeat_batch = self.heartbeat_batcher.flush(self.alloc) catch null;
            }
        }
        defer {
            if (agents) |records| {
                for (records) |record| record.deinit(self.alloc);
                self.alloc.free(records);
            }
            if (reconcile_orphans) |orphans| {
                for (orphans) |assignment| assignment.deinit(self.alloc);
                self.alloc.free(orphans);
            }
            if (heartbeat_batch) |batch| self.alloc.free(batch);
        }

        {
            self.mu.lock();
            defer self.mu.unlock();

            self.raft.tick();
            processActions(self);

            self.tick_count +%= 1;
            if (self.raft.role == .leader) {
                if (agents) |records| {
                    if (do_health) membership_sync.checkAgentHealth(self, records);
                    if (do_reconcile) membership_sync.reconcileOrphanedAssignments(self, reconcile_orphans orelse &.{}, records);
                    if (do_cleanup) membership_sync.cleanupDeadAgents(self, records);
                }
                if (heartbeat_batch) |batch| {
                    _ = self.raft.propose(batch) catch |e| {
                        logger.warn("failed to propose heartbeat batch: {}", .{e});
                    };
                }
            }

            if (self.gossip != null and self.tick_count % 5 == 0) {
                membership_sync.tickGossip(self);
            }

            snapshot_support.maybeSnapshot(self);
        }
        std.Thread.sleep(100 * std.time.ns_per_ms);
    }
}

pub fn recvLoop(self: anytype) void {
    while (self.running.load(.acquire)) {
        const msg = self.transport.receive(self.alloc) catch {
            std.Thread.sleep(10 * std.time.ns_per_ms);
            continue;
        };

        if (msg) |received| {
            self.mu.lock();
            defer self.mu.unlock();

            handleMessage(self, received);
            processActions(self);
        } else {
            membership_sync.receiveGossipMessages(self);
            std.Thread.sleep(10 * std.time.ns_per_ms);
        }
    }
}

pub fn handleMessage(self: anytype, received: transport_mod.ReceivedMessage) void {
    const sender_id = received.sender_id orelse resolveNodeId(self, received.from_addr);

    switch (received.message) {
        .request_vote => |args| {
            const peer_id = sender_id orelse {
                logger.warn("request_vote from unknown address, dropping", .{});
                return;
            };
            if (args.candidate_id != peer_id) {
                logger.warn("request_vote claimed node {} from authenticated peer {}, dropping", .{ args.candidate_id, peer_id });
                return;
            }

            const reply = self.raft.handleRequestVote(args);
            self.transport.send(peer_id, .{ .request_vote_reply = reply }) catch |e| {
                logger.warn("failed to send vote reply to node {}: {}", .{ peer_id, e });
            };
        },
        .request_vote_reply => |reply| {
            if (sender_id) |peer_id| {
                self.raft.handleRequestVoteReply(peer_id, reply);
            } else {
                logger.warn("request_vote_reply from unknown address, dropping", .{});
            }
        },
        .append_entries => |args| {
            defer freeEntries(self.alloc, args.entries);
            const peer_id = sender_id orelse {
                logger.warn("append_entries from unknown address, dropping", .{});
                return;
            };
            if (args.leader_id != peer_id) {
                logger.warn("append_entries claimed leader {} from authenticated peer {}, dropping", .{ args.leader_id, peer_id });
                return;
            }

            const reply = self.raft.handleAppendEntries(args);
            self.transport.send(peer_id, .{ .append_entries_reply = reply }) catch |e| {
                logger.warn("failed to send append entries reply to node {}: {}", .{ peer_id, e });
            };
        },
        .append_entries_reply => |reply| {
            if (sender_id) |id| {
                self.raft.handleAppendEntriesReply(id, reply);
            } else {
                logger.warn("append_entries_reply from unknown address, dropping", .{});
            }
        },
        .install_snapshot => |args| {
            const peer_id = sender_id orelse {
                logger.warn("install_snapshot from unknown address, dropping", .{});
                self.alloc.free(args.data);
                return;
            };
            if (args.leader_id != peer_id) {
                logger.warn("install_snapshot claimed leader {} from authenticated peer {}, dropping", .{ args.leader_id, peer_id });
                self.alloc.free(args.data);
                return;
            }

            const commit_before = self.raft.commit_index;
            const reply = self.raft.handleInstallSnapshot(args);
            self.transport.send(peer_id, .{ .install_snapshot_reply = reply }) catch |e| {
                logger.warn("failed to send snapshot reply to node {}: {}", .{ peer_id, e });
            };

            if (self.raft.commit_index == commit_before) {
                self.alloc.free(args.data);
            }
        },
        .install_snapshot_reply => |reply| {
            if (sender_id) |id| {
                self.raft.handleInstallSnapshotReply(id, reply);
            } else {
                logger.warn("install_snapshot_reply from unknown address, dropping", .{});
            }
        },
    }
}

pub fn resolveNodeId(self: anytype, addr: std.net.Address) ?NodeId {
    const from_ip: [4]u8 = @bitCast(addr.in.sa.addr);
    const from_port = std.mem.bigToNative(u16, addr.in.sa.port);

    for (self.config.peers) |peer| {
        if (std.mem.eql(u8, &peer.addr, &from_ip) and peer.port == from_port) {
            return peer.id;
        }
    }
    return null;
}

pub fn processActions(self: anytype) void {
    const actions = self.raft.drainActions();
    defer self.alloc.free(actions);

    var has_sends = false;
    for (actions) |action| {
        switch (action) {
            .commit_entries => |commit| {
                self.state_machine.applyUpTo(&self.log, self.alloc, commit.up_to);
            },
            .become_leader => {
                self.leader_id = self.config.id;
            },
            .become_follower => |follower| {
                self.leader_id = follower.leader_id;
            },
            .apply_snapshot => |snap| {
                defer self.alloc.free(snap.data);

                const meta = self.state_machine.restoreFromBytes(snap.data) catch |e| {
                    logger.warn("snapshot: failed to restore from bytes: {}", .{e});
                    continue;
                };

                self.log.setSnapshotMeta(meta);
                self.log.truncateUpTo(meta.last_included_index);
                self.last_snapshot_index = meta.last_included_index;
                logger.info("snapshot: restored state machine to index {}", .{meta.last_included_index});
            },
            .take_snapshot => |snap| {
                var snap_path_buf: [512]u8 = undefined;
                const snap_path = @import("bootstrap.zig").snapshotPath(&snap_path_buf, self.config.data_dir) orelse continue;

                const meta = SnapshotMeta{
                    .last_included_index = snap.up_to_index,
                    .last_included_term = snap.term,
                    .data_len = 0,
                };

                self.state_machine.takeSnapshot(snap_path, meta) catch |e| {
                    logger.warn("snapshot: failed to take snapshot at index {}: {}", .{ snap.up_to_index, e });
                    continue;
                };

                self.raft.onSnapshotComplete(meta);
                self.log.truncateUpTo(snap.up_to_index);
                self.last_snapshot_index = snap.up_to_index;
                logger.info("snapshot: completed at index {}, term {}", .{ snap.up_to_index, snap.term });
            },
            else => has_sends = true,
        }
    }

    if (!has_sends) return;

    self.mu.unlock();
    defer self.mu.lock();

    for (actions) |action| {
        switch (action) {
            .send_request_vote => |vote| {
                self.transport.send(vote.target, .{ .request_vote = vote.args }) catch |e| {
                    logger.warn("failed to send vote request to node {}: {}", .{ vote.target, e });
                };
            },
            .send_append_entries => |append| {
                self.transport.send(append.target, .{ .append_entries = append.args }) catch |e| {
                    logger.warn("failed to send append entries to node {}: {}", .{ append.target, e });
                };
                freeEntries(self.alloc, append.args.entries);
            },
            .send_request_vote_reply => |vote| {
                self.transport.send(vote.target, .{ .request_vote_reply = vote.reply }) catch |e| {
                    logger.warn("failed to send vote reply to node {}: {}", .{ vote.target, e });
                };
            },
            .send_append_entries_reply => |append| {
                self.transport.send(append.target, .{ .append_entries_reply = append.reply }) catch |e| {
                    logger.warn("failed to send append entries reply to node {}: {}", .{ append.target, e });
                };
            },
            .send_install_snapshot => |snap| {
                snapshot_support.sendSnapshot(self, snap.target, snap.args);
            },
            .send_install_snapshot_reply => |snap| {
                self.transport.send(snap.target, .{ .install_snapshot_reply = snap.reply }) catch |e| {
                    logger.warn("failed to send snapshot reply to node {}: {}", .{ snap.target, e });
                };
            },
            else => {},
        }
    }
}
