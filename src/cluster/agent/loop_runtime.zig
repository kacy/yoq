const std = @import("std");
const http_client = @import("../http_client.zig");
const json_helpers = @import("../../lib/json_helpers.zig");
const log = @import("../../lib/log.zig");
const setup = @import("../../network/setup.zig");
const ip_mod = @import("../../network/ip.zig");
const gpu_health = @import("../../gpu/health.zig");
const gpu_detect = @import("../../gpu/detect.zig");
const gossip_mod = @import("../gossip.zig");
const resource_support = @import("resource_support.zig");
const request_support = @import("request_support.zig");
const gossip_support = @import("gossip_support.zig");
const assignment_runtime = @import("assignment_runtime.zig");

const extractJsonString = json_helpers.extractJsonString;
const extractJsonInt = json_helpers.extractJsonInt;
const max_peers = 65534;

pub fn agentHeartbeatTicks(self: anytype) u32 {
    if (self.gossip) |gossip| {
        const member_count = gossip.members.count() + 1;
        const multiplier: u32 = @min(gossip_mod.Gossip.ceilLog2(member_count), gossip_mod.Gossip.max_interval_multiplier);
        return 50 * multiplier;
    }
    return 50;
}

pub fn agentLoop(self: anytype) void {
    while (self.running.load(.acquire)) {
        doHeartbeat(self);
        assignment_runtime.reconcile(self);

        var remaining: u32 = agentHeartbeatTicks(self);
        while (remaining > 0 and self.running.load(.acquire)) : (remaining -= 1) {
            std.Thread.sleep(100 * std.time.ns_per_ms);
            if (remaining % 5 == 0) gossip_support.tickGossipLoop(self);
            gossip_support.receiveGossipLoop(self);
        }
    }
}

pub fn doHeartbeat(self: anytype) void {
    const resources = resource_support.getSystemResources();

    var gpu_health_worst: gpu_health.GpuHealth = .healthy;
    const gpu_info = resource_support.cachedGpuDetect();
    if (gpu_info.detect_result) |dr| {
        if (dr.nvml) |*nvml| {
            const metrics = gpu_health.pollAllMetrics(nvml, @intCast(gpu_info.count));
            for (0..@min(gpu_info.count, gpu_detect.max_gpus)) |i| {
                if (metrics[i]) |metric| {
                    const health_state = metric.health();
                    if (health_state == .unhealthy) {
                        gpu_health_worst = .unhealthy;
                        break;
                    } else if (health_state == .warning) {
                        gpu_health_worst = .warning;
                    }
                }
            }
        }
    }

    const body = request_support.buildHeartbeatBody(self.alloc, resources, @tagName(gpu_health_worst)) catch return;
    defer self.alloc.free(body);

    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/agents/{s}/heartbeat", .{self.id}) catch return;

    var resp = http_client.postWithAuth(self.alloc, self.server_addr, self.server_port, path, body, self.token) catch return;
    defer resp.deinit(self.alloc);

    if (resp.status_code != 200) {
        if (extractJsonString(resp.body, "leader")) |leader_str| {
            if (request_support.parseHostPort(leader_str)) |hp| {
                log.info("redirected to leader at {s}", .{leader_str});
                self.server_addr = hp.addr;
                self.server_port = hp.port;
            }
        }
        return;
    }

    if (extractJsonString(resp.body, "status")) |status| {
        if (std.mem.eql(u8, status, "draining")) {
            self.running.store(false, .release);
        }
    }

    if (extractJsonString(resp.body, "leader")) |leader_str| {
        if (request_support.parseHostPort(leader_str)) |hp| {
            if (!std.mem.eql(u8, &self.server_addr, &hp.addr) or self.server_port != hp.port) {
                log.info("leader moved to {s}, following", .{leader_str});
                self.server_addr = hp.addr;
                self.server_port = hp.port;
            }
        }
    }

    if (self.node_id != null) {
        if (extractJsonInt(resp.body, "peers_count")) |count| {
            const server_count: u32 = if (count >= 0 and count <= max_peers) @intCast(count) else 0;
            if (server_count != self.known_peers_count) {
                log.info("peer count changed ({d} -> {d}), reconciling", .{ self.known_peers_count, server_count });
                reconcilePeers(self);
            }
        }
    }
}

pub fn reconcilePeers(self: anytype) void {
    var resp = fetchPeers(self) orelse return;
    defer resp.deinit(self.alloc);

    var new_peers = std.AutoHashMap(u16, [44]u8).init(self.alloc);
    defer new_peers.deinit();

    var iter = json_helpers.extractJsonObjects(resp.body);
    while (iter.next()) |obj| {
        const pub_key = extractJsonString(obj, "public_key") orelse continue;
        const overlay_str = extractJsonString(obj, "overlay_ip") orelse continue;
        const node_id_val = extractJsonInt(obj, "node_id") orelse continue;
        const endpoint = extractJsonString(obj, "endpoint") orelse "";

        if (self.node_id) |our_id| {
            if (node_id_val == our_id) continue;
        }

        const peer_node: u16 = if (node_id_val >= 1 and node_id_val <= 65534) @intCast(node_id_val) else continue;
        const overlay_ip = ip_mod.parseIp(overlay_str) orelse continue;

        if (!self.known_peers.contains(peer_node)) {
            log.info("adding peer node_id={d}", .{peer_node});
            setup.addClusterPeer(.{
                .public_key = pub_key,
                .endpoint = endpoint,
                .overlay_ip = overlay_ip,
                .container_subnet_node = peer_node,
            }) catch |e| {
                log.warn("failed to add cluster peer (node {d}): {}", .{ peer_node, e });
            };
        }

        if (pub_key.len <= 44) {
            var key_buf: [44]u8 = undefined;
            @memcpy(key_buf[0..pub_key.len], pub_key);
            @memset(key_buf[pub_key.len..], 0);
            new_peers.put(peer_node, key_buf) catch {};
        }
    }

    var old_iter = self.known_peers.iterator();
    while (old_iter.next()) |entry| {
        const old_node = entry.key_ptr.*;
        if (!new_peers.contains(old_node)) {
            const old_key = entry.value_ptr;
            var key_len: usize = 44;
            for (old_key, 0..) |byte, i| {
                if (byte == 0) {
                    key_len = i;
                    break;
                }
            }
            log.info("removing peer node_id={d}", .{old_node});
            setup.removeClusterPeer(.{
                .public_key = old_key[0..key_len],
                .endpoint = "",
                .overlay_ip = resource_support.overlayIpForNode(old_node),
                .container_subnet_node = old_node,
            });
        }
    }

    self.known_peers.deinit();
    self.known_peers = new_peers.move();
    self.known_peers_count = @intCast(self.known_peers.count());
    log.info("peer reconciliation complete ({d} peers)", .{self.known_peers_count});
}

pub fn fetchPeers(self: anytype) ?http_client.Response {
    const path = if (self.role == .agent) "/wireguard/peers?servers_only=1" else "/wireguard/peers";
    return http_client.getWithAuth(self.alloc, self.server_addr, self.server_port, path, self.token) catch return null;
}
