// reconcile persisted training jobs on the leader, including after election.
const std = @import("std");
const node_mod = @import("node.zig");
const jobs = @import("../api/routes/cluster_agents/workload_training_jobs.zig");
const log = @import("../lib/log.zig");

const Context = struct {
    alloc: std.mem.Allocator,
    node: *node_mod.Node,
    stopped: std.Io.Event = .unset,
};

pub const Worker = struct {
    context: *Context,
    thread: ?std.Thread,

    pub fn stop(self: *Worker) void {
        const thread = self.thread orelse return;
        self.context.stopped.set(std.Options.debug_io);
        thread.join();
        self.context.alloc.destroy(self.context);
        self.thread = null;
    }
};

pub fn spawn(alloc: std.mem.Allocator, node: *node_mod.Node) !Worker {
    const context = try alloc.create(Context);
    errdefer alloc.destroy(context);
    context.* = .{ .alloc = alloc, .node = node };
    return .{ .context = context, .thread = try std.Thread.spawn(.{}, run, .{context}) };
}

fn run(context: *Context) void {
    while (!context.stopped.isSet()) {
        jobs.reconcileAll(context.alloc, context.node) catch |err| {
            if (err != error.NotLeader) log.warn("training reconciliation failed: {}", .{err});
        };
        context.stopped.waitTimeout(std.Options.debug_io, .{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } }) catch |err| switch (err) {
            error.Timeout => continue,
            error.Canceled => return,
        };
    }
}

test "training reconciliation worker joins before its node is destroyed" {
    var node = try node_mod.Node.initForTests(std.testing.allocator, .{ .id = 1, .port = 0, .peers = &.{}, .data_dir = "/tmp" });
    defer node.deinit();
    var worker = try spawn(std.testing.allocator, &node);
    worker.stop();
    worker.stop();
}
