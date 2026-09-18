// cluster jobs run from the committed app snapshot. the app lifecycle endpoint
// preserves execution metadata and changes assignments with the job record.
const std = @import("std");
const cli = @import("../../lib/cli.zig");
const http_client = @import("../../cluster/http_client.zig");
const state_support = @import("state_support.zig");

pub fn startCluster(self: anytype, server_ip: [4]u8, server_port: u16) !void {
    const path = try std.fmt.allocPrint(self.alloc, "/apps/{s}/training/{s}/start", .{ self.app_name, self.job.name });
    defer self.alloc.free(path);
    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);
    var response = try http_client.postWithAuth(self.alloc, server_ip, server_port, path, "{}", token);
    defer response.deinit(self.alloc);
    if (response.status_code != 200) {
        cli.writeErr("training start failed (status {d}): {s}\n", .{ response.status_code, response.body });
        return error.DeployFailed;
    }
    const Result = struct { job_id: []const u8, state: []const u8, gpus: u32 };
    const result = try std.json.parseFromSlice(Result, self.alloc, response.body, .{ .ignore_unknown_fields = true });
    defer result.deinit();
    const state = @TypeOf(self.state).fromLabel(result.value.state) orelse return error.InvalidResponse;
    const id = try self.alloc.dupe(u8, result.value.job_id);
    self.resizeRanks(result.value.gpus) catch |err| {
        self.alloc.free(id);
        return err;
    };
    if (self.job_id) |old| self.alloc.free(old);
    self.job_id = id;
    self.execution_mode = .cluster;
    self.state = state;
    try state_support.createPersistentRecord(self);
    cli.write("{s}\n", .{response.body});
}
