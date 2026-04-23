const std = @import("std");
const platform = @import("platform");

const cli = @import("../../lib/cli.zig");
const state_support = @import("state_support.zig");

fn buildDeployRequestBody(self: anytype) ![]u8 {
    const json_helpers = @import("../../lib/json_helpers.zig");

    var body_writer = std.Io.Writer.Allocating.init(self.alloc);
    defer body_writer.deinit();

    const writer = &body_writer.writer;

    try writer.writeAll("{\"services\":[{\"image\":\"");
    try json_helpers.writeJsonEscaped(writer, self.job.image);
    try writer.writeAll("\",\"command\":\"");

    for (self.job.command, 0..) |arg, j| {
        if (j > 0) try writer.writeByte(' ');
        try json_helpers.writeJsonEscaped(writer, arg);
    }

    var resource_buf: [512]u8 = undefined;
    const resource_str = try std.fmt.bufPrint(
        &resource_buf,
        "\",\"cpu_limit\":{d},\"memory_limit_mb\":{d},\"gpu_limit\":{d},\"gang_world_size\":{d},\"gpus_per_rank\":1",
        .{
            self.job.resources.cpu,
            self.job.resources.memory_mb,
            self.job.gpus,
            self.job.gpus,
        },
    );
    try writer.writeAll(resource_str);

    if (self.job.gpu_type) |gpu_type| {
        try writer.writeAll(",\"gpu_model\":\"");
        try json_helpers.writeJsonEscaped(writer, gpu_type);
        try writer.writeByte('"');
    }

    try writer.writeAll("}]}");
    return body_writer.toOwnedSlice();
}

pub fn startCluster(self: anytype, server_ip: [4]u8, server_port: u16) !void {
    self.state = .scheduling;
    state_support.generateClusterJobId(self) catch {};
    state_support.createPersistentRecord(self);
    state_support.persistState(self);

    const http_client = @import("../../cluster/http_client.zig");
    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);

    const request_body = buildDeployRequestBody(self) catch {
        self.state = .failed;
        state_support.persistState(self);
        return error.OutOfMemory;
    };
    defer self.alloc.free(request_body);

    var resp = http_client.postWithAuth(self.alloc, server_ip, server_port, "/deploy", request_body, token) catch {
        self.state = .failed;
        state_support.persistState(self);
        return error.ConnectionFailed;
    };
    defer resp.deinit(self.alloc);

    if (resp.status_code == 200) {
        self.state = .running;
        state_support.persistState(self);
        cli.write("{s}\n", .{resp.body});
    } else {
        self.state = .failed;
        state_support.persistState(self);
        cli.writeErr("deploy failed (status {d}): {s}\n", .{ resp.status_code, resp.body });
        return error.DeployFailed;
    }
}
