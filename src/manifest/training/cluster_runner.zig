const std = @import("std");
const platform = @import("platform");

const cli = @import("../../lib/cli.zig");
const state_support = @import("state_support.zig");

pub fn startCluster(self: anytype, server_ip: [4]u8, server_port: u16) !void {
    self.state = .scheduling;
    state_support.generateClusterJobId(self) catch {};
    state_support.createPersistentRecord(self);
    state_support.persistState(self);

    const http_client = @import("../../cluster/http_client.zig");
    const json_helpers = @import("../../lib/json_helpers.zig");

    var json_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer json_buf.deinit(self.alloc);
    const writer = platform.arrayListWriter(&json_buf, self.alloc);

    writer.writeAll("{\"services\":[{\"image\":\"") catch return error.OutOfMemory;
    json_helpers.writeJsonEscaped(writer, self.job.image) catch return error.OutOfMemory;
    writer.writeAll("\",\"command\":\"") catch return error.OutOfMemory;

    for (self.job.command, 0..) |arg, j| {
        if (j > 0) writer.writeByte(' ') catch {};
        json_helpers.writeJsonEscaped(writer, arg) catch {};
    }

    var resource_buf: [512]u8 = undefined;
    const resource_str = std.fmt.bufPrint(
        &resource_buf,
        "\",\"cpu_limit\":{d},\"memory_limit_mb\":{d},\"gpu_limit\":{d},\"gang_world_size\":{d},\"gpus_per_rank\":1",
        .{
            self.job.resources.cpu,
            self.job.resources.memory_mb,
            self.job.gpus,
            self.job.gpus,
        },
    ) catch return error.OutOfMemory;
    writer.writeAll(resource_str) catch return error.OutOfMemory;

    if (self.job.gpu_type) |gt| {
        writer.writeAll(",\"gpu_model\":\"") catch return error.OutOfMemory;
        json_helpers.writeJsonEscaped(writer, gt) catch return error.OutOfMemory;
        writer.writeByte('"') catch return error.OutOfMemory;
    }

    writer.writeAll("}]}") catch return error.OutOfMemory;

    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);

    var resp = http_client.postWithAuth(self.alloc, server_ip, server_port, "/deploy", json_buf.items, token) catch {
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
