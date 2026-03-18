const std = @import("std");

const cli = @import("../../lib/cli.zig");

pub fn startCluster(self: anytype, server_ip: [4]u8, server_port: u16) !void {
    self.state = .scheduling;

    const http_client = @import("../../cluster/http_client.zig");
    const json_helpers = @import("../../lib/json_helpers.zig");

    var json_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer json_buf.deinit(self.alloc);
    const writer = json_buf.writer(self.alloc);

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
        return error.ConnectionFailed;
    };
    defer resp.deinit(self.alloc);

    if (resp.status_code == 200) {
        self.state = .running;
        cli.write("{s}\n", .{resp.body});
    } else {
        self.state = .failed;
        cli.writeErr("deploy failed (status {d}): {s}\n", .{ resp.status_code, resp.body });
        return error.DeployFailed;
    }
}
