// audit_command — `yoq audit` lists recent audit log entries from the local
// agent's GET /v1/audit endpoint.

const std = @import("std");
const cli = @import("../../lib/cli.zig");
const http_client = @import("../../cluster/http_client.zig");
const json_helpers = @import("../../lib/json_helpers.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const extractJsonString = json_helpers.extractJsonString;
const extractJsonInt = json_helpers.extractJsonInt;

const AuditError = error{
    InvalidArgument,
    ConnectionFailed,
    ServerError,
};

pub fn audit(args: *std.process.Args.Iterator, io: std.Io, alloc: std.mem.Allocator) !void {
    var server = cli.ServerAddr{};
    var limit: u32 = 50;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            cli.output_mode = .json;
        } else if (std.mem.eql(u8, arg, "--server")) {
            const addr_str = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                return AuditError.InvalidArgument;
            };
            server = cli.parseServerAddr(addr_str);
        } else if (std.mem.eql(u8, arg, "--limit")) {
            const n = args.next() orelse {
                writeErr("--limit requires a number\n", .{});
                return AuditError.InvalidArgument;
            };
            limit = std.fmt.parseInt(u32, n, 10) catch {
                writeErr("invalid --limit value: {s}\n", .{n});
                return AuditError.InvalidArgument;
            };
        } else {
            writeErr("unknown option: {s}\n", .{arg});
            return AuditError.InvalidArgument;
        }
    }

    var token_buf: [64]u8 = undefined;
    const token = cli.readApiTokenWithIo(io, &token_buf);

    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/v1/audit?limit={d}", .{limit}) catch return AuditError.InvalidArgument;

    var resp = http_client.getWithAuth(alloc, server.ip, server.port, path, token) catch {
        writeErr("failed to connect to server at {d}.{d}.{d}.{d}:{d}\n", .{ server.ip[0], server.ip[1], server.ip[2], server.ip[3], server.port });
        return AuditError.ConnectionFailed;
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("server returned status {d}\n", .{resp.status_code});
        return AuditError.ServerError;
    }

    if (cli.output_mode == .json) {
        write("{s}\n", .{resp.body});
        return;
    }

    write("{s:<12} {s:<16} {s:<16} {s:<28} {s}\n", .{ "TIME", "ACTOR", "ACTION", "TARGET", "OUTCOME" });
    var iter = json_helpers.extractJsonObjects(resp.body);
    while (iter.next()) |obj| {
        const recorded_at = extractJsonInt(obj, "recorded_at") orelse 0;
        const actor = extractJsonString(obj, "actor") orelse "?";
        const action = extractJsonString(obj, "action") orelse "?";
        const target = extractJsonString(obj, "target") orelse "-";
        const outcome = extractJsonString(obj, "outcome") orelse "?";
        write("{d:<12} {s:<16} {s:<16} {s:<28} {s}\n", .{ recorded_at, actor, action, target, outcome });
    }
}
