const std = @import("std");
const cli = @import("../../lib/cli.zig");
const json_out = @import("../../lib/json_output.zig");
const common = @import("common.zig");
const store_support = @import("store_support.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const formatTimestamp = cli.formatTimestamp;

pub fn run(alloc: std.mem.Allocator) common.TlsCommandsError!void {
    var opened = store_support.openCertStore(alloc) catch |err|
        return store_support.reportOpenStoreError(err);
    defer store_support.closeCertStore(alloc, &opened);

    var certs = opened.store.list() catch {
        writeErr("failed to list certificates\n", .{});
        return common.TlsCommandsError.StoreFailed;
    };
    defer {
        for (certs.items) |c| c.deinit(alloc);
        certs.deinit(alloc);
    }

    if (cli.output_mode == .json) {
        var w = json_out.JsonWriter{};
        w.beginArray();
        for (certs.items) |c| {
            w.beginObject();
            w.stringField("domain", c.domain);
            w.intField("not_after", c.not_after);
            w.stringField("source", c.source);
            w.intField("created_at", c.created_at);
            w.endObject();
        }
        w.endArray();
        w.flush();
        return;
    }

    if (certs.items.len == 0) {
        write("no certificates\n", .{});
        return;
    }

    for (certs.items) |c| {
        var ts_buf: [20]u8 = undefined;
        const expires = formatTimestamp(&ts_buf, c.not_after);
        write("{s}  expires={s}  source={s}\n", .{ c.domain, expires, c.source });
    }
}
