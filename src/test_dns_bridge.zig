const std = @import("std");
const dns = @import("network/dns.zig");
const reconciler = @import("network/service_reconciler.zig");
const store = @import("state/store.zig");

fn startGateways() !void {
    dns.startResolver();
    if (!dns.resolverRunningAt(.{ 10, 42, 0, 1 })) return error.ResolverStartFailed;
    dns.startResolverAt(.{ 10, 42, 2, 1 });
    if (!dns.resolverRunningAt(.{ 10, 42, 2, 1 })) return error.ResolverStartFailed;
}

pub fn main(init: std.process.Init) !void {
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.next();
    const automatic_audit = if (args.next()) |mode|
        if (std.mem.eql(u8, mode, "--audit-loop")) true else return error.InvalidMode
    else
        false;

    if (automatic_audit) try store.initTestDb();
    defer if (automatic_audit) {
        reconciler.resetForTest();
        store.deinitTestDb();
    };
    if (automatic_audit) {
        try store.createService(.{
            .service_name = "fixture",
            .vip_address = "10.42.2.9",
            .lb_policy = "consistent_hash",
            .created_at = 1000,
            .updated_at = 1000,
        });
        reconciler.bootstrapIfEnabled();
    }

    dns.registerService("fixture", "fixture-container", .{ 10, 42, 2, 9 });
    try startGateways();
    defer dns.stopResolver();
    dns.stopResolver();
    if (dns.resolverRunning()) return error.ResolverStopFailed;
    try startGateways();
    if (automatic_audit) reconciler.startAuditLoopIfEnabled();
    var output_buffer: [128]u8 = undefined;
    var output = std.Io.File.stdout().writer(init.io, &output_buffer);
    try output.interface.print("dns fixture ready owned={}\n", .{dns.resolverOwnedByCurrentProcess()});
    try output.interface.flush();
    var reported_audit = false;
    for (0..1200) |_| {
        if (automatic_audit) {
            // observe the production loop without driving a retry or audit pass.
            var audit = try reconciler.snapshotAuditState(init.gpa);
            defer audit.deinit(init.gpa);
            if (!audit.enabled or !audit.running) return error.AuditLoopNotRunning;
            if (audit.last_error != null) return error.AuditPassFailed;
            if (audit.passes_total > 0 and !reported_audit) {
                try output.interface.print("dns audit complete owned={}\n", .{dns.resolverOwnedByCurrentProcess()});
                try output.interface.flush();
                reported_audit = true;
            }
        } else {
            _ = dns.refreshResolvers();
        }
        try std.Io.sleep(init.io, std.Io.Duration.fromMilliseconds(100), .awake);
    }
}
