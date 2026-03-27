const std = @import("std");

pub const Upstream = struct {
    service: []const u8,
    endpoint_id: []const u8,
    address: []const u8,
    port: u16,
    eligible: bool = true,

    pub fn deinit(self: Upstream, alloc: std.mem.Allocator) void {
        alloc.free(self.service);
        alloc.free(self.endpoint_id);
        alloc.free(self.address);
    }
};

pub fn selectFirstEligible(upstreams: []const Upstream) ?Upstream {
    for (upstreams) |upstream| {
        if (upstream.eligible) return upstream;
    }
    return null;
}

test "selectFirstEligible returns first eligible upstream" {
    const upstreams = [_]Upstream{
        .{ .service = "api", .endpoint_id = "api-1", .address = "10.0.0.2", .port = 8080, .eligible = false },
        .{ .service = "api", .endpoint_id = "api-2", .address = "10.0.0.3", .port = 8080, .eligible = true },
    };

    const selected = selectFirstEligible(&upstreams) orelse return error.TestExpectedNonNull;
    try std.testing.expectEqualStrings("10.0.0.3", selected.address);
}

test "selectFirstEligible returns null when all upstreams are ineligible" {
    const upstreams = [_]Upstream{
        .{ .service = "api", .endpoint_id = "api-1", .address = "10.0.0.2", .port = 8080, .eligible = false },
        .{ .service = "api", .endpoint_id = "api-2", .address = "10.0.0.3", .port = 8080, .eligible = false },
    };

    try std.testing.expect(selectFirstEligible(&upstreams) == null);
}
