const std = @import("std");
const json_helpers = @import("../../lib/json_helpers.zig");
const proxy_runtime = @import("../../network/proxy/runtime.zig");

pub const RouteTrafficAggregate = struct {
    requests_total: u64 = 0,
    responses_2xx_total: u64 = 0,
    responses_4xx_total: u64 = 0,
    responses_5xx_total: u64 = 0,
    retries_total: u64 = 0,
    upstream_failures_total: u64 = 0,
};

pub fn aggregateRouteTraffic(route_name: []const u8, route_traffic: []const proxy_runtime.RouteTrafficSnapshot) RouteTrafficAggregate {
    var aggregate: RouteTrafficAggregate = .{};
    for (route_traffic) |entry| {
        if (!std.mem.eql(u8, entry.route_name, route_name)) continue;
        aggregate.requests_total += entry.requests_total;
        aggregate.responses_2xx_total += entry.responses_2xx_total;
        aggregate.responses_4xx_total += entry.responses_4xx_total;
        aggregate.responses_5xx_total += entry.responses_5xx_total;
        aggregate.retries_total += entry.retries_total;
        aggregate.upstream_failures_total += entry.upstream_failures_total;
    }
    return aggregate;
}

pub fn writeRouteTrafficSummaryJson(writer: anytype, route_name: []const u8, route_traffic: []const proxy_runtime.RouteTrafficSnapshot) !void {
    const aggregate = aggregateRouteTraffic(route_name, route_traffic);
    try writer.print(
        "{{\"requests_total\":{d},\"responses_2xx_total\":{d},\"responses_4xx_total\":{d},\"responses_5xx_total\":{d},\"retries_total\":{d},\"upstream_failures_total\":{d}}}",
        .{
            aggregate.requests_total,
            aggregate.responses_2xx_total,
            aggregate.responses_4xx_total,
            aggregate.responses_5xx_total,
            aggregate.retries_total,
            aggregate.upstream_failures_total,
        },
    );
}

pub fn writeRouteBackendTrafficJson(writer: anytype, route_name: []const u8, route_traffic: []const proxy_runtime.RouteTrafficSnapshot) !void {
    try writer.writeByte('[');
    var first = true;
    for (route_traffic) |entry| {
        if (!std.mem.eql(u8, entry.route_name, route_name)) continue;
        if (!first) try writer.writeByte(',');
        first = false;
        try writer.writeAll("{\"backend_service\":\"");
        try json_helpers.writeJsonEscaped(writer, entry.backend_service);
        try writer.print(
            "\",\"requests_total\":{d},\"responses_2xx_total\":{d},\"responses_4xx_total\":{d},\"responses_5xx_total\":{d},\"retries_total\":{d},\"upstream_failures_total\":{d}}}",
            .{
                entry.requests_total,
                entry.responses_2xx_total,
                entry.responses_4xx_total,
                entry.responses_5xx_total,
                entry.retries_total,
                entry.upstream_failures_total,
            },
        );
    }
    try writer.writeByte(']');
}
