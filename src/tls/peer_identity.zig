const std = @import("std");

pub const cluster_label = "yoq-cluster";
pub const proxy_identity = "spiffe://" ++ cluster_label ++ "/proxy/ingress";

pub fn service(alloc: std.mem.Allocator, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(alloc, "spiffe://{s}/service/{s}", .{ cluster_label, name });
}
