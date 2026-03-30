const std = @import("std");

pub fn extractJsonStringView(json: []const u8, key: []const u8) ?[]const u8 {
    var search_buf: [128]u8 = undefined;
    const needle = std.fmt.bufPrint(&search_buf, "\"{s}\":\"", .{key}) catch return null;

    const start = (std.mem.indexOf(u8, json, needle) orelse return null) + needle.len;
    const end = std.mem.indexOfPos(u8, json, start, "\"") orelse return null;
    return json[start..end];
}

pub fn extractJsonString(allocator: std.mem.Allocator, json: []const u8, key: []const u8) ![]u8 {
    const value = extractJsonStringView(json, key) orelse return error.KeyNotFound;
    return allocator.dupe(u8, value) catch return error.OutOfMemory;
}

pub fn extractJsonArray(json: []const u8, key: []const u8) ?[]const u8 {
    var search_buf: [64]u8 = undefined;
    const needle = std.fmt.bufPrint(&search_buf, "\"{s}\":[", .{key}) catch return null;

    const start = (std.mem.indexOf(u8, json, needle) orelse return null) + needle.len;
    const end = std.mem.indexOfPos(u8, json, start, "]") orelse return null;

    return json[start..end];
}

pub fn extractHttpChallengeToken(json: []const u8) ?[]const u8 {
    const http01_pos = std.mem.indexOf(u8, json, "\"http-01\"") orelse return null;

    const token_marker = "\"token\":\"";
    const token_start_search = json[http01_pos..];
    const rel_start = (std.mem.indexOf(u8, token_start_search, token_marker) orelse return null) + token_marker.len;
    const abs_start = http01_pos + rel_start;

    const end = std.mem.indexOfPos(u8, json, abs_start, "\"") orelse return null;
    return json[abs_start..end];
}

pub fn extractHttpChallengeUrl(json: []const u8) ?[]const u8 {
    const http01_pos = std.mem.indexOf(u8, json, "\"http-01\"") orelse return null;

    const url_marker = "\"url\":\"";
    const url_start_search = json[http01_pos..];
    const rel_start = (std.mem.indexOf(u8, url_start_search, url_marker) orelse return null) + url_marker.len;
    const abs_start = http01_pos + rel_start;

    const end = std.mem.indexOfPos(u8, json, abs_start, "\"") orelse return null;
    return json[abs_start..end];
}
