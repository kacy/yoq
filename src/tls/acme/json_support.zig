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
    return extractChallengeField(json, "\"http-01\"", "\"token\":\"");
}

pub fn extractHttpChallengeUrl(json: []const u8) ?[]const u8 {
    return extractChallengeField(json, "\"http-01\"", "\"url\":\"");
}

pub fn extractDnsChallengeToken(json: []const u8) ?[]const u8 {
    return extractChallengeField(json, "\"dns-01\"", "\"token\":\"");
}

pub fn extractDnsChallengeUrl(json: []const u8) ?[]const u8 {
    return extractChallengeField(json, "\"dns-01\"", "\"url\":\"");
}

fn extractChallengeField(json: []const u8, challenge_marker: []const u8, field_marker: []const u8) ?[]const u8 {
    const challenge_pos = std.mem.indexOf(u8, json, challenge_marker) orelse return null;
    const field_search = json[challenge_pos..];
    const rel_start = (std.mem.indexOf(u8, field_search, field_marker) orelse return null) + field_marker.len;
    const abs_start = challenge_pos + rel_start;
    const end = std.mem.indexOfPos(u8, json, abs_start, "\"") orelse return null;
    return json[abs_start..end];
}
