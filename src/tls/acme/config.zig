const std = @import("std");
const json_helpers = @import("../../lib/json_helpers.zig");

pub const ChallengeType = enum {
    http_01,
    dns_01,

    pub fn label(self: ChallengeType) []const u8 {
        return switch (self) {
            .http_01 => "http-01",
            .dns_01 => "dns-01",
        };
    }

    pub fn parse(value: []const u8) ?ChallengeType {
        if (std.mem.eql(u8, value, "http-01")) return .http_01;
        if (std.mem.eql(u8, value, "dns-01")) return .dns_01;
        return null;
    }
};

pub const DnsProvider = enum {
    cloudflare,
    route53,
    gcloud,
    exec,

    pub fn label(self: DnsProvider) []const u8 {
        return switch (self) {
            .cloudflare => "cloudflare",
            .route53 => "route53",
            .gcloud => "gcloud",
            .exec => "exec",
        };
    }

    pub fn parse(value: []const u8) ?DnsProvider {
        if (std.mem.eql(u8, value, "cloudflare")) return .cloudflare;
        if (std.mem.eql(u8, value, "route53")) return .route53;
        if (std.mem.eql(u8, value, "gcloud")) return .gcloud;
        if (std.mem.eql(u8, value, "exec")) return .exec;
        return null;
    }
};

pub const KeyValueRef = struct {
    key: []const u8,
    value: []const u8,

    pub fn deinit(self: KeyValueRef, alloc: std.mem.Allocator) void {
        alloc.free(self.key);
        alloc.free(self.value);
    }
};

pub const ManagedConfig = struct {
    email: []const u8,
    directory_url: []const u8,
    challenge_type: ChallengeType,
    dns_provider: ?DnsProvider = null,
    secret_refs: []const KeyValueRef = &.{},
    config_pairs: []const KeyValueRef = &.{},
    hook_command: []const []const u8 = &.{},
    propagation_timeout_secs: u32 = 300,
    poll_interval_secs: u32 = 5,

    pub fn deinit(self: ManagedConfig, alloc: std.mem.Allocator) void {
        alloc.free(self.email);
        alloc.free(self.directory_url);
        for (self.secret_refs) |entry| entry.deinit(alloc);
        alloc.free(self.secret_refs);
        for (self.config_pairs) |entry| entry.deinit(alloc);
        alloc.free(self.config_pairs);
        for (self.hook_command) |entry| alloc.free(entry);
        alloc.free(self.hook_command);
    }

    pub fn clone(self: ManagedConfig, alloc: std.mem.Allocator) !ManagedConfig {
        var copy = ManagedConfig{
            .email = try alloc.dupe(u8, self.email),
            .directory_url = &.{},
            .challenge_type = self.challenge_type,
        };
        errdefer copy.deinit(alloc);

        copy.directory_url = try alloc.dupe(u8, self.directory_url);
        copy.dns_provider = self.dns_provider;
        copy.secret_refs = try cloneKeyValueRefs(alloc, self.secret_refs);
        copy.config_pairs = try cloneKeyValueRefs(alloc, self.config_pairs);
        copy.hook_command = try cloneStringArray(alloc, self.hook_command);
        copy.propagation_timeout_secs = self.propagation_timeout_secs;
        copy.poll_interval_secs = self.poll_interval_secs;
        return copy;
    }

    pub fn writeJson(writer: *std.Io.Writer, config: ManagedConfig) !void {
        try writer.writeByte('{');
        try json_helpers.writeJsonStringField(writer, "email", config.email);
        try writer.writeByte(',');
        try json_helpers.writeJsonStringField(writer, "directory_url", config.directory_url);
        try writer.writeAll(",\"challenge_type\":\"");
        try writer.writeAll(config.challenge_type.label());
        try writer.writeByte('"');
        try writer.writeAll(",\"dns_provider\":");
        if (config.dns_provider) |provider| {
            try writer.writeByte('"');
            try writer.writeAll(provider.label());
            try writer.writeByte('"');
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(",\"secret_refs\":[");
        try writeKeyValueRefArray(writer, config.secret_refs);
        try writer.writeAll("],\"config_pairs\":[");
        try writeKeyValueRefArray(writer, config.config_pairs);
        try writer.writeAll("],\"hook_command\":[");
        for (config.hook_command, 0..) |entry, idx| {
            if (idx > 0) try writer.writeByte(',');
            try writer.writeByte('"');
            try json_helpers.writeJsonEscaped(writer, entry);
            try writer.writeByte('"');
        }
        try writer.print(
            "],\"propagation_timeout_secs\":{d},\"poll_interval_secs\":{d}}}",
            .{ config.propagation_timeout_secs, config.poll_interval_secs },
        );
    }
};

pub fn cloneKeyValueRefs(alloc: std.mem.Allocator, entries: []const KeyValueRef) ![]const KeyValueRef {
    var out: std.ArrayListUnmanaged(KeyValueRef) = .empty;
    errdefer {
        freeKeyValueRefs(alloc, out.items);
        out.deinit(alloc);
    }
    for (entries) |entry| {
        try out.append(alloc, .{
            .key = try alloc.dupe(u8, entry.key),
            .value = try alloc.dupe(u8, entry.value),
        });
    }
    return try out.toOwnedSlice(alloc);
}

pub fn cloneStringArray(alloc: std.mem.Allocator, values: []const []const u8) ![]const []const u8 {
    var out: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        freeStringArray(alloc, out.items);
        out.deinit(alloc);
    }
    for (values) |value| {
        try out.append(alloc, try alloc.dupe(u8, value));
    }
    return try out.toOwnedSlice(alloc);
}

pub fn freeKeyValueRefs(alloc: std.mem.Allocator, entries: []const KeyValueRef) void {
    for (entries) |entry| entry.deinit(alloc);
    alloc.free(entries);
}

pub fn freeStringArray(alloc: std.mem.Allocator, values: []const []const u8) void {
    for (values) |value| alloc.free(value);
    alloc.free(values);
}

fn writeKeyValueRefArray(writer: *std.Io.Writer, entries: []const KeyValueRef) !void {
    for (entries, 0..) |entry, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeAll("{\"key\":\"");
        try json_helpers.writeJsonEscaped(writer, entry.key);
        try writer.writeAll("\",\"value\":\"");
        try json_helpers.writeJsonEscaped(writer, entry.value);
        try writer.writeAll("\"}");
    }
}
