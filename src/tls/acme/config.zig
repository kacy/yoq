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

pub const DnsConfig = struct {
    provider: DnsProvider,
    secret_refs: []const KeyValueRef = &.{},
    config: []const KeyValueRef = &.{},
    hook: []const []const u8 = &.{},
    propagation_timeout_secs: u32 = 300,
    poll_interval_secs: u32 = 5,

    pub fn deinit(self: DnsConfig, alloc: std.mem.Allocator) void {
        freeKeyValueRefs(alloc, self.secret_refs);
        freeKeyValueRefs(alloc, self.config);
        freeStringArray(alloc, self.hook);
    }

    pub fn clone(self: DnsConfig, alloc: std.mem.Allocator) !DnsConfig {
        var copy = DnsConfig{ .provider = self.provider };
        errdefer copy.deinit(alloc);

        copy.secret_refs = try cloneKeyValueRefs(alloc, self.secret_refs);
        copy.config = try cloneKeyValueRefs(alloc, self.config);
        copy.hook = try cloneStringArray(alloc, self.hook);
        copy.propagation_timeout_secs = self.propagation_timeout_secs;
        copy.poll_interval_secs = self.poll_interval_secs;
        return copy;
    }
};

pub const ChallengeConfig = union(ChallengeType) {
    http_01,
    dns_01: DnsConfig,

    pub fn deinit(self: ChallengeConfig, alloc: std.mem.Allocator) void {
        switch (self) {
            .http_01 => {},
            .dns_01 => |dns| dns.deinit(alloc),
        }
    }

    pub fn clone(self: ChallengeConfig, alloc: std.mem.Allocator) !ChallengeConfig {
        return switch (self) {
            .http_01 => .http_01,
            .dns_01 => |dns| .{ .dns_01 = try dns.clone(alloc) },
        };
    }

    pub fn challengeType(self: ChallengeConfig) ChallengeType {
        return switch (self) {
            .http_01 => .http_01,
            .dns_01 => .dns_01,
        };
    }

    pub fn dnsConfig(self: ChallengeConfig) ?DnsConfig {
        return switch (self) {
            .http_01 => null,
            .dns_01 => |dns| dns,
        };
    }
};

pub const ManagedConfig = struct {
    email: []const u8,
    directory_url: []const u8,
    challenge: ChallengeConfig,

    pub fn deinit(self: ManagedConfig, alloc: std.mem.Allocator) void {
        alloc.free(self.email);
        alloc.free(self.directory_url);
        self.challenge.deinit(alloc);
    }

    pub fn clone(self: ManagedConfig, alloc: std.mem.Allocator) !ManagedConfig {
        var copy = ManagedConfig{
            .email = try alloc.dupe(u8, self.email),
            .directory_url = &.{},
            .challenge = .http_01,
        };
        errdefer copy.deinit(alloc);

        copy.directory_url = try alloc.dupe(u8, self.directory_url);
        copy.challenge = try self.challenge.clone(alloc);
        return copy;
    }

    pub fn challengeType(self: ManagedConfig) ChallengeType {
        return self.challenge.challengeType();
    }

    pub fn dnsConfig(self: ManagedConfig) ?DnsConfig {
        return self.challenge.dnsConfig();
    }

    pub fn writeJson(writer: *std.Io.Writer, config: ManagedConfig) !void {
        try writer.writeByte('{');
        try json_helpers.writeJsonStringField(writer, "email", config.email);
        try writer.writeByte(',');
        try json_helpers.writeJsonStringField(writer, "directory_url", config.directory_url);
        try writer.writeAll(",\"challenge\":");
        try writeChallengeJson(writer, config.challenge);
        try writer.writeByte('}');
    }
};

fn writeChallengeJson(writer: *std.Io.Writer, challenge: ChallengeConfig) !void {
    try writer.writeByte('{');
    try json_helpers.writeJsonStringField(writer, "type", challenge.challengeType().label());
    switch (challenge) {
        .http_01 => {},
        .dns_01 => |dns| {
            try writer.writeAll(",\"provider\":\"");
            try writer.writeAll(dns.provider.label());
            try writer.writeByte('"');
            try writer.writeAll(",\"secret_refs\":[");
            try writeKeyValueRefArray(writer, dns.secret_refs);
            try writer.writeAll("],\"config\":[");
            try writeKeyValueRefArray(writer, dns.config);
            try writer.writeAll("],\"hook\":[");
            for (dns.hook, 0..) |entry, idx| {
                if (idx > 0) try writer.writeByte(',');
                try writer.writeByte('"');
                try json_helpers.writeJsonEscaped(writer, entry);
                try writer.writeByte('"');
            }
            try writer.print(
                "],\"propagation_timeout_secs\":{d},\"poll_interval_secs\":{d}",
                .{ dns.propagation_timeout_secs, dns.poll_interval_secs },
            );
        },
    }
    try writer.writeByte('}');
}

pub fn cloneKeyValueRefs(alloc: std.mem.Allocator, entries: []const KeyValueRef) ![]const KeyValueRef {
    return cloneKeyValueRefsFrom(alloc, entries);
}

pub fn cloneKeyValueRefsFrom(alloc: std.mem.Allocator, entries: anytype) ![]const KeyValueRef {
    var out: std.ArrayListUnmanaged(KeyValueRef) = .empty;
    errdefer {
        freeKeyValueRefs(alloc, out.items);
        out.deinit(alloc);
    }
    for (entries) |entry| {
        const cloned = blk: {
            const key = try alloc.dupe(u8, entry.key);
            errdefer alloc.free(key);
            break :blk KeyValueRef{
                .key = key,
                .value = try alloc.dupe(u8, entry.value),
            };
        };
        try out.append(alloc, cloned);
    }
    return try out.toOwnedSlice(alloc);
}

pub fn buildDnsChallenge(
    alloc: std.mem.Allocator,
    provider: DnsProvider,
    secret_refs: anytype,
    config: anytype,
    hook: []const []const u8,
    propagation_timeout_secs: u32,
    poll_interval_secs: u32,
) !ChallengeConfig {
    const owned_secret_refs = try cloneKeyValueRefsFrom(alloc, secret_refs);
    errdefer freeKeyValueRefs(alloc, owned_secret_refs);
    const owned_config = try cloneKeyValueRefsFrom(alloc, config);
    errdefer freeKeyValueRefs(alloc, owned_config);
    const owned_hook = try cloneStringArray(alloc, hook);
    errdefer freeStringArray(alloc, owned_hook);

    return .{ .dns_01 = .{
        .provider = provider,
        .secret_refs = owned_secret_refs,
        .config = owned_config,
        .hook = owned_hook,
        .propagation_timeout_secs = propagation_timeout_secs,
        .poll_interval_secs = poll_interval_secs,
    } };
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
