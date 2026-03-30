const std = @import("std");
const huffman = @import("hpack_huffman.zig");

pub const DecodeError = error{
    BufferTooShort,
    IntegerOverflow,
    InvalidIndex,
    InvalidHuffman,
};

pub const Error = DecodeError || std.mem.Allocator.Error;

pub const HeaderField = struct {
    name: []u8,
    value: []u8,

    pub fn deinit(self: HeaderField, alloc: std.mem.Allocator) void {
        alloc.free(self.name);
        alloc.free(self.value);
    }
};

pub const StaticHeaderField = struct {
    name: []const u8,
    value: []const u8,
};

pub const IntegerDecode = struct {
    value: usize,
    consumed: usize,
};

const dynamic_table_default_max_size = 4096;
const static_table = [_]StaticHeaderField{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

pub fn staticHeader(index: usize) ?StaticHeaderField {
    if (index == 0 or index > static_table.len) return null;
    return static_table[index - 1];
}

pub fn decodeInteger(buf: []const u8, prefix_bits: u3) DecodeError!IntegerDecode {
    if (buf.len == 0) return error.BufferTooShort;

    const prefix_mask = (@as(u8, 1) << prefix_bits) - 1;
    var value: usize = buf[0] & prefix_mask;
    if (value < prefix_mask) {
        return .{ .value = value, .consumed = 1 };
    }

    var consumed: usize = 1;
    var shift: u6 = 0;
    while (true) {
        if (consumed >= buf.len) return error.BufferTooShort;
        const byte = buf[consumed];
        const payload = byte & 0x7f;
        if (shift >= @bitSizeOf(usize)) return error.IntegerOverflow;
        value += (@as(usize, payload) << shift);
        consumed += 1;
        if ((byte & 0x80) == 0) break;
        shift += 7;
    }

    return .{ .value = value, .consumed = consumed };
}

pub fn decodeString(alloc: std.mem.Allocator, buf: []const u8) Error!struct { value: []u8, consumed: usize } {
    if (buf.len == 0) return error.BufferTooShort;

    const huffman_encoded = (buf[0] & 0x80) != 0;
    const len_info = try decodeInteger(buf, 7);
    const start = len_info.consumed;
    const end = start + len_info.value;
    if (end > buf.len) return error.BufferTooShort;

    return .{
        .value = if (huffman_encoded)
            try huffman.decodeString(alloc, buf[start..end])
        else
            try alloc.dupe(u8, buf[start..end]),
        .consumed = end,
    };
}

pub fn decodeHeaderBlock(alloc: std.mem.Allocator, block: []const u8) Error!std.ArrayList(HeaderField) {
    var headers: std.ArrayList(HeaderField) = .empty;
    errdefer {
        for (headers.items) |header| header.deinit(alloc);
        headers.deinit(alloc);
    }

    var dynamic_table: DynamicTable = .{};
    defer dynamic_table.deinit(alloc);

    var pos: usize = 0;
    while (pos < block.len) {
        const byte = block[pos];
        if ((byte & 0x80) != 0) {
            const index_info = try decodeInteger(block[pos..], 7);
            const field = lookupHeader(index_info.value, &dynamic_table) orelse return error.InvalidIndex;
            try headers.append(alloc, .{
                .name = try alloc.dupe(u8, field.name),
                .value = try alloc.dupe(u8, field.value),
            });
            pos += index_info.consumed;
            continue;
        }

        if ((byte & 0xe0) == 0x20) {
            const size_info = try decodeInteger(block[pos..], 5);
            dynamic_table.updateMaxSize(alloc, size_info.value);
            pos += size_info.consumed;
            continue;
        }

        const name_prefix: u3 = if ((byte & 0xc0) == 0x40) 6 else 4;
        const incremental_indexing = (byte & 0xc0) == 0x40;
        const name_index_info = try decodeInteger(block[pos..], name_prefix);
        pos += name_index_info.consumed;

        const name = if (name_index_info.value == 0) blk: {
            const literal = try decodeString(alloc, block[pos..]);
            pos += literal.consumed;
            break :blk literal.value;
        } else blk: {
            const field = lookupHeader(name_index_info.value, &dynamic_table) orelse return error.InvalidIndex;
            break :blk try alloc.dupe(u8, field.name);
        };
        errdefer alloc.free(name);

        const value = blk: {
            const literal = try decodeString(alloc, block[pos..]);
            pos += literal.consumed;
            break :blk literal.value;
        };
        errdefer alloc.free(value);

        try headers.append(alloc, .{ .name = name, .value = value });
        if (incremental_indexing) {
            try dynamic_table.add(alloc, name, value);
        }
    }

    return headers;
}

const HeaderLookup = struct {
    name: []const u8,
    value: []const u8,
};

const DynamicTable = struct {
    entries: std.ArrayList(HeaderField) = .empty,
    size: usize = 0,
    max_size: usize = dynamic_table_default_max_size,

    fn deinit(self: *DynamicTable, alloc: std.mem.Allocator) void {
        for (self.entries.items) |entry| entry.deinit(alloc);
        self.entries.deinit(alloc);
    }

    fn updateMaxSize(self: *DynamicTable, alloc: std.mem.Allocator, new_max_size: usize) void {
        self.max_size = new_max_size;
        self.evictToLimit(alloc);
    }

    fn add(self: *DynamicTable, alloc: std.mem.Allocator, name: []const u8, value: []const u8) Error!void {
        const entry_size = fieldSize(name, value);
        if (entry_size > self.max_size) {
            self.clear(alloc);
            return;
        }

        const entry: HeaderField = .{
            .name = try alloc.dupe(u8, name),
            .value = try alloc.dupe(u8, value),
        };
        errdefer entry.deinit(alloc);

        try self.entries.append(alloc, entry);
        self.size += entry_size;
        self.evictToLimit(alloc);
    }

    fn lookup(self: *const DynamicTable, dynamic_index: usize) ?HeaderLookup {
        if (dynamic_index == 0 or dynamic_index > self.entries.items.len) return null;
        const entry = self.entries.items[self.entries.items.len - dynamic_index];
        return .{ .name = entry.name, .value = entry.value };
    }

    fn clear(self: *DynamicTable, alloc: std.mem.Allocator) void {
        for (self.entries.items) |entry| entry.deinit(alloc);
        self.entries.clearRetainingCapacity();
        self.size = 0;
    }

    fn evictToLimit(self: *DynamicTable, alloc: std.mem.Allocator) void {
        while (self.size > self.max_size and self.entries.items.len > 0) {
            const entry = self.entries.orderedRemove(0);
            self.size -= fieldSize(entry.name, entry.value);
            entry.deinit(alloc);
        }
    }
};

fn lookupHeader(index: usize, dynamic_table: *const DynamicTable) ?HeaderLookup {
    if (index == 0) return null;
    if (staticHeader(index)) |field| {
        return .{ .name = field.name, .value = field.value };
    }
    return dynamic_table.lookup(index - static_table.len);
}

fn fieldSize(name: []const u8, value: []const u8) usize {
    return name.len + value.len + 32;
}
test "staticHeader returns pseudo-header entry" {
    const field = staticHeader(2).?;
    try std.testing.expectEqualStrings(":method", field.name);
    try std.testing.expectEqualStrings("GET", field.value);
}

test "decodeInteger parses inline prefix value" {
    const decoded = try decodeInteger(&[_]u8{0x0a}, 5);
    try std.testing.expectEqual(@as(usize, 10), decoded.value);
    try std.testing.expectEqual(@as(usize, 1), decoded.consumed);
}

test "decodeInteger parses continuation bytes" {
    const decoded = try decodeInteger(&[_]u8{ 0x1f, 0x9a, 0x0a }, 5);
    try std.testing.expectEqual(@as(usize, 1337), decoded.value);
    try std.testing.expectEqual(@as(usize, 3), decoded.consumed);
}

test "decodeString decodes huffman-encoded values" {
    const decoded = try decodeString(std.testing.allocator, &[_]u8{
        0x8c,
        0xf1,
        0xe3,
        0xc2,
        0xe5,
        0xf2,
        0x3a,
        0x6b,
        0xa0,
        0xab,
        0x90,
        0xf4,
        0xff,
    });
    defer std.testing.allocator.free(decoded.value);

    try std.testing.expectEqualStrings("www.example.com", decoded.value);
    try std.testing.expectEqual(@as(usize, 13), decoded.consumed);
}

test "decodeHeaderBlock parses indexed pseudo-header" {
    var headers = try decodeHeaderBlock(std.testing.allocator, &[_]u8{0x82});
    defer {
        for (headers.items) |header| header.deinit(std.testing.allocator);
        headers.deinit(std.testing.allocator);
    }

    try std.testing.expectEqual(@as(usize, 1), headers.items.len);
    try std.testing.expectEqualStrings(":method", headers.items[0].name);
    try std.testing.expectEqualStrings("GET", headers.items[0].value);
}

test "decodeHeaderBlock parses literal header with indexed name" {
    var headers = try decodeHeaderBlock(std.testing.allocator, &[_]u8{
        0x04,
        0x06,
        '/',
        'u',
        's',
        'e',
        'r',
        's',
    });
    defer {
        for (headers.items) |header| header.deinit(std.testing.allocator);
        headers.deinit(std.testing.allocator);
    }

    try std.testing.expectEqual(@as(usize, 1), headers.items.len);
    try std.testing.expectEqualStrings(":path", headers.items[0].name);
    try std.testing.expectEqualStrings("/users", headers.items[0].value);
}

test "decodeHeaderBlock parses literal header with literal name" {
    var headers = try decodeHeaderBlock(std.testing.allocator, &[_]u8{
        0x10,
        0x0b,
        'g',
        'r',
        'p',
        'c',
        '-',
        's',
        't',
        'a',
        't',
        'u',
        's',
        0x01,
        '0',
    });
    defer {
        for (headers.items) |header| header.deinit(std.testing.allocator);
        headers.deinit(std.testing.allocator);
    }

    try std.testing.expectEqual(@as(usize, 1), headers.items.len);
    try std.testing.expectEqualStrings("grpc-status", headers.items[0].name);
    try std.testing.expectEqualStrings("0", headers.items[0].value);
}

test "decodeHeaderBlock parses huffman-encoded literal value" {
    var headers = try decodeHeaderBlock(std.testing.allocator, &[_]u8{
        0x01,
        0x8c,
        0xf1,
        0xe3,
        0xc2,
        0xe5,
        0xf2,
        0x3a,
        0x6b,
        0xa0,
        0xab,
        0x90,
        0xf4,
        0xff,
    });
    defer {
        for (headers.items) |header| header.deinit(std.testing.allocator);
        headers.deinit(std.testing.allocator);
    }

    try std.testing.expectEqual(@as(usize, 1), headers.items.len);
    try std.testing.expectEqualStrings(":authority", headers.items[0].name);
    try std.testing.expectEqualStrings("www.example.com", headers.items[0].value);
}

test "decodeHeaderBlock accepts dynamic table size updates" {
    var headers = try decodeHeaderBlock(std.testing.allocator, &[_]u8{0x20});
    defer headers.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 0), headers.items.len);
}

test "decodeHeaderBlock reuses incremental dynamic entries" {
    var headers = try decodeHeaderBlock(std.testing.allocator, &[_]u8{
        0x40,
        0x06,
        'x',
        '-',
        't',
        'e',
        's',
        't',
        0x02,
        'o',
        'k',
        0xbe,
    });
    defer {
        for (headers.items) |header| header.deinit(std.testing.allocator);
        headers.deinit(std.testing.allocator);
    }

    try std.testing.expectEqual(@as(usize, 2), headers.items.len);
    try std.testing.expectEqualStrings("x-test", headers.items[0].name);
    try std.testing.expectEqualStrings("ok", headers.items[0].value);
    try std.testing.expectEqualStrings("x-test", headers.items[1].name);
    try std.testing.expectEqualStrings("ok", headers.items[1].value);
}
