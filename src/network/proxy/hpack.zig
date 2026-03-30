const std = @import("std");

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
const max_huffman_code_len: u8 = 30;

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
            try decodeHuffmanString(alloc, buf[start..end])
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

fn decodeHuffmanString(alloc: std.mem.Allocator, encoded: []const u8) Error![]u8 {
    var decoded: std.ArrayList(u8) = .empty;
    errdefer decoded.deinit(alloc);

    const total_bits = encoded.len * 8;
    var bit_pos: usize = 0;
    while (bit_pos < total_bits) {
        var probe_pos = bit_pos;
        var code: u32 = 0;
        var code_len: u8 = 0;
        var matched_symbol: ?u8 = null;

        while (probe_pos < total_bits and code_len < max_huffman_code_len) : (probe_pos += 1) {
            code = (code << 1) | bitAt(encoded, probe_pos);
            code_len += 1;
            if (findHuffmanSymbol(code, code_len)) |symbol| {
                matched_symbol = symbol;
                try decoded.append(alloc, symbol);
                bit_pos = probe_pos + 1;
                break;
            }
        }

        if (matched_symbol == null) {
            if (isValidPadding(encoded, bit_pos)) break;
            return error.InvalidHuffman;
        }
    }

    return decoded.toOwnedSlice(alloc);
}

fn bitAt(buf: []const u8, bit_pos: usize) u32 {
    const byte = buf[bit_pos / 8];
    const shift: u3 = @intCast(7 - (bit_pos % 8));
    return @as(u32, (byte >> shift) & 0x1);
}

fn findHuffmanSymbol(code: u32, code_len: u8) ?u8 {
    for (huffman_codes, 0..) |candidate_code, symbol_index| {
        if (huffman_code_lens[symbol_index] == code_len and candidate_code == code) {
            return @intCast(symbol_index);
        }
    }
    return null;
}

fn isValidPadding(encoded: []const u8, bit_pos: usize) bool {
    const total_bits = encoded.len * 8;
    const remaining = total_bits - bit_pos;
    if (remaining == 0) return true;
    if (remaining > 7) return false;

    var pos = bit_pos;
    while (pos < total_bits) : (pos += 1) {
        if (bitAt(encoded, pos) == 0) return false;
    }
    return true;
}

const huffman_codes = [256]u32{
    0x1ff8,    0x7fffd8,  0xfffffe2,  0xfffffe3, 0xfffffe4, 0xfffffe5,  0xfffffe6,  0xfffffe7,
    0xfffffe8, 0xffffea,  0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb,  0xfffffec,
    0xfffffed, 0xfffffee, 0xfffffef,  0xffffff0, 0xffffff1, 0xffffff2,  0x3ffffffe, 0xffffff3,
    0xffffff4, 0xffffff5, 0xffffff6,  0xffffff7, 0xffffff8, 0xffffff9,  0xffffffa,  0xffffffb,
    0x14,      0x3f8,     0x3f9,      0xffa,     0x1ff9,    0x15,       0xf8,       0x7fa,
    0x3fa,     0x3fb,     0xf9,       0x7fb,     0xfa,      0x16,       0x17,       0x18,
    0x0,       0x1,       0x2,        0x19,      0x1a,      0x1b,       0x1c,       0x1d,
    0x1e,      0x1f,      0x5c,       0xfb,      0x7ffc,    0x20,       0xffb,      0x3fc,
    0x1ffa,    0x21,      0x5d,       0x5e,      0x5f,      0x60,       0x61,       0x62,
    0x63,      0x64,      0x65,       0x66,      0x67,      0x68,       0x69,       0x6a,
    0x6b,      0x6c,      0x6d,       0x6e,      0x6f,      0x70,       0x71,       0x72,
    0xfc,      0x73,      0xfd,       0x1ffb,    0x7fff0,   0x1ffc,     0x3ffc,     0x22,
    0x7ffd,    0x3,       0x23,       0x4,       0x24,      0x5,        0x25,       0x26,
    0x27,      0x6,       0x74,       0x75,      0x28,      0x29,       0x2a,       0x7,
    0x2b,      0x76,      0x2c,       0x8,       0x9,       0x2d,       0x77,       0x78,
    0x79,      0x7a,      0x7b,       0x7ffe,    0x7fc,     0x3ffd,     0x1ffd,     0xffffffc,
    0xfffe6,   0x3fffd2,  0xfffe7,    0xfffe8,   0x3fffd3,  0x3fffd4,   0x3fffd5,   0x7fffd9,
    0x3fffd6,  0x7fffda,  0x7fffdb,   0x7fffdc,  0x7fffdd,  0x7fffde,   0xffffeb,   0x7fffdf,
    0xffffec,  0xffffed,  0x3fffd7,   0x7fffe0,  0xffffee,  0x7fffe1,   0x7fffe2,   0x7fffe3,
    0x7fffe4,  0x1fffdc,  0x3fffd8,   0x7fffe5,  0x3fffd9,  0x7fffe6,   0x7fffe7,   0xffffef,
    0x3fffda,  0x1fffdd,  0xfffe9,    0x3fffdb,  0x3fffdc,  0x7fffe8,   0x7fffe9,   0x1fffde,
    0x7fffea,  0x3fffdd,  0x3fffde,   0xfffff0,  0x1fffdf,  0x3fffdf,   0x7fffeb,   0x7fffec,
    0x1fffe0,  0x1fffe1,  0x3fffe0,   0x1fffe2,  0x7fffed,  0x3fffe1,   0x7fffee,   0x7fffef,
    0xfffea,   0x3fffe2,  0x3fffe3,   0x3fffe4,  0x7ffff0,  0x3fffe5,   0x3fffe6,   0x7ffff1,
    0x3ffffe0, 0x3ffffe1, 0xfffeb,    0x7fff1,   0x3fffe7,  0x7ffff2,   0x3fffe8,   0x1ffffec,
    0x3ffffe2, 0x3ffffe3, 0x3ffffe4,  0x7ffffde, 0x7ffffdf, 0x3ffffe5,  0xfffff1,   0x1ffffed,
    0x7fff2,   0x1fffe3,  0x3ffffe6,  0x7ffffe0, 0x7ffffe1, 0x3ffffe7,  0x7ffffe2,  0xfffff2,
    0x1fffe4,  0x1fffe5,  0x3ffffe8,  0x3ffffe9, 0xffffffd, 0x7ffffe3,  0x7ffffe4,  0x7ffffe5,
    0xfffec,   0xfffff3,  0xfffed,    0x1fffe6,  0x3fffe9,  0x1fffe7,   0x1fffe8,   0x7ffff3,
    0x3fffea,  0x3fffeb,  0x1ffffee,  0x1ffffef, 0xfffff4,  0xfffff5,   0x3ffffea,  0x7ffff4,
    0x3ffffeb, 0x7ffffe6, 0x3ffffec,  0x3ffffed, 0x7ffffe7, 0x7ffffe8,  0x7ffffe9,  0x7ffffea,
    0x7ffffeb, 0xffffffe, 0x7ffffec,  0x7ffffed, 0x7ffffee, 0x7ffffef,  0x7fffff0,  0x3ffffee,
};

const huffman_code_lens = [256]u8{
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    6,  10, 10, 12, 13, 6,  8,  11, 10, 10, 8,  11, 8,  6,  6,  6,
    5,  5,  5,  6,  6,  6,  6,  6,  6,  6,  7,  8,  15, 6,  12, 10,
    13, 6,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
    7,  7,  7,  7,  7,  7,  7,  7,  8,  7,  8,  13, 19, 13, 14, 6,
    15, 5,  6,  5,  6,  5,  6,  6,  6,  5,  7,  7,  6,  6,  6,  5,
    6,  7,  6,  5,  5,  6,  7,  7,  7,  7,  7,  15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
};

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
