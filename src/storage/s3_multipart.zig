const std = @import("std");

pub const Part = struct { number: u32, etag: [32]u8 };
pub const ParseError = error{ InvalidPart, InvalidPartOrder, MalformedXml, OutOfMemory };

fn trim(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, " \t\r\n");
}

/// parse only the completion schema; declarations, entities, and arbitrary xml
/// extensions are rejected rather than interpreted by a general xml engine.
pub fn parse(alloc: std.mem.Allocator, body: []const u8) ParseError![]Part {
    var rest = trim(body);
    if (std.mem.startsWith(u8, rest, "<?xml ")) {
        const end = std.mem.indexOf(u8, rest, "?>") orelse return error.MalformedXml;
        rest = trim(rest[end + 2 ..]);
    }
    const root = "<CompleteMultipartUpload";
    if (!std.mem.startsWith(u8, rest, root)) return error.MalformedXml;
    const end = std.mem.indexOfScalar(u8, rest, '>') orelse return error.MalformedXml;
    const attributes = trim(rest[root.len..end]);
    if (attributes.len != 0 and !std.mem.eql(u8, attributes, "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"")) return error.MalformedXml;
    rest = trim(rest[end + 1 ..]);
    var parts: std.ArrayList(Part) = .empty;
    errdefer parts.deinit(alloc);
    var previous: u32 = 0;
    while (!std.mem.startsWith(u8, rest, "</CompleteMultipartUpload>")) {
        if (parts.items.len == 10000) return error.InvalidPart;
        const part_xml = try takeElement(&rest, "Part");
        var fields = trim(part_xml);
        var number: ?u32 = null;
        var etag: ?[32]u8 = null;
        while (fields.len != 0) {
            if (std.mem.startsWith(u8, fields, "<PartNumber>")) {
                if (number != null) return error.MalformedXml;
                number = std.fmt.parseInt(u32, trim(try takeElement(&fields, "PartNumber")), 10) catch return error.InvalidPart;
            } else if (std.mem.startsWith(u8, fields, "<ETag>")) {
                if (etag != null) return error.MalformedXml;
                var value = trim(try takeElement(&fields, "ETag"));
                if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') value = value[1 .. value.len - 1];
                if (value.len >= 12 and std.mem.startsWith(u8, value, "&quot;") and std.mem.endsWith(u8, value, "&quot;")) value = value[6 .. value.len - 6];
                if (value.len != 32) return error.InvalidPart;
                var normalized: [32]u8 = undefined;
                for (value, 0..) |c, i| {
                    if (!std.ascii.isHex(c)) return error.InvalidPart;
                    normalized[i] = std.ascii.toLower(c);
                }
                etag = normalized;
            } else return error.MalformedXml;
        }
        const part_number = number orelse return error.InvalidPart;
        if (part_number == 0 or part_number > 10000) return error.InvalidPart;
        if (part_number <= previous) return error.InvalidPartOrder;
        previous = part_number;
        try parts.append(alloc, .{ .number = part_number, .etag = etag orelse return error.InvalidPart });
    }
    if (parts.items.len == 0) return error.InvalidPart;
    rest = trim(rest["</CompleteMultipartUpload>".len..]);
    if (rest.len != 0) return error.MalformedXml;
    return parts.toOwnedSlice(alloc);
}

fn takeElement(rest: *[]const u8, comptime name: []const u8) ParseError![]const u8 {
    const open = "<" ++ name ++ ">";
    const close = "</" ++ name ++ ">";
    if (!std.mem.startsWith(u8, rest.*, open)) return error.MalformedXml;
    const end = std.mem.indexOfPos(u8, rest.*, open.len, close) orelse return error.MalformedXml;
    const value = rest.*[open.len..end];
    rest.* = trim(rest.*[end + close.len ..]);
    return value;
}

test "s3 completion rejects malformed, duplicate, and unordered parts" {
    const alloc = std.testing.allocator;
    const first = "<Part><PartNumber>1</PartNumber><ETag>&quot;0123456789abcdef0123456789abcdef&quot;</ETag></Part>";
    const second = "<Part><PartNumber>2</PartNumber><ETag>0123456789abcdef0123456789abcdef</ETag></Part>";
    const valid = try parse(alloc, "<CompleteMultipartUpload>" ++ first ++ second ++ "</CompleteMultipartUpload>");
    defer alloc.free(valid);
    try std.testing.expectEqual(@as(usize, 2), valid.len);
    try std.testing.expectError(error.InvalidPartOrder, parse(alloc, "<CompleteMultipartUpload>" ++ first ++ first ++ "</CompleteMultipartUpload>"));
    try std.testing.expectError(error.InvalidPartOrder, parse(alloc, "<CompleteMultipartUpload>" ++ second ++ first ++ "</CompleteMultipartUpload>"));
    try std.testing.expectError(error.InvalidPart, parse(alloc, "<CompleteMultipartUpload></CompleteMultipartUpload>"));
    try std.testing.expectError(error.MalformedXml, parse(alloc, "<CompleteMultipartUpload>" ++ first));
    try std.testing.expectError(error.MalformedXml, parse(alloc, "<!DOCTYPE x><CompleteMultipartUpload>" ++ first ++ "</CompleteMultipartUpload>"));
}
