const std = @import("std");

// the standard iterator rejects hard links before returning their GNU/PAX
// names. keep entry decoding here so every supported kind uses the same names,
// checksum validation, size accounting, and bounded caller-owned buffers.
pub const Iterator = struct {
    reader: *std.Io.Reader,
    header_buffer: [512]u8 = undefined,
    file_name_buffer: []u8,
    link_name_buffer: []u8,
    unread_file_bytes: u64 = 0,
    padding: usize = 0,

    pub const File = struct {
        name: []const u8,
        link_name: []const u8,
        size: u64,
        mode: u32,
        kind: enum { file, directory, sym_link, hard_link },
    };
    pub const Options = struct { file_name_buffer: []u8, link_name_buffer: []u8 };

    pub fn init(reader: *std.Io.Reader, options: Options) Iterator {
        return .{ .reader = reader, .file_name_buffer = options.file_name_buffer, .link_name_buffer = options.link_name_buffer };
    }

    pub fn next(self: *Iterator) !?File {
        try self.reader.discardAll64(self.unread_file_bytes);
        self.unread_file_bytes = 0;
        var name: ?[]const u8 = null;
        var link_name: ?[]const u8 = null;
        var extended_size: ?u64 = null;
        while (try self.readHeader()) {
            const header = &self.header_buffer;
            const size = try number(header[124..136]);
            self.padding = paddingFor(size);
            switch (header[156]) {
                0, '0', '1', '2', '5' => {
                    const entry_size = extended_size orelse size;
                    if (header[156] == '1' and entry_size != 0) return error.InvalidHardLink;
                    self.padding = paddingFor(entry_size);
                    self.unread_file_bytes = entry_size;
                    const mode = try number(header[100..108]);
                    if (mode > std.math.maxInt(u32)) return error.TarHeader;
                    return .{
                        .name = name orelse try self.headerName(),
                        .link_name = link_name orelse try copyName(self.link_name_buffer, terminated(header[157..257])),
                        .size = entry_size,
                        .mode = @intCast(mode),
                        .kind = switch (header[156]) {
                            '1' => .hard_link,
                            '2' => .sym_link,
                            '5' => .directory,
                            else => .file,
                        },
                    };
                },
                'L' => name = try self.readName(size, self.file_name_buffer),
                'K' => link_name = try self.readName(size, self.link_name_buffer),
                'x' => {
                    name = null;
                    link_name = null;
                    extended_size = null;
                    var attributes: std.tar.PaxIterator = .{ .reader = self.reader, .size = @intCast(size) };
                    while (try attributes.next()) |attribute| switch (attribute.kind) {
                        .path => name = try attribute.value(self.file_name_buffer),
                        .linkpath => link_name = try attribute.value(self.link_name_buffer),
                        .size => {
                            var buffer: [64]u8 = undefined;
                            extended_size = try std.fmt.parseInt(u64, try attribute.value(&buffer), 10);
                        },
                    };
                },
                'g' => try self.reader.discardAll64(size),
                else => return error.TarUnsupportedHeader,
            }
        }
        return null;
    }

    fn readHeader(self: *Iterator) !bool {
        try self.reader.discardAll(self.padding);
        self.padding = 0;
        const count = try self.reader.readSliceShort(&self.header_buffer);
        if (count == 0) return false;
        if (count != self.header_buffer.len) return error.UnexpectedEndOfStream;
        const expected = try number(self.header_buffer[148..156]);
        var unsigned: u64 = 0;
        var signed: i64 = 0;
        for (self.header_buffer, 0..) |value, index| {
            const byte: u8 = if (index >= 148 and index < 156) ' ' else value;
            unsigned += byte;
            signed += @as(i8, @bitCast(byte));
        }
        if (expected == 0 and unsigned == 256) return false;
        if (expected != unsigned and (signed < 0 or expected != @as(u64, @intCast(signed)))) return error.TarHeaderChksum;
        return true;
    }

    fn headerName(self: *Iterator) ![]const u8 {
        const name = terminated(self.header_buffer[0..100]);
        const prefix = terminated(self.header_buffer[345..500]);
        const magic = self.header_buffer[257..263];
        if (prefix.len == 0 or !std.mem.eql(u8, magic[0..5], "ustar") or (magic[5] != 0 and magic[5] != ' '))
            return copyName(self.file_name_buffer, name);
        return std.fmt.bufPrint(self.file_name_buffer, "{s}/{s}", .{ prefix, name }) catch error.TarInsufficientBuffer;
    }

    fn readName(self: *Iterator, size: u64, buffer: []u8) ![]const u8 {
        if (size > buffer.len) return error.TarInsufficientBuffer;
        const bytes = buffer[0..@intCast(size)];
        try self.reader.readSliceAll(bytes);
        return terminated(bytes);
    }
};

fn paddingFor(size: u64) usize {
    return @intCast((512 - size % 512) % 512);
}

fn terminated(bytes: []const u8) []const u8 {
    return bytes[0..(std.mem.indexOfScalar(u8, bytes, 0) orelse bytes.len)];
}

fn copyName(buffer: []u8, name: []const u8) ![]const u8 {
    if (name.len > buffer.len) return error.TarInsufficientBuffer;
    @memcpy(buffer[0..name.len], name);
    return buffer[0..name.len];
}

fn number(bytes: []const u8) !u64 {
    if (bytes[0] & 0x80 != 0) {
        if (bytes[0] != 0x80) return error.TarNumericValueNegative;
        var value: u64 = 0;
        for (bytes[1..]) |byte| {
            value = std.math.mul(u64, value, 256) catch return error.TarNumericValueTooBig;
            value = std.math.add(u64, value, byte) catch return error.TarNumericValueTooBig;
        }
        return value;
    }
    const digits = std.mem.trim(u8, bytes, " \x00");
    return if (digits.len == 0) 0 else std.fmt.parseInt(u64, digits, 8) catch error.TarHeader;
}
