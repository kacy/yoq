pub const DnsHeader = struct {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
};

pub const DnsQuestion = struct {
    name: [253]u8,
    name_len: usize,
    qtype: u16,
    qclass: u16,
    end_offset: usize,
};

pub const TYPE_A: u16 = 1;
pub const CLASS_IN: u16 = 1;

pub fn parseHeader(buf: []const u8) ?DnsHeader {
    if (buf.len < 12) return null;

    return DnsHeader{
        .id = readU16(buf[0..2]),
        .flags = readU16(buf[2..4]),
        .qdcount = readU16(buf[4..6]),
        .ancount = readU16(buf[6..8]),
        .nscount = readU16(buf[8..10]),
        .arcount = readU16(buf[10..12]),
    };
}

pub fn parseQuestion(buf: []const u8) ?DnsQuestion {
    if (buf.len < 13) return null;

    var q = DnsQuestion{
        .name = undefined,
        .name_len = 0,
        .qtype = 0,
        .qclass = 0,
        .end_offset = 0,
    };

    var pos: usize = 12;
    var name_pos: usize = 0;
    while (pos < buf.len) {
        const label_len = buf[pos];
        pos += 1;

        if (label_len == 0) break;
        if (label_len >= 0xC0) return null;
        if (label_len > 63) return null;
        if (pos + label_len > buf.len) return null;

        if (name_pos > 0) {
            if (name_pos >= q.name.len) return null;
            q.name[name_pos] = '.';
            name_pos += 1;
        }

        if (name_pos + label_len > q.name.len) return null;
        @memcpy(q.name[name_pos..][0..label_len], buf[pos..][0..label_len]);
        name_pos += label_len;
        pos += label_len;
    }

    q.name_len = name_pos;
    if (pos + 4 > buf.len) return null;
    q.qtype = readU16(buf[pos..][0..2]);
    q.qclass = readU16(buf[pos + 2 ..][0..2]);
    q.end_offset = pos + 4;
    return q;
}

pub fn buildResponse(
    query_buf: []const u8,
    query_len: usize,
    response_ip: [4]u8,
    response_buf: *[512]u8,
) ?usize {
    const query = query_buf[0..@min(query_buf.len, query_len)];
    const header = parseHeader(query) orelse return null;
    const question = parseQuestion(query) orelse return null;

    writeU16(response_buf[0..2], header.id);
    writeU16(response_buf[2..4], 0x8400);
    writeU16(response_buf[4..6], 1);
    writeU16(response_buf[6..8], 1);
    writeU16(response_buf[8..10], 0);
    writeU16(response_buf[10..12], 0);

    const question_bytes = question.end_offset - 12;
    if (12 + question_bytes > response_buf.len) return null;
    @memcpy(response_buf[12..][0..question_bytes], query_buf[12..][0..question_bytes]);

    var pos: usize = 12 + question_bytes;
    if (pos + 16 > response_buf.len) return null;
    writeU16(response_buf[pos..][0..2], 0xC00C);
    pos += 2;
    writeU16(response_buf[pos..][0..2], TYPE_A);
    pos += 2;
    writeU16(response_buf[pos..][0..2], CLASS_IN);
    pos += 2;
    writeU32(response_buf[pos..][0..4], 5);
    pos += 4;
    writeU16(response_buf[pos..][0..2], 4);
    pos += 2;
    response_buf[pos] = response_ip[0];
    response_buf[pos + 1] = response_ip[1];
    response_buf[pos + 2] = response_ip[2];
    response_buf[pos + 3] = response_ip[3];
    pos += 4;
    return pos;
}

pub fn buildNxDomain(query_buf: []const u8, query_len: usize, response_buf: *[512]u8) ?usize {
    const query = query_buf[0..@min(query_buf.len, query_len)];
    const header = parseHeader(query) orelse return null;
    const question = parseQuestion(query) orelse return null;

    writeU16(response_buf[0..2], header.id);
    writeU16(response_buf[2..4], 0x8403);
    writeU16(response_buf[4..6], 1);
    writeU16(response_buf[6..8], 0);
    writeU16(response_buf[8..10], 0);
    writeU16(response_buf[10..12], 0);

    const question_bytes = question.end_offset - 12;
    if (12 + question_bytes > response_buf.len) return null;
    @memcpy(response_buf[12..][0..question_bytes], query_buf[12..][0..question_bytes]);
    return 12 + question_bytes;
}

pub fn ipToU32(ip: [4]u8) u32 {
    return (@as(u32, ip[0]) << 24) | (@as(u32, ip[1]) << 16) | (@as(u32, ip[2]) << 8) | @as(u32, ip[3]);
}

pub fn readU16(buf: *const [2]u8) u16 {
    return (@as(u16, buf[0]) << 8) | @as(u16, buf[1]);
}

pub fn writeU16(buf: *[2]u8, val: u16) void {
    buf[0] = @truncate(val >> 8);
    buf[1] = @truncate(val);
}

pub fn writeU32(buf: *[4]u8, val: u32) void {
    buf[0] = @truncate(val >> 24);
    buf[1] = @truncate(val >> 16);
    buf[2] = @truncate(val >> 8);
    buf[3] = @truncate(val);
}
