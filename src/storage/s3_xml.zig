// s3_xml — XML response builders for S3 API
//
// generates the XML responses that S3 SDKs expect. these are minimal
// implementations covering only the operations yoq supports.
// no external XML library — just bufPrint with escaped values.

const std = @import("std");

/// XML-escape a string value. handles &, <, >, ", '.
pub fn escapeXml(buf: []u8, input: []const u8) ?[]const u8 {
    var pos: usize = 0;
    for (input) |c| {
        const replacement: []const u8 = switch (c) {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '"' => "&quot;",
            '\'' => "&apos;",
            else => {
                if (pos >= buf.len) return null;
                buf[pos] = c;
                pos += 1;
                continue;
            },
        };
        if (pos + replacement.len > buf.len) return null;
        @memcpy(buf[pos..][0..replacement.len], replacement);
        pos += replacement.len;
    }
    return buf[0..pos];
}

/// format an ISO 8601 timestamp from unix epoch seconds.
pub fn formatTimestamp(buf: *[20]u8, epoch: i64) []const u8 {
    const es = std.time.epoch.EpochSeconds{ .secs = @intCast(epoch) };
    const day = es.getEpochDay();
    const yd = day.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,
        @as(u16, @intFromEnum(md.month)),
        @as(u16, md.day_index) + 1,
        ds.getHoursIntoDay(),
        ds.getMinutesIntoHour(),
        ds.getSecondsIntoMinute(),
    }) catch buf[0..0];
}

/// build ListAllMyBucketsResult XML.
pub fn listBucketsXml(buf: []u8, names: []const []const u8, timestamps: []const i64) ?[]const u8 {
    var pos: usize = 0;

    const header =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        \\<Buckets>
    ;
    if (pos + header.len > buf.len) return null;
    @memcpy(buf[pos..][0..header.len], header);
    pos += header.len;

    for (names, 0..) |name, i| {
        var esc_buf: [256]u8 = undefined;
        const esc_name = escapeXml(&esc_buf, name) orelse return null;
        var ts_buf: [20]u8 = undefined;
        const ts = if (i < timestamps.len) formatTimestamp(&ts_buf, timestamps[i]) else "1970-01-01T00:00:00Z";

        const entry = std.fmt.bufPrint(buf[pos..], "<Bucket><Name>{s}</Name><CreationDate>{s}</CreationDate></Bucket>", .{ esc_name, ts }) catch return null;
        pos += entry.len;
    }

    const footer = "</Buckets></ListAllMyBucketsResult>";
    if (pos + footer.len > buf.len) return null;
    @memcpy(buf[pos..][0..footer.len], footer);
    pos += footer.len;

    return buf[0..pos];
}

/// S3 object entry for ListObjectsV2.
pub const ObjectEntry = struct {
    key: []const u8,
    size: u64,
    last_modified: i64,
    etag: []const u8,
};

/// build ListObjectsV2 result XML.
pub fn listObjectsV2Xml(buf: []u8, bucket: []const u8, prefix: []const u8, objects: []const ObjectEntry) ?[]const u8 {
    var pos: usize = 0;

    var esc_bucket_buf: [256]u8 = undefined;
    const esc_bucket = escapeXml(&esc_bucket_buf, bucket) orelse return null;
    var esc_prefix_buf: [256]u8 = undefined;
    const esc_prefix = escapeXml(&esc_prefix_buf, prefix) orelse return null;

    const header = std.fmt.bufPrint(buf[pos..],
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        \\<Name>{s}</Name><Prefix>{s}</Prefix><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated><KeyCount>{d}</KeyCount>
    , .{ esc_bucket, esc_prefix, objects.len }) catch return null;
    pos += header.len;

    for (objects) |obj| {
        var esc_key_buf: [512]u8 = undefined;
        const esc_key = escapeXml(&esc_key_buf, obj.key) orelse return null;
        var esc_etag_buf: [64]u8 = undefined;
        const esc_etag = escapeXml(&esc_etag_buf, obj.etag) orelse return null;
        var ts_buf: [20]u8 = undefined;
        const ts = formatTimestamp(&ts_buf, obj.last_modified);

        const entry = std.fmt.bufPrint(buf[pos..],
            "<Contents><Key>{s}</Key><Size>{d}</Size><LastModified>{s}</LastModified><ETag>\"{s}\"</ETag></Contents>", .{ esc_key, obj.size, ts, esc_etag }) catch return null;
        pos += entry.len;
    }

    const footer = "</ListBucketResult>";
    if (pos + footer.len > buf.len) return null;
    @memcpy(buf[pos..][0..footer.len], footer);
    pos += footer.len;

    return buf[0..pos];
}

/// build InitiateMultipartUploadResult XML.
pub fn initiateMultipartXml(buf: []u8, bucket: []const u8, key: []const u8, upload_id: []const u8) ?[]const u8 {
    var esc_b: [256]u8 = undefined;
    var esc_k: [512]u8 = undefined;
    const eb = escapeXml(&esc_b, bucket) orelse return null;
    const ek = escapeXml(&esc_k, key) orelse return null;

    return std.fmt.bufPrint(buf,
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        \\<Bucket>{s}</Bucket><Key>{s}</Key><UploadId>{s}</UploadId>
        \\</InitiateMultipartUploadResult>
    , .{ eb, ek, upload_id }) catch null;
}

/// build CompleteMultipartUploadResult XML.
pub fn completeMultipartXml(buf: []u8, bucket: []const u8, key: []const u8, etag: []const u8) ?[]const u8 {
    var esc_b: [256]u8 = undefined;
    var esc_k: [512]u8 = undefined;
    const eb = escapeXml(&esc_b, bucket) orelse return null;
    const ek = escapeXml(&esc_k, key) orelse return null;

    return std.fmt.bufPrint(buf,
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        \\<Bucket>{s}</Bucket><Key>{s}</Key><ETag>"{s}"</ETag>
        \\</CompleteMultipartUploadResult>
    , .{ eb, ek, etag }) catch null;
}

/// build a generic S3 error response XML.
pub fn errorXml(buf: []u8, code: []const u8, message: []const u8) ?[]const u8 {
    var esc_msg: [512]u8 = undefined;
    const em = escapeXml(&esc_msg, message) orelse return null;

    return std.fmt.bufPrint(buf,
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<Error><Code>{s}</Code><Message>{s}</Message></Error>
    , .{ code, em }) catch null;
}

// -- tests --

test "escapeXml — no special chars" {
    var buf: [64]u8 = undefined;
    const result = escapeXml(&buf, "hello").?;
    try std.testing.expectEqualStrings("hello", result);
}

test "escapeXml — special chars" {
    var buf: [128]u8 = undefined;
    const result = escapeXml(&buf, "a&b<c>d\"e'f").?;
    try std.testing.expectEqualStrings("a&amp;b&lt;c&gt;d&quot;e&apos;f", result);
}

test "escapeXml — empty" {
    var buf: [16]u8 = undefined;
    const result = escapeXml(&buf, "").?;
    try std.testing.expectEqualStrings("", result);
}

test "formatTimestamp" {
    var buf: [20]u8 = undefined;
    const ts = formatTimestamp(&buf, 0);
    try std.testing.expectEqualStrings("1970-01-01T00:00:00Z", ts);
}

test "formatTimestamp — recent date" {
    var buf: [20]u8 = undefined;
    // 2024-01-15T11:30:00Z = 1705318200
    const ts = formatTimestamp(&buf, 1705318200);
    try std.testing.expectEqualStrings("2024-01-15T11:30:00Z", ts);
}

test "listBucketsXml — empty" {
    var buf: [4096]u8 = undefined;
    const xml = listBucketsXml(&buf, &.{}, &.{}).?;
    try std.testing.expect(std.mem.indexOf(u8, xml, "<Buckets>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "</Buckets>") != null);
}

test "listBucketsXml — with buckets" {
    var buf: [4096]u8 = undefined;
    const names = [_][]const u8{ "bucket1", "bucket2" };
    const times = [_]i64{ 1000, 2000 };
    const xml = listBucketsXml(&buf, &names, &times).?;
    try std.testing.expect(std.mem.indexOf(u8, xml, "<Name>bucket1</Name>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<Name>bucket2</Name>") != null);
}

test "listObjectsV2Xml — empty" {
    var buf: [4096]u8 = undefined;
    const xml = listObjectsV2Xml(&buf, "mybucket", "", &.{}).?;
    try std.testing.expect(std.mem.indexOf(u8, xml, "<Name>mybucket</Name>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<KeyCount>0</KeyCount>") != null);
}

test "listObjectsV2Xml — with objects" {
    var buf: [4096]u8 = undefined;
    const objects = [_]ObjectEntry{
        .{ .key = "file1.txt", .size = 1024, .last_modified = 1000, .etag = "abc123" },
    };
    const xml = listObjectsV2Xml(&buf, "mybucket", "", &objects).?;
    try std.testing.expect(std.mem.indexOf(u8, xml, "<Key>file1.txt</Key>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<Size>1024</Size>") != null);
}

test "initiateMultipartXml" {
    var buf: [4096]u8 = undefined;
    const xml = initiateMultipartXml(&buf, "bucket", "key.txt", "upload-123").?;
    try std.testing.expect(std.mem.indexOf(u8, xml, "<Bucket>bucket</Bucket>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<UploadId>upload-123</UploadId>") != null);
}

test "completeMultipartXml" {
    var buf: [4096]u8 = undefined;
    const xml = completeMultipartXml(&buf, "bucket", "key.txt", "abc123").?;
    try std.testing.expect(std.mem.indexOf(u8, xml, "<Bucket>bucket</Bucket>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "<ETag>") != null);
}

test "errorXml" {
    var buf: [4096]u8 = undefined;
    const xml = errorXml(&buf, "NoSuchBucket", "The specified bucket does not exist").?;
    try std.testing.expect(std.mem.indexOf(u8, xml, "<Code>NoSuchBucket</Code>") != null);
    try std.testing.expect(std.mem.indexOf(u8, xml, "does not exist") != null);
}
