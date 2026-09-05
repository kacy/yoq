const std = @import("std");
const platform = @import("linux_platform");
const linux = std.os.linux;

pub const Identity = struct { uid: u32 = 0, gid: u32 = 0 };
pub const IdentityError = error{ InvalidUser, UnknownUser, UnknownGroup, IdentityFailed };

/// Resolve against image-owned account files, after entering the image root.
/// Numeric users need no passwd entry; an existing entry supplies its primary gid.
pub fn resolve(user: ?[]const u8) IdentityError!Identity {
    const value = user orelse return .{};
    var passwd_buf: [65536]u8 = undefined;
    var group_buf: [65536]u8 = undefined;
    const passwd = readAccounts("/etc/passwd", &passwd_buf) catch return error.IdentityFailed;
    const groups = readAccounts("/etc/group", &group_buf) catch return error.IdentityFailed;
    return resolveAccounts(value, passwd, groups);
}

pub fn validate(value: []const u8) IdentityError!void {
    if (value.len == 0 or std.mem.indexOfAny(u8, value, "\x00\n\r \t/") != null) return error.InvalidUser;
    var parts = std.mem.splitScalar(u8, value, ':');
    if (parts.next().?.len == 0) return error.InvalidUser;
    if (parts.next()) |group| if (group.len == 0) return error.InvalidUser;
    if (parts.next() != null) return error.InvalidUser;
}

fn number(value: []const u8) ?u32 {
    if (value.len == 0) return null;
    for (value) |c| if (!std.ascii.isDigit(c)) return null;
    const n = std.fmt.parseInt(u32, value, 10) catch return null;
    return if (n == std.math.maxInt(u32)) null else n;
}

pub fn resolveAccounts(value: []const u8, passwd: []const u8, groups: []const u8) IdentityError!Identity {
    try validate(value);
    var parts = std.mem.splitScalar(u8, value, ':');
    const user = parts.next().?;
    const explicit_group = parts.next();
    const numeric_uid = number(user);
    var result: Identity = .{ .uid = numeric_uid orelse 0 };
    var found = numeric_uid != null;
    var lines = std.mem.splitScalar(u8, passwd, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, ':');
        const name = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        const uid = number(fields.next() orelse continue) orelse continue;
        const gid = number(fields.next() orelse continue) orelse continue;
        if (if (numeric_uid) |n| uid == n else std.mem.eql(u8, user, name)) {
            result = .{ .uid = uid, .gid = gid };
            found = true;
            break;
        }
    }
    if (!found) return error.UnknownUser;
    if (explicit_group) |group| {
        if (number(group)) |gid| {
            result.gid = gid;
        } else {
            var group_lines = std.mem.splitScalar(u8, groups, '\n');
            while (group_lines.next()) |line| {
                var fields = std.mem.splitScalar(u8, line, ':');
                const name = fields.next() orelse continue;
                _ = fields.next() orelse continue;
                const gid = number(fields.next() orelse continue) orelse continue;
                if (std.mem.eql(u8, name, group)) {
                    result.gid = gid;
                    return result;
                }
            }
            return error.UnknownGroup;
        }
    }
    return result;
}

pub fn apply(identity: Identity) IdentityError!void {
    const empty: [0]linux.gid_t = .{};
    if (linux.errno(linux.setgroups(0, &empty)) != .SUCCESS) {
        // Unprivileged user namespaces deny setgroups. Never retain inherited
        // supplementary groups when that restriction prevents clearing them.
        if (linux.getgroups(0, null) != 0) return error.IdentityFailed;
    }
    if (linux.errno(linux.setresgid(identity.gid, identity.gid, identity.gid)) != .SUCCESS) return error.IdentityFailed;
    if (linux.errno(linux.setresuid(identity.uid, identity.uid, identity.uid)) != .SUCCESS) return error.IdentityFailed;
}

fn readAccounts(path: []const u8, buf: []u8) ![]const u8 {
    const fd = platform.posix.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NONBLOCK = true }, 0) catch |err| {
        if (err == error.FileNotFound) return "";
        return err;
    };
    defer platform.posix.close(fd);
    const stat = try platform.posix.fstat(fd);
    if (stat.mode & std.posix.S.IFMT != std.posix.S.IFREG) return error.IdentityFailed;
    var len: usize = 0;
    while (len < buf.len) {
        const n = try std.posix.read(fd, buf[len..]);
        if (n == 0) return buf[0..len];
        len += n;
    }
    return error.IdentityFailed;
}

test "build identity resolves numeric and named users and explicit groups" {
    const passwd = "root:x:0:0::/:/bin/sh\napp:x:123:456::/:/bin/sh\n";
    const groups = "staff:x:789:\n";
    try std.testing.expectEqual(Identity{ .uid = 123, .gid = 456 }, try resolveAccounts("app", passwd, groups));
    try std.testing.expectEqual(Identity{ .uid = 123, .gid = 456 }, try resolveAccounts("123", passwd, groups));
    try std.testing.expectEqual(Identity{ .uid = 321, .gid = 789 }, try resolveAccounts("321:staff", passwd, groups));
    try std.testing.expectEqual(Identity{ .uid = 123, .gid = 42 }, try resolveAccounts("app:42", passwd, groups));
    try std.testing.expectError(error.UnknownUser, resolveAccounts("missing", passwd, groups));
    try std.testing.expectError(error.UnknownGroup, resolveAccounts("app:missing", passwd, groups));
    for ([_][]const u8{ "", ":staff", "app:", "app:42:99", "app\x00" }) |invalid| {
        try std.testing.expectError(error.InvalidUser, resolveAccounts(invalid, passwd, groups));
    }
}
