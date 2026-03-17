const std = @import("std");

const types = @import("types.zig");

pub fn matchKeyword(keyword: []const u8) ?types.InstructionKind {
    var lower_buf: [16]u8 = undefined;
    if (keyword.len > lower_buf.len) return null;

    for (keyword, 0..) |c, i| {
        lower_buf[i] = std.ascii.toLower(c);
    }
    const lower = lower_buf[0..keyword.len];

    if (std.mem.eql(u8, lower, "from")) return .from;
    if (std.mem.eql(u8, lower, "run")) return .run;
    if (std.mem.eql(u8, lower, "copy")) return .copy;
    if (std.mem.eql(u8, lower, "add")) return .add;
    if (std.mem.eql(u8, lower, "env")) return .env;
    if (std.mem.eql(u8, lower, "expose")) return .expose;
    if (std.mem.eql(u8, lower, "entrypoint")) return .entrypoint;
    if (std.mem.eql(u8, lower, "cmd")) return .cmd;
    if (std.mem.eql(u8, lower, "workdir")) return .workdir;
    if (std.mem.eql(u8, lower, "arg")) return .arg;
    if (std.mem.eql(u8, lower, "user")) return .user;
    if (std.mem.eql(u8, lower, "label")) return .label;
    if (std.mem.eql(u8, lower, "volume")) return .volume;
    if (std.mem.eql(u8, lower, "shell")) return .shell;
    if (std.mem.eql(u8, lower, "healthcheck")) return .healthcheck;
    if (std.mem.eql(u8, lower, "stopsignal")) return .stopsignal;
    if (std.mem.eql(u8, lower, "onbuild")) return .onbuild;
    return null;
}
