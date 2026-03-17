const toml = @import("../../lib/toml.zig");
const types = @import("types.zig");

pub fn readStage(table: *const toml.Table, name: []const u8) ?types.StageSpec {
    const from = table.getString("from") orelse return null;

    return .{
        .name = name,
        .from = from,
        .workdir = table.getString("workdir"),
        .env = table.getArray("env"),
        .arg = table.getArray("arg"),
        .steps = table.getArray("steps"),
        .expose = table.getArray("expose"),
        .entrypoint = table.getArray("entrypoint"),
        .cmd = table.getArray("cmd"),
        .user = table.getString("user"),
        .volume = table.getArray("volume"),
        .shell = table.getArray("shell"),
        .stopsignal = table.getString("stopsignal"),
        .label = table.getArray("label"),
        .healthcheck = table.getString("healthcheck"),
    };
}
