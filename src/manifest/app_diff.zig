const std = @import("std");
const json_helpers = @import("../lib/json_helpers.zig");

pub const WorkloadKind = enum {
    service,
    worker,
    cron,
    training_job,

    fn jsonKey(self: WorkloadKind) []const u8 {
        return switch (self) {
            .service => "services",
            .worker => "workers",
            .cron => "crons",
            .training_job => "training_jobs",
        };
    }

    fn label(self: WorkloadKind) []const u8 {
        return switch (self) {
            .service => "service",
            .worker => "worker",
            .cron => "cron",
            .training_job => "training_job",
        };
    }

    fn heading(self: WorkloadKind) []const u8 {
        return switch (self) {
            .service => "services",
            .worker => "workers",
            .cron => "crons",
            .training_job => "training jobs",
        };
    }
};

pub const ChangeKind = enum {
    create,
    update,
    delete,
    unchanged,

    fn label(self: ChangeKind) []const u8 {
        return switch (self) {
            .create => "create",
            .update => "update",
            .delete => "delete",
            .unchanged => "unchanged",
        };
    }

    fn marker(self: ChangeKind) []const u8 {
        return switch (self) {
            .create => "+",
            .update => "~",
            .delete => "-",
            .unchanged => "=",
        };
    }
};

pub const WorkloadChange = struct {
    kind: WorkloadKind,
    name: []const u8,
    change: ChangeKind,
};

pub const Summary = struct {
    create: usize = 0,
    update: usize = 0,
    delete: usize = 0,
    unchanged: usize = 0,

    fn add(self: *Summary, change: ChangeKind) void {
        switch (change) {
            .create => self.create += 1,
            .update => self.update += 1,
            .delete => self.delete += 1,
            .unchanged => self.unchanged += 1,
        }
    }
};

pub const AppDiff = struct {
    app_name: []const u8,
    proposed_manifest_hash: []const u8,
    current_release_id: ?[]const u8,
    current_manifest_hash: ?[]const u8,
    changes: []WorkloadChange,
    summary: Summary,
    alloc: std.mem.Allocator,

    pub fn deinit(self: *AppDiff) void {
        self.alloc.free(self.changes);
    }

    pub fn renderJson(self: *const AppDiff, alloc: std.mem.Allocator) ![]u8 {
        var out = std.Io.Writer.Allocating.init(alloc);
        defer out.deinit();
        const writer = &out.writer;

        try writer.writeAll("{\"app_name\":\"");
        try json_helpers.writeJsonEscaped(writer, self.app_name);
        try writer.writeAll("\",\"proposed_manifest_hash\":\"");
        try json_helpers.writeJsonEscaped(writer, self.proposed_manifest_hash);
        try writer.writeAll("\",\"current_release_id\":");
        try writeNullableString(writer, self.current_release_id);
        try writer.writeAll(",\"current_manifest_hash\":");
        try writeNullableString(writer, self.current_manifest_hash);
        try writer.print(
            ",\"summary\":{{\"create\":{d},\"update\":{d},\"delete\":{d},\"unchanged\":{d}}},\"changes\":[",
            .{ self.summary.create, self.summary.update, self.summary.delete, self.summary.unchanged },
        );

        for (self.changes, 0..) |change, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeAll("{\"kind\":\"");
            try writer.writeAll(change.kind.label());
            try writer.writeAll("\",\"name\":\"");
            try json_helpers.writeJsonEscaped(writer, change.name);
            try writer.writeAll("\",\"change\":\"");
            try writer.writeAll(change.change.label());
            try writer.writeAll("\"}");
        }
        try writer.writeAll("]}");

        return out.toOwnedSlice();
    }

    pub fn renderText(self: *const AppDiff, alloc: std.mem.Allocator) ![]u8 {
        var out = std.Io.Writer.Allocating.init(alloc);
        defer out.deinit();
        const writer = &out.writer;

        try writer.print("dry run for app {s}\n", .{self.app_name});
        if (self.current_release_id) |id| {
            try writer.print("current release: {s}", .{id});
            if (self.current_manifest_hash) |hash| try writer.print(" ({s})", .{hash});
            try writer.writeByte('\n');
        } else {
            try writer.writeAll("current release: none\n");
        }
        try writer.print("proposed manifest: {s}\n", .{self.proposed_manifest_hash});
        try writer.print(
            "changes: {d} create, {d} update, {d} delete, {d} unchanged\n",
            .{ self.summary.create, self.summary.update, self.summary.delete, self.summary.unchanged },
        );

        const kinds = [_]WorkloadKind{ .service, .worker, .cron, .training_job };
        for (kinds) |kind| {
            if (hasKind(self.changes, kind)) {
                try writer.print("{s}:\n", .{kind.heading()});
                for (self.changes) |change| {
                    if (change.kind != kind) continue;
                    try writer.print("  {s} {s} ({s})\n", .{
                        change.change.marker(),
                        change.name,
                        change.change.label(),
                    });
                }
            }
        }

        return out.toOwnedSlice();
    }
};

pub fn compute(
    alloc: std.mem.Allocator,
    app_name: []const u8,
    proposed_manifest_hash: []const u8,
    current_release_id: ?[]const u8,
    current_manifest_hash: ?[]const u8,
    current_snapshot: ?[]const u8,
    proposed_snapshot: []const u8,
) !AppDiff {
    var changes: std.ArrayList(WorkloadChange) = .empty;
    errdefer changes.deinit(alloc);

    inline for (.{ WorkloadKind.service, WorkloadKind.worker, WorkloadKind.cron, WorkloadKind.training_job }) |kind| {
        try appendKindDiff(alloc, &changes, kind, current_snapshot, proposed_snapshot);
    }

    const owned_changes = try changes.toOwnedSlice(alloc);
    var summary: Summary = .{};
    for (owned_changes) |change| summary.add(change.change);

    return .{
        .app_name = app_name,
        .proposed_manifest_hash = proposed_manifest_hash,
        .current_release_id = current_release_id,
        .current_manifest_hash = current_manifest_hash,
        .changes = owned_changes,
        .summary = summary,
        .alloc = alloc,
    };
}

fn appendKindDiff(
    alloc: std.mem.Allocator,
    changes: *std.ArrayList(WorkloadChange),
    kind: WorkloadKind,
    current_snapshot: ?[]const u8,
    proposed_snapshot: []const u8,
) !void {
    const current_array = if (current_snapshot) |snapshot| json_helpers.extractJsonArray(snapshot, kind.jsonKey()) else null;
    const proposed_array = json_helpers.extractJsonArray(proposed_snapshot, kind.jsonKey());

    if (proposed_array) |array| {
        var iter = json_helpers.extractJsonObjects(array);
        while (iter.next()) |proposed_obj| {
            const name = json_helpers.extractJsonString(proposed_obj, "name") orelse continue;
            const current_obj = if (current_array) |cur| findNamedObject(cur, name) else null;
            const change: ChangeKind = if (current_obj) |cur_obj|
                if (std.mem.eql(u8, cur_obj, proposed_obj)) .unchanged else .update
            else
                .create;
            try changes.append(alloc, .{ .kind = kind, .name = name, .change = change });
        }
    }

    if (current_array) |array| {
        var iter = json_helpers.extractJsonObjects(array);
        while (iter.next()) |current_obj| {
            const name = json_helpers.extractJsonString(current_obj, "name") orelse continue;
            if (proposed_array != null and findNamedObject(proposed_array.?, name) != null) continue;
            try changes.append(alloc, .{ .kind = kind, .name = name, .change = .delete });
        }
    }
}

fn findNamedObject(array_json: []const u8, name: []const u8) ?[]const u8 {
    var iter = json_helpers.extractJsonObjects(array_json);
    while (iter.next()) |obj| {
        const obj_name = json_helpers.extractJsonString(obj, "name") orelse continue;
        if (std.mem.eql(u8, obj_name, name)) return obj;
    }
    return null;
}

fn hasKind(changes: []const WorkloadChange, kind: WorkloadKind) bool {
    for (changes) |change| {
        if (change.kind == kind) return true;
    }
    return false;
}

fn writeNullableString(writer: *std.Io.Writer, value: ?[]const u8) !void {
    if (value) |text| {
        try writer.writeByte('"');
        try json_helpers.writeJsonEscaped(writer, text);
        try writer.writeByte('"');
    } else {
        try writer.writeAll("null");
    }
}

test "diff marks all proposed workloads as creates without current snapshot" {
    const alloc = std.testing.allocator;
    var diff = try compute(alloc, "demo", "sha256:new", null, null, null,
        \\{"app_name":"demo","services":[{"name":"web","image":"nginx"}],"workers":[],"crons":[],"training_jobs":[]}
    );
    defer diff.deinit();

    try std.testing.expectEqual(@as(usize, 1), diff.summary.create);
    try std.testing.expectEqual(@as(usize, 0), diff.summary.update);
    try std.testing.expectEqual(@as(usize, 0), diff.summary.delete);
    try std.testing.expectEqualStrings("web", diff.changes[0].name);
}

test "diff detects unchanged update and delete" {
    const alloc = std.testing.allocator;
    var diff = try compute(alloc, "demo", "sha256:new", "dep-1", "sha256:old",
        \\{"app_name":"demo","services":[{"name":"web","image":"nginx:1"},{"name":"old","image":"busybox"}],"workers":[{"name":"migrate","image":"alpine"}],"crons":[],"training_jobs":[]}
    ,
        \\{"app_name":"demo","services":[{"name":"web","image":"nginx:2"}],"workers":[{"name":"migrate","image":"alpine"}],"crons":[],"training_jobs":[]}
    );
    defer diff.deinit();

    try std.testing.expectEqual(@as(usize, 0), diff.summary.create);
    try std.testing.expectEqual(@as(usize, 1), diff.summary.update);
    try std.testing.expectEqual(@as(usize, 1), diff.summary.delete);
    try std.testing.expectEqual(@as(usize, 1), diff.summary.unchanged);
}

test "diff renders json and text" {
    const alloc = std.testing.allocator;
    var diff = try compute(alloc, "demo", "sha256:new", null, null, null,
        \\{"app_name":"demo","services":[{"name":"web","image":"nginx"}],"workers":[],"crons":[],"training_jobs":[]}
    );
    defer diff.deinit();

    const json = try diff.renderJson(alloc);
    defer alloc.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"change\":\"create\"") != null);

    const text = try diff.renderText(alloc);
    defer alloc.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "dry run for app demo") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "+ web") != null);
}
