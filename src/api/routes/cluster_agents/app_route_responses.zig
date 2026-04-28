const std = @import("std");
const sqlite = @import("sqlite");

const apply_release = @import("../../../manifest/apply_release.zig");
const app_snapshot = @import("../../../manifest/app_snapshot.zig");
const app_view = @import("../../../manifest/app_view.zig");
const store = @import("../../../state/store.zig");

pub fn formatApps(
    alloc: std.mem.Allocator,
    db: *sqlite.Db,
    latest_deployments: []const store.DeploymentRecord,
) ![]u8 {
    var json_buf_writer = std.Io.Writer.Allocating.init(alloc);
    defer json_buf_writer.deinit();

    const writer = &json_buf_writer.writer;
    try writer.writeByte('[');
    for (latest_deployments, 0..) |latest, i| {
        const previous_successful = try loadPreviousSuccessfulDeployment(db, alloc, latest.app_name.?, latest.id);
        defer if (previous_successful) |dep| dep.deinit(alloc);

        if (i > 0) try writer.writeByte(',');
        const json = try formatStatusFromDeployments(alloc, db, latest, previous_successful);
        defer alloc.free(json);
        try writer.writeAll(json);
    }
    try writer.writeByte(']');
    return json_buf_writer.toOwnedSlice();
}

pub fn loadPreviousSuccessfulDeployment(
    db: *sqlite.Db,
    alloc: std.mem.Allocator,
    app_name: []const u8,
    exclude_release_id: []const u8,
) !?store.DeploymentRecord {
    return store.getPreviousSuccessfulDeploymentByAppInDb(db, alloc, app_name, exclude_release_id) catch |err| switch (err) {
        error.NotFound => null,
        else => return err,
    };
}

pub fn formatStatusFromDeployments(
    alloc: std.mem.Allocator,
    db: *sqlite.Db,
    latest: store.DeploymentRecord,
    previous_successful: ?store.DeploymentRecord,
) ![]u8 {
    return app_view.renderStatus(alloc, app_view.statusViewFromDeploymentsInDb(db, alloc, latest, previous_successful));
}

pub fn formatHistory(alloc: std.mem.Allocator, deployments: []const store.DeploymentRecord) ![]u8 {
    var entries = try app_view.releaseViewsFromDeployments(alloc, deployments);
    defer app_view.deinitReleaseViews(alloc, &entries);

    return app_view.renderHistory(alloc, entries.items);
}

pub fn formatStatus(
    alloc: std.mem.Allocator,
    report: apply_release.ApplyReport,
    previous_successful: ?apply_release.ApplyReport,
    summary: app_snapshot.Summary,
    training_summary: store.TrainingJobSummary,
) ![]u8 {
    return app_view.renderStatus(
        alloc,
        app_view.statusViewFromReports(
            report,
            previous_successful,
            report.app_name,
            report.app_name,
            if (previous_successful) |previous| previous.app_name else null,
            if (previous_successful) |previous| previous.app_name else null,
            summary,
            null,
            training_summary,
        ),
    );
}
