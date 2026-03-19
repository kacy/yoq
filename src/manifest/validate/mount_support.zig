const spec = @import("../spec.zig");

pub const MountEntry = struct {
    name: []const u8,
    volumes: []const spec.VolumeMount,
};

pub const MountCollection = struct {
    entries: []const MountEntry,
    truncated: bool,
};

pub fn collectAllMounts(manifest: *const spec.Manifest) MountCollection {
    const max_entries = 128;
    const S = struct {
        var buf: [max_entries]MountEntry = undefined;
    };
    var count: usize = 0;
    var truncated = false;

    for (manifest.services) |svc| {
        if (count >= max_entries) {
            truncated = true;
            break;
        }
        S.buf[count] = .{ .name = svc.name, .volumes = svc.volumes };
        count += 1;
    }
    for (manifest.workers) |worker| {
        if (count >= max_entries) {
            truncated = true;
            break;
        }
        S.buf[count] = .{ .name = worker.name, .volumes = worker.volumes };
        count += 1;
    }
    for (manifest.crons) |cron| {
        if (count >= max_entries) {
            truncated = true;
            break;
        }
        S.buf[count] = .{ .name = cron.name, .volumes = cron.volumes };
        count += 1;
    }
    for (manifest.training_jobs) |job| {
        if (count >= max_entries) {
            truncated = true;
            break;
        }
        S.buf[count] = .{ .name = job.name, .volumes = job.volumes };
        count += 1;
    }

    return .{ .entries = S.buf[0..count], .truncated = truncated };
}
