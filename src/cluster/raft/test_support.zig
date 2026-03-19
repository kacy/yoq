const std = @import("std");

pub fn freeActionEntries(comptime Action: type, alloc: std.mem.Allocator, actions: []const Action) void {
    for (actions) |action| {
        if (action == .send_append_entries) {
            const entries = action.send_append_entries.args.entries;
            for (entries) |entry| {
                if (entry.data.len > 0) alloc.free(entry.data);
            }
            if (entries.len > 0) alloc.free(entries);
        }
    }
}

pub fn deinitOwnedActions(comptime Action: type, alloc: std.mem.Allocator, actions: []const Action) void {
    freeActionEntries(Action, alloc, actions);
    alloc.free(actions);
}
