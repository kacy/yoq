const std = @import("std");
const platform = @import("platform");
pub const rate_limit_per_sec: u32 = 10;
pub const rate_limit_burst: u32 = 50;
pub const rate_table_size: usize = 64;

pub const RateLimiter = struct {
    entries: [rate_table_size]RateEntry,
    mutex: std.Io.Mutex,

    const RateEntry = struct {
        ip: u32,
        count: u32,
        window_start: i64,
        active: bool,
    };

    const empty_entry = RateEntry{
        .ip = 0,
        .count = 0,
        .window_start = 0,
        .active = false,
    };

    pub fn init() RateLimiter {
        return .{
            .entries = [_]RateEntry{empty_entry} ** rate_table_size,
            .mutex = .init,
        };
    }

    pub fn checkRate(self: *RateLimiter, ip: u32) bool {
        return self.checkRateAt(ip, platform.timestamp());
    }

    pub fn checkRateAt(self: *RateLimiter, ip: u32, now: i64) bool {
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);

        const start_idx = @as(usize, ip *% 2654435761);
        var probe: usize = 0;
        var first_empty: ?usize = null;
        var stale_slot: ?usize = null;

        while (probe < rate_table_size) : (probe += 1) {
            const idx = (start_idx +% probe) % rate_table_size;
            const entry = &self.entries[idx];

            if (!entry.active) {
                if (first_empty == null) first_empty = idx;
                break;
            }

            if (entry.ip == ip) {
                if (now != entry.window_start) {
                    entry.window_start = now;
                    entry.count = 1;
                    return true;
                }

                entry.count += 1;
                return entry.count <= rate_limit_burst;
            }

            if (entry.window_start != now and stale_slot == null) {
                stale_slot = idx;
            }
        }

        if (first_empty orelse stale_slot) |idx| {
            self.entries[idx] = .{
                .ip = ip,
                .count = 1,
                .window_start = now,
                .active = true,
            };
            return true;
        }

        return false;
    }

    pub fn reset(self: *RateLimiter) void {
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);
        self.entries = [_]RateEntry{empty_entry} ** rate_table_size;
    }
};

pub var rate_limiter: RateLimiter = RateLimiter.init();
