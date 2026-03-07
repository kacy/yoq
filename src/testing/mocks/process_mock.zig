//! process_mock.zig - Mock implementation of runtime/process.zig for testing
//!
//! This module provides mock implementations of process management functions
//! without actually sending signals to real processes.

const std = @import("std");
const process = @import("../../runtime/process.zig");

pub const ProcessError = process.ProcessError;
pub const ExitStatus = process.ExitStatus;

/// Mock process manager for testing
pub const MockProcess = struct {
    /// Map of PID -> termination status
    terminated_pids: std.AutoHashMap(i32, void),
    killed_pids: std.AutoHashMap(i32, void),
    fail_next_terminate: ?ProcessError = null,
    fail_next_kill: ?ProcessError = null,

    pub fn init(alloc: std.mem.Allocator) MockProcess {
        return .{
            .terminated_pids = std.AutoHashMap(i32, void).init(alloc),
            .killed_pids = std.AutoHashMap(i32, void).init(alloc),
        };
    }

    pub fn deinit(self: *MockProcess) void {
        self.terminated_pids.deinit();
        self.killed_pids.deinit();
    }

    /// Set a failure for the next terminate() call
    pub fn setNextTerminateFailure(self: *MockProcess, err: ProcessError) void {
        self.fail_next_terminate = err;
    }

    /// Set a failure for the next kill() call
    pub fn setNextKillFailure(self: *MockProcess, err: ProcessError) void {
        self.fail_next_kill = err;
    }

    /// Clear any pending failures
    pub fn clearFailures(self: *MockProcess) void {
        self.fail_next_terminate = null;
        self.fail_next_kill = null;
    }

    /// Simulate sending SIGTERM to a process
    pub fn terminate(self: *MockProcess, pid: i32) ProcessError!void {
        if (self.fail_next_terminate) |err| {
            self.fail_next_terminate = null;
            return err;
        }

        // In mock, we just record that the PID was terminated
        try self.terminated_pids.put(pid, {});
    }

    /// Simulate sending SIGKILL to a process
    pub fn kill(self: *MockProcess, pid: i32) ProcessError!void {
        if (self.fail_next_kill) |err| {
            self.fail_next_kill = null;
            return err;
        }

        try self.killed_pids.put(pid, {});
    }

    /// Check if a PID was terminated
    pub fn wasTerminated(self: *MockProcess, pid: i32) bool {
        return self.terminated_pids.contains(pid);
    }

    /// Check if a PID was killed
    pub fn wasKilled(self: *MockProcess, pid: i32) bool {
        return self.killed_pids.contains(pid);
    }

    /// Get count of terminated processes
    pub fn terminatedCount(self: *MockProcess) usize {
        return self.terminated_pids.count();
    }

    /// Get count of killed processes
    pub fn killedCount(self: *MockProcess) usize {
        return self.killed_pids.count();
    }

    /// Reset all recorded PIDs
    pub fn reset(self: *MockProcess) void {
        self.terminated_pids.clearRetainingCapacity();
        self.killed_pids.clearRetainingCapacity();
        self.clearFailures();
    }
};

/// Helper function to parse status (copied from real implementation for accuracy)
pub fn parseStatus(status: u32) ExitStatus {
    // WIFEXITED: (status & 0x7f) == 0
    if (status & 0x7f == 0) {
        // WEXITSTATUS: (status >> 8) & 0xff
        return .{ .exited = @intCast((status >> 8) & 0xff) };
    }

    // WIFSIGNALED: (status & 0x7f) != 0x7f && (status & 0x7f) != 0
    const signal = status & 0x7f;
    if (signal != 0x7f and signal != 0) {
        return .{ .signaled = @intCast(signal) };
    }

    // WIFSTOPPED: (status & 0xff) == 0x7f
    if (status & 0xff == 0x7f) {
        return .{ .stopped = @intCast((status >> 8) & 0xff) };
    }

    // WIFCONTINUED: status == 0xffff
    if (status == 0xffff) {
        return .continued;
    }

    return .{ .unknown = status };
}

// -- Tests --

test "MockProcess terminate and kill" {
    var mock = MockProcess.init(std.testing.allocator);
    defer mock.deinit();

    const test_pid = 1234;

    // Initially not terminated
    try std.testing.expect(!mock.wasTerminated(test_pid));
    try std.testing.expect(!mock.wasKilled(test_pid));

    // Terminate the process
    try mock.terminate(test_pid);
    try std.testing.expect(mock.wasTerminated(test_pid));
    try std.testing.expect(!mock.wasKilled(test_pid));
    try std.testing.expectEqual(@as(usize, 1), mock.terminatedCount());

    // Kill the process
    try mock.kill(test_pid);
    try std.testing.expect(mock.wasKilled(test_pid));
    try std.testing.expectEqual(@as(usize, 1), mock.killedCount());
}

test "MockProcess multiple PIDs" {
    var mock = MockProcess.init(std.testing.allocator);
    defer mock.deinit();

    try mock.terminate(100);
    try mock.terminate(200);
    try mock.kill(300);

    try std.testing.expect(mock.wasTerminated(100));
    try std.testing.expect(mock.wasTerminated(200));
    try std.testing.expect(!mock.wasTerminated(300));
    try std.testing.expect(mock.wasKilled(300));
    try std.testing.expect(!mock.wasKilled(100));

    try std.testing.expectEqual(@as(usize, 2), mock.terminatedCount());
    try std.testing.expectEqual(@as(usize, 1), mock.killedCount());
}

test "MockProcess simulate failure" {
    var mock = MockProcess.init(std.testing.allocator);
    defer mock.deinit();

    // Set up failure for terminate
    mock.setNextTerminateFailure(ProcessError.InvalidProcess);

    // Next terminate should fail
    const result = mock.terminate(1234);
    try std.testing.expectError(ProcessError.InvalidProcess, result);

    // After failure, terminate works again
    try mock.terminate(1234);
    try std.testing.expect(mock.wasTerminated(1234));
}

test "MockProcess reset" {
    var mock = MockProcess.init(std.testing.allocator);
    defer mock.deinit();

    try mock.terminate(100);
    try mock.kill(200);
    try std.testing.expectEqual(@as(usize, 1), mock.terminatedCount());
    try std.testing.expectEqual(@as(usize, 1), mock.killedCount());

    mock.reset();

    try std.testing.expectEqual(@as(usize, 0), mock.terminatedCount());
    try std.testing.expectEqual(@as(usize, 0), mock.killedCount());
    try std.testing.expect(!mock.wasTerminated(100));
    try std.testing.expect(!mock.wasKilled(200));
}

test "parseStatus exited" {
    // Simulate status for process that exited with code 0
    const status: u32 = 0; // exit code 0
    const result = parseStatus(status);
    try std.testing.expectEqual(@as(u8, 0), result.exited);
}

test "parseStatus exited with code" {
    // Simulate status for process that exited with code 42
    const status: u32 = 42 << 8; // exit code 42
    const result = parseStatus(status);
    try std.testing.expectEqual(@as(u8, 42), result.exited);
}

test "parseStatus signaled" {
    // Simulate status for process killed by SIGTERM (signal 15)
    const status: u32 = 15; // signaled with signal 15
    const result = parseStatus(status);
    try std.testing.expectEqual(@as(u8, 15), result.signaled);
}

test "parseStatus stopped" {
    // Simulate stopped process (SIGSTOP = 19)
    const status: u32 = 0x7f | (19 << 8);
    const result = parseStatus(status);
    try std.testing.expectEqual(@as(u8, 19), result.stopped);
}

test "parseStatus continued" {
    const status: u32 = 0xffff;
    const result = parseStatus(status);
    try std.testing.expectEqual(ExitStatus.continued, result);
}
