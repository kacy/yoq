//! store_mock.zig - Mock implementation of state/store.zig for testing
//!
//! This module provides a mock store that simulates database operations
//! without requiring a real SQLite database. It's useful for unit testing
//! API routes and other components that depend on store operations.

const std = @import("std");
const store = @import("../../state/store.zig");

pub const ContainerRecord = store.ContainerRecord;
pub const ImageRecord = store.ImageRecord;
pub const StoreError = store.StoreError;

/// Mock store for testing container and image operations
pub const MockStore = struct {
    alloc: std.mem.Allocator,
    containers: std.ArrayList(ContainerRecord),
    images: std.ArrayList(ImageRecord),
    fail_next: ?StoreError = null, // Set to simulate failures

    pub fn init(alloc: std.mem.Allocator) MockStore {
        return .{
            .alloc = alloc,
            .containers = std.ArrayList(ContainerRecord).init(alloc),
            .images = std.ArrayList(ImageRecord).init(alloc),
        };
    }

    pub fn deinit(self: *MockStore) void {
        // Free all container records
        for (self.containers.items) |*container| {
            container.deinit(self.alloc);
        }
        self.containers.deinit();

        // Free all image records
        for (self.images.items) |*image| {
            image.deinit(self.alloc);
        }
        self.images.deinit();
    }

    /// Simulate a failure on the next operation
    pub fn setNextFailure(self: *MockStore, err: StoreError) void {
        self.fail_next = err;
    }

    /// Clear any pending failure
    pub fn clearFailure(self: *MockStore) void {
        self.fail_next = null;
    }

    fn checkFailure(self: *MockStore) StoreError!void {
        if (self.fail_next) |err| {
            self.fail_next = null;
            return err;
        }
    }

    // Container operations

    pub fn listIds(self: *MockStore) StoreError!std.ArrayList([]const u8) {
        try self.checkFailure();

        var result = std.ArrayList([]const u8).init(self.alloc);
        errdefer {
            for (result.items) |id| {
                self.alloc.free(id);
            }
            result.deinit();
        }

        for (self.containers.items) |container| {
            const id_copy = try self.alloc.dupe(u8, container.id);
            try result.append(id_copy);
        }

        return result;
    }

    pub fn load(self: *MockStore, id: []const u8) StoreError!?ContainerRecord {
        try self.checkFailure();

        for (self.containers.items) |container| {
            if (std.mem.eql(u8, container.id, id)) {
                return try copyContainerRecord(self.alloc, container);
            }
        }

        return null;
    }

    pub fn updateStatus(
        self: *MockStore,
        id: []const u8,
        status: []const u8,
        pid: ?i32,
        exit_code: ?u8,
    ) StoreError!void {
        try self.checkFailure();

        for (self.containers.items) |*container| {
            if (std.mem.eql(u8, container.id, id)) {
                // Free old status
                self.alloc.free(container.status);

                // Update status
                container.status = try self.alloc.dupe(u8, status);
                container.pid = pid;
                container.exit_code = exit_code;
                return;
            }
        }

        return StoreError.NotFound;
    }

    pub fn remove(self: *MockStore, id: []const u8) StoreError!void {
        try self.checkFailure();

        for (self.containers.items, 0..) |container, i| {
            if (std.mem.eql(u8, container.id, id)) {
                // Free the container record
                var removed = self.containers.swapRemove(i);
                removed.deinit(self.alloc);
                return;
            }
        }

        return StoreError.NotFound;
    }

    pub fn listAll(self: *MockStore) StoreError!std.ArrayList(ContainerRecord) {
        try self.checkFailure();

        var result = std.ArrayList(ContainerRecord).init(self.alloc);
        errdefer {
            for (result.items) |*container| {
                container.deinit(self.alloc);
            }
            result.deinit();
        }

        for (self.containers.items) |container| {
            const copy = try copyContainerRecord(self.alloc, container);
            try result.append(copy);
        }

        return result;
    }

    // Image operations

    pub fn listImages(self: *MockStore) StoreError!std.ArrayList(ImageRecord) {
        try self.checkFailure();

        var result = std.ArrayList(ImageRecord).init(self.alloc);
        errdefer {
            for (result.items) |*image| {
                image.deinit(self.alloc);
            }
            result.deinit();
        }

        for (self.images.items) |image| {
            const copy = try copyImageRecord(self.alloc, image);
            try result.append(copy);
        }

        return result;
    }

    pub fn loadImage(self: *MockStore, id: []const u8) StoreError!?ImageRecord {
        try self.checkFailure();

        for (self.images.items) |image| {
            if (std.mem.eql(u8, image.id, id)) {
                return try copyImageRecord(self.alloc, image);
            }
        }

        return null;
    }

    pub fn removeImage(self: *MockStore, id: []const u8) StoreError!void {
        try self.checkFailure();

        for (self.images.items, 0..) |image, i| {
            if (std.mem.eql(u8, image.id, id)) {
                var removed = self.images.swapRemove(i);
                removed.deinit(self.alloc);
                return;
            }
        }

        return StoreError.NotFound;
    }

    // Test helpers

    pub fn addTestContainer(
        self: *MockStore,
        id: []const u8,
        status: []const u8,
        pid: ?i32,
    ) !void {
        const record = ContainerRecord{
            .id = try self.alloc.dupe(u8, id),
            .rootfs = try self.alloc.dupe(u8, "/tmp/test-rootfs"),
            .command = try self.alloc.dupe(u8, "echo test"),
            .hostname = try self.alloc.dupe(u8, "test-host"),
            .status = try self.alloc.dupe(u8, status),
            .pid = pid,
            .exit_code = null,
            .ip_address = null,
            .veth_host = null,
            .app_name = null,
            .created_at = @import("compat").timestamp(),
        };

        try self.containers.append(record);
    }

    pub fn addTestImage(
        self: *MockStore,
        id: []const u8,
        repository: []const u8,
        tag: []const u8,
    ) !void {
        const record = ImageRecord{
            .id = try self.alloc.dupe(u8, id),
            .repository = try self.alloc.dupe(u8, repository),
            .tag = try self.alloc.dupe(u8, tag),
            .manifest_digest = try self.alloc.dupe(u8, "sha256:abcdef"),
            .config_digest = try self.alloc.dupe(u8, "sha256:123456"),
            .total_size = 1024,
            .created_at = @import("compat").timestamp(),
        };

        try self.images.append(record);
    }

    pub fn containerCount(self: *MockStore) usize {
        return self.containers.items.len;
    }

    pub fn imageCount(self: *MockStore) usize {
        return self.images.items.len;
    }
};

// Helper functions

fn copyContainerRecord(alloc: std.mem.Allocator, source: ContainerRecord) !ContainerRecord {
    return ContainerRecord{
        .id = try alloc.dupe(u8, source.id),
        .rootfs = try alloc.dupe(u8, source.rootfs),
        .command = try alloc.dupe(u8, source.command),
        .hostname = try alloc.dupe(u8, source.hostname),
        .status = try alloc.dupe(u8, source.status),
        .pid = source.pid,
        .exit_code = source.exit_code,
        .ip_address = if (source.ip_address) |ip| try alloc.dupe(u8, ip) else null,
        .veth_host = if (source.veth_host) |veth| try alloc.dupe(u8, veth) else null,
        .app_name = if (source.app_name) |app| try alloc.dupe(u8, app) else null,
        .created_at = source.created_at,
    };
}

fn copyImageRecord(alloc: std.mem.Allocator, source: ImageRecord) !ImageRecord {
    return ImageRecord{
        .id = try alloc.dupe(u8, source.id),
        .repository = try alloc.dupe(u8, source.repository),
        .tag = try alloc.dupe(u8, source.tag),
        .manifest_digest = try alloc.dupe(u8, source.manifest_digest),
        .config_digest = try alloc.dupe(u8, source.config_digest),
        .total_size = source.total_size,
        .created_at = source.created_at,
    };
}

// -- Tests --

test "MockStore init and deinit" {
    var mock_store = MockStore.init(std.testing.allocator);
    defer mock_store.deinit();

    try std.testing.expectEqual(@as(usize, 0), mock_store.containerCount());
    try std.testing.expectEqual(@as(usize, 0), mock_store.imageCount());
}

test "MockStore add and retrieve container" {
    var mock = MockStore.init(std.testing.allocator);
    defer mock.deinit();

    const test_id = "abc123def456";
    try mock.addTestContainer(test_id, "running", 1234);

    try std.testing.expectEqual(@as(usize, 1), mock.containerCount());

    const container = try mock.load(test_id);
    try std.testing.expect(container != null);
    try std.testing.expectEqualStrings(test_id, container.?.id);
    try std.testing.expectEqualStrings("running", container.?.status);
    try std.testing.expectEqual(@as(i32, 1234), container.?.pid.?);

    // Cleanup the returned record
    if (container) |*c| {
        c.deinit(std.testing.allocator);
    }
}

test "MockStore container not found" {
    var mock = MockStore.init(std.testing.allocator);
    defer mock.deinit();

    const container = try mock.load("nonexistent");
    try std.testing.expect(container == null);
}

test "MockStore update status" {
    var mock = MockStore.init(std.testing.allocator);
    defer mock.deinit();

    const test_id = "container1";
    try mock.addTestContainer(test_id, "running", 1234);

    // Update status
    try mock.updateStatus(test_id, "stopped", null, 0);

    const container = try mock.load(test_id);
    try std.testing.expect(container != null);
    try std.testing.expectEqualStrings("stopped", container.?.status);
    try std.testing.expect(container.?.pid == null);

    if (container) |*c| {
        c.deinit(std.testing.allocator);
    }
}

test "MockStore remove container" {
    var mock = MockStore.init(std.testing.allocator);
    defer mock.deinit();

    const test_id = "to-remove";
    try mock.addTestContainer(test_id, "running", null);
    try std.testing.expectEqual(@as(usize, 1), mock.containerCount());

    try mock.remove(test_id);
    try std.testing.expectEqual(@as(usize, 0), mock.containerCount());

    const container = try mock.load(test_id);
    try std.testing.expect(container == null);
}

test "MockStore listIds" {
    var mock = MockStore.init(std.testing.allocator);
    defer mock.deinit();

    try mock.addTestContainer("id1", "running", null);
    try mock.addTestContainer("id2", "stopped", null);

    const ids = try mock.listIds();
    defer {
        for (ids.items) |id| {
            mock.alloc.free(id);
        }
        ids.deinit();
    }

    try std.testing.expectEqual(@as(usize, 2), ids.items.len);
}

test "MockStore listAll containers" {
    var mock = MockStore.init(std.testing.allocator);
    defer mock.deinit();

    try mock.addTestContainer("c1", "running", null);
    try mock.addTestContainer("c2", "stopped", null);

    const all = try mock.listAll();
    defer {
        for (all.items) |*container| {
            container.deinit(std.testing.allocator);
        }
        all.deinit();
    }

    try std.testing.expectEqual(@as(usize, 2), all.items.len);
}

test "MockStore add and retrieve image" {
    var mock = MockStore.init(std.testing.allocator);
    defer mock.deinit();

    try mock.addTestImage("img123", "alpine", "latest");

    const image = try mock.loadImage("img123");
    try std.testing.expect(image != null);
    try std.testing.expectEqualStrings("alpine", image.?.repository);
    try std.testing.expectEqualStrings("latest", image.?.tag);

    if (image) |*img| {
        img.deinit(std.testing.allocator);
    }
}

test "MockStore listImages" {
    var mock = MockStore.init(std.testing.allocator);
    defer mock.deinit();

    try mock.addTestImage("img1", "nginx", "1.0");
    try mock.addTestImage("img2", "redis", "6.0");

    const images = try mock.listImages();
    defer {
        for (images.items) |*img| {
            img.deinit(std.testing.allocator);
        }
        images.deinit();
    }

    try std.testing.expectEqual(@as(usize, 2), images.items.len);
}

test "MockStore simulate failure" {
    var mock = MockStore.init(std.testing.allocator);
    defer mock.deinit();

    // Set up a failure
    mock.setNextFailure(StoreError.ReadFailed);

    // Next operation should fail
    const result = mock.listIds();
    try std.testing.expectError(StoreError.ReadFailed, result);

    // After failure, operations work again
    const ids = try mock.listIds();
    defer {
        for (ids.items) |id| {
            mock.alloc.free(id);
        }
        ids.deinit();
    }
    try std.testing.expectEqual(@as(usize, 0), ids.items.len);
}
