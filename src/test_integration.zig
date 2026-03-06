// integration test root — imports integration tests that exercise
// the manifest loader, validator, JSON output, and test helpers.
//
// this file lives inside src/ so that relative imports from the
// modules under test (e.g. loader.zig → ../lib/toml.zig) resolve
// correctly within the module path.
//
// run with: zig build test-integration

const std = @import("std");

// pull in tests from integration test modules
comptime {
    _ = @import("test_manifest_integration.zig");
    _ = @import("test_json_integration.zig");
}
