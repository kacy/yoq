const std = @import("std");

fn addSqlite(module: *std.Build.Module, b: *std.Build) void {
    const sqlite = b.dependency("sqlite", .{
        .target = module.resolved_target.?,
        .optimize = module.optimize.?,
    });
    module.addImport("sqlite", sqlite.module("sqlite"));
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "yoq",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    addSqlite(exe.root_module, b);
    b.installArtifact(exe);

    const run_step = b.step("run", "Run yoq");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    addSqlite(tests.root_module, b);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);
}
