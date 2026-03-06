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
            .root_source_file = b.path("src/test_root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    addSqlite(tests.root_module, b);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);

    // -- BPF compilation (optional) --
    //
    // compiles BPF C programs in bpf/ and generates Zig bytecode arrays
    // in src/network/bpf/. requires clang with BPF target support.
    //
    // usage:
    //   zig build bpf           — compile all BPF programs
    //   zig build bpf -- test_prog  — compile a specific program
    //
    // the generated .zig files are checked into the repo, so this step
    // is only needed when BPF C sources change. normal builds use the
    // checked-in bytecode files directly.

    const bpf_step = b.step("bpf", "Compile BPF C programs and generate Zig bytecode");

    // build the bpf_gen tool first
    const bpf_gen = b.addExecutable(.{
        .name = "bpf_gen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/bpf_gen.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
        }),
    });

    // list of BPF programs to compile
    const bpf_programs = [_][]const u8{
        "test_prog",
        "dns_intercept",
        "lb",
        "policy",
        "metrics",
        "port_map",
    };

    for (bpf_programs) |prog| {
        // step 1: compile C → .o with clang
        const c_source = b.fmt("bpf/{s}.c", .{prog});
        const obj_output = b.fmt("bpf/{s}.o", .{prog});

        const clang = b.addSystemCommand(&.{
            "clang",
            "-target",
            "bpf",
            "-O2",
            "-g",
            "-c",
            "-o",
        });
        const obj_file = clang.addOutputFileArg(obj_output);
        clang.addFileArg(b.path(c_source));

        // step 2: run bpf_gen to extract bytecode
        const zig_output = b.fmt("src/network/bpf/{s}.zig", .{prog});
        const gen = b.addRunArtifact(bpf_gen);
        gen.addFileArg(obj_file);
        gen.addArg(zig_output);
        gen.step.dependOn(&clang.step);

        bpf_step.dependOn(&gen.step);
    }
}
