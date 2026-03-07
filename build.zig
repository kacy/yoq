const std = @import("std");

// sqlite version hash from build.zig.zon - bump this when updating sqlite
const SQLITE_HASH = "sqlite-3.48.0-F2R_a9eODgDPCO5CDptJHZINZSIn48IFVIWUhuxxwGTb";

/// check if we have a cached sqlite build matching current version
fn hasCachedSqlite(b: *std.Build) bool {
    const hash_file = std.fs.cwd().openFile("vendor/prebuilt/sqlite.hash", .{}) catch return false;
    defer hash_file.close();

    const hash_content = hash_file.readToEndAlloc(b.allocator, 1024) catch return false;
    defer b.allocator.free(hash_content);

    return std.mem.eql(u8, std.mem.trim(u8, hash_content, " \n\r\t"), SQLITE_HASH);
}

fn addSqlite(module: *std.Build.Module, b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) void {
    // note: for now we always use zig-sqlite to compile
    // the cache-sqlite step creates a prebuilt library but integrating it
    // with zig-sqlite's build system requires more work
    _ = target;
    _ = optimize;

    const sqlite = b.dependency("sqlite", .{
        .target = module.resolved_target.?,
        .optimize = module.optimize.?,
    });
    module.addImport("sqlite", sqlite.module("sqlite"));

    // log cache status for debugging
    if (hasCachedSqlite(b)) {
        std.log.info("sqlite cache exists at vendor/prebuilt/ (zig-sqlite manages compilation)", .{});
    }
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Default to ReleaseSafe to work around Zig 0.15.2 segfault in Debug mode.
    const optimize = b.option(std.builtin.OptimizeMode, "optimize", "Optimization mode") orelse .ReleaseSafe;

    const exe = b.addExecutable(.{
        .name = "yoq",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    addSqlite(exe.root_module, b, target, optimize);
    b.installArtifact(exe);

    const run_step = b.step("run", "Run yoq");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // -- unit tests (require sqlite, run without root) --
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addSqlite(test_mod, b, target, optimize);

    const tests = b.addTest(.{
        .root_module = test_mod,
    });

    // workaround for zig 0.15.2: --listen=- flag causes tests to hang
    // manually create run step without enableTestRunnerMode
    const test_step = b.step("test", "Run tests");
    const run_tests = std.Build.Step.Run.create(b, "run test");
    run_tests.producer = tests;
    run_tests.addArtifactArg(tests);
    run_tests.has_side_effects = true;
    test_step.dependOn(&run_tests.step);

    // -- integration tests (no sqlite required) --
    //
    // these test the manifest loader, validator, CLI helpers, and JSON output
    // without requiring sqlite or root. they import source modules directly.
    //
    // usage:
    //   zig build test-integration    — run all integration tests
    //   make test-integration         — same via Makefile

    const integration_test_step = b.step("test-integration", "Run integration tests (no sqlite/root required)");

    // integration test root lives inside src/ so that relative imports
    // from modules under test (e.g. loader → ../lib/toml) resolve correctly.
    // tests cover manifest loading, validation, and JSON output — all without
    // sqlite, so they run in any environment.
    const integration_tests_mod = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/test_integration.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    // workaround for zig 0.15.2: avoid --listen=- hang by manually creating run step
    const run_integration = std.Build.Step.Run.create(b, "run integration tests");
    run_integration.producer = integration_tests_mod;
    run_integration.addArtifactArg(integration_tests_mod);
    run_integration.has_side_effects = true;
    integration_test_step.dependOn(&run_integration.step);

    // helper module tests (subprocess runner, temp dirs)
    const helper_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/helpers.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    // workaround for zig 0.15.2: avoid --listen=- hang
    const run_helpers = std.Build.Step.Run.create(b, "run helper tests");
    run_helpers.producer = helper_tests;
    run_helpers.addArtifactArg(helper_tests);
    run_helpers.has_side_effects = true;
    integration_test_step.dependOn(&run_helpers.step);

    // -- privileged integration tests (require root + linux 6.1+) --
    //
    // these tests run the yoq binary as a subprocess and exercise the full
    // container lifecycle: run, ps, logs, stop, rm, networking, port mapping,
    // and service discovery. they require root for namespace and cgroup ops.
    //
    // usage:
    //   sudo zig build test-privileged    — run privileged tests
    //   sudo make test-privileged         — same via Makefile
    //
    // prerequisites:
    //   zig build                         — build the yoq binary first

    const privileged_test_step = b.step("test-privileged", "Run privileged integration tests (requires root)");
    privileged_test_step.dependOn(b.getInstallStep());

    const priv_tests = [_][]const u8{
        "tests/privileged/test_container.zig",
        "tests/privileged/test_networking.zig",
    };

    for (priv_tests) |test_file| {
        const priv_mod = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(test_file),
                .target = target,
                .optimize = optimize,
            }),
        });
        priv_mod.root_module.addImport("helpers", b.createModule(.{
            .root_source_file = b.path("tests/helpers.zig"),
            .target = target,
            .optimize = optimize,
        }));
        // workaround for zig 0.15.2: avoid --listen=- hang
        const run_priv = std.Build.Step.Run.create(b, b.fmt("run {s}", .{test_file}));
        run_priv.producer = priv_mod;
        run_priv.addArtifactArg(priv_mod);
        run_priv.has_side_effects = true;
        privileged_test_step.dependOn(&run_priv.step);
    }

    // -- cache-sqlite step: precompile sqlite and cache it --
    //
    // this step compiles sqlite once and stores it in vendor/prebuilt/.
    // run this when you bump the sqlite version (update SQLITE_HASH above).
    // the cached library can be used for reference but zig-sqlite manages
    // its own compilation via the build system.
    //
    // usage:
    //   zig build cache-sqlite          — compile and cache sqlite
    //   zig build                       — normal build (uses zig's built-in cache)

    const cache_sqlite_step = b.step("cache-sqlite", "Compile and cache sqlite (run after version bump)");

    // get the upstream sqlite amalgamation directly
    const sqlite_upstream = b.dependency("sqlite_amalgamation", .{});
    const sqlite_c_path = sqlite_upstream.path("sqlite3.c");

    // create the static library
    const sqlite_lib = b.addLibrary(.{
        .name = "sqlite",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    sqlite_lib.addCSourceFile(.{
        .file = sqlite_c_path,
        .flags = &.{
            "-std=c99",
            "-DSQLITE_THREADSAFE=1",
            "-DSQLITE_ENABLE_FTS5",
            "-DSQLITE_ENABLE_JSON1",
        },
    });

    // create vendor/prebuilt directory
    const mkdir = b.addSystemCommand(&.{ "mkdir", "-p", "vendor/prebuilt" });

    // copy the built library to vendor/prebuilt/
    const copy_lib = b.addSystemCommand(&.{"cp"});
    copy_lib.addFileArg(sqlite_lib.getEmittedBin());
    copy_lib.addArg("vendor/prebuilt/libsqlite.a");
    copy_lib.step.dependOn(&sqlite_lib.step);
    copy_lib.step.dependOn(&mkdir.step);

    // copy header file
    const copy_header = b.addSystemCommand(&.{"cp"});
    copy_header.addFileArg(sqlite_upstream.path("sqlite3.h"));
    copy_header.addArg("vendor/prebuilt/sqlite3.h");
    copy_header.step.dependOn(&copy_lib.step);

    // create hash file
    const write_hash = b.addWriteFile("vendor/prebuilt/sqlite.hash", SQLITE_HASH);
    write_hash.step.dependOn(&copy_header.step);

    cache_sqlite_step.dependOn(&write_hash.step);

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
