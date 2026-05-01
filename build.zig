const std = @import("std");

// sqlite wrapper cache key - bump this when updating the vendored wrapper.
const SQLITE_HASH = "sqlite-3.49.2-N-V-__8AAH-mpwB7g3MnqYU-ooUBF1t99RP27dZ9addtMVXD";

/// check if we have a cached sqlite build matching current version
fn hasCachedSqlite(b: *std.Build) bool {
    const hash_file = std.fs.cwd().openFile("vendor/prebuilt/sqlite.hash", .{}) catch return false;
    defer hash_file.close();

    const hash_content = hash_file.readToEndAlloc(b.allocator, 1024) catch return false;
    defer b.allocator.free(hash_content);

    return std.mem.eql(u8, std.mem.trim(u8, hash_content, " \n\r\t"), SQLITE_HASH);
}

fn addLinuxImport(module: *std.Build.Module, b: *std.Build) void {
    const mod_target = module.resolved_target orelse unreachable;
    const mod_optimize = module.optimize orelse unreachable;

    const linux_mod = b.createModule(.{
        .root_source_file = b.path("src/lib/linux_platform.zig"),
        .target = mod_target,
        .optimize = mod_optimize,
    });
    module.addImport("linux_platform", linux_mod);
}

fn addSqlite(module: *std.Build.Module, b: *std.Build) void {
    const mod_target = module.resolved_target orelse unreachable;
    const mod_optimize = module.optimize orelse unreachable;

    // get zig-sqlite for its Zig wrapper (sqlite.zig) and C headers
    const sqlite_dep = b.dependency("sqlite", .{
        .target = mod_target,
        .optimize = mod_optimize,
    });

    // get upstream sqlite amalgamation for sqlite3.c
    const sqlite_upstream = b.dependency("sqlite_amalgamation", .{});

    // compile sqlite3.c as a static library (zig-sqlite defaults to dynamic)
    const sqlite_lib = b.addLibrary(.{
        .name = "sqlite-static",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = mod_target,
            .optimize = mod_optimize,
            .link_libc = true,
        }),
    });
    const c_flags: []const []const u8 = &.{
        "-std=c99",
        "-DSQLITE_THREADSAFE=1",
        "-DSQLITE_ENABLE_FTS5",
        "-DSQLITE_ENABLE_JSON1",
    };
    sqlite_lib.root_module.addCSourceFile(.{
        .file = sqlite_upstream.path("sqlite3.c"),
        .flags = c_flags,
    });
    // zig-sqlite's workaround.c provides sqliteTransientAsDestructor
    sqlite_lib.root_module.addCSourceFile(.{
        .file = sqlite_dep.path("c/workaround.c"),
        .flags = c_flags,
    });
    sqlite_lib.root_module.addIncludePath(sqlite_upstream.path("."));
    sqlite_lib.root_module.addIncludePath(sqlite_dep.path("c"));

    // create the sqlite module using zig-sqlite's Zig wrapper but our static lib
    const sqlite_mod = b.addModule("sqlite-import", .{
        .root_source_file = sqlite_dep.path("sqlite.zig"),
        .target = mod_target,
        .optimize = mod_optimize,
        .link_libc = true,
    });
    sqlite_mod.addIncludePath(sqlite_dep.path("c"));
    sqlite_mod.addIncludePath(sqlite_upstream.path("."));
    sqlite_mod.linkLibrary(sqlite_lib);

    module.addImport("sqlite", sqlite_mod);
    addLinuxImport(module, b);
}

fn createArtifactRunner(
    b: *std.Build,
    artifact: *std.Build.Step.Compile,
    name: []const u8,
    skip_slow_tests: bool,
) *std.Build.Step.Run {
    const run = std.Build.Step.Run.create(b, name);
    run.producer = artifact;
    run.addArtifactArg(artifact);
    run.has_side_effects = true;
    if (skip_slow_tests) {
        run.setEnvironmentVariable("YOQ_SKIP_SLOW_TESTS", "1");
    }
    if (b.args) |args| {
        run.addArgs(args);
    }
    return run;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Default to ReleaseSafe to keep local and CI behavior aligned for the
    // heavier integration-style test lanes.
    const optimize = b.option(std.builtin.OptimizeMode, "optimize", "Optimization mode") orelse .ReleaseSafe;
    const test_filter = b.option([]const u8, "test-filter", "Only compile unit tests matching this substring");
    const run_privileged_tests = b.option(
        bool,
        "run-privileged-tests",
        "Run privileged runtime tests instead of preflight-skipping them",
    ) orelse false;

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

    const test_http_server = b.addExecutable(.{
        .name = "yoq-test-http-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/privileged/http_server.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    addLinuxImport(test_http_server.root_module, b);
    const install_test_http_server = b.addInstallArtifact(test_http_server, .{});

    const test_net_probe = b.addExecutable(.{
        .name = "yoq-test-net-probe",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/privileged/net_probe.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    addLinuxImport(test_net_probe.root_module, b);
    const install_test_net_probe = b.addInstallArtifact(test_net_probe, .{});

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
    addSqlite(test_mod, b);

    const tests = b.addTest(.{
        .root_module = test_mod,
        .filters = if (test_filter) |filter| &.{filter} else &.{},
    });

    const test_step = b.step("test", "Run tests");
    const run_tests = createArtifactRunner(b, tests, "run test", false);
    test_step.dependOn(&run_tests.step);

    const hardening_test_step = b.step(
        "test-hardening",
        "Run deterministic non-privileged hardening tests",
    );

    // -- operator smoke tests (sqlite required, no root) --
    //
    // these are the preferred regression lanes for the app-first control plane:
    // local lifecycle, remote lifecycle, rollout control, rollback parity, and
    // partial-failure operator views. keep this target focused and high-signal.
    const operator_test_step = b.step("test-operator", "Run app operator smoke tests");
    const operator_test_mod = b.createModule(.{
        .root_source_file = b.path("src/test_operator.zig"),
        .target = target,
        .optimize = optimize,
    });
    addSqlite(operator_test_mod, b);

    const operator_tests = b.addTest(.{
        .root_module = operator_test_mod,
        .filters = if (test_filter) |filter| &.{filter} else &.{},
    });
    const run_operator = createArtifactRunner(b, operator_tests, "run operator smoke tests", true);
    operator_test_step.dependOn(&run_operator.step);

    // -- network rollout smoke tests (sqlite required, no root) --
    //
    // these are the preferred regression lanes for the network/proxy/service
    // rollout stack: status/metrics, service registry bridging, reconciler
    // readiness, and rollout flag semantics. keep this target deterministic
    // and separate from privileged proxy/runtime coverage.
    const network_test_step = b.step("test-network", "Run network rollout smoke tests");
    const network_test_mod = b.createModule(.{
        .root_source_file = b.path("src/test_network.zig"),
        .target = target,
        .optimize = optimize,
    });
    addSqlite(network_test_mod, b);

    const network_tests = b.addTest(.{
        .root_module = network_test_mod,
        .filters = if (test_filter) |filter| &.{filter} else &.{},
    });
    const run_network = createArtifactRunner(b, network_tests, "run network rollout smoke tests", true);
    network_test_step.dependOn(&run_network.step);

    // -- golden path tests (installed binary + documented examples) --
    //
    // these keep the documented single-machine operator flow executable:
    // CLI entry points, example manifest validation, and example app shapes.
    const golden_path_test_step = b.step("test-golden-path", "Run documented golden path smoke tests");
    const golden_path_test_mod = b.createModule(.{
        .root_source_file = b.path("src/test_golden_path.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    addLinuxImport(golden_path_test_mod, b);
    golden_path_test_mod.addImport("helpers", b.createModule(.{
        .root_source_file = b.path("tests/helpers.zig"),
        .target = target,
        .optimize = optimize,
    }));
    const golden_path_tests = b.addTest(.{
        .root_module = golden_path_test_mod,
        .filters = if (test_filter) |filter| &.{filter} else &.{},
    });
    const run_golden_path = createArtifactRunner(b, golden_path_tests, "run golden path tests", true);
    run_golden_path.step.dependOn(b.getInstallStep());
    golden_path_test_step.dependOn(&run_golden_path.step);
    hardening_test_step.dependOn(golden_path_test_step);

    // -- gpu tests (no hardware required) --
    //
    // these focus on the src/gpu subtree plus manifest GPU env glue. they are
    // intended to stay deterministic on hosts without physical GPUs by using
    // fake procfs/sysfs layouts and synthetic topology fixtures.
    const gpu_test_step = b.step("test-gpu", "Run GPU-focused tests");
    const gpu_test_mod = b.createModule(.{
        .root_source_file = b.path("src/test_gpu_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addSqlite(gpu_test_mod, b);

    const gpu_tests = b.addTest(.{
        .root_module = gpu_test_mod,
    });
    const run_gpu_tests = createArtifactRunner(b, gpu_tests, "run gpu tests", false);
    gpu_test_step.dependOn(&run_gpu_tests.step);
    hardening_test_step.dependOn(gpu_test_step);

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
    const integration_test_mod = b.createModule(.{
        .root_source_file = b.path("src/test_integration.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    addLinuxImport(integration_test_mod, b);
    const integration_tests_mod = b.addTest(.{
        .root_module = integration_test_mod,
    });
    const run_integration = createArtifactRunner(b, integration_tests_mod, "run integration tests", false);
    integration_test_step.dependOn(&run_integration.step);

    // helper module tests (subprocess runner, temp dirs)
    const helper_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/helpers.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_helpers = createArtifactRunner(b, helper_tests, "run helper tests", false);
    integration_test_step.dependOn(&run_helpers.step);
    hardening_test_step.dependOn(integration_test_step);

    // -- contract tests (no sqlite/root required) --
    //
    // these assert externally visible API and storage behavior with exact
    // status codes, content types, and response bodies. keep these
    // deterministic and filesystem-backed without requiring root.
    const contract_test_step = b.step("test-contract", "Run API and storage contract tests");
    const contract_test_mod = b.createModule(.{
        .root_source_file = b.path("src/test_contract.zig"),
        .target = target,
        .optimize = optimize,
    });
    addSqlite(contract_test_mod, b);
    const contract_tests = b.addTest(.{
        .root_module = contract_test_mod,
        .filters = if (test_filter) |filter| &.{filter} else &.{"contract"},
    });
    const run_contract = createArtifactRunner(b, contract_tests, "run contract tests", true);
    run_contract.step.dependOn(b.getInstallStep());
    contract_test_step.dependOn(&run_contract.step);
    hardening_test_step.dependOn(contract_test_step);

    // -- deterministic simulation tests (require sqlite, no root) --
    //
    // these focus on cluster state-machine behavior under simulated delivery,
    // partitions, and recovery without relying on timing-heavy subprocess tests.
    const sim_test_step = b.step("test-sim", "Run deterministic cluster simulation tests");
    const sim_test_mod = b.createModule(.{
        .root_source_file = b.path("src/test_sim.zig"),
        .target = target,
        .optimize = optimize,
    });
    addSqlite(sim_test_mod, b);

    const sim_tests = b.addTest(.{
        .root_module = sim_test_mod,
        .filters = if (test_filter) |filter| &.{filter} else &.{},
    });
    const run_sim = createArtifactRunner(b, sim_tests, "run simulation tests", true);
    sim_test_step.dependOn(&run_sim.step);
    hardening_test_step.dependOn(sim_test_step);

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

    const runtime_core_test_step = b.step(
        "test-runtime-core",
        "Run privileged container lifecycle, error, and limits tests",
    );
    const runtime_network_test_step = b.step(
        "test-runtime-network",
        "Run privileged container networking and service discovery tests",
    );
    const runtime_cluster_test_step = b.step(
        "test-runtime-cluster",
        "Run privileged cluster, chaos, stress, and API security tests",
    );
    const privileged_test_step = b.step(
        "test-privileged",
        "Run all privileged runtime integration tests (requires root)",
    );
    privileged_test_step.dependOn(runtime_core_test_step);
    privileged_test_step.dependOn(runtime_network_test_step);
    privileged_test_step.dependOn(runtime_cluster_test_step);

    const runtime_core_tests = [_][]const u8{
        "tests/privileged/test_container.zig",
        "tests/privileged/test_errors.zig",
        "tests/privileged/test_limits.zig",
    };
    const runtime_network_tests = [_][]const u8{
        "tests/privileged/test_networking.zig",
    };
    const runtime_cluster_tests = [_][]const u8{
        "tests/privileged/test_cluster.zig",
        "tests/privileged/test_chaos.zig",
        "tests/privileged/test_security.zig",
        "tests/privileged/test_security_audit.zig",
        "tests/privileged/test_stress.zig",
    };
    const runtime_preflight_options = b.addOptions();
    runtime_preflight_options.addOption(bool, "run_privileged_tests", run_privileged_tests);

    const privileged_lanes = [_]struct {
        step: *std.Build.Step,
        tests: []const []const u8,
        needs_network_helpers: bool = false,
    }{
        .{ .step = runtime_core_test_step, .tests = &runtime_core_tests },
        .{ .step = runtime_network_test_step, .tests = &runtime_network_tests, .needs_network_helpers = true },
        .{ .step = runtime_cluster_test_step, .tests = &runtime_cluster_tests },
    };

    for (privileged_lanes) |lane| {
        lane.step.dependOn(b.getInstallStep());

        for (lane.tests) |test_file| {
            const priv_mod = b.addTest(.{
                .root_module = b.createModule(.{
                    .root_source_file = b.path(test_file),
                    .target = target,
                    .optimize = optimize,
                }),
                .filters = if (test_filter) |filter| &.{filter} else &.{},
            });
            const helpers_mod = b.createModule(.{
                .root_source_file = b.path("tests/helpers.zig"),
                .target = target,
                .optimize = optimize,
            });
            const linux_mod = b.createModule(.{
                .root_source_file = b.path("src/lib/linux_platform.zig"),
                .target = target,
                .optimize = optimize,
            });
            priv_mod.root_module.addImport("linux_platform", linux_mod);
            const runtime_preflight_mod = b.createModule(.{
                .root_source_file = b.path("tests/privileged/preflight.zig"),
                .target = target,
                .optimize = optimize,
            });
            runtime_preflight_mod.addImport("linux_platform", linux_mod);
            runtime_preflight_mod.addOptions("build_options", runtime_preflight_options);
            priv_mod.root_module.addImport("helpers", helpers_mod);

            const cluster_harness_mod = b.createModule(.{
                .root_source_file = b.path("tests/cluster_test_harness.zig"),
                .target = target,
                .optimize = optimize,
            });
            cluster_harness_mod.addImport("linux_platform", linux_mod);
            const http_client_mod = b.createModule(.{
                .root_source_file = b.path("src/cluster/http_client.zig"),
                .target = target,
                .optimize = optimize,
            });
            http_client_mod.addImport("linux_platform", linux_mod);
            const http_mod = b.createModule(.{
                .root_source_file = b.path("src/api/http.zig"),
                .target = target,
                .optimize = optimize,
            });
            const container_mod = b.createModule(.{
                .root_source_file = b.path("src/runtime/container.zig"),
                .target = target,
                .optimize = optimize,
            });
            const cgroups_mod = b.createModule(.{
                .root_source_file = b.path("src/runtime/cgroups.zig"),
                .target = target,
                .optimize = optimize,
            });
            const cgroups_common_mod = b.createModule(.{
                .root_source_file = b.path("src/runtime/cgroups/common.zig"),
                .target = target,
                .optimize = optimize,
            });
            cluster_harness_mod.addImport("helpers", helpers_mod);
            cluster_harness_mod.addImport("http_client", http_client_mod);
            cluster_harness_mod.addImport("runtime_preflight", runtime_preflight_mod);
            priv_mod.root_module.addImport("http_client", http_client_mod);
            priv_mod.root_module.addImport("http", http_mod);
            priv_mod.root_module.addImport("container", container_mod);
            priv_mod.root_module.addImport("cgroups", cgroups_mod);
            priv_mod.root_module.addImport("cgroups_common", cgroups_common_mod);
            priv_mod.root_module.addImport("cluster_test_harness", cluster_harness_mod);
            priv_mod.root_module.addImport("runtime_preflight", runtime_preflight_mod);
            const run_priv = createArtifactRunner(b, priv_mod, b.fmt("run {s}", .{test_file}), false);
            if (run_privileged_tests) {
                run_priv.setEnvironmentVariable("YOQ_RUN_PRIVILEGED_TESTS", "1");
            }
            run_priv.step.dependOn(b.getInstallStep());
            if (lane.needs_network_helpers) {
                run_priv.step.dependOn(&install_test_http_server.step);
                run_priv.step.dependOn(&install_test_net_probe.step);
            }
            lane.step.dependOn(&run_priv.step);
        }
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

    sqlite_lib.root_module.addCSourceFile(.{
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

    // -- fuzz tests --
    //
    // fuzz targets for attack-surface-exposed parsers. each target uses
    // std.testing.fuzz() which runs corpus inputs in normal test mode
    // and continuous fuzzing with `zig build fuzz-<name> -- --fuzz`.
    //
    // usage:
    //   zig build fuzz-http         — run HTTP parser fuzz target
    //   zig build fuzz-manifest     — run manifest parser fuzz target
    //   zig build fuzz-dns          — run DNS parser fuzz target
    //   zig build fuzz-cluster-msg  — run cluster message fuzz target
    //   zig build fuzz-gossip-msg   — run gossip message fuzz target

    {
        const fuzz_simple = [_]struct { name: []const u8, file: []const u8, mod_name: []const u8, mod_path: []const u8 }{
            .{ .name = "fuzz-http", .file = "tests/fuzz/fuzz_http.zig", .mod_name = "http", .mod_path = "src/api/http.zig" },
            .{ .name = "fuzz-cluster-msg", .file = "tests/fuzz/fuzz_cluster_msg.zig", .mod_name = "transport", .mod_path = "src/cluster/transport.zig" },
            .{ .name = "fuzz-gossip-msg", .file = "tests/fuzz/fuzz_gossip_msg.zig", .mod_name = "gossip", .mod_path = "src/cluster/gossip.zig" },
        };

        for (fuzz_simple) |ft| {
            const step = b.step(ft.name, b.fmt("Fuzz {s}", .{ft.name}));
            const mod = b.createModule(.{
                .root_source_file = b.path(ft.file),
                .target = target,
                .optimize = optimize,
            });
            mod.addImport(ft.mod_name, b.createModule(.{
                .root_source_file = b.path(ft.mod_path),
                .target = target,
                .optimize = optimize,
            }));
            const comp = b.addTest(.{ .root_module = mod });
            const run = createArtifactRunner(b, comp, b.fmt("run {s}", .{ft.name}), false);
            step.dependOn(&run.step);
            hardening_test_step.dependOn(step);
        }

        // fuzz-manifest: lives in src/ so loader's relative imports resolve
        {
            const step = b.step("fuzz-manifest", "Fuzz manifest parser");
            const mod = b.createModule(.{
                .root_source_file = b.path("src/test_fuzz_manifest.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            });
            addLinuxImport(mod, b);
            const comp = b.addTest(.{ .root_module = mod });
            const run = createArtifactRunner(b, comp, "run fuzz-manifest", false);
            step.dependOn(&run.step);
            hardening_test_step.dependOn(step);
        }

        // fuzz-dns: lives in src/ so dns.zig's relative imports resolve; needs sqlite
        {
            const step = b.step("fuzz-dns", "Fuzz DNS parser");
            const mod = b.createModule(.{
                .root_source_file = b.path("src/test_fuzz_dns.zig"),
                .target = target,
                .optimize = optimize,
            });
            addSqlite(mod, b);
            const comp = b.addTest(.{ .root_module = mod });
            const run = createArtifactRunner(b, comp, "run fuzz-dns", false);
            step.dependOn(&run.step);
            hardening_test_step.dependOn(step);
        }

        // fuzz-wireguard: lives in src/ so wireguard.zig's relative imports resolve
        {
            const step = b.step("fuzz-wireguard", "Fuzz WireGuard handshake");
            const mod = b.createModule(.{
                .root_source_file = b.path("src/test_fuzz_wireguard.zig"),
                .target = target,
                .optimize = optimize,
            });
            addSqlite(mod, b);
            const comp = b.addTest(.{ .root_module = mod });
            const run = createArtifactRunner(b, comp, "run fuzz-wireguard", false);
            step.dependOn(&run.step);
            hardening_test_step.dependOn(step);
        }

        // manifest edge cases (adversarial parser inputs)
        {
            const step = b.step("test-manifest-edge", "Run manifest edge case tests");
            const mod = b.createModule(.{
                .root_source_file = b.path("src/test_fuzz_manifest_edge.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            });
            addLinuxImport(mod, b);
            const comp = b.addTest(.{ .root_module = mod });
            const run = std.Build.Step.Run.create(b, "run test-manifest-edge");
            run.producer = comp;
            run.addArtifactArg(comp);
            run.has_side_effects = true;
            step.dependOn(&run.step);
            hardening_test_step.dependOn(step);
        }
    }

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
        "storage_metrics",
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
