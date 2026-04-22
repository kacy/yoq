// completion — shell completion script generators for bash, zsh, and fish
//
// outputs a completion script to stdout for the given shell. command names
// are pulled from command_registry at comptime. per-command flags and
// subcommand metadata live here to keep the completion concern isolated.

const std = @import("std");
const cli = @import("cli.zig");
const registry = @import("command_registry.zig");

const write = cli.write;

const CompletionError = error{
    InvalidArgument,
    UnknownShell,
};

// -- metadata --

const SubcommandMeta = struct {
    name: []const u8,
    flags: []const []const u8 = &.{},
};

const CommandMeta = struct {
    name: []const u8,
    flags: []const []const u8 = &.{},
    subcommands: []const SubcommandMeta = &.{},
};

/// completion metadata for every registered command.
/// flags and subcommands are listed here rather than in each command module
/// so that completion logic stays in one place and doesn't leak into the
/// rest of the codebase.
const command_meta = [_]CommandMeta{
    // runtime
    .{ .name = "run", .flags = &.{ "--name", "-p", "--no-net" } },
    .{ .name = "ps" },
    .{ .name = "logs", .flags = &.{"--tail"} },
    .{ .name = "stop" },
    .{ .name = "rm" },
    .{ .name = "restart" },
    .{ .name = "exec" },
    .{ .name = "status", .flags = &.{ "--app", "--verbose", "-v", "--server" } },
    .{ .name = "apps", .flags = &.{ "--server", "--json", "--status", "--failed", "--in-progress" } },
    .{ .name = "metrics", .flags = &.{ "--server", "--pairs" } },
    .{ .name = "gpu", .subcommands = &.{
        .{ .name = "topo", .flags = &.{"--json"} },
    } },

    // image
    .{ .name = "pull" },
    .{ .name = "push" },
    .{ .name = "images" },
    .{ .name = "rmi" },
    .{ .name = "prune" },
    .{ .name = "inspect" },

    // build and manifest
    .{ .name = "build", .flags = &.{ "-t", "-f", "--format", "--build-arg" } },
    .{ .name = "init", .flags = &.{"-f"} },
    .{ .name = "validate", .flags = &.{ "-f", "-q", "--quiet" } },
    .{ .name = "up", .flags = &.{ "-f", "--dev", "--server" } },
    .{ .name = "down", .flags = &.{"-f"} },
    .{ .name = "run-worker", .flags = &.{ "-f", "--server" } },
    .{ .name = "rollback", .flags = &.{ "--app", "--server", "--release", "--print" } },
    .{ .name = "history", .flags = &.{ "--app", "--server", "--json" } },
    .{ .name = "rollout", .flags = &.{ "--app", "--server" }, .subcommands = &.{
        .{ .name = "pause", .flags = &.{ "--app", "--server" } },
        .{ .name = "resume", .flags = &.{ "--app", "--server" } },
        .{ .name = "cancel", .flags = &.{ "--app", "--server" } },
    } },
    .{ .name = "train", .flags = &.{ "-f", "--server", "--rank" }, .subcommands = &.{
        .{ .name = "start", .flags = &.{ "-f", "--server" } },
        .{ .name = "status", .flags = &.{ "-f", "--server" } },
        .{ .name = "stop", .flags = &.{ "-f", "--server" } },
        .{ .name = "pause", .flags = &.{ "-f", "--server" } },
        .{ .name = "resume", .flags = &.{ "-f", "--server" } },
        .{ .name = "scale", .flags = &.{ "--gpus", "--server" } },
        .{ .name = "logs", .flags = &.{ "--rank", "--server" } },
    } },

    // cluster
    .{ .name = "serve", .flags = &.{ "--port", "--log-format", "--http-proxy-bind", "--http-proxy-port" } },
    .{ .name = "init-server", .flags = &.{ "--id", "--port", "--api-port", "--peers", "--token", "--log-format", "--http-proxy-bind", "--http-proxy-port" } },
    .{ .name = "join", .flags = &.{ "--token", "--port" } },
    .{ .name = "cluster", .subcommands = &.{
        .{ .name = "status" },
    } },
    .{ .name = "nodes", .flags = &.{"--server"} },
    .{ .name = "drain", .flags = &.{"--server"} },

    // state and security
    .{ .name = "secret", .subcommands = &.{
        .{ .name = "set", .flags = &.{"--value"} },
        .{ .name = "get" },
        .{ .name = "rm" },
        .{ .name = "list" },
        .{ .name = "rotate" },
    } },
    .{ .name = "policy", .subcommands = &.{
        .{ .name = "deny" },
        .{ .name = "allow" },
        .{ .name = "rm" },
        .{ .name = "list" },
    } },
    .{ .name = "cert", .subcommands = &.{
        .{ .name = "install", .flags = &.{ "--cert", "--key" } },
        .{ .name = "provision", .flags = &.{ "--email", "--staging" } },
        .{ .name = "renew", .flags = &.{ "--email", "--staging" } },
        .{ .name = "list" },
        .{ .name = "rm" },
    } },
    .{ .name = "backup", .flags = &.{"--output"} },
    .{ .name = "restore", .flags = &.{"--input"} },

    // misc
    .{ .name = "doctor", .flags = &.{"--json"} },
    .{ .name = "version" },
    .{ .name = "help" },
    .{ .name = "completion" },
    .{ .name = "__run-supervisor" }, // internal hidden command
};

fn findMeta(name: []const u8) ?*const CommandMeta {
    for (&command_meta) |*meta| {
        if (std.mem.eql(u8, meta.name, name)) return meta;
    }
    return null;
}

// -- handler --

pub fn handler(args: *std.process.Args.Iterator, _: std.mem.Allocator) !void {
    const shell = args.next() orelse {
        cli.writeErr("usage: yoq completion <bash|zsh|fish>\n", .{});
        return CompletionError.InvalidArgument;
    };

    if (std.mem.eql(u8, shell, "bash")) {
        generateBash();
    } else if (std.mem.eql(u8, shell, "zsh")) {
        generateZsh();
    } else if (std.mem.eql(u8, shell, "fish")) {
        generateFish();
    } else {
        cli.writeErr("unknown shell: {s}\n", .{shell});
        cli.writeErr("supported shells: bash, zsh, fish\n", .{});
        return CompletionError.UnknownShell;
    }
}

// -- bash --

fn generateBash() void {
    write(
        \\_yoq() {{
        \\    local cur prev commands
        \\    COMPREPLY=()
        \\    cur="${{COMP_WORDS[COMP_CWORD]}}"
        \\    prev="${{COMP_WORDS[COMP_CWORD-1]}}"
        \\
        \\    commands="
    , .{});

    // list all command names
    for (command_meta, 0..) |meta, i| {
        if (i > 0) write(" ", .{});
        write("{s}", .{meta.name});
    }

    write(
        \\"
        \\
        \\    # completing a subcommand or flag based on previous word
        \\    case "$prev" in
        \\
    , .{});

    // case entries for commands with subcommands or flags
    for (command_meta) |meta| {
        if (meta.subcommands.len == 0 and meta.flags.len == 0) continue;

        write("        {s})\n", .{meta.name});
        write("            COMPREPLY=( $(compgen -W \"", .{});

        // subcommands first, then flags
        var first = true;
        for (meta.subcommands) |sub| {
            if (!first) write(" ", .{});
            write("{s}", .{sub.name});
            first = false;
        }
        for (meta.flags) |flag| {
            if (!first) write(" ", .{});
            write("{s}", .{flag});
            first = false;
        }

        write("\" -- \"$cur\") )\n", .{});
        write("            return 0\n", .{});
        write("            ;;\n", .{});
    }

    // subcommand flag completion (e.g. "secret set --value")
    for (command_meta) |meta| {
        for (meta.subcommands) |sub| {
            if (sub.flags.len == 0) continue;
            write("        {s})\n", .{sub.name});
            write("            COMPREPLY=( $(compgen -W \"", .{});
            for (sub.flags, 0..) |flag, i| {
                if (i > 0) write(" ", .{});
                write("{s}", .{flag});
            }
            write("\" -- \"$cur\") )\n", .{});
            write("            return 0\n", .{});
            write("            ;;\n", .{});
        }
    }

    write(
        \\    esac
        \\
        \\    # top-level: complete command names
        \\    if [ "$COMP_CWORD" -eq 1 ]; then
        \\        COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
        \\        return 0
        \\    fi
        \\
        \\    # flag completion when cur starts with -
        \\    if [[ "$cur" == -* ]]; then
        \\        case "${{COMP_WORDS[1]}}" in
        \\
    , .{});

    for (command_meta) |meta| {
        if (meta.flags.len == 0) continue;
        write("            {s})\n", .{meta.name});
        write("                COMPREPLY=( $(compgen -W \"", .{});
        for (meta.flags, 0..) |flag, i| {
            if (i > 0) write(" ", .{});
            write("{s}", .{flag});
        }
        write("\" -- \"$cur\") )\n", .{});
        write("                ;;\n", .{});
    }

    write(
        \\        esac
        \\    fi
        \\}}
        \\complete -F _yoq yoq
        \\
    , .{});
}

// -- zsh --

fn generateZsh() void {
    write(
        \\#compdef yoq
        \\
        \\_yoq() {{
        \\    local -a commands
        \\    commands=(
        \\
    , .{});

    // command list with descriptions from the registry
    for (command_meta) |meta| {
        const desc = blk: {
            for (registry.command_specs) |spec| {
                if (std.mem.eql(u8, spec.name, meta.name))
                    break :blk spec.description;
            }
            break :blk "";
        };
        write("        '{s}:{s}'\n", .{ meta.name, desc });
    }

    write(
        \\    )
        \\
        \\    if (( CURRENT == 2 )); then
        \\        _describe 'command' commands
        \\        return
        \\    fi
        \\
        \\    case "$words[2]" in
        \\
    , .{});

    for (command_meta) |meta| {
        if (meta.flags.len == 0 and meta.subcommands.len == 0) continue;

        write("        {s})\n", .{meta.name});

        if (meta.subcommands.len > 0) {
            // commands with subcommands: complete subcommands at position 3
            write("            if (( CURRENT == 3 )); then\n", .{});
            write("                local -a subcmds\n", .{});
            write("                subcmds=(", .{});
            for (meta.subcommands, 0..) |sub, i| {
                if (i > 0) write(" ", .{});
                write("'{s}'", .{sub.name});
            }
            write(")\n", .{});
            write("                _describe 'subcommand' subcmds\n", .{});
            write("            fi\n", .{});
        } else {
            // commands with flags only
            write("            _arguments", .{});
            for (meta.flags) |flag| {
                write(" '{s}'", .{flag});
            }
            write("\n", .{});
        }

        write("            ;;\n", .{});
    }

    write(
        \\    esac
        \\}}
        \\
        \\_yoq "$@"
        \\
    , .{});
}

// -- fish --

fn generateFish() void {
    // top-level commands
    for (command_meta) |meta| {
        const desc = blk: {
            for (registry.command_specs) |spec| {
                if (std.mem.eql(u8, spec.name, meta.name))
                    break :blk spec.description;
            }
            break :blk "";
        };
        write(
            "complete -c yoq -n '__fish_use_subcommand' -a '{s}' -d '{s}'\n",
            .{ meta.name, desc },
        );
    }

    // per-command flags and subcommands
    for (command_meta) |meta| {
        for (meta.flags) |flag| {
            // strip leading dashes for fish long/short flag syntax
            if (std.mem.startsWith(u8, flag, "--")) {
                write(
                    "complete -c yoq -n '__fish_seen_subcommand_from {s}' -l '{s}'\n",
                    .{ meta.name, flag[2..] },
                );
            } else if (std.mem.startsWith(u8, flag, "-")) {
                write(
                    "complete -c yoq -n '__fish_seen_subcommand_from {s}' -s '{s}'\n",
                    .{ meta.name, flag[1..] },
                );
            }
        }

        for (meta.subcommands) |sub| {
            write(
                "complete -c yoq -n '__fish_seen_subcommand_from {s}' -a '{s}'\n",
                .{ meta.name, sub.name },
            );

            // subcommand flags
            for (sub.flags) |flag| {
                if (std.mem.startsWith(u8, flag, "--")) {
                    write(
                        "complete -c yoq -n '__fish_seen_subcommand_from {s}; and __fish_seen_subcommand_from {s}' -l '{s}'\n",
                        .{ meta.name, sub.name, flag[2..] },
                    );
                } else if (std.mem.startsWith(u8, flag, "-")) {
                    write(
                        "complete -c yoq -n '__fish_seen_subcommand_from {s}; and __fish_seen_subcommand_from {s}' -s '{s}'\n",
                        .{ meta.name, sub.name, flag[1..] },
                    );
                }
            }
        }
    }
}

// -- tests --

test "metadata covers all registered commands" {
    // every command in the registry should have a metadata entry
    for (registry.command_specs) |spec| {
        const found = findMeta(spec.name);
        if (found == null) {
            std.debug.print("missing completion metadata for command: {s}\n", .{spec.name});
        }
        try std.testing.expect(found != null);
    }
}

test "metadata has no stale entries" {
    // every metadata entry should correspond to a registered command
    for (command_meta) |meta| {
        const found = registry.findCommand(meta.name);
        // "completion" won't be in the registry until we wire it up,
        // so skip it here
        if (std.mem.eql(u8, meta.name, "completion")) continue;
        if (found == null) {
            std.debug.print("stale completion metadata for command: {s}\n", .{meta.name});
        }
        try std.testing.expect(found != null);
    }
}

test "metadata entries are unique" {
    for (command_meta, 0..) |left, i| {
        for (command_meta[i + 1 ..]) |right| {
            try std.testing.expect(!std.mem.eql(u8, left.name, right.name));
        }
    }
}
