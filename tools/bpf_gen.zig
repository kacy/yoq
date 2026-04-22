// bpf_gen — extract BPF bytecode from ELF .o files into Zig comptime arrays
//
// reads a BPF ELF relocatable object (produced by clang -target bpf) and
// generates a .zig file containing:
//   - map definitions (type, key_size, value_size, max_entries)
//   - program instructions as a comptime BPF.Insn array
//   - relocation entries (which instructions reference which maps)
//
// supports multiple program sections per ELF (e.g. lb.c has both
// tc_ingress and tc_egress). the first section uses bare names (insns,
// relocs, prog_name), additional sections use egress_ prefixed names.
//
// the generated files are checked into the repo so that normal builds
// don't need clang. only run this tool when BPF C sources change.
//
// usage: zig run tools/bpf_gen.zig -- <input.o> <output.zig>

const std = @import("std");
const elf = std.elf;

const R_BPF_64_64: u32 = 1;
const BPF_INSN_SIZE: usize = 8;

const Elf64_Ehdr = elf.Elf64_Ehdr;
const Elf64_Shdr = elf.Elf64_Shdr;
const Elf64_Sym = elf.Elf64_Sym;

const Elf64_Rel = extern struct {
    r_offset: u64,
    r_info: u64,

    fn sym(self: Elf64_Rel) u32 {
        return @intCast(self.r_info >> 32);
    }

    fn typ(self: Elf64_Rel) u32 {
        return @intCast(self.r_info & 0xFFFFFFFF);
    }
};

const BpfMapDef = extern struct {
    type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
};

const MapInfo = struct {
    name: []const u8,
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
};

const RelocInfo = struct {
    insn_idx: u32,
    map_name: []const u8,
    target_section_idx: u16,
};

const ProgramInfo = struct {
    name: []const u8,
    insn_data: []const u8,
    section_idx: u16,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    if (args.len != 3) {
        std.debug.print("usage: bpf_gen <input.o> <output.zig>\n", .{});
        std.process.exit(1);
    }

    const input_path = args[1];
    const output_path = args[2];

    const data = @import("compat").cwd().readFileAlloc(alloc, input_path, 10 * 1024 * 1024) catch |e| {
        std.debug.print("error: cannot read {s}: {}\n", .{ input_path, e });
        std.process.exit(1);
    };
    defer alloc.free(data);

    var maps: std.ArrayList(MapInfo) = .empty;
    defer maps.deinit(alloc);
    var programs: std.ArrayList(ProgramInfo) = .empty;
    defer programs.deinit(alloc);
    var relocs: std.ArrayList(RelocInfo) = .empty;
    defer relocs.deinit(alloc);

    try parseElf(data, alloc, &maps, &programs, &relocs);

    if (programs.items.len == 0) {
        std.debug.print("error: no BPF program sections found in {s}\n", .{input_path});
        std.process.exit(1);
    }

    const output_file = @import("compat").cwd().createFile(output_path, .{}) catch |e| {
        std.debug.print("error: cannot create {s}: {}\n", .{ output_path, e });
        std.process.exit(1);
    };
    defer output_file.close();

    var write_buf: [4096]u8 = undefined;
    var file_writer = output_file.writer(&write_buf);
    try generateZig(&file_writer.interface, input_path, maps.items, programs.items, relocs.items);
    try file_writer.interface.flush();

    std.debug.print("generated {s} ({d} program(s), {d} map(s), {d} relocation(s))\n", .{
        output_path, programs.items.len, maps.items.len, relocs.items.len,
    });
}

fn parseElf(data: []const u8, alloc: std.mem.Allocator, maps: *std.ArrayList(MapInfo), programs: *std.ArrayList(ProgramInfo), relocs: *std.ArrayList(RelocInfo)) !void {
    if (data.len < @sizeOf(Elf64_Ehdr)) return error.InvalidElf;
    const ehdr: *const Elf64_Ehdr = @ptrCast(@alignCast(data.ptr));
    if (!std.mem.eql(u8, ehdr.e_ident[0..4], "\x7fELF")) return error.InvalidElf;
    if (ehdr.e_ident[4] != elf.ELFCLASS64) return error.InvalidElf;
    if (ehdr.e_ident[5] != elf.ELFDATA2LSB) return error.InvalidElf;
    if (ehdr.e_type != elf.ET.REL) return error.InvalidElf;
    if (ehdr.e_machine != elf.EM.BPF) return error.InvalidElf;
    const shdr_count = ehdr.e_shnum;
    if (ehdr.e_shoff + @as(u64, shdr_count) * ehdr.e_shentsize > data.len) return error.InvalidElf;
    if (ehdr.e_shstrndx >= shdr_count) return error.InvalidElf;
    const shstrtab_shdr = getSectionHeader(data, ehdr, ehdr.e_shstrndx);
    const shstrtab = getSectionData(data, shstrtab_shdr);

    var symtab_shdr: ?*const Elf64_Shdr = null;
    var strtab_data: ?[]const u8 = null;
    for (0..shdr_count) |i| {
        const shdr = getSectionHeader(data, ehdr, @intCast(i));
        if (shdr.sh_type == elf.SHT_SYMTAB) {
            symtab_shdr = shdr;
            if (shdr.sh_link < shdr_count) {
                const linked = getSectionHeader(data, ehdr, @intCast(shdr.sh_link));
                strtab_data = getSectionData(data, linked);
            }
        }
    }

    for (0..shdr_count) |i| {
        const shdr = getSectionHeader(data, ehdr, @intCast(i));
        const sec_name = getSectionName(shstrtab, shdr.sh_name);
        if (shdr.sh_type == elf.SHT_PROGBITS and (shdr.sh_flags & elf.SHF_EXECINSTR) != 0 and !std.mem.eql(u8, sec_name, ".text")) {
            // skip .text — it contains static helper functions that get
            // inlined into the real program sections by the compiler.
            try programs.append(alloc, .{ .name = sec_name, .insn_data = getSectionData(data, shdr), .section_idx = @intCast(i) });
        } else if (shdr.sh_type == elf.SHT_PROGBITS and std.mem.eql(u8, sec_name, "maps")) {
            try parseMaps(getSectionData(data, shdr), alloc, maps, symtab_shdr, strtab_data, data, ehdr, @intCast(i));
        } else if (shdr.sh_type == elf.SHT_REL) {
            const target_idx: u16 = @intCast(shdr.sh_info);
            const target_shdr = getSectionHeader(data, ehdr, target_idx);
            if (target_shdr.sh_type == elf.SHT_PROGBITS and (target_shdr.sh_flags & elf.SHF_EXECINSTR) != 0) {
                try parseRelocs(getSectionData(data, shdr), alloc, relocs, symtab_shdr, strtab_data, data, ehdr, target_idx);
            }
        }
    }
}

fn getSectionHeader(data: []const u8, ehdr: *const Elf64_Ehdr, index: u16) *const Elf64_Shdr {
    const offset = ehdr.e_shoff + @as(u64, index) * ehdr.e_shentsize;
    return @ptrCast(@alignCast(&data[offset]));
}

fn getSectionData(data: []const u8, shdr: *const Elf64_Shdr) []const u8 {
    const start: usize = @intCast(shdr.sh_offset);
    const size: usize = @intCast(shdr.sh_size);
    if (start + size > data.len) return &.{};
    return data[start..][0..size];
}

fn getSectionName(strtab: []const u8, offset: u32) []const u8 {
    if (offset >= strtab.len) return "";
    const start = strtab[offset..];
    const end = std.mem.indexOfScalar(u8, start, 0) orelse start.len;
    return start[0..end];
}

fn parseMaps(section_data: []const u8, alloc: std.mem.Allocator, maps: *std.ArrayList(MapInfo), symtab_shdr: ?*const Elf64_Shdr, strtab_data: ?[]const u8, elf_data: []const u8, ehdr: *const Elf64_Ehdr, maps_section_idx: u16) !void {
    const map_def_size = @sizeOf(BpfMapDef);
    var offset: usize = 0;
    var map_idx: usize = 0;
    while (offset + map_def_size <= section_data.len) : ({
        offset += map_def_size;
        map_idx += 1;
    }) {
        const def: *const BpfMapDef = @ptrCast(@alignCast(&section_data[offset]));
        const name = findSymbolName(symtab_shdr, strtab_data, elf_data, ehdr, maps_section_idx, offset) orelse "unknown";
        try maps.append(alloc, .{ .name = name, .map_type = def.type, .key_size = def.key_size, .value_size = def.value_size, .max_entries = def.max_entries });
    }
}

fn findSymbolName(symtab_shdr: ?*const Elf64_Shdr, strtab_data: ?[]const u8, elf_data: []const u8, _: *const Elf64_Ehdr, section_idx: u16, offset: usize) ?[]const u8 {
    const shdr = symtab_shdr orelse return null;
    const strtab = strtab_data orelse return null;
    const sym_data = getSectionData(elf_data, shdr);
    const sym_size = @sizeOf(Elf64_Sym);
    for (0..sym_data.len / sym_size) |i| {
        const sym: *const Elf64_Sym = @ptrCast(@alignCast(&sym_data[i * sym_size]));
        if (sym.st_shndx == section_idx and sym.st_value == offset) return getSectionName(strtab, sym.st_name);
    }
    return null;
}

fn parseRelocs(section_data: []const u8, alloc: std.mem.Allocator, relocs: *std.ArrayList(RelocInfo), symtab_shdr: ?*const Elf64_Shdr, strtab_data: ?[]const u8, elf_data: []const u8, _: *const Elf64_Ehdr, target_section_idx: u16) !void {
    const rel_size = @sizeOf(Elf64_Rel);
    const shdr = symtab_shdr orelse return;
    const strtab = strtab_data orelse return;
    const sym_data = getSectionData(elf_data, shdr);
    const sym_entry_size = @sizeOf(Elf64_Sym);
    for (0..section_data.len / rel_size) |i| {
        const rel: *const Elf64_Rel = @ptrCast(@alignCast(&section_data[i * rel_size]));
        if (rel.typ() != R_BPF_64_64) continue;
        const sym_idx = rel.sym();
        if (@as(usize, sym_idx) * sym_entry_size >= sym_data.len) continue;
        const sym: *const Elf64_Sym = @ptrCast(@alignCast(&sym_data[sym_idx * sym_entry_size]));
        try relocs.append(alloc, .{ .insn_idx = @intCast(rel.r_offset / BPF_INSN_SIZE), .map_name = getSectionName(strtab, sym.st_name), .target_section_idx = target_section_idx });
    }
}

fn generateZig(writer: anytype, source_file: []const u8, maps: []const MapInfo, programs: []const ProgramInfo, relocs: []const RelocInfo) !void {
    _ = source_file;
    try writer.writeAll("// generated by tools/bpf_gen.zig — do not edit\n//\n// regenerate with:\n//   clang -target bpf -O2 -g -c -o <name>.o bpf/<name>.c\n//   zig run tools/bpf_gen.zig -- <name>.o src/network/bpf/<name>.zig\n\nconst BPF = @import(\"std\").os.linux.BPF;\n\n");

    try writer.writeAll("pub const MapDef = struct {\n    name: []const u8,\n    map_type: u32,\n    key_size: u32,\n    value_size: u32,\n    max_entries: u32,\n};\n\n");

    try writer.print("pub const maps = [_]MapDef{{\n", .{});
    for (maps) |m| {
        try writer.print("    .{{ .name = \"{s}\", .map_type = {d}, .key_size = {d}, .value_size = {d}, .max_entries = {d} }},\n", .{ m.name, m.map_type, m.key_size, m.value_size, m.max_entries });
    }
    try writer.writeAll("};\n\n");

    try writer.writeAll("pub const Reloc = struct {\n    insn_idx: u32,\n    map_idx: u32,\n};\n\n");

    for (programs, 0..) |prog, prog_idx| {
        const is_primary = prog_idx == 0;

        try writer.print("/// BPF program section: \"{s}\"\n", .{prog.name});
        if (is_primary) {
            try writer.print("pub const prog_name = \"{s}\";\n\n", .{prog.name});
        } else {
            try writer.print("pub const egress_prog_name = \"{s}\";\n\n", .{prog.name});
        }

        if (is_primary) {
            try writer.writeAll("pub const relocs = [_]Reloc{\n");
        } else {
            try writer.writeAll("pub const egress_relocs = [_]Reloc{\n");
        }
        for (relocs) |r| {
            if (r.target_section_idx != prog.section_idx) continue;
            try writer.print("    .{{ .insn_idx = {d}, .map_idx = {d} }},\n", .{ r.insn_idx, findMapIndex(maps, r.map_name) });
        }
        try writer.writeAll("};\n\n");

        const insn_count = prog.insn_data.len / BPF_INSN_SIZE;
        if (is_primary) {
            try writer.print("pub const insns = [_]BPF.Insn{{\n", .{});
        } else {
            try writer.print("pub const egress_insns = [_]BPF.Insn{{\n", .{});
        }
        for (0..insn_count) |ii| {
            const off = ii * BPF_INSN_SIZE;
            const code = prog.insn_data[off];
            const regs = prog.insn_data[off + 1];
            const dst: u4 = @truncate(regs);
            const src: u4 = @truncate(regs >> 4);
            const off_val = std.mem.readInt(i16, prog.insn_data[off + 2 ..][0..2], .little);
            const imm = std.mem.readInt(i32, prog.insn_data[off + 4 ..][0..4], .little);
            try writer.print("    .{{ .code = 0x{x:0>2}, .dst = {d}, .src = {d}, .off = {d}, .imm = {d} }},\n", .{ code, dst, src, off_val, imm });
        }
        try writer.writeAll("};\n\n");
    }
}

fn findMapIndex(maps: []const MapInfo, name: []const u8) u32 {
    for (maps, 0..) |m, i| {
        if (std.mem.eql(u8, m.name, name)) return @intCast(i);
    }
    return 0;
}
