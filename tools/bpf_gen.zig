// bpf_gen — extract BPF bytecode from ELF .o files into Zig comptime arrays
//
// reads a BPF ELF relocatable object (produced by clang -target bpf) and
// generates a .zig file containing:
//   - map definitions (type, key_size, value_size, max_entries)
//   - program instructions as a comptime BPF.Insn array
//   - relocation entries (which instructions reference which maps)
//
// the generated files are checked into the repo so that normal builds
// don't need clang. only run this tool when BPF C sources change.
//
// usage: zig run tools/bpf_gen.zig -- <input.o> <output.zig>

const std = @import("std");
const elf = std.elf;

// BPF-specific constants not in std.elf
const R_BPF_64_64: u32 = 1; // ld_imm64 map fd relocation
const BPF_INSN_SIZE: usize = 8;

// convenience aliases for std.elf types
const Elf64_Ehdr = elf.Elf64_Ehdr;
const Elf64_Shdr = elf.Elf64_Shdr;
const Elf64_Sym = elf.Elf64_Sym;

// std.elf doesn't have a Rel type with helper methods, so we keep
// a thin wrapper for the sym()/typ() accessors.
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

// -- map definition as stored in the "maps" ELF section --

const BpfMapDef = extern struct {
    type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
};

// -- parsed output --

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
};

const ProgramInfo = struct {
    name: []const u8,
    insn_data: []const u8, // raw instruction bytes
};

// -- main --

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

    const data = std.fs.cwd().readFileAlloc(alloc, input_path, 10 * 1024 * 1024) catch |e| {
        std.debug.print("error: cannot read {s}: {}\n", .{ input_path, e });
        std.process.exit(1);
    };
    defer alloc.free(data);

    // parse the ELF file
    var maps = std.ArrayList(MapInfo).init(alloc);
    defer maps.deinit();
    var programs = std.ArrayList(ProgramInfo).init(alloc);
    defer programs.deinit();
    var relocs = std.ArrayList(RelocInfo).init(alloc);
    defer relocs.deinit();

    try parseElf(data, alloc, &maps, &programs, &relocs);

    if (programs.items.len == 0) {
        std.debug.print("error: no BPF program sections found in {s}\n", .{input_path});
        std.process.exit(1);
    }

    // generate the output .zig file
    const output_file = std.fs.cwd().createFile(output_path, .{}) catch |e| {
        std.debug.print("error: cannot create {s}: {}\n", .{ output_path, e });
        std.process.exit(1);
    };
    defer output_file.close();

    try generateZig(output_file.writer(), input_path, maps.items, programs.items, relocs.items);

    std.debug.print("generated {s} ({d} program(s), {d} map(s), {d} relocation(s))\n", .{
        output_path,
        programs.items.len,
        maps.items.len,
        relocs.items.len,
    });
}

// -- ELF parsing --

fn parseElf(
    data: []const u8,
    alloc: std.mem.Allocator,
    maps: *std.ArrayList(MapInfo),
    programs: *std.ArrayList(ProgramInfo),
    relocs: *std.ArrayList(RelocInfo),
) !void {
    if (data.len < @sizeOf(Elf64_Ehdr)) {
        return error.InvalidElf;
    }

    const ehdr: *const Elf64_Ehdr = @ptrCast(@alignCast(data.ptr));

    // validate ELF header
    if (!std.mem.eql(u8, ehdr.e_ident[0..4], "\x7fELF")) return error.InvalidElf;
    if (ehdr.e_ident[4] != elf.ELFCLASS64) return error.InvalidElf;
    if (ehdr.e_ident[5] != elf.ELFDATA2LSB) return error.InvalidElf;
    if (ehdr.e_type != elf.ET.REL) return error.InvalidElf;
    if (ehdr.e_machine != elf.EM.BPF) return error.InvalidElf;

    // read section headers
    const shdr_offset = ehdr.e_shoff;
    const shdr_count = ehdr.e_shnum;
    const shdr_size = ehdr.e_shentsize;

    if (shdr_offset + @as(u64, shdr_count) * shdr_size > data.len) {
        return error.InvalidElf;
    }

    // get section name string table
    if (ehdr.e_shstrndx >= shdr_count) return error.InvalidElf;
    const shstrtab_shdr = getSectionHeader(data, ehdr, ehdr.e_shstrndx);
    const shstrtab = getSectionData(data, shstrtab_shdr);

    // first pass: find symtab and strtab
    var symtab_shdr: ?*const Elf64_Shdr = null;
    var strtab_data: ?[]const u8 = null;

    for (0..shdr_count) |i| {
        const shdr = getSectionHeader(data, ehdr, @intCast(i));
        if (shdr.sh_type == elf.SHT_SYMTAB) {
            symtab_shdr = shdr;
            // the strtab is linked via sh_link
            if (shdr.sh_link < shdr_count) {
                const linked = getSectionHeader(data, ehdr, @intCast(shdr.sh_link));
                strtab_data = getSectionData(data, linked);
            }
        }
    }

    // second pass: find programs, maps, and relocations
    for (0..shdr_count) |i| {
        const shdr = getSectionHeader(data, ehdr, @intCast(i));
        const sec_name = getSectionName(shstrtab, shdr.sh_name);

        if (shdr.sh_type == elf.SHT_PROGBITS and (shdr.sh_flags & elf.SHF_EXECINSTR) != 0) {
            // executable section = BPF program
            const sec_data = getSectionData(data, shdr);
            try programs.append(.{
                .name = sec_name,
                .insn_data = sec_data,
            });
        } else if (shdr.sh_type == elf.SHT_PROGBITS and std.mem.eql(u8, sec_name, "maps")) {
            // map definitions section
            try parseMaps(getSectionData(data, shdr), alloc, maps, symtab_shdr, strtab_data, data, ehdr, @intCast(i));
        } else if (shdr.sh_type == elf.SHT_REL) {
            // relocation section — find which program section it applies to
            const target_shdr = getSectionHeader(data, ehdr, @intCast(shdr.sh_info));
            if (target_shdr.sh_type == elf.SHT_PROGBITS and (target_shdr.sh_flags & elf.SHF_EXECINSTR) != 0) {
                try parseRelocs(getSectionData(data, shdr), alloc, relocs, symtab_shdr, strtab_data, data, ehdr);
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

fn parseMaps(
    section_data: []const u8,
    _: std.mem.Allocator,
    maps: *std.ArrayList(MapInfo),
    symtab_shdr: ?*const Elf64_Shdr,
    strtab_data: ?[]const u8,
    elf_data: []const u8,
    ehdr: *const Elf64_Ehdr,
    maps_section_idx: u16,
) !void {
    const map_def_size = @sizeOf(BpfMapDef);

    // each map is a BpfMapDef-sized entry in the maps section.
    // map names come from symbols pointing into this section.
    var offset: usize = 0;
    var map_idx: usize = 0;
    while (offset + map_def_size <= section_data.len) : ({
        offset += map_def_size;
        map_idx += 1;
    }) {
        const def: *const BpfMapDef = @ptrCast(@alignCast(&section_data[offset]));

        // find the symbol name for this map
        const name = findSymbolName(symtab_shdr, strtab_data, elf_data, ehdr, maps_section_idx, offset) orelse "unknown";

        try maps.append(.{
            .name = name,
            .map_type = def.type,
            .key_size = def.key_size,
            .value_size = def.value_size,
            .max_entries = def.max_entries,
        });
    }
}

fn findSymbolName(
    symtab_shdr: ?*const Elf64_Shdr,
    strtab_data: ?[]const u8,
    elf_data: []const u8,
    _: *const Elf64_Ehdr,
    section_idx: u16,
    offset: usize,
) ?[]const u8 {
    const shdr = symtab_shdr orelse return null;
    const strtab = strtab_data orelse return null;

    const sym_data = getSectionData(elf_data, shdr);
    const sym_size = @sizeOf(Elf64_Sym);
    const sym_count = sym_data.len / sym_size;

    for (0..sym_count) |i| {
        const sym: *const Elf64_Sym = @ptrCast(@alignCast(&sym_data[i * sym_size]));
        if (sym.st_shndx == section_idx and sym.st_value == offset) {
            return getSectionName(strtab, sym.st_name);
        }
    }

    return null;
}

fn parseRelocs(
    section_data: []const u8,
    _: std.mem.Allocator,
    relocs: *std.ArrayList(RelocInfo),
    symtab_shdr: ?*const Elf64_Shdr,
    strtab_data: ?[]const u8,
    elf_data: []const u8,
    _: *const Elf64_Ehdr,
) !void {
    const rel_size = @sizeOf(Elf64_Rel);
    const rel_count = section_data.len / rel_size;

    const shdr = symtab_shdr orelse return;
    const strtab = strtab_data orelse return;
    const sym_data = getSectionData(elf_data, shdr);
    const sym_entry_size = @sizeOf(Elf64_Sym);

    for (0..rel_count) |i| {
        const rel: *const Elf64_Rel = @ptrCast(@alignCast(&section_data[i * rel_size]));

        // only handle R_BPF_64_64 (map fd) relocations
        if (rel.typ() != R_BPF_64_64) continue;

        const sym_idx = rel.sym();
        if (@as(usize, sym_idx) * sym_entry_size >= sym_data.len) continue;

        const sym: *const Elf64_Sym = @ptrCast(@alignCast(&sym_data[sym_idx * sym_entry_size]));
        const sym_name = getSectionName(strtab, sym.st_name);

        // instruction index = byte offset / instruction size
        const insn_idx: u32 = @intCast(rel.r_offset / BPF_INSN_SIZE);

        try relocs.append(.{
            .insn_idx = insn_idx,
            .map_name = sym_name,
        });
    }
}

// -- code generation --

fn generateZig(
    writer: anytype,
    source_file: []const u8,
    maps: []const MapInfo,
    programs: []const ProgramInfo,
    relocs: []const RelocInfo,
) !void {
    // header comment
    try writer.print(
        \\// generated by tools/bpf_gen.zig from {s} — do not edit
        \\//
        \\// regenerate with:
        \\//   clang -target bpf -O2 -g -c -o <name>.o bpf/<name>.c
        \\//   zig run tools/bpf_gen.zig -- <name>.o src/network/bpf/<name>.zig
        \\
        \\const BPF = @import("std").os.linux.BPF;
        \\
        \\
    , .{source_file});

    // map definitions
    try writer.writeAll(
        \\pub const MapDef = struct {
        \\    name: []const u8,
        \\    map_type: u32,
        \\    key_size: u32,
        \\    value_size: u32,
        \\    max_entries: u32,
        \\};
        \\
        \\
    );

    try writer.print("pub const maps = [_]MapDef{{\n", .{});
    for (maps) |m| {
        try writer.print("    .{{ .name = \"{s}\", .map_type = {d}, .key_size = {d}, .value_size = {d}, .max_entries = {d} }},\n", .{
            m.name,
            m.map_type,
            m.key_size,
            m.value_size,
            m.max_entries,
        });
    }
    try writer.writeAll("};\n\n");

    // relocation info
    try writer.writeAll(
        \\pub const Reloc = struct {
        \\    insn_idx: u32,
        \\    map_idx: u32,
        \\};
        \\
        \\
    );

    try writer.print("pub const relocs = [_]Reloc{{\n", .{});
    for (relocs) |r| {
        // find the map index by name
        const map_idx = findMapIndex(maps, r.map_name);
        try writer.print("    .{{ .insn_idx = {d}, .map_idx = {d} }},\n", .{
            r.insn_idx,
            map_idx,
        });
    }
    try writer.writeAll("};\n\n");

    // program instructions — use the first program section
    if (programs.len > 0) {
        const prog = programs[0];
        try writer.print("/// BPF program section: \"{s}\"\n", .{prog.name});
        try writer.print("pub const prog_name = \"{s}\";\n\n", .{prog.name});

        const insn_count = prog.insn_data.len / BPF_INSN_SIZE;
        try writer.print("pub const insns = [_]BPF.Insn{{\n", .{});

        for (0..insn_count) |i| {
            const off = i * BPF_INSN_SIZE;
            const code = prog.insn_data[off];
            const regs = prog.insn_data[off + 1];
            const dst: u4 = @truncate(regs);
            const src: u4 = @truncate(regs >> 4);
            const off_val = std.mem.readInt(i16, prog.insn_data[off + 2 ..][0..2], .little);
            const imm = std.mem.readInt(i32, prog.insn_data[off + 4 ..][0..4], .little);

            try writer.print("    .{{ .code = 0x{x:0>2}, .dst = {d}, .src = {d}, .off = {d}, .imm = {d} }},\n", .{
                code,
                dst,
                src,
                off_val,
                imm,
            });
        }
        try writer.writeAll("};\n");
    }
}

fn findMapIndex(maps: []const MapInfo, name: []const u8) u32 {
    for (maps, 0..) |m, i| {
        if (std.mem.eql(u8, m.name, name)) return @intCast(i);
    }
    return 0; // fallback — shouldn't happen with valid ELF
}
