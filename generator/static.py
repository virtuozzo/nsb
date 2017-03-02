from __future__ import print_function

import sys
import re
from elftools.elf import elffile

import debuginfo

ELF64_R_INFO = lambda s, t: (s << 32) | t

PREFIX = 'vzpatch'
prefix_re = re.compile(r'^{0}_(\d+_)*'.format(PREFIX))

old_file   = sys.argv[1]
patch_file = sys.argv[2]

p_elf = elffile.ELFFile(open(patch_file, 'r+'))
o_elf = elffile.ELFFile(open(old_file))

def is_mangled(n):
	return n.startswith(PREFIX)

def demangle(n):
	return prefix_re.sub('', n)

def reverse_mapping(d):
	result = dict((v,k) for k, v in d.iteritems())
	assert len(result) == len(d)
	return result

relocations_dyn = p_elf.get_section_by_name('.rela.dyn')
assert relocations_dyn.header.sh_type == 'SHT_RELA'

rel2sym_idx = dict()
rel_ent_size = relocations_dyn.header.sh_entsize
assert rel_ent_size
rel_sect_pos = relocations_dyn.header.sh_offset

for rel_idx, rel in enumerate(relocations_dyn.iter_relocations()):
	sym_idx = rel.entry.r_info_sym
	if not sym_idx:
		continue

	rel_pos = rel_sect_pos + rel_idx * rel_ent_size
	rel2sym_idx[(rel_pos, rel)] = sym_idx

sym_idx2rel = reverse_mapping(rel2sym_idx)

sym_info  = list()
sym_names = set()
symtab = p_elf.get_section_by_name('.dynsym')

print("== Searching symbols to process")
for sym_idx, sym in enumerate(symtab.iter_symbols()):
	if not is_mangled(sym.name):
		continue

	name = sym.name
	addr = sym.entry.st_value
	print("{0:<4d} {1:<30s} {2:016x}".format(sym_idx, name, addr))

	orig_name = demangle(name)
	sym_info.append((sym_idx, orig_name, addr))
	sym_names.add(orig_name)

print("== Reading debuginfo for {0}".format(old_file))
o_di2addr = debuginfo.read(o_elf, sym_names)

print("== Reading debuginfo for {0}".format(patch_file))
p_di2addr = debuginfo.read(p_elf, sym_names,
		lambda n: demangle(n) if is_mangled(n) else n)

p_addr2di = reverse_mapping(p_di2addr)

processed_rels = list()

print("== Resolving addresses in old ELF")
for sym_idx, sym, p_addr in sym_info:
	o_addr = o_di2addr[p_addr2di[p_addr]]
	rel_pos, rel = rel_info = sym_idx2rel[sym_idx]
	processed_rels.append(rel_info)

	print("{0:<4d} {1:30s} {2:016x} @ {3:016x}".format(
		sym_idx, sym, o_addr, rel.entry.r_offset))

# Set R_X86_64_NONE type for processed relocations
for rel_pos, rel in processed_rels:
	p_elf.stream.seek(rel_pos)
	rel.entry.r_info = ELF64_R_INFO(rel.entry.r_info_sym, 0)
	p_elf.structs.Elf_Rela.build_stream(rel.entry, p_elf.stream)

