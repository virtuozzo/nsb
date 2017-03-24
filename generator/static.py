from collections import defaultdict

from elftools.elf import enums

import debuginfo
from consts import *

set_const_str(enums.ENUM_SH_TYPE)
set_const_raw(enums.ENUM_RELOC_TYPE_x64)

class DebugInfoReloc(object):
	def __init__(self, elf):
		self.elf = elf
		self._sec_idx2offset = mapping = defaultdict(list)

		sec_name = '.rela.debug_info'
		self.sec = sec = elf.get_section_by_name(sec_name)
		if not sec:
			raise Exception("No {0} section".format(sec_name))

		self.sym_sec_idx = sec.header.sh_link
		self.symtab = symtab = elf.get_section(self.sym_sec_idx)
		if not symtab:
			raise Exception("No symbol table")

		for rel in sec.iter_relocations():
			sym = symtab.get_symbol(rel.entry.r_info_sym)
			mapping[sym.entry.st_shndx].append(rel.entry.r_offset)

	def get_offsets(self, sec_idx):
		return self._sec_idx2offset[sec_idx]

def should_resolve(sec):
	if sec.name == ".rodata":
		return False
	if sec.name.startswith(".text"):
		return False
	return True

def process_obj(elf):
	di = debuginfo.get_debug_info(elf)
	di_reloc = DebugInfoReloc(elf)
	symtab = di_reloc.symtab

	# It is supposed that object files are compiled with options
	# -fdata-sections -ffunction-sections
	# so that each text/data section contains single object.
	# This way, we can lookup: 
	# section => relocations for .debug_info that refer this section 
	# => DIEs that are patched by this relocations.
	# From that DIEs, we derive key which uniquely identifies object.
	@debuginfo.memoize(dict)
	def get_di_key(sec_idx):
		di_offsets = di_reloc.get_offsets(sec_idx)
		di_keys = set(map(di.get_key, di_offsets))
		if len(di_keys) != 1:
			for k in di_keys:
				print "     ", debuginfo.format_di_key(k)
			raise Exception("Got {} DIE keys for section {}".format(len(di_keys), sec_idx))
		return di_keys.pop()

	result = defaultdict(list)
	rel_type2size = {
		RAW.R_X86_64_PC32:		4,
		RAW.R_X86_64_PC64:		8,
		RAW.R_X86_64_GOTOFF64:		8,
	}
	for sec in elf.iter_sections():
		if not sec.name.startswith('.rela.text'):
			continue
		if sec.header.sh_link != di_reloc.sym_sec_idx:
			raise Exception("Symbol table mismatch")

		print "== Processing", sec.name,
		text_sec_idx = sec.header.sh_info
		text_sec = elf.get_section(text_sec_idx)
		print "=>", text_sec.name

		func_di_key = get_di_key(text_sec_idx)
		for rel in sec.iter_relocations():
			rel_size = rel_type2size.get(rel.entry.r_info_type)
			if rel_size is None:
				continue

			target_sec_idx = symtab.get_symbol(rel.entry.r_info_sym).entry.st_shndx
			target_sec = elf.get_section(target_sec_idx)
			if not should_resolve(target_sec):
				continue

			di_key = get_di_key(target_sec_idx)
			result[func_di_key].append((rel_size, rel.entry.r_offset, di_key))
			print "  +{:<5x} {:40s} {}".format(rel.entry.r_offset,
				target_sec.name, debuginfo.format_di_key(di_key))

	return result
