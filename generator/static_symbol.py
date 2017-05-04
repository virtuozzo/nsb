'''
Copyright (c) 2016-2017, Parallels International GmbH

Our contact details: Parallels International GmbH, Vordergasse 59, 8200
Schaffhausen, Switzerland.
'''

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
	if sec.name.startswith(".rodata"):
		return False
	if sec.name.startswith(".text"):
		return False
	return True

def process_obj(elf, di=None):
	di = di or debuginfo.DebugInfo(elf)
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
		di_keys = [di.get_dio_by_pos(offset).get_key() for offset in di_offsets]
		di_key_set = set(filter(None, di_keys))
		if len(di_key_set) != 1:
			for offs, key in zip(di_offsets, di_keys):
				print "   0x{:<4x} {}".format(offs, key)
			raise Exception("Got {} DIE keys for section {}".format(len(di_keys), sec_idx))
		return di_key_set.pop()

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
			print "  +{:<5d} {:40s} {}".format(rel.entry.r_offset,
				target_sec.name, debuginfo.format_di_key(di_key))

	return result

def resolve(old_elf, new_elf, obj_seq):
	get_debug_info = debuginfo.memoize(dict)(debuginfo.DebugInfo)

	old_elf_di = get_debug_info(old_elf)
	old_elf_cus = set(old_elf_di.get_cu_names())

	new_elf_di = get_debug_info(new_elf)
	new_elf_cus = set(new_elf_di.get_cu_names())

	if not (new_elf_cus <= old_elf_cus):
		print "NEW CUs", " ".join(new_elf_cus)
		print "OLD CUs", " ".join(old_elf_cus)
		raise Exception("CU mismatch")

	obj_cus = set()
	for obj in obj_seq:
		obj_di = get_debug_info(obj)
		obj_cus.update(obj_di.get_cu_names())

	if new_elf_cus != obj_cus:
		print "NEW CUs", " ".join(new_elf_cus)
		print "OBJ CUs", " ".join(obj_cus)
		raise Exception("CU mismatch")

	text_sec = new_elf.get_section_by_name('.text')
	file_offset = text_sec.header.sh_offset - text_sec.header.sh_addr
	stream = new_elf.stream

	def read(pos, size):
		stream.seek(pos)
		data = stream.read(size)
		assert len(data) == size

		result = 0
		shift = 0
		for b in data:
			result += ord(b) << shift
			shift += 8
		return result

	def sign_extend(n, low_bits, high_bits):
		low_sign = 1 << (low_bits - 1)
		low_lim  = low_sign << 1
		high_lim = 1 << high_bits
		assert 0 <= n < low_lim
		sign = n & low_sign
		return n + high_lim - low_lim if sign else n

	result = []
	modulo = 1 << 64
	for obj in obj_seq:
		for func_di_key, relocs in process_obj(obj, get_debug_info(obj)).iteritems():
			func_addr = new_elf_di.get_dio_by_key(func_di_key).get_addr()
			for rel_size, rel_offset, di_key in relocs:
				patch_address = func_addr + rel_offset

				old_addr = old_elf_di.get_addr(di_key)
				if not old_addr:
					print "!! {} is absent in old ELF".format(debuginfo.format_di_key(di_key))
					continue

				rel_value = read(patch_address + file_offset, rel_size)
				if rel_size < 8:
					rel_value = sign_extend(rel_value, 8*rel_size, 64)

				new_addr = new_elf_di.get_addr(di_key)
				# Emulate arithmetic modulo 2**64
				# To get final address, one should subtract base load address of new ELF, and
				# add base load address of old ELF  (zero for executables).  This calculation
				# should also be made with modulo arithmetic. Then, for small relocation size
				# one should verify that truncated value sign-extends to the full value.
				target_value = (rel_value + old_addr - new_addr) % modulo

				result.append((rel_size, patch_address, target_value))

	return result


	
