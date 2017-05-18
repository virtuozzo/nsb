'''
Copyright (c) 2016-2017, Parallels International GmbH

Our contact details: Parallels International GmbH, Vordergasse 59, 8200
Schaffhausen, Switzerland.
'''

from collections import defaultdict
from weakref import WeakKeyDictionary

from elftools.elf import enums
from elftools.elf import descriptions

import debuginfo
from consts import *

set_const_str(enums.ENUM_SH_TYPE)
set_const_str(enums.ENUM_ST_SHNDX)
set_const_raw(enums.ENUM_RELOC_TYPE_x64)
set_const_str(descriptions._DESCR_ST_INFO_BIND)
set_const_str(descriptions._DESCR_ST_INFO_TYPE)

INT_TYPES = (int, long)

RELOC_SIZES = {
	RAW.R_X86_64_PC32:		4,
	RAW.R_X86_64_PC64:		8,
	RAW.R_X86_64_GOTOFF64:		8,
	RAW.R_X86_64_PLT32:		4,
	RAW.R_X86_64_GOTPCREL:		4,
}
RELOC_PIC_TYPES = [
	RAW.R_X86_64_PC32,
	RAW.R_X86_64_PC64,
	RAW.R_X86_64_GOTOFF64,
]

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

get_debug_info = debuginfo.memoize(WeakKeyDictionary)(debuginfo.DebugInfo)

class SymTab(object):
	def __init__(self, elf):
		self.elf = elf
		self.sec = elf.get_section_by_name('.symtab')
		if not self.sec:
			raise Exception("No symbol table")
		self._masked_addrs = set()

		# Symbols can be:
		# 1. visible only within file
		# 2. visible outside file, interposable
		# 3. visible outside file, non-interposable
		# Here we want to mask types 1,2
		dyn_symtab = elf.get_section_by_name('.dynsym')
		for dio in get_debug_info(elf).iter_dios():
			if dio.tag != STR.DW_TAG_variable:
				continue

			# skip variables not in file scope
			if dio.get_parent().tag != STR.DW_TAG_compile_unit:
				continue

			# skip non-defining declarations
			if STR.DW_AT_declaration in dio.attributes:
				continue

			# Symbol is visible outside file
			if STR.DW_AT_external in dio.attributes:
				sym_name = dio.attributes[STR.DW_AT_name].value
				dym_sym_list = dyn_symtab.get_symbol_by_name(sym_name)
				assert dym_sym_list is None or len(dym_sym_list) == 1

				if dym_sym_list:
					dyn_sym = dym_sym_list[0]
					visibility = dyn_sym.entry.st_other.visibility
				else:
					# STV_HIDDEN or STV_INTERNAL visibility
					visibility = None

				# Symbol is non-interposable
				if visibility in [None, STR.STV_PROTECTED]:
					continue 

			self._masked_addrs.add(dio.get_addr())

		sym_types = [STR.STT_OBJECT, STR.STT_FUNC]
		self.module_sym_names = set(sym.name for sym in self.sec.iter_symbols() if
				sym.entry.st_shndx != STR.SHN_UNDEF and
				sym.entry.st_info.type in sym_types and
				sym.entry.st_value not in self._masked_addrs)
	
	def get_sym(self, name):
		sym_list = [sym for sym in self.sec.get_symbol_by_name(name)
				if sym.entry.st_value not in self._masked_addrs]
		if len(sym_list) != 1:
			raise Exception("Found {} symbols with name {}".format(
				len(sym_list), name))
		return sym_list[0]

def should_resolve(sec):
	if sec.name.startswith(".rodata"):
		return False
	if sec.name.startswith(".text"):
		return False
	return True

class ObjectFile(object):
	def __init__(self, elf):
		self.elf = elf
		self.di = debuginfo.DebugInfo(elf)
		self.di_reloc = DebugInfoReloc(elf)

	# It is supposed that object files are compiled with options
	# -fdata-sections -ffunction-sections
	# so that each text/data section contains single object.
	# This way, we can lookup: 
	# section => relocations for .debug_info that refer this section 
	# => DIEs that are patched by this relocations.
	# From that DIEs, we derive key which uniquely identifies object.
	@debuginfo.memoize(WeakKeyDictionary, dict)
	def get_di_key(self, sec_idx):
		di_offsets = self.di_reloc.get_offsets(sec_idx)
		di_keys = [self.di.get_dio_by_pos(offset).get_key() for offset in di_offsets]
		di_key_set = set(filter(None, di_keys))
		if len(di_key_set) != 1:
			for offs, key in zip(di_offsets, di_keys):
				print "   0x{:<4x} {}".format(offs, key)
			raise Exception("Got {} DIE keys for section {}".format(len(di_keys), sec_idx))
		return di_key_set.pop()

	def get_relocs(self):
		elf = self.elf
		di_reloc = self.di_reloc
		symtab = di_reloc.symtab
		get_di_key = self.get_di_key
		result = {}

		def append_rel():
			reloc_list.append((rel_type, rel.entry.r_offset, key))

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
			reloc_list = []
			result[func_di_key] = (text_sec, reloc_list)

			for rel in sec.iter_relocations():
				rel_type = rel.entry.r_info_type
				rel_size = RELOC_SIZES[rel_type]

				sym = symtab.get_symbol(rel.entry.r_info_sym)
				sym_bind = sym.entry.st_info.bind
				target_sec_idx = sym.entry.st_shndx
				target_sec = elf.get_section(target_sec_idx) \
					 if isinstance(target_sec_idx, INT_TYPES) else None
				target_sec_name = target_sec.name if target_sec else target_sec_idx

				if sym_bind == STR.STB_GLOBAL:
					key = key_repr = sym.name
				elif sym_bind == STR.STB_LOCAL:
					if not should_resolve(target_sec):
						key = None
						append_rel()
						continue

					key = get_di_key(target_sec_idx)
					key_repr = debuginfo.format_di_key(key)
				else:
					assert 0

				append_rel()
				print "  +{:<5d} {:40s} {}".format(rel.entry.r_offset,
						target_sec_name, key_repr)

		return result

def resolve(old_elf, new_elf, obj_seq):
	obj_seq = list(obj_seq)
	get_symtab = debuginfo.memoize(dict)(SymTab)

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

	new_text_sec = new_elf.get_section_by_name('.text')

	def read(sec, addr, size):
		stream = sec.stream
		pos = addr - sec.header.sh_addr + sec.header.sh_offset 

		stream.seek(pos)
		data = stream.read(size)
		assert len(data) == size
		return data
	
	def read_num(sec, addr, size):
		data = read(sec, addr, size)

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

	def get_addr(elf, key):
		if isinstance(key, basestring):
			symtab = get_symtab(elf)
			sym = symtab.get_sym(key)
			return sym.entry.st_value
		else:
			di = get_debug_info(elf)
			return di.get_dio_by_key(key).get_addr()

	def cmp_func():
		func_new_size = func_new_dio.get_size()
		func_obj_size = func_obj_dio.get_size()

		if func_new_size != func_obj_size:
			raise Exception("Function {} size mismatch".format(func_new_dio))
		func_size = func_new_size

		reloc_map = {}
		for rel_type, rel_offset, key in relocs:
			reloc_map[rel_offset] = RELOC_SIZES[rel_type]
		assert len(reloc_map) == len(relocs)

		func_new_code = read(new_text_sec, func_new_addr, func_size)
		func_obj_code = read(obj_text_sec, func_obj_addr, func_size)

		next_offset = 0
		for offset, (x_new, x_obj) in enumerate(zip(func_new_code, func_obj_code)):
			skip = reloc_map.get(offset)
			if skip:
				next_offset = offset + skip
			if offset < next_offset:
				continue

			if x_new != x_obj:
				raise Exception("Code mismatch for function {} at offset {}".format(
					debuginfo.format_di_key(func_di_key), offset))


	result = []
	modulo = 1 << 64
	format_key = lambda: key if isinstance(key, basestring) else debuginfo.format_di_key(key)
	for obj in obj_seq:
		obj_di = get_debug_info(obj)
		for func_di_key, (obj_text_sec, relocs) in ObjectFile(obj).get_relocs().iteritems():
			func_new_dio = new_elf_di.get_dio_by_key(func_di_key)
			func_obj_dio = obj_di.get_dio_by_key(func_di_key)

			func_new_addr = func_new_dio.get_addr()
			func_obj_addr = func_obj_dio.get_addr()

			cmp_func()

			for rel_type, rel_offset, key in relocs:
				if rel_type not in RELOC_PIC_TYPES:
					continue
				if key is None:
					continue

				patch_address = func_new_addr + rel_offset

				old_addr = get_addr(old_elf, key)
				if not old_addr:
					print "!! {} is absent in old ELF".format(format_key())
					continue

				rel_size = RELOC_SIZES[rel_type]
				rel_value = read_num(new_text_sec, patch_address, rel_size)
				if rel_size < 8:
					rel_value = sign_extend(rel_value, 8*rel_size, 64)

				new_addr = get_addr(new_elf, key)
				# Emulate arithmetic modulo 2**64
				# To get final address, one should subtract base load address of new ELF, and
				# add base load address of old ELF  (zero for executables).  This calculation
				# should also be made with modulo arithmetic. Then, for small relocation size
				# one should verify that truncated value sign-extends to the full value.
				target_value = (rel_value + old_addr - new_addr) % modulo

				result.append((rel_size, patch_address, target_value))

	return result


	
