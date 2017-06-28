from __future__ import print_function

import bisect
import itertools

from elftools.elf import enums as elf_enums
from elftools.dwarf import enums as dwarf_enums

from consts import *
import debuginfo
from util import reverse_mapping

set_const_str(elf_enums.ENUM_ST_INFO_TYPE)
set_const_str(elf_enums.ENUM_ST_SHNDX)
set_const_str(elf_enums.ENUM_ST_INFO_BIND)
set_const_str(elf_enums.ENUM_ST_VISIBILITY)
set_const_str(dwarf_enums.ENUM_DW_TAG)
set_const_str(dwarf_enums.ENUM_DW_AT)

IGNORED_SYMS = set([
	"completed.6344",
])

SYM_DEF			= 1
SYM_REF			= 2

ELF_TAB_REG		= 1
ELF_TAB_DYN		= 2

class Symbol(object):
	kind = None

	def __init__(self, parent, elf_sym, visibility, filename, line):
		assert parent is None or isinstance(parent, Symbol)
		self.parent = parent

		assert (
			(self.kind == SYM_REF and elf_sym.tab == ELF_TAB_DYN) or
			(self.kind == SYM_DEF and elf_sym.tab == ELF_TAB_REG and
				elf_sym.entry.st_info.type == STR.STT_FUNC))
		self.elf_sym = elf_sym
		self.name = self.target_name = elf_sym.name

		assert visibility in [VIS_EXTERNAL, VIS_STATIC,
				VIS_INTERNAL, VIS_HIDDEN, VIS_PROTECTED]
		self.visibility  = visibility

		assert filename is None or isinstance(filename, basestring)
		assert line is None or isinstance(line, (int, long)) and line > 0
		assert (filename is None) == (line is None)
		self.filename = filename
		self.line = line

	def __str__(self):
		vis = {
			VIS_EXTERNAL:		'E',
			VIS_STATIC:		'S',
			VIS_INTERNAL:		'I',
			VIS_HIDDEN:		'H',
			VIS_PROTECTED:		'P',
		}[self.visibility]

		kind = {
			SYM_REF:	"SYM_REF",
			SYM_DEF:	"SYM_DEF",
		}[self.kind]

		loc = "@{}:{}".format(self.filename, self.line) if self.filename else ""
		return "{}<{}:{}{}>".format(kind, vis, self.name, loc)

	__repr__ = __str__

class StaticSymbol(Symbol):
	def __init__(self, parent, elf_sym, filename, line):
		assert filename
		assert line
		Symbol.__init__(self, parent, elf_sym, VIS_STATIC, filename, line)

		# If None, these attrs will be set again when resolving file scopes
		self.target_filename = None
		self.target_name = None

class StaticSymbolRef(StaticSymbol):
	kind = SYM_REF

	def __init__(self, parent, elf_sym, filename, line, target_filename):
		StaticSymbol.__init__(self, parent, elf_sym, filename, line)

		assert target_filename is None or isinstance(target_filename, basestring)
		self.target_filename = target_filename

class StaticSymbolDef(StaticSymbol):
	kind = SYM_DEF

class ExternalSymbol(Symbol):
	def __init__(self, parent, elf_sym, filename, line):
		Symbol.__init__(self, parent, elf_sym, VIS_EXTERNAL, filename, line)

class ExternalSymbolRef(ExternalSymbol):
	kind = SYM_REF

class ExternalSymbolDef(ExternalSymbol):
	kind = SYM_DEF

class InternalSymbol(Symbol):
	def __init__(self, parent, elf_sym, filename, line):
		Symbol.__init__(self, parent, elf_sym, VIS_INTERNAL, filename, line)

class InternalSymbolRef(InternalSymbol):
	kind = SYM_REF

class InternalSymbolDef(InternalSymbol):
	kind = SYM_DEF

class HiddenSymbol(Symbol):
	def __init__(self, parent, elf_sym, filename, line):
		Symbol.__init__(self, parent, elf_sym, VIS_HIDDEN, filename, line)

class HiddenSymbolRef(HiddenSymbol):
	kind = SYM_REF

class HiddenSymbolDef(HiddenSymbol):
	kind = SYM_DEF

class ProtectedSymbol(Symbol):
	def __init__(self, parent, elf_sym, filename, line):
		Symbol.__init__(self, parent, elf_sym, VIS_PROTECTED, filename, line)

class ProtectedSymbolRef(ProtectedSymbol):
	kind = SYM_REF

class ProtectedSymbolDef(ProtectedSymbol):
	kind = SYM_DEF

def get_symbol(kind, visibility, **kw):
	cl_map = {
		(VIS_STATIC,		SYM_REF):	StaticSymbolRef,
		(VIS_STATIC,		SYM_DEF):	StaticSymbolDef,

		(VIS_EXTERNAL,		SYM_REF):	ExternalSymbolRef,
		(VIS_EXTERNAL,		SYM_DEF):	ExternalSymbolDef,

		(VIS_INTERNAL,		SYM_REF):	InternalSymbolRef,
		(VIS_INTERNAL,		SYM_DEF):	InternalSymbolDef,

		(VIS_HIDDEN,		SYM_REF):	HiddenSymbolRef,
		(VIS_HIDDEN,		SYM_DEF):	HiddenSymbolDef,

		(VIS_PROTECTED,		SYM_REF):	ProtectedSymbolRef,
		(VIS_PROTECTED,		SYM_DEF):	ProtectedSymbolDef,
	}
	cl = cl_map[(visibility, kind)]
	return cl(**kw)

def read_patch(elf):
	di = debuginfo.get_debug_info(elf)

	st = elf.get_section_by_name(".symtab")
	null_sym = st.get_symbol(0)
	assert not hasattr(null_sym, "idx")
	assert not hasattr(null_sym, "tab")

	sec_name2idx = reverse_mapping(dict((n, sec.name)
		for n, sec in enumerate(elf.iter_sections()) ))
	vzp_sec_idx = sec_name2idx[META_SECTION]

	undef_sym_names = set()
	def_sym_types = [STR.STT_OBJECT, STR.STT_FUNC]
	def_elf_addr2sym = {}
	def_sym_names = []

	# islice() here to skip symbol zero
	for elf_sym_idx, elf_sym in itertools.islice(
			enumerate(st.iter_symbols()), 1, None):
		elf_sym.tab = ELF_TAB_REG
		elf_sym.idx = elf_sym_idx

		if elf_sym.entry.st_info.bind == STR.STB_WEAK:
			continue
		if elf_sym.name in IGNORED_SYMS:
			continue

		if elf_sym.entry.st_shndx == STR.SHN_UNDEF:
			assert elf_sym.name not in undef_sym_names
			undef_sym_names.add(elf_sym.name)
			continue

		if not elf_sym.entry.st_size:
			continue
		if elf_sym.entry.st_info.type not in def_sym_types:
			continue

		addr = elf_sym.entry.st_value
		assert addr not in def_elf_addr2sym
		def_elf_addr2sym[addr] = elf_sym

		def_sym_names.append(elf_sym.name)

	dyn_st = elf.get_section_by_name(".dynsym")
	dyn_sym_name2idx = reverse_mapping(dict((i, s.name)
		for i, s in enumerate(dyn_st.iter_symbols())
			if s.entry.st_shndx == STR.SHN_UNDEF ))

	def get_dyn_elf_sym(name):
		idx = dyn_sym_name2idx.get(name)
		if idx is None:
			raise Exception("Symbol '{}' is not found".format(name))

		s = dyn_st.get_symbol(idx)
		s.tab = ELF_TAB_DYN
		s.idx = idx
		return s

	def_sym_names.sort()
	def is_prefix(n):
		# check whether 'n' is prefix of some symbol name
		idx = bisect.bisect_left(def_sym_names, n)
		return idx < len(def_sym_names) and def_sym_names[idx].startswith(n)

	symbols = []
	meta = []

	sym_ref_name2vis = {}
	def verify_vis(md):
		vis = sym_ref_name2vis.get(md.symbol)
		if vis is None:
			sym_ref_name2vis[md.symbol] = md.visibility
			return

		if vis != md.visibility:
			raise Exception("Visibility mismatch for '{}' at "
				"{}:{}".format(md.symbol, filename, line))

		if vis not in [VIS_INTERNAL, VIS_HIDDEN, VIS_PROTECTED]:
			raise Exception("Symbol reference is redefined at "
				"{}:{}".format(filename, line))

	def handle_meta(md):
		assert filename == md.header.filename
		assert line == md.header.line

		if md.header.tag == META_TAG_FILE and dio.get_parent().tag != STR.DW_TAG_compile_unit:
			raise Exception("VZP_FILE at {}:{} should be "
					"at top level ".format(filename, line))
		meta.append(md)

		if md.header.tag != META_TAG_SYMBOL:
			return

		verify_vis(md)

		if md.symbol not in undef_sym_names:
			print("!! symbol '{}' is unused".format(md.symbol))
			return

		undef_sym_names.remove(md.symbol)
		symbols.append(get_symbol(SYM_REF, md.visibility,
			parent=parent_sym, elf_sym=get_dyn_elf_sym(md.symbol),
			filename=filename, line=line,
				**(dict(target_filename=md.target_filename)
					if md.visibility == VIS_STATIC else {}) ))

	def get_visibility():
		if sym_vis == STR.STV_PROTECTED:
			return VIS_PROTECTED
		elif sym_vis == STR.STV_HIDDEN:
			return VIS_HIDDEN
		elif sym_vis == STR.STV_INTERNAL:
			return VIS_INTERNAL
		elif sym_vis == STR.STV_DEFAULT:
			pass
		else:
			raise Exception("Unknown symbol visibility: {}".format(sym_vis))

		# STV_DEFAULT
		if sym_bind == STR.STB_GLOBAL:
			return VIS_EXTERNAL
		elif sym_bind == STR.STB_LOCAL:
			pass
		else:
			raise Exception("Unknown symbol binding: {}".format(sym_bind))

		# STB_LOCAL and STV_DEFAULT case.
		# In shared libraries, symbols declared as HIDDEN/INTERNAL in
		# source are listed as STB_LOCAL and STV_DEFAULT in ELF symbol
		# table,  the same as for static variables.  Use debuginfo to
		# disambiguate.  Note that HIDDEN/INTERNAL is really the same,
		# and we can't distinguish between them.
		cu_external = STR.DW_AT_external in dio.attributes
		return VIS_HIDDEN if cu_external else VIS_STATIC

	# Walk over debuginfo entries and match them with defined symbols
	die_pos_stack = [debuginfo.DI_ROOT]
	die_pos_map = {}
	for dio in di.iter_dios():
		del die_pos_stack[die_pos_stack.index(dio.parent_die_pos) + 1:]
		die_pos_stack.append(dio.die_pos)

		if dio.tag not in [STR.DW_TAG_subprogram, STR.DW_TAG_variable]:
			continue

		# Avoid spurious warnings when object address cannot be
		# determined from debuginfo (local variables, for example).
		if not is_prefix(dio.get_name()):
			continue

		addr = dio.get_addr()
		if addr is None:
			continue

		elf_sym = def_elf_addr2sym.pop(addr)

		sym_name = elf_sym.name
		sym_sec_idx = elf_sym.entry.st_shndx 
		if sym_sec_idx != vzp_sec_idx and sym_name != dio.get_name():
			raise Exception("Symbol name '{}' is mangled".format(sym_name))

		sym_type = elf_sym.entry.st_info.type 
		sym_bind = elf_sym.entry.st_info.bind
		sym_vis = elf_sym.entry.st_other.visibility

		filename, line = dio.get_src_location()
		# Only functions may be defined in patch
		if sym_type == STR.STT_OBJECT and sym_sec_idx != vzp_sec_idx:
			raise Exception("Data symbol '{}' is defined in patch at "
				"{}:{}".format(sym_name, filename, line))

		cu_filename = debuginfo.get_CU_name(dio.die.cu)
		# We don't allow any objects to be defined in included files
		if filename != cu_filename:
			raise Exception("Symbol '{}' is defined outside main file, "
				"in {}:{}".format(sym_name, filename, line))

		for parent_die_pos in reversed(die_pos_stack):
			parent_sym = die_pos_map.get(parent_die_pos)
			if parent_sym:
				break
		else:
			parent_sym = None

		if sym_sec_idx == vzp_sec_idx:
			handle_meta(dio.get_value())
		else:
			sym = get_symbol(SYM_DEF, get_visibility(),
				parent=parent_sym, elf_sym=elf_sym,
				filename=filename, line=line)
			symbols.append(sym)
			die_pos_map[dio.die_pos] = sym

	if def_elf_addr2sym:
		print("!! Unmatched symbols:\n",
			" \n".join("  '{}'".format(s.name)
				for s in def_elf_addr2sym.itervalues() ))
		raise Exception("Can't match symtab entries with debuginfo objects")

	symbols.extend(get_symbol(SYM_REF, VIS_EXTERNAL,
			parent=None, elf_sym=get_dyn_elf_sym(name),
			filename=None, line=None)
				for name in undef_sym_names)

	return symbols

