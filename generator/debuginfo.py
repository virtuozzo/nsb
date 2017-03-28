from __future__ import print_function

import array
import bisect
from elftools.dwarf import enums, dwarf_expr
from elftools.dwarf.die import DIE

from consts import *

set_const_str(enums.ENUM_DW_TAG)
set_const_str(enums.ENUM_DW_AT)
set_const_str(enums.ENUM_DW_FORM)
set_const_str(dwarf_expr.DW_OP_name2opcode)

def format_di_key(di_key):
	suffix_map = {
		STR.DW_TAG_compile_unit:	'::',
		STR.DW_TAG_subprogram:		'()::',
		STR.DW_TAG_variable:		'',
	}
	get_suffix = lambda tag: suffix_map.get(tag, '??')
	return ''.join(name + get_suffix(tag) for name, tag in di_key)

class ExprVisitor(dwarf_expr.GenericExprVisitor):
	def __init__(self, structs):
		super(ExprVisitor, self).__init__(structs)
		self.__value = None

	def _after_visit(self, opcode, opcode_name, args):
		if opcode_name != STR.DW_OP_addr:
			raise Exception("Unsupported opcode {0}".format(opcode_name))

		self.__value = args[0]

	def get_addr(self, expr):
		self.process_expr(expr)
		return self.__value

def get_die_name(die):
	attr = die.attributes[STR.DW_AT_name]
	assert attr.form in [STR.DW_FORM_string, STR.DW_FORM_strp], attr.form
	return attr.value

def get_die_key(die):
	if die.tag not in [STR.DW_TAG_subprogram, STR.DW_TAG_variable]:
		return

	skip_attrs = [
		STR.DW_AT_abstract_origin,
		STR.DW_AT_declaration,
		STR.DW_AT_artificial,
	]
	if set(die.attributes).intersection(skip_attrs):
		return

	result = []
	while die:
		if die.tag == STR.DW_TAG_lexical_block:
			return
		sym_name = get_die_name(die)
		result.append((sym_name, die.tag))
		die = die.get_parent()

	result.reverse()
	return tuple(result)

def get_die_addr(die):
	structs = die.cu.structs

	if die.tag == STR.DW_TAG_subprogram:
		if STR.DW_AT_entry_pc in die.attributes:
			raise Exception("DW_AT_entry_pc is not supported")

		attr = die.attributes[STR.DW_AT_low_pc]
		assert attr.form == STR.DW_FORM_addr, attr.form
		return attr.value

	elif die.tag == STR.DW_TAG_variable:
		attr = die.attributes[STR.DW_AT_location]
		assert attr.form == STR.DW_FORM_exprloc, attr.form

		expr_visitor = ExprVisitor(structs)
		return expr_visitor.get_addr(attr.value)

	else:
		assert 0

class DebugInfo(object):
	def __init__(self, elf):
		self.elf = elf
		self._cu_pos  = cu_pos  = []

		def walk(die):
			assert die_pos[-1] < die.offset
			die_pos.append(die.offset)

			for child_die in die.iter_children():
				walk(child_die)

		if not self.elf.has_dwarf_info():
			raise Exception("No debuginfo in ELF")
		dwi = self.elf.get_dwarf_info()

		for cu in dwi.iter_CUs():
			die_pos = array.array('l', [-1])
			cu_pos.append((-cu.cu_offset, cu, die_pos))
			walk(cu.get_top_DIE())

		cu_pos.append((1, None, None))
		cu_pos.sort()

	def lookup_die(self, pos):
		assert pos >= 0
		# Consider sorted array A  having no duplicate elements
		# [..., X, Y, ...], where X < Y, and some element P
		# If X < P < Y then bisect_left(P) == bisect_right(P) == index(Y)
		# as described at https://docs.python.org/2/library/bisect.html
		# IOW, bisection selects right end of the range. Finally, when
		# P is same as Y, these functions return different results:
		# bisect_left(P)  == index(Y)
		# bisect_right(P) == index(Y) + 1
		# So we use A[bisect_right(pos) - 1] to lookup DIEs.
		# When looking up CUs, situation is a bit different, since we store
		# 3-tuples in the array. To make comparisons possible, we should use 1-tuple as a key.
		# When position to look up matches CU offset, key tuple will be less than element tuple.
		# So subtracting one will give wrong result. To overcome this, we use negated offsets.
		# In such case, we want to select the right end, so to lookup CUs we use
		# A[bisect_right(key)]
		# bisect_right() is the same as bisect()
		cu_key =(-pos,)
		cu_idx = bisect.bisect(self._cu_pos, cu_key)
		_, cu, die_pos = self._cu_pos[cu_idx]
		if not cu:
			return

		die_idx = bisect.bisect(die_pos, pos)
		assert die_idx > 0
		die_offset = die_pos[die_idx - 1]
		if die_offset < 0:
			return

		# See CompileUnit._parse_DIEs()
		die = DIE(
			cu=cu,
			stream=cu.dwarfinfo.debug_info_sec.stream,
			offset=die_offset)
		return die if die.offset <= pos < die.offset + die.size else None

	def get_die_key_addrs(self):
		result = {}
		for _, die in self._die_pos:
			if not die:
				continue

			die_key = get_die_key(die)
			if not die_key:
				continue

			if die_key in result:
				print(die_key)
				raise Exception("Duplicate DIE key")

			sym_addr = get_die_addr(die)
			if sym_addr is not None:
				result[die_key] = sym_addr

		return result

