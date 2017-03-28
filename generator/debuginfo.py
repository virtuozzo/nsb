from __future__ import print_function

import bisect
from elftools.dwarf import enums, dwarf_expr

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
		self._die_pos = die_pos = []

		def walk(die):
			die_pos.append((-die.offset, die))

			for child_die in die.iter_children():
				walk(child_die)

		if not self.elf.has_dwarf_info():
			raise Exception("No debuginfo in ELF")
		dwi = self.elf.get_dwarf_info()

		for cu in dwi.iter_CUs():
			walk(cu.get_top_DIE())
		die_pos.append((1, None))
		die_pos.sort()

	def lookup_die(self, pos):
		assert pos >= 0
		# Consider sorted array
		# ...,X,Y,... where X < Y, and some element A
		# If X < A < Y then bisect_left(A) == bisect_right(A) == index(Y)
		# as described at https://docs.python.org/2/library/bisect.html
		# IOW, bisection selects right end of the range. However, if X & Y
		# represent DIE offsets, we want to select left end. By using negated
		# offsets, selecting right end becomes right thing to do. Finally, in
		# the case when A is some as Y, bisect_left() & bisect_right() return
		# different results.  However, we completely avoid this case by using
		# single element tuple as lookup key.  It is never equal to two-tuples
		# in the array. Also, one-tuple (-offset,) is less than (-offset, die)
		# tuple from the array, so bisect will point at the latter.
		key = (-pos,)
		idx = bisect.bisect(self._die_pos, key)
		die = self._die_pos[idx][1]
		return die if die and die.offset <= pos < die.offset + die.size else None

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

