from __future__ import print_function

import bisect
from elftools.dwarf import enums, dwarf_expr

from consts import *

set_const_str(enums.ENUM_DW_TAG)
set_const_str(enums.ENUM_DW_AT)
set_const_str(enums.ENUM_DW_FORM)
set_const_str(dwarf_expr.DW_OP_name2opcode)

class ExprVisitor(dwarf_expr.GenericExprVisitor):
	def __init__(self, structs):
		super(ExprVisitor, self).__init__(structs)
		self.__value = None
		self.__supported = True

	def _after_visit(self, opcode, opcode_name, args):
		if opcode_name != STR.DW_OP_addr:
			print("Can't interpret {0}".format(opcode_name))
			self.__supported = False

		self.__value = args[0]

	def get_value(self):
		return self.__value if self.__supported else None

def get_die_name(die):
	attr = die.attributes[STR.DW_AT_name]
	assert attr.form in [STR.DW_FORM_string, STR.DW_FORM_strp], attr.form
	return attr.value

def get_die_key(die, demangler):
	result = []
	while die:
		sym_name = demangler(get_die_name(die))
		result.append((sym_name, die.tag))
		die = die.get_parent()

	result.reverse()
	return tuple(result)

def get_addr(die, structs):
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
		expr_visitor.process_expr(attr.value)
		return expr_visitor.get_value()

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

def read(elf, sym_names=None,
		demangler = lambda s: s):
	if not elf.has_dwarf_info():
		return None
	dwarf_info = elf.get_dwarf_info()

	result = {}
	sym_tags = [STR.DW_TAG_subprogram, STR.DW_TAG_variable]

	def should_process(die):
		if die.tag not in sym_tags:
			return False

		if STR.DW_AT_abstract_origin in die.attributes:
			return False

		if STR.DW_AT_declaration in die.attributes:
			return False

		if sym_names is None:
			return True

		name = get_die_name(die)
		return demangler(name) in sym_names

	def walk(die):
		if should_process(die):
			die_key = get_die_key(die, demangler)
			assert die_key not in result

			sym_addr = get_addr(die, cu.structs)
			if sym_addr is not None:
				result[die_key] = sym_addr

		for child_die in die.iter_children():
			walk(child_die)

	cu_list = dwarf_info.iter_CUs()
	for cu in cu_list:
		top_die = cu.get_top_DIE()
		walk(top_die)

	return result

