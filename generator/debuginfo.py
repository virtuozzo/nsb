'''
Copyright (c) 2016-2017, Parallels International GmbH

Our contact details: Parallels International GmbH, Vordergasse 59, 8200
Schaffhausen, Switzerland.
'''

from __future__ import print_function

import array
import bisect
import functools
from weakref import WeakKeyDictionary
import itertools

from elftools.dwarf import enums, dwarf_expr
from elftools.dwarf.die import DIE
from elftools.dwarf import descriptions

from consts import *

set_const_str(enums.ENUM_DW_TAG)
set_const_str(enums.ENUM_DW_AT)
set_const_str(enums.ENUM_DW_FORM)
set_const_str(dwarf_expr.DW_OP_name2opcode)

def format_di_key(di_key):
	get_suffix = lambda tag: '()' if tag == STR.DW_TAG_subprogram else ''
	return '::'.join(name + get_suffix(tag) for name, tag in di_key)

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

def get_die_addr(die):
	structs = die.cu.structs

	if die.tag == STR.DW_TAG_subprogram:
		if STR.DW_AT_entry_pc in die.attributes:
			raise Exception("DW_AT_entry_pc is not supported")

		attr = die.attributes[STR.DW_AT_low_pc]
		assert attr.form == STR.DW_FORM_addr, attr.form
		return attr.value

	elif die.tag == STR.DW_TAG_variable:
		const_value_attr = die.attributes.get(STR.DW_AT_const_value)
		if const_value_attr:
			return "is optimized out, has constant value 0x{:x}".format(
				const_value_attr.value)

		attr = die.attributes[STR.DW_AT_location]
		assert attr.form == STR.DW_FORM_exprloc, attr.form

		expr_visitor = ExprVisitor(structs)
		return expr_visitor.get_addr(attr.value)

	else:
		assert 0

def get_die_size(die):
	if die.tag in [STR.DW_TAG_compile_unit, STR.DW_TAG_subprogram]:
		low_pc  = die.attributes.get(STR.DW_AT_low_pc)
		high_pc = die.attributes.get(STR.DW_AT_high_pc)
		if low_pc is None or high_pc is None:
			raise Exception("DW_AT_{low,high}_pc attr missing. Non-continuos code?")

		high_pc_form = descriptions.describe_form_class(high_pc.form)
		if high_pc_form == "constant":
			return high_pc.value
		elif high_pc_form == "address":
			return high_pc.value - low_pc.value
		else:
			raise Exception("Unknown attribute form {}".format(high_pc.form))
	else:
		assert 0

def memoize(dict_class):
	def fix_dict_class(f):
		cache = dict_class()

		@functools.wraps(f)
		def wrapper(arg):
			res = cache.get(arg)
			if res is not None:
				return res
			res = cache[arg] = f(arg)
			return res

		return wrapper

	return fix_dict_class

def _iter_DIEs(cu):
	cu_boundary = cu.cu_offset + cu['unit_length'] + cu.structs.initial_length_field_size()
	die_offset = cu.cu_die_offset

	while die_offset < cu_boundary:
		die = DIE(
			cu=cu,
			stream=cu.dwarfinfo.debug_info_sec.stream,
			offset=die_offset)

		yield die
		die_offset += die.size

@memoize(WeakKeyDictionary)
def _read_CU(cu):
	die_pos        = array.array('l', [-1])
	die_parent_pos = array.array('l', [-1])

	# See CompileUnit._unflatten_tree()
	parent_stack = [-1]
	for die in _iter_DIEs(cu):
		if not die.is_null():
			die_pos.append(die.offset)
			die_parent_pos.append(parent_stack[-1])
			if die.has_children:
				parent_stack.append(die.offset)
		elif parent_stack:
			parent_stack.pop()

	return die_pos, die_parent_pos

class DebugInfoObject(object):
	def __init__(self, debug_info, die, parent_die_pos):
		self.debug_info		= debug_info
		self.die		= die
		self.parent_die_pos	= parent_die_pos

	def get_parent(self):
		pos = self.parent_die_pos
		return self.debug_info.get_dio_by_pos(pos) if pos >= 0 else None

	def get_key(self):
		die = self.die

		if die.tag not in [STR.DW_TAG_subprogram, STR.DW_TAG_variable]:
			return

		skip_attrs = [
			STR.DW_AT_abstract_origin,
			STR.DW_AT_declaration,
			STR.DW_AT_artificial,
		]
		if set(die.attributes).intersection(skip_attrs):
			return

		key = []
		dio = self
		while dio:
			die = dio.die
			if die.tag == STR.DW_TAG_lexical_block:
				return
			sym_name = get_die_name(die)
			key.append((sym_name, die.tag))

			dio = dio.get_parent()

		key.reverse()
		return tuple(key)

	def get_addr(self):
		addr = get_die_addr(self.die)
		if isinstance(addr, basestring):
			print("!! {} {}".format(self, addr))
			return

		assert isinstance(addr, (int, long))
		return addr

class DebugInfo(object):
	def __init__(self, elf):
		self.elf = elf
		self._cu_pos  = cu_pos  = []
		self._cu_names = {}

		if not self.elf.has_dwarf_info():
			raise Exception("No debuginfo in ELF")
		dwi = self.elf.get_dwarf_info()

		for cu in dwi.iter_CUs():
			cu_pos.append((-cu.cu_offset, cu))
			cu_name = get_die_name(_iter_DIEs(cu).next())
			self._cu_names[cu_name] = cu

		cu_pos.append((1, None, None))
		cu_pos.sort()

	def get_cu_names(self):
		return self._cu_names.keys()

	def get_dio_by_pos(self, pos):
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
		_, cu = self._cu_pos[cu_idx]
		if not cu:
			return
		die_pos, die_parent_pos = _read_CU(cu)

		die_idx = bisect.bisect(die_pos, pos)
		assert die_idx > 0
		die_idx -= 1
		die_offset = die_pos[die_idx]
		if die_offset < 0:
			return

		# See CompileUnit._parse_DIEs()
		die = DIE(
			cu=cu,
			stream=cu.dwarfinfo.debug_info_sec.stream,
			offset=die_offset)
		within_die = die.offset <= pos < die.offset + die.size
		if not within_die:
			raise Exception("Position is outside DIE")
		return DebugInfoObject(self, die, die_parent_pos[die_idx])

	def _get_key_die(self, pos):
		pass

	def get_dio_by_key(self, key):
		cu_name, die_type = key[0]
		assert die_type == STR.DW_TAG_compile_unit
		cu = self._cu_names[cu_name]
		die_pos, die_parent_pos = _read_CU(cu)

		dio = None
		# Skip sentinel at position zero
		for pos in itertools.islice(die_pos, 1, None):
			curr_dio = self.get_dio_by_pos(pos)
			if curr_dio.get_key() != key:
				continue

			if dio:
				raise Exception("Duplicate key {0}".format(key))
			dio = curr_dio

		return dio
			

