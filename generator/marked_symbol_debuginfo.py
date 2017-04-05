from __future__ import print_function

from elftools.dwarf import enums, dwarf_expr

def set_dw_consts(const_dict):
	globals().update((const, const) for const in const_dict
		if not const.startswith('_'))

set_dw_consts(enums.ENUM_DW_TAG)
set_dw_consts(enums.ENUM_DW_AT)
set_dw_consts(enums.ENUM_DW_FORM)
set_dw_consts(dwarf_expr.DW_OP_name2opcode)

class ExprVisitor(dwarf_expr.GenericExprVisitor):
	def __init__(self, structs):
		super(ExprVisitor, self).__init__(structs)
		self.__value = None
		self.__supported = True

	def _after_visit(self, opcode, opcode_name, args):
		if opcode_name != DW_OP_addr:
			print("Can't interpret {0}".format(opcode_name))
			self.__supported = False

		self.__value = args[0]

	def get_value(self):
		return self.__value if self.__supported else None

def get_die_name(die):
	attr = die.attributes[DW_AT_name]
	assert attr.form in [DW_FORM_string, DW_FORM_strp], attr.form
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
	if die.tag == DW_TAG_subprogram:
		if DW_AT_entry_pc in die.attributes:
			raise Exception("DW_AT_entry_pc is not supported")

		attr = die.attributes[DW_AT_low_pc]
		assert attr.form == DW_FORM_addr, attr.form
		return attr.value

	elif die.tag == DW_TAG_variable:
		attr = die.attributes[DW_AT_location]
		assert attr.form == DW_FORM_exprloc, attr.form

		expr_visitor = ExprVisitor(structs)
		expr_visitor.process_expr(attr.value)
		return expr_visitor.get_value()

	else:
		assert 0

def read(elf, sym_names=None,
		demangler = lambda s: s):
	if not elf.has_dwarf_info():
		return None
	dwarf_info = elf.get_dwarf_info()

	result = {}
	sym_tags = [DW_TAG_subprogram, DW_TAG_variable]

	def should_process(die):
		if die.tag not in sym_tags:
			return False

		if DW_AT_abstract_origin in die.attributes:
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
				print("{0:016x} {1}".format(sym_addr, die_key))
				result[die_key] = sym_addr

		for child_die in die.iter_children():
			walk(child_die)

	cu_list = dwarf_info.iter_CUs()
	for cu in cu_list:
		top_die = cu.get_top_DIE()
		walk(top_die)

	return result

