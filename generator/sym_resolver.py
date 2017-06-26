import re
from abc import ABCMeta, abstractmethod

import ms_debuginfo
from util import reverse_mapping

def single(objects):
	obj_set = set(objects)
	if len(obj_set) != 1:
		print obj_set
		raise Exception("Multiple objects")
	return obj_set.pop()

class SymResolver:
	__metaclass__ = ABCMeta

	def __init__(self, t_elf, p_elf):
		self.t_elf = t_elf
		self.p_elf = p_elf

	@abstractmethod
	def demangle(self, n): pass

	@abstractmethod
	def match(self, sym): pass

	def skip_symbol(self, sym):
		skip = [ '_init', '_fini', '_edata', '_end', '__bss_start' ]
		if not sym.name:
			return True

		if sym.name in skip:
			return True

		return False

	def patch_symbols(self):
		print("== Searching symbols to process")

		symbols = []
		for idx, sym in self.p_elf.dynsyms.iteritems():
			if self.skip_symbol(sym):
				continue

			if not self.match(sym):
				continue

			print("{0:<4d} {1:016x} {2}".format(idx, sym.value, sym.name))
			symbols.append(sym)

		return symbols

	def target_match(self, symbols):
		result = {}
		sym_names = []
		for sym in symbols:
			sym_names.append(self.demangle(sym.name))

		for key, sym in self.t_elf.syms.iteritems():
			if self.skip_symbol(sym):
				continue

			if sym.name not in sym_names:
				continue

			if sym.name in result:
				print("Multiple entries for {0} in symbol table".format(sym.name))
				return None

			result[sym.name] = sym

		return result

	def target_lookup(self, symbols):
		selected = self.target_match(symbols)
		if selected is not None:
			lookup = lambda name, addr: selected[self.demangle(name)].value
		else:
			print("== Reading debuginfo for old ELF")
			t_di2addr = ms_debuginfo.read(self.t_elf.elf, selected)

			print("== Reading debuginfo for new ELF")
			p_di2addr = ms_debuginfo.read(self.p_elf.elf, selected, self.demangle)

			p_addr2di_list = reverse_mapping(p_di2addr)
			lookup = lambda name, addr: single([t_di2addr[di]
					for di in p_addr2di_list[addr]])

		return lookup

	def resolve_symbol(self, sym, lookup):
		return lookup(sym.name, sym.value)

	def resolve(self):
		result = []

		syms = self.patch_symbols()
		lookup = self.target_lookup(syms)

		print("== Resolving addresses in old ELF")
		for sym in syms:
			o_addr = self.resolve_symbol(sym, lookup)
			if o_addr is None:
				continue

			result.append((sym.num, o_addr))
			print("{0:<4d} {1:016x} {2}".format(sym.num, o_addr, sym.name))

		return result


class ManualSymResolver(SymResolver):
	PREFIX = 'vzpatch'
	prefix_re = re.compile(r'^{0}_(\d+_)*'.format(PREFIX))

	def demangle(self, n):
		return self.prefix_re.sub('', n)

	def match(self, sym):
		return sym.name.startswith(self.PREFIX)


class GlobalSymResolver(SymResolver):
	def demangle(self, n):
		return n

	def match(self, sym):
		return sym.bind == 'STB_GLOBAL'

	def skip_symbol(self, sym):
		if sym.bind != 'STB_GLOBAL':
			return True
		return SymResolver.skip_symbol(self, sym)

	def resolve_symbol(self, sym, lookup):
		try:
			return lookup(sym.name, sym.value)
		except:
			pass
		return None
