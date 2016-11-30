from collections import namedtuple
from function import ElfFunction
import os
import re

import elffile

FuncInfo = namedtuple("FuncInfo", "start lenght")

class BinFile:
	def __init__(self, filename):
		if not os.access(filename, os.R_OK):
			print "File %s doesn't exist" % filename
			exit(1)
		self.filename = os.path.realpath(filename)
		self.functions = {}
		self.objects = {}
		self.dyn_functions = {}
		self.dyn_objects = {}
		self.elf_data = None
		self.sections = None
		self.symbols = None
		self.__parse__()

	def __exec__(self, cmd):
		import subprocess
		p = subprocess.Popen(cmd.split(),
					stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		out, err = p.communicate()
		return out

	def __get_plt_info(self):
		text = self.__exec__("objdump -d -j.plt %s" % self.filename)
		entries = re.findall('[0-9A-Fa-f]{16}.+<.+plt>', text)
		PltEntry = namedtuple("PltEntry", "addr name")
		for e in entries:
			pe = PltEntry(*filter(None, re.split(' ?\t?<(.+)@.+>', e)));
			print pe
			if pe.name in self.dyn_functions:
				self.dyn_functions[pe.name].start = int(pe.addr, 16)

	def __add_function__(self, func):
		if '@' in func.name:
			name = re.search('^[^@]+', func.name).group(0)
			if func.ndx != "SHN_UNDEF":
				print "Function with '@' and defined: %s" % s
				raise
			self.dyn_functions[name] = ElfFunction(self.filename, name, func.value, func.size)
		elif func.size:
			self.functions[func.name] = ElfFunction(self.filename, func.name, func.value, func.size)

	def __add_object__(self, obj):
		if '@' in obj.name:
			name = re.search('^[^@]+', obj.name).group(0)
			self.dyn_objects[name] = obj
		else:
			self.objects[obj.name] = obj

	def __parse__(self):
		with open(self.filename, 'rb') as stream:
			elf = elffile.ElfFile(stream)
			self.header = elf.get_header()
			self.symbols = elf.get_symbols()
			self.sections = elf.get_sections()

		if self.header.type != 'ET_EXEC':
			print "Wrong object file type: %s" % self.header.type
			print "Only executables are supported"
			raise

		if self.symbols is None:
			print "  No symbols found. Perhaps this ELF has been stripped?"
			exit(1)

		for k, s in self.symbols.iteritems():
			if s.name is None:
				continue

			if s.type == "STT_FUNC":
				self.__add_function__(s)
			elif s.type == "STT_OBJECT":
				self.__add_object__(s)

		if self.dyn_functions:
			self.__get_plt_info()


	def __text_load_addr__(self):
		section = self.sections['.text']
		return section.addr - section.offset

	def function_code(self, vaddr, size):
		with open(self.filename, 'rb') as stream:
			stream.seek(vaddr - self.__text_load_addr__())
			return stream.read(size)

	def read_rodata(self):
		rodata = self.sections['.rodata']
		with open(self.filename, 'rb') as stream:
			stream.seek(rodata.offset)
			return stream.read(rodata.size)
