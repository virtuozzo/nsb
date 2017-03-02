from collections import namedtuple
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

	def __add_function__(self, func):
		if func.size:
			self.functions[func.name] = func

	def __add_object__(self, obj):
		self.objects[obj.name] = obj

	def __parse__(self):
		with open(self.filename, 'rb') as stream:
			elf = elffile.ElfFile(stream)
			self.header = elf.get_header()
			self.symbols = elf.get_symbols()
			self.sections = elf.get_sections()
			self.segments = elf.get_segments()

		if self.header.type != 'ET_DYN':
			print "Wrong object file type: %s" % self.header.type
			print "Only shared object files are supported"
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

	def add_section(self, sname, filename):
		cmd = "objcopy --remove-section=%s %s" % (sname, self.filename)
		self.__exec__(cmd)
		print "Removed old \"%s\" ELF section from %s" % (sname, self.filename)
		cmd = "objcopy --add-section %s=%s %s" % (sname, filename, self.filename)
		self.__exec__(cmd)
		print "Added %s as ELF section \"%s\" to %s" % (filename, sname, self.filename)
