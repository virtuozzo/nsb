from collections import namedtuple
from function import ElfFunction
import os
import re

ElfSym = namedtuple("ElfSym", "num value size type bind vis ndx name")
ElfSym.__new__.__defaults__ = (None,) * len(ElfSym._fields)

FuncInfo = namedtuple("FuncInfo", "start lenght")

class BinFile:
	def __init__(self, filename):
		if not os.access(filename, os.R_OK):
			print "File %s doesn't exist" % filename
			exit(1)
		self.filename = filename
		self.functions = {}
		self.objects = {}
		self.dyn_functions = {}
		self.dyn_objects = {}
		self.elf_data = None

	def __readelf__(self):
		import subprocess
		p = subprocess.Popen(['readelf', '-s', self.filename],
					stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		out, err = p.communicate()
		return out

	def __parse__(self):
		if self.elf_data is None:
			self.elf_data = self.__readelf__()

		functions = {}
		objects = {}
		dyn_functions = {}
		dyn_objects = {}
		symbols = self.elf_data.split('\n')
		for s in symbols:
			tokens = s.split()
			if len(tokens) > 8:
				tokens[7] = ' '.join(tokens[7::])
				tokens = tokens[:8]
			es = ElfSym(*tokens)

			if es.name is None:
				continue
			if es.size == 0:
				continue

			# Filter out plt symbols from .symtab entries
			# They will be taken .dynsym and there they
			# have only one '@' symbol in it
			if "@@" in es.name:
				continue;

			if '@' in es.name:
				name = re.search('^[^@]+', es.name).group(0)
				if es.type == "FUNC":
					if es.ndx != "UND":
						print "Function with '@' and defined: %s" % s
						raise
					self.dyn_functions[name] = ElfFunction(self.filename, name, es.value, es.size)
				elif es.type == "OBJECT":
					self.dyn_objects[name] = es
			else:
				if es.type == "FUNC":
					self.functions[es.name] = ElfFunction(self.filename, es.name, es.value, es.size)
				elif es.type == "OBJECT":
					self.objects[es.name] = es

	def functions_dict(self):
		if not self.functions:
			self.__parse__()
		return self.functions

	def objects_dict(self):
		if not self.objects:
			self.__parse__()
		return self.objects

	def dyn_functions_dict(self):
		if not self.dyn_functions:
			self.__parse__()
		return self.dyn_functions


	def dyn_objects_dict(self):
		if not self.dyn_objects:
			self.__parse__()
		return self.dyn_objects
