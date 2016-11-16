from collections import namedtuple
from function import ElfFunction
import os

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
		symbols = self.elf_data.split('\n')
		for s in symbols:
			tokens = s.split()
			if len(tokens) > 8:
				tokens[7] = ' '.join(tokens[7::])
				tokens = tokens[:8]
			es = ElfSym(*tokens)
			if es.size == 0:
				continue

			if es.type == "FUNC":
				functions[es.name] = ElfFunction(self.filename, es.name, es.value, es.size)
			elif es.type == "OBJECT":
				objects[es.name] = es
		return [ functions, objects ]

	def functions_dict(self):
		if not self.functions:
			self.functions, self.objects = self.__parse__()
		return self.functions

	def objects_dict(self):
		if not self.objects:
			self.functions, self.objects = self.__parse__()
		return self.objects
