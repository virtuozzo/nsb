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

	def __readelf_symbols__(self):
		import subprocess
		p = subprocess.Popen(['readelf', '-s', self.filename],
					stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		out, err = p.communicate()
		return out

	def functions_dict(self):
		if not self.functions:
			out = self.__readelf_symbols__()
			symbols = out.split('\n')
			for s in symbols:
				tokens = s.split()
				if len(tokens) > 8:
					tokens[7] = ' '.join(tokens[7::])
					tokens = tokens[:8]
				es = ElfSym(*tokens)
				if es.size == "0" or es.type != "FUNC":
					continue
				#self.functions[es.name] = FuncInfo(es.value, es.size)
				self.functions[es.name] = ElfFunction(self.filename, es.name, es.value, es.size)
		return self.functions

	def objects_dict(self):
		if not self.objects:
			out = self.__readelf_symbols__()
			symbols = out.split('\n')
			for s in symbols:
				tokens = s.split()
				if len(tokens) > 8:
					tokens[7] = ' '.join(tokens[7::])
					tokens = tokens[:8]
				es = ElfSym(*tokens)
				if es.type == "OBJECT":
					self.objects[es.name] = es
		return self.objects
