from collections import namedtuple
import sys
import os
import re
import tempfile

import elffile

FuncInfo = namedtuple("FuncInfo", "start lenght")

class BinFile:
	def __init__(self, filename, debug_filename=None, keep_merged=False):
		fn_list = [filename]
		if debug_filename is not None:
			fn_list.append(debug_filename)
		for fn in fn_list:
			if not os.access(fn, os.R_OK):
				print "File %s doesn't exist" % fn
				sys.exit(1)

		self.filename = os.path.realpath(filename)
		self.debug_filename = debug_filename
		self.keep_merged = keep_merged

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
		elf = elffile.ElfFile(open(self.filename, 'rb'))
		if self.debug_filename:
			bid = elf.build_id()

			with open(self.debug_filename, 'rb') as debug_stream:
				debug_bid = elffile.ElfFile(debug_stream).build_id()

			if bid != debug_bid:
				print "Build ID mismatch between input ELFs"
				sys.exit(1)

			merge_filename = tempfile.mktemp(
				prefix=os.path.basename(self.filename) + '-')
			if self.keep_merged:
				print "Merged ELF:", merge_filename
			cmd = 'eu-unstrip -o %s %s %s' % (merge_filename,
					self.filename, self.debug_filename)
			self.__exec__(cmd)

			self.elf = elf = elffile.ElfFile(open(merge_filename, 'rb'))
			if not self.keep_merged:
				os.unlink(merge_filename)
		else:
			self.elf = elf

		self.header = elf.get_header()
		self.symbols = elf.get_symbols()
		self.sections = elf.get_sections()

		if self.symbols is None:
			print "  No symbols found. Perhaps this ELF has been stripped?"
			sys.exit(1)

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
