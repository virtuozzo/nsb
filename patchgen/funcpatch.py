import re
import os
from collections import namedtuple

import funcpatch_pb2

class CommandType:
	def __init__(self, num, name):
		self.num = num
		self.name = name

	def __str__(self):
		return self.name


class MathCommand(CommandType):
	def __init__(self):
		CommandType.__init__(self, 0, "math")


class CallCommand(CommandType):
	def __init__(self):
		CommandType.__init__(self, 1, "call")


class VarCommand(CommandType):
	def __init__(self):
		CommandType.__init__(self, 2, "var")


class CodeLineInfo:
	def __init__(self, dumpline):
		self.dumpline = dumpline
		self.command_type = MathCommand()
		self.access_addr = None
		self.access_name = None
		self.access_plt = False
		self.__analize__()

	def __analize__(self):
		self.dumpline.show()
		if self.dumpline.name:
			split = self.dumpline.name.split('@')
			self.access_name = split[0];
			if len(split) > 1:
				if split[1] == "plt":
					self.access_plt = True
				else:
					print "WTF?!"
					print split
					exit()

			if self.dumpline.hint:
					print "WTF?!"
					print split
					exit()
			self.command_type = CallCommand()
		elif self.dumpline.hint:
			split = filter(None, re.split('<(.+)>', self.dumpline.hint))
			self.access_addr = split[0].strip()
			self.access_name = split[1].strip()
			self.command_type = VarCommand()


	def show(self):
		if self.command_type != CommandType.math:
			print "%s: '%s', '%s'" % (self.command_type, self.access_addr, self.access_name)



class FuncPatch:
	def __init__(self, function, functype):
		self.function = function
		self.old = []
		self.new = []
		self.calls = []
		self.functype = functype
		self.code_info = []

	def add_line(self, old, new):
		self.old.append(old)
		self.new.append(new)

#	def add_call(self, offset, name):
#		ExtCall = namedtuple("ExtCall", "offset name")
#		self.lines.append(ExtCall(offset, name))

	def show(self):
		print "Patch:"
		print "\tName    : %s" % self.function.funcname
		print "\tStart   : 0x%x" % self.function.start
		print "\tFile off: 0x%x" % self.function.file_offset
		print "\tSize    : 0x%x" % self.function.size
		print "\tType    : %s" % self.functype.name
		if len(self.new):
			print "\tLines: %d" % len(self.new)
			for o, n in zip(self.old, self.new):
				print "\t\t<<<< %s | %s | %s | %s | %s" % (o.addr, o.bytes, o.code, o.name, o.hint)
				print "\t\t>>>> %s | %s | %s | %s | %s" % (n.addr, n.bytes, n.code, n.name, n.hint)
#		else:
#			for n in self.function.lines:
#				print "\t\t>>>> %s | %s | %s | %s | %s" % (n.addr, n.bytes, n.code, n.name, n.hint)

	def analize(self):
		print "\tAnalize: %s" % self.functype.name
		for l in self.function.lines:
			info = CodeLineInfo(l)
#			info.show()
			self.code_info.append(info)

	def write(self, patchdir, code):
		filename = patchdir + "/" + self.function.funcname + ".patch"
		pfile = os.open(filename, os.O_CREAT | os.O_WRONLY)

		image = funcpatch_pb2.FuncPatch()
		image.name = self.function.funcname
		image.start = self.function.start
		image.size = self.function.size
		image.new = False
		if self.functype.name == "new":
			image.new = True
		image.code = code

		data = image.SerializeToString()

		os.write(pfile, data)
		print "Written %d bytes to %s" % (len(data), filename)

