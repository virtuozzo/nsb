import re
import os
from collections import namedtuple

import funcpatch_pb2
import objinfo_pb2

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

class JmpqCommand(CommandType):
	def __init__(self):
		CommandType.__init__(self, 3, "jmpq")

class JmpCommand(CommandType):
	def __init__(self):
		CommandType.__init__(self, 4, "jmp")

class CodeLineInfo:
	def __init__(self, dumpline, func_start):
		self.dumpline = dumpline
		self.addr = int(self.dumpline.addr, 16)
		self.offset = self.addr - func_start
		self.command_type = MathCommand()
		self.access_addr = 0
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

			if "jmpq" in self.dumpline.code:
				self.command_type = JmpqCommand()
			elif "call" in self.dumpline.code:
				self.command_type = CallCommand()
			elif "jmp" in self.dumpline.code:
				self.command_type = CallCommand()
			else:
				print "Unsupported redirect command: %s" % self.dumpline.code
				raise
		elif self.dumpline.hint:
			split = filter(None, re.split('<(.+)>', self.dumpline.hint))
			self.access_addr = split[0].strip()
			self.access_name = split[1].strip()
			self.command_type = VarCommand()


	def show(self):
		if self.command_type != MathCommand():
			print "%s: '%s', '%s', %s, %d" % (self.command_type, self.access_name, self.access_addr, self.access_addr, self.offset)

	def get_patch(self):
		print "CodeLineInfo: get_patch for %s" % self.dumpline.line
		image = objinfo_pb2.ObjInfo()
		image.name = self.access_name
		image.offset = self.offset
		image.external = self.access_plt
		image.ref_addr = self.access_addr
		if self.command_type.num == 1:
			image.reftype = objinfo_pb2.ObjInfo.CALL
		elif self.command_type.num == 3:
			image.reftype = objinfo_pb2.ObjInfo.JMPQ
		elif self.command_type.num == 4:
			image.reftype = objinfo_pb2.ObjInfo.JMP
		else:
			print "Unsupported reftype: %s" % self.command_type.num 
		return image


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
			info = CodeLineInfo(l, self.function.start)
#			info.show()
			# skip pure math commands
			if info.command_type.num:
				self.code_info.append(info)

	def get_patch(self, code):
		image = funcpatch_pb2.FuncPatch()
		image.name = self.function.funcname
		image.start = self.function.start
		image.size = self.function.size
		image.new = False
		if self.functype.name == "new":
			image.new = True
		image.code = code
		for i in self.code_info:
			ci = i.get_patch()
			image.objs.extend([ci])
		return image

	def write(self, patchdir, code):
		filename = patchdir + "/" + self.function.funcname + ".patch"
		pfile = os.open(filename, os.O_CREAT | os.O_WRONLY)

		image = self.get_patch()

		data = image.SerializeToString()

		os.write(pfile, data)
		print "Written %d bytes to %s" % (len(data), filename)

