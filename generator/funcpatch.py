import re
import os
from collections import namedtuple

import funcpatch_pb2
import objinfo_pb2

class CmdInfo:
	def __init__(self, name, op, size, is_jump):
		self.name = name
		self.op = op
		self.size = size
		self.is_jump = is_jump

	def __str__(self):
		return self.name


class JumpCmdInfo(CmdInfo):
	def __init__(self, name, op, size):
		CmdInfo.__init__(self, name, op, size, True)


class JumpByteCmd(JumpCmdInfo):
	def __init__(self, name, op):
		JumpCmdInfo.__init__(self, name, op, 2)


class JumpQuadCmd(JumpCmdInfo):
	def __init__(self, name, op):
		JumpCmdInfo.__init__(self, name, op, 5)


class JmpqCmd(JumpQuadCmd):
	def __init__(self):
		JumpQuadCmd.__init__(self, "jmpq", 0xe9)


class CallqCmd(JumpQuadCmd):
	def __init__(self):
		JumpQuadCmd.__init__(self, "call", 0xe8)


class JmpCmd(JumpByteCmd):
	def __init__(self):
		JumpByteCmd.__init__(self, "jmp", 0xeb)


class JeCmd(JumpByteCmd):
	def __init__(self):
		JumpByteCmd.__init__(self, "je", 0x74)


class JneCmd(JumpByteCmd):
	def __init__(self):
		JumpByteCmd.__init__(self, "jne", 0x75)


class MovCmd(CmdInfo):
	def __init__(self, code):
		code_bytes = code.split()
		if code_bytes[0] == '8b':
			op = int(code_bytes[0] + code_bytes[1], 16)
		elif code_bytes[0] == '89':
			op = int(code_bytes[0] + code_bytes[1], 16)
		else:
			raise
		CmdInfo.__init__(self, "mov", op, len(code_bytes), False)


class CodeLineInfo:
	def __init__(self, dumpline, func_start):
		self.dumpline = dumpline
		self.addr = int(self.dumpline.addr, 16)
		self.offset = self.addr - func_start
		self.command_info = None
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
				self.command_info = JmpqCmd()
			elif "callq" in self.dumpline.code:
				self.command_info = CallqCmd()
			elif "jmp" in self.dumpline.code:
				self.command_info = JmpCmd()
			elif "jne " in self.dumpline.code:
				self.command_info = JneCmd()
			elif "je " in self.dumpline.code:
				self.command_info = JeCmd()
			else:
				print "Unsupported redirect command: %s" % self.dumpline.code
				raise
		elif self.dumpline.hint:
			split = filter(None, re.split('<(.+)>', self.dumpline.hint))
			self.access_addr = int(split[0].strip(), 16)
			self.access_name = split[1].strip()
			print "self.access_addr: %#x" % self.access_addr
			print "self.access_name: %s" % self.access_name
			print "self.dumpline.bytes: '%s'" % self.dumpline.bytes
			try:
				if "mov " in self.dumpline.code:
					self.command_info = MovCmd(self.dumpline.bytes)
				else:
					raise
			except:
                               print "Unsupported variable command: %s" % self.dumpline.line
                               raise

	def show(self):
		if self.command_info:
			print "%s: '%s', '%s', %s, %d" % (self.command_info, self.access_name, self.access_addr, self.access_addr, self.offset)

	def get_patch(self):
		print "CodeLineInfo: get_patch for %s" % self.dumpline.line
		image = objinfo_pb2.ObjInfo()
		image.name = self.access_name
		image.offset = self.offset
		image.op = self.command_info.op
		image.size = self.command_info.size
		image.ref_addr = self.access_addr
		image.external = self.access_plt
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
			if info.command_info:
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

