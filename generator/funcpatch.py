import re
import os
from collections import namedtuple

import funcpatch_pb2
import objinfo_pb2

class CmdInfo:
	def __init__(self, name, op, prefix_size, op_size, addr_size, is_jump):
		self.name = name
		self.op = op
		self.prefix_size = prefix_size
		self.op_size = op_size
		self.addr_size = addr_size
		self.is_jump = is_jump

	def __str__(self):
		return self.name


class JumpCmdInfo(CmdInfo):
	def __init__(self, name, op, prefix_size, op_size, addr_size):
		CmdInfo.__init__(self, name, op, prefix_size, op_size, addr_size, True)


class JumpByteCmd(JumpCmdInfo):
	def __init__(self, name, op, prefix_size):
		JumpCmdInfo.__init__(self, name, op, prefix_size, 1, 1)


class JumpQuadCmd(JumpCmdInfo):
	def __init__(self, name, op, prefix_size):
		JumpCmdInfo.__init__(self, name, op, prefix_size, 1, 4)


class JmpqCmd(JumpQuadCmd):
	def __init__(self, prefix_size):
		JumpQuadCmd.__init__(self, "jmpq", 0xe9, prefix_size)


class CallqCmd(JumpQuadCmd):
	def __init__(self, prefix_size):
		JumpQuadCmd.__init__(self, "call", 0xe8, prefix_size)


class JmpCmd(JumpByteCmd):
	def __init__(self, prefix_size):
		JumpByteCmd.__init__(self, "jmp", 0xeb, prefix_size)


class JeCmd(JumpByteCmd):
	def __init__(self, prefix_size):
		JumpByteCmd.__init__(self, "je", 0x74, prefix_size)


class JneCmd(JumpByteCmd):
	def __init__(self, prefix_size):
		JumpByteCmd.__init__(self, "jne", 0x75, prefix_size)


class VarCmdInfo(CmdInfo):
	def __init__(self, name, op, prefix_size, op_size, addr_size):
		CmdInfo.__init__(self, name, op, prefix_size, op_size, addr_size, False)

class VarQuadCmd(VarCmdInfo):
	def __init__(self, name, op, prefix_size, op_size):
		VarCmdInfo.__init__(self, name, op, prefix_size, op_size, 4)


class MovCmd(VarQuadCmd):
	def __init__(self, code, prefix_size):
		code_bytes = code.split()
		if code_bytes[prefix_size] == '8b' or code_bytes[prefix_size] == '89':
			op_size = 2
			op = int(''.join(code_bytes[:op_size + prefix_size]), 16)
		else:
			raise
		VarQuadCmd.__init__(self, "mov", op, prefix_size, op_size)


class MovlCmd(VarQuadCmd):
	def __init__(self, code, prefix_size):
		code_bytes = code.split()
		if code_bytes[prefix_size] == 'c7':
			op_size = 2
			op = int(''.join(code_bytes[:op_size + prefix_size]), 16)
		else:
			raise
		VarQuadCmd.__init__(self, "movl", op, prefix_size, op_size)



class CodeLineInfo:
	def __init__(self, dumpline, func_name, func_start):
		self.dumpline = dumpline
		self.addr = int(self.dumpline.addr, 16)
		self.offset = self.addr - func_start
		self.func_name = func_name
		self.command_info = None
		self.access_addr = 0
		self.access_name = None
		self.access_plt = False
		self.__analize__()

	def __analize__(self):
		self.dumpline.show()

		prefix_size = 0
		code_bytes = self.dumpline.bytes.split()
		if 0x40 <= int(code_bytes[0], 16) <= 0x4f:
			prefix_size = 1

		if self.dumpline.name:
			split = self.dumpline.name.split('@')
			self.access_name = split[0];
			if '+' in self.access_name:
				func_name = self.dumpline.name.split('+')[0]
				if func_name == self.func_name:
					print "Local jump. Skip"
					return

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
				self.command_info = JmpqCmd(prefix_size)
			elif "callq" in self.dumpline.code:
				self.command_info = CallqCmd(prefix_size)
			elif "jmp" in self.dumpline.code:
				self.command_info = JmpCmd(prefix_size)
			elif "jne " in self.dumpline.code:
				self.command_info = JneCmd(prefix_size)
			elif "je " in self.dumpline.code:
				self.command_info = JeCmd(prefix_size)
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
					self.command_info = MovCmd(self.dumpline.bytes, prefix_size)
				elif "movl " in self.dumpline.code:
					self.command_info = MovlCmd(self.dumpline.bytes, prefix_size)
				else:
					raise
			except:
                               print "Unsupported variable command: %s" % self.dumpline.line
			       print self.dumpline.bytes
                               raise

	def show(self):
		if self.command_info:
			print "%s: '%s', '%s', %s, %d" % (self.command_info, self.access_name, self.access_addr, self.access_addr, self.offset)

	def get_patch(self):
		image = objinfo_pb2.ObjInfo()
		image.name = self.access_name
		image.offset = self.offset
		image.op_size = self.command_info.op_size + self.command_info.prefix_size
		image.addr_size = self.command_info.addr_size
		image.ref_addr = self.access_addr

		print "    Reference to %s:" % image.name
		print "      Offset   : %#x" % image.offset
		print "      Op_size  : %#x" % image.op_size
		print "      Addr_size: %#x" % image.addr_size
		print "      Ref_addr : %#x" % image.ref_addr

		return image


class FuncPatch:
	def __init__(self, func_a, func_b, functype):
		self.func_a = func_a
		self.func_b = func_b
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
		print "\tName    : %s" % self.func_b.funcname
		print "\tStart   : 0x%x" % self.func_b.start
		print "\tSize    : 0x%x" % self.func_b.size
		print "\tType    : %s" % self.functype.name
		if len(self.new):
			print "\tLines: %d" % len(self.new)
			for o, n in zip(self.old, self.new):
				print "\t\t<<<< %s | %s | %s | %s | %s" % (o.addr, o.bytes, o.code, o.name, o.hint)
				print "\t\t>>>> %s | %s | %s | %s | %s" % (n.addr, n.bytes, n.code, n.name, n.hint)
#		else:
#			for n in self.func_b.lines:
#				print "\t\t>>>> %s | %s | %s | %s | %s" % (n.addr, n.bytes, n.code, n.name, n.hint)

	def analize(self):
		print "\tAnalize: %s" % self.functype.name
		for l in self.func_b.lines:
			info = CodeLineInfo(l, self.func_b.funcname, self.func_b.start)
#			info.show()
			# skip pure math commands
			if info.command_info:
				self.code_info.append(info)

	def get_patch(self, code, dyn, plt):
		image = funcpatch_pb2.FuncPatch()
		image.name = self.func_b.funcname
		image.addr = self.func_b.start
		image.size = self.func_b.size
		image.new = False
		if self.functype.name == "new":
			image.new = True
		image.code = code
		image.dyn = dyn
		image.plt = plt

		print "  Function %s:" % image.name
		print "    Addr    : %#x" % image.addr
		print "    Size    : %#x" % image.size
		print "    New     : %s" % image.new
		print "    Dyn     : %s" % image.dyn
		print "    Plt     : %s" % image.plt

		for i in self.code_info:
			ci = i.get_patch()
			image.objs.extend([ci])
		return image

	def write(self, patchdir, code):
		filename = patchdir + "/" + self.func_b.funcname + ".patch"
		pfile = os.open(filename, os.O_CREAT | os.O_WRONLY)

		image = self.get_patch()

		data = image.SerializeToString()

		os.write(pfile, data)
		print "Written %d bytes to %s" % (len(data), filename)

