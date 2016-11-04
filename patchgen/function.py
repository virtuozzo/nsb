import re
from funcpatch import FuncPatch

class PatchFuncType:
	def __init__(self, type, name):
		self.type = type
		self.name = name
	def __str__(self):
		return self.name


class NewFuncType(PatchFuncType):
	def __init__(self):
		PatchFuncType.__init__(self, 1, "new")


class ModifiedFuncType(PatchFuncType):
	def __init__(self):
		PatchFuncType.__init__(self, 2, "modified")


class DumpLine:
	def __init__(self, line):
		self.line = line
		split = re.split('\t|#', self.line)
		self.addr = split[0]
		self.bytes = split[1]
		self.code = None
		self.name = None
		self.hint = None
		if len(split) > 2 :
			self.code = split[2]
#		if len(split) > 3 :
#			self.name = split[3]
		if len(split) > 3 :
			self.hint = split[3]

		if self.code and '<' in self.code:
#			print "'%s'" % self.code

			split = filter(None, re.split('<(.+)>', self.code))
			if len(split) > 2:
				print "WTF?!"
				print split
				exit()

			self.code = split[0]
			self.name = split[1]

#			print self.line

#		self.show()

	def show(self):
		print "%s | %s | %s | %s | %s" % (self.addr, self.bytes, self.code, self.name, self.hint)

	@staticmethod
	def equal_lines(a, b):
		if a.bytes != b.bytes:
			# This can be due to different adrress offsets.
			# Let's compare disassemble if exists
			# print "================= start ==================="
			if a.code and b.code and a.code == b.code:
				#print "================= stop (code match) ==================="
				return True

			if a.name and b.name and a.name == b.name:
				# print "================= stop (name match) ==================="
				return True

			if a.hint and b.hint and a.hint == b.hint:
				# print "================= stop (hint match) ==================="
				return True
			# print "================= stop ==================="
			return False
		else:
			if a.name != b.name:
				return False

		return True


class ElfFunction:
	def __init__(self, filename, funcname, start, size):
		self.filename = filename
		self.funcname = funcname
		self.start = int(start, 16)
		self.size = int(size, 10)
		self.end = self.start + self.size
		self.data = None
		self.lines = []
		self.text = None
		# TODO That's bad, very bad.
		# File offset must be taken from .text header
		self.file_offset = self.start - 0x400000
		self.__parse__()


	def read(self):
		import subprocess
		p = subprocess.Popen(['objdump', '-d',
					str('--start-address=%s' % hex(self.start)),
					str('--stop-address=%s' % hex(self.end)),
					self.filename], stdout=subprocess.PIPE,
					stderr=subprocess.PIPE)
		out, err = p.communicate()
		return out[out.find('%016x' % self.start):]

	def show(self):
		if self.data is None:
			out = self.read()
			self.data = out[out.find('%016x' % self.start):]

		print "%s:%s:\n%s" % (self.filename, self.funcname, self.data)

	def __parse__(self):
		if not self.lines:
			if self.text is None:
				out = self.read()
				self.text = out[out.find('%016x' % self.start):]
			for line in self.text.split('\n')[1:]:
				if len(line):
#					DumpLine(line).show()
					self.lines.append(DumpLine(line))
		return self.lines

	def analize(self):
		for line in lines:
			if line.name or line.hint:
				print "%s (%s) (%s)" % (line.code, line.name or None, line.hint or "None")

	@staticmethod
	def compare_content(func_a, func_b):
		diff_lines = []
		for a, b in zip(func_a.lines, func_b.lines):
			if DumpLine.equal_lines(a, b) == False:
				diff_lines.append([a, b])
		return diff_lines

	@staticmethod
	def patch(func_a, func_b):
		if func_a:
			patch = FuncPatch(func_b, ModifiedFuncType());
		else:
			patch = FuncPatch(func_b, NewFuncType());

		if func_a:
			if func_a.size == func_b.size:
				lines_pairs = ElfFunction.compare_content(func_a, func_b)
				if not lines_pairs:
					print "\t%s: Content is equal" % func_a.funcname
					return None

				print "\t%s: content differs" % func_a.funcname
				for pair in lines_pairs:
					print "\t\tlines differ:\n\t\t\t%s\n\t\t\t%s" % (pair[0].line, pair[1].line)
					patch.add_line(pair[0], pair[1])
			else:
				print "\t%s: size differs" % func_a.funcname

		return patch

