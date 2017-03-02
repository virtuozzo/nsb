import os
from abc import ABCMeta, abstractmethod

import binpatch_pb2
from build_id import get_build_id
from funcjump import FuncJump

class BinPatch:
	__metaclass__ = ABCMeta

	def __init__(self, bf_old, bf_new, patchfile):
		self.bf_old = bf_old
		self.bf_new = bf_new
		self.patchfile = patchfile
		self.common_func = []

		old_func = self.bf_old.functions
		new_func = self.bf_new.functions

		common_func = list(set(old_func.keys()) & set(new_func.keys()))
		for name in common_func:
			fj = FuncJump(name, old_func[name], new_func[name])
			self.common_func.append(fj)

	def applicable(self):
		if self.bf_old.header.type != self.bf_new.header.type:
			print "Binaries have different object types: %s != %s" %	\
				(self.bf_old.header.type, self.bf_new.header.type)
			print "Not supported."
			return False

		for k, s in self.bf_new.objects.iteritems():
			if k.startswith("completed."):
				continue
			if s.size != 0:
				print "Patch has object \"%s\" with size: %d" % (k, s.size)
				print "Patch with data objects (variables) are not supported"
				print self.bf_new.objects
				return False

		if not self.common_func:
			print "Nothing to patch"
			return False

		print "\n*************************************************"
		print "***************** Functions *********************"
		print "*************************************************\n"

		print "Common functions:"
		for fj in self.common_func:
			fj.show()

		return True

	def get_patch(self):
		print "\n*************************************************"
		print "***************** Patch info ********************"
		print "*************************************************\n"

		image = binpatch_pb2.BinPatch()

		image.object_type = self.bf_old.header.type
		image.old_bid = get_build_id(self.bf_old.filename)
		image.new_bid = get_build_id(self.bf_new.filename)

		print "image.object_type: %s" % image.object_type
		print "image.old_bid    : %s" % image.old_bid
		print "image.new_bid    : %s" % image.new_bid

		if self.patchfile:
			image.new_path = self.bf_new.filename
			print "image.new_path   : %s" % image.new_path

		print "\nimage.new_segments:"
		for s in self.bf_new.segments:
			si = image.new_segments.add()
			si.type    = s.type;
			si.offset  = s.offset;
			si.vaddr   = s.vaddr;
			si.paddr   = s.paddr;
			si.mem_sz  = s.mem_sz;
			si.flags   = s.flags;
			si.align   = s.align;
			si.file_sz = s.file_sz;
			print "  %s: offset: %#x, vaddr: %#x, paddr: %#x, mem_sz: %#x, flags: %#x, align: %#x, file_sz: %#x" %  \
				(si.type, si.offset, si.vaddr, si.paddr, si.mem_sz, si.flags, si.align, si.file_sz)

		print "\nimage.funcjumps:"
		for fj in self.common_func:
			funcjump = fj.get_patch()
			image.func_jumps.extend([funcjump])

		print"\n"
		return image

	def write(self):
		if self.patchfile:
			filename = self.patchfile
		else:
			filename = "./" + os.path.basename(self.bf_old.filename) + ".patchinfo"

		pfile = os.open(filename, os.O_CREAT | os.O_WRONLY | os.O_TRUNC)

		image = self.get_patch()

		data = image.SerializeToString()

		os.write(pfile, data)
		print "Written %d bytes to %s" % (len(data), filename)

		if self.patchfile is None:
			self.bf_new.add_section("vzpatch", filename)
			os.unlink(filename)
			print "Temporary file %s removed" % filename
