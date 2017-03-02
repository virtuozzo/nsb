import os
from abc import ABCMeta, abstractmethod

import binpatch_pb2
from build_id import get_build_id

class BinPatch:
	__metaclass__ = ABCMeta

	def __init__(self, bf_old, bf_new, patchfile):
		self.bf_old = bf_old
		self.bf_new = bf_new
		self.patchfile = patchfile

		self.common_func = []

		self.applicable = True

	def create(self):
		old_func = self.bf_old.functions
		new_func = self.bf_new.functions

		self.common_func = list(set(old_func.keys()) & set(new_func.keys()))

	def analize(self):
		if self.bf_old.header.type != self.bf_new.header.type:
			print "Binaries have different object types: %s != %s" %	\
				(self.bf_old.header.type, self.bf_new.header.type)
			print "Not supported."
			raise

		for k, s in self.bf_new.objects.iteritems():
			if k.startswith("completed."):
				continue
			if s.size != 0:
				print "Patch has object \"%s\" with size: %d" % (k, s.size)
				print "Patch with data objects (variables) are not supported"
				print self.bf_new.objects
				raise

		if not self.common_func:
			print "Nothing to patch"
			exit(0)

	def get_patch(self):
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
		for name in self.common_func:
			fj = image.func_jumps.add()
			fj.name = name
			fj.func_value = self.bf_old.functions[name].value
			fj.func_size = self.bf_old.functions[name].size
			fj.patch_value = self.bf_new.functions[name].value
			print "  %s: func_value: %#x, func_size: %d, patch_value: %#x" % (name, fj.func_value, fj.func_size, fj.patch_value)

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
