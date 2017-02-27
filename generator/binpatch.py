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
		self.removed_func = []
		self.new_func = []
		self.modified_func = []

		self.common_obj = []
		self.removed_obj = []
		self.new_obj = []
		self.patches_list = []

		self.applicable = False

	def create(self):
		if self.bf_old.header.type != self.bf_new.header.type:
			print "Binaries have different object types: %s != %s" %	\
				(self.bf_old.header.type, self.bf_new.header.type)
			print "Not supported."
			raise

		if self.bf_old:
			old_func = self.bf_old.functions
			old_obj = self.bf_old.objects
			old_dyn_func = self.bf_old.dyn_functions
			old_dyn_obj = self.bf_old.dyn_objects

		new_func = self.bf_new.functions
		self.common_func = list(set(old_func.keys()) & set(new_func.keys()))
		self.removed_func = list(set(old_func.keys()) - set(new_func.keys()))
		self.new_func = list(set(new_func.keys()) - set(old_func.keys()))

		new_obj = self.bf_new.objects
		self.common_obj = list(set(old_obj.keys()) & set(new_obj.keys()))
		self.removed_obj = list(set(old_obj.keys()) - set(new_obj.keys()))
		self.new_obj = list(set(new_obj.keys()) - set(old_obj.keys()))

		new_dyn_func = self.bf_new.dyn_functions
		self.common_dyn_func = list(set(old_dyn_func.keys()) & set(new_dyn_func.keys()))
		self.new_dyn_func = list(set(new_dyn_func.keys()) - set(old_dyn_func.keys()))

		new_dyn_obj = self.bf_new.dyn_objects
		self.common_dyn_obj = list(set(old_dyn_obj.keys()) & set(new_dyn_obj.keys()))
		self.new_dyn_obj = list(set(new_dyn_obj.keys()) - set(old_dyn_obj.keys()))

	@abstractmethod
	def __applicable__(self, p): pass

	def analize(self):
		if not self.patches_list:
			print "Nothing to patch"
			exit(0)

		# This has to be done differently. Function object has to be
		# marked as modified instead of redundant "modified" list.
		for p in self.patches_list:
			if p.func_b.funcname in self.common_func:
				self.common_func.remove(p.func_b.funcname)
				self.modified_func.append(p.func_b.funcname)
				print "Modified function: %s" % p.func_b.funcname

		for p in self.patches_list:
			print "*************************************************\n"
			p.show()
			self.applicable = self.__applicable__(p)
			if not self.applicable:
				return

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

		for patch in self.patches_list:
			code = self.bf_new.function_code(patch.func_b.start,
							 patch.func_b.size)
			fpatch = patch.get_patch(code)
			image.patches.extend([fpatch])

		print "\nimage.new_relocations:"
		for name, rp in self.bf_new.rela_plt.iteritems():
			if self.bf_new.dynsym_by_name(name).bind == "STB_WEAK":
				continue
			if rp.info_type == "R_X86_64_RELATIVE":
				continue
			rpi = image.relocations.add()
			rpi.name = name
			rpi.info_type = rp.info_type
			rpi.offset = rp.offset
			rpi.addend = rp.addend
			rpi.hint = 0
			rpi.path = ""
			if rp.info_type != "R_X86_64_GLOB_DAT":
				try:
					rpo = self.bf_old.rela_plt[name]
					if rpo.addend:
						rpi.hint = rpo.addend
						rpi.path = self.bf_old.filename
				except:
					pass
			print "  %s: type: %s, offset: %#x, addend: %#x, hint: %#x, path: %s" % \
				(rpi.name, rpi.info_type, rpi.offset, rpi.addend, rpi.hint, rpi.path)

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

		print "\nimage.datasym:"
		for name in self.common_obj:
			if self.bf_old.objects[name].size != self.bf_new.objects[name].size:
				print "Object %s has different size: %d != %d" % (name, self.bf_old.objects[name].size, self.bf_new.objects[name].size)
				raise
			if self.bf_old.objects[name].size == 0:
				continue

			if "." in name:
				continue

			li = image.local_vars.add()
			li.name = name
			li.size = self.bf_new.objects[name].size
			li.offset = self.bf_new.objects[name].value
			li.ref = self.bf_old.objects[name].value
			print "  %s: size: %d, offset: %#x, ref: %#x" % (li.name, li.size, li.offset, li.ref)

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


class StaticBinPatch(BinPatch):
	def __init__(self, bf_old, bf_new, patchfile):
		BinPatch.__init__(self, bf_old, bf_new, patchfile)

	def create(self):
		if self.bf_old.read_rodata() != self.bf_new.read_rodata():
			print "Binaries have different .rodata segments."
			print "Not supported."
			raise
		BinPatch.create(self)

	def __applicable__(self, p):
		p.analize()
		for ci in p.code_info:
			if ci.command_info.is_jump:
				if ci.access_name in self.common_func:
					ci.access_addr = self.bf_old.functions[ci.access_name].start 
					print "%s to COMMON function: '%s', '%s', '0x%x'" % (ci.command_info.name, ci.access_name, ci.access_plt, ci.access_addr)
				elif ci.access_name in self.modified_func:
					print "%s to MODIFIED function: '%s', '%s', '0x%x'" % (ci.command_info.name, ci.access_name, ci.access_plt, ci.access_addr)
				elif ci.access_name in self.common_dyn_func:
					ci.access_addr = self.bf_old.dyn_functions[ci.access_name].start 
					print "%s to COMMON PLT function: '%s', '%s', '0x%x'" % (ci.command_info.name, ci.access_name, ci.access_plt, ci.access_addr)
				else:
					print "%s to NEW function: '%s', '%s'" % (ci.command_info.name, ci.access_name, ci.access_plt)
					if ci.access_plt and self.bf_old.header.type != 'ET_DYN':
						print "New PLT entry.\nUnsupported"
						return False
			else:
				if ci.access_name in self.common_obj:
					ci.access_addr = self.bf_old.objects[ci.access_name].value
					print "Access to COMMON object: '%s', '%s'" % (ci.access_addr, ci.access_name)
				elif ci.access_name in self.common_func:
					ci.access_addr = self.bf_old.functions[ci.access_name].start
					print "Access to COMMON function: '%s', '%s'" % (ci.access_addr, ci.access_name)
				else:
					print "Access to NEW object: '%s', '%s'" % (ci.access_addr, ci.access_name)
					ci.show()
					print "Unsupported"
					return False
		return True


class SharedBinPatch(BinPatch):
	def __init__(self, bf_old, bf_new, patchfile):
		BinPatch.__init__(self, bf_old, bf_new, patchfile)

	def __applicable__(self, p):
		return True
