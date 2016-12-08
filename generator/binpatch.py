import os

import binpatch_pb2

class BinPatch:

	def __init__(self, bf_old, bf_new, patchdir, patchfile):
		self.bf_old = bf_old
		self.bf_new = bf_new
		self.patchdir = patchdir
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
		self.name = os.path.basename(self.bf_old.filename)

	def create(self):
		if self.bf_old.read_rodata() != self.bf_new.read_rodata():
			print "Binaries have different .rodata segments."
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

	def __static_code_is_applicable__(self, p):
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
					ci.show()
					if ci.access_plt:
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
			self.applicable = self.__static_code_is_applicable__(p)
			if not self.applicable:
				return

	def get_patch(self):
		image = binpatch_pb2.BinPatch()

		image.old_path = self.bf_old.filename
		image.new_path = self.bf_new.filename
		image.object_type = self.bf_old.header.type

		print "image.old_path   : %s" % image.old_path
		print "image.new_path   : %s" % image.new_path
		print "image.object_type: %s" % image.object_type

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

		return image

	def write(self):
		if self.patchfile:
			filename = self.patchfile
		else:
			filename = self.patchdir + "/" + self.name + ".patch"

		pfile = os.open(filename, os.O_CREAT | os.O_WRONLY | os.O_TRUNC)

		image = self.get_patch()

		data = image.SerializeToString()

		os.write(pfile, data)
		print "Written %d bytes to %s" % (len(data), filename)


