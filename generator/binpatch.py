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
		if self.bf_old:
			old_func = self.bf_old.functions_dict()
			old_obj = self.bf_old.objects_dict()
			old_dyn_func = self.bf_old.dyn_functions_dict()
			old_dyn_obj = self.bf_old.dyn_objects_dict()

		new_func = self.bf_new.functions_dict()
		self.common_func = list(set(old_func.keys()) & set(new_func.keys()))
		self.removed_func = list(set(old_func.keys()) - set(new_func.keys()))
		self.new_func = list(set(new_func.keys()) - set(old_func.keys()))

		new_obj = self.bf_new.objects_dict()
		self.common_obj = list(set(old_obj.keys()) & set(new_obj.keys()))
		self.removed_obj = list(set(old_obj.keys()) - set(new_obj.keys()))
		self.new_obj = list(set(new_obj.keys()) - set(old_obj.keys()))

		new_dyn_func = self.bf_new.dyn_functions_dict()
		self.common_dyn_func = list(set(old_dyn_func.keys()) & set(new_dyn_func.keys()))
		self.new_dyn_func = list(set(new_dyn_func.keys()) - set(old_dyn_func.keys()))

		new_dyn_obj = self.bf_new.dyn_objects_dict()
		self.common_dyn_obj = list(set(old_dyn_obj.keys()) & set(new_dyn_obj.keys()))
		self.new_dyn_obj = list(set(new_dyn_obj.keys()) - set(old_dyn_obj.keys()))

	def analize(self):
		if not self.patches_list:
			print "Nothing to patch"
			exit(0)

		# This has to be done differently. Function object has to be
		# marked as modified instead of redundant "modified" list.
		for p in self.patches_list:
			if p.function.funcname in self.common_func:
				self.common_func.remove(p.function.funcname)
				self.modified_func.append(p.function.funcname)
				print "Modified function: %s" % p.function.funcname

		for p in self.patches_list:
			print "*************************************************\n"
			p.show()
			p.analize()
			for ci in p.code_info:
				if ci.command_info.is_jump:
					if ci.access_name in self.common_func:
						ci.access_addr = self.bf_old.functions_dict()[ci.access_name].start 
						print "%s to COMMON function: '%s', '%s', '0x%x'" % (ci.command_info.name, ci.access_name, ci.access_plt, ci.access_addr)
					elif ci.access_name in self.modified_func:
						print "%s to MODIFIED function: '%s', '%s', '0x%x'" % (ci.command_info.name, ci.access_name, ci.access_plt, ci.access_addr)
					elif ci.access_name in self.common_dyn_func:
						ci.access_addr = self.bf_old.dyn_functions_dict()[ci.access_name].start 
						print "%s to COMMON PLT function: '%s', '%s', '0x%x'" % (ci.command_info.name, ci.access_name, ci.access_plt, ci.access_addr)
					else:
						print "%s to NEW function: '%s', '%s'" % (ci.command_info.name, ci.access_name, ci.access_plt)
						ci.show()
						if ci.access_plt:
							print "New PLT entry.\nUnsupported"
							return
				else:
					if ci.access_name in self.common_obj:
						ci.access_addr = int(self.bf_old.objects_dict()[ci.access_name].value, 16)
						print "Access to COMMON object: '%s', '%s'" % (ci.access_addr, ci.access_name)
					elif ci.access_name in self.common_func:
						ci.access_addr = self.bf_old.functions_dict()[ci.access_name].start
						print "Access to COMMON function: '%s', '%s'" % (ci.access_addr, ci.access_name)
					else:
						print "Access to NEW object: '%s', '%s'" % (ci.access_addr, ci.access_name)
						ci.show()
						print "Unsupported"
						return
		self.applicable = True

	def get_patch(self):
		image = binpatch_pb2.BinPatch()
		image.name = self.name

		src = os.open(self.bf_new.filename, os.O_RDONLY)

		for patch in self.patches_list:
			pos = os.lseek(src, patch.function.file_offset, os.SEEK_SET)
			code = os.read(src, patch.function.size)

			fpatch = patch.get_patch(code)
			image.patches.extend([fpatch])

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


