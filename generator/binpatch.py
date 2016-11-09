import os

import binpatch_pb2

class BinPatch:

	def __init__(self, bf_old, bf_new, patchdir):
		self.bf_old = bf_old
		self.bf_new = bf_new
		self.patchdir = patchdir
		self.common_func = []
		self.removed_func = []
		self.new_func = []
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

		new_func = self.bf_new.functions_dict()
		self.common_func = list(set(old_func.keys()) & set(new_func.keys()))
		self.removed_func = list(set(old_func.keys()) - set(new_func.keys()))
		self.new_func = list(set(new_func.keys()) - set(old_func.keys()))

		new_obj = self.bf_new.objects_dict()
		self.common_obj = list(set(old_obj.keys()) & set(new_obj.keys()))
		self.removed_obj = list(set(old_obj.keys()) - set(new_obj.keys()))
		self.new_obj = list(set(new_obj.keys()) - set(old_obj.keys()))

	def analize(self):
		if not self.patches_list:
			print "Nothing to patch"
			exit(0)

		for p in self.patches_list:
			print "*************************************************\n"
			p.show()
			p.analize()
			for ci in p.code_info:
				if ci.command_type.name == "call" or ci.command_type.name == "jmp":
					if ci.access_name in self.common_func:
						print "Call/jmpq to COMMON function: '%s', '%s'" % (ci.access_name, ci.access_plt)
					else:
						print "Call/jmpq to NEW function: '%s', '%s'" % (ci.access_name, ci.access_plt)
						ci.access_new = True
						ci.show()
						if ci.access_plt:
							print "New call/jmpq to PLT entry.\nUnsupported"
							return

				elif ci.command_type.name == "var":
					if ci.access_name in self.common_obj:
						print "Access to COMMON object: '%s', '%s'" % (ci.access_addr, ci.access_name)
					else:
						ci.access_new = True
						ci.show()
#						print "Access to NEW object: '%s', '%s'" % (ci.access_addr, ci.access_name)
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
		filename = self.patchdir + "/" + self.name + ".patch"
		pfile = os.open(filename, os.O_CREAT | os.O_WRONLY)

		image = self.get_patch()

		data = image.SerializeToString()

		os.write(pfile, data)
		print "Written %d bytes to %s" % (len(data), filename)


