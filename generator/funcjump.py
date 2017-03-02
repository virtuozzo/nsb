import funcjump_pb2

class FuncJump:
	def __init__(self, name, func, patch):
		self.name = name
		self.func_value = func.value
		self.func_size = func.size
		self.patch_value = patch.value
		self.patch_size = patch.size

	def show(self):
		print "\t%s: %#x-%#x ---> %#x-%#x" % (self.name,
				self.func_value, self.func_size,
				self.patch_value, self.patch_size)

	def patch_info(self):
		fj = funcjump_pb2.FuncJump()
		fj.name = self.name
		fj.func_value = self.func_value
		fj.func_size = self.func_size
		fj.patch_value = self.patch_value
		print "  %s: func_value: %#x, func_size: %d, patch_value: %#x" % (self.name, fj.func_value, fj.func_size, fj.patch_value)
		return fj
