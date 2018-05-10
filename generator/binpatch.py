import os

from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_E_TYPE
from elftools.elf.enums import ENUM_E_MACHINE

from consts import *
from elffile import get_build_id
import static_symbol
import patch_symbol

MIN_FUNC_SIZE		= 8

set_const_str(ENUM_E_TYPE)

class BinPatch:
	def __init__(self, bf_old, bf_new, obj_files, patchfile, mode):
		bf_new_type = bf_new.elf.header.e_type 
		if bf_new_type != STR.ET_DYN:
			print "Wrong object file type: %s" % bf_new_type
			raise Exception("Only shared object patches are supported")

		self.bf_old = bf_old
		self.bf_new = bf_new

		self.obj_files = [ELFFile(open(fn)) for fn in obj_files] 
		self.patchfile = patchfile
		self.mode = mode

		self.get_patch_info()

	def get_patch_info(self):
		if self.mode == "manual":
			pi = patch_symbol.resolve(self.bf_old.elf, self.bf_new.elf)
		elif self.mode == "auto":
			raise Exception("Not implemented")
		else:
			print "Unknown patch mode: \"%s\"" % self.mode

		if not pi.func_jumps:
			raise Exception("No functions to patch")

		for fj in pi.func_jumps:
			if fj.func_size < MIN_FUNC_SIZE:
				raise Exception("Function '%s' size less than minimal: %d < %d" %
							fj.name, fj.func_size, MIN_FUNC_SIZE)

		print "\n*************************************************"
		print "***************** Patch info ********************"
		print "*************************************************\n"

		pi.old_bid = get_build_id(self.bf_old.elf)
		pi.new_bid = get_build_id(self.bf_new.elf)

		pi.new_arch_type = self.bf_new.elf.header.e_machine

		print "Header:"
		print "  Target BuildId: %s" % pi.old_bid
		print "  Patch BuildId : %s" % pi.new_bid
		print "  Architecture on which patch is built : %s" % pi.new_arch_type

		if self.patchfile:
			pi.new_path = self.bf_new.filename
			print "  Patch path    : %s" % pi.new_path

		self.pi = pi

	def write(self):
		if self.patchfile:
			filename = self.patchfile
		else:
			filename = self.bf_new.filename + ".patchinfo"

		pfile = os.open(filename, os.O_CREAT | os.O_WRONLY | os.O_TRUNC)

		data = self.pi.SerializeToString()

		os.write(pfile, data)
		print "Written %d bytes to %s" % (len(data), filename)

		if self.patchfile is None:
			self.bf_new.add_section("vzpatch", filename)
			os.unlink(filename)
			print "Temporary file %s removed" % filename
