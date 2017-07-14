import os
from abc import ABCMeta, abstractmethod

from elftools.elf import elffile

import binpatch_pb2
from build_id import get_build_id
from funcjump import FuncJump
import markedsym_pb2
import staticsym_pb2
import static_symbol

from sym_resolver import ManualSymResolver, GlobalSymResolver

class BinPatch:
	__metaclass__ = ABCMeta

	def __init__(self, bf_old, bf_new, obj_files, patchfile, mode):
		self.bf_old = bf_old
		self.bf_new = bf_new
		self.obj_files = [elffile.ELFFile(open(fn)) for fn in obj_files] 
		self.patchfile = patchfile
		self.mode = mode
		self.common_func = []

		old_func = self.bf_old.functions
		new_func = self.bf_new.functions

		common_func = list(set(old_func.keys()) & set(new_func.keys()))
		for name in common_func:
			fj = FuncJump(name, old_func[name], new_func[name])
			self.common_func.append(fj)

	def applicable(self):
		if self.bf_new.header.type != 'ET_DYN':
			print "Wrong object file type: %s" % self.bf_new.header.type
			print "Only shared object patches are supported"
			return False

		if not self.common_func:
			print "Nothing to patch"
			return False

		unapplicable_functions = False
		for fj in self.common_func:
			if not fj.applicable():
				unapplicable_functions = True

		if unapplicable_functions:
			return False

		print "\n*************************************************"
		print "***************** Functions *********************"
		print "*************************************************\n"

		print "Common functions:"
		for fj in self.common_func:
			fj.show()

		return True

	def __auto_patch_info__(self, pi):
		print "\nResolving static symbols:"
		static_sym_info = static_symbol.resolve(self.bf_old.elf.elf,
				self.bf_new.elf.elf, self.obj_files)
		pi.static_symbols.extend(staticsym_pb2.StaticSym(
			patch_size=size, patch_address=addr, target_value=value)
				for size, addr, value in static_sym_info)

	def __manual_patch_info__(self, pi):
		print "\nResolving marked symbols"
		msr = ManualSymResolver(self.bf_old.elf, self.bf_new.elf)
		manual_sym_info = msr.resolve()
		pi.manual_symbols.extend(
			markedsym_pb2.MarkedSym(idx=idx, addr=addr)
				for idx, addr in manual_sym_info)

	def patch_info(self):
		print "\n*************************************************"
		print "***************** Patch info ********************"
		print "*************************************************\n"

		pi = binpatch_pb2.BinPatch()

		pi.old_bid = get_build_id(self.bf_old.filename)
		pi.new_bid = get_build_id(self.bf_new.filename)

		print "Header:"
		print "  Target BuildId: %s" % pi.old_bid
		print "  Patch BuildId : %s" % pi.new_bid

		if self.patchfile:
			pi.new_path = self.bf_new.filename
			print "  Patch path    : %s" % pi.new_path

		print "\nFunction jumps:"
		for fj in self.common_func:
			funcjump = fj.patch_info()
			pi.func_jumps.extend([funcjump])

		print "\nResolving global symbols"
		gsr = GlobalSymResolver(self.bf_old.elf, self.bf_new.elf)
		global_sym_info = gsr.resolve()
		pi.global_symbols.extend(
			markedsym_pb2.MarkedSym(idx=idx, addr=addr)
				for idx, addr in global_sym_info)

		if self.mode == "manual":
			self.__manual_patch_info__(pi)
		elif self.mode == "auto":
			self.__auto_patch_info__(pi)
		else:
			print "Unknown patch mode: \"%s\"" % self.mode


		return pi

	def write(self):
		if self.patchfile:
			filename = self.patchfile
		else:
			filename = self.bf_new.filename + ".patchinfo"

		pfile = os.open(filename, os.O_CREAT | os.O_WRONLY | os.O_TRUNC)

		pi = self.patch_info()

		data = pi.SerializeToString()

		os.write(pfile, data)
		print "Written %d bytes to %s" % (len(data), filename)

		if self.patchfile is None:
			self.bf_new.add_section("vzpatch", filename)
			os.unlink(filename)
			print "Temporary file %s removed" % filename
