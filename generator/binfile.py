import sys
import os
import tempfile

from elftools.elf.elffile import ELFFile

from elffile import get_build_id
import util

class BinFile:
	def __init__(self, filename, debug_filename=None, keep_merged=False):
		fn_list = [filename]
		if debug_filename is not None:
			fn_list.append(debug_filename)
		for fn in fn_list:
			if not os.access(fn, os.R_OK):
				print "File %s doesn't exist" % fn
				sys.exit(1)

		self.filename = os.path.realpath(filename)
		self.debug_filename = debug_filename
		self.keep_merged = keep_merged

		self._merge_debuginfo()

	def _merge_debuginfo(self):
		elf = ELFFile(open(self.filename, 'rb'))
		if self.debug_filename:
			bid = get_build_id(elf)

			with open(self.debug_filename, 'rb') as debug_stream:
				debug_bid = get_build_id(ELFFile(debug_stream))

			if bid != debug_bid:
				print "Build ID mismatch between input ELFs"
				sys.exit(1)

			merge_filename = tempfile.mktemp(
				prefix=os.path.basename(self.filename) + '-')
			if self.keep_merged:
				print "Merged ELF:", merge_filename
			cmd = 'eu-unstrip -o %s %s %s' % (merge_filename,
					self.filename, self.debug_filename)
			util.system_exc(cmd)

			self.elf = ELFFile(open(merge_filename, 'rb'))
			if not self.keep_merged:
				os.unlink(merge_filename)
		else:
			self.elf = elf

	def add_section(self, sname, filename):
		cmd = "objcopy --remove-section=%s %s" % (sname, self.filename)
		util.system_exc(cmd)
		print "Removed old \"%s\" ELF section from %s" % (sname, self.filename)
		cmd = "objcopy --add-section %s=%s %s" % (sname, filename, self.filename)
		util.system_exc(cmd)
		print "Added %s as ELF section \"%s\" to %s" % (filename, sname, self.filename)
