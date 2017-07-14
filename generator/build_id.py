from elffile import ElfFile
from elftools.common.exceptions import ELFError

def get_build_id(path):
	with open(path, 'rb') as stream:
		build_id = None
		try:
			build_id = ElfFile(stream).build_id()
		except ELFError:
			print "%s is not an ELF file" % path
		return build_id

def print_build_id(args):
	try:
		build_id = get_build_id(args.file)
		if build_id:
			print build_id
			return 0
	except IOError as e:
		print e
	return 1
