import sys

from binfile import BinFile
from binpatch import BinPatch

def gen_patch(args):
	print "ELF A: %s" % args.elfa,
	if args.debugfile:
		print "+", args.debugfile
	else:
		print ""

	bfa = BinFile(args.elfa, args.debugfile, args.keep_merged)

	print "ELF B: %s" % args.elfb
	bfb = BinFile(args.elfb)

	if args.outfile:
		print "Out file: %s" % args.outfile

	if bfa.header.type != 'ET_DYN':
		print "Only ET_DYN patch creation is supported"

	binpatch = BinPatch(bfa, bfb, args.outfile)

	if not binpatch.applicable():
		print "Can't apply patch"
		sys.exit(1)

	binpatch.write()

	print "SUCCESS"
