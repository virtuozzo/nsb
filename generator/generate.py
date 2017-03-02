from binfile import BinFile
from binpatch import BinPatch

def gen_patch(args):
	print "ELF A: %s" % args.elfa
	bfa = BinFile(args.elfa)
	print "ELF B: %s" % args.elfb
	bfb = BinFile(args.elfb)

	if args.outfile:
		print "Out file: %s" % args.outfile

	if bfa.header.type != 'ET_DYN':
		print "Only ET_DYN patch creation is supported"

	binpatch = BinPatch(bfa, bfb, args.outfile)
	binpatch.create()

	print "Common functions: %s" % binpatch.common_func

	if binpatch.bf_old.functions == binpatch.bf_new.functions:
		print "Binaries function attribues are equal\n"
	else:
		print "Binaries function attribues differ\n"

	print "\n*************************************************"
	print "****************** Patches **********************"
	print "*************************************************\n"

	binpatch.analize()
	if not binpatch.applicable:
		exit(1)

	print "\nPatch is applicable\n"

	binpatch.write()

	print "SUCCESS"
