from funcpatch import FuncPatch
from binfile import BinFile
from binpatch import StaticBinPatch, SharedBinPatch
from function import ElfFunction, DumpLine

def gen_patch(args):
	print "ELF A: %s" % args.elfa
	bfa = BinFile(args.elfa)
	print "ELF B: %s" % args.elfb
	bfb = BinFile(args.elfb)

	print args.patchdir
	print args.outfile

	if bfa.header.type == 'ET_DYN':
		binpatch = SharedBinPatch(bfa, bfb, args.patchdir, args.outfile)
	else:
		binpatch = StaticBinPatch(bfa, bfb, args.patchdir, args.outfile)

	binpatch.create()

	print "Common functions: %s" % binpatch.common_func
	print "Removed functions: %s" % binpatch.removed_func
	print "New functions: %s " % binpatch.new_func

	print "Common objects: %s" % binpatch.common_obj
	print "Removed objects: %s" % binpatch.removed_obj
	print "New objects: %s " % binpatch.new_obj

	print "Common dynamic functions: %s" % binpatch.common_dyn_func
	print "New dynamic functions: %s " % binpatch.new_dyn_func

	print "Common dynamic objects: %s" % binpatch.common_dyn_obj
	print "New dynamic objects: %s " % binpatch.new_dyn_obj

	for nf in binpatch.new_func:
		print "---------------------------------"
		ns = binpatch.bf_new.functions[nf].start
		print "New function %s start: %s" % (nf, ns)

	for rf in binpatch.removed_func:
		rs = binpatch.bf_old.functions[rf].start
		print "Removed function %s start: %s" % (rf, rs)

	#######################

	if binpatch.bf_old.functions == binpatch.bf_new.functions:
		print "Binaries function attribues are equal\n"
	else:
		print "Binaries function attribues differ\n"

	new_functions = []

	for name in binpatch.common_func:
		a = bfa.functions[name]
		b = bfb.functions[name]
		patch = ElfFunction.patch(a, b, bfb.header.type)
		if patch:
			binpatch.patches_list.append(patch)

	for name in binpatch.new_func:
		b = bfb.functions[name]
		patch = ElfFunction.patch(None, b, bfb.header.type)
		if patch:
			binpatch.patches_list.append(patch)
		new_functions.append(bfb.functions[name])


	#print "\n*************************************************"
	#print "*************** New functions *******************"
	#print "*************************************************\n"

	#for f in new_functions:
	#	print "Function name: %s" % f.funcname
	#	f.show()
	#	f.analize()

	print "\n*************************************************"
	print "****************** Patches **********************"
	print "*************************************************\n"

	binpatch.analize()
	if not binpatch.applicable:
		exit(1)

	print "\nPatch is applicable\n"
	print "SUCCESS"

	binpatch.write()


