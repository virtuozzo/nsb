import sys
sys.path.append('./protobuf')

import argparse
parser = argparse.ArgumentParser()
parser.add_argument("elfa", help="Old ELF file")
parser.add_argument("elfb", help="New ELF file")
parser.add_argument("patchdir", help="New ELF file")
args = parser.parse_args()

from funcpatch import FuncPatch
from binfile import BinFile
from binpatch import BinPatch
from function import ElfFunction, DumpLine


print "ELF A: %s" % args.elfa
bfa = BinFile(args.elfa)
print "ELF B: %s" % args.elfb
bfb = BinFile(args.elfb)

binpatch = BinPatch(bfa, bfb, args.patchdir)
binpatch.create()

print "Common functions: %s" % binpatch.common_func
print "Removed functions: %s" % binpatch.removed_func
print "New functions: %s " % binpatch.new_func

print "Common objects: %s" % binpatch.common_obj
print "Removed objects: %s" % binpatch.removed_obj
print "New objects: %s " % binpatch.new_obj

for nf in binpatch.new_func:
	print "---------------------------------"
	ns = binpatch.bf_new.functions_dict()[nf].start
	print "New function %s start: %s" % (nf, ns)

for rf in binpatch.removed_func:
	rs = binpatch.bf_old.functions_dict()[rf].start
	print "Removed function %s start: %s" % (rf, rs)

#######################

if binpatch.bf_old.functions_dict() == binpatch.bf_new.functions_dict():
	print "Binaries function attribues are equal\n"
else:
	print "Binaries function attribues differ\n"

new_functions = []

for name in binpatch.common_func:
	a = bfa.functions_dict()[name]
	b = bfb.functions_dict()[name]
	patch = ElfFunction.patch(a, b)
	if patch:
		binpatch.patches_list.append(patch)

for name in binpatch.new_func:
	b = bfb.functions_dict()[name]
	patch = ElfFunction.patch(None, b)
	if patch:
		binpatch.patches_list.append(patch)
	new_functions.append(bfb.functions_dict()[name])


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

exit(0)
