import argparse
import os
import re
from testrunner import Test

parser = argparse.ArgumentParser()
parser.add_argument("name", help="Test name")
parser.add_argument("--outfile", help="Output test file")
args = parser.parse_args()

if args.name.endswith('.py'):
    args.name = args.name[:-3]

test_name = os.path.basename(args.name)
patch_type = "jump"

if "__" in test_name:
	split = re.split('__', os.path.basename(args.name))
	test_name = split[0]
	patch_type = split[1]

if patch_type != "jump" and patch_type != "swap":
	print "Unsupported patch type: %s" % patch_type
	exit(1)


split = re.split('_to_', test_name)

source = split[0]
target = split[1]

src_type = re.split('_', source)[0]
tgt_type = re.split('_', target)[0]

if src_type != tgt_type:
	print "Tests must have equal types: %s != %s" % (src_type, tgt_type)
	exit(1)

if src_type == "shared":
	tst_type = "Shared"
elif src_type == "static":
	tst_type = "Static"
else:
	print "Unsupported test type: %s" % src_type
	exit(1)

outfile = args.outfile
if outfile is None:
	outfile = "%s_to_%s.py" % (source, target)

tests_dir = os.environ.get('TESTS_DIR')
if not os.path.isabs(source) and tests_dir:
	source = tests_dir + "/" + source
if not os.path.isabs(target) and tests_dir:
	target = tests_dir + "/" + target

src_ret = Test(source).run()
tgt_ret = Test(target).run()

code =	"#!/usr/bin/env python2\n" +						\
	"import os\n" +								\
	"import testrunner\n\n" +						\
	"os.environ['PYTHONPATH'] = os.getcwd() + \"/protobuf\"\n" +		\
	"exit(testrunner.%sLivePatchTest('%s', '%s', '%s', %u, %u).run())\n" %	\
	(tst_type, source, target, patch_type, src_ret, tgt_ret)

f = os.open(outfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
os.write(f, code)
