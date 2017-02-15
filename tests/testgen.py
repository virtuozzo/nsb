import argparse
import os
import re
from testrunner import Test

parser = argparse.ArgumentParser()
parser.add_argument("name", help="Test name")
parser.add_argument("--outfile", help="Output test file")
args = parser.parse_args()

split = re.split('_to_|_|.py', os.path.basename(args.name))

source = split[0] + '_' + split[1]
target = split[2] + '_' + split[3]
src_type = split[0]
tgt_type = split[2]

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
	"exit(testrunner.%sLivePatchTest('%s', '%s', %u, %u).run())\n" %	\
	(tst_type, source, target, src_ret, tgt_ret)

f = os.open(outfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
os.write(f, code)
