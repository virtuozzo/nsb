import argparse
import os
import re
from testrunner import Test

parser = argparse.ArgumentParser()
parser.add_argument("source", help="Source binary test")
parser.add_argument("target", help="Target binary test")
parser.add_argument("--outfile", help="Output test file")
args = parser.parse_args()

source = args.source
target = args.target

src_type = re.search('[^_]+', os.path.basename(source)).group(0)
tgt_type = re.search('[^_]+', os.path.basename(target)).group(0)

if src_type == "shared":
	tst_type = "Shared"
elif src_type == "static":
	tst_type = "Static"
else:
	print "Unsupported test type: %s" % src_type

if src_type != tgt_type:
	print "Tests must have equal types: %s != %s" % (src_type, tgt_type)
	raise

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
