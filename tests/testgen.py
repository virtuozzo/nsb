import argparse
import os
import re
from testrunner import Test

def get_test_type(test_name):
	from nsb_test_types import NSB_TEST_TYPES

	test_item = "TEST_TYPE_" + test_name.upper()
	return NSB_TEST_TYPES[test_item]

parser = argparse.ArgumentParser()
parser.add_argument("name", help="Test name")
args = parser.parse_args()

outfile = args.name

if args.name.endswith('.py'):
    args.name = args.name[:-3]

test_name, test_type = os.path.basename(args.name).split('__', 1)

if test_type == "library":
	source = "nsbtest_library"
else:
	print "Unsupported test type: \"%s\"" % test_type
	exit(1)

target = "patch_" + test_name + ".so"
test_type = get_test_type(test_name)

code =	"#!/usr/bin/env python2\n" +						\
	"import os\n" +								\
	"import testrunner\n\n" +						\
	"try:\n"								\
	"\tos.environ['NSB_GENERATOR']\n"					\
	"except:\n"								\
	"\tos.environ['NSB_GENERATOR'] = os.getcwd() + '/generator/nsbgen.py'\n"\
	"try:\n"								\
	"\tos.environ['NSB_PATCHER']\n"						\
	"except:\n"								\
	"\tos.environ['NSB_PATCHER'] = os.getcwd() + '/nsb'\n"			\
	"os.environ['PYTHONPATH'] = os.getcwd() + \"/protobuf\"\n" +		\
	"exit(testrunner.LibraryLivePatchTest('%s', '%s', %d).run())\n" %	\
	(source, target, test_type)

f = os.open(outfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
os.write(f, code)
