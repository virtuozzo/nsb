'''
Copyright (c) 2016-2017, Parallels International GmbH

Our contact details: Parallels International GmbH, Vordergasse 59, 8200
Schaffhausen, Switzerland.
'''

import argparse
import os
import re

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

test_name, patch_mode, test_type = os.path.basename(args.name).split('__', 2)

if test_type == "library":
	source = "nsbtest_library"
	test_class = "LibraryLivePatchTest"
elif test_type == "static":
	source = "nsbtest_static"
	test_class = "ExecutableLivePatchTest"
elif test_type == "shared":
	source = "nsbtest_shared"
	test_class = "ExecutableLivePatchTest"
else:
	print "Unsupported test type: \"%s\"" % test_type
	exit(1)

if patch_mode != "manual" and patch_mode != "auto":
	print "Unsupported test patch mode: \"%s\"" % patch_mode
	exit(1)

target = test_name + ".patch"
target_obj = test_name + ".o"
test_type = get_test_type(test_name)

code = """
#!/usr/bin/env python2
import os

try:
	os.environ['NSB_GENERATOR']
except:
	os.environ['NSB_GENERATOR'] = os.getcwd() + '/generator/nsbgen.py'

try:
	os.environ['NSB_PATCHER']
except:
	os.environ['NSB_PATCHER'] = os.getcwd() + '/nsb'

try:
	os.environ['NSB_TESTS']
except:
	os.environ['NSB_TESTS'] = os.getcwd() + '/tests'

try:
	os.environ['LD_LIBRARY_PATH']
except:
	os.environ['LD_LIBRARY_PATH'] = os.getcwd() + '/.libs'

os.environ['PYTHONPATH'] = os.getcwd() + '/protobuf'

import sys
sys.path.append(os.path.dirname(os.environ['NSB_GENERATOR']))

import testrunner
exit(testrunner.%s('%s', '%s', '%s', %d, '%s').run())
""" % (test_class, source, target, target_obj, test_type, patch_mode)

f = os.open(outfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
os.write(f, code)
