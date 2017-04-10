'''
Copyright (c) 2016-2017, Parallels International GmbH

Our contact details: Parallels International GmbH, Vordergasse 59, 8200
Schaffhausen, Switzerland.
'''

import argparse
import os
import re

def convert_enum(header):
	src = os.open(header, os.O_RDONLY)
	content = os.read(src, 4096)
	start = content.find("enum")
	end = content.find("test_type_t")
	enum = content[start:end]

	test_types = re.findall('TEST_TYPE_[^,]*', enum)

	code =	"#!/usr/bin/env python2\n"
	code += "NSB_TEST_TYPES = dict(\n"
	nr = 0
	for t in test_types:
		if t.find("=") != -1:
			print "Enumerated enums are not supported"
			exit(1)
		code += "\t%s=%d,\n" % (t, nr)
		nr += 1
	code += ")\n"

	pyfile = "nsb_" + header[:header.find('.')] + ".py"
	dst = os.open(pyfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
	os.write(dst, code)

parser = argparse.ArgumentParser()
parser.add_argument("header", help="C-header file")
args = parser.parse_args()

convert_enum(args.header)
