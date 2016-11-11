import argparse
import os
parser = argparse.ArgumentParser()
parser.add_argument("source", help="Source binary test")
parser.add_argument("target", help="Target binary test")
parser.add_argument("--outfile", help="Output test file")
args = parser.parse_args()

if args.outfile is None:
	args.outfile = "%s_to_%s.py" % (args.source, args.target)

code =	"import testrunner\n\n" +	\
	"exit(testrunner.LivePatchTest('%s', '%s').run())\n" % (args.source, args.target)

f = os.open(args.outfile, os.O_WRONLY | os.O_CREAT)
os.write(f, code)
