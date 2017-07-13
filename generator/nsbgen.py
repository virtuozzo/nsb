import sys
import argparse

from generate import gen_patch
from check import print_build_id, check_pid, check_build_id, make_check, check_mode

parser = argparse.ArgumentParser()
sp = parser.add_subparsers(help = "Use --help for list of actions")

genp = sp.add_parser("generate", help = "Create binary patch")
genp.set_defaults(action = gen_patch)
genp.add_argument("elfa", help="Old ELF file")
genp.add_argument("elfb", help="New ELF file")
genp.add_argument("obj_files", nargs="*", metavar='obj', help="Object file used to make new ELF")
genp.add_argument("-o", "--outfile", help="Output file")
genp.add_argument("-d", "--debugfile", help="File containing separate debuginfo")
genp.add_argument("--keep-merged", action="store_true",
	help="Keep result of merging with debuginfo file")

genp.add_argument("--mode", type=check_mode,  default="manual",
		  help="Patch creation mode: auto or manual")

bid = sp.add_parser("build-id", help = "Get ELF file Build ID")
bid.set_defaults(action = print_build_id)
bid.add_argument("file")

chk = sp.add_parser("check", help = "Check process for mapped ELF by Build ID")
chk.set_defaults(action = make_check)
chk.add_argument("pid", type=check_pid, help = "Process pid")
chk.add_argument("id", type=check_build_id, help = "Build ID")

args = parser.parse_args()
sys.exit(args.action(args))
