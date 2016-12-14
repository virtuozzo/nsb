import argparse
from generate import gen_patch
from build_id import print_build_id

parser = argparse.ArgumentParser()
sp = parser.add_subparsers(help = "Use --help for list of actions")

genp = sp.add_parser("generate", help = "Create binary patch")
genp.set_defaults(action = gen_patch)
genp.add_argument("elfa", help="Old ELF file")
genp.add_argument("elfb", help="New ELF file")
genp.add_argument("--patchdir", help="Output directory")
genp.add_argument("--outfile", help="Output file")

bid = sp.add_parser("build-id", help = "Get ELF file Build ID")
bid.set_defaults(action = print_build_id)
bid.add_argument("file")

args = parser.parse_args()
exit(args.action(args))
