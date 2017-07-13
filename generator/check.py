import os
import argparse

from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

import elffile

def get_build_id(path):
	with open(path, 'rb') as stream:
		build_id = None
		try:
			build_id = elffile.get_build_id(ELFFile(stream))
		except ELFError:
			print "%s is not an ELF file" % path
		return build_id

def print_build_id(args):
	try:
		build_id = get_build_id(args.file)
	except IOError as e:
		print e
		return 1

	if build_id:
		print build_id
	return 0

def check_build_id(bid):
	if len(bid) != 40:
		msg = "%r must be 40-symbols long" % bid
		raise argparse.ArgumentTypeError(msg)

	try:
		val = int(bid, 16)
	except ValueError:
		msg = "%r must be hexidecimal number" % bid
		raise argparse.ArgumentTypeError(msg)

	return bid


def check_pid(pid):
	try:
		val = int(pid)
	        if val < 0:
			msg = "%r must be positive" % pid
			raise argparse.ArgumentTypeError(msg)
		if val == 0:
			msg = "%r can't be zero" % pid
			raise argparse.ArgumentTypeError(msg)
	except ValueError:
		msg = "%r must be decimal number" % pid
		raise argparse.ArgumentTypeError(msg)
	return val

def map_by_build_id(pid, bid):
	for link in os.listdir("/proc/%d/map_files" % pid):
		linkpath = "/proc/%d/map_files/%s" % (pid, link)
		build_id = get_build_id(linkpath)
		if build_id == bid:
			return linkpath
	return None

def make_check(args):
	link = map_by_build_id(args.pid, args.id)
	if link:
		return os.readlink(link)
	return 1

def check_mode(mode):
	if mode != "auto" and mode != "manual":
		msg = "Wrong mode (can be either \"auto\" or \"manual\")" % mode
		raise argparse.ArgumentTypeError(msg)
	return mode
