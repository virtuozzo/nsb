'''
Copyright (c) 2016-2017, Parallels International GmbH

Our contact details: Parallels International GmbH, Vordergasse 59, 8200
Schaffhausen, Switzerland.
'''

import os
import argparse
from build_id import get_build_id

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
