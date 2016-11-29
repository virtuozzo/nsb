import sys
import os
import subprocess
import signal
import multiprocessing
from collections import namedtuple


class Test:
	def __init__(self, path):
		self.path = path
		self.pid = None
		self.stdout = None
		self.stderr = None
		self.returncode = None
		self.__state__ = "init"

	def start(self):
		try:
			if self.__state__ != "init":
				print "Test is not new. State: %s" % self.__state__
				raise
			self.p = subprocess.Popen(self.path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			self.pid = self.p.pid
			self.__state__ = "started"
		except NameError as e:
			print "Unexpected NameError: %s" % e
		except OSError as e:
			print "Unexpected start OSError: '%s', %s" % (' '.join(args), e.strerror)
		except:
			print "Unexpected start error:", sys.exc_info()[0]
		return self.pid

	def wait(self):
		try:
			if self.__state__ != "started":
				print "Process is not started. State: %s" % self.__state__
				raise

			self.returncode = self.p.wait()
			self.stdout, self.stderr = self.p.communicate()
			self.__state__ = "stopped"

		except OSError as e:
			print "Unexpected OSError: %s, %s" % (e.filename, e.strerror)
			return 1
		except:
			print "Failed to wait process %d\n" % self.pid
			print "Unexpected wait error:", sys.exc_info()[0]
			return self.returncode
		return 0

	def stop(self):
		try:
			if self.__state__ != "started":
				print "Process is not started. State: %s" % self.__state__
				return

			os.kill(self.pid, signal.SIGINT)
		except OSError as e:
			print "Unexpected OSError: %s, %s" % (e.filename, e.strerror)
			return 1
		except:
			print "Failed to stop process %d\n" % self.pid
			print "Unexpected stop error:", sys.exc_info()[0]
			return 1
		return self.wait()

	def is_running(self):
		try:
			os.kill(self.pid, 0)
		except OSError:
			return False
		return True



class BinPatch:
	def __init__(self, source, target):
		self.source = source
		self.target = target
		self.outfile = os.path.dirname(source) + "/" + os.path.basename(source) + "_to_" + os.path.basename(target) + ".binpatch"

		self.gen_stderr = None
		self.gen_stderr = None
		self.gen_result = None

		self.apply_result = None
		self.apply_stdout = None
		self.apply_stderr = None

		self.generator = os.environ.get('NSB_GENERATOR')
		if not self.generator:
			print "NSB_GENERATOR environment variable must be set"
			raise

		self.patcher = os.environ.get('NSB_PATCHER')
		if not self.patcher:
			print "NSB_PATCHER environment variable must be set"
			raise

	def generate(self):
		try:
			cmd = "python %s %s %s --outfile %s" % (self.generator, self.source, self.target, self.outfile)
			p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			self.gen_stdout, self.gen_stderr = p.communicate()
			print self.gen_stdout
			self.gen_result = p.returncode
		except:
			print "Unexpected error:", sys.exc_info()[0]
		print "self.gen_result: %d" % self.gen_result
		return self.gen_result

	def apply(self, test):
		try:
			if not test.is_running():
				print "Tests with pid %d is not running" % test.pid
				return 1

			cmd = "%s patch -v 4 -p %d -f %s" % (self.patcher, test.pid, self.outfile)
			p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			self.apply_stdout, self.apply_stderr = p.communicate()
			print self.apply_stdout
			self.apply_result = p.returncode
		except:
			print "Unexpected error:", sys.exc_info()[0]
		return self.apply_result


class LivePatchTest:
	def __init__(self, source, target):
		tests_dir = os.environ.get('TESTS_DIR')
		if not os.path.isabs(source) and tests_dir:
			source = tests_dir + "/" + source
		if not os.path.isabs(target) and tests_dir:
			target = tests_dir + "/" + target

		self.test = Test(source)
		self.patch = BinPatch(source, target)
		self.result = 0

	def run(self):
		if self.patch.generate() != 0:
			print "Failed to generate binary patch\n"
			return 1

		if self.test.start() is None:
			print "Failed to start process %s\n" % self.test.path
			return 1

		if self.patch.apply(self.test) != 0:
			print "Failed to apply binary patch\n"
			self.result = 1

		if self.test.stop() != 0:
			self.result = 1

		return self.result
