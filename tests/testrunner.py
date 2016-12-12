import sys
import os
import re
import subprocess
import signal
import multiprocessing
from collections import namedtuple


class Test:
	def __init__(self, path):
		self.path = path
		self.stdout = None
		self.stderr = None
		self.returncode = None
		self.__state__ = "init"
		self.p = None
		self.__set_test_env__(os.path.dirname(path))

	def __set_test_env__(self, library_path):
		ld_library_path = ""
		try:
			ld_library_path = os.environ['LD_LIBRARY_PATH']
		except:
			pass
		os.environ['LD_LIBRARY_PATH'] = ld_library_path + ":" + library_path

	def start(self, wait=True):
		args = [self.path]
		if wait:
			args.append("wait");

		try:
			if self.__state__ != "init":
				print "Test is not new. State: %s" % self.__state__
				raise
			self.p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			self.__state__ = "started"
		except NameError as e:
			print "Unexpected NameError: %s" % e
		except OSError as e:
			print "Unexpected start OSError: '%s', %s" % (' '.join(args), e.strerror)
		except:
			print "Unexpected start error:", sys.exc_info()[0]
		return self.p.pid

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
			print "Failed to wait process %d\n" % self.p.pid
			print "Unexpected wait error:", sys.exc_info()[0]
			return self.returncode
		return 0

	def stop(self):
		try:
			if self.__state__ != "started":
				print "Process is not started. State: %s" % self.__state__
				return

			os.kill(self.p.pid, signal.SIGINT)
		except OSError as e:
			print "Unexpected OSError: %s, %s" % (e.filename, e.strerror)
			return 1
		except:
			print "Failed to stop process %d\n" % self.p.pid
			print "Unexpected stop error:", sys.exc_info()[0]
			return 1
		return self.wait()

	def run(self):
		if self.start(wait=False) is None:
			print "Failed to start process %s\n" % self.path
			raise

		if self.wait() != 0:
			print "Failed to wait process %d\n" % self.p.pid
			raise

		return self.returncode

	def is_running(self):
		try:
			os.kill(self.p.pid, 0)
		except OSError:
			return False
		return True

	def check_result(self, expected):
		if self.returncode != expected:
			print "************ Error ************"
			print "Test %s (pid %d): exited with %d (expected: %d)" % (self.path, self.p.pid, self.returncode, expected)
			print "stdout:\n%s" % self.stdout
			print "stderr:\n%s" % self.stderr
			return 1

		print "************ Pass *************"
		return 0


class BinPatch:
	def __init__(self, source, target, outfile):
		self.source = source
		self.target = target
		self.outfile = outfile

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

	def __run_cmd__(self, cmd):
		print "Execute: %s" % cmd
		return subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	def generate(self):
		try:
			p = self.__run_cmd__("python %s %s %s --outfile %s" % (self.generator, self.source, self.target, self.outfile))
			self.gen_stdout, self.gen_stderr = p.communicate()
			print self.gen_stdout
			self.gen_result = p.returncode
		except OSError as e:
			print "Unexpected generate OSError: %s, %s" % (e.filename, e.strerror)
			return 1
		except:
			print "Unexpected generate error:", sys.exc_info()[0]
		print "self.gen_result: %d" % self.gen_result
		return self.gen_result

	def apply(self, test):
		try:
			if not test.is_running():
				print "Test with pid %d is not running" % test.p.pid
				return 1

			p = self.__run_cmd__("%s patch -v 4 -f %s -p %d" % (self.patcher, self.outfile, test.p.pid))
			self.apply_stdout, self.apply_stderr = p.communicate()
			print self.apply_stdout
			self.apply_result = p.returncode
		except OSError as e:
			print "Unexpected apply OSError: %s, %s" % (e.filename, e.strerror)
			return 1
		except:
			print "Unexpected apply error:", sys.exc_info()[0]
		return self.apply_result


class LivePatchTest:
	def __init__(self, binary, src_res, tgt_res, patch):
		self.test = Test(binary)
		self.patch = patch
		self.src_res = src_res
		self.tgt_res = tgt_res
		self.lp_failed = False

	def test_result(self):
		if self.lp_failed:
			return 1

		return self.test.check_result(self.tgt_res)

	def run(self):
		if self.patch.generate() != 0:
			print "Failed to generate binary patch\n"
			return 1

		if self.test.start() is None:
			print "Failed to start process %s\n" % self.test.path
			return 1

		if self.patch.apply(self.test) != 0:
			print "Failed to apply binary patch:\n%s" % self.patch.apply_stderr
			self.lp_failed = True

		if self.test.stop() != 0:
			self.lp_failed = True

		return self.test_result()


class StaticLivePatchTest(LivePatchTest):
	def __init__(self, source, target, src_res, tgt_res):
		outfile = os.path.dirname(source) + "/" + os.path.basename(source) + "_to_" + os.path.basename(target) + ".binpatch"
		patch = BinPatch(source, target, outfile)
		LivePatchTest.__init__(self, source, src_res, tgt_res, patch)


class SharedLivePatchTest(LivePatchTest):
	def __init__(self, source, target, src_res, tgt_res):
		outfile = os.path.dirname(source) + "/" + os.path.basename(source) + "_to_" + os.path.basename(target) + ".binpatch"
		binary = self.__get_bin_by_test__(source)
		source = self.__get_lib_by_test__(source)
		target = self.__get_lib_by_test__(target)
		patch = BinPatch(source, target, outfile)
		LivePatchTest.__init__(self, binary, src_res, tgt_res, patch)

	def __get_bin_by_test__(self, test):
		return os.path.dirname(test) + "/.libs/" + os.path.basename(test)

	def __get_lib_by_test__(self, test):
		label = re.split('_', os.path.basename(test))[1]
		return os.path.dirname(test) + "/.libs/libtest_" + label + ".so"
