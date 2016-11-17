import sys
import os
import subprocess
import signal
import multiprocessing
from multiprocessing import Process, Pipe
from collections import namedtuple

def thread_run(path, pipe):
	try:
		p = subprocess.Popen(path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		pipe.send(p.pid)
		out, err = p.communicate()
		pipe.send(out)
		pipe.send(err)
		pipe.send(p.returncode)
	except OSError as e:
		print "Unexpected OSError: %s, %s" % (e.filename, e.strerror)
		return 1
	except:
		print "Unexpected error:", sys.exc_info()[0]
		return 1
	return 0


class Test:
	def __init__(self, path):
		self.path = path
		self.pipe = None
		self.pid = None
		self.stdout = None
		self.stderr = None
		self.returncode = None
		self.__state__ = "init"

	def __thread_run__(self, pipe):
		p = subprocess.Popen([self.path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		pipe.send(p.pid)
		out, err = p.communicate()
		pipe.send(out)
		pipe.send(err)
		pipe.send(p.returncode)

	def start(self):
		try:
			if self.__state__ != "init":
				print "Test is not new. State: %s" % self.__state__
				raise

			read_end, write_end = multiprocessing.Pipe(False)
			self.pipe = read_end

			p = Process(target=thread_run, args=(self.path, write_end))
			p.start()
			if not p.is_alive:
				print "Failed to fork a child"
				raise

			self.pid = self.pipe.recv()
			self.__state__ = "started"
		except:
			print "Unexpected error:", sys.exc_info()[0]
		return self.pid

	def stop(self):
		try:
			if self.__state__ != "started":
				print "Process is not started. State: %s" % self.__state__
				return

			os.kill(self.pid, signal.SIGINT)
			self.stdout = self.pipe.recv()
			self.stderr = self.pipe.recv()
			self.returncode = self.pipe.recv()
			self.__state__ = "stopped"

			if self.returncode:
				print "************ Error ************"
				print "Process %s (pid %d): exited with %d" % (self.path, self.pid, self.returncode)
				print "stdout:\n%s" % self.stdout
				print "stderr:\n%s" % self.stderr
			else:
				print "************ Pass *************"
		except:
			print "Failed to stop process %d\n" % self.pid
			print "Unexpected error:", sys.exc_info()[0]
		return self.returncode

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
