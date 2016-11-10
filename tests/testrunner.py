import os
import subprocess
import signal
import multiprocessing
from multiprocessing import Process, Pipe
from collections import namedtuple

def thread_run(path, pipe):
	print "thread full path: %s" % path
	p = subprocess.Popen(path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	print "%s pid: %d" % (path, p.pid)
	pipe.send(p.pid)
	out, err = p.communicate()
	pipe.send(out)
	pipe.send(err)
	pipe.send(p.returncode)


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
		if self.__state__ != "init":
			print "Test is not new. State: %s" % self.__state__
			return

		pipe = multiprocessing.Pipe(False)
		self.pipe = pipe[0]

		print "path: %s" % self.path
		print "cwd: %s" % os.getcwd()
		print "full path: %s" % os.getcwd() + "/" + self.path

		p = Process(target=thread_run, args=(os.getcwd() + "/" + self.path, pipe[1]))
		p.start()
		self.pid = self.pipe.recv()
		self.__state__ = "started"

	def stop(self):
		if self.__state__ != "started":
			print "Process is not started. State: %s" % self.__state__
			return

		os.kill(self.pid, signal.SIGINT)
		self.stdout = self.pipe.recv()
		self.stderr = self.pipe.recv()
		self.returncode = self.pipe.recv()
		self.__state__ = "stopped"
		return self.returncode

	def results(self):
		if self.__state__ != "stopped":
			print "Process is not stopped yet. State: %s" % self.__state__
			return
		print "Test %s (pid %d):" % (self.path, self.pid)
		print "exit code: %d" % self.returncode
		print "stdout:\n%s" % self.stdout
		print "stderr:\n%s" % self.stderr


class BinPatch:
	def __init__(self, source, target):
		self.source = source
		self.target = target
		self.outfile = "./" + os.path.basename(source) + "_to_" + os.path.basename(target) + ".binpatch"

		self.gen_result = None
		self.gen_stderr = None
		self.gen_stderr = None

		self.apply_result = None
		self.apply_stdout = None
		self.apply_stderr = None

		print os.environ

		self.generator = os.environ.get('NSB_GENERATOR')
		print "Generator: %s" % self.generator
		if not self.generator:
			print "NSB_GENERATOR environment variable must be set"
			raise

		self.patcher = os.environ.get('NSB_PATCHER')
		print "Patcher: %s" % self.patcher
		if not self.patcher:
			print "NSB_PATCHER environment variable must be set"
			raise

	def generate(self):
		cmd = "python %s %s %s --outfile %s" % (self.generator, self.source, self.target, self.outfile)
		p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		self.gen_stdout, self.gen_stderr = p.communicate()
		print self.gen_stdout
		self.gen_result = p.returncode
		return self.gen_result

	def apply(self, pid):
		cmd = "%s patch -v 4 -p %d -f %s" % (self.patcher, pid, self.outfile)
		p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		self.apply_stdout, self.apply_stderr = p.communicate()
		print self.apply_stdout
		self.apply_result = p.returncode
		return self.apply_result


class LivePatchTest:
	def __init__(self, source, target):
		self.test = Test(source)
		self.patch = BinPatch(source, target)

	def run(self):
		if self.patch.generate():
			print "Failed to generate binary patch: %d\n" % self.patch.gen_result
			return self.patch.gen_result

		self.test.start()

		if self.patch.apply(self.test.pid):
			print "Failed to apply binary patch: %d\n" % self.patch.apply_result

		self.test.stop()
		self.test.results()
		return 0
