SUBDIRS = protobuf tests

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -Wall -Wformat-security -Werror -DCONFIG_X86_64 -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE
AM_MAKEFLAGS = --no-print-directory

# These exports are required for tests generation and tests running
# For tests running they can be set via AM_TESTS_ENVIRONMENT.
# But how to set them for tests generation?
export NSB_GENERATOR=$(top_srcdir)/generator/nsbgen.py
export NSB_PATCHER=$(top_srcdir)/nsb
export TESTS_DIR=$(top_srcdir)/tests

generator_PYTHON =						\
			generator/binfile.py		\
			generator/binpatch.py		\
			generator/elffile.py		\
			generator/funcpatch.py		\
			generator/function.py		\
			generator/nsbgen.py		\
							\
			protobuf/binpatch_pb2.py	\
			protobuf/datasym_pb2.py		\
			protobuf/funcpatch_pb2.py	\
			protobuf/objinfo_pb2.py		\
			protobuf/funcjump_pb2.py	\
			protobuf/segment_pb2.py

bin_PROGRAMS = nsb

nsb_SOURCES =						\
			protobuf/binpatch.pb-c.c	\
			protobuf/binpatch.pb-c.h	\
			protobuf/segment.pb-c.c		\
			protobuf/segment.pb-c.h		\
			protobuf/funcjump.pb-c.c	\
			protobuf/funcjump.pb-c.h	\
							\
			patcher/include/compiler.h	\
			patcher/include/log.h		\
			patcher/include/list.h		\
			patcher/include/patch.h		\
			patcher/include/xmalloc.h	\
			patcher/include/protobuf.h	\
			patcher/include/process.h	\
			patcher/include/x86_64.h	\
			patcher/include/vma.h		\
			patcher/include/elf.h		\
			patcher/include/backtrace.h	\
			patcher/include/util.h		\
			patcher/include/relocations.h	\
							\
			patcher/x86_64.c		\
			patcher/protobuf.c		\
			patcher/process.c		\
			patcher/log.c			\
			patcher/main.c			\
			patcher/vma.c			\
			patcher/elf.c			\
			patcher/backtrace.c		\
			patcher/util.c			\
			patcher/relocations.c		\
			patcher/patch.c


nsb_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)
nsb_LDFLAGS = -rdynamic

LIBRARY_TESTS = tests/library_global_func.py
LIBRARY_TESTS += tests/library_static_func.py
LIBRARY_TESTS += tests/library_ext_global_func.py
LIBRARY_TESTS += tests/library_global_func_cb.py
LIBRARY_TESTS += tests/library_global_func_p.py
LIBRARY_TESTS += tests/library_global_var.py
LIBRARY_TESTS += tests/library_global_var_addr.py
LIBRARY_TESTS += tests/library_static_func_cb.py
LIBRARY_TESTS += tests/library_static_var.py

LIBRARY_XFAIL_TESTS = tests/library_static_func_cb.py
LIBRARY_XFAIL_TESTS += tests/library_static_var.py

TESTS = $(LIBRARY_TESTS)

XFAIL_TESTS = $(LIBRARY_XFAIL_TESTS)

$(TESTS): $(TESTS_DIR)/testgen.py
	$(AM_V_GEN) python $(TESTS_DIR)/testgen.py $@


TEST_EXTENSIONS = .py
PY_LOG_COMPILER = python

CLEANFILES = $(TESTS) $(TESTS:.py=.binpatch)
