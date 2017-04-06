SUBDIRS = plugins protobuf tests

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -Wall -Wformat-security -Werror -DCONFIG_X86_64 -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE
AM_MAKEFLAGS = --no-print-directory

# These exports are required for tests generation and tests running
# For tests running they can be set via AM_TESTS_ENVIRONMENT.
# But how to set them for tests generation?
export NSB_GENERATOR=$(top_srcdir)/generator/nsbgen.py
export NSB_PATCHER=$(top_srcdir)/nsb
export TESTS_DIR=$(top_srcdir)/tests

generator_PYTHON =					\
			generator/binfile.py		\
			generator/binpatch.py		\
			generator/elffile.py		\
			generator/funcjump.py		\
			generator/static.py		\
			generator/debuginfo.py		\
			generator/check.py		\
			generator/build_id.py		\
			generator/generate.py		\
			generator/nsbgen.py		\
							\
			protobuf/binpatch_pb2.py	\
			protobuf/funcjump_pb2.py	\
			protobuf/staticsym_pb2.py

sbin_PROGRAMS = nsb

nsb_SOURCES =						\
			protobuf/binpatch.pb-c.c	\
			protobuf/binpatch.pb-c.h	\
			protobuf/funcjump.pb-c.c	\
			protobuf/funcjump.pb-c.h	\
			protobuf/markedsym.pb-c.c	\
			protobuf/markedsym.pb-c.h	\
			protobuf/staticsym.pb-c.c	\
			protobuf/staticsym.pb-c.h	\
							\
			plugins/service.h		\
							\
			patcher/include/compiler.h	\
			patcher/include/context.h	\
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
			patcher/include/service.h	\
			patcher/include/dl_map.h	\
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
			patcher/service.c		\
			patcher/dl_map.c		\
			patcher/patch.c


nsb_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)
nsb_LDFLAGS = -rdynamic

TEST_FILES = tests/global_func.c
TEST_FILES += tests/static_func.c
TEST_FILES += tests/ext_global_func.c
TEST_FILES += tests/global_func_cb.c
TEST_FILES += tests/global_func_p.c
TEST_FILES += tests/global_var.c
TEST_FILES += tests/global_var_addr.c
TEST_FILES += tests/static_func_cb.c
TEST_FILES += tests/static_var.c

LIBRARY_TESTS = $(TEST_FILES:.c=__library.py)

STATIC_TESTS = $(TEST_FILES:.c=__static.py)
STATIC_XFAIL_TESTS =

SHARED_TESTS = $(TEST_FILES:.c=__shared.py)
SHARED_XFAIL_TESTS =

TESTS = $(LIBRARY_TESTS) $(STATIC_TESTS) $(SHARED_TESTS)

XFAIL_TESTS = $(LIBRARY_XFAIL_TESTS) $(STATIC_XFAIL_TESTS)  $(SHARED_XFAIL_TESTS)

$(TESTS): $(TESTS_DIR)/testgen.py
	$(AM_V_GEN) python $(TESTS_DIR)/testgen.py $@


TEST_EXTENSIONS = .py
PY_LOG_COMPILER = python

CLEANFILES = $(TESTS) $(TESTS:.py=.binpatch)
