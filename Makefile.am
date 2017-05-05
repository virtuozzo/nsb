SUBDIRS = protobuf tests

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -Wall -Wformat-security -Werror -DCONFIG_X86_64 -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE
AM_MAKEFLAGS = --no-print-directory

# Erase LIBS, so plugin won't depend on collected list of libraries.
# Libraries for binary are passed in NSB_LIBS

LIBS =

# These exports are required for tests generation and tests running
# For tests running they can be set via AM_TESTS_ENVIRONMENT.
# But how to set them for tests generation?
export NSB_GENERATOR=$(top_srcdir)/generator/nsbgen.py
export NSB_PATCHER=$(top_srcdir)/nsb
export NSB_TESTS=$(top_srcdir)/tests

generator_PYTHON =					\
			generator/binfile.py		\
			generator/binpatch.py		\
			generator/elffile.py		\
			generator/funcjump.py		\
			generator/static_symbol.py	\
			generator/debuginfo.py		\
			generator/check.py		\
			generator/build_id.py		\
			generator/generate.py		\
			generator/nsbgen.py		\
			generator/consts.py		\
			generator/ms_debuginfo.py	\
			generator/sym_resolver.py	\
							\
			protobuf/binpatch_pb2.py	\
			protobuf/funcjump_pb2.py	\
			protobuf/staticsym_pb2.py	\
			protobuf/markedsym_pb2.py

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
			common/scm.h			\
			common/scm.c			\
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


nsb_CFLAGS = $(AM_CFLAGS)
nsb_LDFLAGS = -rdynamic
nsb_LDADD = $(NSB_LIBS)

libnsb_service_la_SOURCES =				\
			plugins/service.h		\
							\
			common/scm.h			\
			common/scm.c			\
							\
			plugins/service.c

libnsb_service_la_CFLAGS = $(AM_CFLAGS)

lib_LTLIBRARIES = libnsb_service.la

COMMON_TEST_FILES = tests/global_func.c
COMMON_TEST_FILES += tests/ext_global_func.c
COMMON_TEST_FILES += tests/global_func_cb.c
COMMON_TEST_FILES += tests/global_func_p.c
COMMON_TEST_FILES += tests/global_var.c
COMMON_TEST_FILES += tests/global_var_addr.c
COMMON_TEST_FILES += tests/const_var.c

MANUAL_TEST_FILES = $(COMMON_TEST_FILES)
MANUAL_TEST_FILES += tests/static_func_manual.c
MANUAL_TEST_FILES += tests/static_var_manual.c

MANUAL_LIBRARY_TESTS = $(MANUAL_TEST_FILES:.c=__manual__library.py)

MANUAL_STATIC_TESTS = $(MANUAL_TEST_FILES:.c=__manual__static.py)
MANUAL_STATIC_XFAIL_TESTS =

MANUAL_SHARED_TESTS = $(MANUAL_TEST_FILES:.c=__manual__shared.py)
MANUAL_SHARED_XFAIL_TESTS =

MANUAL_TESTS = $(MANUAL_LIBRARY_TESTS) $(MANUAL_STATIC_TESTS) $(MANUAL_SHARED_TESTS)
MANUAL_XFAIL_TESTS = $(MANUAL_LIBRARY_XFAIL_TESTS) $(MANUAL_STATIC_XFAIL_TESTS)  $(MANUAL_SHARED_XFAIL_TESTS)

AUTO_TEST_FILES = $(COMMON_TEST_FILES)
AUTO_TEST_FILES += tests/static_func_auto.c
AUTO_TEST_FILES += tests/static_var_auto.c

AUTO_LIBRARY_TESTS = $(AUTO_TEST_FILES:.c=__auto__library.py)

AUTO_STATIC_XFAIL_FILES =

AUTO_STATIC_TESTS = $(AUTO_TEST_FILES:.c=__auto__static.py)
AUTO_STATIC_XFAIL_TESTS = $(AUTO_STATIC_XFAIL_FILES:.c=__auto__static.py)

AUTO_SHARED_XFAIL_FILES =

AUTO_SHARED_TESTS = $(AUTO_TEST_FILES:.c=__auto__shared.py)
AUTO_SHARED_XFAIL_TESTS = $(AUTO_SHARED_XFAIL_FILES:.c=__auto__shared.py)

AUTO_TESTS = $(AUTO_LIBRARY_TESTS) $(AUTO_STATIC_TESTS) $(AUTO_SHARED_TESTS)
AUTO_XFAIL_TESTS = $(AUTO_LIBRARY_XFAIL_TESTS) $(AUTO_STATIC_XFAIL_TESTS)  $(AUTO_SHARED_XFAIL_TESTS)

TESTS = $(MANUAL_TESTS) $(AUTO_TESTS)

XFAIL_TESTS = $(MANUAL_XFAIL_TESTS) $(AUTO_XFAIL_TESTS)

$(TESTS): $(NSB_TESTS)/testgen.py
	$(AM_V_GEN) python $(NSB_TESTS)/testgen.py $@


TEST_EXTENSIONS = .py
PY_LOG_COMPILER = python

CLEANFILES = $(TESTS) $(TESTS:.py=.binpatch)
