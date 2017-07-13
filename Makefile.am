SUBDIRS = protobuf

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -Wall -Wformat-security -Werror -DCONFIG_X86_64 -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE
AM_MAKEFLAGS = --no-print-directory

# Erase LIBS, so plugin won't depend on collected list of libraries.
# Libraries for binary are passed in NSB_LIBS

LIBS =

# These exports are required for tests generation and tests running
# For tests running they can be set via AM_TESTS_ENVIRONMENT.
# But how to set them for tests generation?
export NSB_GENERATOR
export NSB_PATCHER
export NSB_TESTS

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
			generator/patch_symbol.py	\
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
			patcher/include/rtld.h		\
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
			patcher/rtld.c		\
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

##############################################################
# Test engine: binaries + generation
##############################################################

COMMON_TEST_FILES = 					\
		tests/global_func.c		\
		tests/ext_global_func.c		\
		tests/global_func_cb.c		\
		tests/global_var.c		\
		tests/global_var_addr.c		\
		tests/global_func_p.c		\
		tests/const_var.c

MANUAL_TEST_FILES = 					\
		tests/static_func_manual.c	\
		tests/static_var_manual.c	\
						\
		tests/static_func_manual_v2.c	\
		tests/static_var_manual_v2.c

AUTO_TEST_FILES = 					\
		tests/static_func_auto.c	\
		tests/static_var_auto.c

TEST_FILES = $(COMMON_TEST_FILES) $(AUTO_TEST_FILES) $(MANUAL_TEST_FILES)

tests_libtest_la_SOURCES = tests/library.c tests/test_types.h $(TEST_FILES)
tests_libtest_la_CFLAGS = $(AM_CFLAGS) -g
tests_libtest_la_LDFLAGS = -avoid-version -rpath /whereever

check_LTLIBRARIES = tests/libtest.la

tests_nsbtest_library_SOURCES = tests/main.c
tests_nsbtest_library_LDADD = tests/libtest.la -lpthread
tests_nsbtest_library_CFLAGS = $(AM_CFLAGS) -g

tests_nsbtest_static_SOURCES = tests/main.c tests/library.c tests/test_types.h $(TEST_FILES)
tests_nsbtest_static_LDADD = -lpthread
tests_nsbtest_static_CFLAGS = $(AM_CFLAGS) -g

tests_nsbtest_shared_SOURCES = tests/main.c tests/library.c tests/test_types.h $(TEST_FILES)
tests_nsbtest_shared_LDADD = -lpthread
tests_nsbtest_shared_CFLAGS = $(AM_CFLAGS) -g -fpic -pie

check_PROGRAMS = tests/nsbtest_library tests/nsbtest_static tests/nsbtest_shared

tests/nsb_test_types.py$(EXEEXT): tests/test_types.h
	$(AM_V_GEN) python tests/convert_test_types.py $<

tests/nsb_test_types.py$(EXEEXT):  tests/convert_test_types.py

check_SCRIPTS = tests/nsb_test_types.py

otherincludedir = $(includedir)/@PACKAGE@
otherinclude_HEADERS = include/vzp.h

#########################
# Tests
########################

# "Manual"-mode tests

MANUAL_TESTS_LIST = $(COMMON_TEST_FILES) $(MANUAL_TEST_FILES)

MANUAL_XFAIL_LIST =							\
			tests/static_func_manual_v2.c			\
			tests/static_var_manual_v2.c

MANUAL_LIBRARY_TESTS = $(MANUAL_TESTS_LIST:.c=__manual__library.py)
MANUAL_LIBRARY_XFAIL_TESTS = $(MANUAL_XFAIL_LIST:.c=__manual__library.py)

MANUAL_STATIC_TESTS = $(MANUAL_TESTS_LIST:.c=__manual__static.py)
MANUAL_STATIC_XFAIL_TESTS = $(MANUAL_XFAIL_LIST:.c=__manual__static.py)

MANUAL_SHARED_TESTS = $(MANUAL_TESTS_LIST:.c=__manual__shared.py)
MANUAL_SHARED_XFAIL_TESTS = $(MANUAL_XFAIL_LIST:.c=__manual__shared.py)

MANUAL_TESTS = $(MANUAL_LIBRARY_TESTS) $(MANUAL_STATIC_TESTS) $(MANUAL_SHARED_TESTS)
MANUAL_XFAIL_TESTS = $(MANUAL_LIBRARY_XFAIL_TESTS) $(MANUAL_STATIC_XFAIL_TESTS)  $(MANUAL_SHARED_XFAIL_TESTS)

# "Auto"-mode tests

AUTO_TESTS_LIST = $(COMMON_TEST_FILES) $(AUTO_TEST_FILES)

AUTO_LIBRARY_TESTS = $(AUTO_TESTS_LIST:.c=__auto__library.py)
AUTO_LIBRARY_XFAIL_FILES =

AUTO_STATIC_TESTS = $(AUTO_TESTS_LIST:.c=__auto__static.py)
AUTO_STATIC_XFAIL_TESTS =

AUTO_SHARED_TESTS = $(AUTO_TESTS_LIST:.c=__auto__shared.py)
AUTO_SHARED_XFAIL_TESTS =

AUTO_TESTS = $(AUTO_LIBRARY_TESTS) $(AUTO_STATIC_TESTS) $(AUTO_SHARED_TESTS)
AUTO_XFAIL_TESTS = $(AUTO_LIBRARY_XFAIL_TESTS) $(AUTO_STATIC_XFAIL_TESTS)  $(AUTO_SHARED_XFAIL_TESTS)

TESTS = $(MANUAL_TESTS) $(AUTO_TESTS)
XFAIL_TESTS = $(MANUAL_XFAIL_TESTS) $(AUTO_XFAIL_TESTS)

$(TESTS): $(NSB_TESTS)/testgen.py
	$(AM_V_GEN) python $(NSB_TESTS)/testgen.py $@


TEST_EXTENSIONS = .py
PY_LOG_COMPILER = python

CLEANFILES = $(TESTS) $(TESTS:.py=.binpatch)

#########################
# Patches
########################

TESTS_PATCHES = $(TESTS:.py=.patch)

TESTS_CFLAGS = -c -g -fpic

MANUAL_TESTS_CFLAGS = ${TESTS_CFLAGS} -I.

%.o: tests/test_types.h

SUFFIXES = __manual__library.o
SUFFIXES += __manual__shared.o
SUFFIXES += __manual__static.o

.c__manual__library.o: tests/test_types.h
	$(AM_V_CC) $(CC) -DPATCH ${MANUAL_TESTS_CFLAGS} $^ -o $@

.c__manual__shared.o: tests/test_types.h
	$(AM_V_CC) $(CC) -DPATCH ${MANUAL_TESTS_CFLAGS} $^ -o $@

.c__manual__static.o: tests/test_types.h
	$(AM_V_CC) $(CC) -DPATCH ${MANUAL_TESTS_CFLAGS} $^ -o $@

AUTO_TESTS_CFLAGS = ${TESTS_CFLAGS} -ffunction-sections -fdata-sections

SUFFIXES += __auto__library.o
SUFFIXES += __auto__shared.o
SUFFIXES += __auto__static.o

.c__auto__library.o: tests/test_types.h
	$(AM_V_CC) $(CC) -DPATCH ${AUTO_TESTS_CFLAGS} $^ -o $@

.c__auto__shared.o: tests/test_types.h
	$(AM_V_CC) $(CC) -DPATCH ${AUTO_TESTS_CFLAGS} $^ -o $@

.c__auto__static.o: tests/test_types.h
	$(AM_V_CC) $(CC) -DPATCH ${AUTO_TESTS_CFLAGS} $^ -o $@

.o.patch:
	$(AM_V_CC) $(CC) -g -shared -fpic $^ -o $@

check_DATA = $(TESTS_PATCHES)

.SECONDARY: $(TESTS_PATCHES:.patch=.o)

CLEANFILES += $(TESTS_PATCHES)
