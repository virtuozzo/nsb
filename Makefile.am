SUBDIRS = protobuf tests

AM_CFLAGS = -Wall -Wformat-security -Werror -DCONFIG_X86_64 -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE
AM_MAKEFLAGS = --no-print-directory

# These exports are required for tests generation and tests running
# For tests running they can be set via AM_TESTS_ENVIRONMENT.
# But how to set them for tests generation?
export NSB_GENERATOR=$(top_srcdir)/generator/main.py
export NSB_PATCHER=$(top_srcdir)/nsb
export TESTS_DIR=$(top_srcdir)/tests

bin_PROGRAMS = nsb

nsb_SOURCES =						\
			protobuf/funcpatch.pb-c.c	\
			protobuf/funcpatch.pb-c.h	\
			protobuf/binpatch.pb-c.c	\
			protobuf/binpatch.pb-c.h	\
			protobuf/objinfo.pb-c.c		\
			protobuf/objinfo.pb-c.h		\
			protobuf/relaplt.pb-c.c		\
			protobuf/relaplt.pb-c.h		\
			protobuf/segment.pb-c.c		\
			protobuf/segment.pb-c.h		\
			protobuf/datasym.pb-c.c		\
			protobuf/datasym.pb-c.h		\
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
							\
			patcher/x86_64.c		\
			patcher/protobuf.c		\
			patcher/process.c		\
			patcher/log.c			\
			patcher/main.c			\
			patcher/vma.c			\
			patcher/patch.c

nsb_CFLAGS = -I$(top_srcdir)
nsb_LDFLAGS = -rdynamic


TESTS = 					\
			tests/static_a_to_static_b.py	\
			tests/static_a_to_static_c.py	\
			tests/static_a_to_static_f.py	\
			tests/static_d_to_static_g.py	\
			tests/static_e_to_static_h.py	\
			tests/static_j_to_static_i.py	\
			tests/static_i_to_static_j.py

$(TESTS): $(TESTS_DIR)/testgen.py
	$(AM_V_GEN) python $(TESTS_DIR)/testgen.py $(subst _to_, ,$(subst .py,,$(subst tests/, ,$@)))  --outfile $@


TEST_EXTENSIONS = .py
PY_LOG_COMPILER = python

CLEANFILES = $(TESTS) $(TESTS:.py=.binpatch)
