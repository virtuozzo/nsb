SUBDIRS = protobuf tests

AM_CFLAGS = -Wall -Wformat-security -Werror -DCONFIG_X86_64 -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE
AM_MAKEFLAGS = --no-print-directory

bin_PROGRAMS = nsb

nsb_SOURCES =						\
			protobuf/funcpatch.pb-c.c	\
			protobuf/funcpatch.pb-c.h	\
			protobuf/binpatch.pb-c.c	\
			protobuf/binpatch.pb-c.h	\
			protobuf/objinfo.pb-c.c		\
			protobuf/objinfo.pb-c.h		\
							\
			patcher/include/compiler.h	\
			patcher/include/log.h		\
			patcher/include/list.h		\
			patcher/include/patch.h		\
			patcher/include/xmalloc.h	\
			patcher/include/protobuf.h	\
			patcher/include/process.h	\
			patcher/include/x86_64.h	\
							\
			patcher/x86_64.c		\
			patcher/protobuf.c		\
			patcher/process.c		\
			patcher/log.c			\
			patcher/main.c			\
			patcher/patch.c

nsb_CFLAGS = -I$(top_srcdir)/protobuf/
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
AM_TESTS_ENVIRONMENT =	export NSB_GENERATOR=@NSB_GENERATOR@;	\
			export NSB_PATCHER=@NSB_PATCHER@;	\
			export TESTS_DIR=@TESTS_DIR@;

CLEANFILES = $(TESTS) $(TESTS:.py=.binpatch)
