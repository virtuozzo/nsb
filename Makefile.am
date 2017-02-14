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
			protobuf/relaplt_pb2.py		\
			protobuf/segment_pb2.py

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
			patcher/include/elf.h		\
			patcher/include/backtrace.h	\
			patcher/include/rtld.h		\
							\
			patcher/x86_64.c		\
			patcher/protobuf.c		\
			patcher/process.c		\
			patcher/log.c			\
			patcher/main.c			\
			patcher/vma.c			\
			patcher/elf.c			\
			patcher/backtrace.c		\
			patcher/rtld.c			\
			patcher/patch.c

nsb_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)
nsb_LDFLAGS = -rdynamic

TESTS = 							\
			tests/static_a_to_static_b.py		\
			tests/static_a_to_static_c.py		\
			tests/static_a_to_static_f.py		\
			tests/static_d_to_static_g.py		\
			tests/static_e_to_static_h.py		\
			tests/static_j_to_static_i.py		\
			tests/static_i_to_static_j.py		\
								\
			tests/shared_a_to_shared_b.py		\
			tests/shared_a_to_shared_c.py		\
			tests/shared_a_to_shared_f.py		\
			tests/shared_d_to_shared_g.py		\
			tests/shared_e_to_shared_h.py		\
			tests/shared_j_to_shared_i.py		\
			tests/shared_i_to_shared_j.py		\
			tests/shared_k_to_shared_l.py		\
			tests/shared_l_to_shared_k.py		\
			tests/shared_m_to_shared_n.py		\
								\
			tests/shared_a_to_shared_combined.py

$(TESTS): $(TESTS_DIR)/testgen.py
	$(AM_V_GEN) python $(TESTS_DIR)/testgen.py $(subst _to_, ,$(subst .py,,$(subst tests/, ,$@)))  --outfile $@


TEST_EXTENSIONS = .py
PY_LOG_COMPILER = python

CLEANFILES = $(TESTS) $(TESTS:.py=.binpatch)
