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

nsb_CPPFLAGS = -Iprotobuf/ -I/usr/local/lib
nsb_LDFLAGS = -rdynamic

CP_FILES =	generator/funcpatch_pb2.py	\
		generator/binpatch_pb2.py	\
		generator/objinfo_pb2.py

AM_V_CP = $(am__v_CP_@AM_V@)
am__v_CP_ = $(am__v_CP_@AM_DEFAULT_V@)
am__v_CP_0 = @echo "  CP      " $@;

generator/funcpatch_pb2.py:  protobuf/funcpatch_pb2.py
	$(AM_V_CP) cp $< $@
generator/binpatch_pb2.py:  protobuf/binpatch_pb2.py
	$(AM_V_CP) cp $< $@
generator/objinfo_pb2.py:  protobuf/objinfo_pb2.py
	$(AM_V_CP) cp $< $@

all-local: $(CP_FILES)

CLEANFILES = $(CP_FILES)

check_SCRIPTS = 					\
			tests/sample_a_to_sample_b.py	\
			tests/sample_a_to_sample_c.py	\
			tests/sample_a_to_sample_f.py	\
			tests/sample_d_to_sample_g.py	\
			tests/sample_e_to_sample_h.py

$(check_SCRIPTS):
	$(AM_V_GEN) python tests/testgen.py $(subst _to_, ,$(subst .py,,$(subst tests/, ,$@))) --outfile $@

CLEANFILES += $(check_SCRIPTS)

TESTS = $(check_SCRIPTS)
TEST_EXTENSIONS = .py
PY_LOG_COMPILER = python
AM_TESTS_ENVIRONMENT =	export NSB_GENERATOR=@NSB_GENERATOR@;	\
			export NSB_PATCHER=@NSB_PATCHER@;	\
			export TESTS_DIR=@TESTS_DIR@;

CLEANFILES += $(TESTS:.py=.binpatch)
