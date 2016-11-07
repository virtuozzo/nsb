SUBDIRS = samples

AM_CFLAGS = -Wall -Wformat-security -Werror -DCONFIG_X86_64 -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE
AM_MAKEFLAGS = --no-print-directory

SUFFIXES = .pb-c.c .pb-c.h .proto
.proto.pb-c.c:
	$(AM_V_GEN) protoc-c -I=. --c_out=. $<

BUILT_SOURCES =		protobuf/funcpatch.pb-c.c
CLEANFILES = $(BUILT_SOURCES)

bin_PROGRAMS = nsb

nsb_SOURCES =						\
			protobuf/funcpatch.pb-c.c	\
			protobuf/funcpatch.pb-c.h	\
							\
			patcher/src/protobuf.c		\
			patcher/src/log.c		\
			patcher/src/main.c		\
			patcher/src/patch.c

nsb_CPPFLAGS = -Ipatcher/include -Ipatcher/compel -Iprotobuf/
nsb_LDFLAGS = -rdynamic
nsb_LDADD =		patcher/compel/lib/libcompel.a		\
			patcher/compel/lib/std.built-in.o	\
			patcher/compel/lib/fds.built-in.o	\
			-lprotobuf-c

noinst_SCRIPTS =	protobuf/funcpatch_pb2.py
CLEANFILES += $(noinst_SCRIPTS)

SUFFIXES += _pb2.py

.proto_pb2.py:
	$(AM_V_GEN) protoc -I=. --python_out=. $<

AM_V_CP = $(am__v_CP_@AM_V@)
am__v_CP_ = $(am__v_CC_@AM_DEFAULT_V@)
am__v_CP_0 = @echo "  CP      " $@;
am__v_CP_1 =

patchgen/funcpatch_pb2.py:  protobuf/funcpatch_pb2.py
	$(AM_V_CP) cp $< $@

all: patchgen/funcpatch_pb2.py

CLEANFILES += patchgen/funcpatch_pb2.py
