AM_CFLAGS = -Wall -Wformat-security -Werror -DCONFIG_X86_64 -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE
AM_MAKEFLAGS = --no-print-directory

%.pb-c.c: @PROTODIR@/%.proto
	$(AM_V_GEN) protoc-c -I=@PROTODIR@ --c_out=. $<

BUILT_SOURCES =					\
			funcpatch.pb-c.c	\
			funcpatch.pb-c.h

bin_PROGRAMS = nsb

nsb_SOURCES =			\
		src/log.c	\
		src/main.c	\
		src/patch.c

nodist_nsb_SOURCES = $(BUILT_SOURCES)
CLEANFILES = $(BUILT_SOURCES)

nsb_CPPFLAGS = -Iinclude -Icompel

nsb_LDADD =	compel/lib/libcompel.a		\
		compel/lib/std.built-in.o	\
		compel/lib/fds.built-in.o	\
		-lprotobuf-c

nsb_LDFLAGS = -rdynamic
