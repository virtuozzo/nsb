AM_CFLAGS = -Wall -Wformat-security -Werror -DCONFIG_X86_64 -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE
AM_MAKEFLAGS = --no-print-directory

bin_PROGRAMS = nsb

nsb_SOURCES =			\
		src/log.c	\
		src/main.c	\
		src/patch.c

nsb_CPPFLAGS = -Iinclude -Icompel
nsb_LDADD = compel/lib/libcompel.a compel/lib/std.built-in.o compel/lib/fds.built-in.o
nsb_LDFLAGS = -rdynamic
