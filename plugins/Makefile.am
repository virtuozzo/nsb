LIBS =

AM_CFLAGS = -Wall -Wformat-security -Werror -DCONFIG_X86_64 -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE
AM_MAKEFLAGS = --no-print-directory

libnsb_service_la_SOURCES =				\
					service.h	\
							\
					service.c

libnsb_service_la_CFLAGS = $(AM_CFLAGS) -g

lib_LTLIBRARIES = libnsb_service.la
