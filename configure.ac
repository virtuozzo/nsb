AC_INIT([nsb], [0.0.01], [skinsbursky@virtuozzo.org])

m4_ifdef([AM_SILENT_RULES],
	 [AM_SILENT_RULES([yes])],
	 [AC_SUBST([AM_DEFAULT_VERBOSITY], [1])])

AM_INIT_AUTOMAKE([subdir-objects])
AM_PROG_CC_C_O

AC_GNU_SOURCE
AC_CONFIG_FILES([
		 Makefile
		 patchgen/Makefile
		 patchgen/samples/Makefile
		 patchgen/protobuf/Makefile
])

AC_OUTPUT

