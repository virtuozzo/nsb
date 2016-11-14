AC_INIT([nsb], [0.0.01], [skinsbursky@virtuozzo.org])

m4_ifdef([AM_SILENT_RULES],
	 [AM_SILENT_RULES([yes])],
	 [AC_SUBST([AM_DEFAULT_VERBOSITY], [1])])

AM_INIT_AUTOMAKE([subdir-objects])
AM_PROG_CC_C_O

AC_GNU_SOURCE
AC_CONFIG_FILES([
		 Makefile
		 protobuf/Makefile
		 tests/Makefile
])

AC_CHECK_PROG(PROTOC_CHECK, protoc, yes)
if test x"$PROTOC_CHECK" != x"yes" ; then
	AC_MSG_ERROR([protobuf-compiler is required.])
fi

AC_CHECK_LIB(
		[protobuf-c],
		[protobuf_c_message_get_packed_size],
		[],
		[AC_MSG_ERROR([*** libprotobuf-c not found.])
])

AC_SUBST([NSB_GENERATOR], ${ac_pwd}/generator/main.py)
AC_SUBST([NSB_PATCHER], ${ac_pwd}/nsb)
AC_SUBST([TESTS_DIR], ${ac_pwd}/tests)

AC_OUTPUT
