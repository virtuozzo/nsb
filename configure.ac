AC_INIT([nsb], [0.0.01], [skinsbursky@virtuozzo.org])

m4_ifdef([AM_SILENT_RULES],
	 [AM_SILENT_RULES([yes])],
	 [AC_SUBST([AM_DEFAULT_VERBOSITY], [1])])

AM_INIT_AUTOMAKE([subdir-objects foreign])
AM_PROG_CC_C_O

AC_PATH_PROG([M4], [m4])
AC_CONFIG_MACRO_DIR([m4])

AC_GNU_SOURCE
LT_INIT
AC_CONFIG_HEADERS([nsb_config.h])
AC_CONFIG_FILES([
		 Makefile
		 protobuf/Makefile
		 plugins/Makefile
		 tests/Makefile
])

AM_PATH_PYTHON([2.7])
AC_SUBST(generatordir, ${pythondir}/nsb)

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

AC_CHECK_LIB(
		[compel],
		[compel_prepare],
		[],
		[AC_MSG_ERROR([*** libcompel not found.])
])

AC_CHECK_LIB(
		[dl],
		[dlopen],
		[],
		[AC_MSG_ERROR([*** libdl not found.])
])

AC_CHECK_LIB(
		[unwind],
		[_ULx86_64_create_addr_space],
		[],
		[AC_MSG_ERROR([*** libunwind not found.])
])

AC_CHECK_LIB(
		[unwind-x86_64],
		[_Ux86_64_get_reg],
		[],
		[AC_MSG_ERROR([*** libunwind-x86_64 not found.])
])

AC_CHECK_LIB(
		[unwind-ptrace],
		[_UPT_accessors],
		[],
		[AC_MSG_ERROR([*** libunwind-x86_64 not found.])
])

AC_CHECK_LIB(
		[elf],
		[elf_version],
		[],
		[AC_MSG_ERROR([*** libelf not found.])
])

AC_PYTHON_MODULE(elftools.elf.elffile)
AC_PYTHON_MODULE(google.protobuf)

AC_SUBST([NSB_GENERATOR], ${ac_pwd}/generator/nsbgen.py)
AC_SUBST([NSB_PATCHER], ${ac_pwd}/nsb)
AC_SUBST([TESTS_DIR], ${ac_pwd}/tests)

AC_OUTPUT
