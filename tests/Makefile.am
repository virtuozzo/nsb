LIBS =

TESTS_LIST = 				\
		global_func.c		\
		ext_global_func.c	\
		global_func_cb.c	\
		global_func_p.c		\
		global_var.c		\
		global_var_addr.c	\
		static_func_cb.c	\
		static_var.c

AM_LDFLAGS = -avoid-version -rpath /whereever

libtest_la_SOURCES = library.c test_types.h $(TESTS_LIST)
libtest_la_CFLAGS = $(AM_CFLAGS) -g

check_LTLIBRARIES = libtest.la

nsbtest_library_SOURCES = main.c
nsbtest_library_LDADD = libtest.la -lpthread
nsbtest_library_CFLAGS = $(AM_CFLAGS) -g

nsbtest_static_SOURCES = main.c library.c test_types.h $(TESTS_LIST)
nsbtest_static_LDADD = -lpthread
nsbtest_static_CFLAGS = $(AM_CFLAGS) -g

nsbtest_shared_SOURCES = main.c library.c test_types.h $(TESTS_LIST)
nsbtest_shared_LDADD = -lpthread
nsbtest_shared_CFLAGS = $(AM_CFLAGS) -g -fpic -pie

check_PROGRAMS = nsbtest_library nsbtest_static nsbtest_shared

nsb_test_types.py$(EXEEXT): test_types.h
	$(AM_V_GEN) python convert_test_types.py $<

nsb_test_types.py$(EXEEXT):  convert_test_types.py

check_SCRIPTS = nsb_test_types.py

#########################
# Patches
########################

.c.patch: test_types.h
	$(AM_V_CC) $(CC) -DPATCH -g -shared -fpic $^ -o $@

check_DATA = global_func.patch
check_DATA += static_func.patch
check_DATA += ext_global_func.patch
check_DATA += global_func_cb.patch
check_DATA += global_func_p.patch
check_DATA += global_var.patch
check_DATA += global_var_addr.patch
check_DATA += static_func_cb.patch
check_DATA += static_var.patch
