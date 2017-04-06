LIBS =

TESTS_LIST = 				\
		global_func.c		\
		ext_global_func.c	\
		global_func_cb_manual.c	\
		global_func_p.c		\
		global_var_manual.c	\
		global_var_addr_manual.c\
		static_func_manual.c	\
		const_var.c		\
		static_var_manual.c	\
					\
		static_func_auto.c	\
		global_func_cb_auto.c	\
		global_var_auto.c	\
		global_var_addr_auto.c	\
		static_var_auto.c

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

.c.o: test_types.h
	$(AM_V_CC) $(CC) -DPATCH -c -g -fpic -ffunction-sections -fdata-sections $^ -o $@

.o.patch:
	$(AM_V_CC) $(CC) -g -shared -fpic $^ -o $@

check_DATA = global_func.patch
check_DATA += static_func_manual.patch
check_DATA += ext_global_func.patch
check_DATA += global_func_cb_manual.patch
check_DATA += global_func_p.patch
check_DATA += global_var_manual.patch
check_DATA += global_var_addr_manual.patch
check_DATA += static_var_manual.patch
check_DATA += const_var.patch

check_DATA += global_func_cb_auto.patch
check_DATA += static_func_auto.patch
check_DATA += global_var_auto.patch
check_DATA += global_var_addr_auto.patch
check_DATA += static_var_auto.patch

.SECONDARY: $(TESTS_LIST:.c=.o)

CLEANFILES = $(TESTS_LIST:.c=.o) $(TESTS_LIST:.c=.patch)
