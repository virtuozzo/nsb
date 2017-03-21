LIBS =

AM_LDFLAGS = -avoid-version -rpath /whereever

libtest_la_SOURCES =	library.c test_types.h
libtests_la_CFLAGS = $(AM_CFLAGS) -g

check_LTLIBRARIES = libtest.la

nsbtest_library_SOURCES = main.c
nsbtest_library_LDADD = libtest.la -lpthread
nsbtest_library_CFLAGS = $(AM_CFLAGS) -g

nsbtest_static_SOURCES = main.c library.c test_types.h
nsbtest_static_LDADD = -lpthread
nsbtest_static_CFLAGS = $(AM_CFLAGS) -g

nsbtest_shared_SOURCES = main.c library.c test_types.h
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

patch_%.so: %.c test_types.h
	$(AM_V_CC) $(CC) -DPATCH -g -shared -fpic $^ -o $@

patch_global_func.so$(EXEEXT): global_func.c
patch_static_func.so$(EXEEXT): static_func.c
patch_ext_global_func.so$(EXEEXT): ext_global_func.c
patch_global_func_cb.so$(EXEEXT): global_func_cb.c
patch_global_func_p.so$(EXEEXT): global_func_p.c
patch_global_var.so$(EXEEXT): global_var.c
patch_global_var_addr.so$(EXEEXT): global_var_addr.c
patch_static_func_cb.so$(EXEEXT): static_func_cb.c
patch_static_var.so$(EXEEXT): static_var.c

check_PROGRAMS += patch_global_func.so
check_PROGRAMS += patch_static_func.so
check_PROGRAMS += patch_ext_global_func.so
check_PROGRAMS += patch_global_func_cb.so
check_PROGRAMS += patch_global_func_p.so
check_PROGRAMS += patch_global_var.so
check_PROGRAMS += patch_global_var_addr.so
check_PROGRAMS += patch_static_func_cb.so
check_PROGRAMS += patch_static_var.so

ctags:
