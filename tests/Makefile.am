LIBS =

AM_LDFLAGS = -avoid-version -rpath /whereever

libtest_la_SOURCES =	library.c test_types.h

check_LTLIBRARIES = libtest.la

nsbtest_SOURCES = main.c
nsbtest_LDADD = libtest.la

check_PROGRAMS = nsbtest

nsb_test_types.py: test_types.h
	$(AM_V_GEN) python convert_test_types.py $<

nsb_test_types.py:  convert_test_types.py

check_PROGRAMS += nsb_test_types.py

#########################
# Patches
########################

patch_%.so: %.c test_types.h
	$(AM_V_CC) $(CC) -DPATCH -shared -fpic $^ -o $@

patch_lib_global_func.so: lib_global_func.c
patch_lib_static_func.so: lib_static_func.c
patch_ext_global_func.so: ext_global_func.c
patch_lib_global_func_cb.so: lib_global_func_cb.c
patch_lib_global_func_p.so: lib_global_func_p.c
patch_lib_global_var.so: lib_global_var.c
patch_lib_global_var_addr.so: lib_global_var_addr.c
patch_lib_global_var_addend.so: lib_global_var_addend.c

check_PROGRAMS += patch_lib_global_func.so
check_PROGRAMS += patch_lib_static_func.so
check_PROGRAMS += patch_ext_global_func.so
check_PROGRAMS += patch_lib_global_func_cb.so
check_PROGRAMS += patch_lib_global_func_p.so
check_PROGRAMS += patch_lib_global_var.so
check_PROGRAMS += patch_lib_global_var_addr.so
check_PROGRAMS += patch_lib_global_var_addend.so

ctags:
