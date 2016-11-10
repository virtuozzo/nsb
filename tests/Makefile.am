sample_a_SOURCES =			\
			sample_a.c	\
					\
			waitsig.c	\
			waitsig.h

sample_b_SOURCES =			\
			sample_b.c	\
					\
			waitsig.c	\
			waitsig.h

sample_c_SOURCES =			\
			sample_c.c	\
					\
			waitsig.c	\
			waitsig.h

sample_d_SOURCES =			\
			sample_d.c	\
					\
			waitsig.c	\
			waitsig.h

sample_e_SOURCES =			\
			sample_e.c	\
					\
			waitsig.c	\
			waitsig.h

sample_f_SOURCES =			\
			sample_f.c	\
					\
			waitsig.c	\
			waitsig.h

check_PROGRAMS = sample_a sample_b sample_c sample_d sample_e sample_f

TESTS = sample_a_to_sample_b.py sample_a_to_sample_c.py sample_a_to_sample_f.py
TEST_EXTENSIONS = .py
PY_LOG_COMPILER = python
AM_TESTS_ENVIRONMENT =	export NSB_GENERATOR=@NSB_GENERATOR@; \
			export NSB_PATCHER=@NSB_PATCHER@;

CLEANFILES = $(TESTS:.py=.binpatch)
