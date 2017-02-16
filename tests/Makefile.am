LIBS =

AM_LDFLAGS = -avoid-version -rpath /whereever

libtest_a_la_SOURCES = test_a.c
libtest_b_la_SOURCES = test_b.c
libtest_c_la_SOURCES = test_c.c
libtest_d_la_SOURCES = test_d.c
libtest_e_la_SOURCES = test_e.c
libtest_f_la_SOURCES = test_f.c
libtest_g_la_SOURCES = test_g.c
libtest_h_la_SOURCES = test_h.c
libtest_i_la_SOURCES = test_i.c
libtest_j_la_SOURCES = test_j.c
libtest_k_la_SOURCES = test_k.c
libtest_l_la_SOURCES = test_l.c
libtest_m_la_SOURCES = test_m.c
libtest_n_la_SOURCES = test_n.c

libtest_combined_la_SOURCES = test_combined.c

libtest_mta_la_SOURCES = test_a.c
libtest_mtcombined_la_SOURCES = test_combined.c

libtest_pvar_la_SOURCES = test_pvar.c

check_LTLIBRARIES = libtest_a.la libtest_b.la libtest_c.la libtest_d.la	\
		  libtest_e.la libtest_f.la libtest_g.la libtest_h.la	\
		  libtest_i.la libtest_j.la libtest_k.la libtest_l.la	\
		  libtest_m.la libtest_n.la				\
									\
		  libtest_combined.la					\
		  							\
		  libtest_mta.la					\
		  libtest_mtcombined.la					\
									\
		  libtest_pvar.la

shared_a_SOURCES = test_main.c
shared_a_LDADD = libtest_a.la

shared_b_SOURCES = test_main.c
shared_b_LDADD = libtest_b.la

shared_c_SOURCES = test_main.c
shared_c_LDADD = libtest_c.la

shared_d_SOURCES = test_main.c
shared_d_LDADD = libtest_d.la

shared_e_SOURCES = test_main.c
shared_e_LDADD = libtest_e.la

shared_f_SOURCES = test_main.c
shared_f_LDADD = libtest_f.la

shared_g_SOURCES = test_main.c
shared_g_LDADD = libtest_g.la

shared_h_SOURCES = test_main.c
shared_h_LDADD = libtest_h.la

shared_i_SOURCES = test_main.c
shared_i_LDADD = libtest_i.la

shared_j_SOURCES = test_main.c
shared_j_LDADD = libtest_j.la

shared_k_SOURCES = test_main.c
shared_k_LDADD = libtest_k.la

shared_l_SOURCES = test_main.c
shared_l_LDADD = libtest_l.la

shared_m_SOURCES = test_main.c
shared_m_LDADD = libtest_m.la

shared_n_SOURCES = test_main.c
shared_n_LDADD = libtest_n.la

shared_combined_SOURCES = test_main.c
shared_combined_LDADD = libtest_combined.la


shared_mta_SOURCES = test_main_mt.c
shared_mta_LDADD = libtest_mta.la -lpthread

shared_mtcombined_SOURCES = test_main_mt.c
shared_mtcombined_LDADD = libtest_mtcombined.la -lpthread

shared_pvar_SOURCES = test_main_sym.c
shared_pvar_LDADD = libtest_pvar.la

check_PROGRAMS = shared_a shared_b shared_c shared_d	\
		 shared_e shared_f shared_g shared_h	\
		 shared_i shared_j shared_k shared_l	\
		 shared_m shared_n			\
		 					\
		 shared_combined			\
		 					\
		 shared_mta				\
		 shared_mtcombined			\
							\
		 shared_pvar

static_a_SOURCES =			\
			test_main.c	\
			test_a.c

static_b_SOURCES =			\
			test_main.c	\
			test_b.c

static_c_SOURCES =			\
			test_main.c	\
			test_c.c

static_d_SOURCES =			\
			test_main.c	\
			test_d.c

static_e_SOURCES =			\
			test_main.c	\
			test_e.c

static_f_SOURCES =			\
			test_main.c	\
			test_f.c

static_g_SOURCES =			\
			test_main.c	\
			test_g.c

static_h_SOURCES =			\
			test_main.c	\
			test_h.c

static_i_SOURCES =			\
			test_main.c	\
			test_i.c

static_j_SOURCES =			\
			test_main.c	\
			test_j.c

static_a_CFLAGS = $(AM_CFLAGS)
static_b_CFLAGS = $(AM_CFLAGS)
static_c_CFLAGS = $(AM_CFLAGS)
static_d_CFLAGS = $(AM_CFLAGS)
static_e_CFLAGS = $(AM_CFLAGS)
static_f_CFLAGS = $(AM_CFLAGS)
static_g_CFLAGS = $(AM_CFLAGS)
static_h_CFLAGS = $(AM_CFLAGS)
static_i_CFLAGS = $(AM_CFLAGS)
static_j_CFLAGS = $(AM_CFLAGS)

check_PROGRAMS += static_a static_b static_c static_d static_e static_f static_g static_h static_j static_i
