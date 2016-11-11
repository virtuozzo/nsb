#ifndef __TESTS_WAITSIG_H__
#define __TESTS_WAITSIG_H__

typedef int (*caller_t)(void);

int call_after_sig(caller_t caller);

#endif
