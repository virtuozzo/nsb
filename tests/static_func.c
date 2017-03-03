#ifndef __NSB_TESTS_LIB_STATIC_FUNC_C__
#define __NSB_TESTS_LIB_STATIC_FUNC_C__

#include "test_types.h"

static long __attribute__ ((noinline)) test_static_func(int type)
{
	return function_result(type);
}

#endif /* __NSB_TESTS_LIB_STATIC_FUNC_C__ */
