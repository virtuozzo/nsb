#include "test_types.h"

static long __attribute__ ((noinline)) lib_static_func(int type)
{
	return function_result(type);
}
