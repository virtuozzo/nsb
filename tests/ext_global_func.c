#include "test_types.h"

long ext_global_func(int type)
{
	if (atoi("3") == 3)
		return function_result(type);
	return TEST_FAILED;
}
