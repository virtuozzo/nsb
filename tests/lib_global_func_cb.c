#include "test_types.h"

int lib_global_func_cb(int type)
{
	if (lib_global_func(type) == original_result(type))
		return function_result(type);
	return TEST_FAILED;
}
