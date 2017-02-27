#include "test_types.h"

int global_func_p(int type)
{
	return function_result(type);
}

int lib_global_func_p(int type)
{
	return global_func_p(type);
}
