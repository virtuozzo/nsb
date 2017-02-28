#include "test_types.h"

long global_func_p(int type)
{
	return function_result(type);
}

long lib_global_func_p(int type)
{
	return global_func_p(type);
}
