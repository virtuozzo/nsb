#include "test_types.h"

extern long test_global_func(int type);

long test_global_func_cb(int type)
{
	return test_global_func(type);
}
