#include "test_types.h"

extern long lib_global_func(int type);

long lib_global_func_cb(int type)
{
	return lib_global_func(type);
}
