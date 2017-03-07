#include "test_types.h"

#ifdef PATCH
extern long vzpatch_test_global_func(int type);

long test_global_func_cb(int type)
{
	return vzpatch_test_global_func(type);
}
#else
extern long test_global_func(int type);

long test_global_func_cb(int type)
{
	return test_global_func(type);
}
#endif
