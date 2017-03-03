#include "test_types.h"

#ifdef PATCH

extern long vzpatch_test_static_func(int type);

long test_static_func_cb(int type)
{
	return vzpatch_test_static_func(type);
}

#else

#include "static_func.c"

long test_static_func_cb(int type)
{
	return test_static_func(type);
}

#endif
