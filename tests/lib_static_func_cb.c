#include "test_types.h"

#ifdef PATCH

extern long vzpatch_lib_static_func(int type);

long lib_static_func_cb(int type)
{
	return vzpatch_lib_static_func(type);
}

#else

#include "lib_static_func.c"

long lib_static_func_cb(int type)
{
	return lib_static_func(type);
}

#endif
