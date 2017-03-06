#include "test_types.h"

#ifdef PATCH

extern long vzpatch_static_var;

long test_static_var(int type)
{
	return vzpatch_static_var;
}

#else

long static_var = original_result(TEST_TYPE_STATIC_VAR);

long test_static_var(int type)
{
	return static_var;
}

#endif