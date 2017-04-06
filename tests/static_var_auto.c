#include "test_types.h"

#ifdef PATCH
static long static_var_auto = patched_result(TEST_TYPE_STATIC_VAR_AUTO);
#else
static long static_var_auto = original_result(TEST_TYPE_STATIC_VAR_AUTO);
#endif

long test_static_var_auto(int type)
{
	return static_var_auto;
}

/* This is a dummy function to prevent compiler from optimizing away the
 * variable */
void set_static_var_auto(long value)
{
	static_var_auto = value;
}
