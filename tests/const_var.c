#include "test_types.h"

long test_const_var(int type)
{
#ifdef PATCH
	return patched_result(TEST_TYPE_CONST_VAR);
#else
	return original_result(TEST_TYPE_CONST_VAR);
#endif
}
