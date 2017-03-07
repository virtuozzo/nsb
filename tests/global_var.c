#include "test_types.h"

#ifdef PATCH
extern long vzpatch_global_var;

long test_global_var(int type)
{
	return vzpatch_global_var;
}
#else
long global_var = original_result(TEST_TYPE_GLOBAL_VAR);

long test_global_var(int type)
{
	return global_var;
}
#endif
