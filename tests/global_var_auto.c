#include "test_types.h"

#ifdef PATCH
extern long global_var_auto;
#else
long global_var_auto = original_result(TEST_TYPE_GLOBAL_VAR_AUTO);
#endif

long test_global_var_auto(int type)
{
	return global_var_auto;
}
