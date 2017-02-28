#include "test_types.h"

#ifdef PATCH
extern long global_var;
#else
long global_var = original_result(TEST_TYPE_LIB_GLOBAL_VAR);
#endif

long lib_global_var(int type)
{
	return global_var;
}
