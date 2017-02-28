#include "test_types.h"

#ifdef PATCH
extern int global_var;
#else
int global_var = TEST_TYPE_LIB_GLOBAL_VAR;
#endif

int lib_global_var(int type)
{
	return global_var;
}
