#include "test_types.h"

extern long global_var;

#ifdef PATCH
extern long *global_var_addr;
#else
long *global_var_addr = &global_var;
#endif

long lib_global_var_addr(int type)
{
	if (global_var_addr == &global_var)
		return original_result(type);
	return TEST_FAILED;
}
