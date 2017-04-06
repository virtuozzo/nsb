#include "test_types.h"

#ifdef PATCH
extern long global_var_auto;
extern long *global_var_addr_auto;
#else
extern long global_var_auto;
long *global_var_addr_auto = &global_var_auto;
#endif

long test_global_var_addr_auto(int type)
{
	if (global_var_addr_auto == &global_var_auto)
		return original_result(type);
	return TEST_FAILED;
}
