#include "test_types.h"


#ifdef PATCH
extern long vzpatch_global_var;
extern long *vzpatch_global_var_addr;

long test_global_var_addr(int type)
{
	if (vzpatch_global_var_addr == &vzpatch_global_var)
		return original_result(type);
	return TEST_FAILED;
}
#else
extern long global_var;
long *global_var_addr = &global_var;

long test_global_var_addr(int type)
{
	if (global_var_addr == &global_var)
		return original_result(type);
	return TEST_FAILED;
}
#endif
