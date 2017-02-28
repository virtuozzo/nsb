#include "test_types.h"

#ifdef PATCH
extern int global_var;
#endif

void *lib_global_var_addr(int type)
{
	return function_addr_result(type, &global_var);
}
