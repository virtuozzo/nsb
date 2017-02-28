#include "test_types.h"

struct global_var_addend_s {
	long a;
	long b;
};

#ifdef PATCH
extern struct global_var_addend_s global_var_addend;
#else
struct global_var_addend_s global_var_addend;
#endif

long *global_var_addend_b_ptr = &global_var_addend.b;

long lib_global_var_addend(int type)
{
	if (!global_var_addend.b)
		global_var_addend.b = function_result(type);
	return *global_var_addend_b_ptr;
}
