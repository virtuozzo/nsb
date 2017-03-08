#include "test_types.h"

#ifdef PATCH
extern long vzpatch_test_global_func(int type);

long test_global_func_cb(int type)
{
	return vzpatch_test_global_func(type);
}
#else
extern long test_global_func(int type);

long test_global_func_cb(int type)
{
	/* Increasing function size up to 8+ bytes
	 * to overcome generator limitation */
	asm("nop;nop;nop;nop;nop;nop;nop;nop;");
	return test_global_func(type);
}
#endif
