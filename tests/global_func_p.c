#include "test_types.h"

long global_func_p(int type)
{
	return function_result(type);
}

long test_global_func_p(int type)
{
	/* Increasing function size up to 8+ bytes
	 * to overcome generator limitation */
	asm("nop;nop;nop;nop;nop;nop;nop;nop;");
	return global_func_p(type);
}
