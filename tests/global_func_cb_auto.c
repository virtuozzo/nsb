#include "test_types.h"

extern long test_global_func(int type);

long test_global_func_cb_auto(int type)
{
	/* Increasing function size up to 8+ bytes
	 * to overcome generator limitation */
	asm("nop;nop;nop;nop;nop;nop;nop;nop;");
	return test_global_func(type);
}
