#include "test_types.h"

#ifdef PATCH

extern long vzpatch_static_func(int type);

long __attribute__ ((noinline)) test_static_func(int type)
{
	return vzpatch_static_func(type);
}

#else
static long __attribute__ ((noinline)) static_func(int type)
{
	return function_result(type);
}

long __attribute__ ((noinline)) test_static_func(int type)
{
	asm("nop;nop;nop;nop;nop;nop;nop;nop;");
	return static_func(type);
}
#endif
