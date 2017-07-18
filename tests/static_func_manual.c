#include "test_types.h"

#ifdef PATCH

#include <include/vzp.h>

VZP_STATIC_FUNC_REF(long, static_func_manual, (int))

long __attribute__ ((noinline)) test_static_func_manual(int type)
{
	return static_func_manual(type);
}

#else
static long __attribute__ ((noinline)) static_func_manual(int type)
{
	return function_result(type);
}

long __attribute__ ((noinline)) test_static_func_manual(int type)
{
	asm("nop;nop;nop;nop;nop;nop;nop;nop;");
	return static_func_manual(type);
}
#endif
