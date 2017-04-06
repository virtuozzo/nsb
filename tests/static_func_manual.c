/*
 * Copyright (c) 2016-2017, Parallels International GmbH
 *
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#include "test_types.h"

#ifdef PATCH

extern long vzpatch_static_func_manual(int type);

long __attribute__ ((noinline)) test_static_func_manual(int type)
{
	return vzpatch_static_func_manual(type);
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
