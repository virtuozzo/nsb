/*
 * Copyright (c) 2016-2017, Parallels International GmbH
 *
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#include "test_types.h"

#ifdef PATCH
extern long vzpatch_test_global_func(int type);

long test_global_func_cb_manual(int type)
{
	return vzpatch_test_global_func(type);
}
#else
extern long test_global_func(int type);

long test_global_func_cb_manual(int type)
{
	/* Increasing function size up to 8+ bytes
	 * to overcome generator limitation */
	asm("nop;nop;nop;nop;nop;nop;nop;nop;");
	return test_global_func(type);
}
#endif
