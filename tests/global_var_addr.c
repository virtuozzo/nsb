/*
 * Copyright (c) 2016-2017, Parallels International GmbH
 *
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#include "test_types.h"

#ifdef PATCH
extern long global_var;
extern long *global_var_addr;
#else
extern long global_var;
long *global_var_addr= &global_var;
#endif

long test_global_var_addr(int type)
{
	if (global_var_addr== &global_var)
		return original_result(type);
	return TEST_FAILED;
}
