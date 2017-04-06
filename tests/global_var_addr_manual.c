/*
 * Copyright (c) 2016-2017, Parallels International GmbH
 *
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#include "test_types.h"


#ifdef PATCH
extern long vzpatch_global_var_manual;
extern long *vzpatch_global_var_addr_manual;

long test_global_var_addr_manual(int type)
{
	if (vzpatch_global_var_addr_manual == &vzpatch_global_var_manual)
		return original_result(type);
	return TEST_FAILED;
}
#else
extern long global_var_manual;
long *global_var_addr_manual = &global_var_manual;

long test_global_var_addr_manual(int type)
{
	if (global_var_addr_manual == &global_var_manual)
		return original_result(type);
	return TEST_FAILED;
}
#endif
