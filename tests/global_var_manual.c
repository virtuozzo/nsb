/*
 * Copyright (c) 2016-2017, Parallels International GmbH
 *
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#include "test_types.h"

#ifdef PATCH
extern long vzpatch_global_var_manual;

long test_global_var_manual(int type)
{
	return vzpatch_global_var_manual;
}
#else
long global_var_manual = original_result(TEST_TYPE_GLOBAL_VAR_MANUAL);

long test_global_var_manual(int type)
{
	return global_var_manual;
}
#endif
