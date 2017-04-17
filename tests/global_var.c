/*
 * Copyright (c) 2016-2017, Parallels International GmbH
 *
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#include "test_types.h"

#ifdef PATCH
extern long global_var;
#else
long global_var = original_result(TEST_TYPE_GLOBAL_VAR);
#endif

long test_global_var(int type)
{
	return global_var;
}
