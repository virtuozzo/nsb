/*
 * Copyright (c) 2016-2017, Parallels International GmbH
 *
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#include "test_types.h"

#ifdef PATCH
static const long const_var = patched_result(TEST_TYPE_CONST_VAR);
#else
static const long const_var = original_result(TEST_TYPE_CONST_VAR);
#endif

long test_const_var(int type)
{
	return const_var;
}
