/*
 * Copyright (c) 2016-2017, Parallels International GmbH
 *
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#include "test_types.h"

#ifdef PATCH

#include <include/vzp.h>

VZP_STATIC_VAR_REF(long, static_var_manual_v2)

long test_static_var_manual_v2(int type)
{
	return static_var_manual_v2;
}

#else

static long static_var_manual_v2 = original_result(TEST_TYPE_STATIC_VAR_MANUAL_V2);

long test_static_var_manual_v2(int type)
{
	return static_var_manual_v2;
}

/* This is a dummy function to prevent compiler from optimizing away the
 * variable */
void set_static_var_manual_v2(long value)
{
	static_var_manual_v2 = value;
}

#endif
