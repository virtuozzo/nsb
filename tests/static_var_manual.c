/*
 * Copyright (c) 2016-2017, Parallels International GmbH
 *
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#include "test_types.h"

#ifdef PATCH

extern long vzpatch_static_var_manual;

long test_static_var_manual(int type)
{
	return vzpatch_static_var_manual;
}

#else

static long static_var_manual = original_result(TEST_TYPE_STATIC_VAR_MANUAL);

long test_static_var_manual(int type)
{
	return static_var_manual;
}

/* This is a dummy function to prevent compiler from optimizing away the
 * variable */
void set_static_var_manual(long value)
{
	static_var_manual = value;
}

#endif
