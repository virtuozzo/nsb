/*
 * Copyright (c) 2016-2017, Parallels International GmbH
 *
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#include "test_types.h"

long ext_global_func(int type)
{
	if (atoi("3") == 3)
		return function_result(type);
	return TEST_FAILED;
}
