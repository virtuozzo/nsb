#include <stdio.h>
#include <stdbool.h>

#include "test_types.h"

#include "lib_global_func.c"
#include "lib_static_func.c"
#include "ext_global_func.c"
#include "lib_global_func_cb.c"
#include "lib_global_func_p.c"
#include "lib_global_var.c"
#include "lib_global_var_addr.c"
#include "lib_static_func_cb.c"
#include "lib_static_var.c"

typedef long (*test_actor_t)(int tt);

struct test_info_s {
	test_actor_t	actor;
	bool		match;
} tst_info[TEST_TYPE_MAX] = {
	[TEST_TYPE_LIB_GLOBAL_FUNC] = {
		.actor = lib_global_func,
		.match = false,
	},
	[TEST_TYPE_LIB_STATIC_FUNC] = {
		.actor = lib_static_func,
		.match = false,
	},
	[TEST_TYPE_EXT_GLOBAL_FUNC] = {
		.actor = ext_global_func,
		.match = false,
	},
	[TEST_TYPE_LIB_GLOBAL_FUNC_CB] = {
		.actor = lib_global_func_cb,
		.match = true,
	},
	[TEST_TYPE_LIB_GLOBAL_FUNC_P] = {
		.actor = lib_global_func_p,
		.match = false,
	},
	[TEST_TYPE_LIB_GLOBAL_VAR] = {
		.actor = lib_global_var,
		.match = true,
	},
	[TEST_TYPE_LIB_GLOBAL_VAR_ADDR] = {
		.actor = lib_global_var_addr,
		.match = true,
	},
	[TEST_TYPE_LIB_STATIC_FUNC_CB] = {
		.actor = lib_static_func_cb,
		.match = true,
	},
	[TEST_TYPE_LIB_STATIC_VAR] = {
		.actor = lib_static_var,
		.match = true,
	},
};

static const struct test_info_s *get_test_info(int tt)
{
	if ((tt < TEST_TYPE_LIB_GLOBAL_FUNC) ||
	    (tt >= TEST_TYPE_MAX)) {
		printf("wrong test type: %d\n", tt);
		return NULL;
	}
	return &tst_info[tt];
}

int run_test(int tt, int print)
{
	const struct test_info_s *ti = get_test_info(tt);
	bool failed;

	if (!ti)
		return TEST_ERROR;

	if (ti->match)
		failed = ti->actor(tt) != original_result(tt);
	else
		failed = ti->actor(tt) != patched_result(tt);

	if (print) {
		printf("Original result: %#lx\n", original_result(tt));
		printf("Patched  result: %#lx\n", patched_result(tt));
		printf("Actor result   : %#lx\n", ti->actor(tt));
	}
	return failed;
}
