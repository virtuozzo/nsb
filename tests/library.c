#include <stdio.h>
#include <stdbool.h>

#include "test_types.h"

typedef long (*test_actor_t)(int tt);

extern long test_global_func(int type);
extern long test_static_func(int type);
extern long ext_global_func(int type);
extern long test_global_func_cb(int type);
extern long test_global_func_p(int type);
extern long test_global_var(int type);
extern long test_global_var_addr(int type);
extern long test_static_func_cb(int type);
extern long test_static_var(int type);
extern long test_const_var(int type);

struct test_info_s {
	test_actor_t	actor;
	bool		match;
} tst_info[TEST_TYPE_MAX] = {
	[TEST_TYPE_GLOBAL_FUNC] = {
		.actor = test_global_func,
		.match = false,
	},
	[TEST_TYPE_STATIC_FUNC] = {
		.actor = test_static_func,
		.match = false,
	},
	[TEST_TYPE_EXT_GLOBAL_FUNC] = {
		.actor = ext_global_func,
		.match = false,
	},
	[TEST_TYPE_GLOBAL_FUNC_CB] = {
		.actor = test_global_func_cb,
		.match = true,
	},
	[TEST_TYPE_GLOBAL_FUNC_P] = {
		.actor = test_global_func_p,
		.match = false,
	},
	[TEST_TYPE_GLOBAL_VAR] = {
		.actor = test_global_var,
		.match = true,
	},
	[TEST_TYPE_GLOBAL_VAR_ADDR] = {
		.actor = test_global_var_addr,
		.match = true,
	},
	[TEST_TYPE_STATIC_FUNC_CB] = {
		.actor = test_static_func_cb,
		.match = true,
	},
	[TEST_TYPE_STATIC_VAR] = {
		.actor = test_static_var,
		.match = true,
	},
	[TEST_TYPE_CONST_VAR] = {
		.actor = test_const_var,
		.match = false,
	},
};

static const struct test_info_s *get_test_info(int tt)
{
	if ((tt < TEST_TYPE_GLOBAL_FUNC) ||
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
