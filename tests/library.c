#include <stdio.h>

#include "test_types.h"

#include "lib_global_func.c"
#include "lib_static_func.c"
#include "ext_global_func.c"
#include "lib_global_func_cb.c"

int run_test(int tt)
{
	switch (tt) {
		case TEST_TYPE_LIB_GLOBAL_FUNC:
			return lib_global_func(tt) != patched_result(tt);
		case TEST_TYPE_LIB_STATIC_FUNC:
			return lib_static_func(tt) != patched_result(tt);
		case TEST_TYPE_EXT_GLOBAL_FUNC:
			return ext_global_func(tt) != patched_result(tt);
		case TEST_TYPE_LIB_GLOBAL_FUNC_CB:
			return lib_global_func_cb(tt) != patched_result(tt);
	}
}
