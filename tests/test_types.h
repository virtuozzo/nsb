#ifndef __NSB_TESTS_TYPES__
#define __NSB_TESTS_TYPES__

#define TEST_ERROR	0xDEADDEAD
#define TEST_FAILED	0xDEADBEAF

typedef enum {
	TEST_TYPE_GLOBAL_FUNC,
	TEST_TYPE_STATIC_FUNC,
	TEST_TYPE_EXT_GLOBAL_FUNC,
	TEST_TYPE_GLOBAL_FUNC_CB,
	TEST_TYPE_GLOBAL_FUNC_P,

	TEST_TYPE_GLOBAL_VAR,
	TEST_TYPE_GLOBAL_VAR_ADDR,

	TEST_TYPE_STATIC_FUNC_CB,
	TEST_TYPE_STATIC_VAR,
	TEST_TYPE_MAX,
} test_type_t;

#define RESULT_CODE			0x0000C0FFEE000000UL

#define original_result(type)		(RESULT_CODE + type)
#define patched_result(type)		(original_result(type) + TEST_TYPE_MAX)

static inline unsigned long __attribute__((always_inline)) function_result(test_type_t type)
{
#ifdef PATCH
	return patched_result(type);
#else
	return original_result(type);
#endif
}

#endif
