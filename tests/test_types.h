#ifndef __NSB_TESTS_TYPES__
#define __NSB_TESTS_TYPES__

#define TEST_FAILED	0xDEADBEAF

typedef enum {
	TEST_TYPE_LIB_GLOBAL_FUNC,
	TEST_TYPE_LIB_STATIC_FUNC,
	TEST_TYPE_EXT_GLOBAL_FUNC,
	TEST_TYPE_LIB_GLOBAL_FUNC_CB,
	TEST_TYPE_LIB_GLOBAL_FUNC_P,
	TEST_TYPE_MAX,
} test_type_t;

#define RESULT		0xC0FFEE

static inline int __attribute__((always_inline)) original_result(test_type_t type)
{
	return RESULT + type;
}

static inline int __attribute__((always_inline)) patched_result(test_type_t type)
{
	return original_result(type) + TEST_TYPE_MAX;
}

static inline int __attribute__((always_inline)) function_result(test_type_t type)
{
#ifdef PATCH
	return patched_result(type);
#else
	return original_result(type);
#endif
}

#endif
