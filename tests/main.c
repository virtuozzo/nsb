#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "test_types.h"

extern int run_test(int test_type);

int signalled;

static void sighandler(int dummy)
{
	signalled = 1;
}

int call_loop(int test_type)
{
	signal(SIGINT, sighandler);

	while (!signalled) {
		if (run_test(test_type) == TEST_FAILED)
			return 1;
	}
	return run_test(test_type);
}

static int print_usage(int res)
{
	extern const char *__progname;

	printf("\n"
		"Usage:\n"
		"  %s patch -t test-type\n"
		"\n", __progname);

	return res;
}

int main(int argc, char **argv)
{
	static const char short_opts[] = "t:";
	static struct option long_opts[] = {
		{ "test-type",	required_argument,	0, 't'},
		{ },
	};
	int opt, idx = -1;
	int test_type = -1;

	while (1) {
		opt = getopt_long(argc, argv, short_opts, long_opts, &idx);
		if (opt == -1)
			break;

		switch (opt) {
			case 't':
				test_type = atoi(optarg);
				if (test_type < 0)
					return print_usage(1);
				break;
			case '?':
				return print_usage(0);
			default:
				return print_usage(1);
		}
	}

	if (test_type == -1) {
		printf("test type is required\n");
		return print_usage(1);
	}

	if ((test_type < TEST_TYPE_LIB_GLOBAL_FUNC) ||
	    (test_type >= TEST_TYPE_MAX)) {
		printf("invalid test type: %d\n", test_type);
		return print_usage(1);
	}

	return call_loop(test_type);
}
