#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <pthread.h>
#include <unistd.h>

#include "test_types.h"

extern int run_test(int test_type, int print);

int test_stop;

static void stop_handler(int dummy)
{
	test_stop = 1;
}

static void delay_handler(int dummy)
{
	usleep(1);
}

int call_loop(int test_type)
{
	long iter = 1;

	if (signal(SIGINT, stop_handler) == SIG_ERR) {
		perror("failed to register SIGINT handler");
		return TEST_ERROR;
	}

	if (signal(SIGUSR1, delay_handler) == SIG_ERR) {
		perror("failed to register SIGUSR1 handler");
		return TEST_ERROR;
	}

	if (run_test(test_type, 0) == TEST_ERROR)
		return 1;

	while (!test_stop) {
		if (!(iter % 1000000))
			kill(getpid(), SIGUSR1);
		(void)run_test(test_type, 0);
		iter++;
	}
	return run_test(test_type, 1);
}

static int print_usage(int res)
{
	extern const char *__progname;

	printf("\n"
		"Usage:\n"
		"  %s patch -t test-type -n nr-threads\n"
		"\n", __progname);

	return res;
}

static int run_single_threaded(int test_type)
{
	return call_loop(test_type);
}

static void *thread_fn(void *data)
{
	int test_type = *(int *)data;

	exit(call_loop(test_type));
}

static int run_multi_threaded(int test_type, int nr_threads)
{
	pthread_t *tarray;
	int i;

	tarray = malloc(sizeof(*tarray) * nr_threads);
	if (!tarray) {
		printf("failed to allocate tests array\n");
		return TEST_ERROR;
	}

	for (i = 0; i < nr_threads; i++) {
		if (pthread_create(&tarray[i], NULL, thread_fn, &test_type)) {
			printf("failed to create thread\n");
			return TEST_ERROR;
		}
	}

	for (i = 0; i < nr_threads; i++) {
		int res;

		res = pthread_join(tarray[i], NULL);
		if (res)
			return res;
	}
	return 0;
}

int main(int argc, char **argv)
{
	static const char short_opts[] = "t:n:";
	static struct option long_opts[] = {
		{ "test-type",	required_argument,	0, 't'},
		{ "nr-threads",	required_argument,	0, 'n'},
		{ },
	};
	int opt, idx = -1;
	int test_type = -1;
	int nr_threads = 0;

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
			case 'n':
				nr_threads = atoi(optarg);
				if (nr_threads < 0)
					return print_usage(1);
				break;
			default:
				return print_usage(1);
		}
	}

	if (test_type == -1) {
		printf("test type is required\n");
		return print_usage(1);
	}

	if ((test_type < 0) || (test_type >= TEST_TYPE_MAX)) {
		printf("invalid test type: %d\n", test_type);
		return print_usage(1);
	}

	if (nr_threads)
		return run_multi_threaded(test_type, nr_threads);

	return run_single_threaded(test_type);
}
