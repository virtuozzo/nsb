#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdlib.h>

extern int caller(int dry_run);

typedef int (*caller_t)(int dry_run);

int signalled;

static void sighandler(int dummy)
{
	signalled = 1;
}

int call_after_sig(caller_t caller)
{
	signal(SIGINT, sighandler);

	while (!signalled)
		(void) caller(0);
	return caller(0);
}

void *thread_fn(void *data)
{
	exit(call_after_sig(caller));
}

int main(int argc, char **argv)
{
	pthread_t th1, th2;
	int rc1, rc2;

	if (argc == 1)
		return caller(1);

	rc1 = pthread_create(&th1, NULL, thread_fn, NULL);
	rc2 = pthread_create(&th2, NULL, thread_fn, NULL);

	if (rc1 | rc2)
		return 1;

        rc1 = pthread_join(th1, NULL);
	rc2 = pthread_join(th2, NULL);

	if (rc1 != rc2)
		return 1;

	return rc1;
}
