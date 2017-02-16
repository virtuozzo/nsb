#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <signal.h>

extern int *caller(int dry_run);

typedef int *(*caller_t)(int dry_run);

int signalled;

static void sighandler(int dummy)
{
	signalled = 1;
}

int call_after_sig(caller_t caller)
{
	int *p1, *p2;

	p1 = caller(0);

	printf("p1: %p\n", p1);

	signal(SIGINT, sighandler);

	while (!signalled)
		p2 = caller(0);
	p2 = caller(0);

	printf("p2: %p\n", p2);

	return p1 != p2;
}

int main(int argc, char **argv)
{
	if (argc == 1)
		return 0;

        return call_after_sig(caller);
}
