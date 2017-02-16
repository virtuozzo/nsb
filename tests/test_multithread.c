#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdbool.h>

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

int main(int argc, char **argv)
{
	if (argc == 1)
		return caller(1);

	return call_after_sig(caller);
}
