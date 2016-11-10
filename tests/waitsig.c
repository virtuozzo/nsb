#include <unistd.h>
#include <signal.h>
#include <stdio.h>

#include "waitsig.h"

int signalled;

static void sighandler(int dummy)
{
	signalled = 1;
}

int call_after_sig(caller_t caller)
{
	int ret, old;

	old = caller();

	signal(SIGINT, sighandler);

	while (!signalled) {
		sleep(1);
	}

	ret = caller();

	printf("caller result: %d ---> %d\n", old, ret);

	return ret;
}
