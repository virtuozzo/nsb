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

	if (old == ret)
		return 1;

	/* TODO; there should be some better way to check that patch was
	 * applied properly.
	 * However, code is changing in case of printing some text: mov command
	 * uses different addresses.
	 */
	return 0;
}
