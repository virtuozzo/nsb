#include <unistd.h>
#include <signal.h>

#include "waitsig.h"

int signalled;

static void sighandler(int dummy)
{
	signalled = 1;
}

int call_after_sig(caller_t caller)
{
	signal(SIGINT, sighandler);

	while (!signalled) {
		sleep(1);
	}
	return caller();
}
