#include <unistd.h>
#include <signal.h>
#include <stdio.h>

typedef int (*caller_t)(void);
extern int test_func(void);

int signalled;

static void sighandler(int dummy)
{
	signalled = 1;
}

static int __attribute__ ((noinline)) call_after_sig(void)
{
	int ret, old;

	old = test_func();

	signal(SIGINT, sighandler);

	while (!signalled) {
		sleep(1);
	}

	ret = test_func();

	return old == ret;
}

int main(int argc, char **argv)
{
	return call_after_sig();
}
