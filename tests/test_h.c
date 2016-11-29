#include <stdlib.h>

static int var;

int __attribute__ ((noinline)) func_b(void)
{
	var += 2;
	return var + 3;
}

int __attribute__ ((noinline)) caller(int dry_run)
{
	return func_b();
}
