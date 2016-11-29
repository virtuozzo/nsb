#include <stdlib.h>

int __attribute__ ((noinline)) func_b(void)
{
	return atoi("1");
}

int __attribute__ ((noinline)) caller(int dry_run)
{
	return func_b();
}
