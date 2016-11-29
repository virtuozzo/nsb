#include <stdlib.h>

int __attribute__ ((noinline)) func_g(void)
{
	return atoi("1") + 7;
}

int __attribute__ ((noinline)) caller(int dry_run)
{
	return func_g();
}
