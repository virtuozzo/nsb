#include <stdlib.h>

int __attribute__ ((noinline)) func_d(void)
{
	return atoi("0") + 'd';
}

int __attribute__ ((noinline)) caller(int dry_run)
{
	return func_d();
}
