#include <stdlib.h>

int __attribute__ ((noinline)) func_g(void)
{
	return atoi("0") + 'g';
}

int __attribute__ ((noinline)) caller(int dry_run)
{
	return func_g();
}
