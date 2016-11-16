#include <stdlib.h>

#include "waitsig.h"

static int var;

int __attribute__ ((noinline)) func_j(void)
{
	if (var)
		var += 2;
	return var + 5;
}

int __attribute__ ((noinline)) test_func(void)
{
	return func_j();
}
