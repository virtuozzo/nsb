#include <stdlib.h>

#include "waitsig.h"

static int var = 1;

int __attribute__ ((noinline)) func_b(void)
{
	return var + 3;
}

int __attribute__ ((noinline)) caller(void)
{
	return func_b();
}

int main(int argc, char **argv)
{
	return call_after_sig(caller);
}
