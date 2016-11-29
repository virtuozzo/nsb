#include <stdlib.h>

#include "waitsig.h"

int __attribute__ ((noinline)) func_g(void)
{
	return atoi("1") + 7;
}

int __attribute__ ((noinline)) caller(void)
{
	return func_g();
}

int main(int argc, char **argv)
{
	return call_after_sig(caller);
}
