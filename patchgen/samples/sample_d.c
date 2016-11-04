#include <stdlib.h>

#include "waitsig.h"

int __attribute__ ((noinline)) func_b(void)
{
	return atoi("1");
}

int __attribute__ ((noinline)) caller(void)
{
	return func_b();
}

int main(int argc, char **argv)
{
	return call_after_sig(caller);
}
