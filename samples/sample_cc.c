#include "waitsig.h"

int __attribute__ ((noinline)) func_b(void)
{
	return 5;
}

int __attribute__ ((noinline)) caller(void)
{
	int a = 7;

	return func_b() + a;
}

int main(int argc, char **argv)
{
	return call_after_sig(caller);
}
