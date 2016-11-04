#include "waitsig.h"

int __attribute__ ((noinline)) func_a(void)
{
	return 3;
}

int __attribute__ ((noinline)) caller(void)
{
	return func_a();
}

int main(int argc, char **argv)
{
	return call_after_sig(caller);
}
