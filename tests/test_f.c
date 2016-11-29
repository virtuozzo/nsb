int __attribute__ ((noinline)) func_f(void)
{
	return 'f';
}

int __attribute__ ((noinline)) caller(int dry_run)
{
	int a = 0;

	return func_f() + a;
}
