int __attribute__ ((noinline)) func_b(void)
{
	return 5;
}

int __attribute__ ((noinline)) caller(int dry_run)
{
	int a = 7;

	return func_b() + a;
}
