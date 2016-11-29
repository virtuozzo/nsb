int __attribute__ ((noinline)) func_b(void)
{
	return 5;
}

int __attribute__ ((noinline)) caller(int dry_run)
{
	return func_b();
}
