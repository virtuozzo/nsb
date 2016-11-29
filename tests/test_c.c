int __attribute__ ((noinline)) func_c(void)
{
	return 'c';
}

int __attribute__ ((noinline)) caller(int dry_run)
{
	return func_c();
}
