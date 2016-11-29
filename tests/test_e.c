static int var;

int __attribute__ ((noinline)) func_e(void)
{
	var = 'e';
	return var;
}

int __attribute__ ((noinline)) caller(int dry_run)
{
	return func_e();
}
