static int var;

int __attribute__ ((noinline)) func_h(void)
{
	var = 'h';
	return var;
}

int __attribute__ ((noinline)) caller(int dry_run)
{
	return func_h();
}
