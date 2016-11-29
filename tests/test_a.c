int __attribute__ ((noinline)) return_number(void)
{
	return 'a';
}

int __attribute__ ((noinline)) caller(int dry_run)
{
	return return_number();
}
