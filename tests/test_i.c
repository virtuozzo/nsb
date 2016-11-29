static int var;

int __attribute__ ((noinline)) func_i(int dry_run)
{
	if (dry_run)
		return 'i';

	if (!var) {
		var = 'i';
		return 0;
	} else if (var == 'i')
		return -1;
	return 'i';
}

int __attribute__ ((noinline)) caller(int dry_run)
{
	return func_i(dry_run);
}
