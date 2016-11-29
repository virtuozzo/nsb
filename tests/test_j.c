static int var;

int __attribute__ ((noinline)) func_j(int dry_run)
{
	if (dry_run)
		return 'j';

	if (!var) {
		var = 'j';
		return 0;
	} else if (var == 'j')
		return -1;
	return 'j';
}

int __attribute__ ((noinline)) caller(int dry_run)
{
	return func_j(dry_run);
}
