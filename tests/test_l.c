int var;

int __attribute__ ((noinline)) func_l(int dry_run)
{
	if (dry_run)
		return 'l';

	if (!var) {
		var = 'l';
		return 0;
	} else if (var == 'j')
		return -1;
	return 'l';
}

int __attribute__ ((noinline)) caller(int dry_run)
{
	return func_l(dry_run);
}
