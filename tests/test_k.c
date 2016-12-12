int var;

int __attribute__ ((noinline)) func_k(int dry_run)
{
	if (dry_run)
		return 'k';

	if (!var) {
		var = 'k';
		return 0;
	} else if (var == 'j')
		return -1;
	return 'k';
}

int __attribute__ ((noinline)) caller(int dry_run)
{
	return func_k(dry_run);
}
