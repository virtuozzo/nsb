static int dummy;
static int var;

static int __attribute__ ((noinline)) set_var(void)
{
	var = 'n';
}

int __attribute__ ((noinline)) get_var(void)
{
	return var;
}

int __attribute__ ((noinline)) caller(int dry_run)
{
	set_var();
	return get_var();
}
