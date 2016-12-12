#include <stdlib.h>
#include <stdio.h>

int global_var;
static int local_var;
static char buf[8];

#define VAL	5

static int __attribute__ ((noinline)) call_external_function(void)
{
	sprintf(buf, "%d", local_var);
	return 0;
}

static void __attribute__ ((noinline)) update_global_var(void)
{
	global_var = VAL + local_var;
}

static void __attribute__ ((noinline)) set_local_var(void)
{
	local_var = VAL;
}

static int __attribute__ ((noinline)) return_number(void)
{
	return VAL;
}

int __attribute__ ((noinline)) caller(int dry_run)
{
	int err;

	global_var = return_number();

	set_local_var();
	update_global_var();

	err = call_external_function();
	if (err) {
		printf("call_external_function\n");
		return 1;
	}

	if (atoi(buf) + VAL != global_var) {
		printf("atoi(buf) + VAL != global_var\n");
		return 1;
	}

	printf("PASS\n");
	return 0;
}
