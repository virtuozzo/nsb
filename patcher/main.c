#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>

#include <compel/compel.h>

#include "include/version.h"
#include "include/patch.h"
#include "include/log.h"

/* Stub for compel */
int compel_main(void *arg_p, unsigned int arg_s) { return 0; }

struct options {
	pid_t		 pid;
	const char	*patch_path;
	int		verbosity;
	char		*command;
};

static int parse_options(int argc, char **argv, struct options *o)
{

	static const char short_opts[] = "p:v:f:";
	static struct option long_opts[] = {
		{ "pid",			required_argument,	0, 'p'	},
		{ "log-level",			required_argument,	0, 'v'	},
		{ "filename",			required_argument,	0, 'f'	},
		{ },
	};
	int opt, idx = -1;

	while (1) {
		opt = getopt_long(argc, argv, short_opts, long_opts, &idx);
		if (opt == -1)
			break;

		switch (opt) {
		case 'p':
			o->pid = atoi(optarg);
			if (o->pid <= 0)
				goto bad_arg;
			break;
		case 'v':
			o->verbosity = atoi(optarg);
			if (o->verbosity <= 0)
				goto bad_arg;
			break;
		case 'f':
			o->patch_path = optarg;
			break;
		default:
			goto usage;
		}
	}

	if (!o->pid) {
		pr_msg("Error: process pid has to be provided\n");
		goto usage;
	}

	if (!o->patch_path) {
		pr_msg("Error: patch file has to be provided\n");
		goto usage;
	}

	if (optind == argc) {
		pr_msg("Error: command has to be provided\n");
		goto usage;
	}
	if (argc > optind + 1) {
		pr_msg("Error: only one command has to be provided\n");
		goto usage;
	}

	o->command = argv[optind];
	return 0;

usage:
	pr_msg("\n"
"Usage:\n"
"  nsb patch -p PID -f patch-file [options]\n"
"\n");
	return 1;

bad_arg:
	if (idx < 0)
		pr_msg("Error: invalid argument for -%c: %s\n",
		       opt, optarg);
	else
		pr_msg("Error: invalid argument for --%s: %s\n",
		       long_opts[idx].name, optarg);

	return 1;
}

int main(int argc, char *argv[])
{
	struct options o = {};
	int err;

	err = parse_options(argc, argv, &o);
	if (err)
		return err;

	log_set_loglevel(o.verbosity);
	log_init(NULL);

	compel_log_init(__print_on_level, o.verbosity);

	if (strcmp(o.command, "patch")) {
		pr_msg("Error: unknown command: %s\n", argv[optind]);
		return -1;
	}

	return patch_process(o.pid, 4096, o.patch_path);
}
