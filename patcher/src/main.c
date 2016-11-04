#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>

#include "version.h"
#include "patch.h"
#include "log.h"

/* Stub for compel */
int compel_main(void *arg_p, unsigned int arg_s) { return 0; }

int main(int argc, char *argv[])
{
	pid_t pid = 0;
	int opt, idx;

	static const char short_opts[] = "p:v:";
	static struct option long_opts[] = {
		{ "pid",			required_argument,	0, 'p'	},
		{ "log-level",			required_argument,	0, 'v'	},
		{ },
	};

	if (argc < 2)
		goto usage;

	while (1) {
		idx = -1;
		opt = getopt_long(argc, argv, short_opts, long_opts, &idx);
		if (opt == -1)
			break;

		switch (opt) {
		case 'p':
			pid = atoi(optarg);
			if (pid <= 0)
				goto bad_arg;
			break;
		case 'v':
			log_set_loglevel(atoi(optarg));
			break;
		default:
			goto usage;
			break;
		}
	}

	log_init(NULL);

	if (!strcmp(argv[optind], "patch"))
		return patch_process(pid, 4096);

	pr_msg("Error: unknown command: %s\n", argv[optind]);
usage:
	pr_msg("\n"
"Usage:\n"
"  nsb patch -t PID [options]\n"
"\n");
	return 0;

bad_arg:
	if (idx < 0)
		pr_msg("Error: invalid argument for -%c: %s\n",
		       opt, optarg);
	else
		pr_msg("Error: invalid argument for --%s: %s\n",
		       long_opts[idx].name, optarg);
	return 1;
}
