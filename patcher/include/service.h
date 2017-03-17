#ifndef __PATCHER_SERVICE_H__
#define __PATCHER_SERVICE_H__

#include <stdbool.h>

#include "list.h"

struct service {
	const char		*name;
	pid_t			pid;
	uint64_t		handle;
	struct list_head	vmas;
	int			sock;
	uint64_t		runner;
	bool			released;
};

struct process_ctx_s;
int service_start(struct process_ctx_s *ctx, struct service *plugin);
int service_stop(struct process_ctx_s *ctx, struct service *plugin);

#endif
