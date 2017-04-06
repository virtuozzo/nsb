/*
 * Copyright (c) 2016-2017, Parallels International GmbH
 *
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#ifndef __PATCHER_SERVICE_H__
#define __PATCHER_SERVICE_H__

#include <stdbool.h>

#include "list.h"

struct vma_area;

struct service {
	const char		*name;
	pid_t			pid;
	uint64_t		handle;
	struct dl_map		*dlm;
	int			sock;
	uint64_t		runner;
	bool			loaded;
	bool			released;
};

struct process_ctx_s;
int service_start(struct process_ctx_s *ctx, struct service *plugin);
int service_stop(struct process_ctx_s *ctx, struct service *plugin);

struct dl_map;
int service_mmap_dlm(struct process_ctx_s *ctx, const struct service *service,
		     const struct dl_map *dlm);
int service_munmap_dlm(struct process_ctx_s *ctx, const struct service *service,
		       const struct dl_map *dlm);

ssize_t service_needed_array(struct process_ctx_s *ctx, const struct service *service,
			     uint64_t **needed_array);

#endif
