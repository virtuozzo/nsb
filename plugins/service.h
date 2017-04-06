/*
 * Copyright (c) 2016-2017, Parallels International GmbH
 *
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#ifndef __NSB_PLUGINS_SERVICE__
#define __NSB_PLUGINS_SERVICE__

#include <limits.h>

typedef enum {
	NSB_SERVICE_CMD_EMERG_SIGFRAME,
	NSB_SERVICE_CMD_STOP,
	NSB_SERVICE_CMD_NEEDED_LIST,
	NSB_SERVICE_CMD_MMAP,
	NSB_SERVICE_CMD_MUNMAP,
	NSB_SERVICE_CMD_MAX,
} nsb_service_cmd_t;

#define NSB_SERVICE_MESSAGE_DATA_SIZE		8192

struct nsb_service_request {
	unsigned cmd;
	char data[NSB_SERVICE_MESSAGE_DATA_SIZE];
};

struct nsb_service_response {
	int ret;
	char data[NSB_SERVICE_MESSAGE_DATA_SIZE];
};

struct nsb_service_needed_list {
	size_t nr_addrs;
	uint64_t address[1];
};

#define NSB_SERVICE_NEEDED_LIST_SIZE_MAX	\
	(NSB_SERVICE_MESSAGE_DATA_SIZE - sizeof(struct nsb_service_needed_list))

struct nsb_service_map_addr_info {
	uint64_t addr;
	size_t length;
};

struct nsb_service_mmap_info {
	struct nsb_service_map_addr_info info;
	int prot;
	int flags;
	off_t offset;
};

struct nsb_service_mmap_request {
	char path[PATH_MAX];
	size_t nr_mmaps;
	struct nsb_service_mmap_info mmap[0];
};

#define NSB_SERVICE_MMAP_DATA_SIZE_MAX	\
	(NSB_SERVICE_MESSAGE_DATA_SIZE - sizeof(struct nsb_service_mmap_request))

struct nsb_service_munmap_request {
	size_t nr_munmaps;
	struct nsb_service_map_addr_info munmap[0];
};

#define NSB_SERVICE_MUNMAP_DATA_SIZE_MAX	\
	(NSB_SERVICE_MESSAGE_DATA_SIZE - sizeof(struct nsb_service_munmap_request))

#endif
