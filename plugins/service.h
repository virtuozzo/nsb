#ifndef __NSB_PLUGINS_SERVICE__
#define __NSB_PLUGINS_SERVICE__

typedef enum {
	NSB_SERVICE_CMD_EMERG_SIGFRAME,
	NSB_SERVICE_CMD_STOP,
	NSB_SERVICE_CMD_READ,
	NSB_SERVICE_CMD_WRITE,
	NSB_SERVICE_CMD_MAX,
} nsb_service_cmd_t;

#define NSB_SERVICE_MESSAGE_DATA_SIZE		8192

struct nsb_service_data_rw {
	void *address;
	size_t size;
	char data[0];
};

#define NSB_SERVICE_RW_DATA_SIZE_MAX	\
	(NSB_SERVICE_MESSAGE_DATA_SIZE - sizeof(struct nsb_service_data_rw))

struct nsb_service_request {
	unsigned cmd;
	char data[NSB_SERVICE_MESSAGE_DATA_SIZE];
};

struct nsb_service_response {
	int ret;
	char data[NSB_SERVICE_MESSAGE_DATA_SIZE];
};

#endif
