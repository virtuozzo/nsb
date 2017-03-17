#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/syscall.h>

#include <compel/asm/sigframe.h>

#include "service.h"

static int listen_sock;
static int cmd_sock = -1;
static int nsb_service_stop;

struct rt_sigframe emergency_sigframe;

static void emergency_sigreturn(void)
{
	uint64_t offset = RT_SIGFRAME_OFFSET(&emergency_sigframe);
	uint64_t new_sp = (uint64_t)&emergency_sigframe + offset;

	if (cmd_sock != -1) {
		close(cmd_sock);
		cmd_sock = -1;
	}

	if (emergency_sigframe.is_native)
		ARCH_RT_SIGRETURN_NATIVE(new_sp);
	else
		ARCH_RT_SIGRETURN_NATIVE(new_sp);
}

static int nsb_service_send_response(const struct nsb_service_response *rs,
				     size_t rslen)
{
	ssize_t size;

	size = send(cmd_sock, rs, rslen, 0);
	if (size < 0)
		return -errno;
	return 0;
}

static ssize_t nsb_service_receive_request(struct nsb_service_request *rq,
					   unsigned flags)
{
	ssize_t size;

	size = recv(cmd_sock, rq, sizeof(*rq), flags);
	if (size < 0)
		return -errno;

	if (size && (size < sizeof(rq->cmd)))
		return -EINVAL;
	return size;
}

typedef size_t (*handler_t)(const void *data, size_t size,
			    struct nsb_service_response *rs);

static size_t nsb_service_cmd_emerg_sigframe(const void *data, size_t size,
					     struct nsb_service_response *rs)
{
	if (size != sizeof(emergency_sigframe)) {
		rs->ret = -EINVAL;
		return sprintf(rs->data, "frame size is invalid: %ld (%ld)\n",
				size, sizeof(emergency_sigframe)) + 1;
	}
	memcpy(&emergency_sigframe, data, size);
	rs->ret = 0;
	return 0;
}

static size_t nsb_service_cmd_stop(const void *data, size_t size,
				   struct nsb_service_response *rs)
{
	nsb_service_stop = 1;
	rs->ret = 0;
	return sprintf(rs->data, "stopped") + 1;
}

static handler_t nsb_service_cmd_handlers[] = {
	[NSB_SERVICE_CMD_EMERG_SIGFRAME] = nsb_service_cmd_emerg_sigframe,
	[NSB_SERVICE_CMD_STOP] = nsb_service_cmd_stop,
};

static size_t nsb_do_handle_cmd(const struct nsb_service_request *rq, size_t data_size, 
				struct nsb_service_response *rs)
{
	handler_t handler;

	rs->ret = -EINVAL;

	if (rq->cmd > NSB_SERVICE_CMD_MAX)
		return sprintf(rs->data, "unknown command: %d\n", rq->cmd) + 1;

	handler = nsb_service_cmd_handlers[rq->cmd];
	if (!handler)
		return sprintf(rs->data, "unsupported command: %d\n", rq->cmd) + 1;

	return handler(rq->data, data_size, rs);
}

static int nsb_handle_command(const struct nsb_service_request *rq, size_t data_size)
{
	struct nsb_service_response rs;
	size_t rslen;

	rslen = sizeof(rs.ret) + nsb_do_handle_cmd(rq, data_size, &rs);

	return nsb_service_send_response(&rs, rslen);
}

int nsb_service_run(bool wait)
{
	unsigned flags = 0;
	ssize_t size;
	struct nsb_service_request rq;

	if (!wait)
		flags = MSG_DONTWAIT;

	size = nsb_service_receive_request(&rq, flags);
	if (size < 0) {
		if ((size == -EAGAIN) || (size == -EWOULDBLOCK))
			return 0;
		return size;
	}
	if (!size)
		emergency_sigreturn();

	return nsb_handle_command(&rq, size - sizeof(rq.cmd));
}

int nsb_service_run_loop(bool once, bool wait)
{
	int ret;

	do {
		ret = nsb_service_run(wait);
	} while (!nsb_service_stop && !once);

	return ret;
}

int nsb_service_accept(void)
{
	if (cmd_sock != -1)
		close(cmd_sock);

	cmd_sock = accept4(listen_sock, NULL, NULL, SOCK_CLOEXEC);
	if (cmd_sock == -1)
		return errno;

	return 0;
}

__attribute__((destructor))
static int nsb_service_destructor(void)
{
	if (cmd_sock != -1)
		close(cmd_sock);

	close(listen_sock);
	return 0;
}

__attribute__((constructor))
static int nsb_service_constructor(void)
{
	int err;
	struct sockaddr_un addr;

	memset(&addr, 0, sizeof(addr.sun_path));
	addr.sun_family = AF_UNIX;
	if (snprintf(&addr.sun_path[1], UNIX_PATH_MAX - 1,
		     "NSB-SERVICE-%d", getpid()) > UNIX_PATH_MAX - 1)
		return ENOMEM;

	listen_sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (listen_sock == -1)
		return errno;

	if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr))) {
		err = errno;
		goto close_sock;
	}

	if (listen(listen_sock, 1)) {
		err = errno;
		goto close_sock;
	}
	return 0;

close_sock:
	close(listen_sock);
	return err;
}
