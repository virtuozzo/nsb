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
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <link.h>

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

static ssize_t nsb_service_send_response(const struct nsb_service_response *rs,
				     size_t rslen)
{
	ssize_t size;

	size = send(cmd_sock, rs, rslen, 0);
	if (size < 0)
		return -errno;
	return size;
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

struct nsb_response_data {
	ssize_t	used;
	char	*data;
};

static void nsb_service_response_print(struct nsb_response_data *rd,
				       const char *fmt, ...)
{
	size_t left = NSB_SERVICE_MESSAGE_DATA_SIZE - rd->used;
	va_list ap;
	int __errno_saved = errno;
	ssize_t n;

	if (!left)
		return;

	va_start(ap, fmt);
	n = vsnprintf(rd->data + rd->used, left, fmt, ap);
	rd->used += n + 1;
	va_end(ap);

	errno = __errno_saved;
}

typedef int (*handler_t)(const void *data, size_t size,
			 struct nsb_response_data *rd);

static int nsb_service_cmd_emerg_sigframe(const void *data, size_t size,
					  struct nsb_response_data *rd)
{
	if (size != sizeof(emergency_sigframe)) {
		nsb_service_response_print(rd,
				"frame size is invalid: %ld (%ld)",
				size, sizeof(emergency_sigframe));
		return -EINVAL;
	}
	memcpy(&emergency_sigframe, data, size);
	return 0;
}

static int nsb_service_cmd_stop(const void *data, size_t size,
				struct nsb_response_data *rd)
{
	nsb_service_stop = 1;
	return 0;
}

static int nsb_service_cmd_do_munmap(const struct nsb_service_map_addr_info *mai,
				     struct nsb_response_data *rd)
{
	int err;

	err = munmap((void *)mai->addr, mai->length);
	if (err == -1) {
		nsb_service_response_print(rd,
				"failed to munmap %#lx-%#lx",
				mai->addr, mai->addr + mai->length);
		return -errno;
	}
	return 0;
}

static int nsb_service_cmd_munmap(const void *data, size_t size,
				  struct nsb_response_data *rd)
{
	const struct nsb_service_munmap_request *rq = data;
	const struct nsb_service_map_addr_info *mai;
	int nr, err;
	size_t max_munmaps = NSB_SERVICE_MUNMAP_DATA_SIZE_MAX / sizeof(*mai);

	if (rq->nr_munmaps > max_munmaps) {
		nsb_service_response_print(rd, "too many numap requests: %d (max: %ld)",
				rq->nr_munmaps, max_munmaps);
		return -E2BIG;
	}

	for (nr = 0, mai = rq->munmap; nr < rq->nr_munmaps; nr++, mai++) {
		err = nsb_service_cmd_do_munmap(mai, rd);
		if (err)
			return err;
	}

	return 0;

}

static int nsb_service_cmd_do_mmap(int fd,
				   const struct nsb_service_mmap_info *mi,
				   struct nsb_response_data *rd)
{
	void *address;
	const struct nsb_service_map_addr_info *mai = &mi->info;

	address = mmap((void *)mai->addr, mai->length,
			mi->prot, mi->flags, fd, mi->offset);
	if (address == MAP_FAILED) {
		printf("failed to create new mapping %#lx-%#lx "
				"with flags %#x, prot %#x, offset %#lx",
				mai->addr, mai->addr + mai->length,
				mi->prot, mi->flags, mi->offset);
		nsb_service_response_print(rd,
				"failed to create new mapping %#lx-%#lx "
				"with flags %#x, prot %#x, offset %#lx",
				mai->addr, mai->addr + mai->length,
				mi->prot, mi->flags, mi->offset);
		return -errno;
	}
	return 0;
}

static int nsb_service_cmd_mmap(const void *data, size_t size,
				struct nsb_response_data *rd)
{
	const struct nsb_service_mmap_request *rq = data;
	const struct nsb_service_mmap_info *mi;
	int fd, nr, err;
	size_t max_mmaps = NSB_SERVICE_MMAP_DATA_SIZE_MAX / sizeof(*mi);

	if (rq->nr_mmaps > max_mmaps) {
		nsb_service_response_print(rd, "too many map requests: %d (max: %ld)",
				rq->nr_mmaps, max_mmaps);
		return -E2BIG;
	}

	if (rq->nr_mmaps != 2) {
		nsb_service_response_print(rd, "rq->nr_mmaps: %d",
				rq->nr_mmaps);
		return -EINVAL;
	}
	fd = open(rq->path, O_RDONLY);
	if (fd < 0) {
		nsb_service_response_print(rd, "failed to open %s", rq->path);
		return -errno;
	}

	for (nr = 0, mi = rq->mmap; nr < rq->nr_mmaps; nr++, mi++) {
		err = nsb_service_cmd_do_mmap(fd, mi, rd);
		if (err)
			goto unmap;
	}

	close(fd);
	return 0;

unmap:
	for (; nr > 0; nr--, mi--)
		(void)nsb_service_cmd_do_munmap(&mi->info, rd);
	return err;
}

static int64_t nsb_service_dynamic_tag_val(const ElfW(Dyn) *l_ld, uint32_t d_tag)
{
	const ElfW(Dyn) *d;

	for (d = l_ld; d->d_tag != DT_NULL; ++d) {
		if (d->d_tag == d_tag)
			return d->d_un.d_val;
	}
	return -ENOENT;
}

static int nsb_service_cmd_needed_list(const void *data, size_t size,
				       struct nsb_response_data *rd)
{
	struct nsb_service_needed_list *nl = (void *)rd->data;
        struct link_map *lm;
	size_t nr = 0;
	size_t max_base_addrs = NSB_SERVICE_NEEDED_LIST_SIZE_MAX /
						sizeof(nl->address);

	lm = _r_debug.r_map;

	do {
		int64_t dt_symtab_addr;

		if (nr == max_base_addrs) {
			rd->used = 0;
			nsb_service_response_print(rd, "to many base addresses (max: %ld)",
					max_base_addrs);
			return -E2BIG;
		}

		/* We rely upon presense of DT_SYMTAB, because it's mandatory */
		dt_symtab_addr = nsb_service_dynamic_tag_val(lm->l_ld, DT_SYMTAB);
		if (dt_symtab_addr == -ENOENT) {
			rd->used = 0;
			nsb_service_response_print(rd,
					"failed to find DT_SYMTAB (l_addr: %lx)",
					lm->l_addr);
			return -ENOENT;
		}

		/* Check dt_symtab_addr for non-negative value.
		 * This is diferent in VDSO, which has negative addresses
		 * (offsets from base)?
		 */
		if (dt_symtab_addr >= 0) {
			nl->address[nr] = dt_symtab_addr;
			rd->used += sizeof(nl->address);
			nr++;
		}
		lm = lm->l_next;
		/* Last link is this module. Skip it. */
	} while (lm->l_next);

	nl->nr_addrs = nr;
	rd->used = sizeof(nl->nr_addrs) + sizeof(nl->address) * nr;
	return 0;
}

static handler_t nsb_service_cmd_handlers[] = {
	[NSB_SERVICE_CMD_EMERG_SIGFRAME] = nsb_service_cmd_emerg_sigframe,
	[NSB_SERVICE_CMD_STOP] = nsb_service_cmd_stop,
	[NSB_SERVICE_CMD_NEEDED_LIST] = nsb_service_cmd_needed_list,
	[NSB_SERVICE_CMD_MMAP] = nsb_service_cmd_mmap,
	[NSB_SERVICE_CMD_MUNMAP] = nsb_service_cmd_munmap,
};

static int nsb_do_handle_cmd(const struct nsb_service_request *rq, size_t data_size, 
				struct nsb_response_data *rd)
{
	handler_t handler;

	if (rq->cmd > NSB_SERVICE_CMD_MAX) {
		nsb_service_response_print(rd,
				"unknown command: %d", rq->cmd);
		return -EINVAL;
	}

	handler = nsb_service_cmd_handlers[rq->cmd];
	if (!handler) {
		 nsb_service_response_print(rd,
				"unsupported command: %d", rq->cmd);
		 return -EINVAL;
	}

	return handler(rq->data, data_size, rd);
}

static int nsb_handle_command(const struct nsb_service_request *rq, size_t data_size)
{
	struct nsb_service_response rs = { };
	struct nsb_response_data rd = {
		.data = rs.data,
	};
	ssize_t size;

	rs.ret = nsb_do_handle_cmd(rq, data_size, &rd);

	size = nsb_service_send_response(&rs, sizeof(rs.ret) + rd.used);
	if (size < 0)
		return size;
	if (!size)
		emergency_sigreturn();
	return 0;
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
