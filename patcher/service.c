#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/un.h>

#include "include/util.h"
#include "include/process.h"
#include "include/service.h"
#include "include/log.h"
#include "include/vma.h"
#include "include/elf.h"
#include "include/context.h"
#include "include/x86_64.h"
#include "include/xmalloc.h"
#include "include/dl_map.h"

#include <plugins/service.h>

static int nsb_service_send_request(const struct service *service,
				    const struct nsb_service_request *rq,
				    size_t rqlen)
{
	ssize_t size;

	size = send(service->sock, rq, rqlen, 0);
	if (size < 0) {
		pr_perror("nsb_service_request: send to process %d failed",
				service->pid);
		return -errno;
	}
	return 0;
}

static void nsb_service_print_errors(const struct nsb_service_response *rp,
				     size_t size)
{
	const char *msg = rp->data;
	size_t dsize = size - sizeof(rp->ret);

	while(msg < rp->data + dsize) {
		pr_err("nsb_service: %s\n", msg);
		msg += strlen(msg) + 1;
	}
}

static ssize_t nsb_service_receive_response(const struct service *service,
					    struct nsb_service_response *rp)
{
	ssize_t size;

	size = recv(service->sock, rp, sizeof(*rp), 0);
	if (size < 0) {
		pr_perror("receive from process %d failed", service->pid);
		return -errno;
	}
	if (size < sizeof(rp->ret)) {
		pr_err("message is truncated: %ld < %ld\n", size, sizeof(rp->ret));
		return -EINVAL;
	}
	if (rp->ret < 0)
		nsb_service_print_errors(rp, size);
	return size;
}

static int check_map_file(const char *dentry, void *data)
{
	const char *base = data;

	return !strncmp(dentry, base, strlen(base));
}

static int service_collect_vmas(struct process_ctx_s *ctx, struct service *service)
{
	int err;
	uint64_t base;
	char buf[] = "/proc/XXXXXXXXXX/map_files";
	char path[PATH_MAX];
	char dentry[256];
	ssize_t res;
	LIST_HEAD(service_vmas);

	err = process_read_data(ctx, service->handle, &base, sizeof(base));
	if (err)
		return err;

	sprintf(buf, "/proc/%d/map_files/", service->pid);
	sprintf(dentry, "%lx-", base);

	err = find_dentry(buf, check_map_file, dentry, dentry);
	if (err) {
		pr_err("failed to find dentry, starting with \"%s\" "
			"in %d map files\n", dentry, service->pid);
		return err;
	}

	strcat(buf, dentry);

	res = readlink(buf, path, sizeof(path) - 1);
	if (res == -1) {
		pr_perror("failed to read link %s", buf);
		return -errno;
	}
	if (res > (sizeof(path) - 1)) {
		pr_err("link size if too big: %ld", res);
		return -errno;
	}
	path[res] = '\0';

	err = collect_vmas_by_path(service->pid, &service_vmas, path);
	if (err)
		return err;

	if (list_empty(&service_vmas)) {
		pr_err("failed to collect service VMAs by path %s\n", path);
		return -ENOENT;
	}

	err = create_dl_map(&service_vmas, &service->dlm);
	if (err)
		return err;

	list_splice_tail(&service_vmas, &ctx->vmas);

	return 0;
}

static int service_disconnect(struct process_ctx_s *ctx, struct service *service)
{
	if (service->sock >= 0) {
		if (close(service->sock)) {
			pr_perror("failed ot close service socket %d",
					service->sock);
			return -errno;
		}
		pr_debug("  Disconnected from service socket\n");
		service->sock = -1;
	}
	return 0;
}

static int service_local_connect(struct service *service)
{
	int sock, err;
	struct sockaddr_un addr;

	memset(&addr, 0, sizeof(addr.sun_path));
	addr.sun_family = AF_UNIX;
	if (snprintf(&addr.sun_path[1], UNIX_PATH_MAX - 1,
				"NSB-SERVICE-%d", service->pid) > UNIX_PATH_MAX - 1) {
		printf("Not enough space for socket path\n");
		return ENOMEM;
	}

	sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (sock == -1) {
		err = errno;
		printf("failed to create packet socket: %s\n",
				strerror(errno));
		return err;
	}

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr))) {
		err = -errno;
		pr_perror("failed to connect to service socket \"%s\"", &addr.sun_path[1]);
		close(sock);
		return err;
	}
	pr_debug("  Connected to service socket \"%s\"\n", &addr.sun_path[1]);
	service->sock = sock;
	return 0;
}

static int64_t service_sym_addr(struct service *service, const char *symbol)
{
	int64_t value;

	value = dl_map_symbol_value(service->dlm, symbol);
	if (value < 0)
		pr_err("failed to find symbol %s in %s\n", symbol,
				service->dlm->path);
	return value;
}

static int service_remote_accept(struct process_ctx_s *ctx, struct service *service)
{
	const char *symbol = "nsb_service_accept";
	int64_t address;
	uint64_t code_addr = ctx->remote_map;
	ssize_t size;
	void *code;

	address = service_sym_addr(service, symbol);
	if (address <= 0)
		return address;

	size = x86_64_call(address, code_addr, 0, 0, 0, 0, 0, 0, &code);
	if (size < 0) {
		pr_err("failed to construct %s call\n", symbol);
		return size;
	}

	return process_exec_code(ctx, code_addr, code, size);
}

static int service_run(struct process_ctx_s *ctx, const struct service *service,
		       bool once)
{
	uint64_t code_addr = ctx->remote_map;
	ssize_t size;
	void *code;

	if (service->released)
		return 0;

	size = x86_64_call(service->runner, code_addr,
			   once, !once, 0, 0, 0, 0,
			   &code);
	if (size < 0) {
		pr_err("failed to construct runner call\n");
		return size;
	}

	if (once)
		return process_exec_code(ctx, code_addr, code, size);
	else
		return process_release_at(ctx, code_addr, code, size);
}

static int service_provide_sigframe(struct process_ctx_s *ctx, struct service *service)
{
	int err;
	struct nsb_service_request rq = {
		.cmd = NSB_SERVICE_CMD_EMERG_SIGFRAME,
	};
	struct nsb_service_response rs;
	ssize_t size;
	size_t rqlen;
	int64_t address;

	address = service_sym_addr(service, "nsb_service_run_loop");
	if (address <= 0)
		return address;
	service->runner = address;

	address = service_sym_addr(service, "emergency_sigframe");
	if (address <= 0)
		return address;

	size = process_emergency_sigframe(ctx, rq.data, (void *)address);
	if (size < 0)
		return size;

	rqlen = sizeof(rq.cmd) + size;

	err = nsb_service_send_request(service, &rq, rqlen);
	if (err)
		return err;

	err = service_run(ctx, service, true);
	if (err)
		return err;

	size = nsb_service_receive_response(service, &rs);
	if (size < 0)
		return size;

	return err;
}
#if 0
static int service_release(struct process_ctx_s *ctx, struct service *service)
{
	int err;

	if (service->released)
		return 0;

	err = service_run(ctx, service, false);
	if (err)
		return err;

	pr_debug("  Service released\n");
	service->released = true;
	return 0;
}
#endif
static int service_interrupt(struct process_ctx_s *ctx, struct service *service)
{
	int err;
	const struct nsb_service_request rq = {
		.cmd = NSB_SERVICE_CMD_STOP,
		.data = { },
	};
	struct nsb_service_response rs;
	ssize_t size;
	size_t rqlen = sizeof(rq.cmd) + strlen(rq.data) + 1;

	if (!service->released)
		return 0;

	err = nsb_service_send_request(service, &rq, rqlen);
	if (err)
		return err;

	size = nsb_service_receive_response(service, &rs);
	if (size < 0)
		return size;

	err = process_acquire(ctx);
	if (err)
		return err;

	pr_debug("  Service caught\n");
	service->released = false;
	return 0;
}

static int service_connect(struct process_ctx_s *ctx, struct service *service)
{
	int err;

	err = service_local_connect(service);
	if (err)
		return err;

	err = service_remote_accept(ctx, service);
	if (err)
		return err;

	err = service_provide_sigframe(ctx, service);
	if (err)
		return err;

	service->loaded = true;

	return 0;
}

int service_stop(struct process_ctx_s *ctx, struct service *service)
{
	int err;

	err = service_interrupt(ctx, service);
	if (err)
		return err;

	err = service_disconnect(ctx, service);
	if (err)
		return err;

	service->loaded = true;

	return 0;
}

int service_start(struct process_ctx_s *ctx, struct service *service)
{
	int err;

	err = service_collect_vmas(ctx, service);
	if (err)
		return err;

	err = service_connect(ctx, service);
	if (err)
		return err;
#if 0
	err = service_release(ctx, service);
	if (err)
		return err;
#endif
	return 0;
}

int service_mmap_file(struct process_ctx_s *ctx, const struct service *service,
		      const char *path, const struct list_head *mmaps)
{
	struct nsb_service_request rq = {
		.cmd = NSB_SERVICE_CMD_MMAP,
	};
	struct mmap_info_s *mmi;
	struct nsb_service_mmap_request *mrq;
	struct nsb_service_mmap_info *mi;
	size_t max_mmaps;
	struct nsb_service_response rs;
	size_t rqlen, size;
	int err;

	max_mmaps = NSB_SERVICE_MMAP_DATA_SIZE_MAX / sizeof(*mi);

	mrq = (void *)rq.data;
	mi = mrq->mmap;

	list_for_each_entry(mmi, mmaps, list) {
		if (mrq->nr_mmaps == max_mmaps) {
			pr_err("to many map request (max: %ld)\n", max_mmaps);
			return -E2BIG;
		}
		mi->info.addr = mmi->addr;
		mi->info.length = mmi->length;
		mi->prot = mmi->prot;
		mi->flags = mmi->flags;
		mi->offset = mmi->offset;
		mi++;
		mrq->nr_mmaps++;
	}
	strcpy(mrq->path, path);

	rqlen = sizeof(rq.cmd) + sizeof(*mrq) + sizeof(*mi) * mrq->nr_mmaps;

	err = nsb_service_send_request(service, &rq, rqlen);
	if (err)
		return err;

	err = service_run(ctx, service, true);
	if (err)
		return err;

	size = nsb_service_receive_response(service, &rs);
	if (size < 0)
		return size;

	if (rs.ret < 0) {
		errno = -rs.ret;
		pr_perror("mmap request failed");
		return rs.ret;
	}
	return 0;
}

int service_munmap(struct process_ctx_s *ctx, const struct service *service,
		   const struct list_head *mmaps)
{
	struct nsb_service_request rq = {
		.cmd = NSB_SERVICE_CMD_MUNMAP,
	};
	struct mmap_info_s *mmi;
	struct nsb_service_munmap_request *mrq;
	struct nsb_service_map_addr_info *mai;
	size_t max_munmaps;
	struct nsb_service_response rs;
	size_t rqlen, size;
	int err;

	max_munmaps = NSB_SERVICE_MUNMAP_DATA_SIZE_MAX / sizeof(*mai);

	mrq = (void *)rq.data;
	mai = mrq->munmap;

	list_for_each_entry(mmi, mmaps, list) {
		if (mrq->nr_munmaps == max_munmaps) {
			pr_err("to many unmap request (max: %ld)\n", max_munmaps);
			return -E2BIG;
		}
		mai->addr = mmi->addr;
		mai->length = mmi->length;
		mrq->nr_munmaps++;
	}

	rqlen = sizeof(rq.cmd) + sizeof(*mrq) + sizeof(*mai) * mrq->nr_munmaps;

	err = nsb_service_send_request(service, &rq, rqlen);
	if (err)
		return err;

	err = service_run(ctx, service, true);
	if (err)
		return err;

	size = nsb_service_receive_response(service, &rs);
	if (size < 0)
		return size;

	if (rs.ret < 0) {
		errno = -rs.ret;
		pr_perror("mmap request failed");
		return rs.ret;
	}
	return 0;
}

ssize_t service_needed_array(struct process_ctx_s *ctx, const struct service *service,
			     uint64_t **needed_array)
{
	struct nsb_service_request rq = {
		.cmd = NSB_SERVICE_CMD_NEEDED_LIST,
	};
	size_t rqlen, size;
	struct nsb_service_response rs;
	struct nsb_service_needed_list *nl = (void *)rs.data;
	int err;
	size_t array_size;
	uint64_t *array;

	rqlen = sizeof(rq.cmd);

	err = nsb_service_send_request(service, &rq, rqlen);
	if (err)
		return err;

	err = service_run(ctx, service, true);
	if (err)
		return err;

	size = nsb_service_receive_response(service, &rs);
	if (size < 0)
		return size;

	if (rs.ret < 0) {
		errno = -rs.ret;
		pr_perror("request for array of needed maps failed");
		return rs.ret;
	}

	array_size = sizeof(nl->address) * nl->nr_addrs;

	array = xmalloc(array_size);
	if (!array)
		return -ENOMEM;

	memcpy(array, nl->address, array_size);
	*needed_array = array;

	return nl->nr_addrs;
}

