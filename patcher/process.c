#include <stdio.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/types.h>

#include <compel/compel.h>
#include <compel/ptrace.h>

#include "include/context.h"
#include "include/log.h"
#include "include/xmalloc.h"
#include "include/vma.h"
#include "include/backtrace.h"
#include "include/process.h"
#include "include/patch.h"
#include "include/elf.h"
#include "include/util.h"
#include "include/x86_64.h"
#include "include/service.h"

struct patch_place_s {
	struct list_head	list;
	unsigned long		start;
	unsigned long		size;
	unsigned long		used;
};

struct thread_s {
	struct list_head	list;
	pid_t			pid;
	int			seized;
};

int process_write_data(const struct process_ctx_s *ctx, uint64_t addr, const void *data, size_t size)
{
	pid_t pid = ctx->pid;
	int err;

	err = ptrace_poke_area(pid, (void *)data, (void *)addr, size);
	if (err) {
		if (err == -1) {
			pr_err("Failed to write range %#lx-%#lx in process %d: "
			       "size is not aligned\n", addr, addr + size, pid);
			return -EINVAL;
		}
		pr_perror("Failed to write range %#lx-%#lx in process %d",
				addr, addr + size, pid);
		return -errno;
	}
	return 0;
}

int process_read_data(const struct process_ctx_s *ctx, uint64_t addr, void *data, size_t size)
{
	pid_t pid = ctx->pid;
	int err;

	err = ptrace_peek_area(pid, data, (void *)addr, size);
	if (err) {
		if (err == -1) {
			pr_err("Failed to read range %#lx-%#lx in process %d: "
			       "size is not aligned\n", addr, addr + size, pid);
			return -EINVAL;
		}
		pr_perror("Failed to read range %#lx-%#lx from process %d",
				addr, addr + size, pid);
		return -errno;
	}
	return 0;
}

static const char *map_flags(unsigned flags, char *buf)
{
	if (flags & MAP_SHARED)
		strcpy(buf, "MAP_SHARED");
	else
		strcpy(buf, "MAP_PRIVATE");

	if (flags & MAP_FIXED)
		strcat(buf, " | MAP_FIXED");

	if (flags & MAP_ANONYMOUS)
		strcat(buf, " | MAP_ANONYMOUS");

	return buf;
}

static const char *map_prot(unsigned prot, char *buf)
{
	strcpy(buf, "---");
	if (prot & PROT_READ)
		buf[0] = 'r';
	if (prot & PROT_WRITE)
		buf[1] = 'w';
	if (prot & PROT_EXEC)
		buf[2] = 'x';
	return buf;
}

static long process_syscall(struct process_ctx_s *ctx, int nr,
			    unsigned long arg1, unsigned long arg2,
			    unsigned long arg3, unsigned long arg4,
			    unsigned long arg5, unsigned long arg6)
{
	int ret;
	long sret = -ENOSYS;

	if (ctx->service.released) {
		pr_err("service plugin in running\n");
		errno = EBUSY;
		return -1;
	}

	ret = compel_syscall(ctx->ctl, nr, &sret,
			     arg1, arg2, arg3, arg4, arg5, arg6);
	if (ret < 0) {
		pr_err("Failed to execute syscall %d in %d\n", nr, ctx->pid);
		return ret;
	}
	if (sret < 0) {
		errno = -sret;
		return -1;
	}
	return sret;
}

int64_t process_map(struct process_ctx_s *ctx, int fd, off_t offset,
		    unsigned long addr, size_t length, int flags, int prot)
{
	long maddr;

	if (ctx->service.loaded) {
		pr_err("service is loaded\n");
		return -EBUSY;
	}

	maddr = process_syscall(ctx, __NR(mmap, false),
				addr, length, prot, flags, fd, offset);
	if (maddr < 0) {
		pr_err("failed to create new mapping %#lx-%#lx "
				"in process %d with flags %#x, prot %#x, offset %#lx\n",
				addr, addr + length, ctx->pid,
				prot, flags, offset);
		return -errno;
	}
	return maddr;
}

static int process_mmap_fd(struct process_ctx_s *ctx, int fd,
			   const struct mmap_info_s *mmi)
{
	int64_t addr;

	addr = process_map(ctx, fd, mmi->offset, mmi->addr,
			mmi->length, mmi->flags, mmi->prot);

	return addr < 0 ? addr : 0;
}

int process_munmap(struct process_ctx_s *ctx,
		   const struct list_head *mmaps)
{
	struct mmap_info_s *mmi, *tmp;
	int err;

	list_for_each_entry(mmi, mmaps, list)
		pr_info("  - munmap: %#lx-%#lx\n", mmi->addr,
				mmi->addr + mmi->length);

	if (ctx->service.loaded)
		return service_munmap(ctx, &ctx->service, mmaps);

	list_for_each_entry_safe(mmi, tmp, mmaps, list) {
		err = process_unmap(ctx, mmi->addr, mmi->length);
		if (err)
			return err;
	}
	return 0;
}

int process_mmap_file(struct process_ctx_s *ctx, const char *path,
		      const struct list_head *mmaps)
{
	int fd, err = 0;
	struct mmap_info_s *mmi;
	char fbuf[512];
	char pbuf[4];

	list_for_each_entry(mmi, mmaps, list)
		pr_info("  - mmap: %#lx-%#lx, off: %#lx, prot: %s, flags: %s\n",
				mmi->addr, mmi->addr + mmi->length, mmi->offset,
				map_prot(mmi->prot, pbuf),
				map_flags(mmi->flags, fbuf));

	if (ctx->service.loaded)
		return service_mmap_file(ctx, &ctx->service, path, mmaps);

	fd = process_open_file(ctx, path, O_RDONLY, 0);
	if (fd < 0)
		return fd;

	list_for_each_entry(mmi, mmaps, list) {
		err = process_mmap_fd(ctx, fd, mmi);
		if (err)
			goto unmap;
	}

	(void)process_close_file(ctx, fd);

	return 0;

unmap:
	list_for_each_entry_reverse(mmi, mmaps, list)
		(void)process_unmap(ctx, mmi->addr, mmi->length);
	return err;
}

int process_close_file(struct process_ctx_s *ctx, int fd)
{
	int err;

	err = process_syscall(ctx, __NR(close, false),
			      fd, 0, 0, 0, 0, 0);
	if (err < 0) {
		pr_perror("Failed to close %d", fd);
		return -errno;
	}
	return 0;
}

static int process_do_open_file(struct process_ctx_s *ctx,
				const char *path, int flags, mode_t mode)
{
	int err, fd;

	err = process_write_data(ctx, ctx->remote_map, path,
				 round_up(strlen(path) + 1, 8));
	if (err)
		return err;

	fd = process_syscall(ctx, __NR(open, false),
			     ctx->remote_map, flags, mode, 0, 0, 0);
	if (fd < 0) {
		pr_perror("Failed to open %s", path);
		return -errno;
	}
	return fd;
}

int process_open_file(struct process_ctx_s *ctx, const char *path, int flags, mode_t mode)
{
	int fd;

	fd = process_do_open_file(ctx, path, flags, mode);
	if (fd < 0)
		pr_err("failed to open %s in process %d\n", path, ctx->pid);
	return fd;
}

static int task_cure(struct thread_s *t)
{
	if (!t->seized)
		return 0;

	pr_debug("  %d\n", t->pid);

	if (compel_resume_task(t->pid, COMPEL_TASK_ALIVE, COMPEL_TASK_ALIVE)) {
		pr_err("Can't unseize from %d\n", t->pid);
		return -1;
	}
	return 0;
}

void thread_destroy(struct thread_s *t)
{
	list_del(&t->list);
	free(t);
}

static int process_cure_threads(struct process_ctx_s *ctx)
{
	struct thread_s *t, *tmp;
	int err;

	list_for_each_entry_safe(t, tmp, &ctx->threads, list) {
		err = task_cure(t);
		if (err)
			return err;
		thread_destroy(t);
	}
	return 0;
}

int process_unlink(struct process_ctx_s *ctx)
{
	int err;

	if (!ctx->ctl)
		return 0;

	pr_debug("= Cleanup %d\n", ctx->pid);

	err = process_unmap(ctx, ctx->remote_map, ctx->remote_map_size);
	if (err)
		return err;

	err = compel_cure(ctx->ctl);
	if (err)
		pr_err("failed to cure process %d: %d\n", ctx->pid, err);

	return err;
}

int process_cure(struct process_ctx_s *ctx)
{
	return process_cure_threads(ctx);
}

int process_link(struct process_ctx_s *ctx)
{
	pr_debug("= Prepare %d\n", ctx->pid);

	ctx->ctl = compel_prepare(ctx->pid);
	if (!ctx->ctl) {
		pr_err("Can't create compel control\n");
		return -1;
	}

	ctx->remote_map_size = PAGE_SIZE;

	ctx->remote_map = process_map(ctx, -1, 0, 0, ctx->remote_map_size,
			MAP_ANONYMOUS | MAP_PRIVATE,
			PROT_READ | PROT_WRITE | PROT_EXEC);
	if ((void *)ctx->remote_map == MAP_FAILED) {
		pr_err("failed to create service memory region in process %d\n", ctx->pid);
		goto cure;
	}

	return 0;

cure:
	if (compel_cure(ctx->ctl))
		pr_err("failed to cure process %d\n", ctx->pid);
	ctx->ctl = NULL;
	return -1;
}

static int task_infect(struct thread_s *t)
{
	pr_debug("  %d\n", t->pid);

	switch (compel_stop_task(t->pid)) {
		case COMPEL_TASK_ALIVE:
			t->seized = true;
			return 0;
		case COMPEL_TASK_STOPPED:
			pr_debug("BUSY\n");
			return -EBUSY;
		case COMPEL_TASK_ZOMBIE:
			pr_debug("ZOMBIE\n");
			break;
		case COMPEL_TASK_DEAD:
			pr_debug("DEAD\n");
			break;
		default:
			if (errno != -ESRCH)
				return -errno;
	}
	thread_destroy(t);
	return 0;
}

static int collect_thread(const char *dentry, void *data)
{
	struct list_head *threads = data;
	struct thread_s *t;
	pid_t pid;

	pid = atoi(dentry);

	list_for_each_entry(t, threads, list) {
		if (t->pid == pid)
			return 0;
	}

	t = malloc(sizeof(*t));
	if (!t)
		return -ENOMEM;

	t->pid = pid;
	t->seized = 0;
	list_add_tail(&t->list, threads);
	return 0;
}

static int process_collect_threads(struct process_ctx_s *ctx)
{
	char tasks[] = "/proc/XXXXXXXXXX/tasks/";

	sprintf(tasks, "/proc/%d/task/", ctx->pid);

	return iterate_dir_name(tasks, collect_thread, &ctx->threads);
}

static int process_infect_threads(struct process_ctx_s *ctx)
{
	struct thread_s *t, *tmp;
	int err;

	list_for_each_entry_safe(t, tmp, &ctx->threads, list) {
		err = task_infect(t);
		if (err)
			return err;
	}
	return 0;
}

static bool process_needs_seize(struct process_ctx_s *ctx)
{
	if (list_empty(&ctx->threads))
		return true;
	return !list_entry(ctx->threads.prev, struct thread_s, list)->seized;
}

int process_infect(struct process_ctx_s *ctx)
{
	int err;

	pr_debug("= Infecting process %d:\n", ctx->pid);

	while (1) {
		err = process_collect_threads(ctx);
		if (err)
			goto err;

		if (!process_needs_seize(ctx))
			break;

		err = process_infect_threads(ctx);
		if (err)
			goto err;
	}

	if (list_empty(&ctx->threads)) {
		pr_err("failed to collect any threads\n");
		pr_err("Process %d is considered dead\n", ctx->pid);
		return -ESRCH;
	}

	return 0;

err:
	process_cure_threads(ctx);
	return err;
}

int process_unmap(struct process_ctx_s *ctx, off_t addr, size_t size)
{
	int err;

	err = process_syscall(ctx, __NR(munmap, false),
			      addr, size, 0, 0, 0, 0);
	if (err < 0) {
		pr_perror("Failed to unmap %#lx-%#lx", addr, addr + size);
		return -errno;
	}

	pr_info("  - munmap: %#lx-%#lx\n", addr, addr + size);
	return 0;
}

static int task_check_stack(const struct process_ctx_s *ctx, const struct thread_s *t,
			    int (*check)(const struct process_ctx_s *ctx,
					 const struct backtrace_s *bt))
{
	int err;
	struct backtrace_s *bt;

	pr_info("  %d:\n", t->pid);

	err = pid_backtrace(t->pid, &bt);
	if (err) {
		pr_err("failed to unwind process %d stack\n", t->pid);
		return err;
	}

	err = check(ctx, bt);

	destroy_backtrace(bt);
	return err;
}

static int process_check_stack(const struct process_ctx_s *ctx,
			      int (*check)(const struct process_ctx_s *ctx,
					   const struct backtrace_s *bt))
{
	struct thread_s *t;
	int err;

	pr_info("= Checking %d stack...\n", ctx->pid);
	list_for_each_entry(t, &ctx->threads, list) {
		err = task_check_stack(ctx, t, check);
		if (err)
			return err;
	}
	return 0;
}

static int process_catch(struct process_ctx_s *ctx)
{
	int ret, err;

	err = process_infect(ctx);
	if (err)
		return err;

	ret = process_check_stack(ctx, ctx->ops->check_backtrace);
	if (ret)
		goto err;

	return 0;

err:
	err = process_cure(ctx);
	return ret ? ret : err;
}

static unsigned increase_timeout(unsigned current_msec)
{
	unsigned max_msec_timeout = 1000;

	if (current_msec < max_msec_timeout)
		current_msec = min(current_msec << 1, max_msec_timeout);
	return current_msec;
}

int64_t process_exec_code(struct process_ctx_s *ctx, uint64_t addr,
		void *code, size_t code_size)
{
	int err;
	user_regs_struct_t regs;

	err = process_write_data(ctx, addr, code, round_up(code_size, 8));
	if (err) {
		pr_err("failed to write code\n");
		return err;
	}

	err = compel_run_at(ctx->ctl, addr, &regs);
	if (err) {
		pr_err("failed to call code at %#lx: %d\n", addr, err);
		return err;
	}

	return get_user_reg(&regs, ax);
}

int process_suspend(struct process_ctx_s *ctx)
{
	int try = 0, tries = 25;
	unsigned timeout_msec = 1;
	int err;

	do {
		if (try) {
			pr_info("  Failed to catch process in a suitable time/place.\n"
				"  Retry in %d msec\n", timeout_msec);

			usleep(timeout_msec * 1000);

			timeout_msec = increase_timeout(timeout_msec);
		}
		err = process_catch(ctx);
		if (err != -EAGAIN)
			break;
	} while (++try < tries);

	return err == -EAGAIN ? -ETIME : err;
}

int process_release_at(struct process_ctx_s *ctx, uint64_t addr,
		       void *code, size_t code_size)
{
	int err;

	err = process_write_data(ctx, addr, code, round_up(code_size, 8));
	if (err) {
		pr_err("failed to write code\n");
		return err;
	}

	err = compel_release_at(ctx->ctl, addr);
	if (err) {
		pr_err("failed to call code at %#lx: %d\n", addr, err);
		return err;
	}

	return 0;
}

int process_acquire(struct process_ctx_s *ctx)
{
	int err;

	err = compel_catch(ctx->ctl, NULL);
	if (err)
		pr_err("failed to catch process %d\n", err);
	return err;
}

ssize_t process_emergency_sigframe(struct process_ctx_s *ctx, void *data,
				   void *where)
{
	int err;

	err = compel_emergency_sigframe(ctx->ctl, data, where);
	if (err) {
		pr_err("failed to get emergency sigframe: %d\n", err);
		return err;
	}
	return sizeof(struct rt_sigframe);
}

static int process_find_sym(struct process_ctx_s *ctx,
			    const char *name, uint64_t *addr)
{
	int64_t value;

	value = vma_get_symbol_value(&ctx->vmas, name);
	if (value <= 0) {
		pr_err("failed to find \"%s\" in process %d\n", name, ctx->pid);
		return value ? value : -ENOENT;
	}
	*addr = value;
	return 0;
}

static int process_find_dlopen(struct process_ctx_s *ctx, uint64_t *addr)
{
	return process_find_sym(ctx, "__libc_dlopen_mode", addr);
}

static int process_find_dlclose(struct process_ctx_s *ctx, uint64_t *addr)
{
	return process_find_sym(ctx, "__libc_dlclose", addr);
}

static int64_t process_call_dlopen(struct process_ctx_s *ctx,
				   uint64_t dlopen_addr, const char *soname)
{
	void *dlopen_code;
	ssize_t size;
	uint64_t code_addr = ctx->remote_map;
	uint64_t name_addr = round_up(code_addr + X86_64_CALL_MAX_SIZE, 8);
	int err;

	size = x86_64_dlopen(dlopen_addr, name_addr,
			     code_addr,
			     &dlopen_code);
	if (size < 0) {
		pr_err("failed to construct dlopen call\n");
		return size;
	}

	err = process_write_data(ctx, name_addr,
				 soname, round_up(strlen(soname) + 1, 8));
	if (err) {
		pr_err("failed to write file name\n");
		return err;
	}

	return process_exec_code(ctx, code_addr, dlopen_code, size);
}

int process_inject_service(struct process_ctx_s *ctx)
{
	int err;
	uint64_t dlopen_addr = 0;
	int64_t handle;

	pr_debug("= Injecting service \"%s\" into %d\n",
			ctx->service.name, ctx->pid);

	err = process_find_dlopen(ctx, &dlopen_addr);
	if (err)
		return err;

	handle = process_call_dlopen(ctx, dlopen_addr, ctx->service.name);
	if (handle <= 0) {
		pr_err("failed to inject nsb service service\n");
		return -EFAULT;
	}

	ctx->service.handle = handle;
	ctx->service.pid = ctx->pid;

	err = service_start(ctx, &ctx->service);
	if (err)
		return err;

	return 0;
}

static int64_t process_call_dlclose(struct process_ctx_s *ctx,
				    uint64_t dlclose_addr, uint64_t handle)
{
	void *dlclose_code;
	ssize_t size;
	uint64_t code_addr = ctx->remote_map;

	size = x86_64_dlclose(dlclose_addr, handle,
			      code_addr,
			      &dlclose_code);
	if (size < 0) {
		pr_err("failed to construct dlclose call\n");
		return size;
	}

	return process_exec_code(ctx, code_addr, dlclose_code, size);
}

int process_shutdown_service(struct process_ctx_s *ctx)
{
	int err;
	uint64_t dlclose_addr = 0;

	if (!ctx->service.handle)
		return 0;

	pr_debug("= Shutting down service service \"%s\" in %d\n",
			ctx->service.name, ctx->pid);

	err = service_stop(ctx, &ctx->service);
	if (err)
		return err;

	err = process_find_dlclose(ctx, &dlclose_addr);
	if (err)
		return err;

	err = process_call_dlclose(ctx, dlclose_addr, ctx->service.handle);
	if (err) {
		pr_err("failed to shutdown nsb service service\n");
		return -EFAULT;
	}

	return 0;
}

static int collect_needed(struct process_ctx_s *ctx, struct list_head *head,
			  const struct vma_area *vma)
{
	struct ctx_dep *cd;

	cd = xmalloc(sizeof(*cd));
	if (!cd)
		return -ENOMEM;

	cd->vma = vma;
	list_add_tail(&cd->list, head);

	pr_debug("  - %lx-%lx - %s\n", vma_start(cd->vma),
			vma_end(cd->vma), cd->vma->path);
	return 0;
}

int process_collect_needed(struct process_ctx_s *ctx)
{
	int err = -ENOENT;
	ssize_t nr, i;
	uint64_t *needed_array;

	pr_debug("= Process soname search list:\n");

	nr = service_needed_array(ctx, &ctx->service, &needed_array);
	if (nr < 0)
		return err;

	for (i = 0; i < nr; i++) {
		const struct vma_area *vma;
		uint64_t address = needed_array[i];

		vma = find_vma_by_addr(&ctx->vmas, address);
		if (!vma) {
			pr_err("failed to find VMA by address %#lx\n", address);
			continue;
			err = -ENOENT;
			goto free_array;
		}

		err = collect_needed(ctx, &ctx->objdeps, vma);
		if (err)
			goto free_array;

	}

free_array:
	free(needed_array);
	return err;
}

int process_collect_vmas(struct process_ctx_s *ctx)
{
	int err;

	err = collect_vmas(ctx->pid, &ctx->vmas);
	if (err) {
		pr_err("Can't collect mappings for %d\n", ctx->pid);
		return err;
	}
	return 0;
}

int process_find_target_vma(struct process_ctx_s *ctx)
{
	const struct vma_area *vma;
	const char *bid = PI(ctx)->old_bid;

	pr_info("= Searching source VMA:\n");

	vma = find_vma_by_bid(&ctx->vmas, bid);
	if (!vma) {
		pr_err("failed to find vma with Build ID %s in process %d\n",
				bid, ctx->pid);
		return -ENOENT;
	}
	pr_info("  - path   : %s\n", vma->path);
	pr_info("  - address: %#lx\n", vma_start(vma));
	TVMA(ctx) = vma;
	return 0;
}

int process_find_patch(struct process_ctx_s *ctx)
{
	const char *bid = PI(ctx)->new_bid;

	pr_info("= Cheking for patch is applied...\n");

	if (find_vma_by_bid(&ctx->vmas, bid)) {
		pr_err("Patch with Build ID %s is already applied\n", bid);
		return -EEXIST;
	}
	return 0;
}
