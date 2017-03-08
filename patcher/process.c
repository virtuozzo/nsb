#include <stdio.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/types.h>
#include <dirent.h>

#include <compel/compel.h>
#include <compel/ptrace.h>

#include "include/log.h"
#include "include/xmalloc.h"
#include "include/vma.h"
#include "include/backtrace.h"
#include "include/process.h"
#include "include/patch.h"

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

int process_write_data(pid_t pid, uint64_t addr, const void *data, size_t size)
{
	int err;

	err = ptrace_poke_area(pid, (void *)data, (void *)addr, size);
	if (err) {
		if (err == -1) {
			pr_err("Failed to write range %#lx-%#lx in process %d: "
			       "size is not aligned\n", addr, addr + size, pid);
			return -EINVAL;
		}
		pr_perror("Failed to read range %#lx-%#lx from process %d",
				addr, addr + size, pid);
		return -errno;
	}
	return 0;
}

int process_read_data(pid_t pid, uint64_t addr, void *data, size_t size)
{
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

int64_t process_create_map(struct process_ctx_s *ctx, int fd, off_t offset,
			unsigned long addr, size_t size, int flags, int prot)
{
	int ret;
	long sret = -ENOSYS;
	char fbuf[512];
	char pbuf[4];

	ret = compel_syscall(ctx->ctl, __NR(mmap, false), &sret,
			     addr, size, prot, flags, fd, offset);
	if (ret < 0) {
		pr_err("Failed to execute syscall for %d\n", ctx->pid);
		return -1;
	}

	if (sret < 0) {
		errno = -sret;
		pr_perror("Failed to create mmap with size %zu bytes", size);
		return -1;
	}

	pr_info("  - %#lx-%#lx, off: %#lx, prot: %s, flags: %s\n",
			sret, sret + size, offset,
			map_prot(prot, pbuf),
			map_flags(flags, fbuf));
	return sret;
}

int process_close_file(struct process_ctx_s *ctx, int fd)
{
	int ret;
	long sret = -ENOSYS;

	ret = compel_syscall(ctx->ctl, __NR(close, false), &sret,
			     (unsigned long)fd, 0, 0, 0, 0, 0);
	if (ret < 0) {
		pr_err("Failed to execute syscall for %d\n", ctx->pid);
		return -1;
	}

	if (sret < 0) {
		errno = -sret;
		pr_perror("Failed to close %d", fd);
		return -1;
	}

	return (int)(long)sret;
}

int process_open_file(struct process_ctx_s *ctx, const char *path, int flags, mode_t mode)
{
	int ret;
	long sret = -ENOSYS;

	process_write_data(ctx->pid, ctx->remote_map,
			path, round_up(strlen(path) + 1, 8));

	ret = compel_syscall(ctx->ctl, __NR(open, false), &sret,
				(unsigned long)ctx->remote_map,
				(unsigned long)flags,
				(unsigned long)mode, 0, 0, 0);
	if (ret < 0) {
		pr_err("Failed to execute syscall for %d\n", ctx->pid);
		return -1;
	}

	if (sret < 0) {
		errno = -sret;
		pr_perror("Failed to open %s", path);
		return -1;
	}

	return (int)(long)sret;
}

static int task_cure(struct thread_s *t)
{
	if (!t->seized)
		return 0;

	if (compel_resume_task(t->pid, TASK_ALIVE, TASK_ALIVE)) {
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

	ctx->remote_map = process_create_map(ctx, -1, 0, 0, PAGE_SIZE,
			MAP_ANONYMOUS | MAP_PRIVATE,
			PROT_READ | PROT_WRITE | PROT_EXEC);
	if ((void *)ctx->remote_map == MAP_FAILED) {
		pr_err("failed to create remove mem\n");
		return -1;
	}

	return 0;
}

static int task_infect(struct thread_s *t)
{
	pr_debug("  %d\n", t->pid);

	switch (compel_stop_task(t->pid)) {
		case TASK_ALIVE:
			t->seized = true;
			return 0;
		case TASK_STOPPED:
			pr_debug("BUSY\n");
			return -EBUSY;
		case TASK_ZOMBIE:
			pr_debug("ZOMBIE\n");
			break;
		case TASK_DEAD:
			pr_debug("DEAD\n");
			break;
		default:
			if (errno != -ESRCH)
				return -errno;
	}
	thread_destroy(t);
	return 0;
}

static int iterate_dir_name(const char *dpath,
			    int (*actor)(const char *dentry, void *data),
			    void *data)
{
	struct dirent *dt;
	DIR *fdir;
	int err;

	fdir = opendir(dpath);
	if (!fdir) {
		pr_perror("failed to open %s", dpath);
		return -errno;
	}

	while ((dt = readdir(fdir)) != NULL) {
		char *dentry = dt->d_name;

		if (!strcmp(dentry, ".") || !strcmp(dentry, ".."))
			continue;

		err = actor(dentry, data);
		if (err)
			break;
	}

	closedir(fdir);
	return err;
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
	int ret;
	long sret = -ENOSYS;

	ret = compel_syscall(ctx->ctl, __NR(munmap, false), &sret,
			addr, size, 0, 0, 0, 0);
	if (ret < 0) {
		pr_err("Failed to execute syscall for %d\n", ctx->pid);
		return -1;
	}

	if (sret < 0) {
		errno = -sret;
		pr_perror("Failed to unmap with size %zu bytes", size);
		return -1;
	}

	pr_debug("Unmapped %#lx-%#lx in task %d\n",
			addr, addr + size, ctx->pid);

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
