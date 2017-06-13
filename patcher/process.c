/*
 * Copyright (c) 2016-2017, Parallels International GmbH
 *
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#include <stdio.h>
#include <limits.h>
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
#include "include/dl_map.h"

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

int process_send_fd(struct process_ctx_s *ctx, int fd)
{
	if (!ctx->service.loaded) {
		pr_err("service is not loaded\n");
		return -EINVAL;
	}

	return service_transfer_fd(ctx, &ctx->service, fd);
}

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

int64_t process_map_vma(struct process_ctx_s *ctx, int fd,
			const struct vma_area *vma)
{
	int64_t addr;

	process_print_munmap(vma);

	if (ctx->service.loaded) {
		pr_err("service is loaded\n");
		return -EBUSY;
	}

	addr = process_syscall(ctx, __NR(mmap, false),
			       vma_start(vma), vma_length(vma), vma_prot(vma),
			       vma_flags(vma), fd, vma_offset(vma));
	if (addr < 0) {
		pr_perror("failed to create new mapping %#lx-%#lx "
			  "in process %d with flags %#x, prot %#x, offset %#lx",
				vma_start(vma), vma_start(vma) + vma_length(vma),
				ctx->pid, vma_prot(vma), vma_flags(vma),
				vma_offset(vma));
		return -errno;
	}
	return addr;
}

void process_print_munmap(const struct vma_area *vma)
{
	pr_info("  - munmap: %#lx-%#lx\n", vma_start(vma), vma_end(vma));
}

static int unmap_dl_vma(struct vma_area *vma, void *data)
{
	struct process_ctx_s *ctx = data;

	return process_unmap_vma(ctx, vma);
}

int process_munmap_dl_map(struct process_ctx_s *ctx, const struct dl_map *dlm)
{
	if (ctx->dry_run)
		return 0;

	if (ctx->service.loaded)
		return service_munmap_dlm(ctx, &ctx->service, dlm);

	return iterate_dl_vmas(dlm, ctx, unmap_dl_vma);
}

void process_print_mmap(const struct vma_area *vma)
{
	char fbuf[512];
	char pbuf[4];

	pr_info("  - mmap: %#lx-%#lx, off: %#lx, prot: %s, flags: %s\n",
			vma_start(vma), vma_end(vma), vma_offset(vma),
			map_prot(vma_prot(vma), pbuf),
			map_flags(vma_flags(vma), fbuf));
}

static int process_mmap_dlm_service(struct process_ctx_s *ctx,
				    const struct dl_map *dlm)
{
	int fd;

	fd = service_transfer_fd(ctx, &ctx->service, elf_info_fd(dlm->ei));
	if (fd < 0)
		return fd;

	return service_mmap_dlm(ctx, &ctx->service, dlm, fd);
}

static int process_mmap_dlm_manual(struct process_ctx_s *ctx,
				   const struct dl_map *dlm)
{
	int fd;
	int64_t addr;
	struct vma_area *vma;

	fd = process_open_file(ctx, dlm->path, O_RDONLY, 0);
	if (fd < 0)
		return fd;

	list_for_each_entry(vma, &dlm->vmas, dl) {
		addr = process_map_vma(ctx, fd, vma);
		if (addr < 0)
			goto unmap;
	}

	(void)process_close_file(ctx, fd);

	return 0;

unmap:
	list_for_each_entry_continue_reverse(vma, &dlm->vmas, dl)
		(void)process_unmap_vma(ctx, vma);
	return addr;
}

int process_mmap_dl_map(struct process_ctx_s *ctx, const struct dl_map *dlm)
{
	if (ctx->dry_run)
		return 0;

	if (ctx->service.loaded)
		return process_mmap_dlm_service(ctx, dlm);

	return process_mmap_dlm_manual(ctx, dlm);
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

	err = process_write_data(ctx, vma_start(&ctx->remote_vma),
				 path, round_up(strlen(path) + 1, 8));
	if (err)
		return err;

	fd = process_syscall(ctx, __NR(open, false),
			     vma_start(&ctx->remote_vma),
			     flags, mode, 0, 0, 0);
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

	err = process_unmap_vma(ctx, &ctx->remote_vma);
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
	int64_t addr;

	pr_debug("= Prepare %d\n", ctx->pid);

	ctx->ctl = compel_prepare(ctx->pid);
	if (!ctx->ctl) {
		pr_err("Can't create compel control\n");
		return -1;
	}

	addr = process_map_vma(ctx, -1, &ctx->remote_vma);
	if ((void *)addr == MAP_FAILED) {
		pr_err("failed to create service memory region in process %d\n", ctx->pid);
		goto cure;
	}

	ctx->remote_vma.addr = addr;

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

int process_unmap_vma(struct process_ctx_s *ctx, const struct vma_area *vma)
{
	int err;

	process_print_munmap(vma);

	if (ctx->service.loaded) {
		pr_err("service is loaded\n");
		return -EBUSY;
	}

	err = process_syscall(ctx, __NR(munmap, false),
			      vma_start(vma), vma_length(vma), 0, 0, 0, 0);
	if (err < 0) {
		pr_perror("Failed to unmap %#lx-%#lx",
				vma_start(vma), vma_end(vma));
		return -errno;
	}
	return 0;
}

static int task_check_stack(const struct process_ctx_s *ctx, const struct thread_s *t,
			    uint64_t start, uint64_t end)
{
	int err;
	struct backtrace_s *bt;

	pr_info("  %d:\n", t->pid);

	err = pid_backtrace(t->pid, &bt);
	if (err) {
		if (err != -EAGAIN)
			pr_err("failed to unwind task %d stack\n", t->pid);
		else
			pr_warn("temporary failed to unwind task %d stack\n",
					t->pid);
		return err;
	}

	err = ctx->check_backtrace(ctx, bt, start, end);

	destroy_backtrace(bt);
	return err;
}

static int process_check_stack(const struct process_ctx_s *ctx,
			       uint64_t start, uint64_t end)
{
	struct thread_s *t;
	int err;

	pr_info("= Checking %d stack...\n", ctx->pid);
	list_for_each_entry(t, &ctx->threads, list) {
		err = task_check_stack(ctx, t, start, end);
		if (err)
			return err;
	}
	return 0;
}

struct target_info {
	const char		*bid;
	uint64_t		start;
	uint64_t		end;
};

static int compare_target_bid(pid_t pid, const struct vma_area *vma, void *data)
{
	struct target_info *ti = data;
	const char *bid = ti->bid;
	struct elf_info_s *ei;
	char map_file[PATH_MAX];
	int ret;

	if (!vma->path)
		return 0;

	snprintf(map_file, sizeof(map_file), "/proc/%d/map_files/%lx-%lx",
			pid, vma_start(vma), vma_end(vma));

	if (access(map_file, F_OK))
		return 0;

	if (!is_elf_file(map_file))
		return 0;

	ret = elf_create_info(map_file, &ei);
	if (ret)
		return ret;

        if (!elf_bid(ei))
		goto destroy_ei;

	if (strcmp(elf_bid(ei), bid))
		goto destroy_ei;

	ti->start = elf_type_dyn(ei) ? vma_start(vma) : 0;
	ti->end = elf_type_dyn(ei) ? vma_end(vma) : 0;
	ret = 1;

destroy_ei:
	elf_destroy_info(ei);
	return ret;
}

int process_get_target_info(pid_t pid, struct target_info *ti)
{
	int ret;

	ret = iter_map_files(pid, compare_target_bid, ti);
	if (ret < 0) {
		errno = -ret;
		pr_perror("failed to open target ELF with Build ID %s in process %d",
				ti->bid, pid);
		return ret;
	}
	if (ret == 0) {
		pr_err("failed to find target ELF with Build ID %s in process %d\n",
				ti->bid, pid);
		return -ENOENT;
	}
	return 0;
}

static int process_catch(struct process_ctx_s *ctx, const char *target_bid)
{
	int ret, err;
	struct target_info ti = {
		.bid = target_bid,
	};

	err = process_infect(ctx);
	if (err)
		return err;

	ret = process_get_target_info(ctx->pid, &ti);
	if (ret)
		goto cure;

	ret = process_check_stack(ctx, ti.start, ti.end);
	if (ret)
		goto cure;

	return 0;

cure:
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
	int64_t ret;
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

	ret = get_user_reg(&regs, ax);
	if (ret < 0)
		pr_err("code execution returned error: %ld\n", ret);
	return ret;
}

int process_suspend(struct process_ctx_s *ctx, const char *target_bid)
{
	int try = 0, tries = 25;
	unsigned timeout_msec = 1;
	int ret;

	do {
		if (try) {
			pr_info("  Failed to catch process in a suitable time/place.\n"
				"  Retry in %d msec\n", timeout_msec);

			usleep(timeout_msec * 1000);

			timeout_msec = increase_timeout(timeout_msec);
		}
		ret = process_catch(ctx, target_bid);
		if (ret != -EAGAIN)
			return ret;
	} while (++try < tries);

	pr_err("failed to suspend process: Timeout reached\n");
	return -ETIME;
}

static int process_find_sym(struct process_ctx_s *ctx,
			    const char *name, uint64_t *addr)
{
	int64_t value;

	value = dl_get_symbol_value(&ctx->dl_maps, name);
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
	uint64_t code_addr = vma_start(&ctx->remote_vma);
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
		if (!handle)
			pr_err("dlopen returned NULL\n");
		pr_err("failed to inject nsb service\n");
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
	uint64_t code_addr = vma_start(&ctx->remote_vma);

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

	ctx->service.handle = 0;
	return 0;
}

static int collect_needed(struct process_ctx_s *ctx, struct list_head *head,
			  const struct dl_map *dlm)
{
	struct ctx_dep *cd;

	cd = xmalloc(sizeof(*cd));
	if (!cd)
		return -ENOMEM;

	cd->dlm = dlm;
	list_add_tail(&cd->list, head);

	pr_debug("  - %lx-%lx - %s\n", dl_map_start(cd->dlm),
			dl_map_start(cd->dlm), cd->dlm->path);
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
		const struct dl_map *dlm;
		uint64_t address = needed_array[i];

		dlm = find_dl_map_by_addr(&ctx->dl_maps, address);
		if (!dlm) {
			pr_err("failed to find VMA by address %#lx\n", address);
			err = -ENOENT;
			goto free_array;
		}

		if (!dlm->exec_vma) {
			pr_err("%s dl_map object doesn't have executable VMA\n",
					dlm->path);
			err = -EFAULT;
			goto free_array;
		}

		err = collect_needed(ctx, &ctx->needed_list, dlm);
		if (err)
			goto free_array;

	}

free_array:
	if (err)
		pr_err("failed to collect process %d binary dependences\n",
				ctx->pid);
	free(needed_array);
	return err;
}

static int check_vzpatch(const struct dl_map *dlm, void *data)
{
	struct process_ctx_s *ctx = data;
	struct patch_s *patch;
	int err;

	if (!dlm) {
		pr_err("VMA without dl_map link\n");
		return -EINVAL;
	}
	if (!dlm->ei) {
		pr_err("Dl map object doesn't have ELF info structure\n");
		return -EFAULT;
	}

	if (!elf_has_section(dlm->ei, VZPATCH_SECTION))
		return 0;

	err = create_patch_by_dlm(ctx, dlm, &patch);
	if (err)
		return err;

	list_add_tail(&patch->list, &ctx->applied_patches);
	return 0;
}

static int collect_patches(struct process_ctx_s *ctx)
{
	pr_info("= Collecting applied patches:\n");

	return iterate_dl_maps(&ctx->dl_maps, ctx, check_vzpatch);
}

int process_collect_vmas(struct process_ctx_s *ctx)
{
	int err;

	err = collect_vmas(ctx->pid, &ctx->vmas);
	if (err) {
		pr_err("Can't collect mappings for %d\n", ctx->pid);
		return err;
	}

	err = collect_dl_maps(&ctx->vmas, &ctx->dl_maps);
	if (err)
		return err;

	err = collect_patches(ctx);
	if (err)
		return err;

	return 0;
}

int process_find_target_dlm(struct process_ctx_s *ctx)
{
	const struct dl_map *dlm;
	const char *bid = PI(ctx)->target_bid;

	pr_info("= Searching target VMA:\n");

	dlm = find_dl_map_by_bid(&ctx->dl_maps, bid);
	if (!dlm) {
		pr_err("failed to find vma with Build ID %s in process %d\n",
				bid, ctx->pid);
		return -ENOENT;
	}
	pr_info("  - path   : %s\n", dlm->path);
	pr_info("  - address: %#lx\n", dl_map_start(dlm));
	TDLM(ctx) = dlm;
	return 0;
}

struct address_hole {
	uint64_t		hint;
	size_t			size;
	uint64_t		address;
};

static int find_hole(struct vma_area *vma, void *data)
{
	struct address_hole *hole = data;

	if (vma_start(next_vma(vma)) < hole->hint)
		return 0;

	if (vma->dlm && (vma != last_dl_vma(vma->dlm)))
		return 0;

	hole->address = max(hole->hint, vma_end(vma));

	return (vma_start(next_vma(vma)) - hole->address) >= hole->size;
}

int64_t process_find_place_for_elf(struct process_ctx_s *ctx,
				   uint64_t hint, size_t size)
{
	struct address_hole hole = {
		.hint = hint,
		.size = size,
	};
	int ret;

	ret = iterate_vmas(&ctx->vmas, &hole, find_hole);
	if (ret <= 0)
		return ret ? ret : -ENOENT;
	return hole.address;
}
