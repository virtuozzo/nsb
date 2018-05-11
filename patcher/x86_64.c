#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>

#include <compel/compel.h>
#include <compel/ptrace.h>
#include <link.h>
#include <gelf.h>

#include "include/log.h"
#include "include/xmalloc.h"

#include "include/log.h"
#include "include/x86_64.h"
#include "include/compiler.h"
#include "stdio.h"

#define X86_64_JUMP_RANGE	(2UL << 30) /* 2 GB */

#include "include/process.h"

int process_do_open_file_x86_64(struct process_ctx_s *ctx,
				const char *path, int flags, mode_t mode)
{
	int err, fd;

	err = ctx->arch_callback->process_write_data(ctx, vma_start(&ctx->remote_vma),
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

int64_t process_map_vma_x86_64(struct process_ctx_s *ctx, int fd,
			const struct vma_area *vma)
{
	int64_t addr;

	process_print_mmap(vma);

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

int process_unmap_vma_x86_64(struct process_ctx_s *ctx, const struct vma_area *vma)
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

int process_close_file_x86_64(struct process_ctx_s *ctx, int fd)
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

long process_syscall(struct process_ctx_s *ctx, int nr,
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


static int rtld_get_dyn(struct process_ctx_s *ctx, const void *addr, GElf_Dyn *dyn)
{
	return ctx->arch_callback->process_read_data(ctx, (uint64_t)addr, dyn, sizeof(*dyn));
}

static int64_t rtld_dynamic_tag_val(struct process_ctx_s *ctx,
				    const GElf_Dyn *l_ld, uint32_t d_tag)
{
	GElf_Dyn dyn;
	const GElf_Dyn *d;
	int err;

	for (d = l_ld; ; d++) {
		err = rtld_get_dyn(ctx, d, &dyn);
		if (err)
			return err;

		if (dyn.d_tag == DT_NULL)
			break;

		if (dyn.d_tag == d_tag)
			return dyn.d_un.d_val;
	}
	return -ENOENT;
}

static int rtld_get_lm(struct process_ctx_s *ctx, void *addr, struct link_map *lm)
{
	return ctx->arch_callback->process_read_data(ctx, (uint64_t)addr, lm, sizeof(*lm));
}

int rtld_needed_array_x86_64(struct process_ctx_s *ctx, uint64_t _r_debug_addr,
		      uint64_t **needed_array)
{
	struct link_map link_map, *lm = &link_map;
	void *lm_addr;
	int err, nr = 0;
	const int step = 10;
	uint64_t *arr = NULL;

	err = ctx->arch_callback->process_read_data(ctx, _r_debug_addr + offsetof(struct r_debug, r_map),
				&lm_addr, sizeof(lm_addr));
	if (err)
		return err;

	do {
		int64_t dt_symtab_addr;

		err = rtld_get_lm(ctx, lm_addr, lm);
		if (err)
			return err;

		/* We rely upon presense of DT_SYMTAB, because it's mandatory */
		dt_symtab_addr = rtld_dynamic_tag_val(ctx, lm->l_ld, DT_SYMTAB);
		if (dt_symtab_addr == -ENOENT)
			return dt_symtab_addr;

		/* Check dt_symtab_addr for being above link addr.
		 * This is diferent in VDSO, which has negative or small
		 * address which is offsets from base.
		 */
		if (dt_symtab_addr >= (int64_t)lm->l_addr) {
			if ((nr % step) == 0) {
				arr = xrealloc(arr, step * sizeof(uint64_t));
				if (!arr)
					return -ENOMEM;
			}
			arr[nr] = dt_symtab_addr;
			nr++;
		}
		lm_addr = lm->l_next;
	} while (lm_addr);

	*needed_array = arr;
	return nr;
}

int process_write_data_x86_64(const struct process_ctx_s *ctx, uint64_t addr, const void *data, size_t size)
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

int process_read_data_x86_64(const struct process_ctx_s *ctx, uint64_t addr, void *data, size_t size)
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

uint64_t x86_jump_min_address(uint64_t address)
{
	if (address > X86_64_JUMP_RANGE)
		return address - X86_64_JUMP_RANGE;
	return 0;
}

uint64_t x86_jump_max_address(uint64_t address)
{
	return address + X86_64_JUMP_RANGE;
}

static int ip_gen_offset(uint64_t next_ip, uint64_t tgt_pos,
			 char addr_size, int *buf)
{
	int64_t offset;
	uint64_t mask = INT_MAX;

	if (addr_size != 4) {
		pr_err("relative offset with size other than 4 bytes "
			"is not supported yet\n");
		return -ENOTSUP;
	}

	offset = tgt_pos - next_ip;
	if (labs(offset) & ~mask) {
		pr_err("%s: offset is beyond command size: %#lx > %#lx\n",
				__func__, offset, mask);
		return -EINVAL;
	}

	*buf = offset;
	return 0;
}

static int x86_modify_instruction(unsigned char *buf, size_t op_size, size_t addr_size,
			   uint64_t cur_pos, uint64_t tgt_pos)
{
	int *addr;
	size_t instr_size = op_size + addr_size;

	addr = (int *)(buf + op_size);
	if (ip_gen_offset(cur_pos + instr_size, tgt_pos, addr_size, addr))
		return -1;
	return instr_size;
}

int x86_jmpq_instruction(unsigned char *buf, size_t buf_size,
			 uint64_t cur_pos, uint64_t tgt_pos)
{
	if (buf_size < 5) {
		pr_err("buffer size is too small for jump command: %ld < 5\n",
				buf_size);
		return -ENOSPC;
	}
	memset(buf, 0x90, buf_size);
	*buf = 0xe9;
	return x86_modify_instruction(buf, 1, 4, cur_pos, tgt_pos);
}

ssize_t x86_64_call(uint64_t call, uint64_t where,
		    uint64_t arg0, uint64_t arg1, uint64_t arg2,
		    uint64_t arg3, uint64_t arg4, uint64_t arg5,
		    void **code)
{
	struct mov_reg {
		unsigned char prefix;
		unsigned char reg;
		unsigned char addr[8];
	};
	static struct x86_64_call_cmd {
		struct mov_reg mov_r9;
		struct mov_reg mov_r8;
		struct mov_reg mov_rcx;
		struct mov_reg mov_rdx;
		struct mov_reg mov_rsi;
		struct mov_reg mov_rdi;
		unsigned char call[5];
		unsigned char int3;
	} blob = {
		.mov_r9 = {
			.prefix = 0x49,
			.reg = 0xb9,
		},
		.mov_r8 = {
			.prefix = 0x49,
			.reg = 0xb8,
		},
		.mov_rcx = {
			.prefix = 0x48,
			.reg = 0xb9,
		},
		.mov_rdx = {
			.prefix = 0x48,
			.reg = 0xba,
		},
		.mov_rsi = {
			.prefix = 0x48,
			.reg = 0xbe,
		},
		.mov_rdi = {
			.prefix = 0x48,
			.reg = 0xbf,
		},
		.call = { 0xe8 },
		.int3 = 0xcc,
	};
	ssize_t size;

	memcpy(blob.mov_r9.addr, &arg5, sizeof(arg5));
	memcpy(blob.mov_r8.addr, &arg4, sizeof(arg4));
	memcpy(blob.mov_rcx.addr, &arg3, sizeof(arg3));
	memcpy(blob.mov_rdx.addr, &arg2, sizeof(arg2));
	memcpy(blob.mov_rsi.addr, &arg1, sizeof(arg1));
	memcpy(blob.mov_rdi.addr, &arg0, sizeof(arg0));

	size = x86_modify_instruction(blob.call, 1, 4, where + offsetof(struct x86_64_call_cmd, call), call);
	if (size < 0)
		return size;
#if 0
	pr_debug("where: %lx\n", where);
	pr_debug("call : %lx\n", call);
	pr_debug("arg0 : %lx\n", arg0);
	pr_debug("size : %ld\n", sizeof(blob));
	{
		unsigned char *p;
		int i;

		pr_msg("%lx: ", where + offsetof(struct x86_64_call_cmd, mov_r9));
		for (i = 0, p = (unsigned char *)&blob.mov_r9; i < sizeof(struct mov_reg); i++, p++)
			pr_msg("%02x ", *p);
		pr_msg("\n");

		pr_msg("%lx: ", where + offsetof(struct x86_64_call_cmd, mov_r8));
		for (i = 0, p = (unsigned char *)&blob.mov_r8; i < sizeof(struct mov_reg); i++, p++)
			pr_msg("%02x ", *p);
		pr_msg("\n");

		pr_msg("%lx: ", where + offsetof(struct x86_64_call_cmd, mov_rcx));
		for (i = 0, p = (unsigned char *)&blob.mov_rcx; i < sizeof(struct mov_reg); i++, p++)
			pr_msg("%02x ", *p);
		pr_msg("\n");

		pr_msg("%lx: ", where + offsetof(struct x86_64_call_cmd, mov_rdx));
		for (i = 0, p = (unsigned char *)&blob.mov_rdx; i < sizeof(struct mov_reg); i++, p++)
			pr_msg("%02x ", *p);
		pr_msg("\n");

		pr_msg("%lx: ", where + offsetof(struct x86_64_call_cmd, mov_rsi));
		for (i = 0, p = (unsigned char *)&blob.mov_rsi; i < sizeof(struct mov_reg); i++, p++)
			pr_msg("%02x ", *p);
		pr_msg("\n");

		pr_msg("%lx: ", where + offsetof(struct x86_64_call_cmd, mov_rdi));
		for (i = 0, p = (unsigned char *)&blob.mov_rdi; i < sizeof(struct mov_reg); i++, p++)
			pr_msg("%02x ", *p);
		pr_msg("\n");

		pr_msg("%lx: ", where + offsetof(struct x86_64_call_cmd, call));
		for (i = 0, p = (unsigned char *)&blob.call; i < 5; i++, p++)
			pr_msg("%02x ", *p);
		pr_msg("\n");

		pr_msg("%lx: ", where + offsetof(struct x86_64_call_cmd, int3));
		for (i = 0, p = (unsigned char *)&blob.int3; i < 1; i++, p++)
			pr_msg("%02x ", *p);
		pr_msg("\n");
	}
#endif
	*code = &blob;
	return sizeof(blob);
}

ssize_t x86_64_dlopen(uint64_t dlopen_addr, uint64_t name_addr,
		      uint64_t where,
		      void **code)
{
	return x86_64_call(dlopen_addr, where,
			   name_addr, 1, 0,
			   0, 0, 0,
			   code);
}

ssize_t x86_64_dlclose(uint64_t dlopen_addr, uint64_t handle,
		       uint64_t where,
		       void **code)
{
	return x86_64_call(dlopen_addr, where,
			   handle, 0, 0,
			   0, 0, 0,
			   code);
}

struct arch_cb x86_64_cb = {
        .jump_min_address = &x86_jump_min_address,
        .jump_max_address = &x86_jump_max_address,
        .call = &x86_64_call,
        .dlopen = &x86_64_dlopen,
        .dlclose = &x86_64_dlclose,
	.process_read_data = &process_read_data_x86_64,
	.process_write_data = &process_write_data_x86_64,
	.rtld_needed_array = &rtld_needed_array_x86_64,
	.process_unmap_vma = &process_unmap_vma_x86_64,
	.process_map_vma = &process_map_vma_x86_64,
	.process_close_file = &process_close_file_x86_64,
	.process_do_open_file = &process_do_open_file_x86_64,

};


int process_do_open_file_x86(struct process_ctx_s *ctx,
				const char *path, int flags, mode_t mode)
{
	int err, fd;

	err = ctx->arch_callback->process_write_data(ctx, vma_start(&ctx->remote_vma),
				 path, round_up(strlen(path) + 1, 8));
	if (err)
		return err;

	fd = process_syscall(ctx, __NR(open, true),
			     vma_start(&ctx->remote_vma),
			     flags, mode, 0, 0, 0);
	if (fd < 0) {
		pr_perror("Failed to open %s", path);
		return -errno;
	}
	return fd;
}

int64_t process_map_vma_x86(struct process_ctx_s *ctx, int fd,
			const struct vma_area *vma)
{
	int64_t addr;

	process_print_mmap(vma);

	if (ctx->service.loaded) {
		pr_err("service is loaded\n");
		return -EBUSY;
	}

	addr = process_syscall(ctx, __NR(mmap, true),
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

int process_unmap_vma_x86(struct process_ctx_s *ctx, const struct vma_area *vma)
{
	int err;

	process_print_munmap(vma);

	if (ctx->service.loaded) {
		pr_err("service is loaded\n");
		return -EBUSY;
	}

	err = process_syscall(ctx, __NR(munmap, true),
			      vma_start(vma), vma_length(vma), 0, 0, 0, 0);
	if (err < 0) {
		pr_perror("Failed to unmap %#lx-%#lx",
				vma_start(vma), vma_end(vma));
		return -errno;
	}
	return 0;
}

int process_close_file_x86(struct process_ctx_s *ctx, int fd)
{
	int err;

	err = process_syscall(ctx, __NR(close, true),
			      fd, 0, 0, 0, 0, 0);
	if (err < 0) {
		pr_perror("Failed to close %d", fd);
		return -errno;
	}
	return 0;
}


struct link_map_32_2
{
     /* These first few members are part of the protocol with the debugger.
       This is the same format used in SVR4.  */
	Elf32_Addr l_addr;
	uint32_t l_name;
	uint32_t l_ld;
	uint32_t l_next, l_prev;
};

struct r_debug_32
{
	int r_version;		/* Version number for this protocol.  */
	uint32_t r_map;	/* Head of the chain of loaded objects.  */

	/* This is the address of a function internal to the run-time linker,
	that will always be called when the linker begins to map in a
	library or unmap it, and again when the mapping change is complete.
	The debugger can set a breakpoint at this address if it wants to
	otice shared object mapping changes.  */
	Elf32_Addr r_brk;
	enum
	{
	/* This state value describes the mapping change taking place when
	the `r_brk' address is called.  */
	RT_CONSISTET,		/* Mapping change is complete.  */
	RTADD,			/* Beginning to add a new object.  */
	RT_ELETE		/* Beginning to remove an object mapping.  */
	} r_state;
	
	Elf32_Addr r_ldbase;	/* Base address the linker is loaded at.  */
};

static int rtld_get_dyn_32(struct process_ctx_s *ctx, uint32_t addr, Elf32_Dyn *dyn)
{
	return ctx->arch_callback->process_read_data(ctx, addr, dyn, sizeof(*dyn));
}

static int32_t rtld_dynamic_tag_val_32(struct process_ctx_s *ctx,
				    uint32_t l_ld, uint32_t d_tag)
{
	Elf32_Dyn dyn;
	uint32_t d;
	int err;
	for (d = l_ld; ;)
	{
		err = rtld_get_dyn_32(ctx, d, &dyn);
		
		if (err){
			return err;
		}
		if (dyn.d_tag == DT_NULL){
			break;
		}

		if (dyn.d_tag == d_tag){
			return dyn.d_un.d_ptr;
		}
		d += 8;
	}
	return -ENOENT;
}

static int rtld_get_lm_32(struct process_ctx_s *ctx, uint32_t addr, struct link_map_32_2 *lm)
{
	return ctx->arch_callback->process_read_data(ctx, addr, lm, sizeof(*lm));
}

int rtld_needed_array_x86(struct process_ctx_s *ctx, uint64_t _r_debug_addr,
		      uint64_t **needed_array)
{	
	struct link_map_32_2 link_map, *lm = &link_map;
	uint32_t lm_addr;
	int err, nr = 0;
	const int step = 10;
	uint64_t *arr = malloc(sizeof(uint64_t) * 10);

	err = ctx->arch_callback->process_read_data(ctx, _r_debug_addr + offsetof(struct r_debug_32, r_map),
			&lm_addr, sizeof(lm_addr));
	if (err)
		return err;

	do {
		int32_t dt_symtab_addr;

		err = rtld_get_lm_32(ctx, lm_addr, lm);
		if (err)
			return err;

		dt_symtab_addr = rtld_dynamic_tag_val_32(ctx, lm->l_ld, DT_SYMTAB);
		if (dt_symtab_addr == -ENOENT){
			return dt_symtab_addr;
		}

		if (dt_symtab_addr >= (int32_t)lm->l_addr) {
			if ((nr % step) == 0) {
				arr = xrealloc(arr, step * sizeof(uint64_t));
				if (!arr)
					return -ENOMEM;
			}
			arr[nr] = lm_addr;
			arr[nr] = dt_symtab_addr & 0xffffffff;
			if(dt_symtab_addr == 0 || dt_symtab_addr == 0x130)
			{
				arr[nr] = lm_addr;
			}
			nr++;
		}


		lm_addr = lm->l_next;
	} while (lm_addr);

	*needed_array = arr;

	return nr;
}


int process_write_data_x86(const struct process_ctx_s *ctx, uint64_t addr, const void *data, size_t size)
{
	pid_t pid = ctx->pid;
	int err_read, err_write;
	uint64_t raddr = round_down(addr, 8);
	size += addr - raddr;
	uint64_t rsize = round_up(size, 8);
	
	uint64_t* buffer = malloc(rsize);
	if(!buffer) {
		printf("failed to allocate %lu bytes\n", rsize);
		return -ENOMEM;
	}

	err_read = ptrace_peek_area(ctx->pid, buffer, (void *)raddr, rsize);

	if (err_read) {
		if (err_read == -1) {
			printf("Failed to read range %#lx-%#lx in process %d: "
					"size is not aligned\n", raddr, raddr + rsize, ctx->pid);
			return -EINVAL;
		}
		printf("Failed to read range %#lx-%#lx from process %d: %d",
				raddr, raddr + rsize, ctx->pid, errno);
		return -errno;
	}	

	if (addr & 7)
		memcpy((void *)buffer + addr - raddr, data, size);
	else
		memcpy(buffer, data, size);

		err_write = ptrace_poke_area(ctx->pid, (void*)buffer, (void *)raddr, rsize);
		if (err_write) {
			if (err_write == -1) {
				pr_err("Failed to write range %#lx-%#lx in process %d: "
				       "size is not aligned\n", raddr, raddr + rsize, pid);
				return -EINVAL;
		}
		pr_perror("Failed to write range %#lx-%#lx in process %d",
				raddr, raddr + rsize, pid);
		return -errno;
	}
	return 0;
}

int process_read_data_x86(const struct process_ctx_s *ctx, uint64_t addr, void *data, size_t size)
{
	int err;
	uint64_t *buf;
	uint64_t raddr = round_down(addr, 8);
	size += addr - raddr;
	ssize_t rsize = round_up(size, 8);

	buf = malloc(rsize);
	if (!buf) {
		printf("failed to allocate %lu bytes\n", rsize);
		return -ENOMEM;
	}

	err = ptrace_peek_area(ctx->pid, buf, (void *)raddr, rsize);

	if (err) {
		if (err == -1) {
			printf("Failed to read range %#lx-%#lx in process %d: "
					"size is not aligned\n", raddr, raddr + rsize, ctx->pid);
			return -EINVAL;
		}	
		printf("Failed to read range %#lx-%#lx from process %d: %d",
				raddr, raddr + rsize, ctx->pid, errno);
		return -errno;
	}

	if (addr & 7)
		memcpy(data, (void *)buf + addr-raddr, size);
	else
		memcpy(data, buf, size);

	return 0;
}

struct arch_cb x86_cb = {
        .jump_min_address = &x86_jump_min_address,
        .jump_max_address = &x86_jump_max_address,
        .call = &x86_64_call,
        .dlopen = &x86_64_dlopen,
        .dlclose = &x86_64_dlclose,
	.process_read_data = &process_read_data_x86,
	.process_write_data = &process_write_data_x86,
	.rtld_needed_array = &rtld_needed_array_x86,
	.process_unmap_vma = &process_unmap_vma_x86,
	.process_map_vma = &process_map_vma_x86,
	.process_close_file = &process_close_file_x86,
	.process_do_open_file = &process_do_open_file_x86,
};
