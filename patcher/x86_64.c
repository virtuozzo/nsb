#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>

#include "include/log.h"
#include "include/x86_64.h"
#include "include/compiler.h"

#define X86_64_JUMP_RANGE	(2UL << 30) /* 2 GB */

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
