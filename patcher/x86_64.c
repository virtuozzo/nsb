#include <stdlib.h>
#include <errno.h>

#include "include/log.h"
#include "include/x86_64.h"

static int ip_gen_offset(unsigned long next_ip, unsigned long tgt_pos,
			 char addr_size, int *buf)
{
	int i;
	long offset;
	unsigned long mask = 0;

	for (i = 0; i < addr_size; i++) {
		mask |= ((unsigned long)0xff << (8 * i));
	}

	offset = tgt_pos - next_ip;
	if (abs(offset) & ~mask) {
		pr_err("%s: offset is beyond command size: %#lx > %#lx\n",
				__func__, offset, mask);
		return -EINVAL;
	}

	*buf = offset;
	return 0;
}

static int ip_change_relative(unsigned char *addr,
			      unsigned long next_ip, unsigned long tgt_pos,
			      size_t addr_size)
{
	int offset;

	if (ip_gen_offset(next_ip, tgt_pos, addr_size, &offset))
		return -1;

	memcpy(addr, (void *)&offset, addr_size);
	return 0;
}

static int x86_modify_instruction(unsigned char *buf, size_t op_size, size_t addr_size,
			   unsigned long cur_pos, unsigned long tgt_pos)
{
	unsigned char *addr;
	size_t instr_size = op_size + addr_size;

	addr = buf + op_size;
	if (ip_change_relative(addr, cur_pos + instr_size, tgt_pos, addr_size))
		return -1;
	return instr_size;
}

int x86_jmpq_instruction(unsigned char *buf, size_t buf_size,
			 unsigned long cur_pos, unsigned long tgt_pos)
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
