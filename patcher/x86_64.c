#include <errno.h>

#include "include/log.h"
#include "include/protobuf.h"
#include "include/x86_64.h"

#define OP_CALLQ	0xe8
#define OP_JMPQ		0xe9
#define OP_JMP		0xeb

int ip_change_relative(unsigned char *buf, unsigned char opcode,
			      unsigned long cur_pos, unsigned long tgt_pos,
			      size_t cmd_size)
{
	unsigned char *instr = &buf[0];
	unsigned int *addr = (unsigned int *)&buf[1];
	int i;

	*instr = opcode;
	*addr = tgt_pos - cur_pos - cmd_size;

	pr_debug("%s: cur_pos : %#lx\n", __func__, cur_pos);
	pr_debug("%s: tgt_pos : %#lx\n", __func__, tgt_pos);
	pr_debug("%s: offset  : %#lx\n", __func__, tgt_pos - cur_pos - cmd_size);
	pr_debug("%s: bytes   :", __func__);
	for (i = 0; i < cmd_size; i++)
		pr_msg(" %02x", buf[i]);
	pr_debug("\n");

	return cmd_size;
}

int x86_create_instruction(unsigned char *buf, unsigned char op,
			   unsigned long cur_pos, unsigned long tgt_pos)
{
	size_t op_size;

	switch (op) {
		case OP_CALLQ:
		case OP_JMPQ:
			op_size = 5;
			break;
		case OP_JMP:
			op_size = 2;
			break;
		default:
			pr_err("unknown command code: %#x\n", op);
			return -EINVAL;
	}
	return ip_change_relative(buf, op, cur_pos, tgt_pos, op_size);
}
