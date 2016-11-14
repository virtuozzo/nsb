#include "include/log.h"
#include "include/protobuf.h"
#include "include/x86_64.h"

#define X64_CALLQ	0xe8
#define X64_JMPQ	0xe9

static int ip_change_relative(unsigned char *buf, unsigned char opcode,
			      unsigned long cur_pos, unsigned long tgt_pos)
{
	unsigned char *instr = &buf[0];
	unsigned int *addr = (unsigned int *)&buf[1];
	int i;
	size_t cmd_size = 5;

	*instr = opcode;
	*addr = tgt_pos - cur_pos - 5;

	pr_debug("%s: cur_pos : %#lx\n", __func__, cur_pos);
	pr_debug("%s: tgt_pos : %#lx\n", __func__, tgt_pos);
	pr_debug("%s: offset  : %#lx\n", __func__, tgt_pos - cur_pos - cmd_size);
	pr_debug("%s: bytes   :", __func__);
	for (i = 0; i < 5; i++)
		pr_msg(" %02x", buf[i]);
	pr_debug("\n");

	return cmd_size;
}

int x86_create_instruction(unsigned char *buf, int type,
			   unsigned long cur_pos, unsigned long tgt_pos)
{
	switch (type) {
		case OBJ_INFO__OBJ_TYPE__CALL:
			return ip_change_relative(buf, X64_CALLQ, cur_pos, tgt_pos);
		case OBJ_INFO__OBJ_TYPE__JMPQ:
			return ip_change_relative(buf, X64_JMPQ, cur_pos, tgt_pos);
	}
	pr_debug("%s: unknown object type: %d\n", __func__, type);
	return -1;
}
