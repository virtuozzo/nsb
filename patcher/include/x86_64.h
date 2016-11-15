#ifndef __PATCHER_X86_64_H__
#define __PATCHER_X86_64_H__

/* In reality the maximum size is 15.
 * But the buffer with this size will be used for read data via ptrace,
 * which requires size, aligned by 8
 */
#define X86_MAX_SIZE	16

int x86_create_instruction(unsigned char *buf, unsigned char op,
			   unsigned long cur_pos, unsigned long tgt_pos);

#endif
