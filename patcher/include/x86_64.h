#ifndef __PATCHER_X86_64_H__
#define __PATCHER_X86_64_H__

/* In reality the maximum size is 15.
 * But the buffer with this size will be used for read data via ptrace,
 * which requires size, aligned by 8
 */
#define X86_MAX_SIZE	16

int x86_modify_instruction(unsigned char *buf, size_t op_size, size_t addr_size,
			   unsigned long cur_pos, unsigned long tgt_pos);
int x86_jmpq_instruction(unsigned char *buf, size_t size,
			 unsigned long cur_pos, unsigned long tgt_pos);

#endif
