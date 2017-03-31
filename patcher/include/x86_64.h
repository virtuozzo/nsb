#ifndef __PATCHER_X86_64_H__
#define __PATCHER_X86_64_H__

/*
 * Maximum size of call command
 */
#define X86_64_CALL_MAX_SIZE	102

uint64_t x86_jump_min_address(uint64_t address);
uint64_t x86_jump_max_address(uint64_t address);

int x86_jmpq_instruction(unsigned char *buf, size_t size,
			 uint64_t cur_pos, uint64_t tgt_pos);

ssize_t x86_64_call(uint64_t call, uint64_t where,
		    uint64_t arg0, uint64_t arg1, uint64_t arg2,
		    uint64_t arg3, uint64_t arg4, uint64_t arg5,
		    void **code);

ssize_t x86_64_dlopen(uint64_t dlopen_addr, uint64_t name_addr,
		      uint64_t where,
		      void **code);
ssize_t x86_64_dlclose(uint64_t dlopen_addr, uint64_t handle,
		       uint64_t where,
		       void **code);

#endif
