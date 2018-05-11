#ifndef __PATCHER_X86_64_H__
#define __PATCHER_X86_64_H__

/*
 * Maximum size of call command
 */
#include "context.h"
#define X86_64_CALL_MAX_SIZE	102

int process_do_open_file_x86_64(struct process_ctx_s *ctx,
				const char *path, int flags, mode_t mode);

long process_syscall(struct process_ctx_s *ctx, int nr,
			    unsigned long arg1, unsigned long arg2,
			    unsigned long arg3, unsigned long arg4,
			    unsigned long arg5, unsigned long arg6);

int process_unmap_vma_x86_64(struct process_ctx_s *ctx, const struct vma_area *vma);
int64_t process_map_vma_x86_64(struct process_ctx_s *ctx, int fd,
		const struct vma_area *vma);
int process_close_file_x86_64(struct process_ctx_s *ctx, int fd);

int rtld_needed_array_x86_64(struct process_ctx_s *ctx, uint64_t _r_debug_addr,
		      uint64_t **needed_array);

int process_read_data_x86_64(const struct process_ctx_s *ctx, uint64_t addr, void *data, size_t size);
int process_write_data_x_86_64(const struct process_ctx_s *ctx, uint64_t addr, const void *data, size_t size);

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

struct arch_cb x86_64_cb;

int process_do_open_file_x86(struct process_ctx_s *ctx,
				const char *path, int flags, mode_t mode);

int process_unmap_vma_x86(struct process_ctx_s *ctx, const struct vma_area *vma);
int64_t process_map_vma_x86(struct process_ctx_s *ctx, int fd,
		const struct vma_area *vma);
int process_close_file_x86(struct process_ctx_s *ctx, int fd);

int rtld_needed_array_x86_64(struct process_ctx_s *ctx, uint64_t _r_debug_addr,
		      uint64_t **needed_array);

int rtld_needed_array_x86(struct process_ctx_s *ctx, uint64_t _r_debug_addr,
		      uint64_t **needed_array);

int process_read_data_x86(const struct process_ctx_s *ctx, uint64_t addr, void *data, size_t size);
int process_write_data_x86(const struct process_ctx_s *ctx, uint64_t addr, const void *data, size_t size);

struct arch_cb x86_cb;

#endif
