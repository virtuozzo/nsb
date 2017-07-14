#ifndef __PATCHER_RTLD_H__
#define __PATCHER_RTLD_H__

int rtld_needed_array(struct process_ctx_s *ctx, uint64_t _r_debug_addr,
		      uint64_t **needed_array);

#endif /* __PATCHER_RTLD_H__ */
