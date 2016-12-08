#ifndef __PATCHER_BACKTRACE_H__
#define __PATCHER_BACKTRACE_H__

struct backtrace_function_s {
	struct list_head	list;
	uint64_t		ip;
	uint64_t		sp;
	char			*name;
};

struct backtrace_s {
	int			depth;
	struct list_head	calls;
};

int process_backtrace(pid_t pid, struct backtrace_s *bt);

#endif
