typedef int (*caller_t)(void);

int call_after_sig(caller_t caller);
