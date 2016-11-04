#ifndef UAPI_COMPEL_H__
#define UAPI_COMPEL_H__

#include <unistd.h>
#include <errno.h>
#include <stdarg.h>

#include <compel/asm/infect-types.h>

#define COMPEL_TYPE_INT		(1u << 0)
#define COMPEL_TYPE_LONG	(1u << 1)
#define COMPEL_TYPE_GOTPCREL	(1u << 2)

typedef struct {
	unsigned int	offset;
	unsigned int	type;
	long		addend;
	long		value;
} compel_reloc_t;

/*
 * Logging
 */
typedef void (*compel_log_fn)(unsigned int lvl, const char *fmt, va_list parms);
extern void compel_log_init(compel_log_fn log_fn, unsigned int level);
extern unsigned int compel_log_get_loglevel(void);

/*
 * Infection.
 */
typedef struct {
	void *		blob;
	size_t		blob_size;
	size_t		pie_size;
	unsigned long	(*get_parasite_ip)(void *remote_map);
	unsigned int *	(*get_addr_cmd)(void *local_map);
	void *		(*get_addr_args)(void *local_map);
	void		(*postproc)(void *local_map, void *remote_map);
} parasite_blob_desc_t;

#include <compel/infect-util.h>
#include <compel/infect-rpc.h>
#include <compel/infect.h>

#endif /* UAPI_COMPEL_H__ */
