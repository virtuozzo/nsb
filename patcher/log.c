#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "include/compiler.h"
#include "include/log.h"

static unsigned int current_loglevel = DEFAULT_LOGLEVEL;
static int logfd = -1;

int log_get_fd(void)
{
	return logfd < 0 ? STDERR_FILENO : logfd;
}

int log_init(const char *output)
{
	if (output && !strncmp(output, "-", 2)) {
		logfd = dup(STDOUT_FILENO);
		if (logfd < 0) {
			pr_perror("Cant't dup stdout stream");
			return -1;
		}
	} else if (output) {
		logfd = open(output, O_CREAT|O_TRUNC|O_WRONLY|O_APPEND, 0600);
		if (logfd < 0) {
			pr_perror("Can't create log file %s", output);
			return -1;
		}
	} else {
		logfd = dup(STDOUT_FILENO);
		if (logfd < 0) {
			pr_perror("Can't dup log file");
			return -1;
		}
	}

	return 0;
}

void log_fini(void)
{
	if (logfd >= 0) {
		close(logfd);
		logfd = -1;
	}
}

void log_set_loglevel(unsigned int level)
{
	if (level == LOG_UNSET)
		current_loglevel = DEFAULT_LOGLEVEL;
	else
		current_loglevel = level;
}

unsigned int log_get_loglevel(void)
{
	return current_loglevel;
}

static void __print_on_level(unsigned int loglevel, const char *format, va_list params)
{
	int fd, size, ret, off = 0;
	int __errno = errno;
	char buffer[1024];

	if (unlikely(loglevel == LOG_MSG)) {
		fd = STDOUT_FILENO;
	} else {
		if (loglevel > current_loglevel)
			return;
		fd = logfd;
	}

	size = vsnprintf(buffer, sizeof(buffer), format, params);

	while (off < size) {
		ret = write(fd, buffer + off, size - off);
		if (ret <= 0)
			break;
		off += ret;
	}
	errno =  __errno;
}

void print_on_level(unsigned int loglevel, const char *format, ...)
{
	va_list params;

	va_start(params, format);
	__print_on_level(loglevel, format, params);
	va_end(params);
}
