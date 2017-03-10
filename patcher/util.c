#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

#include "include/log.h"
#include "include/util.h"

ssize_t read_file(const char *path, uint8_t *buf, off_t offset, size_t len)
{
	int fd;
	ssize_t res;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("failed to open %s", path);
		return -errno;
	}

	if (offset && (lseek(fd, offset, SEEK_SET) != offset)) {
		pr_perror("failed to set offset %ld for %s fd", offset, path);
		res = -errno;
		goto close_fd;
	}

	res = read(fd, buf, len);
	if (res < 0) {
		pr_perror("failed to read %s", path);
		res = -errno;
	}

close_fd:
	close(fd);
	return res;
}

int check_file_type(const char *path, unsigned type)
{
	struct stat st;

	if (stat(path, &st)) {
		pr_perror("failed to stat %s", path);
		return -errno;
	}

	return (st.st_mode & S_IFMT) == type;
}
