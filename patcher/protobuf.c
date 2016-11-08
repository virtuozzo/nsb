#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "include/log.h"

#include "protobuf.h"

static ssize_t read_image(const char *path, uint8_t *buf, size_t max_len)
{
	int fd;
	ssize_t res;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("failed to open %s", path);
		return -errno;
	}

	res = read(fd, buf, max_len);
	if (res < 0) {
		pr_perror("failed to read %s", path);
		res = -errno;
	}

	close(fd);
	return res;
}

FuncPatch *read_funcpatch(const char *path)
{
	uint8_t page[4096];
	ssize_t res;
	FuncPatch *patch;

	res = read_image(path, page, 4096);
	if (res < 0)
		return NULL;

	patch = func_patch__unpack(NULL, res, page); // Deserialize the serialized input
	if (patch == NULL) {
		pr_err("failed to unpack funcpatch\n");
		return NULL;
	}

	return patch;
}

BinPatch *read_binpatch(const char *path)
{
	uint8_t page[4096];
	ssize_t res;
	BinPatch *patch;

	res = read_image(path, page, 4096);
	if (res < 0)
		return NULL;

	patch = bin_patch__unpack(NULL, res, page); // Deserialize the serialized input
	if (patch == NULL) {
		pr_err("failed to unpack binpatch\n");
		return NULL;
	}

	return patch;
}
