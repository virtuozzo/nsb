/*
 * Copyright (c) 2016-2017, Parallels International GmbH
 *
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <dirent.h>

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

static int __iter_dentry(const char *dpath,
			 int (*actor)(const char *dentry, void *data),
			 void *data,
			 struct dirent *dirent)
{
	struct dirent *dt;
	DIR *fdir;
	int err;

	fdir = opendir(dpath);
	if (!fdir) {
		pr_perror("failed to open %s", dpath);
		return -errno;
	}

	while ((err = readdir_r(fdir, dirent, &dt)) == 0) {
		char *dentry;

		if (!dt)
			break;

		dentry = dirent->d_name;

		if (!strcmp(dentry, ".") || !strcmp(dentry, ".."))
			continue;

		err = actor(dentry, data);
		if (err)
			break;
	}

	closedir(fdir);
	return err;

}

int iterate_dir_name(const char *dpath,
		     int (*actor)(const char *dentry, void *data),
		     void *data)
{
	struct dirent dt;

	return __iter_dentry(dpath, actor, data, &dt);
}

int find_dentry(const char *dpath,
		int (*actor)(const char *dentry, void *data),
		void *data, char *dentry)
{
	struct dirent dt;
	int ret;

	ret = __iter_dentry(dpath, actor, data, &dt);
	if (ret < 0) {
		if (!ret)
			return -ENOENT;
		return ret;
	}

	strcpy(dentry, dt.d_name);
	return 0;
}
