#ifndef __PATCHER_UTIL_H__
#define __PATCHER_UTIL_H__

ssize_t read_file(const char *path, uint8_t *buf, off_t offset, size_t len);
int check_file_type(const char *path, unsigned type);
int iterate_dir_name(const char *dpath,
		     int (*actor)(const char *dentry, void *data),
		     void *data);

#endif
