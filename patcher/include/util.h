/*
 * Copyright (c) 2016-2017, Parallels International GmbH
 *
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#ifndef __PATCHER_UTIL_H__
#define __PATCHER_UTIL_H__

#include <stdint.h>

ssize_t read_file(const char *path, uint8_t *buf, off_t offset, size_t len);
int check_file_type(const char *path, unsigned type);
int iterate_dir_name(const char *dpath,
		     int (*actor)(const char *dentry, void *data),
		     void *data);
int find_dentry(const char *dpath,
		int (*actor)(const char *dentry, void *data),
		void *data, char *dentry);

#endif
