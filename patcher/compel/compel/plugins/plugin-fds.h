/*
 * plugin-fds.h -- API for fds compel plugin
 */

#ifndef __COMPEL_PLUGIN_FDS_H__
#define __COMPEL_PLUGIN_FDS_H__

extern int fds_send(int *fds, int nr_fds);
extern int fds_recv(int *fds, int nr_fds);

static inline int fds_send_one(int fd)
{
	return fds_send(&fd, 1);
}

static inline int fds_recv_one(void)
{
	int fd, ret;

	ret = fds_recv(&fd, 1);
	if (ret)
		fd = -1;

	return fd;
}

extern int send_fds(int sock, struct sockaddr_un *saddr, int len,
		    int *fds, int nr_fds, bool with_flags);

static inline int send_fd(int sock, struct sockaddr_un *saddr, int saddr_len, int fd)
{
	return send_fds(sock, saddr, saddr_len, &fd, 1, false);
}

#endif /* __COMPEL_PLUGIN_FDS_H__ */
