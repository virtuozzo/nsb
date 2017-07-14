#include <sys/socket.h>

int send_fd(int sock, int fd)
{
	char cbuf[CMSG_SPACE(sizeof(fd))] = { };
	struct iovec io = {
		.iov_base = "x",
		.iov_len = 1,
	};
	struct msghdr msg = {
		.msg_iov = &io,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),
	};
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	unsigned char *data = CMSG_DATA(cmsg);

	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));

	*(int *)data = fd;

	msg.msg_controllen = cmsg->cmsg_len;

	return sendmsg(sock, &msg, 0);
}

int recv_fd(int sock)
{
	char mbuf[256],  cbuf[256];
	struct iovec io = {
		.iov_base = mbuf,
		.iov_len = sizeof(mbuf),
	};
	struct msghdr msg = {
		.msg_iov = &io,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),
	};
	int err;

	err = recvmsg(sock, &msg, 0);
	if (err < 0)
		return err;

	return *(int*)CMSG_DATA(CMSG_FIRSTHDR(&msg));
}
