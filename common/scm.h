/*
 * Copyright (c) 2016-2017, Parallels International GmbH
 *
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#ifndef __PATCHER_SCM_H__
#define __PATCHER_SCM_H__

int send_fd(int sock, int fd);
int recv_fd(int sock);

#endif /* __PATCHER_SCM_H__ */
