/*
 * Copyright (C) 2020 John Crispin <john@phrozen.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "u80211d.h"

static int ioctl_socket = -1;

static int iface_ioctl_socket(void)
{
	if (ioctl_socket == -1) {
		ioctl_socket = socket(AF_INET, SOCK_DGRAM, 0);
		fcntl(ioctl_socket, F_SETFD, fcntl(ioctl_socket, F_GETFD) | FD_CLOEXEC);
	}

	return ioctl_socket;
}

static int iface_ioctl(int cmd, void *ifr)
{
	int sock = iface_ioctl_socket();

	return ioctl(sock, cmd, ifr);
}

int iface_up(const char *ifname)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

	if (iface_ioctl(SIOCGIFFLAGS, &ifr))
		return 0;

	ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

	return !iface_ioctl(SIOCSIFFLAGS, &ifr);
}


