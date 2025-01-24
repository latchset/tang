/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2022 Nikos Mavrogiannopoulos
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <errno.h>
#include <sys/wait.h>
#include <signal.h>

#include "socket.h"

#define MAX(x,y) ((x)>(y)?(x):(y))

typedef struct socket_list {
	int s;
	int family;
	struct sockaddr addr;
	struct socket_list *next;
} socket_list;

static void free_socket_list(socket_list *slist)
{
	socket_list *ptr, *oldptr;

	for (ptr = slist; ptr != NULL;) {
		if (ptr->s >= 0)
			close(ptr->s);
		oldptr = ptr;
		ptr = ptr->next;
		free(oldptr);
	}
}

static int listen_port(socket_list **slist, int port)
{
	struct addrinfo hints, *res, *ptr;
	int y, r, s;
	char portname[6], strip[64];
	socket_list *lm;

	snprintf(portname, sizeof(portname), "%d", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	*slist = NULL;

	/* listen to all available (IPv4 and IPv6) address */
	if ((r = getaddrinfo(NULL, portname, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo() failed: %s\n", gai_strerror(r));
		return -1;
	}

	for (ptr = res; ptr != NULL; ptr = ptr->ai_next) {
		s = socket(ptr->ai_family, SOCK_STREAM, 0);
		if (s < 0) {
			perror("socket() failed");
			continue;
		}

		if (ptr->ai_family == AF_INET)
			fprintf(stderr, "Listening on %s:%d\n", inet_ntop(ptr->ai_family,
				&((struct sockaddr_in*)ptr->ai_addr)->sin_addr, strip,
				sizeof(strip)), port);
		else if (ptr->ai_family == AF_INET6)
			fprintf(stderr, "Listening on [%s]:%d\n", inet_ntop(ptr->ai_family,
				&((struct sockaddr_in6*)ptr->ai_addr)->sin6_addr, strip,
				sizeof(strip)), port);

#if defined(IPV6_V6ONLY)
		if (ptr->ai_family == AF_INET6) {
			y = 1;
			/* avoid listen on ipv6 addresses failing
			 * because already listening on ipv4 addresses: */
			if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
				   (const void *) &y, sizeof(y)) < 0) {
				perror("setsockopt(IPV6_V6ONLY) failed");
			}
		}
#endif

		y = 1;
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
			       (const void *) &y, sizeof(y)) < 0) {
			perror("setsockopt(SO_REUSEADDR) failed");
		}

		if (bind(s, ptr->ai_addr, ptr->ai_addrlen) < 0) {
			perror("bind() failed");
			close(s);
			continue;
		}

		if (listen(s, 1024) < 0) {
			perror("listen() failed");
			close(s);
			r = -1;
			goto cleanup;
		}

		lm = calloc(1, sizeof(socket_list));
		if (lm == NULL) {
			close(s);
			r = -1;
			goto cleanup;
		}
		lm->s = s;
		lm->family = ptr->ai_family;
		memcpy(&lm->addr, ptr->ai_addr, sizeof(*ptr->ai_addr));
		lm->next = *slist;
		*slist = lm;
	}

	if (*slist == NULL)
		r = -1;
	else
		r = 0;

 cleanup:
	freeaddrinfo(res);
	fflush(stderr);

	return r;
}

static void spawn_process(int fd, const char *jwkdir,
			  process_request_func pfunc,
			  socket_list *slist)
{
	pid_t pid;
	socket_list *ptr;

	pid = fork();
	if (pid == 0) { /* child */
		for (ptr = slist; ptr != NULL; ptr = ptr->next) {
			close(ptr->s);
		}
		/* Ensure that both stdout and stdin are set */
		if (dup2(fd, STDOUT_FILENO) < 0) {
			perror("dup2");
			close(fd);
			return;
		}

		close(fd);

		pfunc(jwkdir, STDOUT_FILENO);
		free_socket_list(slist);
		exit(0);
	} else if (pid == -1) {
		perror("fork failed");
	}
	close(fd);
}

static void handle_child(int sig)
{
	int status;

	while ((waitpid(-1, &status, WNOHANG)) > 0);
}

int run_service(const char *jwkdir, int port, process_request_func pfunc)
{
	socket_list *slist, *ptr;
	int r, n = 0, accept_fd;
	fd_set read_fds;
	struct timeval tv;

	struct sigaction new_action;

	/* Set up the structure to specify the new action. */
	new_action.sa_handler = handle_child;
	sigemptyset (&new_action.sa_mask);
	new_action.sa_flags = 0;
	sigaction(SIGCHLD, &new_action, NULL);

	r = listen_port(&slist, port);
	if (r < 0) {
		fprintf(stderr, "Could not listen port (%d)\n", port);
		if (slist) {
			free_socket_list(slist);
		}
		return -1;
	}

	while (1) {
		FD_ZERO(&read_fds);
		for (ptr = slist; ptr != NULL; ptr = ptr->next) {
			if (ptr->s > FD_SETSIZE) {
				fprintf(stderr, "exceeded FD_SETSIZE\n");
				free_socket_list(slist);
				return -1;
			}
			FD_SET(ptr->s, &read_fds);
			n = MAX(n, ptr->s);
		}
		tv.tv_sec = 1200;
		tv.tv_usec = 0;
		n = select(n+1, &read_fds, NULL, NULL, &tv);
		if (n == -1 && errno == EINTR)
			continue;
		if (n < 0) {
			perror("select");
			free_socket_list(slist);
			return -1;
		}

		for (ptr = slist; ptr != NULL; ptr = ptr->next) {
			if (FD_ISSET(ptr->s, &read_fds)) {
				accept_fd = accept(ptr->s, NULL, 0);
				if (accept_fd < 0) {
					perror("accept");
					continue;
				}

				spawn_process(accept_fd, jwkdir, pfunc, slist);
			}
		}

	}

	return 0;
}
