/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab: */
/*
 * Copyright (c) 2015 Red Hat, Inc.
 * Author: Nathaniel McCallum <npmccallum@redhat.com>
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

#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/wait.h>

#include <errno.h>
#include <error.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>

#include <openssl/evp.h>

#define BIN "../progs/tang-serve"

void
client_checks(int sock, const char *dbdir);

static char tempdir[] = "/var/tmp/tmpXXXXXX";
static pid_t pid;

static void
onexit(void)
{
    const char *cmd = "rm -rf ";
    char tmp[strlen(cmd) + strlen(tempdir) + 1];

    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);

    strcpy(tmp, cmd);
    strcat(tmp, tempdir);
    system(tmp);
}

int
main(int argc, char *argv[])
{
    int socks[2];

    OpenSSL_add_all_algorithms();

    if (!mkdtemp(tempdir))
        error(EXIT_FAILURE, errno, "Error calling mkdtemp()");

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks) != 0)
        error(EXIT_FAILURE, errno, "Error calling socketpair()");

    pid = fork();
    if (pid < 0)
        error(EXIT_FAILURE, errno, "Error calling mkdtemp()");

    if (pid == 0) {
        close(socks[0]);
        dup2(socks[1], 3);
        close(socks[1]);
        setenv("LISTEN_FDS", "1", true);
        execlp(BIN, BIN, "-d", tempdir, NULL);
        exit(EXIT_FAILURE);
    }

    close(socks[1]);
    atexit(onexit);

    client_checks(socks[0], tempdir);

    close(socks[0]);
    EVP_cleanup();
    return 0;
}
