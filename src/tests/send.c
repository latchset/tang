/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
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

#include <netinet/in.h>

#include <errno.h>
#include <error.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>

#include <openssl/evp.h>

#define BIN "../tang-key-send"
#define _str(x) # x
#define str(x) _str(x)

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
    struct sockaddr_in bsa = {};
    struct sockaddr sa = {};
    socklen_t slen = sizeof(sa);
    uint16_t port = 0;
    char svc[64];
    int lsock;
    int asock;

    OpenSSL_add_all_algorithms();

    srand(time(NULL));
    port = 1024 + rand() % (UINT16_MAX - 1024);
    snprintf(svc, sizeof(svc), "%u", port);

    lsock = socket(AF_INET, SOCK_STREAM, 0);
    if (lsock < 0)
        error(EXIT_FAILURE, errno, "Error calling socket()");

    bsa.sin_family = AF_INET;
    bsa.sin_port = htons(port);
    bsa.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(lsock, (struct sockaddr *) &bsa, sizeof(sa)) < 0)
        error(EXIT_FAILURE, errno, "Error calling bind()");

    if (listen(lsock, 1) < 0)
        error(EXIT_FAILURE, errno, "Error calling listen()");

    if (!mkdtemp(tempdir))
        error(EXIT_FAILURE, errno, "Error calling mkdtemp()");

    pid = fork();
    if (pid < 0) {
        error(EXIT_FAILURE, errno, "Error calling fork()");
        rmdir(tempdir);
    }

    if (pid == 0) {
        close(lsock);
        execlp(BIN, BIN, "-d", tempdir, "localhost", svc, NULL);
        exit(EXIT_FAILURE);
    }

    atexit(onexit);

    asock = accept(lsock, &sa, &slen);
    if (asock < 0)
        error(EXIT_FAILURE, errno, "Error calling accept()");

    close(lsock);
    client_checks(asock, tempdir);
    close(asock);

    EVP_cleanup();
    return 0;
}
