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

#include "core/list.h"
#include "clt/msg.h"
#include "clt/rec.h"
#include "luks/asn1.h"
#include "luks/meta.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <errno.h>
#include <error.h>
#include <ctype.h>
#include <sysexits.h>

#include <systemd/sd-bus.h>
#include <libcryptsetup.h>

#define MAX_UDP 65535

struct encrypted {
    list_t list;
    char path[PATH_MAX];
};

struct blockdev {
    list_t list;
    char path[PATH_MAX];

    bool disabled;
    bool HintAuto;
    char Device[PATH_MAX];
    char CryptoBackingDevice[PATH_MAX];
};

static list_t encrypteds = LIST_INIT(encrypteds);
static list_t blockdevs = LIST_INIT(blockdevs);

static void
disable(const char *path)
{
    LIST_FOREACH(&blockdevs, struct blockdev, bd, list) {
        if (strcmp(bd->path, path) == 0)
            bd->disabled = true;
    }
}

static bool
is_locked(const char *obj)
{
    LIST_FOREACH(&blockdevs, struct blockdev, bd, list) {
        if (strcmp(obj, bd->CryptoBackingDevice) == 0)
            return false;
    }

    return true;
}

static bool
TANG_LUKS_get_params(const TANG_LUKS *tl, msg_t *params)
{
    if (!tl || !tl->hostname || !tl->service)
        return false;

    if (tl->hostname->length >= (int) sizeof(params->hostname))
        return false;

    if (tl->service->length >= (int) sizeof(params->service))
        return false;

    strncpy(params->hostname, (char *) tl->hostname->data,
            tl->hostname->length);
    strncpy(params->service, (char *) tl->service->data,
            tl->service->length);

    return true;
}

static skey_t *
get_key(const msg_t *params, TANG_MSG_REC_REQ *req)
{
    EC_KEY *eckey = NULL;
    TANG_MSG *msg = NULL;
    skey_t *skey = NULL;
    BN_CTX *ctx = NULL;

    ctx = BN_CTX_new();
    if (!ctx)
        goto error;

    eckey = rec_req(req, ctx);
    if (!eckey)
        goto error;

    msg = msg_rqst(params, &(TANG_MSG) {
        .type = TANG_MSG_TYPE_REC_REQ,
        .val.rec.req = req
    });

    if (!msg || msg->type != TANG_MSG_TYPE_REC_REP)
        goto error;

    skey = rec_rep(msg->val.rec.rep, eckey, ctx);

error:
    EC_KEY_free(eckey);
    TANG_MSG_free(msg);
    BN_CTX_free(ctx);
    return skey;
}

static int
on_iface_rem(sd_bus_message *m, void *misc, sd_bus_error *ret_error)
{
    const char *obj = NULL;
    int r;

    r = sd_bus_message_has_signature(m, "oas");
    if (r < 0)
        return r;

    r = sd_bus_message_read(m, "o", &obj);
    if (r < 0)
    return r;

    r = sd_bus_message_enter_container(m, 'a', "s");
    if (r < 0)
        return r;

    for (const char *i = NULL; (r = sd_bus_message_read(m, "s", &i)) > 0; ) {
        if (strcmp(i, "org.freedesktop.UDisks2.Encrypted") == 0) {
            LIST_FOREACH(&encrypteds, struct encrypted, e, list) {
                if (strcmp(obj, e->path) != 0)
                    continue;

                list_pop(&e->list);
                free(e);
            }
        } else if (strcmp(i, "org.freedesktop.UDisks2.Block") == 0) {
            LIST_FOREACH(&blockdevs, struct blockdev, bd, list) {
                if (strcmp(obj, bd->path) != 0)
                    continue;

                disable(bd->CryptoBackingDevice);

                list_pop(&bd->list);
                free(bd);
            }
        }
    }
    if (r < 0)
        return r;

    r = sd_bus_message_exit_container(m);
    if (r < 0)
        return r;

    return 0;
}

static int
parse_Device(sd_bus_message *m, struct blockdev *bd)
{
    const void *out = NULL;
    size_t size = 0;
    int r = 0;

    r = sd_bus_message_enter_container(m, 'v', "ay");
    if (r < 0)
        return r;

    r = sd_bus_message_read_array(m, 'y', &out, &size);
    if (r < 0)
        return r;

    if (size > sizeof(bd->Device))
        return -E2BIG;

    memcpy(bd->Device, out, size);
    bd->Device[size] = '\0';

    return sd_bus_message_exit_container(m);
}

static int
parse_HintAuto(sd_bus_message *m, struct blockdev *bd)
{
    int HintAuto = 0;
    int r = 0;

    r = sd_bus_message_enter_container(m, 'v', "b");
    if (r < 0)
        return r;

    r = sd_bus_message_read_basic(m, 'b', &HintAuto);
    if (r < 0)
        return r;

    bd->HintAuto = HintAuto;
    return sd_bus_message_exit_container(m);
}

static int
parse_CryptoBackingDevice(sd_bus_message *m, struct blockdev *bd)
{
    const char *out = NULL;
    int r = 0;

    r = sd_bus_message_enter_container(m, 'v', "o");
    if (r < 0)
        return r;

    r = sd_bus_message_read(m, "o", &out);
    if (r < 0)
        return r;

    if (strlen(out) >= sizeof(bd->CryptoBackingDevice))
        return -E2BIG;

    strcpy(bd->CryptoBackingDevice, out);
    return sd_bus_message_exit_container(m);
}

static int
parse_Encrypted(sd_bus_message *m, const char *obj)
{
    struct encrypted *enc = NULL;

    LIST_FOREACH(&encrypteds, struct encrypted, e, list) {
        if (strcmp(e->path, obj) == 0)
            return 0;
    }

    enc = calloc(1, sizeof(*enc));
    if (!enc)
        return -errno;

    if (strlen(obj) >= sizeof(enc->path)) {
        free(enc);
        return -E2BIG;
    }

    strcpy(enc->path, obj);
    list_add_after(&encrypteds, &enc->list);

    return sd_bus_message_skip(m, "a{sv}");
}

static int
parse_Block(sd_bus_message *m, const char *obj)
{
    struct blockdev *bd = NULL;
    int r;

    LIST_FOREACH(&blockdevs, struct blockdev, b, list) {
        if (strcmp(b->path, obj) == 0)
            return 0;
    }

    bd = calloc(1, sizeof(*bd));
    if (!bd)
        return -errno;

    if (strlen(obj) >= sizeof(bd->path)) {
        free(bd);
        return -E2BIG;
    }

    strcpy(bd->path, obj);

    r = sd_bus_message_enter_container(m, 'a', "{sv}");
    if (r < 0)
        goto error;

    while ((r = sd_bus_message_enter_container(m, 'e', "sv")) > 0) {
        const char *name = NULL;

        r = sd_bus_message_read(m, "s", &name);
        if (r < 0)
            goto error;

        if (strcmp(name, "Device") == 0)
            r = parse_Device(m, bd);
        else if (strcmp(name, "HintAuto") == 0)
            r = parse_HintAuto(m, bd);
        else if (strcmp(name, "CryptoBackingDevice") == 0)
            r = parse_CryptoBackingDevice(m, bd);
        else
            r = sd_bus_message_skip(m, "v");
        if (r < 0)
            goto error;

        r = sd_bus_message_exit_container(m);
        if (r < 0)
            goto error;
    }
    if (r < 0)
        goto error;

    r = sd_bus_message_exit_container(m);
    if (r < 0)
        goto error;

    list_add_after(&blockdevs, &bd->list);
    return r;

error:
    free(bd);
    return r;
}

static int
on_iface_add(sd_bus_message *m, void *misc, sd_bus_error *ret_error)
{
    const char *obj = NULL;
    int r;

    r = sd_bus_message_has_signature(m, "oa{sa{sv}}");
    if (r < 0)
        return r;

    r = sd_bus_message_read(m, "o", &obj);
    if (r < 0)
        return r;

    if (strlen(obj) >= PATH_MAX)
        return -E2BIG;

    r = sd_bus_message_enter_container(m, 'a', "{sa{sv}}");
    if (r < 0)
        return r;

    while ((r = sd_bus_message_enter_container(m, 'e', "sa{sv}")) > 0) {
        const char *iface = NULL;

        r = sd_bus_message_read(m, "s", &iface);
        if (r < 0)
            return r;


        if (strcmp(iface, "org.freedesktop.UDisks2.Encrypted") == 0) {
            r = parse_Encrypted(m, obj);
        } else if (strcmp(iface, "org.freedesktop.UDisks2.Block") == 0) {
            r = parse_Block(m, obj);
        } else {
            r = sd_bus_message_skip(m, "a{sv}");
        }
        if (r < 0)
            return r;

        r = sd_bus_message_exit_container(m);
        if (r < 0)
            return r;
    }
    if (r < 0)
        return r;

    r = sd_bus_message_exit_container(m);
    if (r < 0)
        return r;

    return 0;
}

static int
process(sd_bus *bus, struct blockdev *bd, int sock)
{
    bool enc = false;

    LIST_FOREACH(&encrypteds, struct encrypted, e, list)
        enc |= strcmp(e->path, bd->path) == 0;

    if (!bd->HintAuto || bd->disabled || !enc || !is_locked(bd->path))
        return 0;

    for (int slot = 0; slot < crypt_keyslot_max(CRYPT_LUKS1); slot++) {
        ssize_t len = strlen(bd->Device) + 2;
        uint8_t buf[MAX_UDP] = {};
        TANG_LUKS *tl = NULL;
        skey_t *skey = NULL;
        skey_t *hex = NULL;
        msg_t params = {};
        int r = 0;

        buf[0] = slot;
        memcpy(&buf[1], bd->Device, len - 1);

        fprintf(stderr, "%s\tSLOT\t%d\n", bd->path, slot);

        errno = 0;
        if (send(sock, buf, len, 0) != len)
            return errno != 0 ? -errno : -EIO;

        len = recv(sock, buf, sizeof(buf), 0);
        if (len < 0)
            return -errno;

        fprintf(stderr, "%s\tMETA\t%d\n", bd->path, (int) len);

        tl = d2i_TANG_LUKS(NULL, &(const uint8_t *) { buf }, len);
        if (!tl)
            continue;

        if (!TANG_LUKS_get_params(tl, &params)) {
            TANG_LUKS_free(tl);
            continue;
        }
        fprintf(stderr, "%s\tDATA\t%s (%s)\n",
                bd->path, params.hostname, params.service);

        skey = get_key(&params, tl->rec);
        TANG_LUKS_free(tl);
        fprintf(stderr, "%s\tTREC\t%s\n", bd->path,
                skey ? "success" : "failure");
        if (!skey)
            continue;

        hex = skey_new(skey->size * 2 + 1);
        if (!hex) {
            skey_free(skey);
            continue;
        }

        for (size_t i = 0; i < skey->size; i++)
            snprintf((char *) &hex->data[i * 2], 3, "%02X", skey->data[i]);
        skey_free(skey);

        r = sd_bus_call_method(bus, "org.freedesktop.UDisks2", bd->path,
                               "org.freedesktop.UDisks2.Encrypted", "Unlock",
                               NULL, NULL, "sa{sv}", hex->data, 0);
        skey_free(hex);
        if (r >= 0)
            break;
    }

    return 0;
}

static int
call_GetManagedObjects(sd_bus *bus)
{
    sd_bus_message *msg = NULL;
    int r = 0;

    r = sd_bus_call_method(bus, "org.freedesktop.UDisks2",
                           "/org/freedesktop/UDisks2",
                           "org.freedesktop.DBus.ObjectManager",
                           "GetManagedObjects", NULL, &msg, "");
    if (r < 0)
        goto error;

    r = sd_bus_message_enter_container(msg, 'a', "{oa{sa{sv}}}");
    if (r < 0)
        goto error;

    while ((r = sd_bus_message_enter_container(msg, 'e', "oa{sa{sv}}")) > 0) {
        r = on_iface_add(msg, bus, NULL);
        if (r < 0)
            goto error;

        r = sd_bus_message_exit_container(msg);
        if (r < 0)
            goto error;
    }
    if (r < 0)
        goto error;

    r = sd_bus_message_exit_container(msg);
    if (r < 0)
        goto error;

error:
    sd_bus_message_unref(msg);
    return r;
}

static int
child_main(int sock)
{
    sd_bus_slot *slot_rem = NULL;
    sd_bus_slot *slot_add = NULL;
    sd_bus *bus = NULL;
    int r;

    r = sd_bus_open_system(&bus);
    if (r < 0)
        goto error;

    r = sd_bus_add_object_manager(bus, NULL, "/");
    if (r < 0)
        goto error;

    r = sd_bus_add_match(bus, &slot_rem,
                         "type='signal',"
                         "sender='org.freedesktop.UDisks2',"
                         "path='/org/freedesktop/UDisks2',"
                         "member='InterfacesRemoved',"
                         "interface='org.freedesktop.DBus.ObjectManager'",
                         on_iface_rem, NULL);
    if (r < 0)
        goto error;

    r = sd_bus_add_match(bus, &slot_add,
                         "type='signal',"
                         "sender='org.freedesktop.UDisks2',"
                         "path='/org/freedesktop/UDisks2',"
                         "member='InterfacesAdded',"
                         "interface='org.freedesktop.DBus.ObjectManager'",
                         on_iface_add, NULL);
    if (r < 0)
        goto error;

    r = call_GetManagedObjects(bus);
    if (r < 0)
        goto error;

    LIST_FOREACH(&blockdevs, struct blockdev, bd, list) {
        r = process(bus, bd, sock);
        if (r < 0)
            goto error;
    }

    while ((r = sd_bus_wait(bus, (uint64_t) -1)) >= 0) {
        while ((r = sd_bus_process(bus, NULL)) > 0)
            continue;
        if (r < 0)
            goto error;

        LIST_FOREACH(&blockdevs, struct blockdev, bd, list) {
            r = process(bus, bd, sock);
            if (r < 0)
                goto error;
        }
    }

    LIST_FOREACH(&encrypteds, struct encrypted, e, list)
        free(e);
    LIST_FOREACH(&blockdevs, struct blockdev, bd, list)
        free(bd);

error:
    sd_bus_slot_unref(slot_rem);
    sd_bus_slot_unref(slot_add);
    sd_bus_unref(bus);
    close(sock);
    return (r < 0 && r != -EINTR) ? EXIT_FAILURE : EXIT_SUCCESS;
}

/*
 * ==========================================================================
 *           Caution, code below this point runs with euid = 0!
 * ==========================================================================
 */

static uint8_t *
readmeta(const char *dev, int slot, size_t *size)
{
    struct crypt_device *cd = NULL;
    uint8_t *data = NULL;
    int r = 0;

    if (slot >= crypt_keyslot_max(CRYPT_LUKS1))
        return NULL;

    r = crypt_init(&cd, dev);
    if (r != 0)
        goto error;

    r = crypt_load(cd, NULL, NULL);
    if (r != 0)
        goto error;

    switch (crypt_keyslot_status(cd, slot)) {
    case CRYPT_SLOT_ACTIVE:
    case CRYPT_SLOT_ACTIVE_LAST:
        break;

    default:
        goto error;
    }

    data = meta_read(dev, slot, size);

error:
    crypt_free(cd);
    return data;
}

static int pair[2] = { -1, -1 };

static void
safeclose(int *fd)
{
    if (*fd >= 0)
        close(*fd);
    *fd = -1;
}

static void
on_signal(int sig)
{
    safeclose(&pair[0]);
    safeclose(&pair[1]);
}

int
main(int argc, char *argv[])
{
    pid_t pid = 0;

    signal(SIGHUP, on_signal);
    signal(SIGINT, on_signal);
    signal(SIGPIPE, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGUSR1, on_signal);
    signal(SIGUSR2, on_signal);
    signal(SIGCHLD, on_signal);

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == -1)
        error(EX_OSERR, errno, "Unable to create socket pair");

    pid = fork();
    if (pid < 0) {
        safeclose(&pair[0]);
        safeclose(&pair[1]);
        error(EX_OSERR, errno, "Unable to fork");
    }

    if (pid == 0) {
        int status = EX_OSERR;

        safeclose(&pair[0]);

        if (seteuid(getuid()) == 0)
            status = child_main(pair[1]);

        safeclose(&pair[1]);
        return status;
    }

    if (setuid(geteuid()) == -1)
        goto error;

    safeclose(&pair[1]);

    char buf[MAX_UDP] = {};
    ssize_t len = 0;

    while (true) {
        uint8_t *data = NULL;
        size_t size = 0;

        len = recv(pair[0], buf, sizeof(buf), 0);
        if (len < 2)
            goto error;

        data = readmeta(&buf[1], buf[0], &size);
        if (data) {
            len = 0;
            if (size < sizeof(buf))
                len = send(pair[0], data, size, 0);

            free(data);
            if (len > 0)
                continue;
        }

        if (send(pair[0], "", 0, 0) != 0)
            goto error;
    }

error:
    safeclose(&pair[0]);
    memset(buf, 0, sizeof(buf));

    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);
    return EXIT_FAILURE;
}
