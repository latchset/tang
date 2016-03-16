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

#include <errno.h>
#include <error.h>

#include <systemd/sd-bus.h>
#include <libcryptsetup.h>

struct dev {
    list_t list;
    bool encrypted;
    char object[PATH_MAX];
    char Device[PATH_MAX];
    char CryptoBackingDevice[PATH_MAX];
};

static list_t devs = LIST_INIT(devs);

static bool
is_unlocked(const char *obj)
{
    LIST_FOREACH(&devs, struct dev, d, list) {
        if (strcmp(obj, d->CryptoBackingDevice) == 0)
            return true;
    }

    return false;
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
    params->listen = tl->listen != 0;

    return true;
}

static skey_t *
get_key(TANG_LUKS *tl)
{
    EC_KEY *eckey = NULL;
    TANG_MSG *msg = NULL;
    skey_t *skey = NULL;
    BN_CTX *ctx = NULL;
    msg_t p = {};

    ctx = BN_CTX_new();
    if (!ctx)
        goto error;

    eckey = rec_req(tl->rec, ctx);
    if (!eckey)
        goto error;

    if (!TANG_LUKS_get_params(tl, &p))
        goto error;

    msg = msg_rqst(&p, &(TANG_MSG) {
        .type = TANG_MSG_TYPE_REC_REQ,
        .val.rec.req = tl->rec
    });

    if (!msg || msg->type != TANG_MSG_TYPE_REC_REP) {
        fprintf(stderr, "Unable to contact %s (%s)\n", p.hostname, p.service);
        goto error;
    }

    skey = rec_rep(msg->val.rec.rep, eckey, ctx);

error:
    EC_KEY_free(eckey);
    TANG_MSG_free(msg);
    BN_CTX_free(ctx);
    return skey;
}

static struct crypt_device *
opendev(const char *dev)
{
    struct crypt_device *cd = NULL;
    const char *type = NULL;
    int r = 0;

    r = crypt_init(&cd, dev);
    if (r != 0) {
        fprintf(stderr, "Unable to open device (%s): %s\n", dev, strerror(-r));
        goto error;
    }

    r = crypt_load(cd, NULL, NULL);
    if (r != 0) {
        fprintf(stderr, "Unable to load device (%s): %s\n", dev, strerror(-r));
        goto error;
    }

    type = crypt_get_type(cd);
    if (type == NULL) {
        fprintf(stderr, "Unable to determine device type\n");
        goto error;
    }

    if (strcmp(type, CRYPT_LUKS1) != 0) {
        fprintf(stderr, "%s (%s) is not a LUKS device\n", dev, type);
        goto error;
    }

    return cd;

error:
    crypt_free(cd);
    return NULL;
}

static int
unlock(sd_bus *bus, struct dev *d, struct crypt_device *cd, int slot)
{
    TANG_LUKS *tl = NULL;
    uint8_t *data = NULL;
    skey_t *skey = NULL;
    skey_t *hex = NULL;
    size_t size = 0;
    int r;

    fprintf(stderr, "%s\tSLOT\t%s (%d)\n", d->object, d->Device, slot);

    switch (crypt_keyslot_status(cd, slot)) {
    case CRYPT_SLOT_ACTIVE:
    case CRYPT_SLOT_ACTIVE_LAST:
        break;

    default:
        return -ENOENT;
    }

    data = meta_read(d->Device, slot, &size);
    fprintf(stderr, "%s\tMETA\t%s\n", d->object, data ? "success" : "failure");
    if (!data)
        return -ENOENT;

    tl = d2i_TANG_LUKS(NULL, &(const uint8_t *) { data }, size);
    free(data);
    if (!tl) {
        fprintf(stderr, "Error parsing metadata from %s (%d)\n",
                d->Device, slot);
        return -EINVAL;
    }

    skey = get_key(tl);
    fprintf(stderr, "%s\tTANG\t%s\n", d->object, skey ? "success" : "failure");
    TANG_LUKS_free(tl);
    if (!skey)
        return -EIO;

    hex = skey_new(skey->size * 2 + 1);
    if (!hex) {
        skey_free(skey);
        return -ENOMEM;
    }

    for (size_t i = 0; i < skey->size; i++)
        snprintf((char *) &hex->data[i * 2], 3, "%02X", skey->data[i]);
    skey_free(skey);

    r = sd_bus_call_method(bus, "org.freedesktop.UDisks2", d->object,
                           "org.freedesktop.UDisks2.Encrypted",
                           "Unlock", NULL, NULL,
                           "sa{sv}", hex->data, 0);
    skey_free(hex);
    fprintf(stderr, "%s\tCALL\t%s\n", d->object,
            r < 0 ? "failure" : "success");
    return r;
}

static void
process(sd_bus *bus)
{
    LIST_FOREACH(&devs, struct dev, d, list) {
        struct crypt_device *cd = NULL;

        if (!d->encrypted || is_unlocked(d->object))
            continue;

        cd = opendev(d->Device);
        if (!cd)
            continue;

        for (int slot = 0; slot < crypt_keyslot_max(CRYPT_LUKS1); slot++) {
            if (unlock(bus, d, cd, slot) >= 0)
                break;
        }

        crypt_free(cd);
    }
}

static int
on_iface_rem(sd_bus_message *m, void *bus, sd_bus_error *ret_error)
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
            LIST_FOREACH(&devs, struct dev, d, list) {
                if (strcmp(obj, d->object) != 0)
                    continue;

                fprintf(stderr, "%s\tIREM\t%s\n", d->object, i);
                d->encrypted = false;
            }
        } else if (strcmp(i, "org.freedesktop.UDisks2.Block") == 0) {
            LIST_FOREACH(&devs, struct dev, d, list) {
                if (strcmp(obj, d->object) != 0)
                    continue;

                fprintf(stderr, "%s\tIREM\t%s\n", d->object, i);
                list_pop(&d->list);
                free(d);
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
parse_Device(sd_bus_message *m, const char **out)
{
    size_t size = 0;
    int r = 0;

    r = sd_bus_message_enter_container(m, 'v', "ay");
    if (r < 0)
        return r;

    r = sd_bus_message_read_array(m, 'y', (const void **) out, &size);
    if (r < 0)
        return r;

    return sd_bus_message_exit_container(m);
}

static int
parse_CryptoBackingDevice(sd_bus_message *m, const char **out)
{
    int r = 0;

    r = sd_bus_message_enter_container(m, 'v', "o");
    if (r < 0)
        return r;

    r = sd_bus_message_read(m, "o", out);
    if (r < 0)
        return r;

    return sd_bus_message_exit_container(m);
}

static int
parse_iface(sd_bus_message *m, const char *obj, bool *enc,
            const char **dev, const char **cbd)
{
    const char *iface = NULL;
    int r = 0;

    r = sd_bus_message_read(m, "s", &iface);
    if (r < 0)
        return r;

    if (strcmp(iface, "org.freedesktop.UDisks2.Encrypted") == 0) {
        fprintf(stderr, "%s\tIADD\t%s\n", obj, iface);
        *enc = true;
    }

    if (strcmp(iface, "org.freedesktop.UDisks2.Block") != 0)
        return sd_bus_message_skip(m, "a{sv}");

    fprintf(stderr, "%s\tIADD\t%s\n", obj, iface);

    r = sd_bus_message_enter_container(m, 'a', "{sv}");
    if (r < 0)
        return r;

    while ((r = sd_bus_message_enter_container(m, 'e', "sv")) > 0) {
        const char *name = NULL;

        r = sd_bus_message_read(m, "s", &name);
        if (r < 0)
            return r;

        if (strcmp(name, "Device") == 0)
            r = parse_Device(m, dev);
        else if (strcmp(name, "CryptoBackingDevice") == 0)
            r = parse_CryptoBackingDevice(m, cbd);
        else
            r = sd_bus_message_skip(m, "v");
        if (r < 0)
            return r;

        r = sd_bus_message_exit_container(m);
        if (r < 0)
            return r;
    }
    if (r < 0)
        return r;

    return sd_bus_message_exit_container(m);
}

static int
on_iface_add(sd_bus_message *m, void *bus, sd_bus_error *ret_error)
{
    const char *obj = NULL;
    const char *dev = NULL;
    const char *cbd = NULL;
    struct dev *d = NULL;
    bool enc = false;
    int r;

    r = sd_bus_message_has_signature(m, "oa{sa{sv}}");
    if (r < 0)
        return r;

    r = sd_bus_message_read(m, "o", &obj);
    if (r < 0)
        return r;

    r = sd_bus_message_enter_container(m, 'a', "{sa{sv}}");
    if (r < 0)
        return r;

    while ((r = sd_bus_message_enter_container(m, 'e', "sa{sv}")) > 0) {
        r = parse_iface(m, obj, &enc, &dev, &cbd);
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

    if (!obj || strlen(obj) >= PATH_MAX)
        return 0;

    if (!dev || strlen(dev) >= PATH_MAX)
        return 0;

    if (!cbd || strlen(cbd) >= PATH_MAX)
        return 0;

    d = calloc(1, sizeof(struct dev));
    if (!d)
        return -ENOMEM;

    d->encrypted = enc;
    strcpy(d->object, obj);
    strcpy(d->Device, dev);
    strcpy(d->CryptoBackingDevice, cbd);
    list_add_after(&devs, &d->list);
    return 0;
}

static void
on_signal(int sig)
{

}

int
main(int argc, char *argv[])
{
    sd_bus_message *msg = NULL;
    sd_bus *bus = NULL;
    int r;

    signal(SIGHUP, on_signal);
    signal(SIGINT, on_signal);
    signal(SIGPIPE, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGUSR1, on_signal);
    signal(SIGUSR2, on_signal);

    r = sd_bus_open_system(&bus);
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error connecting to system bus");

    r = sd_bus_add_match(bus, NULL,
                         "type='signal',"
                         "sender='org.freedesktop.UDisks2',"
                         "path='/org/freedesktop/UDisks2',"
                         "member='InterfacesRemoved',"
                         "interface='org.freedesktop.DBus.ObjectManager'",
                         on_iface_rem, bus);
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error registering for interfaces");

    r = sd_bus_add_match(bus, NULL,
                         "type='signal',"
                         "sender='org.freedesktop.UDisks2',"
                         "path='/org/freedesktop/UDisks2',"
                         "member='InterfacesAdded',"
                         "interface='org.freedesktop.DBus.ObjectManager'",
                         on_iface_add, bus);
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error registering for interfaces");

    r = sd_bus_call_method(bus, "org.freedesktop.UDisks2",
                           "/org/freedesktop/UDisks2",
                           "org.freedesktop.DBus.ObjectManager",
                           "GetManagedObjects", NULL, &msg, "");
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error calling ObjectManager");

    r = sd_bus_message_enter_container(msg, 'a', "{oa{sa{sv}}}");
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error parsing results");

    while ((r = sd_bus_message_enter_container(msg, 'e', "oa{sa{sv}}")) > 0) {
        r = on_iface_add(msg, bus, NULL);
        if (r < 0)
            error(EXIT_FAILURE, -r, "Error parsing results");

        r = sd_bus_message_exit_container(msg);
        if (r < 0)
            error(EXIT_FAILURE, -r, "Error parsing results");
    }
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error parsing results");

    r = sd_bus_message_exit_container(msg);
    if (r < 0)
        error(EXIT_FAILURE, -r, "Error parsing results");

    process(bus);

    while ((r = sd_bus_wait(bus, (uint64_t) -1)) >= 0) {
        while ((r = sd_bus_process(bus, NULL)) > 0)
            continue;
        if (r < 0)
            error(EXIT_FAILURE, -r, "Error processing bus");

        process(bus);
    }
    if (r < 0 && r != -EINTR)
        error(EXIT_FAILURE, -r, "Error waiting on bus");

    LIST_FOREACH(&devs, struct dev, d, list)
        free(d);

    sd_bus_message_unref(msg);
    sd_bus_unref(bus);
    return EXIT_SUCCESS;
}
