SUBDIRS = . tests

AM_CFLAGS = @LIBCRYPTO_CFLAGS@ @CRYPTSETUP_CFLAGS@ -fPIC
AM_LDFLAGS = @LIBCRYPTO_LIBS@
LIBS = libcore.a

noinst_LIBRARIES = libcore.a libclt.a libluks.a libsrv.a libaskpass.a
libcore_a_SOURCES = core/asn1.c core/asn1.h core/conv.c core/conv.h core/pkt.c core/pkt.h core/list.c core/list.h
libclt_a_SOURCES = clt/adv.c clt/adv.h clt/rec.c clt/rec.h clt/msg.c clt/msg.h clt/skey.c clt/skey.h
libluks_a_SOURCES = luks/luks.c luks/luks.h luks/meta.c luks/meta.h luks/asn1.c luks/asn1.h
libsrv_a_SOURCES = srv/adv.c srv/adv.h srv/db.c srv/db.h srv/rec.c srv/rec.h srv/srv.c srv/srv.h
libaskpass_a_SOURCES = askpass/question.c askpass/question.h askpass/iface.c askpass/iface.h askpass/askp.c askpass/askp.h

if USE_CLEVIS
clevispin_PROGRAMS = tang.so
tang_so_SOURCES = clevis.c
tang_so_LDADD = libclt.a @clevis_LIBS@
tang_so_LDFLAGS = -shared -Wl,--version-script=clevis.sym
endif

bin_PROGRAMS = tang tang-luks-bind tang-luks-list tang-luks-unbind tang-key-gen tang-key-mod tang-key-send tang-key-groups
tang_luks_bind_LDADD = libclt.a libluks.a
tang_luks_bind_LDFLAGS = @CRYPTSETUP_LIBS@ $(AM_LDFLAGS)
tang_luks_list_LDADD = libluks.a
tang_luks_list_LDFLAGS = @CRYPTSETUP_LIBS@ $(AM_LDFLAGS)
tang_luks_unbind_LDADD = libluks.a
tang_luks_unbind_LDFLAGS = @CRYPTSETUP_LIBS@ $(AM_LDFLAGS)
tang_key_send_LDADD = libsrv.a

libexec_PROGRAMS = tang-keyd tang-luksd
tang_keyd_LDADD = libsrv.a
tang_luksd_LDADD = libaskpass.a libluks.a libclt.a
tang_luksd_LDFLAGS = @CRYPTSETUP_LIBS@ $(AM_LDFLAGS)

