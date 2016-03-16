SUBDIRS = . tests

tangdir = @TANG_DB@
tang_DATA =

systemdsystemunit_DATA =
libexec_PROGRAMS =
EXTRA_DIST =
CLEANFILES =
AM_LDFLAGS = @libcrypto_LIBS@
AM_CFLAGS = @TANG_CFLAGS@ @libcrypto_CFLAGS@ @cryptsetup_CFLAGS@ -fPIC
LIBS = libcore.a

noinst_LIBRARIES = libcore.a libclt.a libsrv.a
libcore_a_SOURCES = core/asn1.c core/asn1.h core/conv.c core/conv.h core/pkt.c core/pkt.h core/list.c core/list.h
libclt_a_SOURCES = clt/adv.c clt/adv.h clt/rec.c clt/rec.h clt/msg.c clt/msg.h clt/skey.c clt/skey.h
libsrv_a_SOURCES = srv/adv.c srv/adv.h srv/db.c srv/db.h srv/rec.c srv/rec.h srv/srv.c srv/srv.h

bin_PROGRAMS = tang tang-key-gen tang-key-mod tang-key-send tang-key-groups
tang_key_send_LDADD = libsrv.a

if USE_SYSTEMD
if USE_LIBSYSTEMD
systemdsystemunit_DATA += tang-keyd.socket tang-keyd.service
EXTRA_DIST += tang-keyd.socket.in tang-keyd.service.in
CLEANFILES += tang-keyd.socket tang-keyd.service
libexec_PROGRAMS += tang-keyd
tang_keyd_LDADD = libsrv.a
endif
endif

if USE_CLEVIS
clevispin_PROGRAMS = tang.so
tang_so_SOURCES = clevis.c
tang_so_LDADD = libclt.a @clevis_LIBS@
tang_so_LDFLAGS = -shared -Wl,--version-script=clevis.sym
endif

if USE_CRYPTSETUP
noinst_LIBRARIES += libluks.a
libluks_a_SOURCES = luks/luks.c luks/luks.h luks/meta.c luks/meta.h luks/asn1.c luks/asn1.h

bin_PROGRAMS += tang-luks-bind tang-luks-list tang-luks-unbind
tang_luks_bind_LDADD = libclt.a libluks.a
tang_luks_bind_LDFLAGS = @cryptsetup_LIBS@ $(AM_LDFLAGS)
tang_luks_list_LDADD = libluks.a
tang_luks_list_LDFLAGS = @cryptsetup_LIBS@ $(AM_LDFLAGS)
tang_luks_unbind_LDADD = libluks.a
tang_luks_unbind_LDFLAGS = @cryptsetup_LIBS@ $(AM_LDFLAGS)

if USE_SYSTEMD
if USE_DRACUT
dracutmodules_SCRIPTS = module-setup.sh
EXTRA_DIST += module-setup.sh.in
CLEANFILES += module-setup.sh
endif

noinst_LIBRARIES += libaskpass.a
libaskpass_a_SOURCES = askpass/question.c askpass/question.h askpass/iface.c askpass/iface.h askpass/askp.c askpass/askp.h

systemdsystemunit_DATA += tang-luksd.path tang-luksd.service
EXTRA_DIST += tang-luksd.path.in tang-luksd.service.in
CLEANFILES += tang-luksd.path tang-luksd.service
libexec_PROGRAMS += tang-luksd
tang_luksd_LDADD = libaskpass.a libluks.a libclt.a
tang_luksd_LDFLAGS = @cryptsetup_LIBS@ $(AM_LDFLAGS)
endif
endif

%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		-e 's,@TANG_DB\@,$(TANG_DB),g' \
		-e 's,@TANG_PORT\@,$(TANG_PORT),g' \
		$(srcdir)/$@.in > $@

