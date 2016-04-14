SUBDIRS = . tests

tangdir = $(localstatedir)/$(PACKAGE_NAME)
tang_DATA =

libexec_PROGRAMS =
EXTRA_DIST =
CLEANFILES =
AM_CFLAGS = @TANG_CFLAGS@ @libcrypto_CFLAGS@ @cryptsetup_CFLAGS@ @udisks2_CFLAGS@ @storaged_CFLAGS@-fPIC -DTANG_DB=\"$(tangdir)\"
LIBS = libcore.a @libcrypto_LIBS@

noinst_LIBRARIES = libcore.a libclt.a libsrv.a
libcore_a_SOURCES = core/asn1.c core/asn1.h core/conv.c core/conv.h core/pkt.c core/pkt.h core/list.c core/list.h
libclt_a_SOURCES = clt/adv.c clt/adv.h clt/rec.c clt/rec.h clt/msg.c clt/msg.h clt/skey.c clt/skey.h
libsrv_a_SOURCES = srv/adv.c srv/adv.h srv/db.c srv/db.h srv/rec.c srv/rec.h srv/srv.c srv/srv.h

bin_PROGRAMS = tang tang-key-gen tang-key-mod tang-key-groups

systemdsystemunit_DATA = tang-keyd.socket tang-keyd.service
EXTRA_DIST += tang-keyd.socket.in tang-keyd.service.in
CLEANFILES += tang-keyd.socket tang-keyd.service
libexec_PROGRAMS += tang-keyd
tang_keyd_LDADD = libsrv.a $(LIBS)

if USE_CLEVIS
clevispin_PROGRAMS = tang.so
tang_so_SOURCES = clevis.c
tang_so_LDADD = libclt.a @clevis_LIBS@ $(LIBS)
tang_so_LDFLAGS = -shared -Wl,--version-script=clevis.sym
endif

if USE_CRYPTSETUP
noinst_LIBRARIES += libluks.a
libluks_a_SOURCES = luks/luks.c luks/luks.h luks/meta.c luks/meta.h luks/asn1.c luks/asn1.h

bin_PROGRAMS += tang-luks-bind tang-luks-list tang-luks-unbind
tang_luks_bind_LDADD = libclt.a libluks.a @cryptsetup_LIBS@ $(LIBS)
tang_luks_list_LDADD = libluks.a @cryptsetup_LIBS@ $(LIBS)
tang_luks_unbind_LDADD = libluks.a @cryptsetup_LIBS@ $(LIBS)

if USE_DRACUT
dracutmodules_SCRIPTS = module-setup.sh
EXTRA_DIST += module-setup.sh.in
CLEANFILES += module-setup.sh
endif

noinst_LIBRARIES += libaskpass.a
libaskpass_a_SOURCES = askpass/question.c askpass/question.h askpass/iface.c askpass/iface.h askpass/askp.c askpass/askp.h

systemdsystemunit_DATA += tang-luks-askpassd.path tang-luks-askpassd.service
EXTRA_DIST += tang-luks-askpassd.path.in tang-luks-askpassd.service.in
CLEANFILES += tang-luks-askpassd.path tang-luks-askpassd.service
libexec_PROGRAMS += tang-luks-askpassd
tang_luks_askpassd_LDADD = libaskpass.a libluks.a libclt.a @cryptsetup_LIBS@ $(LIBS)
endif

autostartdir = $(sysconfdir)/xdg/autostart
autostart_DATA =

if USE_UDISKS2
autostart_DATA += tang-luks-udisks2.desktop
libexec_PROGRAMS += tang-luks-udisks2
tang_luks_udisks2_LDADD = libluks.a libclt.a @cryptsetup_LIBS@ @udisks2_LIBS@ $(LIBS)
EXTRA_DIST += tang-luks-udisks2.desktop.in
CLEANFILES += tang-luks-udisks2.desktop
endif

if USE_STORAGED
autostart_DATA += tang-luks-storaged.desktop
libexec_PROGRAMS += tang-luks-storaged
tang_luks_storaged_LDADD = libluks.a libclt.a @cryptsetup_LIBS@ @storaged_LIBS@ $(LIBS)
EXTRA_DIST += tang-luks-storaged.desktop.in
CLEANFILES += tang-luks-storaged.desktop
endif

install-exec-hook:
	test -x $(DESTDIR)$(libexecdir)/tang-luks-storaged && chmod 4711 $(DESTDIR)$(libexecdir)/tang-luks-storaged
	test -x $(DESTDIR)$(libexecdir)/tang-luks-udisks2 && chmod 4711 $(DESTDIR)$(libexecdir)/tang-luks-udisks2


%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		-e 's,@TANG_DB\@,$(tangdir),g' \
		-e 's,@TANG_PORT\@,$(TANG_PORT),g' \
		$(srcdir)/$@.in > $@

