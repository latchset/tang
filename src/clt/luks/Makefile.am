if USE_LUKSMETA
SUBDIRS = . askp

AM_CFLAGS = @TANG_CFLAGS@ @libcrypto_CFLAGS@ @cryptsetup_CFLAGS@ @udisks2_CFLAGS@ @storaged_CFLAGS@ @luksmeta_CFLAGS@
LIBS = @cryptsetup_LIBS@ @luksmeta_LIBS@

autostartdir = $(sysconfdir)/xdg/autostart
autostart_DATA =
libexec_PROGRAMS =
EXTRA_DIST =
CLEANFILES =

noinst_LTLIBRARIES = libluks.la
libluks_la_SOURCES = asn1.c asn1.h
libluks_la_LIBADD = ../libclt.la

if USE_CRYPTSETUP
bin_PROGRAMS = tang-luks-bind tang-luks-unbind
tang_luks_bind_LDADD = libluks.la $(LIBS)
tang_luks_unbind_LDADD = libluks.la $(LIBS)
endif

if USE_UDISKS2
autostart_DATA += tang-luks-udisks2.desktop
libexec_PROGRAMS += tang-luks-udisks2
tang_luks_udisks2_LDADD = libluks.la @udisks2_LIBS@ $(LIBS)
EXTRA_DIST += tang-luks-udisks2.desktop.in
CLEANFILES += tang-luks-udisks2.desktop
endif

if USE_STORAGED
autostart_DATA += tang-luks-storaged.desktop
libexec_PROGRAMS += tang-luks-storaged
tang_luks_storaged_LDADD = libluks.la @storaged_LIBS@ $(LIBS)
EXTRA_DIST += tang-luks-storaged.desktop.in
CLEANFILES += tang-luks-storaged.desktop
endif

install-exec-hook:
	if [ -x $(DESTDIR)$(libexecdir)/tang-luks-udisks2 ]; then \
	    chmod 4711 $(DESTDIR)$(libexecdir)/tang-luks-udisks2; \
	fi
	if [ -x $(DESTDIR)$(libexecdir)/tang-luks-storaged ]; then \
	    chmod 4711 $(DESTDIR)$(libexecdir)/tang-luks-storaged; \
	fi

%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		$(srcdir)/$@.in > $@
endif
