SUBDIRS = . luks
EXTRA_DIST = clevis.sym

AM_CFLAGS = @TANG_CFLAGS@ @libcrypto_CFLAGS@

noinst_LTLIBRARIES = libclt.la
libclt_la_SOURCES = adv.c adv.h rec.c rec.h msg.c msg.h sbuf.c sbuf.h
libclt_la_LIBADD = ../libcore.la

nagiosdir = $(libdir)/nagios/plugins
nagios_PROGRAMS = tang
tang_SOURCES = nagios.c
tang_LDADD = libclt.la

if USE_CLEVIS
clevispin_LTLIBRARIES = tang.la
tang_la_SOURCES = clevis.c
tang_la_LIBADD = libclt.la @clevis_LIBS@
tang_la_LDFLAGS = -module -avoid-version -export-symbols $(srcdir)/clevis.sym

install-data-hook:
	rm -f $(DESTDIR)$(clevispindir)/tang.la
endif
