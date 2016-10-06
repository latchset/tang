AM_CFLAGS = @TANG_CFLAGS@ @jose_CFLAGS@ @jose_openssl_CFLAGS@ -fvisibility=hidden

tangdbdir = $(localstatedir)/db/$(PACKAGE_NAME)
plugindir = $(libdir)/tang/plugins

systemdsystemunit_DATA = tangd.socket tangd.service
EXTRA_DIST = tangd.socket.in tangd.service.in
CLEANFILES = tangd.socket tangd.service

libexec_PROGRAMS = tangd
tangd_SOURCES = io.c io.h plugin.c plugin.h tangd.c adv.c rec.c
tangd_CFLAGS = $(AM_CFLAGS) -rdynamic
tangd_LDADD = @jose_LIBS@ @http_parser_LIBS@ @dl_LIBS@

plugin_LTLIBRARIES = dbdir.la bldir.la blapi.la
dbdir_la_LIBADD = @jose_openssl_LIBS@ @jose_zlib_LIBS@
dbdir_la_LDFLAGS = -module -avoid-version
bldir_la_LDFLAGS = -module -avoid-version
blapi_la_LDFLAGS = -module -avoid-version

install-data-hook:
	mkdir -p $(DESTDIR)$(tangdbdir)/keys
	mkdir -p $(DESTDIR)$(tangdbdir)/blst

%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		-e 's,@tangdbdir\@,$(tangdbdir),g' \
		-e 's,@plugindir\@,$(plugindir),g' \
		$(srcdir)/$@.in > $@
