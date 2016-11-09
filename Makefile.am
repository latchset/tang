DISTCHECK_CONFIGURE_FLAGS = --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

AM_CFLAGS = @TANG_CFLAGS@ @jose_zlib_CFLAGS@ @jose_openssl_CFLAGS@
LDADD = @jose_zlib_LIBS@ @jose_openssl_LIBS@ @http_parser_LIBS@

TESTS = test-adv test-rec test-nagios
EXTRA_DIST = COPYING $(TESTS) tangd@.service.in tangd.socket.in tangd-update.path.in tangd-update.service.in
CLEANFILES = $(systemdsystemunit_DATA)

nagiosdir = $(libdir)/nagios/plugins

systemdsystemunit_DATA = tangd@.service tangd.socket tangd-update.path tangd-update.service
dist_libexec_SCRIPTS = tangd-update
libexec_PROGRAMS = tangd
nagios_PROGRAMS = tang

tangd_SOURCES = http.c http.h tangd.c
tang_SOURCES = nagios.c

jwkdir = $(localstatedir)/db/$(PACKAGE_NAME)
cachedir = $(localstatedir)/cache/$(PACKAGE_NAME)

%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		-e 's,@jwkdir\@,$(jwkdir),g' \
		-e 's,@cachedir\@,$(cachedir),g' \
		$(srcdir)/$@.in > $@
