DISTCHECK_CONFIGURE_FLAGS = --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

AM_CFLAGS = @TANG_CFLAGS@ @jose_CFLAGS@
LDADD = @jose_LIBS@ @http_parser_LIBS@

nagiosdir = $(libdir)/nagios/plugins
cachedir = $(localstatedir)/cache/$(PACKAGE_NAME)
jwkdir = $(localstatedir)/db/$(PACKAGE_NAME)

nodist_systemdsystemunit_DATA = \
    units/tangd@.service \
    units/tangd.socket \
    units/tangd-update.path \
    units/tangd-update.service \
    units/tangd-keygen.service

dist_libexec_SCRIPTS = src/tangd-update src/tangd-keygen
dist_bin_SCRIPTS = src/tang-show-keys
libexec_PROGRAMS = src/tangd
man1_MANS = doc/tang-show-keys.1
man8_MANS = doc/tang.8

if NAGIOSPLUGIN
nagios_PROGRAMS = src/tang
man1_MANS += doc/tang-nagios.1

src_tang_SOURCES = src/nagios.c
endif

src_tangd_SOURCES = src/http.c src/http.h src/tangd.c

%: %.in
	$(AM_V_GEN)mkdir -p "`dirname "$@"`"
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		-e 's,@jwkdir\@,$(jwkdir),g' \
		-e 's,@cachedir\@,$(cachedir),g' \
		$(srcdir)/$@.in > $@

AM_TESTS_ENVIRONMENT = SD_ACTIVATE="@SD_ACTIVATE@" PATH=$(srcdir)/src:$(builddir)/src:$(PATH)
TESTS = tests/adv tests/rec
if NAGIOSPLUGIN
TESTS += tests/nagios
endif

CLEANFILES = $(nodist_systemdsystemunit_DATA)
EXTRA_DIST = \
    $(foreach unit,$(nodist_systemdsystemunit_DATA),$(unit).in) \
    COPYING \
    $(TESTS) \
    $(man1_MANS) \
    $(man8_MANS)
