DISTCHECK_CONFIGURE_FLAGS = --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)
BUILT_SOURCES=
CLEANFILES=
man1_MANS=
man8_MANS=

AM_CFLAGS = @TANG_CFLAGS@ @jose_CFLAGS@
LDADD = @jose_LIBS@ @http_parser_LIBS@

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

man_ADOC_FILES= \
	doc/tang-show-keys.1.adoc \
	doc/tang.8.adoc

if HAVE_A2X
man_ROFF_FILES = $(man_ADOC_FILES:.adoc=.roff)
BUILT_SOURCES += $(man_ROFF_FILES)
CLEANFILES += $(man_ROFF_FILES) $(man_ROFF_FILES:.roff=)

$(top_builddir)/%.roff: %.adoc
	$(MKDIR_P) $$(dirname $@)
	$(A2X) -f manpage $^ -D $(top_builddir)/$$(dirname $@)
	$(INSTALL) -m 644 $(top_builddir)/$(@:.roff=) $(top_builddir)/$@

man1_MANS += doc/tang-show-keys.1
man8_MANS += doc/tang.8
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

CLEANFILES += $(nodist_systemdsystemunit_DATA)
EXTRA_DIST = \
    $(foreach unit,$(nodist_systemdsystemunit_DATA),$(unit).in) \
    COPYING \
    $(TESTS) \
    $(man_ADOC_FILES)
