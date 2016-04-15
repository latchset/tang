tangdir = $(localstatedir)/$(PACKAGE_NAME)

AM_CFLAGS = @TANG_CFLAGS@ @libcrypto_CFLAGS@ -DTANG_DB=\"$(tangdir)\"
LIBS = ../libcore.la

bin_PROGRAMS = tang-key-gen tang-key-mod tang-key-groups

systemdsystemunit_DATA = tang-keyd.socket tang-keyd.service
EXTRA_DIST = tang-keyd.socket.in tang-keyd.service.in
CLEANFILES = tang-keyd.socket tang-keyd.service

libexec_PROGRAMS = tang-keyd
tang_keyd_SOURCES = adv.c adv.h db.c db.h rec.c rec.h srv.c srv.h tang-keyd.c

install-data-hook:
	mkdir -p $(DESTDIR)$(tangdir)

%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		-e 's,@TANG_DB\@,$(tangdir),g' \
		-e 's,@TANG_PORT\@,$(TANG_PORT),g' \
		$(srcdir)/$@.in > $@
