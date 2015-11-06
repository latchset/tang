ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src

systemdsystemunit_DATA = tang.socket tang@.service

CLEANFILES = $(systemdsystemunit_DATA)
EXTRA_DIST = tang.socket.in tang@.service.in

%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		-e 's,@TANG_DB\@,$(TANG_DB),g' \
		-e 's,@TANG_PORT\@,$(TANG_PORT),g' \
		$(srcdir)/$@.in > $@
