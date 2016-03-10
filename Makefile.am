ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src

systemdsystemunit_DATA = \
	tang-keyd.socket tang-keyd@.service \
	tang-luksd.path tang-luksd.service

CLEANFILES = $(systemdsystemunit_DATA)
EXTRA_DIST = \
	tang-keyd.socket.in tang-keyd@.service.in \
	tang-luksd.path.in tang-luksd.service.in

%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		-e 's,@TANG_DB\@,$(TANG_DB),g' \
		-e 's,@TANG_PORT\@,$(TANG_PORT),g' \
		$(srcdir)/$@.in > $@
