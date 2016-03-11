ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src

dracutmodules_SCRIPTS = module-setup.sh
systemdsystemunit_DATA = \
	tang-keyd.socket tang-keyd.service \
	tang-luksd.path tang-luksd.service

CLEANFILES = $(systemdsystemunit_DATA) $(dracutmodules_SCRIPTS)
EXTRA_DIST = \
	tang-keyd.socket.in tang-keyd.service.in \
	tang-luksd.path.in tang-luksd.service.in \
	module-setup.sh.in

%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		-e 's,@TANG_DB\@,$(TANG_DB),g' \
		-e 's,@TANG_PORT\@,$(TANG_PORT),g' \
		$(srcdir)/$@.in > $@
