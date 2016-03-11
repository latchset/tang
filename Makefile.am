ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src

systemdsystemunit_DATA = tang-keyd.socket tang-keyd.service
EXTRA_DIST = tang-keyd.socket.in tang-keyd.service.in
CLEANFILES = $(systemdsystemunit_DATA)

if USE_CRYPTSETUP
if USE_DRACUT
dracutmodules_SCRIPTS = module-setup.sh
CLEANFILES += $(dracutmodules_SCRIPTS)
endif
systemdsystemunit_DATA += tang-luksd.path tang-luksd.service
EXTRA_DIST += tang-luksd.path.in tang-luksd.service.in module-setup.sh.in
endif

%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		-e 's,@TANG_DB\@,$(TANG_DB),g' \
		-e 's,@TANG_PORT\@,$(TANG_PORT),g' \
		$(srcdir)/$@.in > $@
