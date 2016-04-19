EXTRA_DIST = module-setup.sh.in tang-luks-askpassd.path.in tang-luks-askpassd.service.in
CLEANFILES = module-setup.sh tang-luks-askpassd.path tang-luks-askpassd.service

tangmoddir = $(dracutmodulesdir)/60tang

systemdsystemunit_DATA = tang-luks-askpassd.path tang-luks-askpassd.service
tangmod_SCRIPTS = module-setup.sh

noinst_LTLIBRARIES = libaskp.la
libaskp_la_SOURCES = question.c question.h iface.c iface.h askp.c askp.h
libaskp_la_LIBADD = ../libluks.la

libexec_PROGRAMS = tang-luks-askpassd
tang_luks_askpassd_LDADD = libaskp.la

%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		$(srcdir)/$@.in > $@
