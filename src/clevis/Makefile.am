clevispin_LTLIBRARIES = tang.la

tang_la_SOURCES = common.c common.h acquire.c adv.c provision.c
tang_la_CFLAGS = @CLEVIS_CFLAGS@
tang_la_LIBADD = ../libcommon.la @CLEVIS_LIBS@
tang_la_LDFLAGS = -module -avoid-version -export-symbols-regex '^clevis_pin\\$'
