AM_CFLAGS = @TANG_CFLAGS@ @LIBCRYPTO_CFLAGS@
LDADD = ../libcommon.la @LIBCRYPTO_LIBS@

bin_PROGRAMS = tang-gen tang-mod tang-send
libexec_PROGRAMS = tang-serve

tang_send_SOURCES = tang-send.c \
        adv.c adv.h \
	db.c db.h \
	list.c list.h \
	rec.c rec.h \
	srv.c srv.h

tang_serve_SOURCES = tang-serve.c \
        adv.c adv.h \
	db.c db.h \
	list.c list.h \
	rec.c rec.h \
	srv.c srv.h

