AM_CFLAGS = @TANG_CFLAGS@ @libcrypto_CFLAGS@

if USE_SYSTEMD
if USE_LIBSYSTEMD
check_PROGRAMS = keyd

keyd_LDADD = ../libclt.a ../libcore.a @libcrypto_LIBS@

TESTS = $(check_PROGRAMS)
endif
endif
