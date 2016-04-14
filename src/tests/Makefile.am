AM_CFLAGS = @TANG_CFLAGS@ @libcrypto_CFLAGS@

check_PROGRAMS = keyd

keyd_LDADD = ../libclt.a ../libcore.a @libcrypto_LIBS@

TESTS = $(check_PROGRAMS)
