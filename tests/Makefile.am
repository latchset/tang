AM_CFLAGS = @TANG_CFLAGS@ @libcrypto_CFLAGS@

check_PROGRAMS = keyd
TESTS = $(check_PROGRAMS)

keyd_LDADD = ../src/clt/libclt.la @libcrypto_LIBS@
