AM_CFLAGS = @TANG_CFLAGS@ @LIBCRYPTO_CFLAGS@
LDADD = libtest.la ../libcommon.la @LIBCRYPTO_LIBS@

check_LTLIBRARIES = libtest.la
libtest_la_SOURCES = client.c

check_PROGRAMS = serve send
TESTS = $(check_PROGRAMS)
