AM_CFLAGS = @TANG_CFLAGS@ @LIBCRYPTO_CFLAGS@
LDADD = libtest.a ../libcore.a @LIBCRYPTO_LIBS@

check_LIBRARIES = libtest.a
libtest_a_SOURCES = client.c

check_PROGRAMS = serve send
TESTS = $(check_PROGRAMS)
