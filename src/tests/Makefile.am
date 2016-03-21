AM_CFLAGS = @TANG_CFLAGS@ @libcrypto_CFLAGS@
LDADD = libtest.a ../libcore.a @libcrypto_LIBS@

check_LIBRARIES = libtest.a
libtest_a_SOURCES = client.c

if USE_SYSTEMD
if USE_LIBSYSTEMD
check_PROGRAMS = serve
TESTS = $(check_PROGRAMS)
endif
endif
