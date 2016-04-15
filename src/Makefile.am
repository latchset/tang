SUBDIRS = . srv clt

noinst_LTLIBRARIES = libcore.la
libcore_la_CFLAGS = @TANG_CFLAGS@ @libcrypto_CFLAGS@
libcore_la_LIBADD = @libcrypto_LIBS@
libcore_la_SOURCES = asn1.c asn1.h conv.c conv.h pkt.c pkt.h list.c list.h
