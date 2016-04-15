AC_PREREQ(2.59)
AC_INIT(tang, 0)
AC_CANONICAL_SYSTEM
AC_PROG_CC_C99
AC_PROG_SED

AC_CHECK_LIB([rt], [clock_gettime], [LIBS="-lrt $LIBS"])

AM_INIT_AUTOMAKE([subdir-objects foreign no-dist-gzip dist-bzip2 parallel-tests])
AM_SILENT_RULES([yes])
AM_PROG_CC_C_O

LT_INIT([disable-static])

PKG_PROG_PKG_CONFIG([0.25])
PKG_CHECK_MODULES([libcrypto], [libcrypto])
PKG_CHECK_MODULES([systemd], [systemd],
		  [AC_SUBST([systemdsystemunitdir], [$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])],
		  [AC_SUBST([systemdsystemunitdir], [${prefix}/lib/systemd/system])])
PKG_CHECK_MODULES([dracut], [dracut],
                  [AC_SUBST([dracutmodulesdir], [$($PKG_CONFIG --variable=dracutmodulesdir dracut)])],
                  [AC_SUBST([dracutmodulesdir], [${prefix}/lib/dracut/modules.d])])


AC_ARG_WITH(
    [cryptsetup],
    [AS_HELP_STRING([--with-cryptsetup], [build LUKS utilities @<:@default=check@:>@])],
    [],
    [with_cryptsetup=check]
)
AS_CASE(
    ["$with_cryptsetup"],
    [yes], [PKG_CHECK_MODULES([cryptsetup], [libcryptsetup], [HAVE_CRYPTSETUP=1])],
    [no], [HAVE_CRYPTSETUP=0],
    [PKG_CHECK_MODULES([cryptsetup], [libcryptsetup], [HAVE_CRYPTSETUP=1], [HAVE_CRYPTSETUP=0])]
)
AM_CONDITIONAL([USE_CRYPTSETUP], [test "$with_cryptsetup" != no -a "$HAVE_CRYPTSETUP" -eq 1])


AC_ARG_WITH(
    [udisks2],
    [AS_HELP_STRING([--with-udisks2], [build udisks2 unlocker @<:@default=check@:>@])],
    [],
    [with_udisks2=check]
)
AS_CASE(
    ["$with_udisks2"],
    [yes], [PKG_CHECK_MODULES([udisks2], [udisks2], [HAVE_UDISKS2=1])],
    [no], [HAVE_UDISKS2=0],
    [PKG_CHECK_MODULES([udisks2], [udisks2], [HAVE_UDISKS2=1], [HAVE_UDISKS2=0])]
)
AM_CONDITIONAL([USE_UDISKS2], [test "$with_udisks2" != no -a "$HAVE_UDISKS2" -eq 1])


AC_ARG_WITH(
    [storaged],
    [AS_HELP_STRING([--with-storaged], [build storaged unlocker @<:@default=check@:>@])],
    [],
    [with_storaged=check]
)
AS_CASE(
    ["$with_storaged"],
    [yes], [PKG_CHECK_MODULES([storaged], [storaged], [HAVE_STORAGED=1])],
    [no], [HAVE_STORAGED=0],
    [PKG_CHECK_MODULES([storaged], [storaged], [HAVE_STORAGED=1], [HAVE_STORAGED=0])]
)
AM_CONDITIONAL([USE_STORAGED], [test "$with_storaged" != no -a "$HAVE_STORAGED" -eq 1])


AC_ARG_WITH(
    [clevis],
    [AS_HELP_STRING([--with-clevis], [build clevis pin @<:@default=check@:>@])],
    [],
    [with_clevis=check]
)
AS_CASE(
    ["$with_clevis"],
    [yes],
    [PKG_CHECK_MODULES(
        [clevis],
	[clevis],
	[HAVE_CLEVIS=1 && AC_SUBST([clevispindir], [$($PKG_CONFIG --variable=pindir clevis)])]
    )],
    [no], [HAVE_CLEVIS=0],
    [PKG_CHECK_MODULES(
        [clevis],
        [clevis],
        [HAVE_CLEVIS=1 && AC_SUBST([clevispindir], [$($PKG_CONFIG --variable=pindir clevis)])],
        [HAVE_CLEVIS=0]
    )]
)
AM_CONDITIONAL([USE_CLEVIS], [test "$with_clevis" != no -a "$HAVE_CLEVIS" -eq 1])

TANG_CFLAGS="\
-Wall \
-Wextra \
-Werror \
-Wstrict-aliasing \
-Wchar-subscripts \
-Wformat-security \
-Wmissing-declarations \
-Wmissing-prototypes \
-Wnested-externs \
-Wpointer-arith \
-Wshadow \
-Wsign-compare \
-Wstrict-prototypes \
-Wtype-limits \
-Wunused-function \
-Wno-missing-field-initializers \
-Wno-unused-parameter \
"
AC_SUBST([TANG_CFLAGS])

AC_SUBST([TANG_PORT], [5700])
AC_DEFINE([TANG_PORT], [5700])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
    src/srv/Makefile
    src/clt/Makefile
    src/clt/luks/Makefile
    src/clt/luks/askp/Makefile
    tests/Makefile
])
AC_OUTPUT
