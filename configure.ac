AC_PREREQ(2.59)
AC_INIT(tang, 1)
AC_CONFIG_MACRO_DIRS([m4])
AC_CANONICAL_SYSTEM
AC_PROG_CC_C99
AC_PROG_RANLIB
AC_PROG_SED

AM_INIT_AUTOMAKE([subdir-objects foreign no-dist-gzip dist-bzip2 parallel-tests])
AM_SILENT_RULES([yes])
AM_PROG_CC_C_O
AM_PROG_AR

PKG_PROG_PKG_CONFIG([0.25])

PKG_CHECK_MODULES([LIBCRYPTO], [libcrypto])

PKG_CHECK_EXISTS([dracut], [], [AC_MSG_ERROR([dracut not found])])
AC_ARG_WITH(
    [dracutmodulesdir],
    AS_HELP_STRING(
        [--with-dracutmodulesdir=DIR],
        [Directory for dracut module files]
    ),
    [],
    [with_dracutmodulesdir=$($PKG_CONFIG --variable=dracutmodulesdir dracut)]
)
AC_SUBST([dracutmodulesdir], [$with_dracutmodulesdir])

PKG_CHECK_MODULES(
    [LIBSYSTEMD],
    [libsystemd],
    [],
    [PKG_CHECK_MODULES(
        [LIBSYSTEMD],
        [libsystemd-daemon],
        [],
        AC_MSG_ERROR([libsystemd/systemd-devel not found])
    )]
)

PKG_CHECK_EXISTS([systemd], [], [AC_MSG_ERROR([systemd not found])])
AC_ARG_WITH(
    [systemdsystemunitdir],
    AS_HELP_STRING(
        [--with-systemdsystemunitdir=DIR],
        [Directory for systemd service files]
    ),
    [],
    [with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)]
)
AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])


AC_ARG_WITH(
    [cryptsetup],
    [AS_HELP_STRING([--with-cryptsetup], [build LUKS utilities @<:@default=check@:>@])],
    [],
    [with_cryptsetup=check]
)
AS_CASE(
    ["$with_cryptsetup"],
    [yes], [PKG_CHECK_MODULES([cryptsetup], [libcryptsetup], [HAVE_CRYPTSETUP=1])],
    [no], [],
    [PKG_CHECK_MODULES([cryptsetup], [libcryptsetup], [HAVE_CRYPTSETUP=1], [HAVE_CRYPTSETUP=0])]
)
AM_CONDITIONAL([USE_CRYPTSETUP], [test "$with_cryptsetup" != no -a "$HAVE_CRYPTSETUP" -eq 1])


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
    [no], [],
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
-Wno-missing-field-initializers \
-Wno-unused-parameter \
"
AC_SUBST([TANG_CFLAGS])

AC_SUBST([TANG_PORT], [5700])
AC_DEFINE([TANG_PORT], [5700])

AC_SUBST([TANG_DB], [${localstatedir}/${PACKAGE_NAME}])
AX_DEFINE_DIR(TANG_DB, TANG_DB, [Location of key database])

AC_CONFIG_FILES([Makefile src/Makefile src/tests/Makefile])
AC_OUTPUT
