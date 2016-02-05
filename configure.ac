AC_PREREQ(2.59)
AC_INIT(tang, 1)
AC_CONFIG_MACRO_DIRS([m4])
AC_CANONICAL_SYSTEM
AC_PROG_CC_C99
AC_PROG_SED

AM_INIT_AUTOMAKE([subdir-objects foreign no-dist-gzip dist-bzip2 parallel-tests])
AM_SILENT_RULES([yes])
AM_PROG_CC_C_O

LT_INIT([disable-static])

PKG_PROG_PKG_CONFIG([0.25])

PKG_CHECK_MODULES([LIBCRYPTO], [libcrypto])

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

PKG_CHECK_MODULES([CLEVIS], [clevis])
AC_ARG_WITH(
    [clevispindir],
    AS_HELP_STRING(
        [--with-clevispindir=DIR],
        [Directory for clevis pins]
    ),
    [],
    [with_clevispindir=$($PKG_CONFIG --variable=pindir clevis)]
)
AC_SUBST([clevispindir], [$with_clevispindir])

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

AC_CONFIG_FILES([Makefile src/Makefile src/progs/Makefile src/tests/Makefile src/clevis/Makefile])
AC_OUTPUT
