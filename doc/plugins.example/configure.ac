dnl Process this file with autoconf to produce a configure script.
dnl
dnl This file is free software; as a special exception the author gives
dnl unlimited permission to copy and/or distribute it, with or without
dnl modifications, as long as this notice is preserved.
dnl
dnl This program is distributed in the hope that it will be useful, but
dnl WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
dnl implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

AC_INIT([Wireshark Hello Plugin], [0.0.1])

AM_INIT_AUTOMAKE([foreign])

AC_PREREQ([2.62])

LT_PREREQ([2.2.2])
LT_INIT([disable-static dlopen])

AC_CONFIG_SRCDIR([hello.c])

dnl Requires Wireshark 2.5.0 or greater.
PKG_CHECK_MODULES([WIRESHARK], [wireshark >= 2.5])

saved_CFLAGS="$CFLAGS"; saved_LIBS="$LIBS";
CFLAGS="$WIRESHARK_CFLAGS"
LIBS="$WIRESHARK_LIBS"
AC_CHECK_FUNCS([proto_register_plugin],
	[AC_DEFINE([HAVE_PLUGINS], 1, [Define to 1 if Wireshark supports loading plugins])],
	[AC_MSG_ERROR([Wireshark was compiled without support for plugins])]
)
CFLAGS="$saved_CFLAGS"; LIBS="$saved_LIBS"

AC_CONFIG_HEADER([config.h])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
