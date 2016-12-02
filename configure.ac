#
# Autoconf script for Wireshark
#

#
# Define variables for the components of the Wireshark version number.
#
m4_define([version_major], [2])
m4_define([version_minor], [2])
m4_define([version_micro], [3])
dnl Updated by make-version.pl
m4_define([version_extra], [])
m4_define([version_micro_extra], m4_join([], version_micro, version_extra))

AC_INIT(Wireshark, [version_major.version_minor.version_micro_extra], http://bugs.wireshark.org/, , http://www.wireshark.org/)
CONFIG_ARGS="$*"
AC_SUBST(CONFIG_ARGS)

# Minimum autoconf version we require.
AC_PREREQ(2.64)
# Variable expansion doesn't work in AC_PREREQ()
AC_MIN_VERSION=2.64
AC_SUBST(AC_MIN_VERSION)

dnl Make sure to keep ACLOCAL_AMFLAGS in Makefile.am and AC_CONFIG_MACRO_DIRS
dnl in configure.ac in sync, otherwise there will be an error running autogen.sh.
m4_ifdef([AC_CONFIG_MACRO_DIRS],[AC_CONFIG_MACRO_DIRS([m4])])

dnl Check for CPU / vendor / OS
dnl The user is encouraged to use either `AC_CANONICAL_BUILD', or
dnl `AC_CANONICAL_HOST', or `AC_CANONICAL_TARGET', depending on the
dnl needs.  Using `AC_CANONICAL_TARGET' is enough to run the two other
dnl macros.
dnl
dnl As nothing in the Wireshark is itself a build tool (we are not,
dnl for example, a compiler that generates machine code), we probably
dnl don't need AC_CANONICAL_TARGET, so, in theory, we should be able
dnl to use AC_CANONICAL_BUILD and AC_CANONICAL_HOST - or perhaps just
dnl AC_CANONICAL_HOST - instead.  Note that we do have tools, such as
dnl lemon, that need to be built for the build machine, not for the
dnl host machine, so we might need both.
dnl
dnl This has to be done *after* AC_INIT, otherwise autogen.sh fails.

dnl AC_CANONICAL_BUILD
dnl AC_CANONICAL_HOST
AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([1.11 tar-ustar dist-bzip2 no-dist-gzip subdir-objects])

# Enable silent builds by default. Verbose builds can be enabled with "./configure
# --enable-silent-rules ..." or "make V=1 ..."
AM_SILENT_RULES([yes])

# Make Wireshark's version available in config.h
AC_DEFINE(VERSION_MAJOR, version_major, [Wireshark's major version])
AC_DEFINE(VERSION_MINOR, version_minor, [Wireshark's minor version])
AC_DEFINE(VERSION_MICRO, version_micro, [Wireshark's micro version])

dnl AC_DEFINE_UNQUOTED(VERSION_FLAVOR,
dnl	["${WIRESHARK_VERSION_FLAVOR:-"Development Build"}"], [Wireshark's package flavor])

LT_PREREQ([2.2.2])
LT_INIT([disable-static dlopen])
AC_SUBST([LIBTOOL_DEPS])

AC_CONFIG_LIBOBJ_DIR([wsutil])

#
# Checks for programs used in the main build process.
#
AC_PROG_CC_STDC
if test "$ac_cv_prog_cc_stdc" = "no"
then
	AC_MSG_ERROR([The C compiler does not support standard C])
fi
AC_PROG_CPP

AC_PROG_CXX
if test ! -z "$CXX"; then
	#
	# OK, we found something AC_LANG_CXX thinks is a C++ compiler,
	# but is it one?
	#
	# Some UN*Xes have, by default, a case-insensitive file
	# system, and AC_PROG_CXX looks for, among other things,
	# "CC" as a C++ compiler, and, if you have a case-insensitive
	# file system and a C compiler named "cc" (both true, by
	# default, on OS X), AC_PROG_CXX may end up thinking it's
	# the C++ compiler.
	#
	# So we check by feeding the purported C++ compiler a
	# program using C++ features (iostream).
	#
	AC_MSG_CHECKING(whether $CXX is a C++ compiler)
	AC_LANG_PUSH([C++])
	AC_LINK_IFELSE([AC_LANG_PROGRAM(
	[
#include <iostream>
	],
	[
	std::cout << "Hello World! ";
	return 0;
	])],
		[AC_MSG_RESULT(yes)],
		[
			AC_MSG_RESULT(no)
			CXX=""
		])
	AC_LANG_POP([C++])
fi

# Qt 5.7 or later requires C++11
AS_IF([test -n "$CXX"],
	[AX_CXX_COMPILE_STDCXX([11], [noext], [optional])])

# Set CC_FOR_BUILD (the *local* gcc to use for building e.g. lemon)
if test "x$cross_compiling" = xno -a -z "$CC_FOR_BUILD"; then
	CC_FOR_BUILD="$CC"
fi
AX_PROG_CC_FOR_BUILD

#
# Check for versions of "sed" inadequate to handle, in libtool, a list
# of object files as large as the list in Wireshark.
#
AC_PROG_SED

AC_PROG_LN_S
AC_PROG_MKDIR_P

AC_PATH_PROG(PERL, perl)

# Check for Python.
AC_PATH_PROGS(PYTHON, python python3)
if test ! -z "$PYTHON"; then
	#
	# OK, we found Python; is it Python 2.5 or later?
	# Note: we don't use named components for sys.version_info to get
	# the major version number, as named components for version_info
	# were apparently introduced in Python 2.7.
	#
	AC_MSG_CHECKING([whether $PYTHON is Python 2.5 or later])
	python_major_version=`$PYTHON -c 'import sys; print (sys.version_info[[0]])'`
	python_minor_version=`$PYTHON -c 'import sys; print (sys.version_info[[1]])'`
	if test "$python_major_version" -eq 2 -a "$python_minor_version" -lt 5 ; then
		AC_MSG_RESULT(no)
		AC_MSG_WARN([Building with Python $python_major_version.$python_minor_version may not work])
	else
		AC_MSG_RESULT(yes)
	fi
else
	AC_MSG_ERROR(I couldn't find python; make sure it's installed and in your path)
fi

dnl
dnl Check for yacc/lex. Distribution tarballs include generated source,
dnl in which case these tools are not a mandatory requirement to build.
dnl
AC_PROG_YACC
AS_IF([test "x$YACC" = xyacc], [AS_UNSET(YACC)])
AS_IF([test -z "$YACC" -a ! -f $srcdir/wiretap/ascend.c],
	[AC_MSG_ERROR([I couldn't find bison or byacc; make sure it's installed and in your path])])
AM_MISSING_PROG(YACC, bison)
AC_PROG_LEX
AS_IF([test "x$LEX" != xflex], [AS_UNSET(LEX)])
AS_IF([test -z "$LEX" -a ! -f $srcdir/wiretap/ascend_scanner.c],
	[AC_MSG_ERROR([I couldn't find flex; make sure it's installed and in your path])])
AM_MISSING_PROG(LEX, flex)

AC_PATH_PROG(POD2MAN, pod2man)
if test "x$POD2MAN" = x
then
	#
	# The alternative is not to build the man pages....
	#
	AC_MSG_ERROR(I couldn't find pod2man; make sure it's installed and in your path)
fi
AC_PATH_PROG(POD2HTML, pod2html)
if test "x$POD2HTML" = x
then
	#
	# The alternative is not to build the HTML man pages....
	#
	AC_MSG_ERROR(I couldn't find pod2html; make sure it's installed and in your path)
fi

#
# Set "ac_supports_gcc_flags" if the compiler is known to support GCC-style
# flags such as -pedantic, -W warning flags and -f feature flags.  Currently,
# we assume GCC and clang do; other compilers should be added here.
#
# This is done to avoid getting tripped up by compilers that support
# those flags but give them a different meaning.
#
if test "x$GCC" = "xyes" -o "x$CC" = "xclang" ; then
	ac_supports_gcc_flags=yes
fi

# Check for doxygen
AC_PATH_PROG(DOXYGEN, doxygen)
AC_CHECK_PROG(HAVE_DOXYGEN, doxygen, "yes", "no")
AM_CONDITIONAL(HAVE_DOXYGEN, test x$HAVE_DOXYGEN = xyes)

#
# Check for pkg-config and set PKG_CONFIG accordingly.
#
# This is referenced via AC_REQUIRE([PKG_PROG_PKG_CONFIG] in some macros
# like PKG_CHECK_MODULES. If the first call to such a macro is under an
# "if" statement, it's safer to call PKG_PROG_PKG_CONFIG directly, see
# the comments in acolocal.m4
#
# We want version 0.7 or better.  (XXX - explain why. Is that just
# because our Qt tests were originally based on AM_PATH_GTK, and *it*
# requires 0.7 or better?)
#
PKG_PROG_PKG_CONFIG(0.7)
if test -z "$PKG_CONFIG"; then
	AC_MSG_ERROR(I couldn't find pkg-config; make sure it's installed and in your path)
fi

#
# Add configure argument to select OSX deployment target.
#
AC_WIRESHARK_OSX_DEPLOY_TARGET

#
# Try to arrange for large file support.
#
AC_SYS_LARGEFILE

#
# Check if we need to link with libm
#
AC_SEARCH_LIBS([cos], [m])

#
# Check for C99 math functions.
#
AC_CHECK_FUNCS([floorl lrint])

#
# Check if we need to link with -lnsl and -lsocket
#
AX_LIB_SOCKET_NSL

#
# GUI toolkit options
#
AC_ARG_WITH([qt],
  AC_HELP_STRING( [--with-qt=@<:@yes/no/4/5@:>@],
		  [use Qt @<:@default=yes, if available@:>@]),
  with_qt="$withval", with_qt="unspecified")

AC_ARG_WITH([gtk],
  AC_HELP_STRING( [--with-gtk=@<:@yes/no/2/3@:>@],
	[use GTK+ @<:@default=yes, if available@:>@]),
	AS_CASE([$withval],
	  [yes], [with_gtk="3 2 fail"],
	  [no],  [with_gtk="no"],
	  [3],   [with_gtk="3 fail3"],
	  [2],   [with_gtk="2 fail2"],
	  [AC_MSG_ERROR([--with-gtk must be one of yes/no/2/3])]),
	with_gtk="3 2")

# GnuTLS
# Version 3.0 switched from LGPLv2.1+ to LGPLv3+, then switched back to
# LGPLv2.1+ in version 3.1.10.
# GnuTLS depends on GMP which switched from LGPLv2.1+ to LGPLv3+ in
# version 4.2.2, the switched to LGPLv3+ / GPLv2+ in version 6.0.0.

tls_message="no"
want_gnutls="if_available"
AC_ARG_WITH([gnutls],
  AC_HELP_STRING( [--with-gnutls=@<:@yes/no@:>@],
		  [use GnuTLS library @<:@default=yes, if available@:>@]),
  [ with_gnutls="$withval"; want_gnutls="yes" ], with_gnutls="yes")

if test "x$with_gnutls" = "xyes"; then
  have_license_compatible_gnutls="no"
  PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 3.1.10 ],
    [ have_license_compatible_gnutls="yes" ], [ echo "GnuTLS >= 3.1.10 not found " ]
  )

  if test "x$have_license_compatible_gnutls" != "xyes"; then
    PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 2.12.0 gnutls < 3],
      [ have_license_compatible_gnutls="yes" ] , [ echo "GnuTLS >= 2.12.0, < 3.0 not found " ]
    )
  fi

  if test "x$have_license_compatible_gnutls" != "xyes"; then
    if test "x$want_gnutls" = "xyes"; then
      AC_MSG_ERROR([GnuTLS crypto library was requested, but is not available])
    else
      AS_ECHO(["GnuTLS with compatible license not found, disabling SSL decryption"])
    fi
  else
    AC_DEFINE(HAVE_LIBGNUTLS, 1, [Define to use GnuTLS library])
    tls_message="yes"
  fi
fi

# libgrypt
gcrypt_message="no"
want_gcrypt="if_available"
AC_ARG_WITH([gcrypt],
  AC_HELP_STRING( [--with-gcrypt=@<:@yes/no@:>@],
		  [use gcrypt library @<:@default=yes, if available@:>@]),
  [ with_gcrypt="$withval"; want_gcrypt="yes" ], with_gcrypt="yes")

if test "x$with_gcrypt" = "xyes"; then
  AM_PATH_LIBGCRYPT(1.4.2,
	[
		AC_DEFINE(HAVE_LIBGCRYPT, 1, [Define to use libgcrypt])
		gcrypt_message="yes"
	]
	, [
		if test x$libgcrypt_config_prefix != x ; then
			AC_MSG_ERROR([[libgcrypt not found; install libgcrypt-devel package for your system]])
		else
			AS_ECHO(["libgcrypt not found, disabling decryption for ipsec, ssl, etc."])
			gcrypt_message="no"
		fi

		# Error out if the user explicitly requested gcrypt
		if test "x$want_gcrypt" = "xyes"; then
		    AC_MSG_ERROR([libgcrypt library was requested, but is not available])
		fi
	]
  )
fi

AC_ARG_WITH(libnl,
  AC_HELP_STRING([--with-libnl@<:@=VERSION@:>@],
		 [use libnl (force version VERSION, if supplied) @<:@default: yes, if available@:>@]),
[
	if test "x$withval" = "xno"
	then
		want_libnl=no
	elif test "x$withval" = "xyes"
	then
		want_libnl=yes
		libnl_version=any
	elif test "x$withval" = "x1"
	then
		want_libnl=yes
		libnl_version=1
	elif test "x$withval" = "x2"
	then
		want_libnl=yes
		libnl_version=2
	elif test "x$withval" = "x3"
	then
		want_libnl=yes
		libnl_version=3
	else
		AC_MSG_ERROR(["$withval" is not a valid argument to --with-libnl])
	fi
],[
	#
	# Use libnl if it's present, otherwise don't.
	#
	want_libnl=ifavailable
	libnl_version=any
])
#
# Libnl is Linux-specific.
#
libnl_message="no"
case "$host_os" in
linux*)
	AC_MSG_CHECKING(whether to use libnl for various network interface purposes)

	if test x$want_libnl = "xno"; then
		AC_MSG_RESULT(no)
	else
		AC_MSG_RESULT(yes)
		#
		# Test for specific libnl versions only if no version
		# was specified by the user or if the version in question
		# was requested by the user.
		#
		if test x$libnl_version = "xany" -o x$libnl_version = "x3"; then
			PKG_CHECK_EXISTS([libnl-3.0 libnl-route-3.0 libnl-genl-3.0], [have_libnl3=yes], [have_libnl3=no])
		fi
		if test x$libnl_version = "xany" -o x$libnl_version = "x2"; then
			PKG_CHECK_EXISTS([libnl-2.0], [have_libnl2=yes], [have_libnl2=no])
		fi
		if test x$libnl_version = "xany" -o x$libnl_version = "x1"; then
			PKG_CHECK_EXISTS([libnl-1], [have_libnl1=yes], [have_libnl1=no])
		fi
		if (test "${have_libnl3}" = "yes"); then
			PKG_WIRESHARK_CHECK_SYSTEM_MODULES([LIBNL], [libnl-3.0 libnl-route-3.0 libnl-genl-3.0])
			AC_DEFINE(HAVE_LIBNL, 1, [Enable libnl support])
			AC_DEFINE(HAVE_LIBNL3, 1, [libnl version 3])
			libnl_message="yes (v3)"
		elif (test "${have_libnl2}" = "yes"); then
			PKG_WIRESHARK_CHECK_SYSTEM_MODULES([LIBNL], [libnl-2.0])
			AC_DEFINE(HAVE_LIBNL, 1, [Enable libnl support])
			AC_DEFINE(HAVE_LIBNL2, 1, [libnl version 2])
			libnl_message="yes (v2)"
		elif (test "${have_libnl1}" = "yes"); then
			PKG_WIRESHARK_CHECK_SYSTEM_MODULES([LIBNL], [libnl-1])
			AC_DEFINE(HAVE_LIBNL, 1, [Enable libnl support])
			AC_DEFINE(HAVE_LIBNL1, 1, [libnl version 1])
			libnl_message="yes (v1)"
		else
			if test x$want_libnl = "xyes"; then
				case "$libnl_version" in

				any)
					AC_MSG_ERROR("I couldn't find libnl even though you manually enabled it.")
					;;

				*)
					AC_MSG_ERROR("I couldn't find libnl version $libnl_version even though you manually enabled it.")
					;;
				esac
			fi
		fi
	fi

	AC_MSG_CHECKING([if nl80211.h is new enough])
	  AC_TRY_COMPILE([#include <linux/nl80211.h>],
	    [int x = NL80211_FREQUENCY_ATTR_MAX_TX_POWER;
	     x |= NL80211_ATTR_SUPPORTED_IFTYPES;
	     x |= NL80211_ATTR_SUPPORTED_COMMANDS;
	     x |= NL80211_ATTR_WIPHY_FREQ;
	     x |= NL80211_CHAN_NO_HT;
	     (void)x;],
	    [AC_MSG_RESULT(yes) AC_DEFINE(HAVE_NL80211, 1, [nl80211.h is new enough])],
	    [AC_MSG_RESULT(no)])

	AC_MSG_CHECKING([for NL80211_SET_CHANNEL])
	  AC_TRY_COMPILE([#include <linux/nl80211.h>],
	    [enum nl80211_commands x = NL80211_CMD_SET_CHANNEL;],
	    [AC_MSG_RESULT(yes) AC_DEFINE(HAVE_NL80211_CMD_SET_CHANNEL, 1, [SET_CHANNEL is supported])],
	    [AC_MSG_RESULT(no)])

	AC_MSG_CHECKING([for NL80211_SPLIT_WIPHY_DUMP])
	  AC_TRY_COMPILE([#include <linux/nl80211.h>],
	    [enum nl80211_protocol_features x = NL80211_PROTOCOL_FEATURE_SPLIT_WIPHY_DUMP;],
	    [AC_MSG_RESULT(yes) AC_DEFINE(HAVE_NL80211_SPLIT_WIPHY_DUMP, 1, [SPLIT_WIPHY_DUMP is supported])],
	    [AC_MSG_RESULT(no)])

	AC_MSG_CHECKING([for NL80211_VHT_CAPABILITY])
	  AC_TRY_COMPILE([#include <linux/nl80211.h>],
	    [enum nl80211_attrs x = NL80211_ATTR_VHT_CAPABILITY;],
	    [AC_MSG_RESULT(yes) AC_DEFINE(HAVE_NL80211_VHT_CAPABILITY, 1, [VHT_CAPABILITY is supported])],
	    [AC_MSG_RESULT(no)])
	;;

*)
	if test x$want_libnl != "xno" -a x$want_libnl != "xifavailable"; then
		AC_MSG_WARN([libnl is Linux-specific, ignoring --with-libnl])
	fi
esac

# libsmi
# FIXME: currently the path argument to with-libsmi is being ignored
AX_LIBSMI

#
# Check for programs used when building DocBook documentation.
#
AC_CHECK_PROGS(XSLTPROC, xsltproc, xsltproc)
AC_CHECK_PROGS(A2X, a2x, a2x)
AC_CHECK_PROGS(FOP, fop, fop)

# HTML to text processor
AC_MSG_CHECKING([for an HTML to text processor])
AS_IF([w3m -version >&AS_MESSAGE_LOG_FD 2>&1], [have_a2x_text=w3m],
	[lynx -version >&AS_MESSAGE_LOG_FD 2>&1], [have_a2x_text=lynx],
	[have_a2x_text=no])
AC_MSG_RESULT([$have_a2x_text])
AM_CONDITIONAL(HAVE_A2X_TEXT, [test "x$have_a2x_text" != xno])
AS_IF([test $have_a2x_text = lynx], [A2X_LYNX="--lynx"])
AC_SUBST(A2X_LYNX)

# Check for packaging utilities
# For now, we check to see if the various packaging utilites are in our
# path.  I'm too lazy to write code to go hunt for them.  -  Gerald

#
# Source packages.
# (Lets you install the desktop files.)
#
AC_PATH_PROG(DESKTOP_FILE_INSTALL, desktop-file-install)

# SVR4/Solaris
AC_CHECK_PROG(HAVE_PKGPROTO, pkgproto, "yes", "no")
AC_CHECK_PROG(HAVE_PKGMK, pkgmk, "yes", "no")
AC_CHECK_PROG(HAVE_PKGTRANS, pkgtrans, "yes", "no")

if test x$HAVE_PKGPROTO = xyes -a x$HAVE_PKGMK = xyes \
     -a x$HAVE_PKGTRANS = xyes ; then
  HAVE_SVR4_PACKAGING=yes
else
  HAVE_SVR4_PACKAGING=no
fi
AC_SUBST(HAVE_SVR4_PACKAGING)

# RPM
#
# Looks for the rpmbuild program, and checks to see if we can redefine "_topdir".
#
AC_CHECK_PROGS(RPMBUILD, [rpmbuild], [false])
if test "x$RPMBUILD" != "xfalse" ; then
	AC_MSG_CHECKING([to see if we can redefine _topdir])
	rpm --define '_topdir /tmp' > /dev/null 2>&1
	if test $? -eq 0 ; then
		AC_MSG_RESULT(yes)
		have_rpm=yes
	else
		AC_MSG_RESULT([no, you'll have to build packages manually])
		have_rpm=no
	fi
fi
AM_CONDITIONAL(HAVE_RPM, [test "x$have_rpm" = xyes])

# Debian
AC_CHECK_PROG(HAVE_DPKG_BUILDPACKAGE, dpkg-buildpackage, "yes", "no")

# OS X
AC_CHECK_PROG(HAVE_XCODEBUILD, xcodebuild, "yes", "no")
AC_CHECK_PROG(HAVE_HDIUTIL, hdiutil, "yes", "no")
AC_CHECK_PROG(HAVE_BLESS, bless, "yes", "no")

if test x$HAVE_XCODEBUILD = xyes -a x$HAVE_HDIUTIL = xyes \
     -a x$HAVE_BLESS = xyes ; then
  HAVE_OSX_PACKAGING=yes
else
  HAVE_OSX_PACKAGING=no
fi
AC_SUBST(HAVE_OSX_PACKAGING)

#
# Use this as a proxy for "is this OS X" (just in case somebody actually
# built and installed Darwin as an OS, perhaps with some X11-based GUI,
# don't look for Darwin).
#
AC_CHECK_PROG(have_sw_vers, sw_vers, "yes", "no")
AM_CONDITIONAL(NOT_OS_X, test "x$have_sw_vers" = "xno")

#
# Check compiler vendor. For GCC this will be 'gnu' and for Clang 'clang'.
#
AX_COMPILER_VENDOR
if test "x$CXX" != "x" ; then
	AC_LANG_PUSH(C++)
	AX_COMPILER_VENDOR
	AC_LANG_POP
fi

#
# Some compilers have to be told to fail when passed an unknown -W flag;
# make sure we do that.
#
AC_WIRESHARK_CHECK_UNKNOWN_WARNING_OPTION_ERROR

#
# Some C++ compilers have to be told to fail when passed a -W flag that
# they don't think should apply to C++; make sure we do that.
#
AC_WIRESHARK_CHECK_NON_CXX_WARNING_OPTION_ERROR

#
# The following are for C and C++
#
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wall)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wextra)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wendif-labels)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wpointer-arith)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wformat-security)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-fwrapv)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-fno-strict-overflow)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-fno-delete-null-pointer-checks)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wvla)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Waddress)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wattributes)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wdiv-by-zero)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wignored-qualifiers)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wpragmas)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wno-overlength-strings)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wno-long-long)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wheader-guard)

#
# The following are C only, not C++
#
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wc++-compat, C)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wdeclaration-after-statement, C)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wunused-const-variable, C)

#
# XXX - OK for C++?
#
# Make sure -Wshadow doesn't complain about variables in function and
# function pointer declarations shadowing other variables; if not, don't
# turn it on, as some versions of GCC (including the one in at least
# some Xcode versions that came with Mac OS X 10.5) complain about
# that.
#
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wshadow, C,
  [
extern int bar(int a);
extern int foo(int);

int
foo(int a)
{
	int (*fptr)(int a) = bar;

	return fptr(a) * 2;
}
  ],
  [warns about variables in function declarations shadowing other variables])

AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wno-pointer-sign, C)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wold-style-definition, C)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wstrict-prototypes, C)

# Unfortunately some versions of gcc generate logical-op warnings when strchr()
# is given a constant string.
# gcc versions 4.3.2 and 4.4.5 are known to have the problem.
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wlogical-op, C,
  [
#include <string.h>

int foo(const char *, int);
int bar(void);

int
foo(const char *sep, int c)
{
	if (strchr (sep, c) != NULL)
		return 1;
	else
		return 0;
}

int
bar(void)
{
	return foo("<", 'a');
}
  ],
  [generates warnings from strchr()])

AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wjump-misses-init, C)
# The Qt headers generate a ton of shortening errors on 64-bit systems
# so only enable this for C for now.
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wshorten-64-to-32, C)

# Clang only. Avoid "argument unused during compilation" warnings
# (for example, when getting the -gsplit-dwarf option or
# when combining -fwrapv with -fno-strict-overflow)
if test x"$ax_cv_c_compiler_vendor" = xclang; then
	AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Qunused-arguments, C)
fi
if test x"$ax_cv_cxx_compiler_vendor" = xclang; then
	AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Qunused-arguments, CXX)
fi

#
# Use the faster pre gcc 4.5 floating point precision if available.
#
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-fexcess-precision=fast)

#
# Try to have the compiler default to hiding symbols, so that only
# symbols explicitly exported with WS_DLL_PUBLIC will be visible
# outside (shared) libraries; that way, more UN*X builds will catch
# failures to export symbols, rather than having that fail only on
# Windows.
#
# GCC and GCC-compatible compilers
#
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-fvisibility=hidden)
if test "x$can_add_to_cflags" = "xno"
then
	#
	# Sun^WOracle C.
	#
	AC_WIRESHARK_COMPILER_FLAGS_CHECK(-xldscope=hidden)
	if test "x$can_add_to_cflags" = "xno"
	then
		# TODO add other ways of hiding symbols
		AC_MSG_WARN(Compiler will export all symbols from shared libraries)
	fi
fi

#Clang only
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wc99-extensions, C)

#
# Try to add some additional checks to CFLAGS.
# These are not enabled by default, because the warnings they produce
# are very hard or impossible to eliminate.
#
AC_ARG_ENABLE(extra-compiler-warnings,
  AC_HELP_STRING( [--enable-extra-compiler-warnings],
		  [do additional compiler warnings @<:@default=no@:>@]),
[
	wireshark_extra_flags=$enableval
	if test $enableval != no
	then
		#
		# The following are for C and C++
		#
		AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wpedantic)
		#
		# As we use variadic macros, we don't want warnings
		# about them, even with -Wpedantic.
		#
		AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wno-variadic-macros)
		#
		# Various code blocks this one.
		#
		AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Woverflow)
		AC_WIRESHARK_COMPILER_FLAGS_CHECK(-fstrict-overflow -Wstrict-overflow=4)
		#
		# Due to various places where APIs we don't control
		# require us to cast away constness, we can probably
		# never enable this one with -Werror.
		#
		AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wcast-qual)
		#
		# Some generated ASN.1 dissectors block this one;
		# multiple function declarations for the same
		# function are being generated.
		#
		AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wredundant-decls)
		#
		# Some loops are safe, but it's hard to convince the
		# compiler of that.
		#
		AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wunsafe-loop-optimizations)
		#
		# All the registration functions block these for now.
		#
		AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wmissing-prototypes)
		AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wmissing-declarations)
		#
		# A bunch of "that might not work on SPARC" code blocks
		# this one for now.
		#
		AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wcast-align)
		#
		# Works only with Clang
		#
		AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wunreachable-code)
		#
		# Works only with Clang but generates a lot of warnings
		# (about glib library not using Doxygen)
		#
		AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wdocumentation)

		#
		# The following are C only, not C++
		#
		# Due to various places where APIs we don't control
		# require us to cast away constness, we can probably
		# never enable this one with -Werror.
		#
		AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wbad-function-cast, C)
	fi
])

# Try to add ASAN address analyze.
# Only needed for analyse
#
AC_ARG_ENABLE(asan,
  AC_HELP_STRING( [--enable-asan],
		  [Enable AddressSanitizer (ASAN) for debugging (degrades performance)@<:@default=no@:>@]),
[
	#
	# With Clang >= 3.5 Leak detection is enable by default
	# and no yet all leak is fixed...
	# use ASAN_OPTIONS=detect_leaks=0 to disable detect_leaks
	#
	# XXX shouldn't this also be added to LDFLAGS?
	AC_WIRESHARK_COMPILER_FLAGS_CHECK(-fsanitize=address)

])

# Add check hf conflict..
#
AC_ARG_ENABLE(checkhf-conflict,
  AC_HELP_STRING( [--enable-checkhf-conflict],
		  [Enable hf conflict check for debugging (start-up may be slower)@<:@default=no@:>@]),
[
	AC_DEFINE(ENABLE_CHECK_FILTER, 1, [Enable hf conflict check])
])

AC_WIRESHARK_LDFLAGS_CHECK([-Wl,--as-needed])
###AC_WIRESHARK_LDFLAGS_CHECK([-Wl,-M])
###AC_WIRESHARK_LDFLAGS_CHECK([-Wl,--cref])
# AC_WIRESHARK_LDFLAGS_CHECK([-flto])
# AC_WIRESHARK_LDFLAGS_CHECK([-fwhopr])
# AC_WIRESHARK_LDFLAGS_CHECK([-fwhole-program])

#
# Put -fPIE in PIE_CFLAGS and -pie in PIE_LDFLAGS if we can use them,
# so that we can build dumpcap PIE - it may run with elevated
# privileges, and using PIE means the OS can run it at random locations
# in the address space to make attacks more difficult.
#

WS_CFLAGS_saved="$WS_CFLAGS"
WS_LDFLAGS_saved="$WS_LDFLAGS"
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-fPIE, C)
if test "x$can_add_to_cflags" = "xyes"
then
	AC_WIRESHARK_LDFLAGS_CHECK([-fPIE -pie])
	if test "x$can_add_to_ldflags" = "xyes"
	then
		# We can use PIE
		PIE_CFLAGS="-fPIE"
		PIE_LDFLAGS="-pie"
	fi
fi
WS_CFLAGS="$WS_CFLAGS_saved"
WS_LDFLAGS="$WS_LDFLAGS_saved"
AC_SUBST(PIE_CFLAGS)
AC_SUBST(PIE_LDFLAGS)

WS_CFLAGS_saved="$WS_CFLAGS"
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-msse4.2, C)
if test "x$can_add_to_cflags" = "xyes"
then
	#
	# The compiler supports -msse4.2; use that to enable SSE 4.2.
	#
	# We only want to apply -msse4.2 to
	# wsutil/ws_mempbrk_sse42.c, as the SSE4.2 code there
	# is run only if the hardware supports it, but other
	# code would do no such checks.
	#
	ac_sse4_2_flag=-msse4.2
else
	#
	# Try -xarch=sse4_2; that's the flag for Sun's compiler.
	#
	AC_WIRESHARK_COMPILER_FLAGS_CHECK(-xarch=sse4_2, C)
	if test "x$can_add_to_cflags" = "xyes"
	then
		#
		# The compiler supports -xarch=sse4_2; use that to
		# enable SSE 4.2.
		ac_sse4_2_flag=-xarch=sse4_2
	fi
fi
WS_CFLAGS="$WS_CFLAGS_saved"

if test "x$ac_sse4_2_flag" != x; then
	#
	# OK, we have a compiler flag to enable SSE 4.2.
	#
	# Make sure we have the necessary headers for the SSE4.2 intrinsics
	# and that we can use them.
	#
	# First, check whether we have emmintrin.h and can use it
	# *without* the SSE 4.2 flag.
	#
	AC_MSG_CHECKING([whether there is emmintrin.h header and we can use it])
	AC_TRY_COMPILE(
		[#include <emmintrin.h>],
		[return 0;],
		[
			emmintrin_h_works=yes
			AC_MSG_RESULT([yes])
		],
		[
			emmintrin_h_works=no
			AC_MSG_RESULT([no])
		]
	)

	#
	# OK, if that works, see whether we have nmmintrin.h and
	# can use it *with* the SSE 4.2 flag.
	#
	if test "x$emmintrin_h_works" = "xyes"; then
		#
		# Add the SSE4.2 flags to the beginning of CFLAGS,
		# in case the user explicitly specified -mno-sse4.2
		# (or in case Gentoo's build tools did so); if they
		# did so, we only want this to work if we can use
		# the #pragma to override that for ws_mempbrk_sse42.c,
		# and putting it at the beginning means that the
		# CFLAGS setting in the environment will come later
		# and override it.
		#
		AC_MSG_CHECKING([whether there is nmmintrin.h header and we can use it])
		saved_CFLAGS="$CFLAGS"
		CFLAGS="$ac_sse4_2_flag $WS_CFLAGS $CFLAGS"
		AC_TRY_COMPILE(
			[#include <nmmintrin.h>],
			[return 0;],
			[
				have_sse42=yes
				AC_DEFINE(HAVE_SSE4_2, 1, [Support SSSE4.2 (Streaming SIMD Extensions 4.2) instructions])
				CFLAGS_SSE42="$ac_sse4_2_flag"
				AC_MSG_RESULT([yes])
			],
			[
				have_sse42=no
				AC_MSG_RESULT([no])
			]
		)
		CFLAGS="$saved_CFLAGS"
	else
		have_sse42=no
	fi
else
	have_sse42=no
fi
dnl build libwsutil_sse42 only if there is SSE4.2
AM_CONDITIONAL(SSE42_SUPPORTED, test "x$have_sse42" = "xyes")
AC_SUBST(CFLAGS_SSE42)

#
# If we're running GCC or clang define _U_ to be "__attribute__((unused))"
# so we can use _U_ to flag unused function parameters and not get warnings
# about them. Otherwise, define _U_ to be an empty string so that _U_ used
# to flag an unused function parameters will compile with other compilers.
#
# XXX - similar hints for other compilers?
#
if test "x$GCC" = "xyes" -o "x$CC" = "xclang" ; then
  AC_DEFINE(_U_, __attribute__((unused)), [Hint to the compiler that a function parameters is not used])
  AC_DEFINE(WS_NORETURN, __attribute((noreturn)), [Hint to the compiler that a function never returns])
else
  AC_DEFINE(_U_, , [Hint to the compiler that a function parameters is not used])
  AC_DEFINE(WS_NORETURN, , [Hint to the compiler that a function never returns])
fi

# If we're running GCC or CLang, use FORTIFY_SOURCE=2
#  (only if the GCC 'optimization level' > 0).
#
# See: http://gcc.gnu.org/ml/gcc-patches/2004-09/msg02055.html
# See: http://sourceware.org/bugzilla/show_bug.cgi?id=13979
#
# Note: FORTIFY_SOURCE is only effective for gcc optimization level > 0 (-O1, etc)
AC_WIRESHARK_GCC_FORTIFY_SOURCE_CHECK

#
# If the compiler supports GCC-style flags, enable a barrier "stop on
# warning".
# This barrier is set for a very large part of the code. However, it is
# typically not set for "generated" code  (flex, ans2wrs, idl2wrs, ...)
#
warnings_as_errors_default="no"
AC_MSG_CHECKING(whether we should treat compiler warnings as errors)
AC_ARG_ENABLE(warnings-as-errors,
  AC_HELP_STRING( [--enable-warnings-as-errors],
		  [treat warnings as errors (only for GCC or clang) @<:@default=no@:>@]),
[
  if test "x$ac_supports_gcc_flags" = "xyes" -a "x$enableval" = "xyes"; then
    with_warnings_as_errors="yes"
    AC_MSG_RESULT(yes)
  else
    with_warnings_as_errors="no"
    AC_MSG_RESULT(no)
  fi
],
[
  if test "x$ac_supports_gcc_flags" = "xyes" -a "x$wireshark_extra_flags" = "x" -a "x$warnings_as_errors_default" = "xyes"; then
    with_warnings_as_errors="yes"
    AC_MSG_RESULT(yes)
  else
    with_warnings_as_errors="no"
    AC_MSG_RESULT(no)
  fi
])

AS_IF([test "x$with_warnings_as_errors" = "xyes"], [WERROR="-Werror"], [WERROR=""])
AC_SUBST(WERROR)
AM_CONDITIONAL(HAVE_WARNINGS_AS_ERRORS, [test "x$with_warnings_as_errors" = "xyes"])

#
# Add any platform-specific compiler flags needed.
#
AC_MSG_CHECKING(for platform-specific compiler flags)
if test "x$GCC" = "xyes" ; then
	#
	# GCC - do any platform-specific tweaking necessary.
	#
	case "$host_os" in
	solaris*)
		# the X11 headers don't automatically include prototype info
		# and a lot don't include the return type
		WS_CPPFLAGS="$WS_CPPFLAGS -DFUNCPROTO=15"
		WS_CFLAGS="$WS_CFLAGS -Wno-return-type"
		WS_CXXFLAGS="$WS_CXXFLAGS -Wno-return-type"
		AC_MSG_RESULT(GCC on Solaris - added -Wno-return-type -DFUNCPROTO=15)
		;;
	*)
		AC_MSG_RESULT(none needed)
		;;
	esac
else
	#
	# Not GCC - assume it's the vendor's compiler.
	#
	case "$host_os" in
	hpux*)
		#
		# AC_PROG_CC_STDC should already have added whatever
		# flags are necessary for ISO C - C99 if available,
		# otherwise C89 - with extensions.
		#
		# Add +O2, for optimization, as suggested by Jost Martin.
		# XXX - works with "-g"?
		#
		# +O2 is supported both by the C and C++ compiler.
		#
		WS_CFLAGS="+O2 $WS_CFLAGS"
		if test "$CC" = "$CC_FOR_BUILD"; then
			#
			# We're building the build tools with the same
			# compiler as the one with which we're building
			# Wireshark, so add the flags to the flags for
			# that compiler as well.
			#
			CFLAGS_FOR_BUILD="-Ae +O2 $CFLAGS"
		fi
		WS_CXXFLAGS="+O2 $WS_CXXFLAGS"
		AC_MSG_RESULT(HP C/C++ compiler - added +O2)
		;;
	solaris*)
		#
		# Crank up the warning level.
		#
		WS_CFLAGS="$WS_CFLAGS -v"
		WS_CXXFLAGS="$WS_CXXFLAGS +w2"
		;;
	*)
		AC_MSG_RESULT(none needed)
		;;
	esac
fi

#
# Add any platform-specific linker flags needed.
#
AC_MSG_CHECKING(for platform-specific linker flags)
case "$host_os" in
darwin*)
	#
	# Add -Wl,-single_module to the LDFLAGS used with shared
	# libraries, to fix some error that show up in some cases;
	# some Apple documentation recommends it for most shared
	# libraries.
	#
	LDFLAGS_SHAREDLIB="-Wl,-single_module"
	#
	# Add -Wl,-headerpad_max_install_names to the LDFLAGS, as
	# code-signing issues is running out of padding space.
	#
	# Add -Wl,-search_paths_first to make sure that if we search
	# directories A and B, in that order, for a given library, a
	# non-shared version in directory A, rather than a shared
	# version in directory B, is chosen (so we can use
	# --with-pcap=/usr/local to force all programs to be linked
	# with a static version installed in /usr/local/lib rather than
	# the system version in /usr/lib).
	#
	WS_LDFLAGS="-Wl,-headerpad_max_install_names -Wl,-search_paths_first $WS_LDFLAGS"
	AC_MSG_RESULT([Apple linker - added -Wl,-single_module to shared library linker flags and -Wl,-headerpad_max_install_names -Wl,-search_paths_first and -Wl,-headerpad_max_install_names to all linker flags])
	;;
cygwin*)
	#
	# Shared libraries in cygwin/Win32 must never contain
	# undefined symbols.
	#
	WS_LDFLAGS="$WS_LDFLAGS -no-undefined"
	AC_MSG_RESULT(CygWin GNU ld - added -no-undefined)
	;;
*)
	AC_MSG_RESULT(none needed)
	;;
esac
AC_SUBST(LDFLAGS_SHAREDLIB)

#
# On "Darwin", which we assume to mean "OS X" rather than "iOS" or
# "just Darwin" (as we don't currently support iOS, and as I don't
# think you can build and run "just Darwin" as an OS for PCs), we
# arrange to build some programs with Application Services so they
# can launch Web browsers and Finder windows, arrange to build some
# programs with System Configuration so they can get "friendly names"
# and other information about interfaces, and build any programs that
# use either of those frameworks or that report version information
# with Core Foundation as the frameworks in question use it and as we
# get version information from plists and thus need Core Foundation
# to process those plists.
#
have_os_x_frameworks=no
case "$host_os" in
darwin*)
	have_os_x_frameworks=yes
	AC_DEFINE(HAVE_OS_X_FRAMEWORKS, 1, [Define to 1 if you have OS X frameworks])
	APPLICATIONSERVICES_FRAMEWORKS="-framework ApplicationServices"
	SYSTEMCONFIGURATION_FRAMEWORKS="-framework SystemConfiguration"
	COREFOUNDATION_FRAMEWORKS="-framework CoreFoundation"

	#
	# OK, so we have the OS X frameworks; do they include
	# CFPropertyListCreateWithStream, or do we have
	# to fall back on CFPropertyListCreateFromStream?
	# (They only differ in the error return, which we
	# don't care about.  And, no, we shouldn't just
	# use CFPropertyListCreateFromStream, because it's
	# deprecated in newer releases.)
	#
	ac_save_LIBS="$LIBS"
	LIBS="$LIBS $COREFOUNDATION_FRAMEWORKS"
	AC_CHECK_FUNCS(CFPropertyListCreateWithStream)
	LIBS="$ac_save_LIBS"
	;;
esac
AC_SUBST(APPLICATIONSERVICES_FRAMEWORKS)
AC_SUBST(SYSTEMCONFIGURATION_FRAMEWORKS)
AC_SUBST(COREFOUNDATION_FRAMEWORKS)
AM_CONDITIONAL(HAVE_OS_X_FRAMEWORKS, [test "x$have_os_x_frameworks" = "xyes"])

#
# If we're running Solaris, and LD_LIBRARY_PATH is defined, add it as a
# link directory.
#
case "$host_os" in
  solaris*)
    AC_MSG_CHECKING(for LD_LIBRARY_PATH, since you appear to be running Solaris)
    if test x$LD_LIBRARY_PATH != x ; then
      LIBS="$LIBS -R$LD_LIBRARY_PATH"
      AC_MSG_RESULT(yes -- added LD_LIBRARY_PATH to run-time linker path)
    else
      AC_MSG_RESULT(no -- this may be a problem in a few seconds)
    fi
  ;;
esac

# Enable/disable wireshark
AC_ARG_ENABLE(wireshark,
  AC_HELP_STRING( [--enable-wireshark],
		  [build the Wireshark GUI (with Gtk+, Qt, or both) @<:@default=yes@:>@]),
    enable_wireshark=$enableval,enable_wireshark=yes)
AM_CONDITIONAL(BUILDING_WIRESHARK, test x$enable_wireshark = xyes)

AC_ARG_ENABLE(packet-editor,
  AC_HELP_STRING( [--enable-packet-editor],
		  [add support for packet editor in Wireshark @<:@default=yes@:>@]),
    enable_packet_editor=$enableval,enable_packet_editor=yes)
if test x$enable_packet_editor = xyes; then
	AC_DEFINE(WANT_PACKET_EDITOR, 1, [Support for packet editor])
fi

AC_ARG_ENABLE(profile-build,
  AC_HELP_STRING( [--enable-profile-build],
		  [build profile-ready binaries @<:@default=no@:>@]),
    enable_profile_build=$enableval,enable_profile_build=no)
AM_CONDITIONAL(USE_PROFILE_BUILD, test x$enable_profile_build = xyes)
AC_MSG_CHECKING(if profile builds must be generated)
if test "x$enable_profile_build" = "xyes" ; then
	if test "x$GCC" = "xyes" -o "x$CLANG" = "xyes" ; then
		AC_MSG_RESULT(yes)
		WS_CFLAGS="-pg $WS_CFLAGS"
		WS_CXXFLAGS="-pg $WS_CXXFLAGS"
	else
		AC_MSG_RESULT(no)
		echo "Building profile binaries currently only supported for GCC and clang."
	fi
else
	AC_MSG_RESULT(no)
fi

GLIB_MIN_VERSION=2.16.0
AC_SUBST(GLIB_MIN_VERSION)
# GLib checks; we require GLib $GLIB_MIN_VERSION or later, and require gmodule
# support, as we need that for dynamically loading plugins.
#
# Release dates for GLib versions:
# 2.14.0: 03 Aug 2007
# 2.16.0: 10 Mar 2008
# 2.18.0: 02 Sep 2008
# 2.20.0: 13 Mar 2009
# 2.22.0: 22 Sep 2009
# 2.24.0: 28 Mar 2010
# 2.26.0: 27 Sep 2010
# 2.28.0: 08 Feb 2011
# 2.30.0: 27 Sep 2011
# 2.32.0: 24 Mar 2012
# 2.34.0: 24 Sep 2012
# 2.36.0: 25 Mar 2013
# 2.38.0: 23 Sep 2013
# 2.40.0: 24 Mar 2014
# 2.42.0: 22 Sep 2014
# 2.44.0: 23 Mar 2014
# 2.46.0: 25 Sep 2015

PKG_WIRESHARK_CHECK_SYSTEM_MODULES([GLIB],
	[glib-2.0 >= $GLIB_MIN_VERSION gthread-2.0 >= $GLIB_MIN_VERSION gmodule-2.0 >= $GLIB_MIN_VERSION],
	[GLIB_VERSION=`$PKG_CONFIG --modversion glib-2.0`],
	[AC_MSG_ERROR([GLib $GLIB_MIN_VERSION or later not found.])])

# Error out if a glib header other than a "top level" header
#  (glib.h, glib-object.h, gio.h) or certain other headers( e.g.,gmodule.h)
#  is used.
AX_APPEND_FLAG([-DG_DISABLE_SINGLE_INCLUDES], [GLIB_CONFIG])

# Error out on the usage of deprecated glib functions
AX_APPEND_FLAG([-DG_DISABLE_DEPRECATED], [GLIB_CONFIG])

GLIB_CFLAGS="$GLIB_CONFIG $GLIB_CFLAGS"
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

GTK2_MIN_VERSION=2.12.0
AC_SUBST(GTK2_MIN_VERSION)
GTK3_MIN_VERSION=3.0.0
AC_SUBST(GTK3_MIN_VERSION)
QT_MIN_VERSION=4.7.0
AC_SUBST(QT_MIN_VERSION)
# GTK+ and Qt checks; we require GTK+ $GTK2_MIN_VERSION or later or
# GTK3_MIN_VERSION or later or Qt $QT_MIN_VERSION or later.
#
# We only do those if we're going to be building Wireshark;
# otherwise, we don't have any GUI to build, so we don't use
# GTK+ or Qt.
#
# We don't add $GTK_LIBS or $Qt_LIBS to LIBS, because we don't want to
# force all programs to be built with GTK+ or Qt.
#
# Release dates for GTK+ versions:
# https://en.wikipedia.org/wiki/GTK+#Releases
# 2.12.0: 14 Sep 2007
# 2.14.0: 04 Sep 2008
# 2.16.0: 13 Mar 2009
# 2.18.0: 23 Sep 2009
# 2.20.0: 23 Mar 2010
# 2.22.0: 23 Sep 2010
# 2.24.0: 30 Jan 2011
# 3.0.0:  10 Feb 2011
# 3.2.0:  25 Sep 2011
# 3.4.0:  26 Mar 2012
# 3.6.0:  24 Sep 2012
# 3.8.0:  25 Mar 2013
# 3.10.0: 23 Sep 2013
# 3.12.0: 25 Mar 2014
# 3.14.0: 30 Sep 2014
# 3.16.0: 22 Mar 2015
# 3.18.0  22 Sep 2015
#
# Release dates for Qt versions:
# https://en.wikipedia.org/wiki/List_of_Qt_releases
# 4.6.0:  01 Dec 2009
# 4.7.0:  21 Sep 2010
# 4.8.0:  15 Dec 2011
# 5.0.0:  19 Dec 2012
# 5.1.0:  03 Jul 2013
# 5.2.0:  12 Dec 2013
# 5.3.0:  20 May 2014
# 5.4.0:  10 Dec 2015
# 5.5.0:  01 Jul 2015

have_qt=no
have_gtk=no
if test "x$enable_wireshark" = "xyes"; then
	if test "x$with_qt" != "xno"; then
		#
		# Qt was specified; make sure we have a C++ compiler.
		#
		if test -z "$CXX"; then
			AC_MSG_ERROR(Need a working C++ compiler to build Wireshark with Qt)
		fi

		#
		# Now make sure we have Qt and, if so, add the flags
		# for it to CFLAGS and CXXFLAGS.
		#
		AC_WIRESHARK_QT_CHECK($QT_MIN_VERSION, "$with_qt",
		[
			AC_SUBST(Qt_CFLAGS)
			AC_SUBST(Qt_LIBS)
			have_qt=yes
			GUI_CONFIGURE_FLAGS="$GUI_CONFIGURE_FLAGS --with-qt"

			#
			# We're building with Qt, so we need the Qt build
			# tools in order to build the Wireshark GUI.
			# We've found a particular major version of Qt,
			# and we want that version's build tools; for
			# example, the Qt 4 version of uic produces files
			# that include Qt headers with paths that work
			# with Qt 4 but not Qt 5, so we can't use the
			# Qt 4 version of uic if we're building with Qt 5.
			AC_WIRESHARK_QT_TOOL_CHECK(UIC, uic, "$qt_version")
			AC_SUBST(UIC)
			AC_WIRESHARK_QT_TOOL_CHECK(MOC, moc, "$qt_version")
			AC_SUBST(MOC)
			AC_WIRESHARK_QT_TOOL_CHECK(RCC, rcc, "$qt_version")
			AC_SUBST(RCC)
			AC_WIRESHARK_QT_TOOL_CHECK_LRELEASE("$qt_version")
			AC_SUBST(LRELEASE)

			#
			# On Darwin, find where the Qt frameworks are
			# located, and add that to the rpath, just in
			# case this is Qt 5.5 or later and the frameworks
			# have an install name that begins with @rpath
			# and aren't installed in a frameworks directory
			# that's searched by default.
			#
			case "$host_os" in
			darwin*)
				if test $qt_version -le 4
				then
					Qt_LDFLAGS="-Wl,-rpath,"`$PKG_CONFIG --libs QtCore | sed -e 's/-F//' -e 's/ -framework.*//'`
				else
					Qt_LDFLAGS="-Wl,-rpath,"`$PKG_CONFIG --libs Qt${qt_version}Core | sed -e 's/-F//' -e 's/ -framework.*//'`
				fi
				;;
			esac
			AC_SUBST(Qt_LDFLAGS)

			if test -z "${MOC_OPTIONS+1}"
			then
				# Squelch moc verbose "nothing to do" output
				if test $QT_VERSION_MAJOR -eq 5
				then
					MOC_OPTIONS="-nn"
				elif test $QT_VERSION_MAJOR -eq 4 -a $QT_VERSION_MINOR -ge 8
				then
					MOC_OPTIONS="-nn"
				fi
			fi
			AC_SUBST(MOC_OPTIONS)
		],
		[
			case "$with_qt" in

			unspecified)
				#
				# They didn't explicitly ask for Qt,
				# so just don't build with it.
				#
				;;

			yes)
				AC_MSG_ERROR([Qt is not available])
				;;

			4)
				AC_MSG_ERROR([Qt 4 is not available])
				;;

			5)
				AC_MSG_ERROR([Qt 5 is not available])
				;;
			esac
		])
	fi

	for want_gtk_version in $with_gtk; do
		AS_CASE([$want_gtk_version],
		  [3], [PKG_WIRESHARK_CHECK_SYSTEM_MODULES([GTK],
			[gtk+-3.0 >= $GTK3_MIN_VERSION glib-2.0 >= $GLIB_MIN_VERSION gthread-2.0 >= $GLIB_MIN_VERSION gmodule-2.0 >= $GLIB_MIN_VERSION],
			[
			  have_gtk=yes
			  GTK_VERSION=`$PKG_CONFIG --modversion gtk+-3.0`
			  GUI_CONFIGURE_FLAGS="$GUI_CONFIGURE_FLAGS --with-gtk=3"
			],
			[
			  :
			])],
		  [2], [PKG_WIRESHARK_CHECK_SYSTEM_MODULES([GTK],
			[gtk+-2.0 >= $GTK2_MIN_VERSION glib-2.0 >= $GLIB_MIN_VERSION gthread-2.0 >= $GLIB_MIN_VERSION gmodule-2.0 >= $GLIB_MIN_VERSION],
			[
			  have_gtk=yes
			  GTK_VERSION=`$PKG_CONFIG --modversion gtk+-2.0`
			  GUI_CONFIGURE_FLAGS="$GUI_CONFIGURE_FLAGS --with-gtk=2"
			],
			[
			  :
			])],
		  [fail3], [AC_MSG_ERROR([GTK+ 3 was requested but is not available])],
		  [fail2], [AC_MSG_ERROR([GTK+ 2 was requested but is not available])],
		  [fail],  [AC_MSG_ERROR([GTK+ was requested but is not available])])

		AS_IF([test "x$have_gtk" = xyes], [break])
	done

	if test "$have_gtk" = "yes" ; then
		# If we have GTK then add flags for it.
		#
		# GLib flags first
		#
		GTK_CONFIG="$GLIB_CONFIG"

		gtk_major_version=`echo $GTK_VERSION | cut -d. -f1`
		gtk_minor_version=`echo $GTK_VERSION | cut -d. -f2`

		AX_APPEND_FLAG([-DGDK_DISABLE_DEPRECATED], [GTK_CONFIG])
		if test \( $gtk_major_version -eq 3 -a $gtk_minor_version -ge 10 \) ; then
			## Allow use of deprecated & disable deprecated warnings if Gtk >= 3.10;
			##  The deprecations in Gtk 3.10 will not be fixed ...
			AX_APPEND_FLAG([-DGDK_DISABLE_DEPRECATION_WARNINGS], [GTK_CONFIG])
		else
			AX_APPEND_FLAG([-DGTK_DISABLE_DEPRECATED], [GTK_CONFIG])
		fi
		AX_APPEND_FLAG([-DGTK_DISABLE_SINGLE_INCLUDES], [GTK_CONFIG])
		if test ! \( $gtk_major_version -eq 2 -a $gtk_minor_version -lt 20 \) ; then
			# Enable GSEAL when building with GTK > 2.20
			# (Versions prior to 2.22 lacked some necessary accessors.)
			AX_APPEND_FLAG([-DGSEAL_ENABLE], [GTK_CONFIG])
		fi

		GTK_CFLAGS="$GTK_CONFIG $GTK_CFLAGS"
	fi
fi

AC_SUBST(GTK_CFLAGS)
AC_SUBST(GTK_LIBS)
AC_SUBST(GUI_CONFIGURE_FLAGS)

# Check for GTK GUI support for GResource pixbufs
have_gresource_pixbuf=no
if test "x$have_gtk" = "xyes"; then
	AC_MSG_CHECKING(whether GDK-Pixbuf can load data using GResource)
	PKG_CHECK_EXISTS([gio-2.0 >= 2.32 gdk-pixbuf-2.0 >= 2.26],
	  [
	   AC_MSG_RESULT(yes)
	   AC_DEFINE(HAVE_GDK_GRESOURCE, 1, [Defined if GResource is supported])
	   have_gresource_pixbuf=yes
	  ],
	  [AC_MSG_RESULT(no)])
fi
AM_CONDITIONAL(HAVE_GRESOURCE_PIXBUF, test "x$have_gresource_pixbuf" = "xyes")

if test "$have_gtk" = "yes" -a "$have_qt" = "yes" ; then
	# We have both GTK and Qt and thus will be building both wireshark
	# and wireshark-gtk.

	wireshark_bin="wireshark\$(EXEEXT) wireshark-gtk\$(EXEEXT)"
	wireshark_man="wireshark.1"
	wireshark_SUBDIRS="codecs ui/qt ui/gtk"
elif test "$have_gtk" = "no" -a "$have_qt" = "yes" ; then
	# We don't have GTK+ but we have Qt.

	wireshark_bin="wireshark\$(EXEEXT)"
	wireshark_man="wireshark.1"
	wireshark_SUBDIRS="codecs ui/qt"
elif test "$have_gtk" = "yes" -a "$have_qt" = "no" ; then
	# We have GTK+ but not Qt.

	wireshark_bin="wireshark-gtk\$(EXEEXT)"
	wireshark_man="wireshark.1"
	wireshark_SUBDIRS="codecs ui/gtk"
	OSX_APP_FLAGS="$OSX_APP_FLAGS -gtk"
	OSX_DMG_FLAGS="-gtk"
elif test "$have_gtk" = "no" -a "$have_qt" = "no" ; then
	# We have neither GTK+ nor Qt.
	#
	# If they didn't explicitly say "--disable-wireshark",
	# fail (so that, unless they explicitly indicated that
	# they don't want Wireshark, we stop so they know they
	# won't be getting Wireshark unless they fix the GTK+/Qt
	# problem).
	#
	if test "x$enable_wireshark" = "xyes"; then
		if test "$with_qt" != "no" -a "$with_gtk" != "no" ; then
			AC_MSG_ERROR([Neither Qt nor GTK+ are available, so Wireshark can't be compiled])
		elif test "$with_qt" != "no" -a "$with_gtk" = "no" ; then
			AC_MSG_ERROR([Qt is not available and GTK+ was not requested, so Wireshark can't be compiled])
		elif test "$with_qt" = "no" -a "$with_gtk" != "no" ; then
			AC_MSG_ERROR([Qt was not requested and GTK+ is not available, so Wireshark can't be compiled])
		elif test "$with_qt" = "no" -a "$with_gtk" = "no" ; then
			AC_MSG_ERROR([Neither Qt nor GTK+ were requested, so Wireshark can't be compiled])
		fi
	fi
	wireshark_bin=""
	wireshark_man=""
	wireshark_SUBDIRS=""
fi

#
# Check whether GLib modules are supported, to determine whether we
# can support plugins.
#

AC_CACHE_CHECK([whether GLib supports loadable modules],
               [ac_cv_glib_supports_modules], [
ac_save_CFLAGS="$CFLAGS"
ac_save_LIBS="$LIBS"
CFLAGS="$WS_CFLAGS $GLIB_CFLAGS $CFLAGS"
LIBS="$LIBS $GLIB_LIBS"
AC_TRY_RUN([
#include <glib.h>
#include <gmodule.h>
#include <stdio.h>
#include <stdlib.h>

int
main ()
{
  if (g_module_supported())
    return 0;	/* success */
  else
    return 1;	/* failure */
}
], ac_cv_glib_supports_modules=yes, ac_cv_glib_supports_modules=no,
   [echo $ac_n "cross compiling; assumed OK... $ac_c"
    ac_cv_glib_supports_modules=yes])
CFLAGS="$ac_save_CFLAGS"
LIBS="$ac_save_LIBS"
])
if test "$ac_cv_glib_supports_modules" = yes ; then
  have_plugins=yes
  plugins_dir="plugins"
else
  have_plugins=no
  plugins_dir=""
fi
AC_SUBST(plugins_dir)

#
# If we have <dlfcn.h>, check whether we have dladdr.
#
if test "$ac_cv_header_dlfcn_h" = "yes"
then
	#
	# Use GLib compiler flags and linker flags; GLib's gmodule
	# stuff uses the dl APIs if available, so it might know
	# what flags are needed.
	#
	ac_save_CFLAGS="$CFLAGS"
	ac_save_LIBS="$LIBS"
	CFLAGS="$WS_CFLAGS $GLIB_CFLAGS $CFLAGS"
	LIBS="$LIBS $GLIB_LIBS"
	AC_CHECK_FUNCS(dladdr)
	if test x$ac_cv_func_dladdr = xno
	then
		#
		# OK, try it with -ldl, in case you need that to get
		# dladdr().  For some reason, on Linux, that's not
		# part of the GLib flags; perhaps GLib itself is
		# linked with libdl, so that you can link with
		# Glib and it'll pull libdl in itself.
		#
		LIBS="$LIBS -ldl"
		AC_CHECK_FUNCS(dladdr)
	fi
	CFLAGS="$ac_save_CFLAGS"
	LIBS="$ac_save_LIBS"
fi

#
# Check whether GLib's printf supports thousands grouping. (This might
# be different from the system's printf since GLib can optionally use
# its own printf implementation.)
#
AC_CACHE_CHECK([whether GLib supports POSIX/XSI thousands grouping],
               [ac_cv_glib_supports_printf_grouping], [
ac_save_CFLAGS="$CFLAGS"
ac_save_LIBS="$LIBS"
CFLAGS="$WS_CFLAGS $GLIB_CFLAGS $CFLAGS"
LIBS="$LIBS $GLIB_LIBS"
AC_TRY_RUN([
#include <glib.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>

int
main ()
{
  gchar *str;
  setlocale(LC_ALL, "en_US.UTF-8");
  str = g_strdup_printf("%'u", 123456);
  return (strcmp (str, "123,456") != 0);
}
], ac_cv_glib_supports_printf_grouping=yes, ac_cv_glib_supports_printf_grouping=no,
   [echo $ac_n "cross compiling; playing it safe... $ac_c"
    ac_cv_glib_supports_printf_grouping=no])
CFLAGS="$ac_save_CFLAGS"
LIBS="$ac_save_LIBS"
])
if test "$ac_cv_glib_supports_printf_grouping" = yes ; then
  AC_DEFINE(HAVE_GLIB_PRINTF_GROUPING, 1, [Define if GLib's printf functions support thousands grouping.])
fi

if test "x$have_gtk" = "xyes"
then
    #
    # We have GTK+; do we want the OS X integration functions and,
    # if so, do we have them and, if so, which versions do we have,
    # the old Carbon-based ones or the new Cocoa-based ones?
    #
    AC_MSG_CHECKING(whether to use OS X integration functions)

    AC_ARG_WITH(osx-integration,
      AC_HELP_STRING( [--with-osx-integration],
		      [use OS X integration functions @<:@default=yes, if available@:>@]),
    [
	if test $withval = no
	then
	    want_osx_integration=no
	else
	    want_osx_integration=yes
	fi
    ],[
	want_osx_integration=yes
    ])
    if test "x$want_osx_integration" = "xno"; then
	AC_MSG_RESULT(no)
    else
	AC_MSG_RESULT(yes)
	AC_WIRESHARK_OSX_INTEGRATION_CHECK
    fi
fi

AC_SUBST(wireshark_bin)
AC_SUBST(wireshark_man)
AC_SUBST(wireshark_SUBDIRS)
AM_CONDITIONAL(HAVE_Qt, test "$have_qt" = "yes")
AM_CONDITIONAL(HAVE_GTK, test "$have_gtk" = "yes")
AC_SUBST(OSX_APP_FLAGS)
AC_SUBST(OSX_DMG_FLAGS)

# Enable/disable tshark
AC_ARG_ENABLE(tshark,
  AC_HELP_STRING( [--enable-tshark],
		  [build tshark @<:@default=yes@:>@]),
    tshark=$enableval,enable_tshark=yes)

if test "x$enable_tshark" = "xyes" ; then
	tshark_bin="tshark\$(EXEEXT)"
	tshark_man="tshark.1"
	wiresharkfilter_man="wireshark-filter.4"
else
	tshark_bin=""
	tshark_man=""
fi
AC_SUBST(tshark_bin)
AC_SUBST(tshark_man)

# Enable/disable editcap

AC_ARG_ENABLE(editcap,
  AC_HELP_STRING( [--enable-editcap],
		  [build editcap @<:@default=yes@:>@]),
    enable_editcap=$enableval,enable_editcap=yes)

if test "x$enable_editcap" = "xyes" ; then
	editcap_bin="editcap\$(EXEEXT)"
	editcap_man="editcap.1"
else
	editcap_bin=""
	editcap_man=""
fi
AC_SUBST(editcap_bin)
AC_SUBST(editcap_man)


# Enabling/disabling of dumpcap is done later (after we know if we have PCAP
# or not)

# Enable/disable capinfos

AC_ARG_ENABLE(capinfos,
  AC_HELP_STRING( [--enable-capinfos],
		  [build capinfos @<:@default=yes@:>@]),
    enable_capinfos=$enableval,enable_capinfos=yes)

if test "x$enable_capinfos" = "xyes" ; then
	capinfos_bin="capinfos\$(EXEEXT)"
	capinfos_man="capinfos.1"
else
	capinfos_bin=""
	capinfos_man=""
fi
AC_SUBST(capinfos_bin)
AC_SUBST(capinfos_man)

# Enable/disable captype

AC_ARG_ENABLE(captype,
  AC_HELP_STRING( [--enable-captype],
		  [build captype @<:@default=yes@:>@]),
    enable_captype=$enableval,enable_captype=yes)

if test "x$enable_captype" = "xyes" ; then
	captype_bin="captype\$(EXEEXT)"
	captype_man="captype.1"
else
	captype_bin=""
	captype_man=""
fi
AC_SUBST(captype_bin)
AC_SUBST(captype_man)

# Enable/disable mergecap

AC_ARG_ENABLE(mergecap,
  AC_HELP_STRING( [--enable-mergecap],
		  [build mergecap @<:@default=yes@:>@]),
    enable_mergecap=$enableval,enable_mergecap=yes)

if test "x$enable_mergecap" = "xyes" ; then
	mergecap_bin="mergecap\$(EXEEXT)"
	mergecap_man="mergecap.1"
else
	mergecap_bin=""
	mergecap_man=""
fi
AC_SUBST(mergecap_bin)
AC_SUBST(mergecap_man)

# Enable/disable reordercap

AC_ARG_ENABLE(reordercap,
  AC_HELP_STRING( [--enable-reordercap],
		  [build reordercap @<:@default=yes@:>@]),
    enable_reordercap=$enableval,enable_reordercap=yes)

if test "x$enable_reordercap" = "xyes" ; then
	reordercap_bin="reordercap\$(EXEEXT)"
	reordercap_man="reordercap.1"
else
	reordercap_bin=""
	reordercap_man=""
fi
AC_SUBST(reordercap_bin)
AC_SUBST(reordercap_man)

# Enable/disable text2pcap

AC_ARG_ENABLE(text2pcap,
  AC_HELP_STRING( [--enable-text2pcap],
		  [build text2pcap @<:@default=yes@:>@]),
    text2pcap=$enableval,enable_text2pcap=yes)

if test "x$enable_text2pcap" = "xyes" ; then
	text2pcap_bin="text2pcap\$(EXEEXT)"
	text2pcap_man="text2pcap.1"
else
	text2pcap_bin=""
	text2pcap_man=""
fi
AC_SUBST(text2pcap_bin)
AC_SUBST(text2pcap_man)

# Enable/disable dftest

AC_ARG_ENABLE(dftest,
  AC_HELP_STRING( [--enable-dftest],
		  [build dftest @<:@default=yes@:>@]),
    enable_dftest=$enableval,enable_dftest=yes)

if test "x$enable_dftest" = "xyes" ; then
	dftest_bin="dftest\$(EXEEXT)"
	dftest_man="dftest.1"
else
	dftest_bin=""
	dftest_man=""
fi
AC_SUBST(dftest_bin)
AC_SUBST(dftest_man)

# Enable/disable randpkt

AC_ARG_ENABLE(randpkt,
  AC_HELP_STRING( [--enable-randpkt],
		  [build randpkt @<:@default=yes@:>@]),
    enable_randpkt=$enableval,enable_randpkt=yes)

if test "x$enable_randpkt" = "xyes" ; then
	randpkt_bin="randpkt\$(EXEEXT)"
	randpkt_man="randpkt.1"
else
	randpkt_bin=""
	randpkt_man=""
fi
AC_SUBST(randpkt_bin)
AC_SUBST(randpkt_man)

AC_SUBST(wiresharkfilter_man)

dnl pcap check
AC_MSG_CHECKING(whether to use libpcap for packet capture)

AC_ARG_WITH(pcap,
  AC_HELP_STRING( [--with-pcap@<:@=DIR@:>@],
		  [use libpcap for packet capturing @<:@default=yes@:>@]),
[
	if test $withval = no
	then
		want_pcap=no
	elif test $withval = yes
	then
		want_pcap=yes
	else
		want_pcap=yes
		pcap_dir=$withval
	fi
],[
	want_pcap=yes
	pcap_dir=
])
if test "x$want_pcap" = "xno" ; then
	AC_MSG_RESULT(no)
else
	AC_MSG_RESULT(yes)
	AC_WIRESHARK_PCAP_CHECK
fi

dnl dumpcap check
AC_MSG_CHECKING(whether to build dumpcap)

AC_ARG_ENABLE(dumpcap,
  AC_HELP_STRING( [--enable-dumpcap],
		  [build dumpcap @<:@default=yes@:>@]),
    enable_dumpcap=$enableval,enable_dumpcap=yes)

if test "x$enable_dumpcap" = "xyes" ; then
	if test "x$want_pcap" = "xno" ; then
		enable_dumpcap=no
		AC_MSG_RESULT(pcap not available - disabling dumpcap)
	else
		AC_MSG_RESULT(yes)
	fi
else
	AC_MSG_RESULT(no)
fi

if test "x$enable_dumpcap" = "xyes" ; then
	dumpcap_bin="dumpcap\$(EXEEXT)"
	dumpcap_man="dumpcap.1"
else
	dumpcap_bin=""
	dumpcap_man=""
fi
AC_SUBST(dumpcap_bin)
AC_SUBST(dumpcap_man)

# Enable/disable rawshark

dnl rawshark check
AC_MSG_CHECKING(whether to build rawshark)

AC_ARG_ENABLE(rawshark,
  AC_HELP_STRING( [--enable-rawshark],
		  [build rawshark @<:@default=yes@:>@]),
    rawshark=$enableval,enable_rawshark=yes)

if test "x$enable_rawshark" = "xyes" ; then
	if test "x$want_pcap" = "xno" ; then
		enable_rawshark=no
		AC_MSG_RESULT(pcap not available - disabling rawshark)
	else
		AC_MSG_RESULT(yes)
	fi
else
	AC_MSG_RESULT(no)
fi

if test "x$enable_rawshark" = "xyes" ; then
	rawshark_bin="rawshark\$(EXEEXT)"
	rawshark_man="rawshark.1"
else
	rawshark_bin=""
	rawshark_man=""
fi
AC_SUBST(rawshark_bin)
AC_SUBST(rawshark_man)

# Enable/disable echld
AC_ARG_ENABLE(echld,
  AC_HELP_STRING( [--enable-echld],
		  [support echld (Experimental) @<:@default=no@:>@]),
    have_echld=$enableval,have_echld=no)

AM_CONDITIONAL(HAVE_ECHLD, test "x$have_echld" = "xyes")
if test "x$have_echld" = "xyes"
then
  AC_DEFINE(HAVE_ECHLD, 1, [Define if echld is enabled])
  echld_test_bin="echld_test\$(EXEEXT)"
  echld_dir="echld"
else
  have_echld="no"
  echld_test_bin=""
  echld_dir=""
fi
AC_SUBST(echld_test_bin)
AC_SUBST(echld_dir)

# Enable/disable tfshark
AC_ARG_ENABLE(tfshark,
  AC_HELP_STRING( [--enable-tfshark],
		  [build tfshark (Experimental) @<:@default=no@:>@]),
    tfshark=$enableval,enable_tfshark=no)

if test "x$enable_tfshark" = "xyes" ; then
	tfshark_bin="tfshark\$(EXEEXT)"
	tfshark_man="tfshark.1"
	wiresharkfilter_man="wireshark-filter.4"
else
	tfshark_bin=""
	tfshark_man=""
fi
AC_SUBST(tfshark_bin)
AC_SUBST(tfshark_man)


dnl Use pcap-ng by default
AC_ARG_ENABLE(pcap-ng-default,
  AC_HELP_STRING( [--enable-pcap-ng-default],
		  [use the pcap-ng file format by default instead of pcap @<:@default=yes@:>@]),
    enable_pcap_ng_default=$enableval,enable_pcap_ng_default=yes)
if test x$enable_pcap_ng_default = xyes; then
	AC_DEFINE(PCAP_NG_DEFAULT, 1, [Support for pcap-ng])
fi

dnl pcap remote check
AC_MSG_CHECKING(whether to use libpcap remote capturing feature)

AC_ARG_WITH(pcap-remote,
    AC_HELP_STRING([--with-pcap-remote],
		   [use libpcap remote capturing (requires libpcap)]),
[
    if test $withval = no
    then
	want_pcap_remote=no
    else
	want_pcap_remote=yes
    fi
],[
    want_pcap_remote=no
])
if test "x$want_pcap_remote" = "xno" -o "x$want_pcap" = "xno" ; then
    AC_MSG_RESULT(no)
else
    AC_MSG_RESULT(yes)
    AC_WIRESHARK_PCAP_REMOTE_CHECK
fi

dnl zlib check
AC_MSG_CHECKING(whether to use zlib for gzip compression and decompression)

AC_ARG_WITH(zlib,
  AC_HELP_STRING([--with-zlib@<:@=DIR@:>@],
		 [use zlib (located in directory DIR, if supplied) for gzip compression and decompression @<:@default=yes, if available@:>@]),
[
	if test "x$withval" = "xno"
	then
		want_zlib=no
	elif test "x$withval" = "xyes"
	then
		want_zlib=yes
	else
		want_zlib=yes
		zlib_dir="$withval"
	fi
],[
	#
	# Use zlib if it's present, otherwise don't.
	#
	want_zlib=ifavailable
	zlib_dir=
])
if test "x$want_zlib" = "xno" ; then
	AC_MSG_RESULT(no)
else
	AC_MSG_RESULT(yes)
	AC_WIRESHARK_ZLIB_CHECK
	if test "x$want_zlib" = "xno" ; then
		AC_MSG_RESULT(zlib not found - disabling gzip compression and decompression)
	else
		if test "x$ac_cv_func_inflatePrime" = "xno" ; then
			AC_MSG_RESULT(inflatePrime not found in zlib - disabling gzipped capture file support)
		fi
	fi
fi

dnl Lua check
AC_ARG_WITH(lua,
  AC_HELP_STRING( [--with-lua@<:@=DIR@:>@],
		  [use liblua (located in directory DIR, if supplied) for the Lua scripting plugin @<:@default=yes, if available@:>@]),
[
	if test $withval = no
	then
		want_lua=no
	elif test $withval = yes
	then
		want_lua=yes
	else
		want_lua=yes
		want_lua_dir=$withval
	fi
],[
	# By default use Lua if we can find it
	want_lua=ifavailable
	lua_dir=
])
if test "x$want_lua" != "xno" ; then
	AC_WIRESHARK_LIBLUA_CHECK

	if test "x$want_lua" = "xyes" -a "x$have_lua" = "xno"
	then
		AC_MSG_ERROR([Lua support was requested, but is not available])
	fi
fi
if test "x$have_lua" = "xyes"
then
	AC_DEFINE(HAVE_LUA, 1, [Define to use Lua])
fi
AM_CONDITIONAL(HAVE_LIBLUA, test x$have_lua = xyes)
AC_SUBST(LUA_LIBS)
AC_SUBST(LUA_CFLAGS)


dnl portaudio check
AC_MSG_CHECKING(whether to use libportaudio for the GTK+ RTP player)

AC_ARG_WITH(portaudio,
  AC_HELP_STRING( [--with-portaudio@<:@=DIR@:>@],
		  [use libportaudio (located in directory DIR, if supplied) for the GTK+ RTP player @<:@default=yes, if available@:>@]),
[
	if test $withval = no
	then
		want_portaudio=no
	elif test $withval = yes
	then
		want_portaudio=yes
	else
		want_portaudio=yes
		portaudio_dir=$withval
	fi
],[
	#
	# Use libportaudio by default
	#
	want_portaudio=ifavailable
	portaudio_dir=
])
if test "x$want_portaudio" = "xno" ; then
	AC_MSG_RESULT(no)
else
	AC_MSG_RESULT(yes)
	AC_WIRESHARK_LIBPORTAUDIO_CHECK
	if test "x$want_portaudio" = "xno" ; then
		AC_MSG_RESULT(libportaudio not found - disabling support for the GTK+ RTP player)
	fi
fi
AM_CONDITIONAL(HAVE_LIBPORTAUDIO, test x$want_portaudio = xyes)


dnl Check if dumpcap should be installed with filesystem capabilities
AC_PATH_PROG(SETCAP, setcap)
AC_ARG_ENABLE(setcap-install,
  AC_HELP_STRING( [--enable-setcap-install],
		  [install dumpcap with cap_net_admin and cap_net_raw @<:@default=no@:>@]),
    enable_setcap_install=$enableval,enable_setcap_install=no)

AC_MSG_CHECKING(whether to install dumpcap with cap_net_admin and cap_net_raw capabilities)
if test "x$enable_setcap_install" = "xno" ; then
	AC_MSG_RESULT(no)
else
	if test "x$SETCAP" = "x" ; then
		AC_MSG_RESULT(setcap not found)
		AC_MSG_ERROR([Setcap install was requested, but setcap was not found])
	elif test "x$enable_dumpcap" = "xno" ; then
		AC_MSG_RESULT(dumpcap disabled)
		AC_MSG_ERROR([Setcap install works only with dumpcap, but dumpcap is disabled])
	else
		AC_MSG_RESULT(yes)
	fi
fi

AM_CONDITIONAL(SETCAP_INSTALL, test x$enable_setcap_install = xyes)

dnl Check if dumpcap should be installed setuid
AC_ARG_ENABLE(setuid-install,
  AC_HELP_STRING( [--enable-setuid-install],
		  [install dumpcap as setuid @<:@default=no@:>@]),
    enable_setuid_install=$enableval,enable_setuid_install=no)

AC_MSG_CHECKING(whether to install dumpcap setuid)
if test "x$enable_setuid_install" = "xno" ; then
	AC_MSG_RESULT(no)
else
	if test "x$enable_setcap_install" = "xyes" ; then
		enable_setuid_install=no
		AC_MSG_RESULT(setcap and setuid both selected)
		AC_MSG_ERROR(You must choose one of setcap install and setuid install)
	elif test "x$enable_dumpcap" = "xno" ; then
		AC_MSG_RESULT(dumpcap disabled)
		AC_MSG_ERROR([Setuid install works only with dumpcap, but dumpcap is disabled])
	else
		AC_MSG_RESULT(yes)
	fi
fi

AM_CONDITIONAL(SETUID_INSTALL, test x$enable_setuid_install = xyes)
AC_CHECK_FUNCS(setresuid setresgid)

dnl ...but our Network Operations group is named "no"!
DUMPCAP_GROUP=''
AC_ARG_WITH(dumpcap-group,
  AC_HELP_STRING( [--with-dumpcap-group=GROUP],
		  [restrict dumpcap to GROUP]),
[
  if test "x$withval" = "xyes"; then
      AC_MSG_ERROR([No dumpcap group specified.])
  elif test "x$withval" != "xno"; then
      if test "x$enable_dumpcap" = "xno" ; then
	  AC_MSG_ERROR(dumpcap group install works only with dumpcap but dumpcap is disabled)
      fi
      AC_MSG_RESULT($withval)
      DUMPCAP_GROUP="$withval"
  fi
])
AC_SUBST(DUMPCAP_GROUP)
AM_CONDITIONAL(HAVE_DUMPCAP_GROUP, test x$DUMPCAP_GROUP != x)

dnl libcap (not libpcap) check
LIBCAP_LIBS=''
AC_MSG_CHECKING(whether to use the libcap capabilities library)

AC_ARG_WITH(libcap,
  AC_HELP_STRING( [--with-libcap@<:@=DIR@:>@],
		  [use libcap (located in directory DIR, if supplied) for POSIX.1e capabilities management @<:@default=yes, if present@:>@]),
[
if   test "x$withval" = "xno";  then
	want_libcap=no
elif test "x$withval" = "xyes"; then
	want_libcap=yes
elif test -d "$withval"; then
	want_libcap=yes
	AC_WIRESHARK_ADD_DASH_L(WS_LDFLAGS, ${withval}/lib)
fi
])
if test "x$with_libcap" = "xno" ; then
	AC_MSG_RESULT(no)
else
	AC_MSG_RESULT(yes)
	AC_WIRESHARK_LIBCAP_CHECK
fi
AC_SUBST(LIBCAP_LIBS)

dnl Checks for header files.
dnl Some of these may not be needed: http://hacks.owlfolio.org/header-survey/
dnl Note, however, that, whilst this script is generally run only on UN*Xes:
dnl
dnl     1) we also support building on and for Windows and not all of those
dnl	   headers are present on Windows, so the code has to check a
dnl	   #define *anyway* to determine whether to include the header
dnl	   file
dnl
dnl and
dnl
dnl     2) this might also be run on Windows with a sufficiently UNIXy
dnl	   environment such as Cygwin (although Wireshark should be built
dnl	   natively rather than using Cygwin).
dnl
AC_CHECK_HEADERS(fcntl.h getopt.h grp.h inttypes.h netdb.h pwd.h unistd.h)
AC_CHECK_HEADERS(sys/ioctl.h sys/param.h sys/socket.h sys/sockio.h sys/stat.h sys/time.h sys/types.h sys/utsname.h sys/wait.h)
AC_CHECK_HEADERS(netinet/in.h)
AC_CHECK_HEADERS(arpa/inet.h arpa/nameser.h)
AC_CHECK_HEADERS(ifaddrs.h)

#
# On Linux, check for some additional headers, which we need as a
# workaround for a bonding driver bug and for libpcap's current lack
# of its own workaround for that bug.
#
case "$host_os" in
linux*)
	AC_CHECK_HEADERS(linux/sockios.h linux/if_bonding.h,,,[#include <sys/socket.h>])
	;;
esac

dnl SSL Check
SSL_LIBS=''
AC_MSG_CHECKING(whether to use SSL library)

AC_ARG_WITH(ssl,
  AC_HELP_STRING( [--with-ssl@<:@=DIR@:>@],
		  [use SSL crypto library (located in directory DIR, if supplied) @<:@default=no@:>@]),
[
if test "x$withval" = "xno";  then
	want_ssl=no
elif test "x$withval" = "xyes"; then
	want_ssl=yes
elif test -d "$withval"; then
	want_ssl=yes
	AC_WIRESHARK_ADD_DASH_L(WS_LDFLAGS, ${withval}/lib)
fi
],[
	want_ssl=no
])
if test "x$want_ssl" = "xyes"; then
	AC_MSG_RESULT(yes)
	AC_CHECK_LIB(crypto,EVP_md5,
	    [
		SSL_LIBS=-lcrypto
	    ],
	    [
		AC_MSG_ERROR([SSL crypto library was requested, but is not available])
	    ])
else
	AC_MSG_RESULT(no)
fi
AC_SUBST(SSL_LIBS)

dnl kerberos check
AC_MSG_CHECKING(whether to use Kerberos library)

AC_ARG_WITH(krb5,
  AC_HELP_STRING( [--with-krb5@<:@=DIR@:>@],
		  [use Kerberos library (located in directory DIR, if supplied) to use in Kerberos dissection @<:@default=yes@:>@]),
[
	if test $withval = no
	then
		want_krb5=no
	elif test $withval = yes
	then
		want_krb5=yes
	else
		want_krb5=yes
		krb5_dir=$withval
	fi
],[
	#
	# Use Kerberos library if available, otherwise don't.
	#
	want_krb5=ifavailable
	krb5_dir=
])
if test "x$want_krb5" = "xno" ; then
	AC_MSG_RESULT(no)
else
	AC_MSG_RESULT(yes)
	AC_WIRESHARK_KRB5_CHECK
fi


dnl c-ares Check
C_ARES_LIBS=''
AC_MSG_CHECKING(whether to use the c-ares library if available)

AC_ARG_WITH(c-ares,
  AC_HELP_STRING( [--with-c-ares@<:@=DIR@:>@],
		  [use c-ares (located in directory DIR, if supplied) @<:@default=yes, if present@:>@]),
[
if   test "x$withval" = "xno";  then
	want_c_ares=no
elif test "x$withval" = "xyes"; then
	want_c_ares=yes
elif test -d "$withval"; then
	want_c_ares=yes
	AC_WIRESHARK_ADD_DASH_L(WS_LDFLAGS, ${withval}/lib)
fi
])
if test "x$want_c_ares" = "xno" ; then
	AC_MSG_RESULT(no)
else
	AC_MSG_RESULT(yes)
	AC_WIRESHARK_C_ARES_CHECK
fi
AC_SUBST(C_ARES_LIBS)

dnl GEOIP Check
GEOIP_LIBS=''
AC_MSG_CHECKING(whether to use the GeoIP IP address mapping library if available)

AC_ARG_WITH(geoip,
  AC_HELP_STRING( [--with-geoip@<:@=DIR@:>@],
		  [use GeoIP (located in directory DIR, if supplied) @<:@default=yes, if present@:>@]),
[
if   test "x$withval" = "xno";  then
	want_geoip=no
elif test "x$withval" = "xyes"; then
	want_geoip=yes
elif test -d "$withval"; then
	want_geoip=yes
	AC_WIRESHARK_ADD_DASH_L(WS_LDFLAGS, ${withval}/lib)
fi
])
if test "x$want_geoip" = "xno"; then
	AC_MSG_RESULT(no)
else
	AC_MSG_RESULT(yes)
	AC_WIRESHARK_GEOIP_CHECK
fi
AC_SUBST(GEOIP_LIBS)

dnl LIBSSH Check
LIBSSH=''
AC_MSG_CHECKING(whether to use the libssh library if available)

AC_ARG_WITH(ssh,
  AC_HELP_STRING( [--with-libssh@<:@=DIR@:>@],
		  [use libssh (located in directory DIR, if supplied) @<:@default=yes, if present@:>@]),
[
if   test "x$withval" = "xno";  then
	want_libssh=no
elif test "x$withval" = "xyes"; then
	want_libssh=yes
elif test -d "$withval"; then
	want_libssh=yes
	AC_WIRESHARK_ADD_DASH_L(WS_LDFLAGS, ${withval}/lib)
fi
])
if test "x$want_libssh" = "xno"; then
	AC_MSG_RESULT(no)
else
	AC_MSG_RESULT(yes)
	AC_WIRESHARK_LIBSSH_CHECK
fi
AC_SUBST(LIBSSH_LIBS)

dnl Checks for typedefs, structures, and compiler characteristics.
# AC_C_CONST

# Check how we can get the time zone abbreviation
AC_STRUCT_TIMEZONE

# We need to know whether "struct stat" has an "st_flags" member
# for file_user_immutable().

AC_CHECK_MEMBERS([struct stat.st_flags])

# We need to know whether "struct stat" has an "st_birthtime" member
# or an "__st_birthtime" member for the file set dialog.

AC_CHECK_MEMBERS([struct stat.st_birthtime])
AC_CHECK_MEMBERS([struct stat.__st_birthtime])

# We need to know whether "struct sockaddr" has an "sa_len" member
# for get_interface_list().

AC_CHECK_MEMBERS([struct sockaddr.sa_len])

# We must know our byte order
AC_C_BIGENDIAN

# Checks whether "-traditional" is needed when using "ioctl".
# XXX - do we need this?
AC_PROG_GCC_TRADITIONAL

AC_REPLACE_FUNCS(getopt_long)
dnl
dnl Do we have optreset?
dnl
if test "x$ac_cv_func_getopt_long" = xyes; then
  AC_CACHE_CHECK([whether optreset is defined], ac_cv_have_optreset,
    AC_LINK_IFELSE([AC_LANG_SOURCE([[extern int optreset;return optreset;]])],
        ac_cv_have_optreset=yes, ac_cv_have_optreset=no))
  if test "$ac_cv_have_optreset" = yes ; then
    AC_DEFINE(HAVE_OPTRESET, 1, [Define to 1 if you have the optreset variable])
  fi
fi

AC_REPLACE_FUNCS(inet_aton)

AC_CHECK_FUNC(inet_pton, [
  dnl check for pre-BIND82 inet_pton() bug.
  AC_MSG_CHECKING(for broken inet_pton)
  AC_TRY_RUN([#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
int main()
{
#ifdef AF_INET6
  char buf[16];
  /* this should return 0 (error) */
  return inet_pton(AF_INET6, "0:1:2:3:4:5:6:7:", buf);
#else
  return 1;
#endif
}], [AC_MSG_RESULT(ok);
have_inet_pton=yes], [AC_MSG_RESULT(broken);
have_inet_pton=no], [AC_MSG_RESULT([cross compiling, assume it is broken]);
have_inet_pton=no])],
have_inet_pton=no)
if test "$have_inet_pton" = no; then
  AC_LIBOBJ(inet_pton)
else
  AC_DEFINE(HAVE_INET_PTON, 1, [Define to 1 if you have the `inet_pton' function.])
fi

AC_REPLACE_FUNCS(inet_ntop)
AC_REPLACE_FUNCS(strptime)
AC_REPLACE_FUNCS(popcount)

AC_CHECK_FUNCS(mkstemps mkdtemp)
AC_CHECK_FUNCS(getprotobynumber)
AC_CHECK_FUNCS(issetugid)
AC_CHECK_FUNCS(sysconf)
AC_CHECK_FUNCS(getifaddrs)
AC_CHECK_FUNC(getexecname)

#
# Check for SpeexDSP (http://www.speex.org)
#
AS_IF([test "x$have_qt_multimedia_lib" = xyes],
	[PKG_CHECK_MODULES(SPEEXDSP, speexdsp, [have_speexdsp=yes], [have_speexdsp=no])])
AS_IF([test "x$have_speexdsp" = xyes],
	[AC_DEFINE(HAVE_SPEEXDSP, 1, [Define to 1 if you have SpeexDSP])])
AM_CONDITIONAL(HAVE_SPEEXDSP, [test "x$have_speexdsp" = "xyes"])

# Check Bluetooth SBC codec for RTP Player
# git://git.kernel.org/pub/scm/bluetooth/sbc.git
AC_ARG_WITH([sbc],
  AC_HELP_STRING( [--with-sbc=@<:@yes/no@:>@],
		  [use SBC codec to play Bluetooth A2DP stream @<:@default=yes, if available@:>@]),
  with_sbc="$withval"; want_sbc="yes", with_sbc="yes")

PKG_CHECK_MODULES(SBC, sbc >= 1.0, [have_sbc=yes], [have_sbc=no])
if test "x$with_sbc" != "xno"; then
    if (test "${have_sbc}" = "yes"); then
	AC_DEFINE(HAVE_SBC, 1, [Define to support playing SBC by standalone BlueZ SBC library])
    elif test "x$want_sbc" = "xyes"; then
	# Error out if the user explicitly requested the sbc library
	AC_MSG_ERROR([SBC codec library was requested, but is not available])
    fi
else
    have_sbc=no
fi
AM_CONDITIONAL(HAVE_SBC, test "x$have_sbc" = "xyes")

dnl
dnl check whether plugins should be enabled and, if they should be,
dnl check for plugins directory - stolen from Amanda's configure.ac
dnl
dnl we don't wish to expand ${libdir} yet
plugindir="\${libdir}/wireshark/plugins/${VERSION}"
AC_ARG_WITH(plugins,
  AC_HELP_STRING( [--with-plugins@<:@=DIR@:>@],
		  [support plugins (installed in DIR, if supplied) @<:@default=yes, if possible@:>@]),
[
  if test "x$withval" = "xno"; then
    have_plugins=no
  elif test "x$have_plugins" = "xno"; then
      AC_MSG_ERROR([GLib on this platform doesn't support loadable modules, so you can't enable plugins.])
  elif test "x$withval" != "xyes"; then
      plugindir="$withval"
  fi
])
AM_CONDITIONAL(HAVE_PLUGINS, test "x$have_plugins" = "xyes")
if test x$have_plugins = xyes
then
  AC_DEFINE(HAVE_PLUGINS, 1, [Define if plugins are enabled])
fi
AC_SUBST(plugindir)

#
# The plugin dissectors reside in ./plugins/PROTO/
#
PLUGIN_LIBS=""
AC_SUBST(PLUGIN_LIBS)

dnl
dnl check whether extcap programs should be enabled and, if they should be,
dnl check for extcap directory - stolen from Amanda's configure.ac
dnl
dnl we don't wish to expand ${libdir} yet
extcapdir="\${libdir}/wireshark/extcap"
AC_ARG_WITH(extcap,
  AC_HELP_STRING( [--with-extcap@<:@=DIR@:>@],
		  [use extcap for external capture sources (installed in DIR, if supplied) @<:@default=yes, if possible@:>@]),
[
  if test "x$withval" = "xno"; then
      have_extcap=no
  elif test "x$withval" = "xyes"; then
      have_extcap=yes
  elif test "x$withval" != "xyes"; then
      have_extcap=yes
      extcapdir ="$withval"
  fi
],[
    have_extcap=yes
])
AM_CONDITIONAL(HAVE_EXTCAP, test "x$have_extcap" = "xyes")
if test "x$have_extcap" = "xyes"
then
  AC_DEFINE(HAVE_EXTCAP, 1, [Define if external capture sources should be enabled])
  extcap_subdir="extcap"
  extcap_man="extcap.4"
fi
AC_SUBST(extcap_subdir)
AC_SUBST(extcap_man)
AC_SUBST(extcapdir)

dnl androiddump check
AC_MSG_CHECKING(whether to build androiddump)

AC_ARG_ENABLE(androiddump,
  AC_HELP_STRING( [--enable-androiddump],
		  [build androiddump @<:@default=yes@:>@]),
    androiddump=$enableval,enable_androiddump=yes)

if test "x$have_extcap" != xyes; then
	AC_MSG_RESULT([no, extcap disabled])
	enable_androiddump=no
elif test "x$enable_androiddump" = "xyes" ; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

AC_ARG_ENABLE(androiddump_use_libpcap,
  AC_HELP_STRING( [--enable-androiddump-use-libpcap],
		  [build androiddump using libpcap @<:@default=no@:>@]),
    androiddump_use_libpcap=$enableval,enable_androiddump_use_libpcap=no)

if test "x$enable_androiddump" = "xyes" -a "x$enable_androiddump_use_libpcap" = "xyes" ; then
	AC_DEFINE(ANDROIDDUMP_USE_LIBPCAP, 1, [Androiddump will use Libpcap])
fi

if test "x$enable_androiddump" = "xyes" ; then
	androiddump_bin="androiddump\$(EXEEXT)"
	androiddump_man="androiddump.1"
else
	androiddump_bin=""
	androiddump_man=""
fi
AC_SUBST(androiddump_bin)
AC_SUBST(androiddump_man)

dnl sshdump check
AC_MSG_CHECKING(whether to build sshdump)

AC_ARG_ENABLE(sshdump,
	AC_HELP_STRING( [--enable-sshdump],
		[build sshdump @<:@default=yes@:>@]),
	[],[enable_sshdump=yes])

if test "x$have_extcap" != xyes; then
	AC_MSG_RESULT([no, extcap disabled])
	enable_sshdump=no
elif test "x$have_libssh_pointsix" != xyes; then
	AC_MSG_RESULT([no, libssh >= 0.6.0 not available])
	enable_sshdump=no
elif test "x$enable_sshdump" = "xyes" ; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

if test "x$enable_sshdump" = "xyes" ; then
	sshdump_bin="sshdump\$(EXEEXT)"
	sshdump_man="sshdump.1"
else
	sshdump_bin=""
	sshdump_man=""
fi
AC_SUBST(sshdump_bin)
AC_SUBST(sshdump_man)

dnl ciscodump check
AC_MSG_CHECKING(whether to build ciscodump)

AC_ARG_ENABLE(ciscodump,
	AC_HELP_STRING( [--enable-ciscodump],
		[build ciscodump @<:@default=yes@:>@]),
	[],[enable_ciscodump=yes])

if test "x$have_extcap" != xyes; then
	AC_MSG_RESULT([no, extcap disabled])
	enable_ciscodump=no
elif test "x$have_libssh_pointsix" != xyes; then
	AC_MSG_RESULT([no, libssh >= 0.6.0 not available])
	enable_ciscodump=no
elif test "x$enable_ciscodump" = "xyes" ; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

if test "x$enable_ciscodump" = "xyes" ; then
	ciscodump_bin="ciscodump\$(EXEEXT)"
	ciscodump_man="ciscodump.1"
else
	ciscodump_bin=""
	ciscodump_man=""
fi
AC_SUBST(ciscodump_bin)
AC_SUBST(ciscodump_man)

dnl randpktdump check
AC_MSG_CHECKING(whether to build randpktdump)

AC_ARG_ENABLE(randpktdump,
	AC_HELP_STRING( [--enable-randpktdump],
		[build randpktdump @<:@default=yes@:>@]),
	randpktdump=$enableval,enable_randpktdump=yes)

if test "x$have_extcap" != xyes; then
	AC_MSG_RESULT([no, extcap disabled])
	enable_randpktdump=no
elif test "x$enable_randpktdump" = "xyes" ; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

if test "x$enable_randpktdump" = "xyes" ; then
	randpktdump_bin="randpktdump\$(EXEEXT)"
	randpktdump_man="randpktdump.1"
else
	randpktdump_bin=""
	randpktdump_man=""
fi
AC_SUBST(randpktdump_bin)
AC_SUBST(randpktdump_man)

AM_CONDITIONAL(ENABLE_STATIC, test x$enable_static = xyes)
if test x$enable_static = xyes -a x$have_plugins = xyes
then
  AC_DEFINE(ENABLE_STATIC, 1, [Link plugins statically into Wireshark])
fi
AC_SUBST(ENABLE_STATIC)

# Gather which GUI we're building for rpmbuild
if test "x$have_gtk" = "xyes"; then
	if test "x$gtk_major_version" = "x3"; then
		RPMBUILD_WITH_ARGS="--with gtk3 --without gtk2"
	else
		RPMBUILD_WITH_ARGS="--without gtk3 --with gtk2"
	fi
else
	RPMBUILD_WITH_ARGS="--without gtk2 --without gtk3"
fi
if test "x$have_qt" = "xyes" ; then
	if test "$qt_version" -eq "5"; then
		RPMBUILD_WITH_ARGS="$RPMBUILD_WITH_ARGS --with qt5"
	else
		RPMBUILD_WITH_ARGS="$RPMBUILD_WITH_ARGS --with qt"
	fi
else
	RPMBUILD_WITH_ARGS="$RPMBUILD_WITH_ARGS --without qt --without qt5"
fi
if test "x$have_lua" = "xyes" ; then
	RPMBUILD_WITH_ARGS="$RPMBUILD_WITH_ARGS --with lua"
else
	RPMBUILD_WITH_ARGS="$RPMBUILD_WITH_ARGS --without lua"
fi
AC_SUBST(RPMBUILD_WITH_ARGS)
AC_SUBST(RPM_VERSION, version_major.version_minor.version_micro)

AC_SUBST(WS_CPPFLAGS)
AC_SUBST(WS_CFLAGS)
AC_SUBST(WS_CXXFLAGS)
AC_SUBST(WS_LDFLAGS)

AC_SUBST(WS_CFLAGS_FOR_BUILD)

AH_BOTTOM([#include <ws_diag_control.h>])

dnl Save the cacheable configure results to config.cache before recursing
AC_CACHE_SAVE

sinclude(plugins/Custom.m4) dnl
ifdef(_CUSTOM_AC_OUTPUT_,, define(_CUSTOM_AC_OUTPUT_, )) dnl

sinclude(epan/dissectors/asn1/Custom.m4) dnl
ifdef(_CUSTOM_ASN1_AC_OUTPUT_,, define(_CUSTOM_ASN1_AC_OUTPUT_, )) dnl

AC_CONFIG_HEADERS([config.h])

AC_CONFIG_FILES(
  Makefile
  doxygen.cfg
  epan/dissectors/asn1/Makefile
  wireshark.pc
  _CUSTOM_ASN1_AC_OUTPUT_
  epan/dissectors/asn1/acp133/Makefile
  epan/dissectors/asn1/acse/Makefile
  epan/dissectors/asn1/ansi_map/Makefile
  epan/dissectors/asn1/ansi_tcap/Makefile
  epan/dissectors/asn1/atn-cm/Makefile
  epan/dissectors/asn1/atn-cpdlc/Makefile
  epan/dissectors/asn1/atn-ulcs/Makefile
  epan/dissectors/asn1/c1222/Makefile
  epan/dissectors/asn1/camel/Makefile
  epan/dissectors/asn1/cdt/Makefile
  epan/dissectors/asn1/charging_ase/Makefile
  epan/dissectors/asn1/cmip/Makefile
  epan/dissectors/asn1/cmp/Makefile
  epan/dissectors/asn1/crmf/Makefile
  epan/dissectors/asn1/cms/Makefile
  epan/dissectors/asn1/credssp/Makefile
  epan/dissectors/asn1/dap/Makefile
  epan/dissectors/asn1/disp/Makefile
  epan/dissectors/asn1/dop/Makefile
  epan/dissectors/asn1/dsp/Makefile
  epan/dissectors/asn1/ess/Makefile
  epan/dissectors/asn1/ftam/Makefile
  epan/dissectors/asn1/goose/Makefile
  epan/dissectors/asn1/gprscdr/Makefile
  epan/dissectors/asn1/gsm_map/Makefile
  epan/dissectors/asn1/h225/Makefile
  epan/dissectors/asn1/h235/Makefile
  epan/dissectors/asn1/h245/Makefile
  epan/dissectors/asn1/h248/Makefile
  epan/dissectors/asn1/h282/Makefile
  epan/dissectors/asn1/h283/Makefile
  epan/dissectors/asn1/h323/Makefile
  epan/dissectors/asn1/h450/Makefile
  epan/dissectors/asn1/h450-ros/Makefile
  epan/dissectors/asn1/h460/Makefile
  epan/dissectors/asn1/h501/Makefile
  epan/dissectors/asn1/HI2Operations/Makefile
  epan/dissectors/asn1/hnbap/Makefile
  epan/dissectors/asn1/idmp/Makefile
  epan/dissectors/asn1/ilp/Makefile
  epan/dissectors/asn1/inap/Makefile
  epan/dissectors/asn1/isdn-sup/Makefile
  epan/dissectors/asn1/kerberos/Makefile
  epan/dissectors/asn1/lcsap/Makefile
  epan/dissectors/asn1/ldap/Makefile
  epan/dissectors/asn1/logotypecertextn/Makefile
  epan/dissectors/asn1/lpp/Makefile
  epan/dissectors/asn1/lppa/Makefile
  epan/dissectors/asn1/lppe/Makefile
  epan/dissectors/asn1/lte-rrc/Makefile
  epan/dissectors/asn1/m3ap/Makefile
  epan/dissectors/asn1/mms/Makefile
  epan/dissectors/asn1/mpeg-audio/Makefile
  epan/dissectors/asn1/mpeg-pes/Makefile
  epan/dissectors/asn1/nbap/Makefile
  epan/dissectors/asn1/ns_cert_exts/Makefile
  epan/dissectors/asn1/novell_pkis/Makefile
  epan/dissectors/asn1/ocsp/Makefile
  epan/dissectors/asn1/p1/Makefile
  epan/dissectors/asn1/p22/Makefile
  epan/dissectors/asn1/p7/Makefile
  epan/dissectors/asn1/p772/Makefile
  epan/dissectors/asn1/pcap/Makefile
  epan/dissectors/asn1/pkcs1/Makefile
  epan/dissectors/asn1/pkcs12/Makefile
  epan/dissectors/asn1/pkinit/Makefile
  epan/dissectors/asn1/pkixac/Makefile
  epan/dissectors/asn1/pkix1explicit/Makefile
  epan/dissectors/asn1/pkix1implicit/Makefile
  epan/dissectors/asn1/pkixproxy/Makefile
  epan/dissectors/asn1/pkixqualified/Makefile
  epan/dissectors/asn1/pkixtsp/Makefile
  epan/dissectors/asn1/pres/Makefile
  epan/dissectors/asn1/q932/Makefile
  epan/dissectors/asn1/q932-ros/Makefile
  epan/dissectors/asn1/qsig/Makefile
  epan/dissectors/asn1/ranap/Makefile
  epan/dissectors/asn1/rnsap/Makefile
  epan/dissectors/asn1/ros/Makefile
  epan/dissectors/asn1/rrc/Makefile
  epan/dissectors/asn1/rrlp/Makefile
  epan/dissectors/asn1/rtse/Makefile
  epan/dissectors/asn1/rua/Makefile
  epan/dissectors/asn1/s1ap/Makefile
  epan/dissectors/asn1/sabp/Makefile
  epan/dissectors/asn1/sbc-ap/Makefile
  epan/dissectors/asn1/smrse/Makefile
  epan/dissectors/asn1/snmp/Makefile
  epan/dissectors/asn1/spnego/Makefile
  epan/dissectors/asn1/sv/Makefile
  epan/dissectors/asn1/t124/Makefile
  epan/dissectors/asn1/t125/Makefile
  epan/dissectors/asn1/t38/Makefile
  epan/dissectors/asn1/tcap/Makefile
  epan/dissectors/asn1/tetra/Makefile
  epan/dissectors/asn1/ulp/Makefile
  epan/dissectors/asn1/wlancertextn/Makefile
  epan/dissectors/asn1/x2ap/Makefile
  epan/dissectors/asn1/x509af/Makefile
  epan/dissectors/asn1/x509ce/Makefile
  epan/dissectors/asn1/x509if/Makefile
  epan/dissectors/asn1/x509sat/Makefile
  epan/dissectors/asn1/x721/Makefile
  capchild/Makefile
  capchild/doxygen.cfg
  caputils/Makefile
  caputils/doxygen.cfg
  doc/Makefile
  docbook/Makefile
  epan/Makefile
  epan/compress/Makefile
  epan/crypt/Makefile
  epan/doxygen.cfg
  epan/dfilter/Makefile
  epan/dissectors/Makefile
  epan/dissectors/dcerpc/Makefile
  epan/ftypes/Makefile
  epan/nghttp2/Makefile
  epan/wmem/Makefile
  epan/wslua/Makefile
  extcap/Makefile
  codecs/Makefile
  ui/Makefile
  ui/doxygen.cfg
  ui/gtk/Makefile
  ui/gtk/doxygen.cfg
  ui/cli/Makefile
  ui/qt/Makefile
  ui/qt/doxygen.cfg
  help/Makefile
  packaging/Makefile
  packaging/macosx/Info.plist
  packaging/macosx/Makefile
  packaging/macosx/osx-dmg.sh
  packaging/macosx/Wireshark_package.pmdoc/index.xml
  packaging/nsis/Makefile
  packaging/rpm/Makefile
  packaging/rpm/SPECS/Makefile
  packaging/rpm/SPECS/wireshark.spec
  packaging/svr4/Makefile
  packaging/svr4/checkinstall
  packaging/svr4/pkginfo
  packaging/wix/Makefile
  plugins/Makefile
  plugins/docsis/Makefile
  plugins/easy_codec/Makefile
  plugins/ethercat/Makefile
  plugins/gryphon/Makefile
  plugins/irda/Makefile
  plugins/m2m/Makefile
  plugins/mate/Makefile
  plugins/opcua/Makefile
  plugins/profinet/Makefile
  plugins/stats_tree/Makefile
  plugins/unistim/Makefile
  plugins/wimax/Makefile
  plugins/wimaxasncp/Makefile
  plugins/wimaxmacphy/Makefile
  randpkt_core/doxygen.cfg
  randpkt_core/Makefile
  tools/Makefile
  tools/lemon/Makefile
  wiretap/Makefile
  writecap/Makefile
  writecap/doxygen.cfg
  wsutil/Makefile
  echld/Makefile
  _CUSTOM_AC_OUTPUT_
)

AC_OUTPUT


# Pretty messages

if test "x$have_gtk" = "xyes"; then
	gtk_lib_message=" (with GTK+ v$GTK_VERSION"
	if test "x$have_ige_mac" = "xyes"; then
		gtk_lib_message="$gtk_lib_message and OS X integration)"
	else
		gtk_lib_message="$gtk_lib_message)"
	fi
fi

if test "x$have_qt" = "xyes" ; then
	enable_wireshark_qt="yes"
	qt_lib_message=" (with Qt$qt_version v$QT_VERSION)"
else
	enable_wireshark_qt="no"
fi

if test "x$enable_setcap_install" = "xyes" ; then
	setcap_message="yes"
else
	setcap_message="no"
fi

if test "x$enable_setuid_install" = "xyes" ; then
	setuid_message="yes"
else
	setuid_message="no"
fi

if test "x$DUMPCAP_GROUP" = "x" ; then
	dumpcap_group_message="(none)"
else
	dumpcap_group_message="$DUMPCAP_GROUP"
fi

if test "x$want_zlib" = "xno" ; then
	zlib_message="no"
else
	zlib_message="yes"
fi

if test "x$have_lua" = "xyes" ; then
	lua_message="yes"
else
	lua_message="no"
fi

if test "x$have_qt_multimedia_lib" = "xyes" ; then
	qt_multimedia_message="yes"
else
	qt_multimedia_message="no"
fi

if test "x$want_portaudio" = "xyes" ; then
	portaudio_message="yes"
else
	portaudio_message="no"
fi

if test "x$want_ssl" = "xno" ; then
	ssl_message="no"
else
	ssl_message="yes"
fi

if test "x$want_krb5" = "xno" ; then
	krb5_message="no"
else
	krb5_message="yes ($ac_krb5_version)"
fi

if test "x$have_good_c_ares" = "xyes" ; then
	c_ares_message="yes"
else
	c_ares_message="no (name resolution will be disabled)"
fi

if test "x$have_good_libcap" = "xyes" ; then
	libcap_message="yes"
else
	libcap_message="no"
fi

if test "x$have_good_geoip" = "xyes" ; then
	geoip_message="yes"
else
	geoip_message="no"
fi

if test "x$have_good_libssh" = "xyes" ; then
	libssh_message="yes"
else
	libssh_message="no"
fi

if test "x$have_ssh_userauth_agent" = "xyes" ; then
	ssh_userauth_agent_message="yes"
else
	ssh_userauth_agent_message="no"
fi

echo ""
echo "  CPPFLAGS: $WS_CPPFLAGS $CPPFLAGS"
echo ""
echo "  CFLAGS: $WS_CFLAGS $CFLAGS"
echo ""
echo "  CXXFLAGS: $WS_CXXFLAGS $CXXFLAGS"
echo ""
echo "  LDFLAGS: $WS_LDFLAGS $LDFLAGS"
echo ""
echo "  LIBS: $LIBS"

echo ""
echo "The Wireshark package has been configured with the following options:"
echo "                       GLib version : v$GLIB_VERSION"
echo "                    Build wireshark : $enable_wireshark_qt$qt_lib_message"
echo "                Build wireshark-gtk : $have_gtk""$gtk_lib_message"
echo "                       Build tshark : $enable_tshark"
echo "                      Build tfshark : $enable_tfshark"
echo "                     Build capinfos : $enable_capinfos"
echo "                      Build captype : $enable_captype"
echo "                      Build editcap : $enable_editcap"
echo "                      Build dumpcap : $enable_dumpcap"
echo "                     Build mergecap : $enable_mergecap"
echo "                   Build reordercap : $enable_reordercap"
echo "                    Build text2pcap : $enable_text2pcap"
echo "                      Build randpkt : $enable_randpkt"
echo "                       Build dftest : $enable_dftest"
echo "                     Build rawshark : $enable_rawshark"
echo "                  Build androiddump : $enable_androiddump"
echo "                      Build sshdump : $enable_sshdump"
echo "                    Build ciscodump : $enable_ciscodump"
echo "                  Build randpktdump : $enable_randpktdump"
echo "                        Build echld : $have_echld"
echo ""
echo "   Save files as pcap-ng by default : $enable_pcap_ng_default"
echo "  Install dumpcap with capabilities : $setcap_message"
echo "             Install dumpcap setuid : $setuid_message"
echo "                  Use dumpcap group : $dumpcap_group_message"
echo "                        Use plugins : $have_plugins"
echo "       Use external capture sources : $have_extcap"
echo "                    Use Lua library : $lua_message"
echo "                Build Qt RTP player : $qt_multimedia_message"
echo "              Build GTK+ RTP player : $portaudio_message"
echo "             Build profile binaries : $enable_profile_build"
echo "                   Use pcap library : $want_pcap"
echo "                   Use zlib library : $zlib_message"
echo "               Use kerberos library : $krb5_message"
echo "                 Use c-ares library : $c_ares_message"
echo "                Use SMI MIB library : $libsmi_message"
echo "             Use GNU gcrypt library : $gcrypt_message"
echo "             Use SSL crypto library : $ssl_message"
echo "                 Use GnuTLS library : $tls_message"
echo "     Use POSIX capabilities library : $libcap_message"
echo "                  Use GeoIP library : $geoip_message"
echo "                 Use libssh library : $libssh_message"
echo "            Have ssh_userauth_agent : $ssh_userauth_agent_message"
echo "                     Use nl library : $libnl_message"
echo "              Use SBC codec library : $have_sbc"
#echo "       Use GDK-Pixbuf with GResource: $have_gresource_pixbuf"
