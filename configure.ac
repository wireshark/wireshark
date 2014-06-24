#
# Autoconf script for Wireshark
#

#
# Define variables for the components of the Wireshark version number.
#
m4_define([version_major], [1])
m4_define([version_minor], [99])
m4_define([version_micro], [0])
m4_define([version_micro_extra], version_micro)
m4_append([version_micro_extra], [])

AC_INIT(wireshark, [version_major.version_minor.version_micro_extra], http://bugs.wireshark.org/, , http://www.wireshark.org/)
CONFIG_ARGS="$*"
AC_SUBST(CONFIG_ARGS)

# Minimum autoconf version we require.
AC_PREREQ(2.60)
# Variable expansion doesn't work in AC_PREREQ()
AC_MIN_VERSION=2.60
AC_SUBST(AC_MIN_VERSION)

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

AM_INIT_AUTOMAKE([1.9 tar-ustar dist-bzip2 no-dist-gzip])

# Make Wireshark's version available in config.h
AC_DEFINE(VERSION_MAJOR, version_major, [Wireshark's major version])
AC_DEFINE(VERSION_MINOR, version_minor, [Wireshark's minor version])
AC_DEFINE(VERSION_MICRO, version_micro, [Wireshark's micro version])

AM_DISABLE_STATIC

#
# Checks for programs used in the main build process.
#
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CXX
AC_PROG_CPP
AC_PROG_MKDIR_P

dnl Work around libtool bug (fixed in the version 1.5a?)
AC_DEFUN([AC_PROVIDE_AC_LIBTOOL_DLOPEN], )
AC_LIBTOOL_DLOPEN
AC_PROG_LIBTOOL
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
	# We do this after AC_PROG_LIBTOOL; if we did so before, and
	# cleared CXX if what we had isn't a C++ compiler, that'd
	# get undone by AC_PROG_LIBTOOL for some reason.
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
AC_PATH_PROG(PERL, perl)

# Check for Python.
AC_PATH_PROG(PYTHON, python)
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
fi

#
# XXX - should autogen.sh check for YACC/Bison and Flex?  A user building
# from a distribution tarball shouldn't have to have YACC/Bison or Flex,
# as the tarball should contain the results of running YACC/Bison on .y
# files and running Flex on .l files, but a user building from SVN
# will have to run YACC/Bison and Flex to process those files.
#
# On the other hand, what about users who use a distribution tarball to
# do development?  They *shouldn't* - that's what the SVN repository is
# for - but they might.  They'd get errors if they modify a .y or .l
# file and try to do a build - but the error should tell them that they
# need to get YACC/Bison and/or Flex.
#
# Then again, getting them shouldn't be too big of a burden.
#
# XXX - is the same true of pod2man and pod2html, or are they needed
# even when building from a distribution tarball?
#
#
AC_PROG_YACC
AC_PATH_PROG(YACCDUMMY, $YACC)
if test "x$YACCDUMMY" = x
then
	AC_MSG_ERROR(I couldn't find yacc (or bison or ...); make sure it's installed and in your path)
fi
AM_PROG_LEX
AC_PATH_PROG(LEX, flex)
if test "x$LEX" = x
then
	AC_MSG_ERROR(I couldn't find flex; make sure it's installed and in your path)
fi
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
# Checks for programs used by Wireshark/TShark/etc.
#

#
# XXX - this looks for various HTML viewers on the host, not the target;
# we really want to know what's available on the target, for cross-builds.
# That would probably require us to, at run time, look for xdg-open and,
# if we don't find it, look for mozilla, htmlview, etc.
#
AC_PATH_PROG(HTML_VIEWER, xdg-open)
if test "x$HTML_VIEWER" != x
then
	#
	# XXX - the HTML_VIEWER shell variable is the full path of xdg-open.
	# Define some variable to be that, so we just run that?
	#
	AC_DEFINE(HAVE_XDG_OPEN, 1, [Define if we have xdg-open])

	#
	# XXX - we have to define HTML_VIEWER for the prefs.c code that
	# sets the default value of the Web browser preference, even
	# though that preference won't be offered.
	#
	AC_DEFINE_UNQUOTED(HTML_VIEWER, "xdg-open", [HTML viewer, e.g. mozilla])
else
	AC_PATH_PROG(HTML_VIEWER, htmlview)
	if test "x$HTML_VIEWER" = x
	then
		AC_DEFINE_UNQUOTED(HTML_VIEWER, "mozilla", [HTML viewer, e.g. mozilla])
	else
		AC_DEFINE_UNQUOTED(HTML_VIEWER, "htmlview", [HTML viewer, e.g. mozilla])
	fi
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

#
# Set "ac_supports_W_linker_passthrough" if the compiler is known to
# support "-Wl,{options}" to pass options through to the linker.
# Currently, we assume GCC, xlc, and clang do; other compilers should
# be added here.
#
if test "x$GCC" = "xyes" -o "x$CC" = "xxlc" -o "x$CC" = "xclang" ; then
	ac_supports_W_linker_passthrough=yes
fi

#
# Set "ac_supports_attribute_unused" if the compiler is known to
# support "__attribute__(unused)".
# Currently, we assume GCC and clang do; other compilers should
# be added here.
#
# XXX - do this with a compiler test?
#
if test "x$GCC" = "xyes" -o "x$CC" = "xclang" ; then
	ac_supports_W_linker_passthrough=yes
fi

if test "x$CC_FOR_BUILD" = x
then
       CC_FOR_BUILD=$CC
fi
AC_SUBST(CC_FOR_BUILD)
AC_SUBST(CFLAGS_FOR_BUILD)

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
PKG_PROG_PKG_CONFIG

AC_ARG_ENABLE(osx-deploy-target,
  AC_HELP_STRING( [--enable-osx-deploy-target],
    [choose an OS X deployment target @<:@default=major release on which you're building@:>@]),
[
	#
	# Is this OS X?
	#
	case "$host_os" in
	darwin*)
		#
		# Yes.
		#
		# Let the user specify an OS X release to use as a
		# deplayment target; if they specify that we should
		# have a deployment target but don't specify the
		# deployment target, then, if we have SDKs available,
		# pick the OS version on which the build is being done.
		# This also causes the build to be done against an SDK
		# rather than against the headers and libraries in
		# /usr/include and /usr/lib.
		#
		# Check for an OS X deployment target early, so that
		# as many tests using the compiler are done using the
		# flags that we'll be using when building.
		#
		if test $enableval = no
		then
			#
			# The user explicitly said
			# --disable-osx-deploy-target, so don't build
			# against an SDK.
			#
			deploy_target=
		elif test $enableval = yes
		then
			#
			# The user said --enable-osx-deploy-target, but
			# didn't say what version to target; target the
			# major version number of the version of OS X on
			# which we're running.
			#
			# (We quote the command so that we can use
			# autoconf's M4 quoting characters, [ and ], in
			# the sed expression.)
			#
			[deploy_target=`sw_vers -productVersion | sed 's/\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.[0-9]*/\1.\2/'`]
		else
			deploy_target="$enableval"
		fi
		;;

	*)
		#
		# No.  Fail, because whatever the user intended for us to
		# do, we can't do it.
		#
		AC_MSG_ERROR([--enable-osx-deploy-target specified on an OS other than OS X])
		;;
	esac
],[
	#
	# Is this OS X?
	#
	case "$host_os" in
	darwin*)
		#
		# Yes.
		#
		# If we have SDKs available, default to targeting the major
		# version number of the version of OS X on which we're
		# running.
		#
		# (We quote the command so that we can use autoconf's
		# M4 quoting characters, [ and ], in the sed expression.)
		#
		for i in /Developer/SDKs \
		    /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs \
		    /Library/Developer/CommandLineTools/SDKs
		do
			if test -d "$i"
			then
				[deploy_target=`sw_vers -productVersion | sed 's/\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.[0-9]*/\1.\2/'`]
				break
			fi
		done
		;;

	*)
		#
		# No.  There's nothing to do.
		#
		;;
	esac
])

if test ! -z "$deploy_target"
then
	AC_MSG_CHECKING([whether we can build for OS X $deploy_target])
	case $deploy_target in

	10.0|10.1|10.2)
		#
		# I'm not sure this would even work.
		#
		AC_MSG_RESULT(no)
		AC_ERROR([We don't support building for OS X $deploy_target])
		;;

	10.3)
		#
		# XXX - never tested.
		#
		AC_MSG_RESULT(yes)
		SDKPATH="/Developer/SDKs/MacOSX10.3.9.sdk"
		;;

	*)
		#
		# XXX - for 10.4, do we need 10.4u?  We're
		# not currently doing fat builds (we'd need
		# fat versions of the support libraries for
		# that to be useful), but, if we do, we'd
		# need to use 10.4u.
		#
		for i in /Developer/SDKs \
		    /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs \
		    /Library/Developer/CommandLineTools/SDKs
		do
			if test -d "$i"/"MacOSX$deploy_target.sdk"
			then
				SDKPATH="$i"/"MacOSX$deploy_target.sdk"
				break
			fi
		done
		if test -z "$SDKPATH"
		then
			AC_MSG_RESULT(no)
			AC_MSG_ERROR([We couldn't find the SDK for OS X $deploy_target])
		fi
		AC_MSG_RESULT(yes)
		;;
	esac

	#
	# Add a -mmacosx-version-min flag to force tests that
	# use the compiler, as well as the build itself, not to,
	# for example, use compiler or linker features not supported
	# by the minimum targeted version of the OS.
	#
	# Add an -isysroot flag to use the SDK.
	#
	CFLAGS="-mmacosx-version-min=$deploy_target -isysroot $SDKPATH $CFLAGS"
	CXXFLAGS="-mmacosx-version-min=$deploy_target -isysroot $SDKPATH $CXXFLAGS"
	LDFLAGS="-mmacosx-version-min=$deploy_target -isysroot $SDKPATH $LDFLAGS"

	#
	# Add a -sdkroot flag to use with osx-app.sh.
	#
	OSX_APP_FLAGS="-sdkroot $SDKPATH"

	#
	# XXX - do we need this to build the Wireshark wrapper?
	# XXX - is this still necessary with the -mmacosx-version-min
	# flag being set?
	#
	OSX_DEPLOY_TARGET="MACOSX_DEPLOYMENT_TARGET=$deploy_target"

	#
	# In the installer package XML file, give the deployment target
	# as the minimum version.
	#
	OSX_MIN_VERSION="$deploy_target"

	case $deploy_target in

	10.4|10.5)
		#
		# Only 32-bit builds are supported.  10.5
		# (and 10.4?) had a bug that causes some BPF
		# functions not to work with 64-bit userland
	        # code, so capturing won't work.
		#
		CFLAGS="-m32 $CFLAGS"
		CXXFLAGS="-m32 $CXXFLAGS"
		LDFLAGS="-m32 $LDFLAGS"
		;;
	esac
else
	#
	# Is this OS X?
	#
	case "$host_os" in
	darwin*)
		#
		# Yes.
		#
		# In the installer package XML file, give the current OS
		# version, minor version and all, as the minimum version.
		# We can't guarantee that the resulting binary will work
		# on older OS versions, not even older minor versions
		# (original release or earlier software updates).
		#
		OSX_MIN_VERSION=`sw_vers -productVersion`
		;;
	esac
fi
AC_SUBST(OSX_MIN_VERSION)

#
# Try to arrange for large file support.
#
AC_SYS_LARGEFILE

#
# GUI toolkit options
#
AC_ARG_WITH([qt],
  AC_HELP_STRING( [--with-qt=@<:@yes/no@:>@],
                  [use Qt @<:@default=yes@:>@]),
  with_qt="$withval", with_qt="unspecified")

AC_ARG_WITH([gtk2],
  AC_HELP_STRING( [--with-gtk2=@<:@yes/no@:>@],
                  [use GTK+ 2.0 @<:@default=no@:>@]),
  with_gtk2="$withval", with_gtk2="unspecified")

AC_ARG_WITH([gtk3],
  AC_HELP_STRING( [--with-gtk3=@<:@yes/no@:>@],
                  [use GTK+ 3.0 instead of 2.0 @<:@default=yes@:>@]),
  with_gtk3="$withval", with_gtk3="unspecified")

# GnuTLS
# Version 3.0 switched from LGPLv2.1+ to LGPLv3+, then switched back to
# LGPLv2.1+ in version 3.1.10.
# GnuTLS depends on GMP which switched from LGPLv2.1+ to LGPLv3+ in
# version 4.2.2, the switched to LGPLv3+ / GPLv2+ in version 6.0.0.

tls_message="no"
AC_ARG_WITH([gnutls],
  AC_HELP_STRING( [--with-gnutls=@<:@yes/no@:>@],
		  [use GnuTLS library @<:@default=yes@:>@]),
  with_gnutls="$withval", with_gnutls="yes")
if test "x$with_gnutls" = "xyes"; then
  have_license_compatible_gnutls="no"
  PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 3.1.10 ],
    [ have_license_compatible_gnutls="yes" ], [ echo "GnuTLS >= 3.1.10 not found " ]
  )

  if test "x$have_license_compatible_gnutls" != "xyes"; then
    PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 1.2.0 gnutls < 3],
      [ have_license_compatible_gnutls="yes" ] , [ echo "GnuTLS >= 1.2.0, < 3.0 not found " ]
    )
  fi

  if test "x$have_license_compatible_gnutls" = "xyes"; then
    echo "GnuTLS found, enabling SSL decryption"
    AC_DEFINE(HAVE_LIBGNUTLS, 1, [Define to use GnuTLS library])
    tls_message="yes"
  else
    echo "GnuTLS with compatible license not found, disabling SSL decryption"
    tls_message="no"
  fi
fi

# libgrypt
gcrypt_message="no"
AC_ARG_WITH([gcrypt],
  AC_HELP_STRING( [--with-gcrypt=@<:@yes/no@:>@],
		  [use gcrypt library @<:@default=yes@:>@]),
  with_gcrypt="$withval", with_gcrypt="yes")
if test "x$with_gcrypt" = "xyes"; then
  AM_PATH_LIBGCRYPT(1.1.92,
        [
                echo "libgcrypt found, enabling ipsec decryption"
                AC_DEFINE(HAVE_LIBGCRYPT, 1, [Define to use libgcrypt])
                gcrypt_message="yes"
        ]
        , [
                if test x$libgcrypt_config_prefix != x ; then
	                AC_MSG_ERROR([[libgcrypt not found; install libgcrypt-devel package for your system]])
                else
                        echo "libgcrypt not found, disabling ipsec decryption"
                        gcrypt_message="no"
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
			PKG_CHECK_MODULES(LIBNL3, [libnl-route-3.0 >= 3.0 libnl-genl-3.0] >= 3.0, [have_libnl3=yes], [have_libnl3=no])
		fi
		if test x$libnl_version = "xany" -o x$libnl_version = "x2"; then
			PKG_CHECK_MODULES(LIBNL2, libnl-2.0 >= 2.0, [have_libnl2=yes], [have_libnl2=no])
		fi
		if test x$libnl_version = "xany" -o x$libnl_version = "x1"; then
			PKG_CHECK_MODULES(LIBNL1, libnl-1 >= 1.0, [have_libnl1=yes], [have_libnl1=no])
		fi
		if (test "${have_libnl3}" = "yes"); then
		        CFLAGS="$CFLAGS $LIBNL3_CFLAGS"
		        LIBS="$LIBS $LIBNL3_LIBS"
			AC_DEFINE(HAVE_LIBNL, 1, [Enable libnl support])
			AC_DEFINE(HAVE_LIBNL3, 1, [libnl version 3])
			libnl_message="yes (v3)"
			enable_airpcap=no
		elif (test "${have_libnl2}" = "yes"); then
		        CFLAGS="$CFLAGS $LIBNL2_CFLAGS"
	        	LIBS="$LIBS $LIBNL2_LIBS"
			AC_DEFINE(HAVE_LIBNL, 1, [Enable libnl support])
			AC_DEFINE(HAVE_LIBNL2, 1, [libnl version 2])
			libnl_message="yes (v2)"
			enable_airpcap=no
		elif (test "${have_libnl1}" = "yes"); then
	        	CFLAGS="$CFLAGS $LIBNL1_CFLAGS"
		        LIBS="$LIBS $LIBNL1_LIBS"
			AC_DEFINE(HAVE_LIBNL, 1, [Enable libnl support])
			AC_DEFINE(HAVE_LIBNL1, 1, [libnl version 1])
			libnl_message="yes (v1)"
			enable_airpcap=no
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
		x = NL80211_ATTR_SUPPORTED_IFTYPES;
		x = NL80211_ATTR_SUPPORTED_COMMANDS;
		x = NL80211_ATTR_WIPHY_FREQ;
		x = NL80211_CHAN_NO_HT;],
	    [AC_MSG_RESULT(yes) AC_DEFINE(HAVE_NL80211, 1, [nl80211.h is new enough])],
	    [AC_MSG_RESULT(no)])

	AC_MSG_CHECKING([for NL80211_SET_CHANNEL])
	  AC_TRY_COMPILE([#include <linux/nl80211.h>],
	    [enum nl80211_commands x = NL80211_CMD_SET_CHANNEL;],
	    [AC_MSG_RESULT(yes) AC_DEFINE(HAVE_NL80211_CMD_SET_CHANNEL, 1, [SET_CHANNEL is supported])],
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

# Check for a2x (convert asciidoc to another format)
AC_PATH_PROG(A2X, a2x)
AC_CHECK_PROG(HAVE_A2X, a2x, "yes", "no")
AM_CONDITIONAL(HAVE_A2X, test x$HAVE_A2X = xyes)

# Want to control a tape drive? Use mt. Want to convert HTML to text?
# Uhhhhh... elinks? lynx? w3m? pandoc? html2text?
AC_PATH_PROG(ELINKS, elinks)
AC_CHECK_PROG(HAVE_ELINKS, elinks, "yes", "no")
AM_CONDITIONAL(HAVE_ELINKS, test x$HAVE_ELINKS = xyes)

# Check for fop (translate .fo to e.g. pdf)
AC_PATH_PROG(FOP, fop)
AC_CHECK_PROG(HAVE_FOP, fop, "yes", "no")
AM_CONDITIONAL(HAVE_FOP, test x$HAVE_FOP = xyes)

# Check for lynx (html -> text)
AC_PATH_PROG(LYNX, lynx)
AC_CHECK_PROG(HAVE_LYNX, lynx, "yes", "no")
AM_CONDITIONAL(HAVE_LYNX, test x$HAVE_LYNX = xyes)

# Check for w3m (html -> text)
AC_PATH_PROG(W3M, w3m)
AC_CHECK_PROG(HAVE_W3M, w3m, "yes", "no")
AM_CONDITIONAL(HAVE_W3M, test x$HAVE_W3M = xyes)

# Check for xmllint
AC_PATH_PROG(XMLLINT, xmllint)
AC_CHECK_PROG(HAVE_XMLLINT, xmllint, "yes", "no")
AM_CONDITIONAL(HAVE_XMLLINT, test x$HAVE_XMLLINT = xyes)

# Check for xsltproc
AC_PATH_PROG(XSLTPROC, xsltproc)
AC_CHECK_PROG(HAVE_XSLTPROC, xsltproc, "yes", "no")
AM_CONDITIONAL(HAVE_XSLTPROC, test x$HAVE_XSLTPROC = xyes)


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
AC_WIRESHARK_RPM_CHECK
AC_SUBST(HAVE_RPM)

# Debian
AC_CHECK_PROG(HAVE_DPKG_BUILDPACKAGE, dpkg-buildpackage, "yes", "no")

# Mac OS X
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
		AC_WIRESHARK_COMPILER_FLAGS_CHECK(-pedantic)
		#
		# Various code blocks this one.
		#
		AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Woverflow)
		AC_WIRESHARK_COMPILER_FLAGS_CHECK(-fstrict-overflow -Wstrict-overflow=4)
		#
		# Due to various places where APIs we don't control
		# require us to cast away constness, we can probably
		# never enable these ones with -Werror.
		#
		AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wcast-qual)
		AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wbad-function-cast, C)
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
	fi
],)

AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wall -W) # -W is now known as -Wextra
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wextra) # -W is now known as -Wextra
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wdeclaration-after-statement, C)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wendif-labels)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wpointer-arith)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wno-pointer-sign, C)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Warray-bounds)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wformat-security)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-fwrapv)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-fno-strict-overflow)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-fno-delete-null-pointer-checks)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wold-style-definition, C)
# The Qt headers generate a ton of shortening errors on 64-bit systems
# so only enable this for C for now.
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wshorten-64-to-32, C)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wstrict-prototypes, C)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wjump-misses-init, C)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wvla)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Waddress)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wattributes)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wdiv-by-zero)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wignored-qualifiers)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wpragmas)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wno-overlength-strings)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wwrite-strings)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wno-long-long)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wc++-compat, C)
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wheader-guard)

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


#
# On OS X, suppress warnings about deprecated declarations, because
# they apparently think everything on OS X is Shiny Happy Apple-
# Framework-Based Apps and are deprecating some perfectly OK
# multi-platform open-source libraries that we use in our multi-platform
# open-source application in favor of various frameworks that are
# OS X-only.
#
case "$host_os" in
darwin*)
	AC_WIRESHARK_COMPILER_FLAGS_CHECK(-Wno-deprecated-declarations)
	;;
esac

#
# Use the faster pre gcc 4.5 floating point precision if available.
#
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-fexcess-precision=fast)

CFLAGS_before_fvhidden="$CFLAGS"
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-fvisibility=hidden)
if test "x$CFLAGS" = "x$CFLAGS_before_fvhidden"
then
	# TODO add other ways of hiding symbols
	AC_MSG_WARN(Compiler will export all symbols from shared libraries)
fi

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
CFLAGS_before_pie="$CFLAGS"
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-fPIE)
if test "x$CFLAGS" != "x$CFLAGS_before_pie"
then
	# Restore CFLAGS
	CFLAGS="$CFLAGS_before_pie"

	LDFLAGS_before_pie="$LDFLAGS"
	AC_WIRESHARK_LDFLAGS_CHECK([-fPIE -pie])
	if test "x$LDFLAGS" != "x$LDFLAGS_before_pie"
	then
		# We can use PIE
		PIE_CFLAGS="-fPIE"
		PIE_LDFLAGS="-pie"

		# Restore LDFLAGS
		LDFLAGS="$LDFLAGS_before_pie"
	fi

fi
AC_SUBST(PIE_CFLAGS)
AC_SUBST(PIE_LDFLAGS)

CFLAGS_before_simd="$CFLAGS"
AC_WIRESHARK_COMPILER_FLAGS_CHECK(-msse4.2, C)
if test "x$CFLAGS" != "x$CFLAGS_before_simd"
then
	AC_MSG_CHECKING([whether there is nmmintrin.h header])

	AC_TRY_COMPILE(
		[#include <nmmintrin.h>],
		[return 0;],
		[
		        have_sse42=yes
		        AC_DEFINE(HAVE_SSE4_2, 1, [Support SSSE4.2 (Streaming SIMD Extensions 4.2) instructions])
			CFLAGS_SSE42="-msse4.2"
		        AC_MSG_RESULT([yes])
		],
		[
		        have_sse42=no
		        AC_MSG_RESULT([no])
		]
	)

	# Restore CFLAGS
	CFLAGS="$CFLAGS_before_simd"
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
else
  AC_DEFINE(_U_, , [Hint to the compiler that a function parameters is not used])
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
warnings_as_errors_default="yes"
AC_MSG_CHECKING(whether we should treat compiler warnings as errors)
AC_ARG_ENABLE(warnings-as-errors,
  AC_HELP_STRING( [--enable-warnings-as-errors],
		  [treat warnings as errors (only for GCC or clang) @<:@default=yes, unless extra compiler warnings are enabled@:>@]),
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
]
)
AM_CONDITIONAL(HAVE_WARNINGS_AS_ERRORS, test "x$with_warnings_as_errors" = "xyes")

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
		CPPFLAGS="$CPPFLAGS -DFUNCPROTO=15"
		CFLAGS="$CFLAGS -Wno-return-type"
		CXXFLAGS="$CXXFLAGS -Wno-return-type"
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
		# HP's ANSI C compiler; flags suggested by Jost Martin.
		# "-Ae" for ANSI C plus extensions such as "long long".
		# "+O2", for optimization.  XXX - works with "-g"?
		#
		# HP's ANSI C++ compiler doesn't support "-Ae", but
		# does support "+O2", at least according to the
		# documentation I can find online.
		#
		CFLAGS="-Ae +O2 $CFLAGS"
		CFLAGS_FOR_BUILD="-Ae +O2 $CFLAGS"
		CXXFLAGS="+O2 $CFLAGS"
		AC_MSG_RESULT(HP ANSI C compiler - added -Ae +O2)
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
	# Add -Wl,-search_paths_first to make sure that if we search
	# directories A and B, in that order, for a given library, a
	# non-shared version in directory A, rather than a shared
	# version in directory B, is chosen (so we can use
	# --with-pcap=/usr/local to force all programs to be linked
	# with a static version installed in /usr/local/lib rather than
	# the system version in /usr/lib).
	#
	# Also add -Wl,-rpath,@executable_path/../lib and
	# -Wl,-rpath,/usr/local/lib, so that, if we build an app
	# bundle, we can tweak all the executable images, shared
	# libraries, and plugins in the bundle to look for non-system
	# libraries in the rpath, rather than having a script tweak
	# DYLD_LIBRARY_PATH.
	#
	LDFLAGS="-Wl,-search_paths_first -Wl,-rpath,@executable_path/../lib -Wl,-rpath,@executable_path/../Frameworks -Wl,-rpath,/usr/local/lib $LDFLAGS"
	AC_MSG_RESULT([Apple linker - added -Wl,-single_module and -Wl,-search_paths_first, and rpaths])
	;;
cygwin*)
	#
	# Shared libraries in cygwin/Win32 must never contain
	# undefined symbols.
	#
	LDFLAGS="$LDFLAGS -no-undefined"
	AC_MSG_RESULT(CygWin GNU ld - added -no-undefined)
	;;
*)
	AC_MSG_RESULT(none needed)
	;;
esac
AC_SUBST(LDFLAGS_SHAREDLIB)

# Enable silent builds by default
# Verbose builds can be enabled with "./configure
# --enable-silent-rules ..." or "make V=1 ..."
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])],
  [AC_SUBST([AM_DEFAULT_VERBOSITY], [1])])

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
case "$host_os" in

darwin*)
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

#
# On Solaris, check whether we have getexecname().
#
case "$host_os" in
solaris*)
	AC_CHECK_FUNC(getexecname)
	;;
esac

dnl Look in /usr/local for header files and libraries ?
dnl XXX FIXME don't include /usr/local if it is already in the system
dnl search path as this causes gcc 3.2 on Linux to complain about a change
dnl of the system search order for includes
AC_ARG_ENABLE(usr-local,
  AC_HELP_STRING( [--enable-usr-local],
                  [look for headers and libs in /usr/local tree @<:@default=yes@:>@]),
    ac_cv_enable_usr_local=$enableval,ac_cv_enable_usr_local=yes)

AC_MSG_CHECKING(whether to use /usr/local for headers and libraries)
if test "x$ac_cv_enable_usr_local" = "xyes" ; then
	if test -d "/usr/local"; then
		AC_MSG_RESULT(yes)
		#
		# Arrange that we search for header files in the source directory
		# and in its "wiretap" subdirectory, as well as in "/usr/local/include",
		# as various packages we use ("libpcap", "zlib", "adns")
		# may have been installed under "/usr/local/include".
		#
		CPPFLAGS="$CPPFLAGS -I/usr/local/include"

		#
		# Arrange that we search for libraries in "/usr/local/lib".
		#
		AC_WIRESHARK_ADD_DASH_L(LDFLAGS, /usr/local/lib)
	else
		AC_MSG_RESULT(no)
	fi
else
	AC_MSG_RESULT(no)
fi

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

#
# Check for versions of "sed" inadequate to handle, in libtool, a list
# of object files as large as the list in Wireshark.
#
# On Solaris, we check for "/bin/sed", "/usr/bin/sed", and "/usr/ucb/sed",
# as both "/usr/bin/sed" (which is also "/bin/sed", as "/bin" is just a
# symlink to "/usr/bin", but people may have "/bin" before "/usr/bin" in
# their search path) and "/usr/ucb/sed" are inadequate; "/usr/xpg4/bin/sed"
# is the only "sed" that comes with Solaris that can handle Wireshark.
#
# Add any checks here that are necessary for other OSes.
#
AC_PATH_PROG(SED, sed)
if test "x$SED" = x
then
	AC_MSG_ERROR(I couldn't find sed; make sure it's installed and in your path)
fi
AC_WIRESHARK_GNU_SED_CHECK
if test "$HAVE_GNU_SED" = no ; then
	case "$host_os" in
	solaris*)
		AC_MSG_CHECKING(whether one of /usr/bin/sed or /bin/sed or /usr/ucb/sed will be used)
		case `which sed` in
			/bin/sed|/usr/bin/sed|/usr/ucb/sed)
			AC_MSG_RESULT(yes)
			AC_MSG_ERROR([change your path to search /usr/xpg4/bin or directory containing GNU sed before /usr/bin (and /bin and /usr/ucb)])
			;;

			*)
			AC_MSG_RESULT(no)
			;;
		esac
		;;

	*)
		:
		;;
	esac
fi

# Enable/disable wireshark
AC_ARG_ENABLE(wireshark,
  AC_HELP_STRING( [--enable-wireshark],
                  [build the Wireshark GUI (with Gtk+, Qt, or both) @<:@default=yes@:>@]),
    enable_wireshark=$enableval,enable_wireshark=yes)

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
		CFLAGS=" -pg $CFLAGS"
		CXXFLAGS=" -pg $CXXFLAGS"
	else
		AC_MSG_RESULT(no)
		echo "Building profile binaries currently only supported for GCC and clang."
	fi
else
	AC_MSG_RESULT(no)
fi

# Create DATAFILE_DIR #define for config.h
datafiledir=$datadir/wireshark
datafiledir=`(
    test "x$prefix" = xNONE && prefix=$ac_default_prefix
    test "x$exec_prefix" = xNONE && exec_prefix=${prefix}
    # Ugly hack, but I don't see how this problem can be solved
    # properly that DATAFILE_DIR had a value starting with
    # "${prefix}/" instead of e.g. "/usr/local/"
    eval eval echo "$datafiledir"
)`
AC_DEFINE_UNQUOTED(DATAFILE_DIR,"$datafiledir", [Directory for data])

# Create DOC_DIR #define for config.h
docdir=`(
    test "x$prefix" = xNONE && prefix=$ac_default_prefix
    test "x$exec_prefix" = xNONE && exec_prefix=${prefix}
    # Ugly hack, but I don't see how this problem can be solved
    # properly that DOC_DIR had a value starting with
    # "${prefix}/" instead of e.g. "/usr/local/"
    eval eval echo "$docdir"
)`
AC_DEFINE_UNQUOTED(DOC_DIR, "$docdir", [Directory for docs])

GTK2_MIN_VERSION=2.12.0
AC_SUBST(GTK2_MIN_VERSION)
GTK3_MIN_VERSION=3.0.0
AC_SUBST(GTK3_MIN_VERSION)
QT_MIN_VERSION=4.6.0
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
# http://en.wikipedia.org/wiki/GTK+#Releases
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
#
# Release dates for Qt versions:
# http://en.wikipedia.org/wiki/List_of_Qt_releases
# 4.6.0:  01 Dec 2009
# 4.7.0:  21 Sep 2010
# 4.8.0:  15 Dec 2011
# 5.0.0:  19 Dec 2012
# 5.1.0:  03 Jul 2013
# 5.2.0:  12 Dec 2013

have_qt=no
have_gtk=no
if test "x$enable_wireshark" = "xyes"; then
	if test "x$with_gtk2" = "xunspecified" -a \
		"x$with_gtk3" = "xunspecified" -a \
		"x$with_qt" = "xunspecified"; then
		#
		# No GUI toolkit was explicitly specified; pick Qt and GTK+ 3.
		#
		with_qt=yes
		with_gtk3=yes
	fi
	if test "x$with_qt" = "xyes"; then
		#
		# Qt was specified; Make sure we have a C++ compiler.
		#
		if test -z "$CXX"; then
			AC_MSG_ERROR(Need a working C++ compiler to build Wireshark with Qt)
		fi

		#
		# Now make sure we have Qt and, if so, add the flags
		# for it to CFLAGS and CXXFLAGS.
		#
		AC_WIRESHARK_QT_CHECK($QT_MIN_VERSION,
		[
			CFLAGS="$CFLAGS $Qt_CFLAGS"
			CXXFLAGS="$CXXFLAGS $Qt_CFLAGS"
			have_qt=yes
			GUI_CONFIGURE_FLAGS="$GUI_CONFIGURE_FLAGS --with-qt"
			OSX_APP_FLAGS="$OSX_APP_FLAGS -qt"
			OSX_DMG_FLAGS="-qt"
		],
		[AC_MSG_ERROR([Qt is not available])])

		#
		# XXX - greasy hack to make ui/gtk/recent.c
		# compile.
		#
		CPPFLAGS="-DQT_GUI_LIB"
	fi

	if test "x$with_gtk3" = "xyes"; then
		#
		# GTK+ 3 was specified; make sure they didn't also
		# specify GTK+ 2, as we don't support building both
		# GTK+ 2 and GTK+ 3 versions at the same time.
		#
		if test "x$with_gtk2" = "xyes"; then
			AC_MSG_ERROR([Both GTK+ 2 and GTK+ 3 were specified; choose one but not both])
		fi

		#
		# Make sure we have GTK+ 3.
		#
		AM_PATH_GTK_3_0(3.0.0,
		[
			CFLAGS="$CFLAGS $GTK_CFLAGS"
			CXXFLAGS="$CXXFLAGS $GTK_CFLAGS"
			have_gtk=yes
			GUI_CONFIGURE_FLAGS="$GUI_CONFIGURE_FLAGS --with-gtk3"
		],
		[AC_MSG_ERROR([GTK+ 3 is not available])])
	elif test "x$with_gtk2" = "xyes"; then
		#
		# GTK+ 3 wasn't specified, and GTK+ 2 was specified;
		# make sure we have GTK+ 2.
		#
		AM_PATH_GTK_2_0($GTK2_MIN_VERSION,
		[
			CFLAGS="$CFLAGS $GTK_CFLAGS"
			CXXFLAGS="$CXXFLAGS $GTK_CFLAGS"
			have_gtk=yes
			GUI_CONFIGURE_FLAGS="$GUI_CONFIGURE_FLAGS --with-gtk2"
		],
		[AC_MSG_ERROR([GTK+ 2 is not available])])
	fi
fi
AC_SUBST(GUI_CONFIGURE_FLAGS)

GLIB_MIN_VERSION=2.16.0
AC_SUBST(GLIB_MIN_VERSION)
# GLib checks; we require GLib $GLIB_MIN_VERSION or later, and require gmodule
# support, as we need that for dynamically loading plugins.
# If we found GTK+, this doesn't add GLIB_CFLAGS to CFLAGS, because
# AM_PATH_GTK will add GTK_CFLAGS to CFLAGS, and GTK_CFLAGS is a
# superset of GLIB_CFLAGS.  If we didn't find GTK+, it does add
# GLIB_CFLAGS to CFLAGS.
# However, this means that both @GLIB_LIBS@ and @GTK_LIBS@ will be
# set when generating the Makefile, so we can make programs that require
# only GLib link with @GLIB_LIBS@ and make programs that require GTK+
# link with @GTK_LIBS@ (which includes @GLIB_LIBS@).
# We don't add $GLIB_LIBS to LIBS, because we don't want to force all
# programs to be built with GLib.
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

use_glib_cflags="true"
if test "$have_gtk" = "yes" -a "$have_qt" = "yes" ; then
	# We have both GTK and Qt and thus will be building both wireshark
	# and wireshark-qt.

	wireshark_bin="wireshark\$(EXEEXT) wireshark-qt\$(EXEEXT)"
	wireshark_man="wireshark.1"
	wireshark_SUBDIRS="codecs ui/qt ui/gtk"
fi
if test "$have_gtk" = "no" -a "$have_qt" = "yes" ; then
	# We don't have GTK+ but we have Qt.

	wireshark_bin="wireshark-qt\$(EXEEXT)"
	wireshark_man="wireshark.1"
	wireshark_SUBDIRS="codecs ui/qt"
fi
if test "$have_gtk" = "yes" -a "$have_qt" = "no" ; then
	# We have GTK+ but not Qt.

	wireshark_bin="wireshark\$(EXEEXT)"
	wireshark_man="wireshark.1"
	wireshark_SUBDIRS="codecs ui/gtk"
	use_glib_cflags="false"
fi
if test "$have_gtk" = "no" -a "$have_qt" = "no" ; then
	# We have neither GTK+ nor Qt.
	#
	# If they didn't explicitly say "--disable-wireshark",
	# fail (so that, unless they explicitly indicated that
	# they don't want Wireshark, we stop so they know they
	# won't be getting Wireshark unless they fix the GTK+/Qt
	# problem).
	#
	if test "x$enable_wireshark" = "xyes"; then
		if test "x$with_gtk3" = "xyes"; then
			AC_MSG_ERROR([Neither Qt nor GTK+ $GTK3_MIN_VERSION or later are available, so Wireshark can't be compiled])
		else
			AC_MSG_ERROR([Neither Qt nor GTK+ $GTK2_MIN_VERSION or later are available, so Wireshark can't be compiled])
		fi
	fi
	wireshark_bin=""
	wireshark_man=""
fi

if test "$have_gtk" = "yes" ; then
	# If we have GTK then add flags for it.

	CPPFLAGS="-DGDK_PIXBUF_DISABLE_DEPRECATED $CPPFLAGS"
	CPPFLAGS="-DGDK_DISABLE_DEPRECATED $CPPFLAGS"
	if test \( $gtk_config_major_version -eq 3 -a $gtk_config_minor_version -ge 10 \) ; then
		## Allow use of deprecated & disable deprecated warnings if Gtk >= 3.10;
		##  The deprecations in Gtk 3.10 will not be fixed ...
		CPPFLAGS="-DGDK_DISABLE_DEPRECATION_WARNINGS $CPPFLAGS"
	else
		CPPFLAGS="-DGTK_DISABLE_DEPRECATED $CPPFLAGS"
	fi
	CPPFLAGS="-DGTK_DISABLE_SINGLE_INCLUDES $CPPFLAGS"
	if test ! \( $gtk_config_major_version -eq 2 -a $gtk_config_minor_version -lt 20 \) ; then
		# Enable GSEAL when building with GTK > 2.20
		# (Versions prior to 2.22 lacked some necessary accessors.)
		CPPFLAGS="-DGSEAL_ENABLE $CPPFLAGS"
	fi
fi

# XXX - Is this really necessary?  When we build with both Gtk+ and Qt it works...
if test "$use_glib_cflags" = "true"; then
	# Use GLIB_CFLAGS
	AM_PATH_GLIB_2_0($GLIB_MIN_VERSION,
	[
		CFLAGS="$CFLAGS $GLIB_CFLAGS"
		CXXFLAGS="$CXXFLAGS $GLIB_CFLAGS"
	], AC_MSG_ERROR(GLib $GLIB_MIN_VERSION or later distribution not found.), gthread gmodule)
else
	# Don't use GLIB_CFLAGS
	AM_PATH_GLIB_2_0($GLIB_MIN_VERSION, , AC_MSG_ERROR(GLib $GLIB_MIN_VERSION or later distribution not found.), gthread gmodule)
fi

#
# "make dist" requires that we have the Qt build tools.
#
# Annoyingly, at least on Fedora 16, uic and moc are named XXX-qt4
# rather than just XXX, perhaps to allow Qt 3 and Qt 4 tools to be
# installed; if they're still doing that in current Fedora releases,
# perhaps there will also be XXX-qt5 when they pick up Qt 5.
#
AC_PATH_PROG(UIC, uic)
if test "x$UIC" = x
then
	AC_PATH_PROG(UIC, uic-qt4)
	if test "x$UIC" = x
	then
		if test "x$with_qt" = "xyes"; then
			#
			# If you want to build with Qt, you'd better
			# have uic.
			#
			AC_MSG_ERROR(I couldn't find uic or uic-qt4; make sure it's installed and in your path)
		else
			#
			# We shouldn't fail here, as the user's not
			# building with Qt, and we shouldn't force them
			# to have Qt installed if they're not doing so.
			# "make dist" will fail if they do that, but
			# we don't know whether they'll be doing that,
			# so this is the best we can do.
			#
			UIC=uic
		fi
	fi
fi
AC_SUBST(UIC)
AC_PATH_PROG(MOC, moc)
if test "x$MOC" = x
then
	AC_PATH_PROG(MOC, moc-qt4)
	if test "x$MOC" = x
	then
		if test "x$with_qt" = "xyes"; then
			#
			# If you want to build with Qt, you'd better
			# have moc.
			#
			AC_MSG_ERROR(I couldn't find moc or moc-qt4; make sure it's installed and in your path)
		else
			#
			# We shouldn't fail here, as the user's not
			# building with Qt, and we shouldn't force them
			# to have Qt installed if they're not doing so.
			# "make dist" will fail if they do that, but
			# we don't know whether they'll be doing that,
			# so this is the best we can do.
			#
			MIC=moc
		fi
	fi
fi
AC_SUBST(MOC)

# Error out if a glib header other than a "top level" header
#  (glib.h, glib-object.h, gio.h) or certain other headers( e.g.,gmodule.h)
#  is used.
CPPFLAGS="-DG_DISABLE_SINGLE_INCLUDES $CPPFLAGS"

# Error out on the usage of deprecated glib functions
CPPFLAGS="-DG_DISABLE_DEPRECATED $CPPFLAGS"

#
# Check whether GLib modules are supported, to determine whether we
# can support plugins.
#
AC_MSG_CHECKING(whether GLib supports loadable modules)
ac_save_CFLAGS="$CFLAGS"
ac_save_LIBS="$LIBS"
CFLAGS="$CFLAGS $GLIB_CFLAGS"
LIBS="$GLIB_LIBS $LIBS"
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
if test "$ac_cv_glib_supports_modules" = yes ; then
  AC_MSG_RESULT(yes)
  have_plugins=yes
  plugins_dir="plugins"
else
  AC_MSG_RESULT(no)
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
	CFLAGS="$CFLAGS $GLIB_CFLAGS"
	LIBS="$GLIB_LIBS $LIBS"
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
AC_MSG_CHECKING(whether GLib supports POSIX/XSI thousands grouping)
ac_save_CFLAGS="$CFLAGS"
ac_save_LIBS="$LIBS"
CFLAGS="$CFLAGS $GLIB_CFLAGS"
LIBS="$GLIB_LIBS $LIBS"
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
if test "$ac_cv_glib_supports_printf_grouping" = yes ; then
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_GLIB_PRINTF_GROUPING, 1, [Define if your printf() function supports thousands grouping.])
else
  AC_MSG_RESULT(no)
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
AM_CONDITIONAL(HAVE_Qt, test "$have_qt" = "yes")
AM_CONDITIONAL(HAVE_GTK, test "$have_gtk" = "yes")
AC_SUBST(OSX_APP_FLAGS)
AC_SUBST(OSX_DMG_FLAGS)

# Enable/disable tshark
AC_ARG_ENABLE(tshark,
  AC_HELP_STRING( [--enable-tshark],
                  [build TShark @<:@default=yes@:>@]),
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

# Enable/disable tfshark
AC_ARG_ENABLE(tfshark,
  AC_HELP_STRING( [--enable-tfshark],
                  [build TFShark @<:@default=no@:>@]),
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

# Enable/disable echld

AC_ARG_ENABLE(echld,
  AC_HELP_STRING( [--enable-echld],
                  [support echld]),
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

dnl Checks for "gethostbyname()" - and "-lnsl", if we need it to get
dnl "gethostbyname()".
AC_WIRESHARK_GETHOSTBY_LIB_CHECK

dnl Checks for "connect()", used as a proxy for "socket()" - and
dnl "-lsocket", if we need it to get "connect()".
AC_WIRESHARK_SOCKET_LIB_CHECK

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


dnl Check for airpcap
AC_MSG_CHECKING(whether to include airpcap support)
AC_ARG_ENABLE(airpcap,
  AC_HELP_STRING( [--enable-airpcap],
                  [use AirPcap in Wireshark @<:@default=yes@:>@]),
  enable_airpcap=$enableval, enable_airpcap=yes)

if test x$enable_airpcap = xyes; then
	if test "x$want_pcap" = "xno" ; then
		enable_airpcap=no
		AC_MSG_RESULT(pcap not available - disabling airpcap)
	else
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_AIRPCAP, 1, [Enable AirPcap])
	fi
else
	AC_MSG_RESULT(no)
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
AC_MSG_CHECKING(whether to use liblua for the Lua scripting plugin)

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
		lua_dir=$withval
	fi
],[
	#
	# Use liblua by default
	#
	want_lua=ifavailable
	lua_dir=
])
if test "x$want_lua" = "xno" ; then
	AC_MSG_RESULT(no)
else
	AC_MSG_RESULT(yes)
	AC_WIRESHARK_LIBLUA_CHECK
	if test "x$want_lua" = "xno" ; then
		AC_MSG_RESULT(liblua not found - disabling support for the lua scripting plugin)
	fi
fi
AM_CONDITIONAL(HAVE_LIBLUA, test x$want_lua = xyes)


dnl portaudio check
AC_MSG_CHECKING(whether to use libportaudio for the rtp_player)

AC_ARG_WITH(portaudio,
  AC_HELP_STRING( [--with-portaudio@<:@=DIR@:>@],
                  [use libportaudio (located in directory DIR, if supplied) for the rtp_player @<:@default=yes, if available@:>@]),
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
		AC_MSG_RESULT(libportaudio not found - disabling support for the rtp_player)
	fi
fi
AM_CONDITIONAL(HAVE_LIBPORTAUDIO, test x$want_portaudio = xyes)


dnl ipv6 check
AC_ARG_ENABLE(ipv6,
  AC_HELP_STRING( [--enable-ipv6],
                  [use IPv6 name resolution, if available @<:@default=yes@:>@]),
    enable_ipv6=$enableval,enable_ipv6=yes)

AC_MSG_CHECKING(whether to enable ipv6 name resolution if available)
if test "x$enable_ipv6" = "xno" ; then
	AC_MSG_RESULT(no)
else
	AC_MSG_RESULT(yes)
	AC_WIRESHARK_IPV6_STACK
fi


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
		AC_MSG_RESULT(no. Setcap not found)
	elif test "x$enable_dumpcap" = "xno" ; then
		AC_MSG_ERROR(Setcap install works only with dumpcap but dumpcap is disabled)
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
		AC_MSG_RESULT(no; using setcap instead)
	elif test "x$enable_dumpcap" = "xno" ; then
		AC_MSG_ERROR(Setuid install works only with dumpcap but dumpcap is disabled)
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
	AC_WIRESHARK_ADD_DASH_L(LDFLAGS, ${withval}/lib)
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
AC_CHECK_HEADERS(direct.h dirent.h fcntl.h getopt.h grp.h inttypes.h netdb.h pwd.h stdarg.h stddef.h unistd.h)
AC_CHECK_HEADERS(sys/ioctl.h sys/param.h sys/socket.h sys/sockio.h sys/stat.h sys/time.h sys/types.h sys/utsname.h sys/wait.h)
AC_CHECK_HEADERS(netinet/in.h)
AC_CHECK_HEADERS(arpa/inet.h arpa/nameser.h)

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
	AC_WIRESHARK_ADD_DASH_L(LDFLAGS, ${withval}/lib)
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
                  [use c-ares (located in directory DIR, if supplied) - supersedes --with-adns @<:@default=yes, if present@:>@]),
[
if   test "x$withval" = "xno";  then
	want_c_ares=no
elif test "x$withval" = "xyes"; then
	want_c_ares=yes
elif test -d "$withval"; then
	want_c_ares=yes
	AC_WIRESHARK_ADD_DASH_L(LDFLAGS, ${withval}/lib)
fi
])
if test "x$want_c_ares" = "xno" ; then
	AC_MSG_RESULT(no)
else
	AC_MSG_RESULT(yes)
	AC_WIRESHARK_C_ARES_CHECK
fi
AC_SUBST(C_ARES_LIBS)

dnl ADNS Check
ADNS_LIBS=''
AC_MSG_CHECKING(whether to use the GNU ADNS library if available)

AC_ARG_WITH(adns,
  AC_HELP_STRING( [--with-adns@<:@=DIR@:>@],
                  [use GNU ADNS (located in directory DIR, if supplied) @<:@default=yes, if present@:>@]),
[
if   test "x$withval" = "xno";  then
	want_adns=no
elif test "x$withval" = "xyes"; then
	want_adns=yes
elif test -d "$withval"; then
	want_adns=yes
	AC_WIRESHARK_ADD_DASH_L(LDFLAGS, ${withval}/lib)
fi
])
if test "x$want_adns" = "xno" -o "x$have_good_c_ares" = "xyes" ; then
	AC_MSG_RESULT(no)
else
	AC_MSG_RESULT(yes)
	AC_WIRESHARK_ADNS_CHECK
fi
AC_SUBST(ADNS_LIBS)

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
	AC_WIRESHARK_ADD_DASH_L(LDFLAGS, ${withval}/lib)
fi
])
if test "x$want_geoip" = "xno"; then
	AC_MSG_RESULT(no)
else
	AC_MSG_RESULT(yes)
	AC_WIRESHARK_GEOIP_CHECK
fi
AC_SUBST(GEOIP_LIBS)

#
# Define WS_MSVC_NORETURN appropriately for declarations of routines that
# never return (just like Charlie on the MTA).
#
# Note that MSVC++ expects __declspec(noreturn) to precede the function
# name and GCC, as far as I know, expects __attribute__((noreturn)) to
# follow the function name, so we need two different flavors of
# noreturn tag.
#
AC_DEFINE(WS_MSVC_NORETURN,, [Define as the string to precede declarations of routines that never return])

dnl Checks for typedefs, structures, and compiler characteristics.
# AC_C_CONST

# Check how we can get the time zone abbreviation
AC_WIRESHARK_TIMEZONE_ABBREV

# We need to know whether "struct stat" has an "st_flags" member
# for file_user_immutable().

AC_WIRESHARK_STRUCT_ST_FLAGS

# We need to know whether "struct sockaddr" has an "sa_len" member
# for get_interface_list().

AC_WIRESHARK_STRUCT_SA_LEN

# We must know our byte order
AC_C_BIGENDIAN

# Checks whether "-traditional" is needed when using "ioctl".
# XXX - do we need this?
AC_PROG_GCC_TRADITIONAL

GETOPT_LO=""
AC_CHECK_FUNC(getopt,
  [GETOPT_LO=""
   AC_DEFINE(HAVE_GETOPT, 1, [Define to 1 if you have the getopt function.])
  ],
  GETOPT_LO="wsgetopt.lo"
)
if test "$ac_cv_func_getopt" = no ; then
  GETOPT_LO="wsgetopt.lo"
fi
AM_CONDITIONAL(NEED_GETOPT_LO, test "x$ac_cv_func_getopt" = "xno")
AC_SUBST(GETOPT_LO)

AC_CHECK_FUNC(strncasecmp, STRNCASECMP_LO="",
  STRNCASECMP_LO="strncasecmp.lo")
if test "$ac_cv_func_strncasecmp" = no ; then
  STRNCASECMP_LO="strncasecmp.lo"
fi
AM_CONDITIONAL(NEED_STRNCASECMP_LO, test "x$ac_cv_func_strncasecmp" = "xno")
AC_SUBST(STRNCASECMP_LO)

AC_CHECK_FUNCS(mkstemp mkdtemp)

AC_SEARCH_LIBS(inet_aton, [socket nsl], have_inet_aton=yes,
    have_inet_aton=no)
if test "$have_inet_aton" = no; then
  INET_ATON_LO="inet_aton.lo"
  AC_DEFINE(HAVE_INET_ATON_H, 0, [Define unless inet/aton.h needs to be included])
else
  INET_ATON_LO=""
fi
AM_CONDITIONAL(NEED_INET_ATON_LO, test "x$have_inet_aton" = "xno")
AC_SUBST(INET_ATON_LO)

AC_SEARCH_LIBS(inet_pton, [socket nsl], [
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
have_inet_pton=no], [AC_MSG_RESULT(cross compiling, assume it is broken);
have_inet_pton=no])],
have_inet_pton=no)
if test "$have_inet_pton" = no; then
  INET_PTON_LO="inet_pton.lo"
else
  INET_PTON_LO=""
fi
AM_CONDITIONAL(NEED_INET_PTON_LO, test "x$have_inet_pton" = "xno")
AC_SUBST(INET_PTON_LO)

AC_SEARCH_LIBS(inet_ntop, [socket nsl], [
  AC_MSG_CHECKING([for inet_ntop prototype])
  AC_TRY_COMPILE([#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern const char *inet_ntop(int, const void *, char *, size_t);],, [
    AC_MSG_RESULT(yes)
    AC_DEFINE(HAVE_INET_NTOP_PROTO, 1,
    [Define if inet_ntop() prototype exists])], [
    AC_TRY_COMPILE([#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern const char *inet_ntop(int, const void *, char *, socklen_t);],, [
      AC_MSG_RESULT(yes)
      AC_DEFINE(HAVE_INET_NTOP_PROTO, 1,
      [Define if inet_ntop() prototype exists])], [
      AC_MSG_RESULT(no)])])
  INET_NTOP_LO=""], [
  INET_NTOP_LO="inet_ntop.lo"
  AC_DEFINE(NEED_INET_V6DEFS_H, 1,
  [Define if inet/v6defs.h needs to be included])])
AM_CONDITIONAL(NEED_INET_NTOP_LO, test "x$INET_NTOP_LO" != "x")
AC_SUBST(INET_NTOP_LO)

AC_CHECK_FUNC(strptime, STRPTIME_LO="",
  [STRPTIME_LO="strptime.lo"
   AC_DEFINE(NEED_STRPTIME_H, 1, [Define if strptime.h needs to be included])
])
if test "$ac_cv_func_strptime" = no ; then
  STRPTIME_LO="strptime.lo"
fi
AC_SUBST(STRPTIME_C)
AM_CONDITIONAL(NEED_STRPTIME_LO, test "x$ac_cv_func_strptime" = "no")
AC_SUBST(STRPTIME_LO)

AC_CHECK_FUNCS(getprotobynumber gethostbyname2)
AC_CHECK_FUNCS(issetugid)
AC_CHECK_FUNCS(mmap mprotect sysconf)

dnl blank for now, but will be used in future
AC_SUBST(wireshark_SUBDIRS)

# Check Bluetooth SBC codec for RTP Player
# git://git.kernel.org/pub/scm/bluetooth/sbc.git
PKG_CHECK_MODULES(SBC, sbc >= 1.0, [have_sbc=yes], [have_sbc=no])
if (test "${have_sbc}" = "yes"); then
    AC_DEFINE(HAVE_SBC, 1, [Define to support playing SBC by standalone BlueZ SBC library])
    CFLAGS="$CFLAGS $(pkg-config sbc --cflags)"
    LIBS="$LIBS $(pkg-config sbc --libs)"
fi

dnl
dnl check whether plugins should be enabled and, if they should be,
dnl check for plugins directory - stolen from Amanda's configure.ac
dnl
dnl we don't wish to expand ${libdir} yet
plugindir='${libdir}/wireshark/plugins/${VERSION}'
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
CPPFLAGS="$CPPFLAGS '-DPLUGIN_INSTALL_DIR=\"\$(plugindir)\"'"

#
# The plugin dissectors reside in ./plugins/PROTO/
#
PLUGIN_LIBS=""
AC_SUBST(PLUGIN_LIBS)

#
# Check if (emem) memory allocations must be 8-byte aligned.
# I haven't been able to write C code that reliably makes that determination
# (different versions of GCC with or without optimization give different
# results) so just assume everything except (32-bit) x86 needs 8-byte
# alignment (64-bit platforms either require 8-byte alignment for pointers
# and 64-bit integral data types or may get better performance from that;
# 64-bit x86 will get 8-byte alignment from G_MEM_ALIGN anyway.  32-bit
# platforms would only require it, or get better performance from it,
# for 64-bit floating-point values.).
#
AC_MSG_CHECKING(whether we need memory allocations to be 8-byte aligned)
case $host_cpu in
	i386|i486|i586|i686)
		AC_MSG_RESULT(no)
		;;
	*)
		AC_MSG_RESULT(yes)
		AC_DEFINE(NEED_8_BYTE_ALIGNMENT, 1, [Define if we need memory allocations to be 8-byte aligned])
		;;
esac

# Gather only the "--with*" arguments and also a list of --with arguments for rpmbuild
for f in $CONFIG_ARGS
do
	case $f in
	--with-gtk2*)
		CONFIG_WITH_ARGS="$CONFIG_WITH_ARGS $f"
		RPMBUILD_WITH_ARGS="$RPMBUILD_WITH_ARGS --with gtk2"
		;;
	--without-gtk2*)
		CONFIG_WITH_ARGS="$CONFIG_WITH_ARGS $f"
		RPMBUILD_WITH_ARGS="$RPMBUILD_WITH_ARGS --without gtk2"
		;;
	--with-gtk3*)
		CONFIG_WITH_ARGS="$CONFIG_WITH_ARGS $f"
		RPMBUILD_WITH_ARGS="$RPMBUILD_WITH_ARGS --with gtk3"
		;;
	--without-gtk3*)
		CONFIG_WITH_ARGS="$CONFIG_WITH_ARGS $f"
		RPMBUILD_WITH_ARGS="$RPMBUILD_WITH_ARGS --without gtk3"
		;;
	--with-qt*)
		CONFIG_WITH_ARGS="$CONFIG_WITH_ARGS $f"
		RPMBUILD_WITH_ARGS="$RPMBUILD_WITH_ARGS --with qt"
		;;
	--without-qt*)
		CONFIG_WITH_ARGS="$CONFIG_WITH_ARGS $f"
		RPMBUILD_WITH_ARGS="$RPMBUILD_WITH_ARGS --without qt"
		;;
	--with*)
		CONFIG_WITH_ARGS="$CONFIG_WITH_ARGS $f"
		;;
	esac

done
AC_SUBST(CONFIG_WITH_ARGS)
AC_SUBST(RPMBUILD_WITH_ARGS)

dnl libtool defs
#
# Yes, AM_PROG_LIBTOOL is redundant with newer version(s) of some tool(s)
# (autoconf?  automake?  libtool?) - with the newer version(s), it's
# just an alias for AC_PROG_LIBTOOL, which is called earlier.
#
# With older version(s) of those tool(s), however, it's not just an
# alias, and the configure scripts don't work without it.
#
AM_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

AM_CONDITIONAL(ENABLE_STATIC, test x$enable_static = xyes)
if test x$enable_static = xyes -a x$have_plugins = xyes
then
  AC_DEFINE(ENABLE_STATIC, 1, [Link plugins statically into Wireshark])
fi
AC_SUBST(ENABLE_STATIC)

dnl Save the cacheable configure results to config.cache before recursing
AC_CACHE_SAVE

sinclude(plugins/Custom.m4) dnl
ifdef(_CUSTOM_AC_OUTPUT_,, define(_CUSTOM_AC_OUTPUT_, )) dnl

sinclude(asn1/Custom.m4) dnl
ifdef(_CUSTOM_ASN1_AC_OUTPUT_,, define(_CUSTOM_ASN1_AC_OUTPUT_, )) dnl

AC_CONFIG_HEADERS(config.h)
AC_OUTPUT(
  Makefile
  doxygen.cfg
  asn1/Makefile
  _CUSTOM_ASN1_AC_OUTPUT_
  asn1/acp133/Makefile
  asn1/acse/Makefile
  asn1/ansi_map/Makefile
  asn1/ansi_tcap/Makefile
  asn1/atn-cm/Makefile
  asn1/atn-cpdlc/Makefile
  asn1/atn-ulcs/Makefile
  asn1/c1222/Makefile
  asn1/camel/Makefile
  asn1/cdt/Makefile
  asn1/charging_ase/Makefile
  asn1/cmip/Makefile
  asn1/cmp/Makefile
  asn1/crmf/Makefile
  asn1/cms/Makefile
  asn1/credssp/Makefile
  asn1/dap/Makefile
  asn1/disp/Makefile
  asn1/dop/Makefile
  asn1/dsp/Makefile
  asn1/ess/Makefile
  asn1/ftam/Makefile
  asn1/goose/Makefile
  asn1/gprscdr/Makefile
  asn1/gsm_map/Makefile
  asn1/h225/Makefile
  asn1/h235/Makefile
  asn1/h245/Makefile
  asn1/h248/Makefile
  asn1/h282/Makefile
  asn1/h283/Makefile
  asn1/h323/Makefile
  asn1/h450/Makefile
  asn1/h450-ros/Makefile
  asn1/h460/Makefile
  asn1/h501/Makefile
  asn1/HI2Operations/Makefile
  asn1/hnbap/Makefile
  asn1/idmp/Makefile
  asn1/ilp/Makefile
  asn1/inap/Makefile
  asn1/isdn-sup/Makefile
  asn1/kerberos/Makefile
  asn1/lcsap/Makefile
  asn1/ldap/Makefile
  asn1/logotypecertextn/Makefile
  asn1/lpp/Makefile
  asn1/lppa/Makefile
  asn1/lppe/Makefile
  asn1/lte-rrc/Makefile
  asn1/m3ap/Makefile
  asn1/mms/Makefile
  asn1/mpeg-audio/Makefile
  asn1/mpeg-pes/Makefile
  asn1/nbap/Makefile
  asn1/ns_cert_exts/Makefile
  asn1/novell_pkis/Makefile
  asn1/ocsp/Makefile
  asn1/p1/Makefile
  asn1/p22/Makefile
  asn1/p7/Makefile
  asn1/p772/Makefile
  asn1/pcap/Makefile
  asn1/pkcs1/Makefile
  asn1/pkcs12/Makefile
  asn1/pkinit/Makefile
  asn1/pkixac/Makefile
  asn1/pkix1explicit/Makefile
  asn1/pkix1implicit/Makefile
  asn1/pkixproxy/Makefile
  asn1/pkixqualified/Makefile
  asn1/pkixtsp/Makefile
  asn1/pres/Makefile
  asn1/q932/Makefile
  asn1/q932-ros/Makefile
  asn1/qsig/Makefile
  asn1/ranap/Makefile
  asn1/rnsap/Makefile
  asn1/ros/Makefile
  asn1/rrc/Makefile
  asn1/rrlp/Makefile
  asn1/rtse/Makefile
  asn1/rua/Makefile
  asn1/s1ap/Makefile
  asn1/sabp/Makefile
  asn1/sbc-ap/Makefile
  asn1/smrse/Makefile
  asn1/snmp/Makefile
  asn1/spnego/Makefile
  asn1/sv/Makefile
  asn1/t124/Makefile
  asn1/t125/Makefile
  asn1/t38/Makefile
  asn1/tcap/Makefile
  asn1/tetra/Makefile
  asn1/ulp/Makefile
  asn1/wlancertextn/Makefile
  asn1/x2ap/Makefile
  asn1/x509af/Makefile
  asn1/x509ce/Makefile
  asn1/x509if/Makefile
  asn1/x509sat/Makefile
  asn1/x721/Makefile
  capchild/Makefile
  capchild/doxygen.cfg
  doc/Makefile
  docbook/Makefile
  epan/Makefile
  epan/crypt/Makefile
  epan/doxygen.cfg
  epan/dfilter/Makefile
  epan/dissectors/Makefile
  epan/dissectors/dcerpc/Makefile
  epan/dissectors/pidl/Makefile
  epan/ftypes/Makefile
  epan/wmem/Makefile
  epan/wslua/Makefile
  filetap/Makefile
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
  plugins/Makefile
  plugins/docsis/Makefile
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
  tools/Makefile
  tools/lemon/Makefile
  wiretap/Makefile
  wsutil/Makefile
  wsutil/nghttp2/Makefile
  echld/Makefile
  _CUSTOM_AC_OUTPUT_
  ,)
dnl AC_CONFIG_FILES([tools/setuid-root.pl], [chmod +x tools/setuid-root.pl])


# Pretty messages

if test "x$have_gtk" = "xyes"; then
	if test "x$with_gtk3" = "xyes"; then
		gtk_lib_message=" (with GTK+ 3"
	else
		gtk_lib_message=" (with GTK+ 2"
	fi
	if test "x$have_ige_mac" = "xyes"; then
		gtk_lib_message="$gtk_lib_message and Mac OS X integration)"
	else
		gtk_lib_message="$gtk_lib_message)"
	fi
fi

if test "x$have_qt" = "xyes" ; then
	enable_qtshark="yes"
else
	enable_qtshark="no"
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

if test "x$want_lua" = "xyes" ; then
	lua_message="yes"
else
	lua_message="no"
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
	c_ares_message="no"
fi

if test "x$have_good_adns" = "xyes" ; then
	adns_message="yes"
else
	if test "x$have_good_c_ares" = "xyes" ; then
		adns_message="no (using c-ares instead)"
	else
		adns_message="no"
	fi
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

echo ""
echo "The Wireshark package has been configured with the following options."
echo "             Build wireshark (Gtk+) : $have_gtk""$gtk_lib_message"
echo "                 Build wireshark-qt : $enable_qtshark"
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
echo "                        Build echld : $have_echld"
echo ""
echo "   Save files as pcap-ng by default : $enable_pcap_ng_default"
echo "  Install dumpcap with capabilities : $setcap_message"
echo "             Install dumpcap setuid : $setuid_message"
echo "                  Use dumpcap group : $dumpcap_group_message"
echo "                        Use plugins : $have_plugins"
echo "                    Use Lua library : $lua_message"
echo "                   Build rtp_player : $portaudio_message"
echo "             Build profile binaries : $enable_profile_build"
echo "                   Use pcap library : $want_pcap"
echo "                   Use zlib library : $zlib_message"
echo "               Use kerberos library : $krb5_message"
echo "                 Use c-ares library : $c_ares_message"
echo "               Use GNU ADNS library : $adns_message"
echo "                Use SMI MIB library : $libsmi_message"
echo "             Use GNU crypto library : $gcrypt_message"
echo "             Use SSL crypto library : $ssl_message"
echo "           Use IPv6 name resolution : $enable_ipv6"
echo "                 Use gnutls library : $tls_message"
echo "     Use POSIX capabilities library : $libcap_message"
echo "                  Use GeoIP library : $geoip_message"
echo "                     Use nl library : $libnl_message"
echo "              Use SBC codec library : $have_sbc"
