#!/usr/bin/env sh
# Setup development environment on BSD-like platforms.
#
# Tested on: FreeBSD, NetBSD, OpenBSD, DragonFly BSD.
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# We drag in tools that might not be needed by all users; it's easier
# that way.
#
# We do not use Bash as the shell for this script, and use the POSIX
# syntax for function definition rather than the
# "function <name>() { ... }" syntax, as FreeBSD 13, at least, does
# not have Bash, and its /bin/sh doesn't support the other syntax.
#
# XXX - at least on NetBSD, X11 is part of the system, not a package,
# and Qt depends on it, so you have to do an installation with X11.
#
# The same appears to be the case for OpenBSD.
#
# Should we check whether X11 is available?  Should we allow not
# Qt and other GUI stuff, for the benefit of people who jsut want
# to build command-line tools?
#
# XXX - on DragonFly BSD 6.4.2, the default GCC is too old to compile
# with the Qt installed as a package, so you have to upgrade or use
# (a sufficiently recent) Clang. gcc14 should work.
#
# Furthermore, DragonFly BSD's packages are a bit of a mess, in that,
# if you first install without the optional packages and then install
# with them, it decides it must remove some useful packages, such as
# git-lite and qt6-multimedia, presumably due to some stupid
# package incompatibility, so you may have to run the script several
# times until it reaches a fixed point.
#
# In addition, the BSD make on FreeBSD, NetBSD, and DragonFly BSD can't
# handle quoted target names in some cases, so the build fails due to
# the "No Reassembly" configuration profile having a space in its name,
# so you have to use Ninja. (OpenBSD's make appears to have fixed this.)
#

print_usage() {
	printf "\\nUtility to setup a bsd-based system for Wireshark Development.\\n"
	printf "The basic usage installs the needed software\\n\\n"
	printf "Usage: %s [--install-optional] [...other options...]\\n" "$0"
	printf "\\t--install-optional: install optional software as well\\n"
	printf "\\t[other]: other options are passed as-is to pkg manager.\\n"
}

ADDITIONAL=0
OPTIONS=
for arg; do
	case $arg in
		--help)
			print_usage
			exit 0
			;;
		--install-optional)
			ADDITIONAL=1
			;;
		*)
			OPTIONS="$OPTIONS $arg"
			;;
	esac
done

# Check if the user is root
if [ "$(id -u)" -ne 0 ]
then
	echo "You must be root."
	exit 1
fi

#
# XXX - we may need newer versions of GCC for some platforms.
# For example, the GCC supplied with DragonFly BSD 6.4.2 is
# GCC 8.3, which may not be able to handle some Qt 6 constructs.
#

BASIC_LIST="\
	cmake \
	pcre2 \
	speexdsp"

ADDITIONAL_LIST="\
	ccache \
	doxygen \
	gettext-tools \
	brotli \
	snappy \
	libmaxminddb \
	libsmi \
	zstd \
	"

# PNG compression utilities used by compress-pngs:
ADDITIONAL_LIST="$ADDITIONAL_LIST \
	advancecomp \
	optipng"

# Guess which package manager we will use
PM=$( which pkgin 2> /dev/null || which pkg 2> /dev/null || which pkg_add 2> /dev/null )

case $PM in
	*/pkgin)
		PM_OPTIONS="install"
		PM_SEARCH="pkgin search"
		PM_MUST_GLOB=no
		;;
	*/pkg)
		PM_OPTIONS="install"
		PM_SEARCH="pkg search"
		PM_MUST_GLOB=yes
		;;
	*/pkg_add)
		PM_OPTIONS=""
		PM_SEARCH="pkg_info"
		PM_MUST_GLOB=no
		;;
esac


echo "Using $PM ($PM_SEARCH)"

# Adds package $2 to list variable $1 if the package is found
add_package() {
	# shellcheck disable=SC3043
	local list="$1" pkgname="$2"

	# fail if the package is not known
	if [ "$PM_MUST_GLOB" = yes ]
	then
		#
		# We need to do a glob search, with a "*" at the
		# end, so we only find packages that *begin* with
		# the name; otherwise, searching for pkg-config
		# could find packages that *don't* begin with
		# pkg-config, but have it later in the name
		# (FreeBSD 11 has one such package), so when
		# we then try to install it, that fails.  Doing
		# an *exact* search fails, as that requires that
		# the package name include the version number.
		#
		$PM_SEARCH -g "$pkgname*" > /dev/null 2>&1 || return 1
	else
		$PM_SEARCH "$pkgname" > /dev/null 2>&1 || return 1
	fi

	# package is found, append it to list
	eval "${list}=\"\${${list}} \${pkgname}\""
}

# OpenBSD has its own pkg-config implementation, which is installed
# by default, so if we ahve a pkg-config command, don't try to
# install a package.
if which pkg-config >/dev/null 2>&1
then
	#
	# We have pkg-config; nothing to do.
	#
	:
else
	# pkg-config: NetBSD
	# pkgconf: FreeBSD, DragonFly BSD
	add_package BASIC_LIST pkg-config ||
	add_package BASIC_LIST pkgconf ||
	echo "pkg-config is unavailable"
fi

# Don't mess with an already-installed git.
# DragonFly BSD has both git-lite and git, and if  git-lite is installed
# and we try to install git, they're incompatible, so it uninstalls
# git-lite and doesn't end up installing git.
if which git >/dev/null 2>&1
then
	#
	# We have gti; nothing to do.
	#
	:
else
	add_package BASIC_LIST git ||
	echo "git is unavailable"
fi

# libcares: NetBSD, OpenBSD
# c-ares: FreeBSD, DragonFly BSD
# c-ares matches on NetBSD, but isn't the package name, so search for
# libcares first
add_package BASIC_LIST libcares ||
add_package BASIC_LIST c-ares ||
echo "c-ares is unavailable"

# libgcrypt
add_package BASIC_LIST libgcrypt ||
echo "libgcrypt is unavailable"

# glib2: NetBSD, OpenBSD
# glib: FreeBSD, DragonFly BSD
add_package BASIC_LIST glib2 ||
add_package BASIC_LIST glib ||
echo "GLib 2 is unavailable"

# qt6-qtbase: NetBSD, OpenBSD
# qt6-base: FreeBSD, DragonFly BSD
# At least on NetBSD, this installs Python
add_package BASIC_LIST qt6-qtbase ||
add_package BASIC_LIST qt6-base ||
echo "Qt6 is unavailable"

# qt6-qtmultimediat: NetBSD, OpenBSD
# qt6-multimedia: FreeBSD, DragonFly BSD
add_package BASIC_LIST qt6-qtmultimedia ||
add_package BASIC_LIST qt6-multimedia ||
echo "Qt6 multimedia is unavailable"

# qt6-qttools: NetBSD, OpenBSD
# qt6-tools: FreeBSD, DragonFly BSD
add_package BASIC_LIST qt6-qttools ||
add_package BASIC_LIST qt6-tools ||
echo "Qt6 tools is unavailable"

# libxslt: FreeBSD, OpenBSD, NetBSD, DragonFly BSD
# load this for xsltproc
add_package ADDITIONAL_LIST libxslt ||
echo "libxslt is unavailable"

# rubygem-asciidoctor: FreeBSD, DragonFly BSD
# ruby40-asciidoctor: NetBSD
# asciidoctor: OpenBSD
# XXX - not being found by CMake on NetBSD; it's called "asciidoctor40",
# presumably because they have multiple different Ruby packages for
# different Ruby versions
add_package ADDITIONAL_LIST rubygem-asciidoctor ||
add_package ADDITIONAL_LIST ruby40-asciidoctor ||
add_package ADDITIONAL_LIST asciidoctor ||
echo "asciidoctor is unavailable"

# liblz4: FreeBSD, DragonFly BSD
# lz4: NetBSD, OpenBSD
add_package ADDITIONAL_LIST liblz4 ||
add_package ADDITIONAL_LIST lz4 ||
echo "lz4 is unavailable"

# libnghttp2: FreeBSD, DragonFly BSD
# nghttp2: NetBSD, OpenBSD
add_package ADDITIONAL_LIST libnghttp2 ||
add_package ADDITIONAL_LIST nghttp2 ||
echo "nghttp2 is unavailable"

# libnghttp3: FreeBSD, DragonFly BSD
# nghttp3: NetBSD, OpenBSD
add_package ADDITIONAL_LIST libnghttp3 ||
add_package ADDITIONAL_LIST nghttp3 ||
echo "nghttp3 is unavailable"

# spandsp: FreeBSD, NetBSD, OpenBSD, DragonFly BSD
add_package ADDITIONAL_LIST spandsp ||
echo "spandsp is unavailable"

# Most BSDs provide Kerberos by default; OpenBSD doesn't.
# Check for a system krb5.h header.
if [ -e /usr/include/krb5.h ] || [ -e /usr/include/krb5/krb5.h ]
then
	# FreeBSD, NetBSD
	# We have it; no need to install anything.
	:
else
	# krb5 (MIT Kerberos): DragonFly BSD
	# heimdal: OpenBSD
	# Prefer MIT kerberos to Heimdal
	# XXX - heimdal isn't foun by CMake in OpenBSD
	add_package ADDITIONAL_LIST krb5 ||
	add_package ADDITIONAL_LIST heimdal ||
	echo "Kerberos is unavailable"
fi

# libssh2 and libssh: FreeBSD, NetBSD, OpenBSD, DragonFly BSD
# DragonFly BSD's libssh appears to depend on Heimdal Kerberos, and
# this conflicts with the (MIT) krb5 package that would be installed
# above, so try libssh2 first
# XXX - Libssh2 isn't found by CMake
add_package ADDITIONAL_LIST libssh2 ||
add_package ADDITIONAL_LIST libssh ||
echo "libssh is unavailable"

# xxhash: FreeBSD, NetBSD, OpenBSD, DragonFly BSD
add_package ADDITIONAL_LIST xxhash ||
echo "xxhash is unavailable"

# zlib-ng: FreeBSD, NetBSD, DragonFly BSD
# Not available on OpenBSD
add_package ADDITIONAL_LIST zlib-ng ||
echo "zlib-ng is unavailable"

# minizip-ng: FreeBSD, NetBSD, DragonFly BSD
# Not available on OpenBSD
# XXX - not being found by CMake on NetBSD; no unzip.h file?
add_package ADDITIONAL_LIST minizip-ng ||
echo "minizip-ng is unavailable"

# minizip: FreeBSD, NetBSD, OpenBSD, DragonFly BSD
add_package ADDITIONAL_LIST minizip ||
echo "minizip is unavailable"

# bcg729: FreeBSD, OpenBSD, DragonFly BSD
# Not available on NetBSD
add_package ADDITIONAL_LIST bcg729 ||
echo "bcg729 is unavailable"

# opencore-amr: FreeBSD, NetBSD, OpenBSD, DragonFly BSD
add_package ADDITIONAL_LIST opencore-amr ||
echo "opencore-amr is unavailable"

# ninja: FreeBSD, OpenBSD, DragonFly BSD
# ninja-build: NetBSD
# ninja is a package for an IRC client on NetBSD, so we search for
# ninja-build first
add_package ADDITIONAL_LIST ninja-build ||
add_package ADDITIONAL_LIST ninja ||
echo "ninja is unavailable"

# libilbc: FreeBSD, NetBSD
# ilbc: DragonFly BSD
# Not available on OpenBSD
# XXX - on DragonFly BSD, it doesn't find the include directory
add_package ADDITIONAL_LIST libilbc ||
add_package ADDITIONAL_LIST ilbc ||
echo "libilbc is unavailable"

# gnutls: FreeBSD, NetBSD, OpenBSD, DragonFly BSD
add_package ADDITIONAL_LIST gnutls ||
echo "gnutls is unavailable"

# lua54: FreeBSD, NetBSD, DragonFly BSD
# lua53 is also acceptable
# lua55?
# lua: OpenBSD latest (current 5.4)
add_package ADDITIONAL_LIST lua54 ||
add_package ADDITIONAL_LIST lua53 ||
add_package ADDITIONAL_LIST lua ||
echo "lua >= 5.3 is unavailable"

# pngcrush: NetBSD, OpenBSD
# Not available on FreeBSD or DragonFly BSD
add_package ADDITIONAL_LIST pngcrush ||
echo "pngcrush is unavailable"

ACTUAL_LIST=$BASIC_LIST

# Now arrange for optional support libraries
if [ $ADDITIONAL -ne 0 ]
then
	ACTUAL_LIST="$ACTUAL_LIST $ADDITIONAL_LIST"
fi

# shellcheck disable=SC2086
$PM $PM_OPTIONS $ACTUAL_LIST $OPTIONS
if [ ! $? ]
then
	exit 2
fi

if [ $ADDITIONAL -eq 0 ]
then
	printf "\\n*** Optional packages not installed. Rerun with --install-optional to have them.\\n"
fi
