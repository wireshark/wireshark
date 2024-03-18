#!/bin/bash
# Setup development environment on MSYS2
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

function print_usage() {
	printf "\\nUtility to setup an MSYS2 MinGW-w64 system for Wireshark development.\\n"
	printf "The basic usage installs the needed software\\n\\n"
	printf "Usage: %s [--install-optional] [...other options...]\\n" "$0"
	printf "\\t--install-optional: install optional software as well\\n"
	printf "\\t--install-nsis-deps: install packages required to build NSIS installer\\n"
	printf "\\t--install-test-deps: install packages required to run all tests\\n"
	printf "\\t--install-all: install everything\\n"
	printf "\\t[other]: other options are passed as-is to pacman\\n"
	printf "\\tPass --noconfirm to bypass any \"are you sure?\" messages.\\n"
}

ADDITIONAL=0
TESTDEPS=0
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
		--install-nsis-deps)
			NSISDEPS=1
			;;
		--install-test-deps)
			TESTDEPS=1
			;;
		--install-all)
			ADDITIONAL=1
			NSISDEPS=1
			TESTDEPS=1
			;;
		*)
			OPTIONS="$OPTIONS $arg"
			;;
	esac
done

PACKAGE_PREFIX="${MINGW_PACKAGE_PREFIX:-mingw-w64-x86_64}"

#
# Lua packaging is kind of a mess. Lua 5.2 is not available. Some packages have
# a hard dependency on LuaJIT and it conflicts with Lua 5.1 and vice-versa.
# This will probably have to be fixed by the MSYS2 maintainers.
# XXX Is this still true? We can use Lua 5.3 and 5.4 now, though we still
# might want to package our own version to use our UTF-8 on Windows patch
# (though we don't apply that patch yet.)
#
BASIC_LIST="base-devel \
	git \
	${PACKAGE_PREFIX}-bcg729 \
	${PACKAGE_PREFIX}-brotli \
	${PACKAGE_PREFIX}-c-ares \
	${PACKAGE_PREFIX}-cmake \
	${PACKAGE_PREFIX}-glib2 \
	${PACKAGE_PREFIX}-gnutls \
	${PACKAGE_PREFIX}-libgcrypt \
	${PACKAGE_PREFIX}-libilbc \
	${PACKAGE_PREFIX}-libmaxminddb \
	${PACKAGE_PREFIX}-nghttp2 \
	${PACKAGE_PREFIX}-libpcap \
	${PACKAGE_PREFIX}-libsmi \
	${PACKAGE_PREFIX}-libssh \
	${PACKAGE_PREFIX}-libxml2 \
	${PACKAGE_PREFIX}-lz4 \
	${PACKAGE_PREFIX}-minizip \
	${PACKAGE_PREFIX}-ninja \
	${PACKAGE_PREFIX}-opencore-amr \
	${PACKAGE_PREFIX}-opus \
	${PACKAGE_PREFIX}-pcre2 \
	${PACKAGE_PREFIX}-python \
	${PACKAGE_PREFIX}-qt6-base \
	${PACKAGE_PREFIX}-qt6-multimedia \
	${PACKAGE_PREFIX}-qt6-tools \
	${PACKAGE_PREFIX}-qt6-translations \
	${PACKAGE_PREFIX}-qt6-5compat \
	${PACKAGE_PREFIX}-sbc \
	${PACKAGE_PREFIX}-snappy \
	${PACKAGE_PREFIX}-spandsp \
	${PACKAGE_PREFIX}-speexdsp \
	${PACKAGE_PREFIX}-toolchain \
	${PACKAGE_PREFIX}-winsparkle \
	${PACKAGE_PREFIX}-zlib \
	${PACKAGE_PREFIX}-zstd"

ADDITIONAL_LIST="${PACKAGE_PREFIX}-asciidoctor \
	${PACKAGE_PREFIX}-ccache \
	${PACKAGE_PREFIX}-docbook-xsl \
	${PACKAGE_PREFIX}-doxygen \
	${PACKAGE_PREFIX}-libxslt \
	${PACKAGE_PREFIX}-perl \
	${PACKAGE_PREFIX}-ntldd"

NSISDEPS_LIST="${PACKAGE_PREFIX}-nsis"

TESTDEPS_LIST="${PACKAGE_PREFIX}-python-pytest \
	${PACKAGE_PREFIX}-python-pytest-xdist"

ACTUAL_LIST=$BASIC_LIST

if [ $ADDITIONAL -ne 0 ]
then
	ACTUAL_LIST="$ACTUAL_LIST $ADDITIONAL_LIST"
fi

if [ $NSISDEPS -ne 0 ]
then
	ACTUAL_LIST="$ACTUAL_LIST $NSISDEPS_LIST"
fi

if [ $TESTDEPS -ne 0 ]
then
	ACTUAL_LIST="$ACTUAL_LIST $TESTDEPS_LIST"
fi

# Partial upgrades are unsupported.
pacman --sync --refresh --sysupgrade --needed $ACTUAL_LIST $OPTIONS || exit 2

if [ $ADDITIONAL -eq 0 ]
then
	printf "\n*** Optional packages not installed. Rerun with --install-optional to have them.\n"
fi

if [ $NSISDEPS -eq 0 ]
then
	printf "\n*** NSIS installer deps not installed. Rerun with --install-nsis-deps to have them.\n"
fi

if [ $TESTDEPS -eq 0 ]
then
	printf "\n*** Test deps not installed. Rerun with --install-test-deps to have them.\n"
fi
