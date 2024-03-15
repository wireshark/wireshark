#!/bin/bash
# Copyright 2014, Evan Huus (See AUTHORS file)
#
# Enhance (2016) by Alexis La Goutte (For use with Travis CI)
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

set -e -u -o pipefail

eval "$(brew shellenv)"

HOMEBREW_NO_AUTO_UPDATE=${HOMEBREW_NO_AUTO_UPDATE:-}

function print_usage() {
    printf "\\nUtility to setup a macOS system for Wireshark Development using Homebrew.\\n"
    printf "The basic usage installs the needed software\\n\\n"
    printf "Usage: %s [--install-optional] [--install-dmg-deps] [...other options...]\\n" "$0"
    printf "\\t--install-optional: install optional software as well\\n"
    printf "\\t--install-dmg-deps: install packages required to build the .dmg file\\n"
    printf "\\t--install-sparkle-deps: install the Sparkle automatic updater\\n"
    printf "\\t--install-all: install everything\\n"
    printf "\\t[other]: other options are passed as-is to apt\\n"
}

INSTALLED_FORMULAE=$( brew list --formulae )
function install_formulae() {
    INSTALL_LIST=()
    for FORMULA in "$@" ; do
        if ! grep --word-regexp "$FORMULA" > /dev/null 2>&1 <<<"$INSTALLED_FORMULAE" ; then
            INSTALL_LIST+=( "$FORMULA" )
        fi
    done
    if (( ${#INSTALL_LIST[@]} != 0 )); then
        brew install "${INSTALL_LIST[@]}"
    else
        printf "Nothing to install.\n"
    fi
}

INSTALL_OPTIONAL=0
INSTALL_DOC_DEPS=0
INSTALL_DMG_DEPS=0
INSTALL_SPARKLE_DEPS=0
INSTALL_TEST_DEPS=0
OPTIONS=()
for arg; do
    case $arg in
        --help)
            print_usage
            exit 0
            ;;
        --install-optional)
            INSTALL_OPTIONAL=1
            ;;
        --install-doc-deps)
            INSTALL_DOC_DEPS=1
            ;;
        --install-dmg-deps)
            INSTALL_DMG_DEPS=1
            ;;
        --install-sparkle-deps)
            INSTALL_SPARKLE_DEPS=1
            ;;
        --install-test-deps)
            INSTALL_TEST_DEPS=1
            ;;
        --install-all)
            INSTALL_OPTIONAL=1
            INSTALL_DOC_DEPS=1
            INSTALL_DMG_DEPS=1
            INSTALL_SPARKLE_DEPS=1
            INSTALL_TEST_DEPS=1
            ;;
        *)
            OPTIONS+=("$arg")
            ;;
    esac
done

BUILD_LIST=(
    ccache
    cmake
    ninja
)

# Qt isn't technically required, but...
REQUIRED_LIST=(
    c-ares
    glib
    libgcrypt
    pcre2
    qt6
    speexdsp
)

ADDITIONAL_LIST=(
    brotli
    gettext
    gnutls
    libilbc
    libmaxminddb
    libnghttp2
    libnghttp3
    libsmi
    libssh
    libxml2
    lua
    lz4
    minizip
    opencore-amr
    opus
    snappy
    spandsp
    zstd
)

DOC_DEPS_LIST=(
    asciidoctor
    docbook
    docbook-xsl
)

ACTUAL_LIST=( "${BUILD_LIST[@]}" "${REQUIRED_LIST[@]}" )

# Now arrange for optional support libraries
if [ $INSTALL_OPTIONAL -ne 0 ] ; then
    ACTUAL_LIST+=( "${ADDITIONAL_LIST[@]}" )
fi

if [ $INSTALL_DOC_DEPS -ne 0 ] ; then
    ACTUAL_LIST+=( "${DOC_DEPS_LIST[@]}" )
fi

if (( ${#OPTIONS[@]} != 0 )); then
    ACTUAL_LIST+=( "${OPTIONS[@]}" )
fi

install_formulae "${ACTUAL_LIST[@]}"

if [ $INSTALL_DMG_DEPS -ne 0 ] ; then
    printf "Sorry, you'll have to install dmgbuild yourself for the time being.\\n"
    # pip3 install dmgbuild
fi

if [ $INSTALL_SPARKLE_DEPS -ne 0 ] ; then
    brew cask install sparkle
fi

if [ $INSTALL_TEST_DEPS -ne 0 ] ; then
    printf "Sorry, you'll have to install pytest and pytest-xdist yourself for the time being.\\n"
    # pip3 install pytest pytest-xdist
fi

# Uncomment to add PNG compression utilities used by compress-pngs:
# brew install advancecomp optipng oxipng pngcrush

# Uncomment to enable generation of documentation
# brew install asciidoctor

exit 0
#
#  Editor modelines
#
#  Local Variables:
#  c-basic-offset: 4
#  tab-width: 8
#  indent-tabs-mode: nil
#  End:
#
#  ex: set shiftwidth=4 tabstop=8 expandtab:
#  :indentSize=4:tabSize=8:noTabs=true:
#
