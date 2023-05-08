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

# Update to last brew release
if [ -z "$HOMEBREW_NO_AUTO_UPDATE" ] ; then
    brew update
fi

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
INSTALL_DMG_DEPS=0
INSTALL_SPARKLE_DEPS=0
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
        --install-dmg-deps)
            INSTALL_DMG_DEPS=1
            ;;
        --install-sparkle-deps)
            INSTALL_SPARKLE_DEPS=1
            ;;
        --install-all)
            INSTALL_OPTIONAL=1
            INSTALL_DMG_DEPS=1
            INSTALL_SPARKLE_DEPS=1
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
    libsmi
    libssh
    libxml2
    lua@5.1
    lz4
    minizip
    nghttp2
    opus
    snappy
    spandsp
    zstd
)

ACTUAL_LIST=( "${BUILD_LIST[@]}" "${REQUIRED_LIST[@]}" )

# Now arrange for optional support libraries
if [ $INSTALL_OPTIONAL -ne 0 ] ; then
    ACTUAL_LIST+=( "${ADDITIONAL_LIST[@]}" )
fi

if (( ${#OPTIONS[@]} != 0 )); then
    ACTUAL_LIST+=( "${OPTIONS[@]}" )
fi

install_formulae "${ACTUAL_LIST[@]}"

# Install python modules
pip3 install pytest pytest-xdist

if [ $INSTALL_DMG_DEPS -ne 0 ] ; then
    pip3 install dmgbuild
    pip3 install biplist
fi

if [ $INSTALL_SPARKLE_DEPS -ne 0 ] ; then
    brew cask install sparkle
fi

# Uncomment to add PNG compression utilities used by compress-pngs:
# brew install advancecomp optipng oxipng pngcrush

# Uncomment to enable generation of documentation
# brew install asciidoctor

if [ -z "$HOMEBREW_NO_AUTO_UPDATE" ] ; then
    brew doctor
fi

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
