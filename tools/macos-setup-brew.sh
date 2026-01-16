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
    printf "\\t--install-required: install third party libraries required to build Wireshark\\n"
    printf "\\t  (You should probably set WIRESHARK_BASE_DIR instead:\\n"
    printf "\\t  (https://www.wireshark.org/docs/wsdg_html_chunked/ChapterSetup.html#_macos)\\n"
    printf "\\t--install-optional: install optional third party libraries\\n"
    printf "\\t  (You should probably set WIRESHARK_BASE_DIR instead.)\\n"
    printf "\\t--install-doc-deps: install packages required to build the documentation\\n"
    printf "\\t  (You should probably set WIRESHARK_BASE_DIR instead.)\\n"
    printf "\\t--install-dmg-deps: install packages required to build the .dmg file\\n"
    printf "\\t--install-sparkle-deps: install the Sparkle automatic updater\\n"
    printf "\\t--install-test-deps: install packages required for automated testing\\n"
    printf "\\t--install-all: install everything\\n"
    printf "\\t  (You should probably set WIRESHARK_BASE_DIR instead.)\\n"
    printf "\\t--install-stratoshark: install everything to compile Stratoshark and the Falco Events plugin\\n"
    printf "\\t[other]: other options are passed as-is to brew\\n"
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

INSTALL_REQUIRED=0
INSTALL_OPTIONAL=0
INSTALL_DOC_DEPS=0
INSTALL_DMG_DEPS=0
INSTALL_SPARKLE_DEPS=0
INSTALL_TEST_DEPS=0
INSTALL_STRATOSHARK=0
OPTIONS=()
for arg; do
    case $arg in
        --help|-h)
            print_usage
            exit 0
            ;;
        --install-required)
            INSTALL_REQUIRED=1
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
        --install-stratoshark)
            INSTALL_STRATOSHARK=1
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
    pkgconf
)

# Qt isn't technically required, but...
REQUIRED_LIST=(
    c-ares
    glib
    libgcrypt
    libxml2
    pcre2
    qt6
    speexdsp
)

OPTIONAL_LIST=(
    brotli
    gettext
    gnutls
    libilbc
    libmaxminddb
    libnghttp2
    libnghttp3
    libsmi
    libssh
    lua
    lz4
    minizip
    minizip-ng
    opencore-amr
    opus
    snappy
    spandsp
    xxhash
    zlib-ng
    zstd
)

DOC_DEPS_LIST=(
    asciidoctor
    docbook
    docbook-xsl
)

STRATOSHARK_LIST=(
    jsoncpp
    onetbb
    re2
    uthash
)

ACTUAL_LIST=( "${BUILD_LIST[@]}" )

if [ $INSTALL_REQUIRED -ne 0 ] ; then
    ACTUAL_LIST+=( "${REQUIRED_LIST[@]}" )
fi

# Now arrange for optional support libraries
if [ $INSTALL_OPTIONAL -ne 0 ] ; then
    ACTUAL_LIST+=( "${OPTIONAL_LIST[@]}" )
fi

if [ $INSTALL_DOC_DEPS -ne 0 ] ; then
    ACTUAL_LIST+=( "${DOC_DEPS_LIST[@]}" )
fi

if [ $INSTALL_STRATOSHARK -ne 0 ] ; then
    ACTUAL_LIST+=( "${STRATOSHARK_LIST[@]}" )
fi

if (( ${#OPTIONS[@]} != 0 )); then
    ACTUAL_LIST+=( "${OPTIONS[@]}" )
fi

install_formulae "${ACTUAL_LIST[@]}"

if [ $INSTALL_DMG_DEPS -ne 0 ] ; then
    printf "Sorry, you'll have to install dmgbuild yourself for the time being.\\n"
    # pip3 install "dmgbuild[badge_icons]"
fi

if [ $INSTALL_SPARKLE_DEPS -ne 0 ] ; then
    brew install --cask sparkle
fi

if [ $INSTALL_TEST_DEPS -ne 0 ] ; then
    printf "Sorry, you'll have to install pytest and pytest-xdist yourself for the time being.\\n"
    # pip3 install pytest pytest-xdist
fi

if [ $INSTALL_STRATOSHARK -ne 0 ] ; then
    FALCO_LIBS_VERSION=0.22.2
    FALCO_LIBS_SHA256=53cfb7062cac80623dec7496394739aabdfee8a774942f94be0990d81e3b2fbc
    if [ "$FALCO_LIBS_VERSION" ] && [ ! -f "falco-libs-$FALCO_LIBS_VERSION-done" ] ; then
        echo "Downloading, building, and installing libsinsp and libscap:"
        [ -f "falco-libs-$FALCO_LIBS_VERSION.tar.gz" ] || curl -L -O --remote-header-name "https://github.com/falcosecurity/libs/archive/refs/tags/$FALCO_LIBS_VERSION.tar.gz"
        mv "libs-$FALCO_LIBS_VERSION.tar.gz" "falco-libs-$FALCO_LIBS_VERSION.tar.gz"
        echo "$FALCO_LIBS_SHA256  falco-libs-$FALCO_LIBS_VERSION.tar.gz" | shasum --algorithm 256 --check
        tar -xf "falco-libs-$FALCO_LIBS_VERSION.tar.gz"
        mv "libs-$FALCO_LIBS_VERSION" "falco-libs-$FALCO_LIBS_VERSION"
        cd "falco-libs-$FALCO_LIBS_VERSION"
        mkdir build_dir
        cd build_dir
        cmake -DFALCOSECURITY_LIBS_VERSION="$FALCO_LIBS_VERSION" \
            -DBUILD_SHARED_LIBS=ON -DMINIMAL_BUILD=ON -DCREATE_TEST_TARGETS=OFF \
            -DUSE_BUNDLED_DEPS=ON -DUSE_BUNDLED_CARES=OFF -DUSE_BUNDLED_ZLIB=OFF \
            -DUSE_BUNDLED_JSONCPP=OFF -DUSE_BUNDLED_TBB=OFF -DUSE_BUNDLED_RE2=OFF \
            ..
        make
        sudo make install
        cd ../..
    fi
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
