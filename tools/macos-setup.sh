#!/bin/bash
# Setup development environment on macOS (tested with 10.6.8 and Xcode
# 3.2.6 and with 10.12.4 and Xcode 8.3).
#
# Copyright 2011 Michael Tuexen, Joerg Mayer, Guy Harris (see AUTHORS file)
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

shopt -s extglob

#
# Get the major version of Darwin, so we can check the major macOS
# version.
#
DARWIN_MAJOR_VERSION=`uname -r | sed 's/\([0-9]*\).*/\1/'`

#
# To make this work on Leopard (rather than working *on* Snow Leopard
# when building *for* Leopard) will take more work.
#
if [[ $DARWIN_MAJOR_VERSION -le 9 ]]; then
    echo "This script does not support any versions of macOS before Snow Leopard" 1>&2
    exit 1
fi

#
# Versions of packages to download and install.
#

#
# We use curl, but older versions of curl in older macOS releases can't
# handle some sites - including the xz site.
#
# If the version of curl in the system is older than 7.54.0, download
# curl and install it.
#
current_curl_version=`curl --version | sed -n 's/curl \([0-9.]*\) .*/\1/p'`
current_curl_major_version="`expr $current_curl_version : '\([0-9][0-9]*\).*'`"
current_curl_minor_version="`expr $current_curl_version : '[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
if [[ $current_curl_major_version -lt 7 ||
     ($current_curl_major_version -eq 7 &&
      $current_curl_minor_version -lt 54) ]]; then
    CURL_VERSION=${CURL_VERSION-7.60.0}
fi

#
# Some packages need xz to unpack their current source.
# While tar, in newer versions of macOS, can uncompress xz'ed tarballs,
# it can't do so in older versions, and xz isn't provided with macOS.
#
XZ_VERSION=5.2.3

#
# Some packages need lzip to unpack their current source.
#
LZIP_VERSION=1.19

#
# CMake is required to do the build.
#
# Sigh.  CMake versions 3.7 and later fail on Lion due to issues with
# Lion's libc++, and CMake 3.5 and 3.6 have an annoying "Make sure the
# combination of SDK and Deployment Target are allowed" check that fails
# in some cases.
#
# So if you're on Lion, we choose version 3.5.2, otherwise we choose
# the latest stable version (currently 3.12.4).
#
if [[ $DARWIN_MAJOR_VERSION -gt 11 ]]; then
    CMAKE_VERSION=${CMAKE_VERSION-3.12.4}
else
    CMAKE_VERSION=${CMAKE_VERSION-3.5.2}
fi

#
# Ninja isn't required, as make is provided with Xcode, but it is
# claimed to build faster than make.
# Comment it out if you don't want it.
#
NINJA_VERSION=${NINJA_VERSION-1.8.2}

#
# The following libraries and tools are required even to build only TShark.
#
GETTEXT_VERSION=0.19.8.1
GLIB_VERSION=2.37.6
PKG_CONFIG_VERSION=0.29.2
#
# libgpg-error is required for libgcrypt.
#
LIBGPG_ERROR_VERSION=1.37
#
# libgcrypt is required.
#
LIBGCRYPT_VERSION=1.8.5

#
# One or more of the following libraries are required to build Wireshark.
#
# To override the version of Qt call the script with some of the variables
# set to the new values. Setting the variable to empty will disable building
# the toolkit and will uninstall # any version previously installed by the
# script, e.g.
# "QT_VERSION=5.10.1 ./macos-setup.sh"
# will build and install with QT 5.10.1.
#
# Note that Qt 5, prior to 5.5.0, mishandles context menus in ways that,
# for example, cause them not to work reliably in the packet detail or
# packet data pane; see, for example, Qt bugs QTBUG-31937, QTBUG-41017,
# and QTBUG-43464, all of which seem to be the same bug.
#
QT_VERSION=${QT_VERSION-5.12.4}

if [ "$QT_VERSION" ]; then
    QT_MAJOR_VERSION="`expr $QT_VERSION : '\([0-9][0-9]*\).*'`"
    QT_MINOR_VERSION="`expr $QT_VERSION : '[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
    QT_DOTDOT_VERSION="`expr $QT_VERSION : '[0-9][0-9]*\.[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
    QT_MAJOR_MINOR_VERSION=$QT_MAJOR_VERSION.$QT_MINOR_VERSION
    QT_MAJOR_MINOR_DOTDOT_VERSION=$QT_MAJOR_VERSION.$QT_MINOR_VERSION.$QT_DOTDOT_VERSION
fi

#
# The following libraries are optional.
# Comment them out if you don't want them, but note that some of
# the optional libraries are required by other optional libraries.
#
LIBSMI_VERSION=0.4.8
GNUTLS_VERSION=3.6.14
if [ "$GNUTLS_VERSION" ]; then
    #
    # We'll be building GnuTLS, so we may need some additional libraries.
    # We assume GnuTLS can work with Nettle; newer versions *only* use
    # Nettle, not libgcrypt.
    #
    GNUTLS_MAJOR_VERSION="`expr $GNUTLS_VERSION : '\([0-9][0-9]*\).*'`"
    GNUTLS_MINOR_VERSION="`expr $GNUTLS_VERSION : '[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
    NETTLE_VERSION=3.6

    #
    # And, in turn, Nettle requires GMP.
    #
    GMP_VERSION=6.2.0
fi
# Use 5.2.4, not 5.3, for now; lua_bitop.c hasn't been ported to 5.3
# yet, and we need to check for compatibility issues (we'd want Lua
# scripts to work with 5.1, 5.2, and 5.3, as long as they only use Lua
# features present in all three versions)
LUA_VERSION=5.2.4
SNAPPY_VERSION=1.1.4
ZSTD_VERSION=1.4.2
LIBXML2_VERSION=2.9.9
LZ4_VERSION=1.7.5
SBC_VERSION=1.3
CARES_VERSION=1.15.0
LIBSSH_VERSION=0.9.0
# mmdbresolve
MAXMINDDB_VERSION=1.3.2
NGHTTP2_VERSION=1.39.2
SPANDSP_VERSION=0.0.6
SPEEXDSP_VERSION=1.2.0
if [ "$SPANDSP_VERSION" ]; then
    #
    # SpanDSP depends on libtiff.
    #
    LIBTIFF_VERSION=3.8.1
fi
BCG729_VERSION=1.0.2
ILBC_VERSION=2.0.2
PYTHON3_VERSION=3.7.1
BROTLI_VERSION=1.0.7
# minizip
ZLIB_VERSION=1.2.11
# Uncomment to enable automatic updates using Sparkle
#SPARKLE_VERSION=1.22.0

#
# Asciidoctor is required to build the documentation.
#
ASCIIDOCTOR_VERSION=${ASCIIDOCTOR_VERSION-2.0.10}
ASCIIDOCTORPDF_VERSION=${ASCIIDOCTORPDF_VERSION-1.5.0.beta.5}

#
# GNU autotools; they're provided with releases up to Snow Leopard, but
# not in later releases, and the Snow Leopard version is too old for
# current Wireshark, so we install them unconditionally.
#
AUTOCONF_VERSION=2.69
AUTOMAKE_VERSION=1.15
LIBTOOL_VERSION=2.4.6

install_curl() {
    if [ "$CURL_VERSION" -a ! -f curl-$CURL_VERSION-done ] ; then
        echo "Downloading, building, and installing curl:"
        [ -f curl-$CURL_VERSION.tar.bz2 ] || curl -L -O https://curl.haxx.se/download/curl-$CURL_VERSION.tar.bz2 || exit 1
        $no_build && echo "Skipping installation" && return
        bzcat curl-$CURL_VERSION.tar.bz2 | tar xf - || exit 1
        cd curl-$CURL_VERSION
        ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch curl-$CURL_VERSION-done
    fi
}

uninstall_curl() {
    if [ ! -z "$installed_curl_version" ] ; then
        echo "Uninstalling curl:"
        cd curl-$installed_curl_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm curl-$installed_curl_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf curl-$installed_curl_version
            rm -rf curl-$installed_curl_version.tar.bz2
        fi

        installed_curl_version=""
    fi
}

install_xz() {
    if [ "$XZ_VERSION" -a ! -f xz-$XZ_VERSION-done ] ; then
        echo "Downloading, building, and installing xz:"
        [ -f xz-$XZ_VERSION.tar.bz2 ] || curl -L -O http://tukaani.org/xz/xz-$XZ_VERSION.tar.bz2 || exit 1
        $no_build && echo "Skipping installation" && return
        bzcat xz-$XZ_VERSION.tar.bz2 | tar xf - || exit 1
        cd xz-$XZ_VERSION
        #
        # This builds and installs liblzma, which libxml2 uses, and
        # Wireshark uses liblzma, so we need to build this with
        # all the minimum-deployment-version and SDK stuff.
        #
        CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=0 $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch xz-$XZ_VERSION-done
    fi
}

uninstall_xz() {
    if [ ! -z "$installed_xz_version" ] ; then
        echo "Uninstalling xz:"
        cd xz-$installed_xz_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm xz-$installed_xz_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf xz-$installed_xz_version
            rm -rf xz-$installed_xz_version.tar.bz2
        fi

        installed_xz_version=""
    fi
}

install_lzip() {
    if [ "$LZIP_VERSION" -a ! -f lzip-$LZIP_VERSION-done ] ; then
        echo "Downloading, building, and installing lzip:"
        [ -f lzip-$LZIP_VERSION.tar.gz ] || curl -L -O http://download.savannah.gnu.org/releases/lzip/lzip-$LZIP_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat lzip-$LZIP_VERSION.tar.gz | tar xf - || exit 1
        cd lzip-$LZIP_VERSION
        ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch lzip-$LZIP_VERSION-done
    fi
}

uninstall_lzip() {
    if [ ! -z "$installed_lzip_version" ] ; then
        echo "Uninstalling lzip:"
        cd lzip-$installed_lzip_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm lzip-$installed_lzip_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf lzip-$installed_lzip_version
            rm -rf lzip-$installed_lzip_version.tar.gz
        fi

        installed_lzip_version=""
    fi
}

install_autoconf() {
    if [ "$AUTOCONF_VERSION" -a ! -f autoconf-$AUTOCONF_VERSION-done ] ; then
        echo "Downloading, building and installing GNU autoconf..."
        [ -f autoconf-$AUTOCONF_VERSION.tar.xz ] || curl -L -O ftp://ftp.gnu.org/gnu/autoconf/autoconf-$AUTOCONF_VERSION.tar.xz || exit 1
        $no_build && echo "Skipping installation" && return
        xzcat autoconf-$AUTOCONF_VERSION.tar.xz | tar xf - || exit 1
        cd autoconf-$AUTOCONF_VERSION
        ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch autoconf-$AUTOCONF_VERSION-done
    fi
}

uninstall_autoconf() {
    if [ ! -z "$installed_autoconf_version" ] ; then
        #
        # automake and libtool depend on this, so uninstall them.
        #
        uninstall_libtool
        uninstall_automake

        echo "Uninstalling GNU autoconf:"
        cd autoconf-$installed_autoconf_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm autoconf-$installed_autoconf_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf autoconf-$installed_autoconf_version
            rm -rf autoconf-$installed_autoconf_version.tar.xz
        fi

        installed_autoconf_version=""
    fi
}

install_automake() {
    if [ "$AUTOMAKE_VERSION" -a ! -f automake-$AUTOMAKE_VERSION-done ] ; then
        echo "Downloading, building and installing GNU automake..."
        [ -f automake-$AUTOMAKE_VERSION.tar.xz ] || curl -L -O ftp://ftp.gnu.org/gnu/automake/automake-$AUTOMAKE_VERSION.tar.xz || exit 1
        $no_build && echo "Skipping installation" && return
        xzcat automake-$AUTOMAKE_VERSION.tar.xz | tar xf - || exit 1
        cd automake-$AUTOMAKE_VERSION
        ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch automake-$AUTOMAKE_VERSION-done
    fi
}

uninstall_automake() {
    if [ ! -z "$installed_automake_version" ] ; then
        #
        # libtool depends on this(?), so uninstall it.
        #
        uninstall_libtool "$@"

        echo "Uninstalling GNU automake:"
        cd automake-$installed_automake_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm automake-$installed_automake_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf automake-$installed_automake_version
            rm -rf automake-$installed_automake_version.tar.xz
        fi

        installed_automake_version=""
    fi
}

install_libtool() {
    if [ "$LIBTOOL_VERSION" -a ! -f libtool-$LIBTOOL_VERSION-done ] ; then
        echo "Downloading, building and installing GNU libtool..."
        [ -f libtool-$LIBTOOL_VERSION.tar.xz ] || curl -L -O ftp://ftp.gnu.org/gnu/libtool/libtool-$LIBTOOL_VERSION.tar.xz || exit 1
        $no_build && echo "Skipping installation" && return
        xzcat libtool-$LIBTOOL_VERSION.tar.xz | tar xf - || exit 1
        cd libtool-$LIBTOOL_VERSION
        ./configure --program-prefix=g || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
       touch libtool-$LIBTOOL_VERSION-done
    fi
}

uninstall_libtool() {
    if [ ! -z "$installed_libtool_version" ] ; then
        echo "Uninstalling GNU libtool:"
        cd libtool-$installed_libtool_version
        $DO_MV /usr/local/bin/glibtool /usr/local/bin/libtool
        $DO_MV /usr/local/bin/glibtoolize /usr/local/bin/libtoolize
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm libtool-$installed_libtool_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf libtool-$installed_libtool_version
            rm -rf libtool-$installed_libtool_version.tar.xz
        fi

        installed_libtool_version=""
    fi
}

install_ninja() {
    if [ "$NINJA_VERSION" -a ! -f ninja-$NINJA_VERSION-done ] ; then
        echo "Downloading and installing Ninja:"
        #
        # Download the zipball, unpack it, and move the binary to
        # /usr/local/bin.
        #
        [ -f ninja-mac-v$NINJA_VERSION.zip ] || curl -L -o ninja-mac-v$NINJA_VERSION.zip https://github.com/ninja-build/ninja/releases/download/v$NINJA_VERSION/ninja-mac.zip || exit 1
        $no_build && echo "Skipping installation" && return
        unzip ninja-mac-v$NINJA_VERSION.zip
        sudo mv ninja /usr/local/bin
        touch ninja-$NINJA_VERSION-done
    fi
}

uninstall_ninja() {
    if [ ! -z "$installed_ninja_version" ]; then
        echo "Uninstalling Ninja:"
        sudo rm /usr/local/bin/ninja
        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            rm -f ninja-mac-v$installed_ninja_version.zip
        fi

        installed_ninja_version=""
    fi
}

install_asciidoctor() {
    if [ ! -f asciidoctor-${ASCIIDOCTOR_VERSION}-done ]; then
        echo "Downloading and installing Asciidoctor:"
        sudo gem install -V asciidoctor --version "=${ASCIIDOCTOR_VERSION}"
        touch asciidoctor-${ASCIIDOCTOR_VERSION}-done
    fi
}

uninstall_asciidoctor() {
    if [ ! -z "$installed_asciidoctor_version" ]; then
        echo "Uninstalling Asciidoctor:"
        sudo gem uninstall -V asciidoctor --version "=${installed_asciidoctor_version}"
        rm asciidoctor-$installed_asciidoctor_version-done

        ##if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version,
            # whatever it might happen to be called.
            #
        ##    rm -f asciidoctor-$installed_asciidoctor_version
        ##fi
        installed_asciidoctor_version=""
    fi
}

install_asciidoctorpdf() {
    if [ ! -f asciidoctorpdf-${ASCIIDOCTORPDF_VERSION}-done ]; then
        ## XXX gem does not track dependencies that are installed for asciidoctor-pdf
        ## record them for uninstallation
        ## ttfunk, pdf-core, prawn, prawn-table, Ascii85, ruby-rc4, hashery, afm, pdf-reader, prawn-templates, public_suffix, addressable, css_parser, prawn-svg, prawn-icon, safe_yaml, thread_safe, polyglot, treetop, asciidoctor-pdf
        echo "Downloading and installing Asciidoctor-pdf:"
        sudo gem install -V asciidoctor-pdf --prerelease --version "=${ASCIIDOCTORPDF_VERSION}"
        touch asciidoctorpdf-${ASCIIDOCTORPDF_VERSION}-done
    fi
}

uninstall_asciidoctorpdf() {
    if [ ! -z "$installed_asciidoctorpdf_version" ]; then
        echo "Uninstalling Asciidoctor:"
        sudo gem uninstall -V asciidoctor-pdf --version "=${installed_asciidoctorpdf_version}"
        ## XXX uninstall dependencies
        rm asciidoctorpdf-$installed_asciidoctorpdf_version-done

        ##if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version,
            # whatever it might happen to be called.
            #
        ##    rm -f asciidoctorpdf-$installed_asciidoctorpdf_version
        ##fi
        installed_asciidoctorpdf_version=""
    fi
}

install_cmake() {
    if [ ! -f cmake-$CMAKE_VERSION-done ]; then
        echo "Downloading and installing CMake:"
        CMAKE_MAJOR_VERSION="`expr $CMAKE_VERSION : '\([0-9][0-9]*\).*'`"
        CMAKE_MINOR_VERSION="`expr $CMAKE_VERSION : '[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
        CMAKE_MAJOR_MINOR_VERSION=$CMAKE_MAJOR_VERSION.$CMAKE_MINOR_VERSION

        #
        # NOTE: the "64" in "Darwin64" doesn't mean "64-bit-only"; the
        # package in question supports both 32-bit and 64-bit x86.
        #
        case "$CMAKE_MAJOR_VERSION" in

        0|1)
            echo "CMake $CMAKE_VERSION" is too old 1>&2
            ;;

        2)
            #
            # Download the DMG, run the installer.
            #
            [ -f cmake-$CMAKE_VERSION-Darwin64-universal.dmg ] || curl -L -O https://cmake.org/files/v$CMAKE_MAJOR_MINOR_VERSION/cmake-$CMAKE_VERSION-Darwin64-universal.dmg || exit 1
            $no_build && echo "Skipping installation" && return
            sudo hdiutil attach cmake-$CMAKE_VERSION-Darwin64-universal.dmg || exit 1
            sudo installer -target / -pkg /Volumes/cmake-$CMAKE_VERSION-Darwin64-universal/cmake-$CMAKE_VERSION-Darwin64-universal.pkg || exit 1
            sudo hdiutil detach /Volumes/cmake-$CMAKE_VERSION-Darwin64-universal
            ;;

        3)
            #
            # Download the DMG and do a drag install, where "drag" means
            # "mv".
            #
            # 3.0.* and 3.1.0 have a Darwin64-universal DMG.
            # 3.1.1 and later have a Darwin-x86_64 DMG.
            # Probably not many people are still developing on 32-bit
            # Macs, so we don't worry about them.
            #
            if [ "$CMAKE_MINOR_VERSION" = 0 -o \
                 "$CMAKE_VERSION" = 3.1.0 ]; then
                type="Darwin64-universal"
            else
                type="Darwin-x86_64"
            fi
            [ -f cmake-$CMAKE_VERSION-$type.dmg ] || curl -L -O https://cmake.org/files/v$CMAKE_MAJOR_MINOR_VERSION/cmake-$CMAKE_VERSION-$type.dmg || exit 1
            $no_build && echo "Skipping installation" && return
            sudo hdiutil attach cmake-$CMAKE_VERSION-$type.dmg || exit 1
            sudo ditto /Volumes/cmake-$CMAKE_VERSION-$type/CMake.app /Applications/CMake.app || exit 1

            #
            # Plant the appropriate symbolic links in /usr/local/bin.
            # It's a drag-install, so there's no installer to make them,
            # and the CMake code to put them in place is lame, as
            #
            #    1) it defaults to /usr/bin, not /usr/local/bin;
            #    2) it doesn't request the necessary root privileges;
            #    3) it can't be run from the command line;
            #
            # so we do it ourselves.
            #
            for i in ccmake cmake cmake-gui cmakexbuild cpack ctest
            do
                sudo ln -s /Applications/CMake.app/Contents/bin/$i /usr/local/bin/$i
            done
            sudo hdiutil detach /Volumes/cmake-$CMAKE_VERSION-$type
            ;;

        *)
            ;;
        esac
        touch cmake-$CMAKE_VERSION-done
    fi
}

uninstall_cmake() {
    if [ ! -z "$installed_cmake_version" ]; then
        echo "Uninstalling CMake:"
        installed_cmake_major_version="`expr $installed_cmake_version : '\([0-9][0-9]*\).*'`"
        case "$installed_cmake_major_version" in

        0|1)
            echo "CMake $installed_cmake_version" is too old 1>&2
            ;;

        2)
            sudo rm -rf "/Applications/CMake "`echo "$installed_cmake_version" | sed 's/\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1.\2-\3/'`.app
            for i in ccmake cmake cmake-gui cmakexbuild cpack ctest
            do
                sudo rm -f /usr/bin/$i /usr/local/bin/$i
            done
            sudo pkgutil --forget com.Kitware.CMake
            rm cmake-$installed_cmake_version-done
            ;;

        3)
            sudo rm -rf /Applications/CMake.app
            for i in ccmake cmake cmake-gui cmakexbuild cpack ctest
            do
                sudo rm -f /usr/local/bin/$i
            done
            rm cmake-$installed_cmake_version-done
            ;;
        esac

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version,
            # whatever it might happen to be called.
            #
            rm -f cmake-$installed_cmake_version-Darwin64-universal.dmg
            rm -f cmake-$installed_cmake_version-Darwin-x86_64.dmg
        fi

        installed_cmake_version=""
    fi
}

install_gettext() {
    if [ ! -f gettext-$GETTEXT_VERSION-done ] ; then
        echo "Downloading, building, and installing GNU gettext:"
        [ -f gettext-$GETTEXT_VERSION.tar.gz ] || curl -L -O http://ftp.gnu.org/pub/gnu/gettext/gettext-$GETTEXT_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat gettext-$GETTEXT_VERSION.tar.gz | tar xf - || exit 1
        cd gettext-$GETTEXT_VERSION
        CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=0 $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch gettext-$GETTEXT_VERSION-done
    fi
}

uninstall_gettext() {
    if [ ! -z "$installed_gettext_version" ] ; then
        #
        # GLib depends on this, so uninstall it.
        #
        uninstall_glib "$@"

        echo "Uninstalling GNU gettext:"
        cd gettext-$installed_gettext_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm gettext-$installed_gettext_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf gettext-$installed_gettext_version
            rm -rf gettext-$installed_gettext_version.tar.gz
        fi

        installed_gettext_version=""
    fi
}

install_pkg_config() {
    if [ ! -f pkg-config-$PKG_CONFIG_VERSION-done ] ; then
        echo "Downloading, building, and installing pkg-config:"
        [ -f pkg-config-$PKG_CONFIG_VERSION.tar.gz ] || curl -L -O https://pkgconfig.freedesktop.org/releases/pkg-config-$PKG_CONFIG_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat pkg-config-$PKG_CONFIG_VERSION.tar.gz | tar xf - || exit 1
        cd pkg-config-$PKG_CONFIG_VERSION
        ./configure --with-internal-glib || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch pkg-config-$PKG_CONFIG_VERSION-done
    fi
}

uninstall_pkg_config() {
    if [ ! -z "$installed_pkg_config_version" ] ; then
        echo "Uninstalling pkg-config:"
        cd pkg-config-$installed_pkg_config_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm pkg-config-$installed_pkg_config_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf pkg-config-$installed_pkg_config_version
            rm -rf pkg-config-$installed_pkg_config_version.tar.gz
        fi

        installed_pkg_config_version=""
    fi
}

install_glib() {
    if [ ! -f glib-$GLIB_VERSION-done ] ; then
        echo "Downloading, building, and installing GLib:"
        glib_dir=`expr $GLIB_VERSION : '\([0-9][0-9]*\.[0-9][0-9]*\).*'`
        #
        # Starting with GLib 2.28.8, xz-compressed tarballs are available.
        #
        [ -f glib-$GLIB_VERSION.tar.xz ] || curl -L -O http://ftp.gnome.org/pub/gnome/sources/glib/$glib_dir/glib-$GLIB_VERSION.tar.xz || exit 1
        $no_build && echo "Skipping installation" && return
        xzcat glib-$GLIB_VERSION.tar.xz | tar xf - || exit 1
        cd glib-$GLIB_VERSION
        #
        # macOS ships with libffi, but doesn't provide its pkg-config file;
        # explicitly specify LIBFFI_CFLAGS and LIBFFI_LIBS, so the configure
        # script doesn't try to use pkg-config to get the appropriate
        # C flags and loader flags.
        #
        # And, what's worse, at least with the version of Xcode that comes
        # with Leopard, /usr/include/ffi/fficonfig.h doesn't define MACOSX,
        # which causes the build of GLib to fail.  If we don't find
        # "#define.*MACOSX" in /usr/include/ffi/fficonfig.h, explicitly
        # define it.
        #
        # While we're at it, suppress -Wformat-nonliteral to avoid a case
        # where clang's stricter rules on when not to complain about
        # non-literal format arguments cause it to complain about code
        # that's safe but it wasn't told that.  See my comment #25 in
        # GNOME bug 691608:
        #
        #    https://bugzilla.gnome.org/show_bug.cgi?id=691608#c25
        #
        # First, determine where the system include files are.  (It's not
        # necessarily /usr/include.)  There's a bit of a greasy hack here;
        # pre-5.x versions of the developer tools don't support the
        # --show-sdk-path option, and will produce no output, so includedir
        # will be set to /usr/include (in those older versions of the
        # developer tools, there is a /usr/include directory).
        #
        includedir=`xcrun --show-sdk-path 2>/dev/null`/usr/include
        if grep -qs '#define.*MACOSX' $includedir/ffi/fficonfig.h
        then
            # It's defined, nothing to do
            LIBFFI_CFLAGS="-I $includedir/ffi" LIBFFI_LIBS="-lffi" CFLAGS="$CFLAGS -Wno-format-nonliteral $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS -Wno-format-nonliteral $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        else
            LIBFFI_CFLAGS="-I $includedir/ffi" LIBFFI_LIBS="-lffi" CFLAGS="$CFLAGS -DMACOSX -Wno-format-nonliteral $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS -DMACOSX -Wno-format-nonliteral $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        fi

        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch glib-$GLIB_VERSION-done
    fi
}

uninstall_glib() {
    if [ ! -z "$installed_glib_version" ] ; then
        echo "Uninstalling GLib:"
        cd glib-$installed_glib_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm glib-$installed_glib_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf glib-$installed_glib_version
            rm -rf glib-$installed_glib_version.tar.xz
        fi

        installed_glib_version=""
    fi
}

install_qt() {
    if [ "$QT_VERSION" -a ! -f qt-$QT_VERSION-done ]; then
        echo "Downloading and installing Qt:"
        #
        # What you get for this URL might just be a 302 Found reply, so use
        # -L so we get redirected.
        #
        # 5.0 - 5.1:  qt-mac-opensource-{version}-clang-offline.dmg
        # 5.2.0:      qt-mac-opensource-{version}.dmg
        # 5.2.1:      qt-opensource-mac-x64-clang-{version}.dmg
        # 5.3 - 5.8:  qt-opensource-mac-x64-clang-{version}.dmg
        # 5.9 - 5.13: qt-opensource-mac-x64-{version}.dmg
        #
        case $QT_MAJOR_VERSION in

        1|2|3|4)
            echo "Qt $QT_VERSION" is too old 1>&2
            ;;

        5*)
            case $QT_MINOR_VERSION in

            0|1)
                echo "Qt $QT_VERSION" is too old 1>&2
                ;;

            2)
                case $QT_DOTDOT_VERSION in

                0)
                    QT_VOLUME=qt-mac-opensource-$QT_VERSION
                    ;;

                1)
                    QT_VOLUME=qt-opensource-mac-x64-clang-$QT_VERSION
                    ;;
                esac
                ;;

            3|4|5|6|7|8)
                QT_VOLUME=qt-opensource-mac-x64-clang-$QT_VERSION
                ;;

            9|10|11|12|13)
                QT_VOLUME=qt-opensource-mac-x64-$QT_VERSION
                ;;
            esac
            [ -f $QT_VOLUME.dmg ] || curl -L -O http://download.qt.io/archive/qt/$QT_MAJOR_MINOR_VERSION/$QT_MAJOR_MINOR_DOTDOT_VERSION/$QT_VOLUME.dmg || exit 1
            $no_build && echo "Skipping installation" && return
            sudo hdiutil attach $QT_VOLUME.dmg || exit 1

            #
            # Run the installer executable directly, so that we wait for
            # it to finish.  Then unmount the volume.
            #
            /Volumes/$QT_VOLUME/$QT_VOLUME.app/Contents/MacOS/$QT_VOLUME
            sudo hdiutil detach /Volumes/$QT_VOLUME
            touch qt-$QT_VERSION-done
        esac
    fi
}

uninstall_qt() {
    if [ ! -z "$installed_qt_version" ] ; then
        echo "Uninstalling Qt:"
        rm -rf $HOME/Qt$installed_qt_version
        rm qt-$installed_qt_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded version.
            #
            # 5.0 - 5.1:  qt-mac-opensource-{version}-clang-offline.dmg
            # 5.2.0:      qt-mac-opensource-{version}.dmg
            # 5.2.1:      qt-opensource-mac-x64-clang-{version}.dmg
            # 5.3 - 5.8:  qt-opensource-mac-x64-clang-{version}.dmg
            # 5.9 - 5.13: qt-opensource-mac-x64-{version}.dmg
            #
            installed_qt_major_version="`expr $installed_qt_version : '\([0-9][0-9]*\).*'`"
            installed_qt_minor_version="`expr $installed_qt_version : '[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
            installed_qt_dotdot_version="`expr $installed_qt_version : '[0-9][0-9]*\.[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
            case $installed_qt_major_version in

            1|2|3|4)
                echo "Qt $installed_qt_version" is too old 1>&2
                ;;

            5*)
                case $installed_qt_minor_version in

                0|1)
                    installed_qt_volume=qt-mac-opensource-$installed_qt_version-clang-offline.dmg
                    ;;

                2)
                    case $installed_qt_dotdot_version in

                    0)
                        installed_qt_volume=qt-mac-opensource-$installed_qt_version.dmg
                        ;;

                    1)
                        installed_qt_volume=qt-opensource-mac-x64-clang-$installed_qt_version.dmg
                        ;;
                    esac
                    ;;

                3|4|5|6|7|8)
                    installed_qt_volume=qt-opensource-mac-x64-clang-$installed_qt_version.dmg
                    ;;

                9|10)
                    installed_qt_volume=qt-opensource-mac-x64-$installed_qt_version.dmg
                    ;;
                esac
            esac
            rm -f $installed_qt_volume
        fi

        installed_qt_version=""
    fi
}

install_libsmi() {
    if [ "$LIBSMI_VERSION" -a ! -f libsmi-$LIBSMI_VERSION-done ] ; then
        echo "Downloading, building, and installing libsmi:"
        [ -f libsmi-$LIBSMI_VERSION.tar.gz ] || curl -L -O https://www.ibr.cs.tu-bs.de/projects/libsmi/download/libsmi-$LIBSMI_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat libsmi-$LIBSMI_VERSION.tar.gz | tar xf - || exit 1
        cd libsmi-$LIBSMI_VERSION
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch libsmi-$LIBSMI_VERSION-done
    fi
}

uninstall_libsmi() {
    if [ ! -z "$installed_libsmi_version" ] ; then
        echo "Uninstalling libsmi:"
        cd libsmi-$installed_libsmi_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm libsmi-$installed_libsmi_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf libsmi-$installed_libsmi_version
            rm -rf libsmi-$installed_libsmi_version.tar.gz
        fi

        installed_libsmi_version=""
    fi
}

install_libgpg_error() {
    if [ "$LIBGPG_ERROR_VERSION" -a ! -f libgpg-error-$LIBGPG_ERROR_VERSION-done ] ; then
        echo "Downloading, building, and installing libgpg-error:"
        [ -f libgpg-error-$LIBGPG_ERROR_VERSION.tar.bz2 ] || curl -L -O https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-$LIBGPG_ERROR_VERSION.tar.bz2 || exit 1
        $no_build && echo "Skipping installation" && return
        bzcat libgpg-error-$LIBGPG_ERROR_VERSION.tar.bz2 | tar xf - || exit 1
        cd libgpg-error-$LIBGPG_ERROR_VERSION
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch libgpg-error-$LIBGPG_ERROR_VERSION-done
    fi
}

uninstall_libgpg_error() {
    if [ ! -z "$installed_libgpg_error_version" ] ; then
        #
        # libgcrypt depends on this, so uninstall it.
        #
        uninstall_libgcrypt "$@"

        echo "Uninstalling libgpg-error:"
        cd libgpg-error-$installed_libgpg_error_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm libgpg-error-$installed_libgpg_error_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf libgpg-error-$installed_libgpg_error_version
            rm -rf libgpg-error-$installed_libgpg_error_version.tar.bz2
        fi

        installed_libgpg_error_version=""
    fi
}

install_libgcrypt() {
    if [ "$LIBGCRYPT_VERSION" -a ! -f libgcrypt-$LIBGCRYPT_VERSION-done ] ; then
        #
        # libgpg-error is required for libgcrypt.
        #
        if [ -z $LIBGPG_ERROR_VERSION ]
        then
            echo "libgcrypt requires libgpg-error, but you didn't install libgpg-error." 1>&2
            exit 1
        fi

        echo "Downloading, building, and installing libgcrypt:"
        [ -f libgcrypt-$LIBGCRYPT_VERSION.tar.gz ] || curl -L -O https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-$LIBGCRYPT_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat libgcrypt-$LIBGCRYPT_VERSION.tar.gz | tar xf - || exit 1
        cd libgcrypt-$LIBGCRYPT_VERSION
        #
        # The assembler language code is not compatible with the macOS
        # x86 assembler (or is it an x86-64 vs. x86-32 issue?).
        #
        # libgcrypt expects gnu89, not c99/gnu99, semantics for
        # "inline".  See, for example:
        #
        #    http://lists.freebsd.org/pipermail/freebsd-ports-bugs/2010-October/198809.html
        #
        CFLAGS="$CFLAGS -std=gnu89 $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --disable-asm || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch libgcrypt-$LIBGCRYPT_VERSION-done
    fi
}

uninstall_libgcrypt() {
    if [ ! -z "$installed_libgcrypt_version" ] ; then
        echo "Uninstalling libgcrypt:"
        cd libgcrypt-$installed_libgcrypt_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm libgcrypt-$installed_libgcrypt_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf libgcrypt-$installed_libgcrypt_version
            rm -rf libgcrypt-$installed_libgcrypt_version.tar.gz
        fi

        installed_libgcrypt_version=""
    fi
}

install_gmp() {
    if [ "$GMP_VERSION" -a ! -f gmp-$GMP_VERSION-done ] ; then
        echo "Downloading, building, and installing GMP:"
        [ -f gmp-$GMP_VERSION.tar.lz ] || curl -L -O https://gmplib.org/download/gmp/gmp-$GMP_VERSION.tar.lz || exit 1
        $no_build && echo "Skipping installation" && return
        lzip -c -d gmp-$GMP_VERSION.tar.lz | tar xf - || exit 1
        cd gmp-$GMP_VERSION
        # Create a fat binary: https://gmplib.org/manual/Notes-for-Package-Builds.html
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --enable-fat || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch gmp-$GMP_VERSION-done
    fi
}

uninstall_gmp() {
    if [ ! -z "$installed_gmp_version" ] ; then
        #
        # Nettle depends on this, so uninstall it.
        #
        uninstall_nettle "$@"

        echo "Uninstalling GMP:"
        cd gmp-$installed_gmp_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm gmp-$installed_gmp_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf gmp-$installed_gmp_version
            rm -rf gmp-$installed_gmp_version.tar.lz
        fi

        installed_gmp_version=""
    fi
}

install_nettle() {
    if [ "$NETTLE_VERSION" -a ! -f nettle-$NETTLE_VERSION-done ] ; then
        echo "Downloading, building, and installing Nettle:"
        [ -f nettle-$NETTLE_VERSION.tar.gz ] || curl -L -O https://ftp.gnu.org/gnu/nettle/nettle-$NETTLE_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat nettle-$NETTLE_VERSION.tar.gz | tar xf - || exit 1
        cd nettle-$NETTLE_VERSION
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --with-libgcrypt --without-p11-kit || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch nettle-$NETTLE_VERSION-done
    fi
}

uninstall_nettle() {
    if [ ! -z "$installed_nettle_version" ] ; then
        #
        # GnuTLS depends on this, so uninstall it.
        #
        uninstall_gnutls "$@"

        echo "Uninstalling Nettle:"
        cd nettle-$installed_nettle_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm nettle-$installed_nettle_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf nettle-$installed_nettle_version
            rm -rf nettle-$installed_nettle_version.tar.gz
        fi

        installed_nettle_version=""
    fi
}

install_gnutls() {
    if [ "$GNUTLS_VERSION" -a ! -f gnutls-$GNUTLS_VERSION-done ] ; then
        #
        # GnuTLS requires Nettle.
        #
        if [ -z $NETTLE_VERSION ]
        then
            echo "GnuTLS requires Nettle, but you didn't install Nettle" 1>&2
            exit 1
        fi

        echo "Downloading, building, and installing GnuTLS:"
        if [[ $GNUTLS_MAJOR_VERSION -ge 3 ]]
        then
            #
            # Starting with GnuTLS 3.x, the tarballs are compressed with
            # xz rather than bzip2.
            #
            [ -f gnutls-$GNUTLS_VERSION.tar.xz ] || curl -L -O https://www.gnupg.org/ftp/gcrypt/gnutls/v$GNUTLS_MAJOR_VERSION.$GNUTLS_MINOR_VERSION/gnutls-$GNUTLS_VERSION.tar.xz || exit 1
            $no_build && echo "Skipping installation" && return
            xzcat gnutls-$GNUTLS_VERSION.tar.xz | tar xf - || exit 1
        else
            [ -f gnutls-$GNUTLS_VERSION.tar.bz2 ] || curl -L -O https://www.gnupg.org/ftp/gcrypt/gnutls/v$GNUTLS_MAJOR_VERSION.$GNUTLS_MINOR_VERSION/gnutls-$GNUTLS_VERSION.tar.bz2 || exit 1
            $no_build && echo "Skipping installation" && return
            bzcat gnutls-$GNUTLS_VERSION.tar.bz2 | tar xf - || exit 1
        fi
        cd gnutls-$GNUTLS_VERSION
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --with-included-libtasn1 --with-included-unistring --without-p11-kit --disable-guile || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch gnutls-$GNUTLS_VERSION-done
    fi
}

uninstall_gnutls() {
    if [ ! -z "$installed_gnutls_version" ] ; then
        echo "Uninstalling GnuTLS:"
        cd gnutls-$installed_gnutls_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm gnutls-$installed_gnutls_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf gnutls-$installed_gnutls_version
            rm -rf gnutls-$installed_gnutls_version.tar.bz2
        fi

        installed_gnutls_version=""
    fi
}

install_lua() {
    if [ "$LUA_VERSION" -a ! -f lua-$LUA_VERSION-done ] ; then
        echo "Downloading, building, and installing Lua:"
        [ -f lua-$LUA_VERSION.tar.gz ] || curl -L -O http://www.lua.org/ftp/lua-$LUA_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat lua-$LUA_VERSION.tar.gz | tar xf - || exit 1
        cd lua-$LUA_VERSION
        make MYCFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" MYLDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" $MAKE_BUILD_OPTS macosx || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch lua-$LUA_VERSION-done
    fi
}

uninstall_lua() {
    if [ ! -z "$installed_lua_version" ] ; then
        echo "Uninstalling Lua:"
        #
        # Lua has no "make uninstall", so just remove stuff manually.
        # There's no configure script, so there's no need for
        # "make distclean", either; just do "make clean".
        #
        (cd /usr/local/bin; $DO_RM -f lua luac)
        (cd /usr/local/include; $DO_RM -f lua.h luaconf.h lualib.h lauxlib.h lua.hpp)
        (cd /usr/local/lib; $DO_RM -f liblua.a)
        (cd /usr/local/man/man1; $DO_RM -f lua.1 luac.1)
        cd lua-$installed_lua_version
        make clean || exit 1
        cd ..
        rm lua-$installed_lua_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf lua-$installed_lua_version
            rm -rf lua-$installed_lua_version.tar.gz
        fi

        installed_lua_version=""
    fi
}

install_snappy() {
    if [ "$SNAPPY_VERSION" -a ! -f snappy-$SNAPPY_VERSION-done ] ; then
        echo "Downloading, building, and installing snappy:"
        [ -f snappy-$SNAPPY_VERSION.tar.gz ] || curl -L -O https://github.com/google/snappy/releases/download/$SNAPPY_VERSION/snappy-$SNAPPY_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat snappy-$SNAPPY_VERSION.tar.gz | tar xf - || exit 1
        cd snappy-$SNAPPY_VERSION
        CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=0 $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS -D_FORTIFY_SOURCE=0 $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch snappy-$SNAPPY_VERSION-done
    fi
}

uninstall_snappy() {
    if [ ! -z "$installed_snappy_version" ] ; then
        echo "Uninstalling snappy:"
        cd snappy-$installed_snappy_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm snappy-$installed_snappy_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf snappy-$installed_snappy_version
            rm -rf snappy-$installed_snappy_version.tar.gz
        fi

        installed_snappy_version=""
    fi
}

install_zstd() {
    if [ "$ZSTD_VERSION" -a ! -f zstd-$ZSTD_VERSION-done ] ; then
        echo "Downloading, building, and installing zstd:"
        [ -f zstd-$ZSTD_VERSION.tar.gz ] || curl -L -O https://github.com/facebook/zstd/releases/download/v$ZSTD_VERSION/zstd-$ZSTD_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat zstd-$ZSTD_VERSION.tar.gz | tar xf - || exit 1
        cd zstd-$ZSTD_VERSION
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch zstd-$ZSTD_VERSION-done
    fi
}

uninstall_zstd() {
    if [ ! -z "$installed_zstd_version" ] ; then
        echo "Uninstalling zstd:"
        cd zstd-$installed_zstd_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm zstd-$installed_zstd_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf zstd-$installed_zstd_version
            rm -rf zstd-$installed_zstd_version.tar.gz
        fi

        installed_zstd_version=""
    fi
}

install_libxml2() {
    if [ "$LIBXML2_VERSION" -a ! -f libxml2-$LIBXML2_VERSION-done ] ; then
        echo "Downloading, building, and installing libxml2:"
        [ -f libxml2-$LIBXML2_VERSION.tar.gz ] || curl -L -O ftp://xmlsoft.org/libxml2/libxml2-$LIBXML2_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat libxml2-$LIBXML2_VERSION.tar.gz | tar xf - || exit 1
        cd libxml2-$LIBXML2_VERSION
        CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=0 $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS -D_FORTIFY_SOURCE=0 $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch libxml2-$LIBXML2_VERSION-done
    fi
}

uninstall_libxml2() {
    if [ ! -z "$installed_libxml2_version" ] ; then
        echo "Uninstalling libxml2:"
        cd libxml2-$installed_libxml2_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm libxml2-$installed_libxml2_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf libxml2-$installed_libxml2_version
            rm -rf libxml2-$installed_libxml2_version.tar.gz
        fi

        installed_libxml2_version=""
    fi
}

install_lz4() {
    if [ "$LZ4_VERSION" -a ! -f lz4-$LZ4_VERSION-done ] ; then
        echo "Downloading, building, and installing lz4:"
        #
        # lz4 switched from sequentially numbered releases, named rN,
        # to vX.Y.Z-numbered releases.
        #
        # The old sequentially-numbered releases were in tarballs
        # at https://github.com/lz4/lz4/archive/rN.tar.gz, which
        # extract into an lz4-rN directory.
        #
        # THe new vX.Y.Z-numbered releases are in tarballs at
        # https://github.com/lz4/lz4/archive/vX.Y.Z.tar.gz, which
        # extract into an lz4-X.Y.Z directory - no, not lz4-vX.Y.Z,
        # just lz4-X.Y.Z.
        #
        # We expect LZ4_VERSION to be set to rN for the sequentially-
        # numbered releases and X.Y.Z - not vX.Y.Z - for the vX.Y.Z-
        # numbered releases.  We also tell Curl to download the tarball
        # with a name that corresponds to the name of the target
        # directory, so that it begins with "lz4-" and ends with either
        # "rN" or "X.Y.Z", to match what almost all of the other
        # support libraries do.
        #
        if [[ "$LZ4_VERSION" == r* ]]
        then
            [ -f lz4-$LZ4_VERSION.tar.gz ] || curl -L -o lz4-$LZ4_VERSION.tar.gz https://github.com/lz4/lz4/archive/$LZ4_VERSION.tar.gz  || exit 1
        else
            [ -f lz4-$LZ4_VERSION.tar.gz ] || curl -L -o lz4-$LZ4_VERSION.tar.gz https://github.com/lz4/lz4/archive/v$LZ4_VERSION.tar.gz  || exit 1
        fi
        $no_build && echo "Skipping installation" && return
        gzcat lz4-$LZ4_VERSION.tar.gz | tar xf - || exit 1
        cd lz4-$LZ4_VERSION
        #
        # No configure script here, but it appears that if MOREFLAGS is
        # set, that's added to CFLAGS, and those are combined with LDFLAGS
        # and CXXFLAGS into FLAGS, which is used when building source
        # files and libraries.
        #
        MOREFLAGS="-D_FORTIFY_SOURCE=0 $VERSION_MIN_FLAGS $SDKFLAGS" make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch lz4-$LZ4_VERSION-done
    fi
}

uninstall_lz4() {
    if [ ! -z "$installed_lz4_version" ] ; then
        echo "Uninstalling lz4:"
        cd lz4-$installed_lz4_version
        $DO_MAKE_UNINSTALL || exit 1
        #
        # lz4 uses cmake and doesn't support "make distclean"
        #
        # make distclean || exit 1
        cd ..
        rm lz4-$installed_lz4_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            # "make install" apparently causes some stuff to be
            # modified in the build tree, so, as it's done as
            # root, that leaves stuff owned by root in the build
            # tree.  Therefore, we have to remove the build tree
            # as root.
            #
            sudo rm -rf lz4-$installed_lz4_version
            rm -rf lz4-$installed_lz4_version.tar.gz
        fi

        installed_lz4_version=""
    fi
}

install_sbc() {
    if [ "$SBC_VERSION" -a ! -f sbc-$SBC_VERSION-done ] ; then
        echo "Downloading, building, and installing sbc:"
        [ -f sbc-$SBC_VERSION.tar.gz ] || curl -L -O https://www.kernel.org/pub/linux/bluetooth/sbc-$SBC_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat sbc-$SBC_VERSION.tar.gz | tar xf - || exit 1
        cd sbc-$SBC_VERSION
        CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=0 $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS -D_FORTIFY_SOURCE=0 $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --disable-tools --disable-tester --disable-shared || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch sbc-$SBC_VERSION-done
    fi
}

uninstall_sbc() {
    if [ ! -z "$installed_sbc_version" ] ; then
        echo "Uninstalling sbc:"
        cd sbc-$installed_sbc_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm sbc-$installed_sbc_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf sbc-$installed_sbc_version
            rm -rf sbc-$installed_sbc_version.tar.gz
        fi

        installed_sbc_version=""
    fi
}

install_maxminddb() {
    if [ "$MAXMINDDB_VERSION" -a ! -f maxminddb-$MAXMINDDB_VERSION-done ] ; then
        echo "Downloading, building, and installing MaxMindDB API:"
        [ -f libmaxminddb-$MAXMINDDB_VERSION.tar.gz ] || curl -L -O https://github.com/maxmind/libmaxminddb/releases/download/$MAXMINDDB_VERSION/libmaxminddb-$MAXMINDDB_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat libmaxminddb-$MAXMINDDB_VERSION.tar.gz | tar xf - || exit 1
        cd libmaxminddb-$MAXMINDDB_VERSION
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch maxminddb-$MAXMINDDB_VERSION-done
    fi
}

uninstall_maxminddb() {
    if [ ! -z "$installed_maxminddb_version" ] ; then
        echo "Uninstalling MaxMindDB API:"
        cd libmaxminddb-$installed_maxminddb_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm maxminddb-$installed_maxminddb_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf libmaxminddb-$installed_maxminddb_version
            rm -rf libmaxminddb-$installed_maxminddb_version.tar.gz
        fi

        installed_maxminddb_version=""
    fi
}

install_c_ares() {
    if [ "$CARES_VERSION" -a ! -f c-ares-$CARES_VERSION-done ] ; then
        echo "Downloading, building, and installing C-Ares API:"
        [ -f c-ares-$CARES_VERSION.tar.gz ] || curl -L -O https://c-ares.haxx.se/download/c-ares-$CARES_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat c-ares-$CARES_VERSION.tar.gz | tar xf - || exit 1
        cd c-ares-$CARES_VERSION
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch c-ares-$CARES_VERSION-done
    fi
}

uninstall_c_ares() {
    if [ ! -z "$installed_cares_version" ] ; then
        echo "Uninstalling C-Ares API:"
        cd c-ares-$installed_cares_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm c-ares-$installed_cares_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf c-ares-$installed_cares_version
            rm -rf c-ares-$installed_cares_version.tar.gz
        fi

        installed_cares_version=""
    fi
}

install_libssh() {
    if [ "$LIBSSH_VERSION" -a ! -f libssh-$LIBSSH_VERSION-done ] ; then
        echo "Downloading, building, and installing libssh:"
        LIBSSH_MAJOR_VERSION="`expr $LIBSSH_VERSION : '\([0-9][0-9]*\).*'`"
        LIBSSH_MINOR_VERSION="`expr $LIBSSH_VERSION : '[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
        LIBSSH_MAJOR_MINOR_VERSION=$LIBSSH_MAJOR_VERSION.$LIBSSH_MINOR_VERSION
        [ -f libssh-$LIBSSH_VERSION.tar.xz ] || curl -L -O https://www.libssh.org/files/$LIBSSH_MAJOR_MINOR_VERSION/libssh-$LIBSSH_VERSION.tar.xz
        $no_build && echo "Skipping installation" && return
        xzcat libssh-$LIBSSH_VERSION.tar.xz | tar xf - || exit 1
        cd libssh-$LIBSSH_VERSION
        mkdir build
        cd build
        MACOSX_DEPLOYMENT_TARGET=$min_osx_target SDKROOT="$SDKPATH" cmake -DWITH_GCRYPT=1 ../ || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ../..
        touch libssh-$LIBSSH_VERSION-done
    fi
}

uninstall_libssh() {
    if [ ! -z "$installed_libssh_version" ] ; then
        echo "Uninstalling libssh:"
        cd libssh-$installed_libssh_version
        #
        # libssh uses cmake and doesn't support "make uninstall"
        #
        # $DO_MAKE_UNINSTALL || exit 1
        sudo rm -rf /usr/local/lib/libssh*
        sudo rm -rf /usr/local/include/libssh
        sudo rm -rf /usr/local/lib/pkgconfig/libssh*
        sudo rm -rf /usr/local/lib/cmake/libssh
        #
        # libssh uses cmake and doesn't support "make distclean"
        #
        # make distclean || exit 1
        cd ..
        rm libssh-$installed_libssh_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf libssh-$installed_libssh_version
            rm -rf libssh-$installed_libssh_version.tar.gz
        fi

        installed_libssh_version=""
    fi
}

install_nghttp2() {
    if [ "$NGHTTP2_VERSION" -a ! -f nghttp2-$NGHTTP2_VERSION-done ] ; then
        echo "Downloading, building, and installing nghttp2:"
        [ -f nghttp2-$NGHTTP2_VERSION.tar.xz ] || curl -L -O https://github.com/nghttp2/nghttp2/releases/download/v$NGHTTP2_VERSION/nghttp2-$NGHTTP2_VERSION.tar.xz || exit 1
        $no_build && echo "Skipping installation" && return
        xzcat nghttp2-$NGHTTP2_VERSION.tar.xz | tar xf - || exit 1
        cd nghttp2-$NGHTTP2_VERSION
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch nghttp2-$NGHTTP2_VERSION-done
    fi
}

uninstall_nghttp2() {
    if [ ! -z "$installed_nghttp2_version" ] ; then
        echo "Uninstalling nghttp2:"
        cd nghttp2-$installed_nghttp2_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm nghttp2-$installed_nghttp2_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf nghttp2-$installed_nghttp2_version
            rm -rf nghttp2-$installed_nghttp2_version.tar.xz
        fi

        installed_nghttp2_version=""
    fi
}

install_libtiff() {
    if [ "$LIBTIFF_VERSION" -a ! -f tiff-$LIBTIFF_VERSION-done ] ; then
        echo "Downloading, building, and installing libtiff:"
        [ -f libtiff-$LIBTIFF_VERSION.tar.gz ] || curl -L -O http://dl.maptools.org/dl/libtiff/tiff-$LIBTIFF_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat tiff-$LIBTIFF_VERSION.tar.gz | tar xf - || exit 1
        cd tiff-$LIBTIFF_VERSION
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch tiff-$LIBTIFF_VERSION-done
    fi
}

uninstall_libtiff() {
    if [ ! -z "$installed_libtiff_version" ] ; then
        echo "Uninstalling libtiff:"
        cd tiff-$installed_libtiff_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm tiff-$installed_libtiff_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf tiff-$installed_libtiff_version
            rm -rf tiff-$installed_libtiff_version.tar.gz
        fi

        installed_libtiff_version=""
    fi
}

install_spandsp() {
    if [ "$SPANDSP_VERSION" -a ! -f spandsp-$SPANDSP_VERSION-done ] ; then
        echo "Downloading, building, and installing SpanDSP:"
        [ -f spandsp-$SPANDSP_VERSION.tar.gz ] || curl -L -O https://www.soft-switch.org/downloads/spandsp/spandsp-$SPANDSP_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat spandsp-$SPANDSP_VERSION.tar.gz | tar xf - || exit 1
        cd spandsp-$SPANDSP_VERSION
        #
        # Don't use -Wunused-but-set-variable, as it's not supported
        # by all the gcc versions in the versions of Xcode that we
        # support.
        #
        patch -p0 <${topdir}/macosx-support-lib-patches/spandsp-configure-patch || exit 1
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch spandsp-$SPANDSP_VERSION-done
    fi
}

uninstall_spandsp() {
    if [ ! -z "$installed_spandsp_version" ] ; then
        echo "Uninstalling SpanDSP:"
        cd spandsp-$installed_spandsp_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm spandsp-$installed_spandsp_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf spandsp-$installed_spandsp_version
            rm -rf spandsp-$installed_spandsp_version.tar.gz
        fi

        installed_spandsp_version=""
    fi
}

install_speexdsp() {
    if [ "$SPEEXDSP_VERSION" -a ! -f speexdsp-$SPEEXDSP_VERSION-done ] ; then
        echo "Downloading, building, and installing SpeexDSP:"
        [ -f speexdsp-$SPEEXDSP_VERSION.tar.gz ] || curl -L -O http://downloads.us.xiph.org/releases/speex/speexdsp-$SPEEXDSP_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat speexdsp-$SPEEXDSP_VERSION.tar.gz | tar xf - || exit 1
        cd speexdsp-$SPEEXDSP_VERSION
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch speexdsp-$SPEEXDSP_VERSION-done
    fi
}

uninstall_speexdsp() {
    if [ ! -z "$installed_speexdsp_version" ] ; then
        echo "Uninstalling SpeexDSP:"
        cd speexdsp-$installed_speexdsp_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm speexdsp-$installed_speexdsp_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf speexdsp-$installed_speexdsp_version
            rm -rf speexdsp-$installed_speexdsp_version.tar.gz
        fi

        installed_speexdsp_version=""
    fi
}

install_bcg729() {
    if [ "$BCG729_VERSION" -a ! -f bcg729-$BCG729_VERSION-done ] ; then
        echo "Downloading, building, and installing bcg729:"
        [ -f bcg729-$BCG729_VERSION.tar.gz ] || curl -L -O http://download-mirror.savannah.gnu.org/releases/linphone/plugins/sources/bcg729-$BCG729_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat bcg729-$BCG729_VERSION.tar.gz | tar xf - || exit 1
        cd bcg729-$BCG729_VERSION
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch bcg729-$BCG729_VERSION-done
    fi
}

uninstall_bcg729() {
    if [ ! -z "$installed_bcg729_version" ] ; then
        echo "Uninstalling bcg729:"
        cd bcg729-$installed_bcg729_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm bcg729-$installed_bcg729_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf bcg729-$installed_bcg729_version
            rm -rf bcg729-$installed_bcg729_version.tar.gz
        fi

        installed_bcg729_version=""
    fi
}

install_ilbc() {
    if [ -n "$ILBC_VERSION" ] && [ ! -f ilbc-$ILBC_VERSION-done ] ; then
        echo "Downloading, building, and installing iLBC:"
        [ -f libilbc-$ILBC_VERSION.tar.bz ] || curl --location --remote-name https://github.com/TimothyGu/libilbc/releases/download/v$ILBC_VERSION/libilbc-$ILBC_VERSION.tar.bz2 || exit 1
        $no_build && echo "Skipping installation" && return
        bzcat libilbc-$ILBC_VERSION.tar.bz2 | tar xf - || exit 1
        cd libilbc-$ILBC_VERSION || exit 1
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch ilbc-$ILBC_VERSION-done
    fi
}

uninstall_ilbc() {
    if [ -n "$installed_ilbc_version" ] ; then
        echo "Uninstalling iLBC:"
        cd "libilbc-$installed_ilbc_version" || exit 1
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm "ilbc-$installed_ilbc_version-done"

        if [ "$#" -eq 1 ] && [ "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf "libilbc-$installed_ilbc_version"
            rm -rf "libilbc-$installed_ilbc_version.tar.bz2"
        fi

        installed_ilbc_version=""
    fi
}

install_python3() {
    local macver=10.9
    if [[ $DARWIN_MAJOR_VERSION -lt 13 ]]; then
        # The 64-bit installer requires 10.9 (Mavericks), use the 64-bit/32-bit
        # variant for 10.6 (Snow Leopard) and newer.
        macver=10.6
    fi
    if [ "$PYTHON3_VERSION" -a ! -f python3-$PYTHON3_VERSION-done ] ; then
        echo "Downloading and installing python3:"
        [ -f python-$PYTHON3_VERSION-macosx$macver.pkg ] || curl -L -O https://www.python.org/ftp/python/$PYTHON3_VERSION/python-$PYTHON3_VERSION-macosx$macver.pkg || exit 1
        $no_build && echo "Skipping installation" && return
        sudo installer -target / -pkg python-$PYTHON3_VERSION-macosx$macver.pkg || exit 1
        touch python3-$PYTHON3_VERSION-done
    fi
}

uninstall_python3() {
    # Major version (e.g. "3.7")
    local PYTHON_VERSION=${installed_python3_version%.*}
    if [ ! -z "$installed_python3_version" ] ; then
        echo "Uninstalling python3:"
        frameworkdir="/Library/Frameworks/Python.framework/Versions/$PYTHON_VERSION"
        sudo rm -rf "$frameworkdir"
        sudo rm -rf "/Applications/Python $PYTHON_VERSION"
        sudo find /usr/local/bin -maxdepth 1 -lname "*$frameworkdir/bin/*" -delete
        # Remove three symlinks and empty directories. Removing directories
        # might fail if for some reason multiple versions are installed.
        sudo rm    /Library/Frameworks/Python.framework/Headers
        sudo rm    /Library/Frameworks/Python.framework/Python
        sudo rm    /Library/Frameworks/Python.framework/Resources
        sudo rmdir /Library/Frameworks/Python.framework/Versions
        sudo rmdir /Library/Frameworks/Python.framework
        sudo pkgutil --forget org.python.Python.PythonApplications-$PYTHON_VERSION
        sudo pkgutil --forget org.python.Python.PythonDocumentation-$PYTHON_VERSION
        sudo pkgutil --forget org.python.Python.PythonFramework-$PYTHON_VERSION
        sudo pkgutil --forget org.python.Python.PythonUnixTools-$PYTHON_VERSION
        rm python3-$installed_python3_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -f python-$installed_python3_version-macosx10.9.pkg
            rm -f python-$installed_python3_version-macosx10.6.pkg
        fi

        installed_python3_version=""
    fi
}

install_brotli() {
    if [ "$BROTLI_VERSION" -a ! -f brotli-$BROTLI_VERSION-done ] ; then
        echo "Downloading, building, and installing brotli:"
        [ -f brotli-$BROTLI_VERSION.tar.gz ] || curl -L -o brotli-$BROTLI_VERSION.tar.gz https://github.com/google/brotli/archive/v$BROTLI_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat brotli-$BROTLI_VERSION.tar.gz | tar xf - || exit 1
        cd brotli-$BROTLI_VERSION
        mkdir build_dir
        cd build_dir
        MACOSX_DEPLOYMENT_TARGET=$min_osx_target SDKROOT="$SDKPATH" cmake ../ || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ../..
        touch brotli-$BROTLI_VERSION-done
    fi
}

uninstall_brotli() {
    if [ ! -z "$installed_brotli_version" ] ; then
        echo "Uninstalling brotli:"
        cd brotli-$installed_brotli_version
        #
        # brotli uses cmake on macOS and doesn't support "make uninstall"
        #
        # $DO_MAKE_UNINSTALL || exit 1
        sudo rm -rf /usr/local/bin/brotli
        sudo rm -rf /usr/local/lib/libbrotli*
        sudo rm -rf /usr/local/include/brotli
        sudo rm -rf /usr/local/lib/pkgconfig/libbrotli*
        #
        # brotli uses cmake on macOS and doesn't support "make distclean"
        #
        # make distclean || exit 1
        cd ..
        rm brotli-$installed_brotli_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf brotli-$installed_brotli_version
            rm -rf brotli-$installed_brotli_version.tar.gz
        fi

        installed_brotli_version=""
    fi
}

install_minizip() {
    if [ "$ZLIB_VERSION" ] && [ ! -f minizip-$ZLIB_VERSION-done ] ; then
        echo "Downloading, building, and installing zlib for minizip:"
        [ -f zlib-$ZLIB_VERSION.tar.gz ] || curl -L -o zlib-$ZLIB_VERSION.tar.gz https://zlib.net/zlib-$ZLIB_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat zlib-$ZLIB_VERSION.tar.gz | tar xf - || exit 1
        cd zlib-$ZLIB_VERSION/contrib/minizip || exit 1
        LIBTOOLIZE=glibtoolize autoreconf --force --install
        CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=0 $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS -D_FORTIFY_SOURCE=0 $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ../../..
        touch minizip-$ZLIB_VERSION-done
    fi
}

uninstall_minizip() {
    if [ -n "$installed_minizip_version" ] ; then
        echo "Uninstalling minizip:"
        cd zlib-$installed_minizip_version/contrib/minizip
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ../../..

        rm zlib-$installed_minizip_version-done

        if [ "$#" -eq 1 ] && [ "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf zlib-$installed_minizip_version
            rm -rf zlib-$installed_minizip_version.tar.gz
        fi

        installed_minizip_version=""
    fi
}

install_sparkle() {
    if [ "$SPARKLE_VERSION" ] && [ ! -f sparkle-$SPARKLE_VERSION-done ] ; then
        echo "Downloading and installing Sparkle:"
        #
        # Download the tarball and unpack it in /usr/local/Sparkle-x.y.z
        #
        [ -f Sparkle-$SPARKLE_VERSION.tar.bz2 ] || curl -L -o Sparkle-$SPARKLE_VERSION.tar.bz2 https://github.com/sparkle-project/Sparkle/releases/download/$SPARKLE_VERSION/Sparkle-$SPARKLE_VERSION.tar.bz2 || exit 1
        $no_build && echo "Skipping installation" && return
        test -d "/usr/local/Sparkle-$SPARKLE_VERSION" || sudo mkdir "/usr/local/Sparkle-$SPARKLE_VERSION"
        sudo tar -C "/usr/local/Sparkle-$SPARKLE_VERSION" -xpof Sparkle-$SPARKLE_VERSION.tar.bz2
        touch sparkle-$SPARKLE_VERSION-done
    fi
}

uninstall_sparkle() {
    if [ -n "$installed_sparkle_version" ]; then
        echo "Uninstalling Sparkle:"
        sudo rm -rf "/usr/local/Sparkle-$installed_sparkle_version"
        if [ "$#" -eq 1 ] && [ "$1" = "-r" ] ; then
            rm -f "Sparkle-$installed_sparkle_version.tar.bz2"
        fi

        installed_sparkle_version=""
    fi
}

install_all() {
    #
    # Check whether the versions we have installed are the versions
    # requested; if not, uninstall the installed versions.
    #
    if [ ! -z "$installed_brotli_version" -a \
              "$installed_brotli_version" != "$BROTLI_VERSION" ] ; then
        echo "Installed brotli version is $installed_brotli_version"
        if [ -z "$BROTLI_VERSION" ] ; then
            echo "brotli is not requested"
        else
            echo "Requested brotli version is $BROTLI_VERSION"
        fi
        uninstall_brotli -r
    fi

    if [ ! -z "$installed_python3_version" -a \
              "$installed_python3_version" != "$PYTHON3_VERSION" ] ; then
        echo "Installed python3 version is $installed_python3_version"
        if [ -z "$PYTHON3_VERSION" ] ; then
            echo "python3 is not requested"
        else
            echo "Requested python3 version is $PYTHON3_VERSION"
        fi
        uninstall_python3 -r
    fi

    if [ ! -z "$installed_bcg729_version" -a \
              "$installed_bcg729_version" != "$BCG729_VERSION" ] ; then
        echo "Installed bcg729 version is $installed_bcg729_version"
        if [ -z "$BCG729_VERSION" ] ; then
            echo "bcg729 is not requested"
        else
            echo "Requested bcg729 version is $BCG729_VERSION"
        fi
        uninstall_bcg729 -r
    fi

    if [ -n "$installed_ilbc_version" ] \
              && [ "$installed_ilbc_version" != "$ILBC_VERSION" ] ; then
        echo "Installed iLBC version is $installed_ilbc_version"
        if [ -z "$ILBC_VERSION" ] ; then
            echo "iLBC is not requested"
        else
            echo "Requested iLBC version is $ILBC_VERSION"
        fi
        uninstall_ilbc -r
    fi

    if [ ! -z "$installed_spandsp_version" -a \
              "$installed_spandsp_version" != "$SPANDSP_VERSION" ] ; then
        echo "Installed SpanDSP version is $installed_spandsp_version"
        if [ -z "$SPANDSP_VERSION" ] ; then
            echo "spandsp is not requested"
        else
            echo "Requested SpanDSP version is $SPANDSP_VERSION"
        fi
        uninstall_spandsp -r
    fi

    if [ ! -z "$installed_speexdsp_version" -a \
              "$installed_speexdsp_version" != "$SPEEXDSP_VERSION" ] ; then
        echo "Installed SpeexDSP version is $installed_speexdsp_version"
        if [ -z "$SPEEXDSP_VERSION" ] ; then
            echo "speexdsp is not requested"
        else
            echo "Requested SpeexDSP version is $SPEEXDSP_VERSION"
        fi
        uninstall_speexdsp -r
    fi

    if [ ! -z "$installed_libtiff_version" -a \
              "$installed_libtiff_version" != "$LIBTIFF_VERSION" ] ; then
        echo "Installed libtiff version is $installed_libtiff_version"
        if [ -z "$LIBTIFF_VERSION" ] ; then
            echo "libtiff is not requested"
        else
            echo "Requested libtiff version is $LIBTIFF_VERSION"
        fi
        uninstall_libtiff -r
    fi

    if [ ! -z "$installed_nghttp2_version" -a \
              "$installed_nghttp2_version" != "$NGHTTP2_VERSION" ] ; then
        echo "Installed nghttp2 version is $installed_nghttp2_version"
        if [ -z "$NGHTTP2_VERSION" ] ; then
            echo "nghttp2 is not requested"
        else
            echo "Requested nghttp2 version is $NGHTTP2_VERSION"
        fi
        uninstall_nghttp2 -r
    fi

    if [ ! -z "$installed_libssh_version" -a \
              "$installed_libssh_version" != "$LIBSSH_VERSION" ] ; then
        echo "Installed libssh version is $installed_libssh_version"
        if [ -z "$LIBSSH_VERSION" ] ; then
            echo "libssh is not requested"
        else
            echo "Requested libssh version is $LIBSSH_VERSION"
        fi
        uninstall_libssh -r
    fi

    if [ ! -z "$installed_cares_version" -a \
              "$installed_cares_version" != "$CARES_VERSION" ] ; then
        echo "Installed C-Ares version is $installed_cares_version"
        if [ -z "$CARES_VERSION" ] ; then
            echo "C-Ares is not requested"
        else
            echo "Requested C-Ares version is $CARES_VERSION"
        fi
        uninstall_c_ares -r
    fi

    if [ ! -z "$installed_maxminddb_version" -a \
              "$installed_maxminddb_version" != "$MAXMINDDB_VERSION" ] ; then
        echo "Installed MaxMindDB API version is $installed_maxminddb_version"
        if [ -z "$MAXMINDDB_VERSION" ] ; then
            echo "MaxMindDB is not requested"
        else
            echo "Requested MaxMindDB version is $MAXMINDDB_VERSION"
        fi
        uninstall_maxminddb -r
    fi

    if [ ! -z "$installed_sbc_version" -a \
              "$installed_sbc_version" != "$SBC_VERSION" ] ; then
        echo "Installed SBC version is $installed_sbc_version"
        if [ -z "$SBC_VERSION" ] ; then
            echo "SBC is not requested"
        else
            echo "Requested SBC version is $SBC_VERSION"
        fi
        uninstall_sbc -r
    fi

    if [ ! -z "$installed_lz4_version" -a \
              "$installed_lz4_version" != "$LZ4_VERSION" ] ; then
        echo "Installed LZ4 version is $installed_lz4_version"
        if [ -z "$LZ4_VERSION" ] ; then
            echo "LZ4 is not requested"
        else
            echo "Requested LZ4 version is $LZ4_VERSION"
        fi
        uninstall_lz4 -r
    fi

    if [ ! -z "$installed_libxml2_version" -a \
              "$installed_libxml2_version" != "$LIBXML2_VERSION" ] ; then
        echo "Installed libxml2 version is $installed_libxml2_version"
        if [ -z "$LIBXML2_VERSION" ] ; then
            echo "libxml2 is not requested"
        else
            echo "Requested libxml2 version is $LIBXML2_VERSION"
        fi
        uninstall_libxml2 -r
    fi

    if [ ! -z "$installed_snappy_version" -a \
              "$installed_snappy_version" != "$SNAPPY_VERSION" ] ; then
        echo "Installed SNAPPY version is $installed_snappy_version"
        if [ -z "$SNAPPY_VERSION" ] ; then
            echo "SNAPPY is not requested"
        else
            echo "Requested SNAPPY version is $SNAPPY_VERSION"
        fi
        uninstall_snappy -r
    fi

    if [ ! -z "$installed_lua_version" -a \
              "$installed_lua_version" != "$LUA_VERSION" ] ; then
        echo "Installed Lua version is $installed_lua_version"
        if [ -z "$LUA_VERSION" ] ; then
            echo "Lua is not requested"
        else
            echo "Requested Lua version is $LUA_VERSION"
        fi
        uninstall_lua -r
    fi

    if [ ! -z "$installed_gnutls_version" -a \
              "$installed_gnutls_version" != "$GNUTLS_VERSION" ] ; then
        echo "Installed GnuTLS version is $installed_gnutls_version"
        if [ -z "$GNUTLS_VERSION" ] ; then
            echo "GnuTLS is not requested"
        else
            echo "Requested GnuTLS version is $GNUTLS_VERSION"
        fi
        uninstall_gnutls -r
    fi

    if [ ! -z "$installed_nettle_version" -a \
              "$installed_nettle_version" != "$NETTLE_VERSION" ] ; then
        echo "Installed Nettle version is $installed_nettle_version"
        if [ -z "$NETTLE_VERSION" ] ; then
            echo "Nettle is not requested"
        else
            echo "Requested Nettle version is $NETTLE_VERSION"
        fi
        uninstall_nettle -r
    fi

    if [ ! -z "$installed_gmp_version" -a \
              "$installed_gmp_version" != "$GMP_VERSION" ] ; then
        echo "Installed GMP version is $installed_gmp_version"
        if [ -z "$GMP_VERSION" ] ; then
            echo "GMP is not requested"
        else
            echo "Requested GMP version is $GMP_VERSION"
        fi
        uninstall_gmp -r
    fi

    if [ ! -z "$installed_libgcrypt_version" -a \
              "$installed_libgcrypt_version" != "$LIBGCRYPT_VERSION" ] ; then
        echo "Installed libgcrypt version is $installed_libgcrypt_version"
        if [ -z "$LIBGCRYPT_VERSION" ] ; then
            echo "libgcrypt is not requested"
        else
            echo "Requested libgcrypt version is $LIBGCRYPT_VERSION"
        fi
        uninstall_libgcrypt -r
    fi

    if [ ! -z "$installed_libgpg_error_version" -a \
              "$installed_libgpg_error_version" != "$LIBGPG_ERROR_VERSION" ] ; then
        echo "Installed libgpg-error version is $installed_libgpg_error_version"
        if [ -z "$LIBGPG_ERROR_VERSION" ] ; then
            echo "libgpg-error is not requested"
        else
            echo "Requested libgpg-error version is $LIBGPG_ERROR_VERSION"
        fi
        uninstall_libgpg_error -r
    fi

    if [ ! -z "$installed_libsmi_version" -a \
              "$installed_libsmi_version" != "$LIBSMI_VERSION" ] ; then
        echo "Installed libsmi version is $installed_libsmi_version"
        if [ -z "$LIBSMI_VERSION" ] ; then
            echo "libsmi is not requested"
        else
            echo "Requested libsmi version is $LIBSMI_VERSION"
        fi
        uninstall_libsmi -r
    fi

    if [ ! -z "$installed_qt_version" -a \
              "$installed_qt_version" != "$QT_VERSION" ] ; then
        echo "Installed Qt version is $installed_qt_version"
        if [ -z "$QT_VERSION" ] ; then
            echo "Qt is not requested"
        else
            echo "Requested Qt version is $QT_VERSION"
        fi
        uninstall_qt -r
    fi

    if [ ! -z "$installed_glib_version" -a \
              "$installed_glib_version" != "$GLIB_VERSION" ] ; then
        echo "Installed GLib version is $installed_glib_version"
        if [ -z "$GLIB_VERSION" ] ; then
            echo "GLib is not requested"
        else
            echo "Requested GLib version is $GLIB_VERSION"
        fi
        uninstall_glib -r
    fi

    if [ ! -z "$installed_pkg_config_version" -a \
              "$installed_pkg_config_version" != "$PKG_CONFIG_VERSION" ] ; then
        echo "Installed pkg-config version is $installed_pkg_config_version"
        if [ -z "$PKG_CONFIG_VERSION" ] ; then
            echo "pkg-config is not requested"
        else
            echo "Requested pkg-config version is $PKG_CONFIG_VERSION"
        fi
        uninstall_pkg_config -r
    fi

    if [ ! -z "$installed_gettext_version" -a \
              "$installed_gettext_version" != "$GETTEXT_VERSION" ] ; then
        echo "Installed GNU gettext version is $installed_gettext_version"
        if [ -z "$GETTEXT_VERSION" ] ; then
            echo "GNU gettext is not requested"
        else
            echo "Requested GNU gettext version is $GETTEXT_VERSION"
        fi
        uninstall_gettext -r
    fi

    if [ ! -z "$installed_ninja_version" -a \
              "$installed_ninja_version" != "$NINJA_VERSION" ] ; then
        echo "Installed Ninja version is $installed_ninja_version"
        if [ -z "$NINJA_VERSION" ] ; then
            echo "Ninja is not requested"
        else
            echo "Requested Ninja version is $NINJA_VERSION"
        fi
        uninstall_ninja -r
    fi

    if [ ! -z "$installed_asciidoctorpdf_version" -a \
              "$installed_asciidoctorpdf_version" != "$ASCIIDOCTORPDF_VERSION" ] ; then
        echo "Installed Asciidoctor-pdf version is $installed_asciidoctorpdf_version"
        if [ -z "$ASCIIDOCTORPDF_VERSION" ] ; then
            echo "Asciidoctor-pdf is not requested"
        else
            echo "Requested Asciidoctor-pdf version is $ASCIIDOCTORPDF_VERSION"
        fi
        # XXX - really remove this?
        # Or should we remember it as installed only if this script
        # installed it?
        #
        uninstall_asciidoctorpdf -r
    fi

    if [ ! -z "$installed_asciidoctor_version" -a \
              "$installed_asciidoctor_version" != "$ASCIIDOCTOR_VERSION" ] ; then
        echo "Installed Asciidoctor version is $installed_asciidoctor_version"
        if [ -z "$ASCIIDOCTOR_VERSION" ] ; then
            echo "Asciidoctor is not requested"
        else
            echo "Requested Asciidoctor version is $ASCIIDOCTOR_VERSION"
        fi
        # XXX - really remove this?
        # Or should we remember it as installed only if this script
        # installed it?
        #
        uninstall_asciidoctor -r
    fi

    if [ ! -z "$installed_cmake_version" -a \
              "$installed_cmake_version" != "$CMAKE_VERSION" ] ; then
        echo "Installed CMake version is $installed_cmake_version"
        if [ -z "$CMAKE_VERSION" ] ; then
            echo "CMake is not requested"
        else
            echo "Requested CMake version is $CMAKE_VERSION"
        fi
        uninstall_cmake -r
    fi

    if [ ! -z "$installed_libtool_version" -a \
              "$installed_libtool_version" != "$LIBTOOL_VERSION" ] ; then
        echo "Installed GNU libtool version is $installed_libtool_version"
        if [ -z "$LIBTOOL_VERSION" ] ; then
            echo "GNU libtool is not requested"
        else
            echo "Requested GNU libtool version is $LIBTOOL_VERSION"
        fi
        uninstall_libtool -r
    fi

    if [ ! -z "$installed_automake_version" -a \
              "$installed_automake_version" != "$AUTOMAKE_VERSION" ] ; then
        echo "Installed GNU automake version is $installed_automake_version"
        if [ -z "$AUTOMAKE_VERSION" ] ; then
            echo "GNU automake is not requested"
        else
            echo "Requested GNU automake version is $AUTOMAKE_VERSION"
        fi
        uninstall_automake -r
    fi

    if [ ! -z "$installed_autoconf_version" -a \
              "$installed_autoconf_version" != "$AUTOCONF_VERSION" ] ; then
        echo "Installed GNU autoconf version is $installed_autoconf_version"
        if [ -z "$AUTOCONF_VERSION" ] ; then
            echo "GNU autoconf is not requested"
        else
            echo "Requested GNU autoconf version is $AUTOCONF_VERSION"
        fi
        uninstall_autoconf -r
    fi

    if [ ! -z "$installed_lzip_version" -a \
              "$installed_lzip_version" != "$LZIP_VERSION" ] ; then
        echo "Installed lzip version is $installed_lzip_version"
        if [ -z "$LZIP_VERSION" ] ; then
            echo "lzip is not requested"
        else
            echo "Requested lzip version is $LZIP_VERSION"
        fi
        uninstall_lzip -r
    fi

    if [ ! -z "$installed_xz_version" -a \
              "$installed_xz_version" != "$XZ_VERSION" ] ; then
        echo "Installed xz version is $installed_xz_version"
        if [ -z "$XZ_VERSION" ] ; then
            echo "xz is not requested"
        else
            echo "Requested xz version is $XZ_VERSION"
        fi
        uninstall_xz -r
    fi

    if [ ! -z "$installed_curl_version" -a \
              "$installed_curl_version" != "$CURL_VERSION" ] ; then
        echo "Installed curl version is $installed_curl_version"
        if [ -z "$CURL_VERSION" ] ; then
            echo "curl is not requested"
        else
            echo "Requested curl version is $CURL_VERSION"
        fi
        uninstall_curl -r
    fi

    if [ ! -z "$installed_minizip_version" -a \
              "$installed_minizip_version" != "$ZLIB_VERSION" ] ; then
        echo "Installed minizip (zlib) version is $installed_minizip_version"
        if [ -z "$ZLIB_VERSION" ] ; then
            echo "minizip is not requested"
        else
            echo "Requested minizip (zlib) version is $ZLIB_VERSION"
        fi
        uninstall_minizip -r
    fi

    if [ ! -z "$installed_sparkle_version" -a \
              "$installed_sparkle_version" != "$SPARKLE_VERSION" ] ; then
        echo "Installed Sparkle version is $installed_sparkle_version"
        if [ -z "$SPARKLE_VERSION" ] ; then
            echo "Sparkle is not requested"
        else
            echo "Requested Sparkle version is $SPARKLE_VERSION"
        fi
        uninstall_sparkle -r
    fi

    #
    # Start with curl: we may need it to download and install xz.
    #
    install_curl

    #
    # Now intall xz: it is the sole download format of glib later than 2.31.2.
    #
    install_xz

    install_lzip

    install_autoconf

    install_automake

    install_libtool

    install_cmake

    install_ninja

    install_asciidoctor

    install_asciidoctorpdf

    #
    # Start with GNU gettext; GLib requires it, and macOS doesn't have it
    # or a BSD-licensed replacement.
    #
    # At least on Lion with Xcode 4, _FORTIFY_SOURCE gets defined as 2
    # by default, which causes, for example, stpncpy to be defined as
    # a hairy macro that collides with the GNU gettext configure script's
    # attempts to workaround AIX's lack of a declaration for stpncpy,
    # with the result being a huge train wreck.  Define _FORTIFY_SOURCE
    # as 0 in an attempt to keep the trains on separate tracks.
    #
    install_gettext

    #
    # GLib depends on pkg-config.
    # By default, pkg-config depends on GLib; we break the dependency cycle
    # by configuring pkg-config to use its own internal version of GLib.
    #
    install_pkg_config

    install_glib

    #
    # Now we have reached a point where we can build everything but
    # the GUI (Wireshark).
    #
    install_qt

    #
    # Now we have reached a point where we can build everything including
    # the GUI (Wireshark), but not with any optional features such as
    # SNMP OID resolution, some forms of decryption, Lua scripting, playback
    # of audio, or MaxMindDB mapping of IP addresses.
    #
    # We now conditionally download optional libraries to support them;
    # the default is to download them all.
    #

    install_libsmi

    install_libgpg_error

    install_libgcrypt

    install_gmp

    install_nettle

    install_gnutls

    install_lua

    install_snappy

    install_zstd

    install_libxml2

    install_lz4

    install_sbc

    install_maxminddb

    install_c_ares

    install_libssh

    install_nghttp2

    install_libtiff

    install_spandsp

    install_speexdsp

    install_bcg729

    install_ilbc

    install_python3

    install_brotli

    install_minizip

    install_sparkle
}

uninstall_all() {
    if [ -d "${MACOSX_SUPPORT_LIBS}" ]
    then
        cd "${MACOSX_SUPPORT_LIBS}"

        #
        # Uninstall items in the reverse order from the order in which they're
        # installed.  Only uninstall if the download/build/install process
        # completed; uninstall the version that appears in the name of
        # the -done file.
        #
        # We also do a "make distclean", so that we don't have leftovers from
        # old configurations.
        #
        uninstall_sparkle

        uninstall_minizip

        uninstall_brotli

        uninstall_python3

        uninstall_ilbc

        uninstall_bcg729

        uninstall_speexdsp

        uninstall_spandsp

        uninstall_libtiff

        uninstall_nghttp2

        uninstall_libssh

        uninstall_c_ares

        uninstall_maxminddb

        uninstall_snappy

        uninstall_zstd

        uninstall_libxml2

        uninstall_lz4

        uninstall_sbc

        uninstall_lua

        uninstall_gnutls

        uninstall_nettle

        uninstall_gmp

        uninstall_libgcrypt

        uninstall_libgpg_error

        uninstall_libsmi

        uninstall_qt

        uninstall_glib

        uninstall_pkg_config

        uninstall_gettext

        uninstall_ninja

        #
        # XXX - really remove this?
        # Or should we remember it as installed only if this script
        # installed it?
        #
        uninstall_asciidoctorpdf

        uninstall_asciidoctor

        uninstall_cmake

        uninstall_libtool

        uninstall_automake

        uninstall_autoconf

        uninstall_lzip

        uninstall_xz

        uninstall_curl
    fi
}

#
# Do we have permission to write in /usr/local?
#
# If so, assume we have permission to write in its subdirectories.
# (If that's not the case, this test needs to check the subdirectories
# as well.)
#
# If not, do "make install", "make uninstall", the removes for Lua,
# and the renames of [g]libtool* with sudo.
#
if [ -w /usr/local ]
then
    DO_MAKE_INSTALL="make install"
    DO_MAKE_UNINSTALL="make uninstall"
    DO_RM="rm"
    DO_MV="mv"
else
    DO_MAKE_INSTALL="sudo make install"
    DO_MAKE_UNINSTALL="sudo make uninstall"
    DO_RM="sudo rm"
    DO_MV="sudo mv"
fi

# This script is meant to be run in the source root.  The following
# code will attempt to get you there, but is not perfect (particulary
# if someone copies the script).

topdir=`pwd`/`dirname $0`/..
cd $topdir

# Preference of the support libraries directory:
#   ${MACOSX_SUPPORT_LIBS}
#   ../macosx-support-libs
#   ./macosx-support-libs (default if none exists)
if [ ! -d "${MACOSX_SUPPORT_LIBS}" ]; then
  unset MACOSX_SUPPORT_LIBS
fi
if [ -d ../macosx-support-libs ]; then
  MACOSX_SUPPORT_LIBS=${MACOSX_SUPPORT_LIBS-../macosx-support-libs}
else
  MACOSX_SUPPORT_LIBS=${MACOSX_SUPPORT_LIBS-./macosx-support-libs}
fi

#
# If we have SDKs available, the default target OS is the major version
# of the one we're running; get that and strip off the third component
# if present.
#
for i in /Developer/SDKs \
    /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs \
    /Library/Developer/CommandLineTools/SDKs
do
    if [ -d "$i" ]
    then
        min_osx_target=`sw_vers -productVersion | sed 's/\([0-9]*\)\.\([0-9]*\)\.[0-9]*/\1.\2/'`
        break
    fi
done

#
# Parse command-line flags:
#
# -h - print help.
# -t <target> - build libraries so that they'll work on the specified
# version of macOS and later versions.
# -u - do an uninstall.
# -n - download all packages, but don't build or install.
#

no_build=false

while getopts ht:un name
do
    case $name in
    u)
        do_uninstall=yes
        ;;
    n)
        no_build=true
        ;;
    t)
        min_osx_target="$OPTARG"
        ;;
    h|?)
        echo "Usage: macos-setup.sh [ -t <target> ] [ -u ] [ -n ]" 1>&1
        exit 0
        ;;
    esac
done

#
# Get the version numbers of installed packages, if any.
#
if [ -d "${MACOSX_SUPPORT_LIBS}" ]
then
    cd "${MACOSX_SUPPORT_LIBS}"

    installed_xz_version=`ls xz-*-done 2>/dev/null | sed 's/xz-\(.*\)-done/\1/'`
    installed_lzip_version=`ls lzip-*-done 2>/dev/null | sed 's/lzip-\(.*\)-done/\1/'`
    installed_autoconf_version=`ls autoconf-*-done 2>/dev/null | sed 's/autoconf-\(.*\)-done/\1/'`
    installed_automake_version=`ls automake-*-done 2>/dev/null | sed 's/automake-\(.*\)-done/\1/'`
    installed_libtool_version=`ls libtool-*-done 2>/dev/null | sed 's/libtool-\(.*\)-done/\1/'`
    installed_cmake_version=`ls cmake-*-done 2>/dev/null | sed 's/cmake-\(.*\)-done/\1/'`
    installed_ninja_version=`ls ninja-*-done 2>/dev/null | sed 's/ninja-\(.*\)-done/\1/'`
    installed_asciidoctor_version=`ls asciidoctor-*-done 2>/dev/null | sed 's/asciidoctor-\(.*\)-done/\1/'`
    installed_asciidoctorpdf_version=`ls asciidoctorpdf-*-done 2>/dev/null | sed 's/asciidoctorpdf-\(.*\)-done/\1/'`
    installed_gettext_version=`ls gettext-*-done 2>/dev/null | sed 's/gettext-\(.*\)-done/\1/'`
    installed_pkg_config_version=`ls pkg-config-*-done 2>/dev/null | sed 's/pkg-config-\(.*\)-done/\1/'`
    installed_glib_version=`ls glib-*-done 2>/dev/null | sed 's/glib-\(.*\)-done/\1/'`
    installed_qt_version=`ls qt-*-done 2>/dev/null | sed 's/qt-\(.*\)-done/\1/'`
    installed_libsmi_version=`ls libsmi-*-done 2>/dev/null | sed 's/libsmi-\(.*\)-done/\1/'`
    installed_libgpg_error_version=`ls libgpg-error-*-done 2>/dev/null | sed 's/libgpg-error-\(.*\)-done/\1/'`
    installed_libgcrypt_version=`ls libgcrypt-*-done 2>/dev/null | sed 's/libgcrypt-\(.*\)-done/\1/'`
    installed_gmp_version=`ls gmp-*-done 2>/dev/null | sed 's/gmp-\(.*\)-done/\1/'`
    installed_nettle_version=`ls nettle-*-done 2>/dev/null | sed 's/nettle-\(.*\)-done/\1/'`
    installed_gnutls_version=`ls gnutls-*-done 2>/dev/null | sed 's/gnutls-\(.*\)-done/\1/'`
    installed_lua_version=`ls lua-*-done 2>/dev/null | sed 's/lua-\(.*\)-done/\1/'`
    installed_snappy_version=`ls snappy-*-done 2>/dev/null | sed 's/snappy-\(.*\)-done/\1/'`
    installed_zstd_version=`ls zstd-*-done 2>/dev/null | sed 's/zstd-\(.*\)-done/\1/'`
    installed_libxml2_version=`ls libxml2-*-done 2>/dev/null | sed 's/libxml2-\(.*\)-done/\1/'`
    installed_lz4_version=`ls lz4-*-done 2>/dev/null | sed 's/lz4-\(.*\)-done/\1/'`
    installed_sbc_version=`ls sbc-*-done 2>/dev/null | sed 's/sbc-\(.*\)-done/\1/'`
    installed_maxminddb_version=`ls maxminddb-*-done 2>/dev/null | sed 's/maxminddb-\(.*\)-done/\1/'`
    installed_cares_version=`ls c-ares-*-done 2>/dev/null | sed 's/c-ares-\(.*\)-done/\1/'`
    installed_libssh_version=`ls libssh-*-done 2>/dev/null | sed 's/libssh-\(.*\)-done/\1/'`
    installed_nghttp2_version=`ls nghttp2-*-done 2>/dev/null | sed 's/nghttp2-\(.*\)-done/\1/'`
    installed_libtiff_version=`ls tiff-*-done 2>/dev/null | sed 's/tiff-\(.*\)-done/\1/'`
    installed_spandsp_version=`ls spandsp-*-done 2>/dev/null | sed 's/spandsp-\(.*\)-done/\1/'`
    installed_speexdsp_version=`ls speexdsp-*-done 2>/dev/null | sed 's/speexdsp-\(.*\)-done/\1/'`
    installed_bcg729_version=`ls bcg729-*-done 2>/dev/null | sed 's/bcg729-\(.*\)-done/\1/'`
    installed_ilbc_version=`ls ilbc-*-done 2>/dev/null | sed 's/ilbc-\(.*\)-done/\1/'`
    installed_python3_version=`ls python3-*-done 2>/dev/null | sed 's/python3-\(.*\)-done/\1/'`
    installed_brotli_version=`ls brotli-*-done 2>/dev/null | sed 's/brotli-\(.*\)-done/\1/'`
    installed_minizip_version=`ls minizip-*-done 2>/dev/null | sed 's/minizip-\(.*\)-done/\1/'`
    installed_sparkle_version=`ls sparkle-*-done 2>/dev/null | sed 's/sparkle-\(.*\)-done/\1/'`

    cd $topdir
fi

if [ "$do_uninstall" = "yes" ]
then
    uninstall_all
    exit 0
fi

#
# Configure scripts tend to set CFLAGS and CXXFLAGS to "-g -O2" if
# invoked without CFLAGS or CXXFLAGS being set in the environment.
#
# However, we *are* setting them in the environment, for our own
# nefarious purposes, so start them out as "-g -O2".
#
CFLAGS="-g -O2"
CXXFLAGS="-g -O2"

# if no make options are present, set default options
if [ -z "$MAKE_BUILD_OPTS" ] ; then
    # by default use 1.5x number of cores for parallel build
    MAKE_BUILD_OPTS="-j $(( $(sysctl -n hw.logicalcpu) * 3 / 2))"
fi

#
# If we have a target release, look for the oldest SDK that's for an
# OS equal to or later than that one, and build libraries against it
# rather than against the headers and, more importantly, libraries
# that come with the OS, so that we don't end up with support libraries
# that only work on the OS version on which we built them, not earlier
# versions of the same release, or earlier releases if the minimum is
# earlier.
#
if [ ! -z "$min_osx_target" ]
then
    #
    # Get the real version - strip off the "10.".
    #
    deploy_real_version=`echo "$min_osx_target" | sed -n 's/10\.\(.*\)/\1/p'`

    #
    # Search each directory that might contain SDKs.
    #
    sdkpath=""
    for sdksdir in /Developer/SDKs \
        /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs \
        /Library/Developer/CommandLineTools/SDKs
    do
        #
        # Get a list of all the SDKs.
        #
        if ! test -d "$sdksdir"
        then
            #
            # There is no directory with that name.
            # Move on to the next one in the list, if any.
            #
            continue
        fi

        #
        # Get a list of all the SDKs in that directory, if any.
        #
        sdklist=`(cd "$sdksdir"; ls -d MacOSX10.[0-9]*.sdk 2>/dev/null)`

        for sdk in $sdklist
        do
            #
            # Get the real version for this SDK.
            #
            sdk_real_version=`echo "$sdk" | sed -n 's/MacOSX10\.\(.*\)\.sdk/\1/p'`

            #
            # Is it for the deployment target or some later release?
            #
            if test "$sdk_real_version" -ge "$deploy_real_version"
            then
                #
                # Yes, use it.
                #
                sdkpath="$sdksdir/$sdk"
                break 2
            fi
        done
    done

    if [ -z "$sdkpath" ]
    then
        echo "macos-setup.sh: Couldn't find an SDK for macOS $min_osx_target or later" 1>&2
        exit 1
    fi

    SDKPATH="$sdkpath"
    echo "Using the 10.$sdk_real_version SDK"

    #
    # Make sure there are links to /usr/local/include and /usr/local/lib
    # in the SDK's usr/local.
    #
    if [ ! -e $SDKPATH/usr/local/include ]
    then
        if [ ! -d $SDKPATH/usr/local ]
        then
            sudo mkdir $SDKPATH/usr/local
        fi
        sudo ln -s /usr/local/include $SDKPATH/usr/local/include
    fi
    if [ ! -e $SDKPATH/usr/local/lib ]
    then
        if [ ! -d $SDKPATH/usr/local ]
        then
            sudo mkdir $SDKPATH/usr/local
        fi
        sudo ln -s /usr/local/lib $SDKPATH/usr/local/lib
    fi

    #
    # Set the minimum OS version for which to build to the specified
    # minimum target OS version, so we don't, for example, end up using
    # linker features supported by the OS verson on which we're building
    # but not by the target version.
    #
    VERSION_MIN_FLAGS="-mmacosx-version-min=$min_osx_target"

    #
    # Compile and link against the SDK.
    #
    SDKFLAGS="-isysroot $SDKPATH"

fi

export CFLAGS
export CXXFLAGS

#
# You need Xcode or the command-line tools installed to get the compilers.
#
if [ ! -x /usr/bin/xcodebuild ]; then
    echo "Please install Xcode first (should be available on DVD or from the Mac App Store)."
    exit 1
fi

if [ "$QT_VERSION" ]; then
    #
    # We need Xcode, not just the command-line tools, installed to build
    # Qt.
    #
    # At least with Xcode 8, /usr/bin/xcodebuild --help fails if only
    # the command-line tools are installed and succeeds if Xcode is
    # installed.  Unfortunately, it fails *with* Xcode 3, but
    # /usr/bin/xcodebuild -version works with that and with Xcode 8.
    # Hopefully it fails with only the command-line tools installed.
    #
    if /usr/bin/xcodebuild -version >/dev/null 2>&1; then
        :
    else
        echo "Please install Xcode first (should be available on DVD or from the Mac App Store)."
        echo "The command-line build tools are not sufficient to build Qt."
        exit 1
    fi
fi

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig

#
# Do all the downloads and untarring in a subdirectory, so all that
# stuff can be removed once we've installed the support libraries.

if [ ! -d "${MACOSX_SUPPORT_LIBS}" ]
then
    mkdir "${MACOSX_SUPPORT_LIBS}" || exit 1
fi
cd "${MACOSX_SUPPORT_LIBS}"

install_all

echo ""

#
# Indicate what paths to use for pkg-config and cmake.
#
pkg_config_path=/usr/local/lib/pkgconfig
if [ "$QT_VERSION" ]; then
    qt_base_path=$HOME/Qt$QT_VERSION/$QT_VERSION/clang_64
    pkg_config_path="$pkg_config_path":"$qt_base_path/lib/pkgconfig"
    CMAKE_PREFIX_PATH="$CMAKE_PREFIX_PATH":"$qt_base_path/lib/cmake"
fi

if $no_build; then
    echo "All required dependencies downloaded. Run without -n to install them."
    exit 0
fi

echo "You are now prepared to build Wireshark."
echo
echo "To build:"
echo
echo "export PKG_CONFIG_PATH=$pkg_config_path"
echo "export CMAKE_PREFIX_PATH=$CMAKE_PREFIX_PATH"
echo "export PATH=$PATH:$qt_base_path/bin"
echo
echo "mkdir build; cd build"
if [ ! -z "$NINJA_VERSION" ]; then
    echo "cmake -G Ninja .."
    echo "ninja app_bundle"
    echo "ninja install/strip"
else
    echo "cmake .."
    echo "make $MAKE_BUILD_OPTS app_bundle"
    echo "make install/strip"
fi
echo
echo "Make sure you are allowed capture access to the network devices"
echo "See: https://wiki.wireshark.org/CaptureSetup/CapturePrivileges"
echo

exit 0
