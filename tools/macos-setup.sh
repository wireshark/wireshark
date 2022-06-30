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
# The minimum supported version of Qt is 5.9, so the minimum supported version
# of macOS is OS X 10.10 (Yosemite), aka Darwin 14.0
if [[ $DARWIN_MAJOR_VERSION -lt 14 ]]; then
    echo "This script does not support any versions of macOS before Yosemite" 1>&2
    exit 1
fi

#
# Get the processor architecture of Darwin. Currently supported: arm, i386
#
DARWIN_PROCESSOR_ARCH=`uname -p`

if [ "$DARWIN_PROCESSOR_ARCH" != "arm" -a "$DARWIN_PROCESSOR_ARCH" != "i386" ]; then
    echo "This script does not support this processor architecture" 1>&2
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
# XXX: tar, since macOS 10.9, can uncompress xz'ed tarballs,
# so perhaps we could get rid of this now?
#
XZ_VERSION=5.2.5

#
# Some packages need lzip to unpack their current source.
#
LZIP_VERSION=1.21

#
# The version of libPCRE on Catalina is insufficient to build glib due to
# missing UTF-8 support.
#
PCRE_VERSION=8.45

#
# CMake is required to do the build - and to build some of the
# dependencies.
#
CMAKE_VERSION=${CMAKE_VERSION-3.21.4}

#
# Ninja isn't required, as make is provided with Xcode, but it is
# claimed to build faster than make.
# Comment it out if you don't want it.
#
NINJA_VERSION=${NINJA_VERSION-1.10.2}

#
# The following libraries and tools are required even to build only TShark.
#
GETTEXT_VERSION=0.21
GLIB_VERSION=2.68.4
if [ "$GLIB_VERSION" ]; then
    GLIB_MAJOR_VERSION="`expr $GLIB_VERSION : '\([0-9][0-9]*\).*'`"
    GLIB_MINOR_VERSION="`expr $GLIB_VERSION : '[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
    GLIB_DOTDOT_VERSION="`expr $GLIB_VERSION : '[0-9][0-9]*\.[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
    GLIB_MAJOR_MINOR_VERSION=$GLIB_MAJOR_VERSION.$GLIB_MINOR_VERSION
    GLIB_MAJOR_MINOR_DOTDOT_VERSION=$GLIB_MAJOR_VERSION.$GLIB_MINOR_VERSION.$GLIB_DOTDOT_VERSION
fi
PKG_CONFIG_VERSION=0.29.2
#
# libgpg-error is required for libgcrypt.
#
LIBGPG_ERROR_VERSION=1.39
#
# libgcrypt is required.
#
LIBGCRYPT_VERSION=1.8.7
#
# libpcre2 is required.
#
PCRE2_VERSION=10.39

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
QT_VERSION=${QT_VERSION-5.12.12}

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
GNUTLS_VERSION=3.6.15
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
    GMP_VERSION=6.2.1

    #
    # And p11-kit
    P11KIT_VERSION=0.23.21

    # Which requires libtasn1
    LIBTASN1_VERSION=4.16.0
fi
# Use 5.2.4, not 5.3, for now; lua_bitop.c hasn't been ported to 5.3
# yet, and we need to check for compatibility issues (we'd want Lua
# scripts to work with 5.1, 5.2, and 5.3, as long as they only use Lua
# features present in all three versions)
LUA_VERSION=5.2.4
SNAPPY_VERSION=1.1.8
ZSTD_VERSION=1.4.2
LIBXML2_VERSION=2.9.9
LZ4_VERSION=1.9.2
SBC_VERSION=1.3
CARES_VERSION=1.15.0
LIBSSH_VERSION=0.9.6
# mmdbresolve
MAXMINDDB_VERSION=1.4.3
NGHTTP2_VERSION=1.46.0
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
OPUS_VERSION=1.3.1

#
# Is /usr/bin/python3 a working version of Python?  It may be, as it
# might be a wrapper that runs the Python 3 that's part of Xcode.
#
if /usr/bin/python3 --version >/dev/null 2>&1
then
    #
    # Yes - don't bother installing Python 3 from elsewhere
    #
    :
else
    #
    # No - install a Python package.
    #
    PYTHON3_VERSION=3.9.5
fi
BROTLI_VERSION=1.0.9
# minizip
ZLIB_VERSION=1.2.11
# Uncomment to enable automatic updates using Sparkle
#SPARKLE_VERSION=2.1.0

#
# Asciidoctor is required to build the documentation.
#
ASCIIDOCTOR_VERSION=${ASCIIDOCTOR_VERSION-2.0.16}
ASCIIDOCTORPDF_VERSION=${ASCIIDOCTORPDF_VERSION-1.6.1}

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
        [ -f xz-$XZ_VERSION.tar.bz2 ] || curl -L -O https://tukaani.org/xz/xz-$XZ_VERSION.tar.bz2 || exit 1
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
        [ -f lzip-$LZIP_VERSION.tar.gz ] || curl -L -O https://download.savannah.gnu.org/releases/lzip/lzip-$LZIP_VERSION.tar.gz || exit 1
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

install_pcre() {
    if [ "$PCRE_VERSION" -a ! -f pcre-$PCRE_VERSION-done ] ; then
        echo "Downloading, building, and installing pcre:"
        [ -f pcre-$PCRE_VERSION.tar.bz2 ] || curl -L -O https://sourceforge.net/projects/pcre/files/pcre/$PCRE_VERSION/pcre-$PCRE_VERSION.tar.bz2 || exit 1
        $no_build && echo "Skipping installation" && return
        bzcat pcre-$PCRE_VERSION.tar.bz2 | tar xf - || exit 1
        cd pcre-$PCRE_VERSION
        ./configure --enable-unicode-properties || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch pcre-$PCRE_VERSION-done
    fi
}

uninstall_pcre() {
    if [ ! -z "$installed_pcre_version" ] ; then
        echo "Uninstalling pcre:"
        cd pcre-$installed_pcre_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm pcre-$installed_pcre_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf pcre-$installed_pcre_version
            rm -rf pcre-$installed_pcre_version.tar.bz2
        fi

        installed_pcre_version=""
    fi
}

install_pcre2() {
    if [ "$PCRE2_VERSION" -a ! -f "pcre2-$PCRE2_VERSION-done" ] ; then
        echo "Downloading, building, and installing pcre2:"
        [ -f "pcre2-$PCRE2_VERSION.tar.bz2" ] || curl -L -O "https://github.com/PhilipHazel/pcre2/releases/download/pcre2-$PCRE2_VERSION/pcre2-10.39.tar.bz2" || exit 1
        $no_build && echo "Skipping installation" && return
        bzcat "pcre2-$PCRE2_VERSION.tar.bz2" | tar xf - || exit 1
        cd "pcre2-$PCRE2_VERSION"
        mkdir build_dir
        cd build_dir
        # https://github.com/Homebrew/homebrew-core/blob/master/Formula/pcre2.rb
        # https://github.com/microsoft/vcpkg/blob/master/ports/pcre2/portfile.cmake
        MACOSX_DEPLOYMENT_TARGET=$min_osx_target SDKROOT="$SDKPATH" \
            cmake -DBUILD_STATIC_LIBS=OFF -DBUILD_SHARED_LIBS=ON -DPCRE2_SUPPORT_JIT=ON -DPCRE2_SUPPORT_UNICODE=ON .. || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ../..
        touch "pcre2-$PCRE2_VERSION-done"
    fi
}

uninstall_pcre2() {
    if [ -n "$installed_pcre2_version" ] && [ -s "pcre2-$installed_pcre2_version/build_dir/install_manifest.txt" ] ; then
        echo "Uninstalling pcre2:"
        # PCRE2 10.39 installs pcre2unicode.3 twice, so this will return an error.
        while read -r ; do $DO_RM -v "$REPLY" ; done < <(cat "pcre2-$installed_pcre2_version/build_dir/install_manifest.txt"; echo)
        rm "pcre2-$installed_pcre2_version-done"

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf "pcre2-$installed_pcre2_version"
            rm -rf "pcre2-$installed_pcre2_version.tar.bz2"
        fi

        installed_pcre2_version=""
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
        uninstall_libtool "$@"
        uninstall_automake "$@"

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
        rm ninja-$installed_ninja_version-done
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
        sudo gem install -V asciidoctor-pdf --version "=${ASCIIDOCTORPDF_VERSION}"
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

        0|1|2)
            echo "CMake $CMAKE_VERSION" is too old 1>&2
            ;;

        3)
            #
            # Download the DMG and do a drag install, where "drag" means
            # "mv".
            #
            # 3.1.1 to 3.19.1 have a Darwin-x86_64 DMG.
            # 3.19.2 has a macos-universal DMG for 10.10 and later
            # 3.19.3 and later have a macos-universal DMG for 10.13 and later,
            # and a macos10.10-universal DMG for 10.10 and later.
            #
            if [ "$CMAKE_MINOR_VERSION" -lt 5 ]; then
                echo "CMake $CMAKE_VERSION" is too old 1>&2
            elif [ "$CMAKE_MINOR_VERSION" -lt 19 -o \
                 "$CMAKE_VERSION" = 3.19.0 -o \
                 "$CMAKE_VERSION" = 3.19.1 ]; then
                type="Darwin-x86_64"
            elif [ "$CMAKE_VERSION" = 3.19.2 -o \
                 "$DARWIN_MAJOR_VERSION" -ge 17 ]; then
                type="macos-universal"
            else
                type="macos10.0-universal"
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

        0|1|2)
            echo "CMake $installed_cmake_version" is too old 1>&2
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
            rm -f cmake-$installed_cmake_version-Darwin-x86_64.dmg
            rm -f cmake-$installed_cmake_version-macos-universal.dmg
            rm -f cmake-$installed_cmake_version-macos10.0-universal.dmg
        fi

        installed_cmake_version=""
    fi
}

install_meson() {
    #
    # Install Meson with pip3 if we don't have it already.
    #
    if $MESON --version >/dev/null 2>&1
    then
        # We have it.
        :
    else
        sudo pip3 install meson
        touch meson-done
    fi
}

uninstall_meson() {
    #
    # If we installed Meson, uninstal it with pip3.
    #
    if [ -f meson-done ] ; then
        sudo pip3 uninstall meson
        rm -f meson-done
    fi
}

install_gettext() {
    if [ ! -f gettext-$GETTEXT_VERSION-done ] ; then
        echo "Downloading, building, and installing GNU gettext:"
        [ -f gettext-$GETTEXT_VERSION.tar.gz ] || curl -L -O https://ftp.gnu.org/pub/gnu/gettext/gettext-$GETTEXT_VERSION.tar.gz || exit 1
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
        [ -f glib-$GLIB_VERSION.tar.xz ] || curl -L -O https://download.gnome.org/sources/glib/$glib_dir/glib-$GLIB_VERSION.tar.xz || exit 1
        $no_build && echo "Skipping installation" && return
        xzcat glib-$GLIB_VERSION.tar.xz | tar xf - || exit 1
        cd glib-$GLIB_VERSION
        #
        # First, determine where the system include files are.
        # (It's not necessarily /usr/include.)  There's a bit of a
        # greasy hack here; pre-5.x versions of the developer tools
        # don't support the --show-sdk-path option, and will produce
        # no output, so includedir will be set to /usr/include
        # (in those older versions of the developer tools, there is
        # a /usr/include directory).
        #
        # We need this for several things we do later.
        #
        includedir=`SDKROOT="$SDKPATH" xcrun --show-sdk-path 2>/dev/null`/usr/include
        #
        # GLib's configuration procedure, whether autotools-based or
        # Meson-based, really likes to use pkg-config to find libraries,
        # including libffi.
        #
        # At least some versions of macOS provide libffi, but, as macOS
        # doesn't provide pkg-config, they don't provide a .pc file for
        # it, so the autotools-based configuration needs some trickery
        # to get it to find the OS-supplied libffi, and the Meson-based
        # configuration simply won't find it at all.
        #
        # So, if we have a system-provided libffi, but pkg-config
        # doesn't find libffi, we construct a .pc file for that libffi,
        # and install it in /usr/local/lib/pkgconfig.
        #
        if pkg-config libffi ; then
            # It found libffi; no need to install a .pc file, and we
            # don't want to overwrite what's there already.
            :
        elif [ ! -e $includedir/ffi/ffi.h ] ; then
            # We don't appear to have libffi as part of the system, so
            # let the configuration process figure out what to do.
            #
            # We test for the header file, not the library, because, in
            # Big Sur and later, there's no guarantee that, for a system
            # shared library, there's a corresponding dylib file in
            # /usr/lib.
            :
        else
            #
            # We have libffi, but pkg-config didn't find it; generate
            # and install the .pc file.
            #

            #
            # Now generate the .pc file.
            #
            # We generate the contents of the .pc file by using cat with
            # a here document containing a template for the file and
            # piping that to a sed command that replaces @INCLUDEDIR@ in
            # the template with the include directory we discovered
            # above, so that the .pc file gives the compiler flags
            # necessary to find the libffi headers (which are *not*
            # necessarily in /usr/include, as per the above).
            #
            # The EOF marker for the here document is in quotes, to tell
            # the shell not to do shell expansion, as .pc files use a
            # syntax to refer to .pc file variables that looks like the
            # syntax to refer to shell variables.
            #
            # The writing of the libffi.pc file is a greasy hack - the
            # process of generating the contents of the .pc file writes
            # to the standard output, but running the last process in
            # the pipeline as root won't allow the shell that's
            # *running* it to open the .pc file if we don't have write
            # permission on /usr/local/lib/pkgconfig, so we need a
            # program that creates a file and then reads from the
            # standard input and writes to that file.  UN*Xes have a
            # program that does that; it's called "tee". :-)
            #
            # However, it *also* writes the file to the standard output,
            # so we redirect that to /dev/null when we run it.
            #
            cat <<"EOF" | sed "s;@INCLUDEDIR@;$includedir;" | $DO_TEE_TO_PC_FILE /usr/local/lib/pkgconfig/libffi.pc >/dev/null
prefix=/usr
libdir=${prefix}/lib
includedir=@INCLUDEDIR@

Name: ffi
Description: Library supporting Foreign Function Interfaces
Version: 3.2.9999
Libs: -L${libdir} -lffi
Cflags: -I${includedir}/ffi
EOF
        fi

        #
        # GLib 2.59.1 and later use Meson+Ninja as the build system.
        #
        case $GLIB_MAJOR_VERSION in

        1)
            echo "GLib $GLIB_VERSION" is too old 1>&2
            ;;

        *)
            case $GLIB_MINOR_VERSION in

            [0-9]|1[0-9]|2[0-9]|3[0-7])
                echo "GLib $GLIB_VERSION" is too old 1>&2
                ;;

            3[8-9]|4[0-9]|5[0-8])
                if [ ! -f ./configure ]; then
                    LIBTOOLIZE=glibtoolize ./autogen.sh
                fi
                #
                # At least with the version of Xcode that comes with
                # Leopard, /usr/include/ffi/fficonfig.h doesn't define
                # MACOSX, which causes the build of GLib to fail for at
                # least some versions of GLib.  If we don't find
                # "#define.*MACOSX" in /usr/include/ffi/fficonfig.h,
                # explicitly define it.
                #
                # While we're at it, suppress -Wformat-nonliteral to
                # avoid a case where clang's stricter rules on when not
                # to complain about non-literal format arguments cause
                # it to complain about code that's safe but it wasn't
                # told that.  See my comment #25 in GNOME bug 691608:
                #
                #    https://bugzilla.gnome.org/show_bug.cgi?id=691608#c25
                #
                if grep -qs '#define.*MACOSX' $includedir/ffi/fficonfig.h
                then
                    # It's defined, nothing to do
                    CFLAGS="$CFLAGS -Wno-format-nonliteral $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS -Wno-format-nonliteral $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
                else
                    CFLAGS="$CFLAGS -DMACOSX -Wno-format-nonliteral $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS -DMACOSX -Wno-format-nonliteral $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
                fi
                make $MAKE_BUILD_OPTS || exit 1
                $DO_MAKE_INSTALL || exit 1
                ;;

            59|[6-9][0-9]|[1-9][0-9][0-9])
                #
                # 2.59.0 doesn't require Meson and Ninja, but it
                # supports it, and I'm too lazy to add a dot-dot
                # version check.
                #
                CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" $MESON _build || exit 1
                ninja $MAKE_BUILD_OPTS -C _build || exit 1
                $DO_NINJA_INSTALL || exit 1
                ;;
            *)
                echo "Glib's put out 1000 2.x releases?" 1>&2
                ;;

            esac
        esac
        cd ..
        touch glib-$GLIB_VERSION-done
    fi
}

uninstall_glib() {
    if [ ! -z "$installed_glib_version" ] ; then
        echo "Uninstalling GLib:"
        cd glib-$installed_glib_version
        installed_glib_major_version="`expr $installed_glib_version : '\([0-9][0-9]*\).*'`"
        installed_glib_minor_version="`expr $installed_glib_version : '[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
        installed_glib_dotdot_version="`expr $installed_glib_version : '[0-9][0-9]*\.[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
        installed_glib_major_minor_version=$installed_glib_major_version.$installed_glib_minor_version
        installed_glib_major_minor_dotdot_version=$installed_glib_major_version.$installed_glib_minor_version.$installed_glib_dotdot_version
        #
        # GLib 2.59.1 and later use Meson+Ninja as the build system.
        #
        case $installed_glib_major_version in

        1)
            $DO_MAKE_UNINSTALL || exit 1
            #
            # This appears to delete dependencies out from under other
            # Makefiles in the tree, causing it to fail.  At least until
            # that gets fixed, if it ever gets fixed, we just ignore the
            # exit status of "make distclean"
            #
            # make distclean || exit 1
            make distclean || echo "Ignoring make distclean failure" 1>&2
            ;;

        *)
            case $installed_glib_minor_version in

            [0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-8])
                $DO_MAKE_UNINSTALL || exit 1
                #
                # This appears to delete dependencies out from under other
                # Makefiles in the tree, causing it to fail.  At least until
                # that gets fixed, if it ever gets fixed, we just ignore the
                # exit status of "make distclean"
                #
                # make distclean || exit 1
                make distclean || echo "Ignoring make distclean failure" 1>&2
                ;;

            59|[6-9][0-9]|[1-9][0-9][0-9])
                #
                # 2.59.0 doesn't require Meson and Ninja, but it
                # supports it, and I'm too lazy to add a dot-dot
                # version check.
                #
                $DO_NINJA_UNINSTALL || exit 1
                #
                # For Meson+Ninja, we do the build in an _build
                # subdirectory, so the equivalent of "make distclean"
                # is just to remove the directory tree.
                #
                rm -rf _build
                ;;

            *)
                echo "Glib's put out 1000 2.x releases?" 1>&2
                ;;
            esac
        esac
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
        # 5.9 - 5.14: qt-opensource-mac-x64-{version}.dmg
        # 5.15 - 6.0: Offline installers no longer provided.
        # ( https://download.qt.io/archive/qt/5.15/5.15.0/OFFLINE_README.txt )
        # XXX: We need a different approach for QT >= 5.15
        #
        case $QT_MAJOR_VERSION in

        1|2|3|4)
            echo "Qt $QT_VERSION" is too old 1>&2
            ;;

        5)
            case $QT_MINOR_VERSION in

            0|1|2|3|4|5|6|7|8)
                echo "Qt $QT_VERSION" is too old 1>&2
                ;;

            9|10|11|12|13|14)
                QT_VOLUME=qt-opensource-mac-x64-$QT_VERSION
                ;;
            *)
                echo "The Qt Company no longer provides open source offline installers for Qt $QT_VERSION" 1>&2
                ;;

            esac
            [ -f $QT_VOLUME.dmg ] || curl -L -O https://download.qt.io/archive/qt/$QT_MAJOR_MINOR_VERSION/$QT_MAJOR_MINOR_DOTDOT_VERSION/$QT_VOLUME.dmg || exit 1
            $no_build && echo "Skipping installation" && return
            sudo hdiutil attach $QT_VOLUME.dmg || exit 1

            #
            # Run the installer executable directly, so that we wait for
            # it to finish.  Then unmount the volume.
            #
            /Volumes/$QT_VOLUME/$QT_VOLUME.app/Contents/MacOS/$QT_VOLUME
            sudo hdiutil detach /Volumes/$QT_VOLUME
            touch qt-$QT_VERSION-done
            ;;
        *)
            echo "The Qt Company no longer provides open source offline installers for Qt $QT_VERSION" 1>&2
            ;;
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
            # 5.9 - 5.14: qt-opensource-mac-x64-{version}.dmg
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

                0|1|2|3|4|5)
                    echo "Qt $installed_qt_version" is too old 1>&2
                    ;;

                6|7|8)
                    installed_qt_volume=qt-opensource-mac-x64-clang-$installed_qt_version.dmg
                    ;;

                9|10|11|12|13|14)
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
        #    https://lists.freebsd.org/pipermail/freebsd-ports-bugs/2010-October/198809.html
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

install_libtasn1() {
    if [ "$LIBTASN1_VERSION" -a ! -f libtasn1-$LIBTASN1_VERSION-done ] ; then
        echo "Downloading, building, and installing libtasn1:"
        [ -f libtasn1-$LIBTASN1_VERSION.tar.gz ] || curl -L -O https://ftpmirror.gnu.org/libtasn1/libtasn1-$LIBTASN1_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat libtasn1-$LIBTASN1_VERSION.tar.gz | tar xf - || exit 1
        cd libtasn1-$LIBTASN1_VERSION
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch libtasn1-$LIBTASN1_VERSION-done
    fi
}

uninstall_libtasn1() {
    if [ ! -z "$installed_libtasn1_version" ] ; then
        #
        # p11-kit depends on this, so uninstall it.
        #
        uninstall_p11_kit "$@"

        echo "Uninstalling libtasn1:"
        cd libtasn1-$installed_libtasn1_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm libtasn1-$installed_libtasn1_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf libtasn1-$installed_libtasn1_version
            rm -rf libtasn1-$installed_libtasn1_version.tar.gz
        fi

        installed_libtasn1_version=""
    fi
}

install_p11_kit() {
    if [ "$P11KIT_VERSION" -a ! -f p11-kit-$P11KIT_VERSION-done ] ; then
        echo "Downloading, building, and installing p11-kit:"
        [ -f p11-kit-$P11KIT_VERSION.tar.xz ] || curl -L -O https://github.com/p11-glue/p11-kit/releases/download/$P11KIT_VERSION/p11-kit-$P11KIT_VERSION.tar.xz || exit 1
        $no_build && echo "Skipping installation" && return
        xzcat p11-kit-$P11KIT_VERSION.tar.xz | tar xf - || exit 1
        cd p11-kit-$P11KIT_VERSION
        #
        # Prior to Catalina, the libffi that's supplied with macOS
        # doesn't support ffi_closure_alloc() or ffi_prep_closure_loc(),
        # both of which are required by p11-kit if built with libffi.
        #
        # According to
        #
        #    https://p11-glue.github.io/p11-glue/p11-kit/manual/devel-building.html
        #
        # libffi is used "for sharing of PKCS#11 modules between
        # multiple callers in the same process. It is highly recommended
        # that this dependency be treated as a required dependency.",
        # but it's not clear that this matters to us, so we just
        # configure p11-kit not to use libffi.
        #
        CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --without-libffi --without-trust-paths || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch p11-kit-$P11KIT_VERSION-done
    fi
}

uninstall_p11_kit() {
    if [ ! -z "$installed_p11_kit_version" ] ; then
        #
        # Nettle depends on this, so uninstall it.
        #
        uninstall_nettle "$@"

        echo "Uninstalling p11-kit:"
        cd p11-kit-$installed_p11_kit_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm p11-kit-$installed_p11_kit_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf p11-kit-$installed_p11_kit_version
            rm -rf p11-kit-$installed_p11_kit_version.tar.xz
        fi

        installed_p11_kit_version=""
    fi
}

install_nettle() {
    if [ "$NETTLE_VERSION" -a ! -f nettle-$NETTLE_VERSION-done ] ; then
        echo "Downloading, building, and installing Nettle:"
        [ -f nettle-$NETTLE_VERSION.tar.gz ] || curl -L -O https://ftp.gnu.org/gnu/nettle/nettle-$NETTLE_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat nettle-$NETTLE_VERSION.tar.gz | tar xf - || exit 1
        cd nettle-$NETTLE_VERSION
        if [ "$DARWIN_PROCESSOR_ARCH" = "arm" ] ; then
            CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --disable-assembler || exit 1
        else
            CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        fi
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
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --with-included-unistring --disable-guile || exit 1
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
        [ -f lua-$LUA_VERSION.tar.gz ] || curl -L -O https://www.lua.org/ftp/lua-$LUA_VERSION.tar.gz || exit 1
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
        [ -f snappy-$SNAPPY_VERSION.tar.gz ] || curl -L -o snappy-$SNAPPY_VERSION.tar.gz https://github.com/google/snappy/archive/$SNAPPY_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat snappy-$SNAPPY_VERSION.tar.gz | tar xf - || exit 1
        cd snappy-$SNAPPY_VERSION
        mkdir build_dir
        cd build_dir
        #
        # Build a shared library, because we'll be linking libwireshark,
        # which is a C library, with libsnappy, and libsnappy is a C++
        # library and requires the C++ run time; the shared library
        # will carry that dependency with it, so linking with it should
        # Just Work.
        #
        MACOSX_DEPLOYMENT_TARGET=$min_osx_target SDKROOT="$SDKPATH" cmake -DBUILD_SHARED_LIBS=YES ../ || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ../..
        touch snappy-$SNAPPY_VERSION-done
    fi
}

uninstall_snappy() {
    if [ ! -z "$installed_snappy_version" ] ; then
        echo "Uninstalling snappy:"
        cd snappy-$installed_snappy_version
        #
        # snappy uses cmake and doesn't support "make uninstall";
        # just remove what we know it installs.
        #
        # $DO_MAKE_UNINSTALL || exit 1
        if [ -s build_dir/install_manifest.txt] ; then
            while read -r ; do $DO_RM -v "$REPLY" ; done < <(cat build_dir/install_manifest.txt; echo)
        else
            $DO_RM -f /usr/local/lib/libsnappy.1.1.8.dylib \
                    /usr/local/lib/libsnappy.1.dylib \
                    /usr/local/lib/libsnappy.dylib \
                    /usr/local/include/snappy-c.h \
                    /usr/local/include/snappy-sinksource.h \
                    /usr/local/include/snappy-stubs-public.h \
                    /usr/local/include/snappy.h \
                    /usr/local/lib/cmake/Snappy/SnappyConfig.cmake \
                    /usr/local/lib/cmake/Snappy/SnappyConfigVersion.cmake \
                    /usr/local/lib/cmake/Snappy/SnappyTargets-noconfig.cmake \
                    /usr/local/lib/cmake/Snappy/SnappyTargets.cmake || exit 1
        fi
        #
        # snappy uses cmake and doesn't support "make distclean";
        #.just remove the entire build directory.
        #
        # make distclean || exit 1
        rm -rf build_dir || exit 1
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
        #
        # zstd has no configure script, so there's no need for
        # "make distclean", and the Makefile supplied with it
        # has no "make distclean" rule; just do "make clean".
        #
        make clean || exit 1
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
        #
        # At least on macOS 12.0.1 with Xcode 13.1, when we build
        # libxml2, the linker complains that we don't have the right
        # to link with the Python framework, so don't build with
        # Python.
        #
        CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=0 $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS -D_FORTIFY_SOURCE=0 $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --without-python || exit 1
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
        # lz4's Makefile doesn't support "make distclean"; just do
        # "make clean".  Perhaps not using autotools means that
        # there's no need for "make distclean".
        #
        # make distclean || exit 1
        make clean || exit 1
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
        if [ "$DARWIN_PROCESSOR_ARCH" = "arm" ] ; then
            CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=0 $VERSION_MIN_FLAGS $SDKFLAGS -U__ARM_NEON__" CXXFLAGS="$CXXFLAGS -D_FORTIFY_SOURCE=0 $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --disable-tools --disable-tester --disable-shared || exit 1
        else
            CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=0 $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS -D_FORTIFY_SOURCE=0 $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --disable-tools --disable-tester --disable-shared || exit 1
        fi
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
        [ -f c-ares-$CARES_VERSION.tar.gz ] || curl -L -O https://c-ares.org/download/c-ares-$CARES_VERSION.tar.gz || exit 1
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
        # libssh uses cmake and doesn't support "make uninstall";
        # just remove what we know it installs.
        #
        # $DO_MAKE_UNINSTALL || exit 1
        $DO_RM -rf /usr/local/lib/libssh* \
                   /usr/local/include/libssh \
                   /usr/local/lib/pkgconfig/libssh* \
                   /usr/local/lib/cmake/libssh || exit 1
        #
        # libssh uses cmake and doesn't support "make distclean";
        # just remove the entire build directory.
        #
        # make distclean || exit 1
        rm -rf build || exit 1
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
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --enable-lib-only || exit 1
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
        [ -f tiff-$LIBTIFF_VERSION.tar.gz ] ||
            curl --fail -L -O https://download.osgeo.org/libtiff/tiff-$LIBTIFF_VERSION.tar.gz     ||
            curl --fail -L -O https://download.osgeo.org/libtiff/old/tiff-$LIBTIFF_VERSION.tar.gz ||
            exit 1
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
        [ -f speexdsp-$SPEEXDSP_VERSION.tar.gz ] || curl -L -O https://ftp.osuosl.org/pub/xiph/releases/speex/speexdsp-$SPEEXDSP_VERSION.tar.gz || exit 1
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
        [ -f bcg729-$BCG729_VERSION.tar.gz ] || curl -L -O https://download.savannah.gnu.org/releases/linphone/plugins/sources/bcg729-$BCG729_VERSION.tar.gz || exit 1
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

install_opus() {
    if [ "$OPUS_VERSION" -a ! -f opus-$OPUS_VERSION-done ] ; then
        echo "Downloading, building, and installing opus:"
        [ -f opus-$OPUS_VERSION.tar.gz ] || curl -L -O https://archive.mozilla.org/pub/opus/opus-$OPUS_VERSION.tar.gz || exit 1
        $no_build && echo "Skipping installation" && return
        gzcat opus-$OPUS_VERSION.tar.gz | tar xf - || exit 1
        cd opus-$OPUS_VERSION
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch opus-$OPUS_VERSION-done
    fi
}

uninstall_opus() {
    if [ ! -z "$installed_opus_version" ] ; then
        echo "Uninstalling opus:"
        cd opus-$installed_opus_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm opus-$installed_opus_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf opus-$installed_opus_version
            rm -rf opus-$installed_opus_version.tar.gz
        fi

        installed_opus_version=""
    fi
}

install_python3() {
    # The macos11 installer can be deployed to older versions, down to
    # 10.9 (Mavericks), but is still considered experimental so continue
    # to use the 64-bit installer (10.9) on earlier releases for now.
    local macver=x10.9
    if [[ $DARWIN_MAJOR_VERSION -gt 19 ]]; then
        # The macos11 installer is required for Arm-based Macs, which require
        # macOS 11 Big Sur. Note that the package name is "11.0" (no x) for
        # 3.9.1 but simply "11" for 3.9.2 (and later)
        if [[ $PYTHON3_VERSION = 3.9.1 ]]; then
            macver=11.0
        else
            macver=11
        fi
    fi
    if [ "$PYTHON3_VERSION" -a ! -f python3-$PYTHON3_VERSION-done ] ; then
        echo "Downloading and installing python3:"
        [ -f python-$PYTHON3_VERSION-macos$macver.pkg ] || curl -L -O https://www.python.org/ftp/python/$PYTHON3_VERSION/python-$PYTHON3_VERSION-macos$macver.pkg || exit 1
        $no_build && echo "Skipping installation" && return
        sudo installer -target / -pkg python-$PYTHON3_VERSION-macos$macver.pkg || exit 1
        touch python3-$PYTHON3_VERSION-done

        #
        # On macOS, the pip3 installed from Python packages appears to
        # install scripts /Library/Frameworks/Python.framework/Versions/M.N/bin,
        # where M.N is the major and minor version of Python (the dot-dot
        # release is irrelevant).
        #
        # Strip off any dot-dot component in $PYTHON3_VERSION.
        #
        python_version=`echo $PYTHON3_VERSION | sed 's/\([1-9][0-9]*\.[1-9][0-9]*\).*/\1/'`
        #
        # Now treat Meson as being in the directory in question.
        #
        MESON="/Library/Frameworks/Python.framework/Versions/$python_version/bin/meson"
    else
        #
        # We're using the Python 3 that's in /usr/bin, the pip3 for
        # which installs scripts in /usr/local/bin, so, when we
        # install Meson, look for it there.
        #
        MESON=/usr/local/bin/meson
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
            rm -f python-$installed_python3_version-macos11.pkg
            rm -f python-$installed_python3_version-macos11.0.pkg
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
        # brotli uses cmake on macOS and doesn't support "make uninstall";
        # just remove what we know it installs.
        #
        # $DO_MAKE_UNINSTALL || exit 1
        $DO_RM -rf /usr/local/bin/brotli \
                   /usr/local/lib/libbrotli* \
                   /usr/local/include/brotli \
                   /usr/local/lib/pkgconfig/libbrotli* || exit 1
        #
        # brotli uses cmake on macOS and doesn't support "make distclean";
        # just remove the enire build directory.
        #
        # make distclean || exit 1
        rm -rf build_dir || exit 1
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
        #
        # minizip ships both with a minimal Makefile that doesn't
        # support "make install", "make uninstall", or "make distclean",
        # and with a Makefile.am file that, if we do an autoreconf,
        # gives us a configure script, and a Makefile.in that, if we run
        # the configure script, gives us a Makefile that supports ll of
        # those targets, and that installs a pkg-config .pc file for
        # minizip.
        #
        # So that's what we do.
        #
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

        rm minizip-$installed_minizip_version-done

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
        [ -f Sparkle-$SPARKLE_VERSION.tar.xz ] || curl -L -o Sparkle-$SPARKLE_VERSION.tar.xz https://github.com/sparkle-project/Sparkle/releases/download/$SPARKLE_VERSION/Sparkle-$SPARKLE_VERSION.tar.xz || exit 1
        $no_build && echo "Skipping installation" && return
        test -d "/usr/local/Sparkle-$SPARKLE_VERSION" || sudo mkdir "/usr/local/Sparkle-$SPARKLE_VERSION"
        sudo tar -C "/usr/local/Sparkle-$SPARKLE_VERSION" -xpof Sparkle-$SPARKLE_VERSION.tar.xz
        touch sparkle-$SPARKLE_VERSION-done
    fi
}

uninstall_sparkle() {
    if [ -n "$installed_sparkle_version" ]; then
        echo "Uninstalling Sparkle:"
        sudo rm -rf "/usr/local/Sparkle-$installed_sparkle_version"
        if [ "$#" -eq 1 ] && [ "$1" = "-r" ] ; then
            rm -f "Sparkle-$installed_sparkle_version.tar.xz"
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

    if [ -n "$installed_opus_version" ] \
           && [ "$installed_opus_version" != "$OPUS_VERSION" ] ; then
        echo "Installed opus version is $installed_opus_version"
        if [ -z "$OPUS_VERSION" ] ; then
            echo "opus is not requested"
        else
            echo "Requested opus version is $OPUS_VERSION"
        fi
        uninstall_opus -r
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

    if [ ! -z "$installed_p11_kit_version" -a \
              "$installed_p11_kit_version" != "$P11KIT_VERSION" ] ; then
        echo "Installed p11-kit version is $installed_p11_kit_version"
        if [ -z "$P11KIT_VERSION" ] ; then
            echo "p11-kit is not requested"
        else
            echo "Requested p11-kit version is $P11KIT_VERSION"
        fi
        uninstall_p11_kit -r
    fi

    if [ ! -z "$installed_libtasn1_version" -a \
              "$installed_libtasn1_version" != "$LIBTASN1_VERSION" ] ; then
        echo "Installed libtasn1 version is $installed_libtasn1_version"
        if [ -z "$LIBTASN1_VERSION" ] ; then
            echo "libtasn1 is not requested"
        else
            echo "Requested libtasn1 version is $LIBTASN1_VERSION"
        fi
        uninstall_libtasn1 -r
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

    if [ ! -z "$installed_pcre_version" -a \
              "$installed_pcre_version" != "$PCRE_VERSION" ] ; then
        echo "Installed pcre version is $installed_pcre_version"
        if [ -z "$PCRE_VERSION" ] ; then
            echo "pcre is not requested"
        else
            echo "Requested pcre version is $PCRE_VERSION"
        fi
        uninstall_pcre -r
    fi

    if [ -n "$installed_pcre2_version" -a \
              "$installed_pcre2_version" != "$PCRE2_VERSION" ] ; then
        echo "Installed pcre2 version is $installed_pcre2_version"
        if [ -z "$PCRE2_VERSION" ] ; then
            echo "pcre2 is not requested"
        else
            echo "Requested pcre2 version is $PCRE2_VERSION"
        fi
        uninstall_pcre2 -r
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

    install_pcre

    install_autoconf

    install_automake

    install_libtool

    install_cmake

    install_pcre2

    #
    # Install Python 3 now; not only is it needed for the Wireshark
    # build process, it's also needed for the Meson build system,
    # which newer versions of GLib use as their build system.
    #
    install_python3

    #
    # Now install Meson.
    #
    install_meson

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

    install_libtasn1

    install_p11_kit

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

    install_opus

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

        uninstall_opus

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

        uninstall_p11_kit

        uninstall_libtasn1

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

        uninstall_meson

        uninstall_python3

        uninstall_cmake

        uninstall_libtool

        uninstall_automake

        uninstall_autoconf

        uninstall_pcre

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
# If not, do "make install", "make uninstall", "ninja install",
# "ninja uninstall", the removes for dependencies that don't support
# "make uninstall" or "ninja uninstall", the renames of [g]libtool*,
# and the writing of a libffi .pc file with sudo.
#
if [ -w /usr/local ]
then
    DO_MAKE_INSTALL="make install"
    DO_MAKE_UNINSTALL="make uninstall"
    DO_NINJA_INSTALL="ninja -C _build install"
    DO_NINJA_UNINSTALL="ninja -C _build uninstall"
    DO_TEE_TO_PC_FILE="tee"
    DO_RM="rm"
    DO_MV="mv"
else
    DO_MAKE_INSTALL="sudo make install"
    DO_MAKE_UNINSTALL="sudo make uninstall"
    DO_NINJA_INSTALL="sudo ninja -C _build install"
    DO_NINJA_UNINSTALL="sudo ninja -C _build uninstall"
    DO_TEE_TO_PC_FILE="sudo tee"
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
    installed_pcre_version=`ls pcre-*-done 2>/dev/null | sed 's/pcre-\(.*\)-done/\1/'`
    installed_pcre2_version=$(ls pcre2-*-done 2>/dev/null | sed 's/pcre2-\(.*\)-done/\1/')
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
    installed_libtasn1_version=`ls libtasn1-*-done 2>/dev/null | sed 's/libtasn1-\(.*\)-done/\1/'`
    installed_p11_kit_version=`ls p11-kit-*-done 2>/dev/null | sed 's/p11-kit-\(.*\)-done/\1/'`
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
    installed_opus_version=`ls opus-*-done 2>/dev/null | sed 's/opus-\(.*\)-done/\1/'`
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
    # Get the major and minor version of the target release.
    # We assume it'll be a while before there's a macOS 100. :-)
    #
    case "$min_osx_target" in

    [1-9][0-9].*)
        #
        # major.minor.
        #
        min_osx_target_major=`echo "$min_osx_target" | sed -n 's/\([1-9][0-9]*\)\..*/\1/p'`
        min_osx_target_minor=`echo "$min_osx_target" | sed -n 's/[1-9][0-9]*\.\(.*\)/\1/p'`
        ;;

    [1-9][0-9])
        #
        # Just a major version number was specified; make the minor
        # version 0.
        #
        min_osx_target_major="$min_osx_target"
        min_osx_target_minor=0
        ;;

    *)
        echo "macosx-setup.sh: Invalid target release $min_osx_target" 1>&2
        exit 1
        ;;
    esac

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
        # We assume it'll be a while before there's a macOS 100. :-)
        #
        sdklist=`(cd "$sdksdir"; ls -d MacOSX[1-9][0-9].[0-9]*.sdk 2>/dev/null)`

        for sdk in $sdklist
        do
            #
            # Get the major and minor version for this SDK.
            #
            sdk_major=`echo "$sdk" | sed -n 's/MacOSX\([1-9][0-9]*\)\..*\.sdk/\1/p'`
            sdk_minor=`echo "$sdk" | sed -n 's/MacOSX[1-9][0-9]*\.\(.*\)\.sdk/\1/p'`

            #
            # Is it for the deployment target or some later release?
            # Starting with major 11, the minor version no longer matters.
            #
            if test "$sdk_major" -gt "$min_osx_target_major" -o \
                \( "$sdk_major" -eq "$min_osx_target_major" -a \
                \( "$sdk_major" -ge 11 -o \
                   "$sdk_minor" -ge "$min_osx_target_minor" \) \)
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
    echo "Using the $sdk_major.$sdk_minor SDK"

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
# You need Xcode or the command-line tools installed to get the compilers (xcrun checks both).
#
 if [ ! -x /usr/bin/xcrun ]; then
    echo "Please install Xcode (app or command line) first (should be available on DVD or from the Mac App Store)."
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
    elif qmake --version >/dev/null 2>&1; then
        :
    else
        echo "Please install Xcode first (should be available on DVD or from the Mac App Store)."
        echo "The command-line build tools are not sufficient to build Qt."
        echo "Alternatively build QT according to: https://gist.github.com/shoogle/750a330c851bd1a924dfe1346b0b4a08#:~:text=MacOS%2FQt%5C%20Creator-,Go%20to%20Qt%20Creator%20%3E%20Preferences%20%3E%20Build%20%26%20Run%20%3E%20Kits,for%20both%20compilers%2C%20not%20gcc%20."
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
    echo "ninja wireshark_app_bundle logray_app_bundle # (Modify as needed)"
    echo "ninja install/strip"
else
    echo "cmake .."
    echo "make $MAKE_BUILD_OPTS wireshark_app_bundle logray_app_bundle # (Modify as needed)"
    echo "make install/strip"
fi
echo
echo "Make sure you are allowed capture access to the network devices"
echo "See: https://gitlab.com/wireshark/wireshark/-/wikis/CaptureSetup/CapturePrivileges"
echo

exit 0
