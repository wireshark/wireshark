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

set -e

shopt -s extglob

#
# Get the major version of Darwin, so we can check the major macOS
# version.
#
DARWIN_MAJOR_VERSION=$(uname -r | sed 's/\([0-9]*\).*/\1/')

#
# The minimum supported version of Qt is 5.15, so the minimum supported version
# of macOS is OS X 10.13 (High Sierra), aka Darwin 17.0.
#
if [[ $DARWIN_MAJOR_VERSION -lt 17 ]]; then
    echo "This script does not support any versions of macOS before High Sierra" 1>&2
    exit 1
fi

#
# Get the processor architecture of Darwin. Currently supported: arm, i386
#
DARWIN_PROCESSOR_ARCH=$(uname -m)

if [ "$DARWIN_PROCESSOR_ARCH" != "arm64" ] && [ "$DARWIN_PROCESSOR_ARCH" != "x86_64" ]; then
    echo "This script does not support this processor architecture" 1>&2
    exit 1
fi

#
# Versions of packages to download and install.
#

#
# CMake is required to do the build - and to build some of the
# dependencies.
#
CMAKE_VERSION=${CMAKE_VERSION-4.1.1}
CMAKE_SHA256=${CMAKE_SHA256-d228a1b6f9cf4a0ed5d2df1953cddd4f9be2de49f03de51a4bf06a7b1892d8b4}

#
# Ninja isn't required, as make is provided with Xcode, but it is
# claimed to build faster than make.
# Comment it out if you don't want it.
#
NINJA_VERSION=${NINJA_VERSION-1.12.1}
NINJA_SHA256=89a287444b5b3e98f88a945afa50ce937b8ffd1dcc59c555ad9b1baf855298c9

# pkg-config isn't required, but it makes library discovery more reliable.
PKG_CONFIG_VERSION=0.29.2

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
    PYTHON3_VERSION=3.12.1
fi


uninstall_curl() {
    if [ -n "$installed_curl_version" ] ; then
        echo "Uninstalling curl:"
        cd "curl-$installed_curl_version"
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm "curl-$installed_curl_version-done"
        installed_curl_version=""
    fi
}

uninstall_xz() {
    if [ -n "$installed_xz_version" ] ; then
        echo "Uninstalling xz:"
        cd "xz-$installed_xz_version"
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm "xz-$installed_xz_version-done"
        installed_xz_version=""
    fi
}

uninstall_lzip() {
    if [ -n "$installed_lzip_version" ] ; then
        echo "Uninstalling lzip:"
        cd "lzip-$installed_lzip_version"
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm "lzip-$installed_lzip_version-done"
        installed_lzip_version=""
    fi
}

uninstall_pcre() {
    if [ -n "$installed_pcre_version" ] ; then
        echo "Uninstalling leftover pcre:"
        cd "pcre-$installed_pcre_version"
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm "pcre-$installed_pcre_version-done"
        installed_pcre_version=""
    fi
}


uninstall_pcre2() {
    if [ -n "$installed_pcre2_version" ] && [ -s "pcre2-$installed_pcre2_version/build_dir/install_manifest.txt" ] ; then
        echo "Uninstalling pcre2:"
        # PCRE2 10.39 installs pcre2unicode.3 twice, so this will return an error.
        while read -r ; do $DO_RM -f -v "$REPLY" ; done < <(cat "pcre2-$installed_pcre2_version/build_dir/install_manifest.txt"; echo)
        rm "pcre2-$installed_pcre2_version-done"
        installed_pcre2_version=""
    fi
}

uninstall_m4() {
    if [ -n "$installed_m4_version" ] ; then
        #
        # autoconf depends on this, so uninstall it.
        #
        uninstall_autoconf

        echo "Uninstalling GNU m4:"
        cd m4-$installed_m4_version
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm m4-$installed_m4_version-done
        installed_m4_version=""
    fi
}

uninstall_autoconf() {
    if [ -n "$installed_autoconf_version" ] ; then
        #
        # automake and libtool depend on this, so uninstall them.
        #
        uninstall_libtool
        uninstall_automake

        echo "Uninstalling GNU autoconf:"
        cd autoconf-$installed_autoconf_version
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm autoconf-$installed_autoconf_version-done
        installed_autoconf_version=""
    fi
}

uninstall_automake() {
    if [ -n "$installed_automake_version" ] ; then
        #
        # libtool depends on this(?), so uninstall it.
        #
        uninstall_libtool

        echo "Uninstalling GNU automake:"
        cd automake-$installed_automake_version
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm automake-$installed_automake_version-done
        installed_automake_version=""
    fi
}

uninstall_libtool() {
    if [ -n "$installed_libtool_version" ] ; then
        echo "Uninstalling GNU libtool:"
        cd libtool-$installed_libtool_version
        $DO_MV "$installation_prefix/bin/glibtool" "$installation_prefix/bin/libtool"
        $DO_MV "$installation_prefix/bin/glibtoolize" "$installation_prefix/bin/libtoolize"
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm libtool-$installed_libtool_version-done
        installed_libtool_version=""
    fi
}

install_ninja() {
    if [ "$NINJA_VERSION" ] && [ ! -f "ninja-$NINJA_VERSION-done" ] ; then
        echo "Downloading and installing Ninja:"
        #
        # Download the zipball, unpack it, and move the binary to
        # $installation_prefix/bin.
        #
        [ -f "ninja-mac-v$NINJA_VERSION.zip" ] || curl "${CURL_LOCAL_NAME_OPTS[@]}" "ninja-mac-v$NINJA_VERSION.zip" https://github.com/ninja-build/ninja/releases/download/v$NINJA_VERSION/ninja-mac.zip
        echo "$NINJA_SHA256  ninja-mac-v$NINJA_VERSION.zip" | shasum --algorithm 256 --check
        $no_build && echo "Skipping installation" && return
        unzip "ninja-mac-v$NINJA_VERSION.zip"
        sudo mv ninja "$installation_prefix/bin"
        touch "ninja-$NINJA_VERSION-done"
    fi
}

uninstall_ninja() {
    if [ -n "$installed_ninja_version" ]; then
        echo "Uninstalling Ninja:"
        $DO_RM "$installation_prefix/bin/ninja"
        rm "ninja-$installed_ninja_version-done"
        if [ "$#" -eq 1 ] && [ "$1" = "-r" ] ; then
            rm -f "ninja-mac-v$installed_ninja_version.zip"
        fi

        installed_ninja_version=""
    fi
}

uninstall_asciidoctor() {
    if [ -n "$installed_asciidoctor_version" ]; then
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

uninstall_asciidoctorpdf() {
    if [ -n "$installed_asciidoctorpdf_version" ]; then
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
        $no_build && echo "Skipping installation" && return
        CMAKE_MAJOR_VERSION="$( expr "$CMAKE_VERSION" : '\([0-9][0-9]*\).*' )"
        CMAKE_MINOR_VERSION="$( expr "$CMAKE_VERSION" : '[0-9][0-9]*\.\([0-9][0-9]*\).*' )"
        CMAKE_MAJOR_MINOR_VERSION=$CMAKE_MAJOR_VERSION.$CMAKE_MINOR_VERSION

        #
        # NOTE: the "64" in "Darwin64" doesn't mean "64-bit-only"; the
        # package in question supports both 32-bit and 64-bit x86.
        #
        case "$CMAKE_MAJOR_VERSION" in

        0|1|2|3)
            echo "CMake $CMAKE_VERSION" is too old 1>&2
            ;;

        4)
            #
            # Download the DMG and do a drag install, where "drag" means
            # "mv".
            #
            [ -f cmake-$CMAKE_VERSION-macos-universal.dmg ] || curl "${CURL_REMOTE_NAME_OPTS[@]}" https://cmake.org/files/v$CMAKE_MAJOR_MINOR_VERSION/cmake-$CMAKE_VERSION-macos-universal.dmg
            echo "$CMAKE_SHA256  cmake-$CMAKE_VERSION-macos-universal.dmg" | shasum --algorithm 256 --check
            $no_build && echo "Skipping installation" && return
            sudo hdiutil attach cmake-$CMAKE_VERSION-macos-universal.dmg
            sudo ditto /Volumes/cmake-$CMAKE_VERSION-macos-universal/CMake.app /Applications/CMake.app

            #
            # Plant the appropriate symbolic links in $installation_prefix/bin.
            # It's a drag-install, so there's no installer to make them,
            # and the CMake code to put them in place is lame, as
            #
            #    1) it defaults to /usr/bin, not $installation_prefix/bin;
            #    2) it doesn't request the necessary root privileges;
            #    3) it can't be run from the command line;
            #
            # so we do it ourselves.
            #
            for i in ccmake cmake cmake-gui cmakexbuild cpack ctest
            do
                sudo ln -s /Applications/CMake.app/Contents/bin/$i "$installation_prefix/bin/$i"
            done
            sudo hdiutil detach /Volumes/cmake-$CMAKE_VERSION-macos-universal
            ;;

        *)
            ;;
        esac
        touch cmake-$CMAKE_VERSION-done
    fi
}

uninstall_cmake() {
    if [ -n "$installed_cmake_version" ]; then
        echo "Uninstalling CMake:"
        installed_cmake_major_version="$( expr "$installed_cmake_version" : '\([0-9][0-9]*\).*' )"
        case "$installed_cmake_major_version" in

        0|1|2)
            echo "CMake $installed_cmake_version" is too old 1>&2
            ;;

        3)
            sudo rm -rf /Applications/CMake.app
            for i in ccmake cmake cmake-gui cmakexbuild cpack ctest
            do
                sudo rm -f "$installation_prefix/bin/$i"
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

uninstall_meson() {
    #
    # If we installed Meson, uninstal it with pip3.
    #
    if [ -f meson-done ] ; then
        sudo pip3 uninstall meson
        rm -f meson-done
    fi
}

install_pytest() {
    #
    # Install pytest with pip3 if we don't have it already.
    #
    if python3 -m pytest --version &> /dev/null || pytest --version &> /dev/null
    then
        # We have it.
        :
    else
        sudo pip3 install pytest pytest-xdist
        touch pytest-done
    fi
}

uninstall_pytest() {
    #
    # If we installed pytest, uninstal it with pip3.
    #
    if [ -f pytest-done ] ; then
        sudo pip3 uninstall pytest pytest-xdist
        rm -f pytest-done
    fi
}

uninstall_gettext() {
    if [ -n "$installed_gettext_version" ] ; then
        #
        # GLib depends on this, so uninstall it.
        #
        uninstall_glib

        echo "Uninstalling GNU gettext:"
        cd gettext-$installed_gettext_version
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm gettext-$installed_gettext_version-done
        installed_gettext_version=""
    fi
}

install_pkg_config() {
    if [ ! -f pkg-config-$PKG_CONFIG_VERSION-done ] ; then
        echo "Downloading, building, and installing pkg-config:"
        [ -f pkg-config-$PKG_CONFIG_VERSION.tar.gz ] || curl "${CURL_REMOTE_NAME_OPTS[@]}" https://pkgconfig.freedesktop.org/releases/pkg-config-$PKG_CONFIG_VERSION.tar.gz
        $no_build && echo "Skipping installation" && return
        gzcat pkg-config-$PKG_CONFIG_VERSION.tar.gz | tar xf -
        cd pkg-config-$PKG_CONFIG_VERSION
        CFLAGS="$CFLAGS -Wno-int-conversion" ./configure "${CONFIGURE_OPTS[@]}" --with-internal-glib
        make "${MAKE_BUILD_OPTS[@]}"
        $DO_MAKE_INSTALL
        cd ..
        touch pkg-config-$PKG_CONFIG_VERSION-done
    fi
}

uninstall_pkg_config() {
    if [ -n "$installed_pkg_config_version" ] ; then
        echo "Uninstalling pkg-config:"
        cd pkg-config-$installed_pkg_config_version
        $DO_MAKE_UNINSTALL
        make distclean
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

uninstall_glib() {
    if [ -n "$installed_glib_version" ] ; then
        echo "Uninstalling GLib:"
        cd "glib-$installed_glib_version"
        installed_glib_major_version="$( expr "$installed_glib_version" : '\([0-9][0-9]*\).*' )"
        installed_glib_minor_version="$( expr "$installed_glib_version" : '[0-9][0-9]*\.\([0-9][0-9]*\).*' )"
        # installed_glib_dotdot_version="$( expr $installed_glib_version : '[0-9][0-9]*\.[0-9][0-9]*\.\([0-9][0-9]*\).*' )"
        # installed_glib_major_minor_version=$installed_glib_major_version.$installed_glib_minor_version
        # installed_glib_major_minor_dotdot_version=$installed_glib_major_version.$installed_glib_minor_version.$installed_glib_dotdot_version
        #
        # GLib 2.59.1 and later use Meson+Ninja as the build system.
        #
        case $installed_glib_major_version in

        1)
            $DO_MAKE_UNINSTALL
            #
            # This appears to delete dependencies out from under other
            # Makefiles in the tree, causing it to fail.  At least until
            # that gets fixed, if it ever gets fixed, we just ignore the
            # exit status of "make distclean"
            #
            # make distclean
            make distclean || echo "Ignoring make distclean failure" 1>&2
            ;;

        *)
            case $installed_glib_minor_version in

            [0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-8])
                $DO_MAKE_UNINSTALL
                #
                # This appears to delete dependencies out from under other
                # Makefiles in the tree, causing it to fail.  At least until
                # that gets fixed, if it ever gets fixed, we just ignore the
                # exit status of "make distclean"
                #
                # make distclean
                make distclean || echo "Ignoring make distclean failure" 1>&2
                ;;

            59|[6-9][0-9]|[1-9][0-9][0-9])
                #
                # 2.59.0 doesn't require Meson and Ninja, but it
                # supports it, and I'm too lazy to add a dot-dot
                # version check.
                #
                $DO_NINJA_UNINSTALL
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
        installed_glib_version=""
    fi
}

uninstall_qt() {
    if [ -n "$installed_qt_version" ] ; then
        echo "Uninstalling Qt:"
        rm -rf $HOME/Qt$installed_qt_version
        rm qt-$installed_qt_version-done
        installed_qt_version=""
    fi
}

uninstall_libsmi() {
    if [ -n "$installed_libsmi_version" ] ; then
        echo "Uninstalling libsmi:"
        cd libsmi-$installed_libsmi_version
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm libsmi-$installed_libsmi_version-done
        installed_libsmi_version=""
    fi
}

uninstall_libgpg_error() {
    if [ -n "$installed_libgpg_error_version" ] ; then
        #
        # libgcrypt depends on this, so uninstall it.
        #
        uninstall_libgcrypt

        echo "Uninstalling libgpg-error:"
        cd libgpg-error-$installed_libgpg_error_version
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm libgpg-error-$installed_libgpg_error_version-done
        installed_libgpg_error_version=""
    fi
}

uninstall_libgcrypt() {
    if [ -n "$installed_libgcrypt_version" ] ; then
        echo "Uninstalling libgcrypt:"
        cd libgcrypt-$installed_libgcrypt_version
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm libgcrypt-$installed_libgcrypt_version-done
        installed_libgcrypt_version=""
    fi
}

uninstall_gmp() {
    if [ -n "$installed_gmp_version" ] ; then
        #
        # Nettle depends on this, so uninstall it.
        #
        uninstall_nettle "$@"

        echo "Uninstalling GMP:"
        cd "gmp-$installed_gmp_version"
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm "gmp-$installed_gmp_version-done"
        installed_gmp_version=""
    fi
}

uninstall_libtasn1() {
    if [ -n "$installed_libtasn1_version" ] ; then
        #
        # p11-kit depends on this, so uninstall it.
        #
        uninstall_p11_kit "$@"

        echo "Uninstalling libtasn1:"
        cd "libtasn1-$installed_libtasn1_version"
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm "libtasn1-$installed_libtasn1_version-done"
        installed_libtasn1_version=""
    fi
}

uninstall_p11_kit() {
    if [ -n "$installed_p11_kit_version" ] ; then
        #
        # Nettle depends on this, so uninstall it.
        #
        uninstall_nettle "$@"

        echo "Uninstalling p11-kit:"
        cd "p11-kit-$installed_p11_kit_version"
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm "p11-kit-$installed_p11_kit_version-done"

        if [ "$#" -eq 1 ] && [ "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf "p11-kit-$installed_p11_kit_version"
            rm -rf "p11-kit-$installed_p11_kit_version.tar.xz"
        fi

        installed_p11_kit_version=""
    fi
}

uninstall_nettle() {
    if [ -n "$installed_nettle_version" ] ; then
        #
        # GnuTLS depends on this, so uninstall it.
        #
        uninstall_gnutls "$@"

        echo "Uninstalling Nettle:"
        cd "nettle-$installed_nettle_version"
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm "nettle-$installed_nettle_version-done"

        if [ "$#" -eq 1 ] && [ "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf "nettle-$installed_nettle_version"
            rm -rf "nettle-$installed_nettle_version.tar.gz"
        fi

        installed_nettle_version=""
    fi
}

uninstall_gnutls() {
    if [ -n "$installed_gnutls_version" ] ; then
        echo "Uninstalling GnuTLS:"
        cd "gnutls-$installed_gnutls_version"
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm "gnutls-$installed_gnutls_version-done" s

        if [ "$#" -eq 1 ] && [ "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf "gnutls-$installed_gnutls_version"
            rm -rf "gnutls-$installed_gnutls_version.tar.bz2"
        fi

        installed_gnutls_version=""
    fi
}

uninstall_lua() {
    if [ -n "$installed_lua_version" ] ; then
        echo "Uninstalling Lua:"
        #
        # Lua has no "make uninstall", so just remove stuff manually.
        # There's no configure script, so there's no need for
        # "make distclean", either; just do "make clean".
        #
        (cd "$installation_prefix/bin"; $DO_RM -f lua luac)
        (cd "$installation_prefix/include"; $DO_RM -f lua.h luaconf.h lualib.h lauxlib.h lua.hpp)
        (cd "$installation_prefix/lib"; $DO_RM -f liblua.a)
        (cd "$installation_prefix/man/man1"; $DO_RM -f lua.1 luac.1)
        cd lua-$installed_lua_version
        make clean
        cd ..
        rm lua-$installed_lua_version-done
        installed_lua_version=""
    fi
}

uninstall_snappy() {
    if [ -n "$installed_snappy_version" ] ; then
        echo "Uninstalling snappy:"
        cd snappy-$installed_snappy_version
        #
        # snappy uses cmake and doesn't support "make uninstall";
        # just remove what we know it installs.
        #
        # $DO_MAKE_UNINSTALL
        if [ -s build_dir/install_manifest.txt ] ; then
            while read -r ; do $DO_RM -v "$REPLY" ; done < <(cat build_dir/install_manifest.txt; echo)
        else
            $DO_RM -f "$installation_prefix/lib/libsnappy.1.1.8.dylib" \
                    "$installation_prefix/lib/libsnappy.1.dylib" \
                    "$installation_prefix/lib/libsnappy.dylib" \
                    "$installation_prefix/include/snappy-c.h" \
                    "$installation_prefix/include/snappy-sinksource.h" \
                    "$installation_prefix/include/snappy-stubs-public.h" \
                    "$installation_prefix/include/snappy.h" \
                    "$installation_prefix/lib/cmake/Snappy/SnappyConfig.cmake" \
                    "$installation_prefix/lib/cmake/Snappy/SnappyConfigVersion.cmake" \
                    "$installation_prefix/lib/cmake/Snappy/SnappyTargets-noconfig.cmake" \
                    "$installation_prefix/lib/cmake/Snappy/SnappyTargets.cmake"
        fi
        #
        # snappy uses cmake and doesn't support "make distclean";
        #.just remove the entire build directory.
        #
        # make distclean
        rm -rf build_dir
        cd ..
        rm snappy-$installed_snappy_version-done
        installed_snappy_version=""
    fi
}

uninstall_zstd() {
    if [ -n "$installed_zstd_version" ] ; then
        echo "Uninstalling zstd:"
        cd "zstd-$installed_zstd_version"
        $DO_MAKE_UNINSTALL
        #
        # zstd has no configure script, so there's no need for
        # "make distclean", and the Makefile supplied with it
        # has no "make distclean" rule; just do "make clean".
        #
        make clean
        cd ..
        rm "zstd-$installed_zstd_version-done"
        installed_zstd_version=""
    fi
}

uninstall_zlibng() {
    if [ -n "$installed_zstd_version" ] ; then
        echo "Uninstalling zlibng:"
        cd "zlib-ng-$installed_zlibng_version"
        $DO_MAKE_UNINSTALL
        #
        # XXX not sure what to do here...
        #
        make clean
        cd ..
        rm "zlib-ng-$installed_zlibng_version-done"
        installed_zlibng_version=""
    fi
}

uninstall_libxml2() {
    if [ -n "$installed_libxml2_version" ] ; then
        echo "Uninstalling libxml2:"
        cd "libxml2-$installed_libxml2_version"
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm "libxml2-$installed_libxml2_version-done"
        installed_libxml2_version=""
    fi
}

uninstall_lz4() {
    if [ -n "$installed_lz4_version" ] ; then
        echo "Uninstalling lz4:"
        cd "lz4-$installed_lz4_version"
        $DO_MAKE_UNINSTALL
        #
        # lz4's Makefile doesn't support "make distclean"; just do
        # "make clean".  Perhaps not using autotools means that
        # there's no need for "make distclean".
        #
        # make distclean
        make clean
        cd ..
        rm "lz4-$installed_lz4_version-done"
        installed_lz4_version=""
    fi
}

uninstall_sbc() {
    if [ -n "$installed_sbc_version" ] ; then
        echo "Uninstalling sbc:"
        cd sbc-$installed_sbc_version
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm sbc-$installed_sbc_version-done
        installed_sbc_version=""
    fi
}

uninstall_maxminddb() {
    if [ -n "$installed_maxminddb_version" ] ; then
        echo "Uninstalling MaxMindDB API:"
        cd libmaxminddb-$installed_maxminddb_version
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm maxminddb-$installed_maxminddb_version-done
        installed_maxminddb_version=""
    fi
}

uninstall_c_ares() {
    if [ -n "$installed_cares_version" ] ; then
        echo "Uninstalling C-Ares API:"
        cd c-ares-$installed_cares_version
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm c-ares-$installed_cares_version-done
        installed_cares_version=""
    fi
}

uninstall_libssh() {
    if [ -n "$installed_libssh_version" ] ; then
        echo "Uninstalling libssh:"
        cd libssh-$installed_libssh_version
        #
        # libssh uses cmake and doesn't support "make uninstall";
        # just remove what we know it installs.
        #
        # $DO_MAKE_UNINSTALL
        $DO_RM -rf "$installation_prefix"/lib/libssh* \
                   "$installation_prefix"/include/libssh \
                   "$installation_prefix"/lib/pkgconfig/libssh* \
                   "$installation_prefix"/lib/cmake/libssh
        #
        # libssh uses cmake and doesn't support "make distclean";
        # just remove the entire build directory.
        #
        # make distclean
        rm -rf build
        cd ..
        rm libssh-$installed_libssh_version-done
        installed_libssh_version=""
    fi
}

uninstall_nghttp2() {
    if [ -n "$installed_nghttp2_version" ] ; then
        echo "Uninstalling nghttp2:"
        cd nghttp2-$installed_nghttp2_version
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm nghttp2-$installed_nghttp2_version-done
        installed_nghttp2_version=""
    fi
}

uninstall_nghttp3() {
    if [ -n "$installed_nghttp3_version" ] ; then
        echo "Uninstalling nghttp3:"
        cd nghttp3-$installed_nghttp3_version
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm nghttp3-$installed_nghttp3_version-done
        installed_nghttp3_version=""
    fi
}

uninstall_libtiff() {
    if [ -n "$installed_libtiff_version" ] ; then
        echo "Uninstalling libtiff:"
        cd tiff-$installed_libtiff_version
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm tiff-$installed_libtiff_version-done
        installed_libtiff_version=""
    fi
}

uninstall_spandsp() {
    if [ -n "$installed_spandsp_version" ] ; then
        echo "Uninstalling SpanDSP:"
        cd spandsp-$installed_spandsp_version
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm spandsp-$installed_spandsp_version-done
        installed_spandsp_version=""
    fi
}

uninstall_speexdsp() {
    if [ -n "$installed_speexdsp_version" ] ; then
        echo "Uninstalling SpeexDSP:"
        cd speexdsp-$installed_speexdsp_version
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm speexdsp-$installed_speexdsp_version-done
        installed_speexdsp_version=""
    fi
}

uninstall_bcg729() {
    if [ -n "$installed_bcg729_version" ] ; then
        echo "Uninstalling bcg729:"
        cd bcg729-$installed_bcg729_version
        #
        # bcg729 uses cmake on macOS and doesn't support "make uninstall";
        # just remove what we know it installs.
        #
        # $DO_MAKE_UNINSTALL
        $DO_RM -rf "$installation_prefix"/share/Bcg729 \
                   "$installation_prefix"/lib/libbcg729* \
                   "$installation_prefix"/include/bcg729 \
                   "$installation_prefix"/lib/pkgconfig/libbcg729*
        #
        # bcg729 uses cmake on macOS and doesn't support "make distclean";
        # just remove the enire build directory.
        #
        # make distclean
        rm -rf build_dir
        cd ..
        rm bcg729-$installed_bcg729_version-done
        installed_bcg729_version=""
    fi
}

uninstall_ilbc() {
    if [ -n "$installed_ilbc_version" ] ; then
        echo "Uninstalling iLBC:"
        cd "libilbc-$installed_ilbc_version"
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm "ilbc-$installed_ilbc_version-done"
        installed_ilbc_version=""
    fi
}

uninstall_opencore_amr() {
    if [ -n "$installed_opencore_amr_version" ] ; then
        echo "Uninstalling opencore-amr:"
        cd "opencore-amr-$installed_opencore_amr_version"
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm "opencore-amr-$installed_opencore_amr_version-done"
        installed_opencore_amr_version=""
    fi
}

uninstall_opus() {
    if [ -n "$installed_opus_version" ] ; then
        echo "Uninstalling opus:"
        cd opus-$installed_opus_version
        $DO_MAKE_UNINSTALL
        make distclean
        cd ..
        rm opus-$installed_opus_version-done
        installed_opus_version=""
    fi
}

uninstall_jsoncpp() {
    if [ "$installed_jsoncpp_version" ] && [ -s "jsoncpp-$installed_jsoncpp_version/build_dir/install_manifest.txt" ] ; then
        echo "Uninstalling JsonCpp:"
        while read -r ; do $DO_RM -v "$REPLY" ; done < <(cat "jsoncpp-$installed_jsoncpp_version/build_dir/install_manifest.txt"; echo)
        rm "jsoncpp-$JSONCPP_VERSION-done"
        installed_jsoncpp_version=""
    fi
}

uninstall_onetbb() {
    if [ "$installed_onetbb_version" ] && [ -s "oneTBB-$installed_onetbb_version/build_dir/install_manifest.txt" ] ; then
        echo "Uninstalling oneTBB:"
        while read -r ; do $DO_RM -v "$REPLY" ; done < <(cat "oneTBB-$installed_onetbb_version/build_dir/install_manifest.txt"; echo)
        rm "onetbb-$installed_onetbb_version-done"
        installed_onetbb_version=""
    fi
}

uninstall_re2() {
    if [ -n "$installed_re2_version" ] && [ -s "re2-$installed_re2_version/build_dir/install_manifest.txt" ] ; then
        echo "Uninstalling RE2:"
        while read -r ; do $DO_RM -v "$REPLY" ; done < <(cat "re2-$installed_re2_version/build_dir/install_manifest.txt"; echo)
        rm "re2-$installed_re2_version-done"
        installed_re2_version=""
    fi
}

uninstall_falco_libs() {
    if [ -n "$installed_falco_libs_version" ] && [ -s "falco-libs-$installed_falco_libs_version/build_dir/install_manifest.txt" ] ; then
        echo "Uninstalling Falco libs:"
        $DO_RM "$installation_prefix"/include/falcosecurity/uthash.h
        while read -r ; do $DO_RM -v "$REPLY" ; done < <(cat "falco-libs-$installed_falco_libs_version/build_dir/install_manifest.txt"; echo)
        rm "falco-libs-$installed_falco_libs_version-done"
        installed_falco_libs_version=""
    fi
}

install_python3() {
    # The macos11 universal2 installer can be deployed to older versions,
    # down to 10.9 (Mavericks). The 10.9 installer was deprecated in 3.9.8
    # and stopped being released after 3.9.13
    local macver=11
    if [ "$PYTHON3_VERSION" -a ! -f python3-$PYTHON3_VERSION-done ] ; then
        echo "Downloading and installing python3:"
        [ -f python-$PYTHON3_VERSION-macos$macver.pkg ] || curl "${CURL_REMOTE_NAME_OPTS[@]}" https://www.python.org/ftp/python/$PYTHON3_VERSION/python-$PYTHON3_VERSION-macos$macver.pkg
        $no_build && echo "Skipping installation" && return
        sudo installer -target / -pkg python-$PYTHON3_VERSION-macos$macver.pkg
        touch python3-$PYTHON3_VERSION-done

        #
        # On macOS, the pip3 installed from Python packages appears to
        # install scripts /Library/Frameworks/Python.framework/Versions/M.N/bin,
        # where M.N is the major and minor version of Python (the dot-dot
        # release is irrelevant).
        #
        # Strip off any dot-dot component in $PYTHON3_VERSION.
        #
        python_version=$( echo "$PYTHON3_VERSION" | sed 's/\([1-9][0-9]*\.[1-9][0-9]*\).*/\1/' )
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
    if [ -n "$installed_python3_version" ] ; then
        echo "Uninstalling python3:"
        frameworkdir="/Library/Frameworks/Python.framework/Versions/$PYTHON_VERSION"
        sudo rm -rf "$frameworkdir"
        sudo rm -rf "/Applications/Python $PYTHON_VERSION"
        sudo find "$installation_prefix"/bin -maxdepth 1 -lname "*$frameworkdir/bin/*" -delete
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

uninstall_brotli() {
    if [ -n "$installed_brotli_version" ] ; then
        echo "Uninstalling brotli:"
        cd brotli-$installed_brotli_version
        #
        # brotli uses cmake on macOS and doesn't support "make uninstall";
        # just remove what we know it installs.
        #
        # $DO_MAKE_UNINSTALL
        $DO_RM -rf "$installation_prefix"/bin/brotli \
                   "$installation_prefix"/lib/libbrotli* \
                   "$installation_prefix"/include/brotli \
                   "$installation_prefix"/lib/pkgconfig/libbrotli*
        #
        # brotli uses cmake on macOS and doesn't support "make distclean";
        # just remove the enire build directory.
        #
        # make distclean
        rm -rf build_dir
        cd ..
        rm brotli-$installed_brotli_version-done
        installed_brotli_version=""
    fi
}

uninstall_minizip() {
    if [ -n "$installed_minizip_version" ] ; then
        echo "Uninstalling minizip:"
        cd zlib-$installed_minizip_version/contrib/minizip
        $DO_MAKE_UNINSTALL
        make distclean
        cd ../../..

        rm minizip-$installed_minizip_version-done
        installed_minizip_version=""
    fi
}

uninstall_minizip_ng() {
    if [ -n "$installed_minizip_ng_version" ] ; then
        echo "Uninstalling minizip-ng:"
        cd minizip-ng-$installed_minizip_ng_version
        #
        # minizip-ng uses cmake and doesn't support "make uninstall";
        # just remove what we know it installs.
        #
        # $DO_MAKE_UNINSTALL
        $DO_RM -rf "$installation_prefix"/lib/libminizip-ng* \
                   "$installation_prefix"/lib/cmake/minizip-ng \
                   "$installation_prefix"/lib/pkgconfig/minizip-ng* \
                   "$installation_prefix"/include/minizip-ng
        #
        # minizip-ng uses cmake on macOS and doesn't support "make distclean";
        # just remove the enire build directory.
        #
        # make distclean
        rm -rf build_dir
        cd ..

        rm minizip-ng-$installed_minizip_ng_version-done
        installed_minizip_ng_version=""
    fi
}

uninstall_sparkle() {
    if [ -n "$installed_sparkle_version" ]; then
        echo "Uninstalling Sparkle:"
        sudo rm -rf "$installation_prefix/Sparkle-$installed_sparkle_version"

        rm sparkle-$installed_sparkle_version-done
        installed_sparkle_version=""
    fi
}

install_all() {
    #
    # Check whether the versions we have installed are the versions
    # requested; if not, uninstall the installed versions.
    #

    cat <<FIN
==============================================================================
= This script only installs the tools required to build Wireshark. It no     =
= longer installs any development libraries. Set WIRESHARK_BASE_DIR instead: =
= https://www.wireshark.org/docs/wsdg_html_chunked/ChapterSetup.html#_macos  =
==============================================================================
FIN

    if [ -n "$installed_python3_version" -a \
              "$installed_python3_version" != "$PYTHON3_VERSION" ] ; then
        echo "Installed python3 version is $installed_python3_version"
        if [ -z "$PYTHON3_VERSION" ] ; then
            echo "python3 is not requested"
        else
            echo "Requested python3 version is $PYTHON3_VERSION"
        fi
        uninstall_python3 -r
    fi

    if [ -n "$installed_pkg_config_version" -a \
              "$installed_pkg_config_version" != "$PKG_CONFIG_VERSION" ] ; then
        echo "Installed pkg-config version is $installed_pkg_config_version"
        if [ -z "$PKG_CONFIG_VERSION" ] ; then
            echo "pkg-config is not requested"
        else
            echo "Requested pkg-config version is $PKG_CONFIG_VERSION"
        fi
        uninstall_pkg_config -r
    fi

    if [ -n "$installed_ninja_version" -a \
              "$installed_ninja_version" != "$NINJA_VERSION" ] ; then
        echo "Installed Ninja version is $installed_ninja_version"
        if [ -z "$NINJA_VERSION" ] ; then
            echo "Ninja is not requested"
        else
            echo "Requested Ninja version is $NINJA_VERSION"
        fi
        uninstall_ninja -r
    fi

    if [ -n "$installed_cmake_version" -a \
              "$installed_cmake_version" != "$CMAKE_VERSION" ] ; then
        echo "Installed CMake version is $installed_cmake_version"
        if [ -z "$CMAKE_VERSION" ] ; then
            echo "CMake is not requested"
        else
            echo "Requested CMake version is $CMAKE_VERSION"
        fi
        uninstall_cmake -r
    fi


    install_cmake

    install_python3

    install_pytest

    install_ninja

    install_pkg_config
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
        uninstall_falco_libs

        uninstall_jsoncpp

        uninstall_onetbb

        uninstall_re2

        uninstall_sparkle

        uninstall_minizip

        uninstall_minizip_ng

        uninstall_brotli

        uninstall_opus

        uninstall_opencore_amr

        uninstall_ilbc

        uninstall_bcg729

        uninstall_speexdsp

        uninstall_spandsp

        uninstall_libtiff

        uninstall_nghttp2

        uninstall_nghttp3

        uninstall_libssh

        uninstall_c_ares

        uninstall_maxminddb

        uninstall_snappy

        uninstall_zstd

        uninstall_zlibng

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

        uninstall_libxml2

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

        uninstall_pytest

        uninstall_meson

        uninstall_python3

        uninstall_cmake

        uninstall_libtool

        uninstall_automake

        uninstall_autoconf

        uninstall_m4

        uninstall_pcre

        uninstall_pcre2

        # Legacy, remove
        uninstall_lzip

        uninstall_xz

        uninstall_curl
    fi
}

# This script is meant to be run in the source root.  The following
# code will attempt to get you there, but is not perfect (particularly
# if someone copies the script).

topdir="$( pwd )/$( dirname "$0" )/.."
cd "$topdir"

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
# Parse command-line flags:
#
# -h - print help.
# version of macOS and later versions.
# -u - do an uninstall.
# -n - download all packages, but don't build or install.
#

no_build=false

installation_prefix=/usr/local

while getopts hnp:u name
do
    case $name in
    h|\?)
        echo "Usage: macos-setup.sh [ -n ] [ -p <installation prefix> ] [ -u ]" 1>&1
        exit 0
        ;;
    n)
        no_build=true
        ;;
    p)
        installation_prefix="$OPTARG"
        ;;
    u)
        do_uninstall=yes
        ;;
    esac
done

#
# Create our custom installation prefix if needed.
#
if [ "$installation_prefix" != "/usr/local" ] ; then
    export PATH="$installation_prefix/bin:$PATH"
    if [ ! -d "$installation_prefix" ] ; then
        echo "Creating $installation_prefix"
        $DO_MKDIR "$installation_prefix"
    fi
fi

#
# Do we have permission to write in $installation_prefix?
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
if [ -w "$installation_prefix" ]
then
    DO_MAKE_INSTALL="make install"
    DO_MAKE_UNINSTALL="make uninstall"
    DO_NINJA_UNINSTALL="ninja -C _build uninstall"
    DO_RM="rm"
    DO_MV="mv"
else
    DO_MAKE_INSTALL="sudo make install"
    DO_MAKE_UNINSTALL="sudo make uninstall"
    DO_NINJA_UNINSTALL="sudo ninja -C _build uninstall"
    DO_RM="sudo rm"
    DO_MV="sudo mv"
fi

#
# Get the version numbers of installed packages, if any.
#
if [ -d "${MACOSX_SUPPORT_LIBS}" ]
then
    cd "${MACOSX_SUPPORT_LIBS}"

    installed_xz_version=$( ls xz-*-done 2>/dev/null | sed 's/xz-\(.*\)-done/\1/' )
    installed_lzip_version=$( ls lzip-*-done 2>/dev/null | sed 's/lzip-\(.*\)-done/\1/' )
    installed_pcre_version=$( ls pcre-*-done 2>/dev/null | sed 's/pcre-\(.*\)-done/\1/' )
    installed_pcre2_version=$( ls pcre2-*-done 2>/dev/null | sed 's/pcre2-\(.*\)-done/\1/' )
    installed_autoconf_version=$( ls autoconf-*-done 2>/dev/null | sed 's/autoconf-\(.*\)-done/\1/' )
    installed_automake_version=$( ls automake-*-done 2>/dev/null | sed 's/automake-\(.*\)-done/\1/' )
    installed_libtool_version=$( ls libtool-*-done 2>/dev/null | sed 's/libtool-\(.*\)-done/\1/' )
    installed_cmake_version=$( ls cmake-*-done 2>/dev/null | sed 's/cmake-\(.*\)-done/\1/' )
    installed_ninja_version=$( ls ninja-*-done 2>/dev/null | sed 's/ninja-\(.*\)-done/\1/' )
    installed_asciidoctor_version=$( ls asciidoctor-*-done 2>/dev/null | sed 's/asciidoctor-\(.*\)-done/\1/' )
    installed_asciidoctorpdf_version=$( ls asciidoctorpdf-*-done 2>/dev/null | sed 's/asciidoctorpdf-\(.*\)-done/\1/' )
    installed_gettext_version=$( ls gettext-*-done 2>/dev/null | sed 's/gettext-\(.*\)-done/\1/' )
    installed_pkg_config_version=$( ls pkg-config-*-done 2>/dev/null | sed 's/pkg-config-\(.*\)-done/\1/' )
    installed_glib_version=$( ls glib-*-done 2>/dev/null | sed 's/glib-\(.*\)-done/\1/' )
    installed_qt_version=$( ls qt-*-done 2>/dev/null | sed 's/qt-\(.*\)-done/\1/' )
    installed_libsmi_version=$( ls libsmi-*-done 2>/dev/null | sed 's/libsmi-\(.*\)-done/\1/' )
    installed_libgpg_error_version=$( ls libgpg-error-*-done 2>/dev/null | sed 's/libgpg-error-\(.*\)-done/\1/' )
    installed_libgcrypt_version=$( ls libgcrypt-*-done 2>/dev/null | sed 's/libgcrypt-\(.*\)-done/\1/' )
    installed_gmp_version=$( ls gmp-*-done 2>/dev/null | sed 's/gmp-\(.*\)-done/\1/' )
    installed_libtasn1_version=$( ls libtasn1-*-done 2>/dev/null | sed 's/libtasn1-\(.*\)-done/\1/' )
    installed_p11_kit_version=$( ls p11-kit-*-done 2>/dev/null | sed 's/p11-kit-\(.*\)-done/\1/' )
    installed_nettle_version=$( ls nettle-*-done 2>/dev/null | sed 's/nettle-\(.*\)-done/\1/' )
    installed_gnutls_version=$( ls gnutls-*-done 2>/dev/null | sed 's/gnutls-\(.*\)-done/\1/' )
    installed_lua_version=$( ls lua-*-done 2>/dev/null | sed 's/lua-\(.*\)-done/\1/' )
    installed_snappy_version=$( ls snappy-*-done 2>/dev/null | sed 's/snappy-\(.*\)-done/\1/' )
    installed_zstd_version=$( ls zstd-*-done 2>/dev/null | sed 's/zstd-\(.*\)-done/\1/' )
    installed_zlibng_version=$( ls zlibng-*-done 2>/dev/null | sed 's/zlibng-\(.*\)-done/\1/' )
    installed_libxml2_version=$( ls libxml2-*-done 2>/dev/null | sed 's/libxml2-\(.*\)-done/\1/' )
    installed_lz4_version=$( ls lz4-*-done 2>/dev/null | sed 's/lz4-\(.*\)-done/\1/' )
    installed_sbc_version=$( ls sbc-*-done 2>/dev/null | sed 's/sbc-\(.*\)-done/\1/' )
    installed_maxminddb_version=$( ls maxminddb-*-done 2>/dev/null | sed 's/maxminddb-\(.*\)-done/\1/' )
    installed_cares_version=$( ls c-ares-*-done 2>/dev/null | sed 's/c-ares-\(.*\)-done/\1/' )
    installed_libssh_version=$( ls libssh-*-done 2>/dev/null | sed 's/libssh-\(.*\)-done/\1/' )
    installed_nghttp2_version=$( ls nghttp2-*-done 2>/dev/null | sed 's/nghttp2-\(.*\)-done/\1/' )
    installed_nghttp3_version=$( ls nghttp3-*-done 2>/dev/null | sed 's/nghttp3-\(.*\)-done/\1/' )
    installed_libtiff_version=$( ls tiff-*-done 2>/dev/null | sed 's/tiff-\(.*\)-done/\1/' )
    installed_spandsp_version=$( ls spandsp-*-done 2>/dev/null | sed 's/spandsp-\(.*\)-done/\1/' )
    installed_speexdsp_version=$( ls speexdsp-*-done 2>/dev/null | sed 's/speexdsp-\(.*\)-done/\1/' )
    installed_bcg729_version=$( ls bcg729-*-done 2>/dev/null | sed 's/bcg729-\(.*\)-done/\1/' )
    installed_ilbc_version=$( ls ilbc-*-done 2>/dev/null | sed 's/ilbc-\(.*\)-done/\1/' )
    installed_opencore_amr_version=$( ls opencore-amr-*-done 2>/dev/null | sed 's/opencore-amr-\(.*\)-done/\1/' )
    installed_opus_version=$( ls opus-*-done 2>/dev/null | sed 's/opus-\(.*\)-done/\1/' )
    installed_python3_version=$( ls python3-*-done 2>/dev/null | sed 's/python3-\(.*\)-done/\1/' )
    installed_brotli_version=$( ls brotli-*-done 2>/dev/null | sed 's/brotli-\(.*\)-done/\1/' )
    installed_minizip_version=$( ls minizip-[0-9.]*-done 2>/dev/null | sed 's/minizip-\(.*\)-done/\1/' )
    installed_minizip_ng_version=$( ls minizip-ng-*-done 2>/dev/null | sed 's/minizip-ng-\(.*\)-done/\1/' )
    installed_sparkle_version=$( ls sparkle-*-done 2>/dev/null | sed 's/sparkle-\(.*\)-done/\1/' )

    cd "$topdir"
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
export CFLAGS="-g -O2 -I$installation_prefix/include"
export CXXFLAGS="-g -O2 -I$installation_prefix/include"
export LDFLAGS="-L$installation_prefix/lib"
export PKG_CONFIG_PATH="$installation_prefix/lib/pkgconfig"

CONFIGURE_OPTS=( --prefix="$installation_prefix" )
# if no make options are present, set default options
# Should we just set MAKEFLAGS instead?
if [ -z "$MAKE_BUILD_OPTS" ] ; then
    # by default use 1.5x number of cores for parallel build
    MAKE_BUILD_OPTS=( -j $(( $(sysctl -n hw.logicalcpu) * 3 / 2)) )
fi

CURL_REMOTE_NAME_OPTS=(--fail-with-body --location --remote-name)
CURL_LOCAL_NAME_OPTS=(--fail-with-body --location --output)

#
# You need Xcode or the command-line tools installed to get the compilers (xcrun checks both).
#
 if [ ! -x /usr/bin/xcrun ]; then
    echo "Please install Xcode (app or command line) first (should be available from the Mac App Store)."
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
        echo "Please install Xcode first (should be available from the Mac App Store)."
        echo "The command-line build tools are not sufficient to build Qt."
        echo "Alternatively build QT according to: https://gist.github.com/shoogle/750a330c851bd1a924dfe1346b0b4a08#:~:text=MacOS%2FQt%5C%20Creator-,Go%20to%20Qt%20Creator%20%3E%20Preferences%20%3E%20Build%20%26%20Run%20%3E%20Kits,for%20both%20compilers%2C%20not%20gcc%20."
        exit 1
    fi
fi

#
# Do all the downloads and untarring in a subdirectory, so all that
# stuff can be removed once we've installed the support libraries.

if [ ! -d "${MACOSX_SUPPORT_LIBS}" ]
then
    mkdir "${MACOSX_SUPPORT_LIBS}"
fi
cd "${MACOSX_SUPPORT_LIBS}"

install_all

echo ""

#
# Indicate what paths to use for pkg-config and cmake.
#
if [ "$QT_VERSION" ]; then
    qt_base_path=$HOME/Qt$QT_VERSION/$QT_VERSION/clang_64
    # CMAKE_PREFIX_PATH="$PACKAGE_CONFIG_PATH:$qt_base_path/lib/cmake"
fi

if $no_build; then
    echo "All required dependencies downloaded. Run without -n to install them."
    exit 0
fi

if [ "$QT_VERSION" ]; then
    if [ -f "qt-$QT_VERSION-done" ]; then
        echo "You are now prepared to build Wireshark."
    else
        echo "Qt was not installed; you will have to install it in order to build the"
        echo "Wireshark application, but you can build all the command-line tools in"
        echo "the Wireshark distribution."
        echo ""
        echo "See section 2.1.1. \"Build environment setup\" of the Wireshark Developer's"
        echo "Guide for instructions on how to install Qt."
    fi
else
    echo "You did not install Qt; you will have to install it in order to build"
    echo "the Wireshark application, but you can build all the command-line tools in"
    echo "the Wireshark distribution."
fi
echo
echo "To build:"
echo
echo "export PATH=$PATH:$qt_base_path/bin"
echo
echo "mkdir build; cd build"
if [ -n "$NINJA_VERSION" ]; then
    echo "cmake -G Ninja .."
    echo "ninja wireshark_app_bundle stratoshark_app_bundle # (Modify as needed)"
    echo "ninja install/strip"
else
    echo "cmake .."
    echo "make ${MAKE_BUILD_OPTS[*]} wireshark_app_bundle stratoshark_app_bundle # (Modify as needed)"
    echo "make install/strip"
fi
echo
echo "Make sure you are allowed capture access to the network devices"
echo "See: https://gitlab.com/wireshark/wireshark/-/wikis/CaptureSetup/CapturePrivileges"
echo

exit 0
