#!/bin/sh
# Setup development environment on Mac OS X (tested with 10.6.8 and Xcode 3.2.6)
#
# Copyright 2011 Michael Tuexen, Joerg Mayer, Guy Harris (see AUTHORS file)
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#
# To build cmake
CMAKE=1
#
# To build all libraries as 32-bit libraries uncomment the following three lines.
#
# export CFLAGS="$CFLAGS -arch i386"
# export CXXFLAGS="$CXXFLAGS -arch i386"
# export LDFLAGS="$LDFLAGS -arch i386"
#
# and change "macx-clang" to "macx-clang-32" in the line below.
#
# Note: when building against the 10.6 SDK, clang fails, because there's
# a missing libstdc++.dylib in the SDK; this does not bother g++, however.
#
#TARGET_PLATFORM=macx-g++
TARGET_PLATFORM=macx-clang

#
# Versions of packages to download and install.
#

#
# Some packages need xz to unpack their current source.
# xz is not yet provided with OS X.
#
XZ_VERSION=5.0.4

#
# In case we want to build with cmake.
#
CMAKE_VERSION=2.8.12.2

#
# The following libraries and tools are required even to build only TShark.
#
GETTEXT_VERSION=0.18.2
GLIB_VERSION=2.36.0
PKG_CONFIG_VERSION=0.28

#
# One or more of the following libraries are required to build Wireshark.
#
# If you don't want to build with Qt, comment out the QT_VERSION= line.
#
# If you want to build with GTK+ 2, comment out the GTK_VERSION=3.* line
# and un-comment the GTK_VERSION=2.* line.
#
# If you don't want to build with GTK+ at all, comment out both lines.
# 
QT_VERSION=5.2.1
GTK_VERSION=2.24.17
#GTK_VERSION=3.5.2
if [ "$GTK_VERSION" ]; then
    #
    # We'll be building GTK+, so we need some additional libraries.
    #
    GTK_MAJOR_VERSION="`expr $GTK_VERSION : '\([0-9][0-9]*\).*'`"
    GTK_MINOR_VERSION="`expr $GTK_VERSION : '[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
    GTK_DOTDOT_VERSION="`expr $GTK_VERSION : '[0-9][0-9]*\.[0-9][0-9]*\.\([0-9][0-9]*\).*'`"

    ATK_VERSION=2.8.0
    PANGO_VERSION=1.30.1
    PNG_VERSION=1.5.17
    PIXMAN_VERSION=0.26.0
    CAIRO_VERSION=1.12.2
    GDK_PIXBUF_VERSION=2.28.0
fi

# In case we want to build GTK *and* we don't have Apple's X11 SDK installed
# we may want to install XQuartz. The version will only be used in the printing
# of a URL, the package will not be installed.
#
XQUARTZ_VERSION=2.7.5
#
# The following libraries are optional.
# Comment them out if you don't want them, but note that some of
# the optional libraries are required by other optional libraries.
#
LIBSMI_VERSION=0.4.8
#
# libgpg-error is required for libgcrypt.
#
LIBGPG_ERROR_VERSION=1.10
#
# libgcrypt is required for GnuTLS.
# XXX - the link for "Libgcrypt source code" at
# http://www.gnupg.org/download/#libgcrypt is for 1.5.0, and is a bzip2
# file, but http://directory.fsf.org/project/libgcrypt/ lists only
# 1.4.6.
#
LIBGCRYPT_VERSION=1.5.0
GNUTLS_VERSION=2.12.19
# Default to 5.2 now, unless user overrides it later
LUA_VERSION=5.2.3
PORTAUDIO_VERSION=pa_stable_v19_20111121
#
# XXX - they appear to have an unversioned gzipped tarball for the
# current version; should we just download that, with some other
# way of specifying whether to download the GeoIP API?
#
GEOIP_VERSION=1.4.8

CARES_VERSION=1.10.0

DARWIN_MAJOR_VERSION=`uname -r | sed 's/\([0-9]*\).*/\1/'`

#
# GNU autotools; they're provided with releases up to Snow Leopard, but
# not in later releases.
#
if [[ $DARWIN_MAJOR_VERSION -gt 10 ]]; then
    AUTOCONF_VERSION=2.69
    AUTOMAKE_VERSION=1.13.3
    LIBTOOL_VERSION=2.4.2
fi

uninstall() {
    if [ -d macosx-support-libs ]
    then
        cd macosx-support-libs

        #
        # Uninstall items in the reverse order from the order in which they're
        # installed.  Only uninstall if the download/build/install process
        # completed; uninstall the version that appears in the name of
        # the -done file.
        #
        # We also do a "make distclean", so that we don't have leftovers from
        # old configurations.
        #

        installed_cares_version=`ls cares-*-done 2>/dev/null | sed 's/cares-\(.*\)-done/\1/'`
        if [ ! -z "$installed_cares_version" ] ; then
            echo "Uninstalling C-Ares API:"
            cd cares-$installed_cares_version
            $DO_MAKE_UNINSTALL || exit 1
            make distclean || exit 1
            cd ..
            rm cares-$installed_cares_version-done
        fi

        installed_geoip_version=`ls geoip-*-done 2>/dev/null | sed 's/geoip-\(.*\)-done/\1/'`
        if [ ! -z "$installed_geoip_version" ] ; then
            echo "Uninstalling GeoIP API:"
            cd GeoIP-$installed_geoip_version
            $DO_MAKE_UNINSTALL || exit 1
            make distclean || exit 1
            cd ..
            rm geoip-$installed_geoip_version-done
        fi

        if [ "$PORTAUDIO_VERSION" -a -f portaudio-done ] ; then
            echo "Uninstalling PortAudio:"
            cd portaudio
            $DO_MAKE_UNINSTALL || exit 1
            make distclean || exit 1
            cd ..
            rm portaudio-done
        fi

        installed_lua_version=`ls lua-*-done 2>/dev/null | sed 's/lua-\(.*\)-done/\1/'`
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
        fi

        installed_gnutls_version=`ls gnutls-*-done 2>/dev/null | sed 's/gnutls-\(.*\)-done/\1/'`
        if [ ! -z "$installed_gnutls_version" ] ; then
            echo "Uninstalling GnuTLS:"
            cd gnutls-$installed_gnutls_version
            $DO_MAKE_UNINSTALL || exit 1
            make distclean || exit 1
            cd ..
            rm gnutls-$installed_gnutls_version-done
        fi

        installed_libgcrypt_version=`ls libgcrypt-*-done 2>/dev/null | sed 's/libgcrypt-\(.*\)-done/\1/'`
        if [ ! -z "$installed_libgcrypt_version" ] ; then
            echo "Uninstalling libgcrypt:"
            cd libgcrypt-$installed_libgcrypt_version
            $DO_MAKE_UNINSTALL || exit 1
            make distclean || exit 1
            cd ..
            rm libgcrypt-$installed_libgcrypt_version-done
        fi

        installed_libgpg_error_version=`ls libgpg-error-*-done 2>/dev/null | sed 's/libgpg-error-\(.*\)-done/\1/'`
        if [ ! -z "$installed_libgpg_error_version" ] ; then
            echo "Uninstalling libgpg-error:"
            cd libgpg-error-$installed_libgpg_error_version
            $DO_MAKE_UNINSTALL || exit 1
            make distclean || exit 1
            cd ..
            rm libgpg-error-$installed_libgpg_error_version-done
        fi

        installed_libsmi_version=`ls libsmi-*-done 2>/dev/null | sed 's/libsmi-\(.*\)-done/\1/'`
        if [ ! -z "$installed_libsmi_version" ] ; then
            echo "Uninstalling libsmi:"
            cd libsmi-$installed_libsmi_version
            $DO_MAKE_UNINSTALL || exit 1
            make distclean || exit 1
            cd ..
            rm libsmi-$installed_libsmi_version-done
        fi

        installed_gtk_version=`ls gtk+-*-done 2>/dev/null | sed 's/gtk+-\(.*\)-done/\1/'`
        if [ ! -z "$installed_gtk_version" ] ; then
            echo "Uninstalling GTK+:"
            cd gtk+-$installed_gtk_version
            $DO_MAKE_UNINSTALL || exit 1
            make distclean || exit 1
            cd ..
            rm gtk+-$installed_gtk_version-done
        fi

        installed_gdk_pixbuf_version=`ls gdk-pixbuf-*-done 2>/dev/null | sed 's/gdk-pixbuf-\(.*\)-done/\1/'`
        if [ ! -z "$installed_gdk_pixbuf_version" ] ; then
            echo "Uninstalling gdk-pixbuf:"
            cd gdk-pixbuf-$installed_gdk_pixbuf_version
            $DO_MAKE_UNINSTALL || exit 1
            make distclean || exit 1
            cd ..
            rm gdk-pixbuf-$installed_gdk_pixbuf_version-done
        fi

        installed_pango_version=`ls pango-*-done 2>/dev/null | sed 's/pango-\(.*\)-done/\1/'`
        if [ ! -z "$installed_pango_version" ] ; then
            echo "Uninstalling Pango:"
            cd pango-$installed_pango_version
            $DO_MAKE_UNINSTALL || exit 1
            make distclean || exit 1
            cd ..
            rm pango-$installed_pango_version-done
        fi

        installed_atk_version=`ls atk-*-done 2>/dev/null | sed 's/atk-\(.*\)-done/\1/'`
        if [ ! -z "$installed_atk_version" ] ; then
            echo "Uninstalling ATK:"
            cd atk-$installed_atk_version
            $DO_MAKE_UNINSTALL || exit 1
            make distclean || exit 1
            cd ..
            rm atk-$installed_atk_version-done
        fi

        installed_cairo_version=`ls cairo-*-done 2>/dev/null | sed 's/cairo-\(.*\)-done/\1/'`
        if [ ! -z "$installed_cairo_version" ] ; then
            echo "Uninstalling Cairo:"
            cd cairo-$installed_cairo_version
            $DO_MAKE_UNINSTALL || exit 1
            make distclean || exit 1
            cd ..
            rm cairo-$installed_cairo_version-done
        fi

        installed_pixman_version=`ls pixman-*-done 2>/dev/null | sed 's/pixman-\(.*\)-done/\1/'`
        if [ ! -z "$installed_pixman_version" ] ; then
            echo "Uninstalling pixman:"
            cd pixman-$installed_pixman_version
            $DO_MAKE_UNINSTALL || exit 1
            make distclean || exit 1
            cd ..
            rm pixman-$installed_pixman_version-done
        fi

        installed_libpng_version=`ls libpng-*-done 2>/dev/null | sed 's/libpng-\(.*\)-done/\1/'`
        if [ ! -z "$installed_libpng_version" ] ; then
            echo "Uninstalling libpng:"
            cd libpng-$installed_libpng_version
            $DO_MAKE_UNINSTALL || exit 1
            make distclean || exit 1
            cd ..
            rm libpng-$installed_libpng_version-done
        fi

        installed_qt_version=`ls qt-*-done 2>/dev/null | sed 's/qt-\(.*\)-done/\1/'`
        if [ ! -z "$installed_qt_version" ] ; then
            echo "Uninstalling Qt:"
            cd qt-everywhere-opensource-src-$installed_qt_version
            $DO_MAKE_UNINSTALL || exit 1
            #
            # XXX - "make distclean" doesn't work.  qmake sure does a
            # good job of constructing Makefiles that work correctly....
            #
            #make distclean || exit 1
            cd ..
            rm qt-$installed_qt_version-done
        fi

        installed_glib_version=`ls glib-*-done 2>/dev/null | sed 's/glib-\(.*\)-done/\1/'`
        if [ ! -z "$installed_glib_version" ] ; then
            echo "Uninstalling GLib:"
            cd glib-$installed_glib_version
            $DO_MAKE_UNINSTALL || exit 1
            make distclean || exit 1
            cd ..
            rm glib-$installed_glib_version-done
        fi

        installed_pkg_config_version=`ls pkg-config-*-done 2>/dev/null | sed 's/pkg-config-\(.*\)-done/\1/'`
        if [ ! -z "$installed_pkg_config_version" ] ; then
            echo "Uninstalling pkg-config:"
            cd pkg-config-$installed_pkg_config_version
            $DO_MAKE_UNINSTALL || exit 1
            make distclean || exit 1
            cd ..
            rm pkg-config-$installed_pkg_config_version-done
        fi

        installed_gettext_version=`ls gettext-*-done 2>/dev/null | sed 's/gettext-\(.*\)-done/\1/'`
        if [ ! -z "$installed_gettext_version" ] ; then
            echo "Uninstalling GNU gettext:"
            cd gettext-$installed_gettext_version
            $DO_MAKE_UNINSTALL || exit 1
            make distclean || exit 1
            cd ..
            rm gettext-$installed_gettext_version-done
        fi

        installed_cmake_version=`ls cmake-*-done 2>/dev/null | sed 's/cmake-\(.*\)-done/\1/'`
        if [ ! -z "$installed_cmake_version" ]; then
            echo "Uninstalling CMake:"
            cd cmake-$installed_cmake_version
            $DO_MAKE_UNINSTALL || exit 1
            make distclean || exit 1
            cd ..
            rm cmake-$installed_cmake_version-done
        fi

        installed_libtool_version=`ls libtool-*-done 2>/dev/null | sed 's/libtool-\(.*\)-done/\1/'`
        if [ ! -z "$installed_libtool_version" ] ; then
            echo "Uninstalling GNU libtool:"
            cd libtool-$installed_libtool_version
            mv /usr/local/bin/glibtool /usr/local/bin/libtool
            mv /usr/local/bin/glibtoolize /usr/local/bin/libtoolize
            $DO_MAKE_UNINSTALL || exit 1
            make distclean || exit 1
            cd ..
            rm libtool-$installed_libtool_version-done
        fi

        installed_automake_version=`ls automake-*-done 2>/dev/null | sed 's/automake-\(.*\)-done/\1/'`
        if [ ! -z "$installed_automake_version" ] ; then
            echo "Uninstalling GNU automake:"
            cd automake-$installed_automake_version
            $DO_MAKE_UNINSTALL || exit 1
            make distclean || exit 1
            cd ..
            rm automake-$installed_automake_version-done
        fi

        installed_autoconf_version=`ls autoconf-*-done 2>/dev/null | sed 's/autoconf-\(.*\)-done/\1/'`
        if [ ! -z "$installed_autoconf_version" ] ; then
            echo "Uninstalling GNU autoconf:"
            cd autoconf-$installed_autoconf_version
            $DO_MAKE_UNINSTALL || exit 1
            make distclean || exit 1
            cd ..
            rm autoconf-$installed_autoconf_version-done
        fi

        installed_xz_version=`ls xz-*-done 2>/dev/null | sed 's/xz-\(.*\)-done/\1/'`
        if [ ! -z "$installed_xz_version" ] ; then
            echo "Uninstalling xz:"
            cd xz-$installed_xz_version
            $DO_MAKE_UNINSTALL || exit 1
            make distclean || exit 1
            cd ..
            rm xz-$installed_xz_version-done
        fi
    fi
}

#
# Do we have permission to write in /usr/local?
#
# If so, assume we have permission to write in its subdirectories.
# (If that's not the case, this test needs to check the subdirectories
# as well.)
#
# If not, do "make install", "make uninstall", and the removes for Lua
# with sudo.
#
if [ -w /usr/local ]
then
    DO_MAKE_INSTALL="make install"
    DO_MAKE_UNINSTALL="make uninstall"
    DO_RM="rm"
else
    DO_MAKE_INSTALL="sudo make install"
    DO_MAKE_UNINSTALL="sudo make uninstall"
    DO_RM="sudo rm"
fi

#
# If we have SDKs available, the default target OS is the major version
# of the one we're running; get that and strip off the third component.
#
for i in /Developer/SDKs \
    /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs \
    /Library/Developer/CommandLineTools/SDKs
do
    if [ -d "$i" ]
    then
        min_osx_target=`sw_vers -productVersion | sed 's/\([[0-9]]*\).\([[0-9]]*\).[[0-9]]*/\1.\2/'`
        break
    fi
done

#
# Parse command-line flags:
#
# -h - print help.
# -t <target> - build libraries so that they'll work on the specified
# version of OS X and later versions.
# -u - do an uninstall.
#
while getopts ht:u name
do
    case $name in
    u)
        do_uninstall=yes
        ;;
    t)
        min_osx_target="$OPTARG"
        ;;
    h|?)
        echo "Usage: macosx-setup.sh [ -t <target> ] [ -u ]" 1>&1
        exit 0
        ;;
    esac
done

if [ "$do_uninstall" = "yes" ]
then
    uninstall
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

#
# To make this work on Leopard (rather than working *on* Snow Leopard
# when building *for* Leopard) will take more work.
#
# For one thing, Leopard's /usr/X11/lib/libXdamage.la claims, at least
# with all software updates applied, that the Xdamage shared library
# is libXdamage.1.0.0.dylib, but it is, in fact, libXdamage.1.1.0.dylib.
# This causes problems when building GTK+, so the script would have to
# fix that file.
#
if [[ $DARWIN_MAJOR_VERSION -le 9 ]]; then
    echo "This script does not support any versions of OS X before Snow Leopard" 1>&2 
    exit 1
fi

# if no make options are present, set default options
if [ -z "$MAKE_BUILD_OPTS" ] ; then
    # by default use 1.5x number of cores for parallel build
    MAKE_BUILD_OPTS="-j $(( $(sysctl -n hw.logicalcpu) * 3 / 2))"
fi

#
# If we have a target release, look for its SDK, and build libraries
# against it rather than against the headers and, more importantly,
# libraries that come with the OS, so that we don't end up with
# support libraries that only work on the OS version on which
# we built them, not earlier versions of the same release, or
# earlier releases if the minimum is earlier.
#
if [ ! -z "$min_osx_target" ]
then
    for i in /Developer/SDKs \
        /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs \
        /Library/Developer/CommandLineTools/SDKs
    do
        if [ -d "$i"/"MacOSX$min_osx_target.sdk" ]
        then
            SDKPATH="$i"/"MacOSX$min_osx_target.sdk"
            break
        fi
    done

    if [ -z "$SDKPATH" ]
    then
        echo "macosx-setup.sh: Couldn't find the SDK for OS X $min_osx_target" 1>&2
        exit 1
    fi

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

    if [[ "$min_osx_target" == "10.5" ]]
    then
        #
        # Cairo is part of Mac OS X 10.6 and later.
        # The *headers* are supplied by 10.5, but the *libraries*
        # aren't, so we have to build it if we're building for 10.5.
        #
        cairo_not_in_the_os=yes

        #
        # Build with older versions of the support libraries, as
        # were used on the Wireshark Leopard buildbot at one
        # point.  (Most of these versions come from the About page
        # from Wireshark 1.8.6, the last build done on that buildbot;
        # the ATK version isn't reported, so this is a guess.)
        #
        # If you want to try building with newer versions of
        # the libraries, note that:
        #
        # The version of fontconfig that comes with Leopard doesn't
        # support FC_WEIGHT_EXTRABLACK, so we can't use any version
        # of Pango newer than 1.22.4.
        #
        # However, Pango 1.22.4 doesn't work with versions of GLib
        # after 2.29.6, because Pango 1.22.4 uses G_CONST_RETURN and
        # GLib 2.29.8 and later deprecate it (there doesn't appear to
        # be a GLib 2.29.7).  That means we'd either have to patch
        # Pango not to use it (just use "const"; G_CONST_RETURN was
        # there to allow code to choose whether to use "const" or not),
        # or use GLib 2.29.6 or earlier.
        #
        # GLib 2.29.6 includes an implementation of g_bit_lock() that,
        # on x86 (32-bit and 64-bit), uses asms in a fashion
        # ("asm volatile goto") that requires GCC 4.5 or later, which
        # is later than the compilers that come with Leopard and Snow
        # Leopard.  Recent versions of GLib check for that, but 2.29.6
        # doesn't, so, if you want to build GLib 2.29.6 on Leopard or
        # Snow Leopard, you would have to patch glib/gbitlock.c to do
        # what the newer versions of GLib do:
        #
        #  define a USE_ASM_GOTO macro that indicates whether "asm goto"
        #  can be used:
        #    #if (defined (i386) || defined (__amd64__))
        #      #if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
        #        #define USE_ASM_GOTO 1
        #      #endif
        #    #endif
        #
        #  replace all occurrences of
        #
        #    #if defined (__GNUC__) && (defined (i386) || defined (__amd64__))
        #
        #  with
        #
        #    #ifdef USE_ASM_GOTO
        #
        # Using GLib 2.29.6 or earlier, however, means that we can't
        # use a version of ATK later than 2.3.93, as those versions
        # don't work with GLib 2.29.6.  The same applies to gdk-pixbuf;
        # versions of gdk-pixbuf after 2.24.1 won't work with GLib
        # 2.29.6.
        #
        # Then you have to make sure that what you've build doesn't
        # cause the X server that comes with Leopard to crash; at
        # least one attempt at building for Leopard did.
        #
        # At least if building on Leopard, you might also find
        # that, with various older versions of Cairo, including
        # 1.6.4 and at least some 1.8.x versions, when you try to
        # build it, the build fails because it can't find
        # png_set_longjmp_fn().  I vaguely remember dealing with that,
        # ages ago, but don't remember what I did.
        #
        GLIB_VERSION=2.16.3
        CAIRO_VERSION=1.6.4
        ATK_VERSION=1.24.0
        PANGO_VERSION=1.20.2
        GTK_VERSION=2.12.9

        #
        # That version of GTK+ includes gdk-pixbuf.
        # XXX - base this on the version of GTK+ requested.
        #
        GDK_PIXBUF_VERSION=

        #
        # Libgcrypt 1.5.0 fails to compile due to some problem with an
        # asm in rijndael.c, at least with i686-apple-darwin10-gcc-4.2.1
        # (GCC) 4.2.1 (Apple Inc. build 5666) (dot 3) when building
        # 32-bit.
        #
        # We try libgcrypt 1.4.3 instead, as that's what shows up in
        # the version from the Leopard buildbot.
        LIBGCRYPT_VERSION=1.4.3

        #
        # Build 32-bit while we're at it; Leopard has a bug that
        # causes some BPF functions not to work with 64-bit userland
        # code, so capturing won't work.
        #
        CFLAGS="$CFLAGS -arch i386"
        CXXFLAGS="$CXXFLAGS -arch i386"
        export LDFLAGS="$LDFLAGS -arch i386"
    fi
fi

export CFLAGS
export CXXFLAGS

#
# You need Xcode or the command-line tools installed to get the compilers.
#
if [ ! -x /usr/bin/xcodebuild ]; then
    echo "Please install Xcode first (should be available on DVD or from http://developer.apple.com/xcode/index.php)."
    exit 1
fi

if [ "$QT_VERSION" ]; then
    #
    # We need Xcode, not just the command-line tools, installed to build
    # Qt.
    #
    if ! /usr/bin/xcrun -find xcrun >/dev/null 2>&1; then
        echo "Please install Xcode first (should be available on DVD or from http://developer.apple.com/xcode/index.php)."
        echo "The command-line build tools are not sufficient to build Qt."
        exit 1
    fi
fi
if [ "$GTK_VERSION" ]; then
    #
    # If we're building with GTK+, you also need the X11 SDK; with at least
    # some versions of OS X and Xcode, that is, I think, an optional install.
    # (Or it might be installed with X11, but I think *that* is an optional
    # install on at least some versions of OS X.)
    #
    if [ ! -d /usr/X11/include ]; then
        echo "Please install X11 and the X11 SDK first."
        echo "  You can either use http://xquartz.macosforge.org/, e.g."
        echo "  http://xquartz-dl.macosforge.org/SL/XQuartz-$XQUARTZ_VERSION.dmg"
        echo "  or the native Apple packages if you are on Lion or below."
        exit 1
    fi
fi

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/X11/lib/pkgconfig

#
# Do all the downloads and untarring in a subdirectory, so all that
# stuff can be removed once we've installed the support libraries.
#
if [ ! -d macosx-support-libs ]
then
    mkdir macosx-support-libs || exit 1
fi
cd macosx-support-libs

# Start with xz: It is the sole download format of glib later than 2.31.2
#
if [ "$XZ_VERSION" -a ! -f xz-$XZ_VERSION-done ] ; then
    echo "Downloading, building, and installing xz:"
    [ -f xz-$XZ_VERSION.tar.bz2 ] || curl -O http://tukaani.org/xz/xz-$XZ_VERSION.tar.bz2 || exit 1
    bzcat xz-$XZ_VERSION.tar.bz2 | tar xf - || exit 1
    cd xz-$XZ_VERSION
    CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=0" ./configure || exit 1
    make $MAKE_BUILD_OPTS || exit 1
    $DO_MAKE_INSTALL || exit 1
    cd ..
    touch xz-$XZ_VERSION-done
fi

if [ "$AUTOCONF_VERSION" -a ! -f autoconf-$AUTOCONF_VERSION-done ] ; then
    echo "Downloading, building and installing GNU autoconf..."
    [ -f autoconf-$AUTOCONF_VERSION.tar.xz ] || curl -O ftp://ftp.gnu.org/gnu/autoconf/autoconf-$AUTOCONF_VERSION.tar.xz || exit 1
    xzcat autoconf-$AUTOCONF_VERSION.tar.xz | tar xf - || exit 1
    cd autoconf-$AUTOCONF_VERSION
    ./configure || exit 1
    make $MAKE_BUILD_OPTS || exit 1
    $DO_MAKE_INSTALL || exit 1
    cd ..
    touch autoconf-$AUTOCONF_VERSION-done
fi

if [ "$AUTOMAKE_VERSION" -a ! -f automake-$AUTOMAKE_VERSION-done ] ; then
    echo "Downloading, building and installing GNU automake..."
    [ -f automake-$AUTOMAKE_VERSION.tar.xz ] || curl -O ftp://ftp.gnu.org/gnu/automake/automake-$AUTOMAKE_VERSION.tar.xz || exit 1
    xzcat automake-$AUTOMAKE_VERSION.tar.xz | tar xf - || exit 1
    cd automake-$AUTOMAKE_VERSION
    ./configure || exit 1
    make $MAKE_BUILD_OPTS || exit 1
    $DO_MAKE_INSTALL || exit 1
    cd ..
    touch automake-$AUTOMAKE_VERSION-done
fi

if [ "$LIBTOOL_VERSION" -a ! -f libtool-$LIBTOOL_VERSION-done ] ; then
    echo "Downloading, building and installing GNU libtool..."
    [ -f libtool-$LIBTOOL_VERSION.tar.xz ] || curl -O ftp://ftp.gnu.org/gnu/libtool/libtool-$LIBTOOL_VERSION.tar.xz || exit 1
    xzcat libtool-$LIBTOOL_VERSION.tar.xz | tar xf - || exit 1
    cd libtool-$LIBTOOL_VERSION
    ./configure || exit 1
    make $MAKE_BUILD_OPTS || exit 1
    $DO_MAKE_INSTALL || exit 1
    mv /usr/local/bin/libtool /usr/local/bin/glibtool
    mv /usr/local/bin/libtoolize /usr/local/bin/glibtoolize
    cd ..
    touch libtool-$LIBTOOL_VERSION-done
fi

if [ -n "$CMAKE" -a ! -f cmake-$CMAKE_VERSION-done ]; then
  echo "Downloading, building, and installing CMAKE:"
  cmake_dir=`expr $CMAKE_VERSION : '\([0-9][0-9]*\.[0-9][0-9]*\).*'`
  [ -f cmake-$CMAKE_VERSION.tar.gz ] || curl -O http://www.cmake.org/files/v$cmake_dir/cmake-$CMAKE_VERSION.tar.gz || exit 1
  gzcat cmake-$CMAKE_VERSION.tar.gz | tar xf - || exit 1
  cd cmake-$CMAKE_VERSION
  ./bootstrap || exit 1
  make $MAKE_BUILD_OPTS || exit 1
  $DO_MAKE_INSTALL || exit 1
  cd ..
  touch cmake-$CMAKE_VERSION-done
fi

#
# Start with GNU gettext; GLib requires it, and OS X doesn't have it
# or a BSD-licensed replacement.
#
# At least on Lion with Xcode 4, _FORTIFY_SOURCE gets defined as 2
# by default, which causes, for example, stpncpy to be defined as
# a hairy macro that collides with the GNU gettext configure script's
# attempts to workaround AIX's lack of a declaration for stpncpy,
# with the result being a huge train wreck.  Define _FORTIFY_SOURCE
# as 0 in an attempt to keep the trains on separate tracks.
#
if [ ! -f gettext-$GETTEXT_VERSION-done ] ; then
    echo "Downloading, building, and installing GNU gettext:"
    [ -f gettext-$GETTEXT_VERSION.tar.gz ] || curl -O http://ftp.gnu.org/pub/gnu/gettext/gettext-$GETTEXT_VERSION.tar.gz || exit 1
    gzcat gettext-$GETTEXT_VERSION.tar.gz | tar xf - || exit 1
    cd gettext-$GETTEXT_VERSION
    CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=0 $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
    make $MAKE_BUILD_OPTS || exit 1
    $DO_MAKE_INSTALL || exit 1
    cd ..
    touch gettext-$GETTEXT_VERSION-done
fi

#
# GLib depends on pkg-config.
# By default, pkg-config depends on GLib; we break the dependency cycle
# by configuring pkg-config to use its own internal version of GLib.
#
if [ ! -f pkg-config-$PKG_CONFIG_VERSION-done ] ; then
    echo "Downloading, building, and installing pkg-config:"
    [ -f pkg-config-$PKG_CONFIG_VERSION.tar.gz ] || curl -O http://pkgconfig.freedesktop.org/releases/pkg-config-$PKG_CONFIG_VERSION.tar.gz || exit 1
    gzcat pkg-config-$PKG_CONFIG_VERSION.tar.gz | tar xf - || exit 1
    cd pkg-config-$PKG_CONFIG_VERSION
    ./configure --with-internal-glib || exit 1
    make $MAKE_BUILD_OPTS || exit 1
    $DO_MAKE_INSTALL || exit 1
    cd ..
    touch pkg-config-$PKG_CONFIG_VERSION-done
fi

if [ ! -f glib-$GLIB_VERSION-done ] ; then
    echo "Downloading, building, and installing GLib:"
    glib_dir=`expr $GLIB_VERSION : '\([0-9][0-9]*\.[0-9][0-9]*\).*'`
    GLIB_MAJOR_VERSION="`expr $GLIB_VERSION : '\([0-9][0-9]*\).*'`"
    GLIB_MINOR_VERSION="`expr $GLIB_VERSION : '[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
    GLIB_DOTDOT_VERSION="`expr $GLIB_VERSION : '[0-9][0-9]*\.[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
    if [[ $GLIB_MAJOR_VERSION -gt 2 ||
          $GLIB_MINOR_VERSION -gt 28 ||
          ($GLIB_MINOR_VERSION -eq 28 && $GLIB_DOTDOT_VERSION -ge 8) ]]
    then
        #
        # Starting with GLib 2.28.8, xz-compressed tarballs are available.
        #
        [ -f glib-$GLIB_VERSION.tar.xz ] || curl -L -O http://ftp.gnome.org/pub/gnome/sources/glib/$glib_dir/glib-$GLIB_VERSION.tar.xz || exit 1
        xzcat glib-$GLIB_VERSION.tar.xz | tar xf - || exit 1
    else
        [ -f glib-$GLIB_VERSION.tar.bz2 ] || curl -L -O http://ftp.gnome.org/pub/gnome/sources/glib/$glib_dir/glib-$GLIB_VERSION.tar.bz2 || exit 1
        bzcat glib-$GLIB_VERSION.tar.bz2 | tar xf - || exit 1
    fi
    cd glib-$GLIB_VERSION
    #
    # OS X ships with libffi, but doesn't provide its pkg-config file;
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
    #	https://bugzilla.gnome.org/show_bug.cgi?id=691608#c25
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
        LIBFFI_CFLAGS="-I $includedir/ffi" LIBFFI_LIBS="-lffi" CFLAGS="$CFLAGS -Wno-format-nonliteral $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
    else
        LIBFFI_CFLAGS="-I $includedir/ffi" LIBFFI_LIBS="-lffi" CFLAGS="$CFLAGS -DMACOSX -Wno-format-nonliteral $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
    fi

    #
    # Apply the fix to GNOME bug 529806:
    #
    #    https://bugzilla.gnome.org/show_bug.cgi?id=529806
    #
    # if we have a version of GLib prior to 2.30.
    #
    if [[ $GLIB_MAJOR_VERSION -eq 2 && $GLIB_MINOR_VERSION -le 30 ]]
    then
        patch -p0 <../../macosx-support-lib-patches/glib-gconvert.c.patch || exit 1
    fi
    make $MAKE_BUILD_OPTS || exit 1
    $DO_MAKE_INSTALL || exit 1
    cd ..
    touch glib-$GLIB_VERSION-done
fi

#
# Now we have reached a point where we can build everything but
# the GUI (Wireshark).
#
if [ "$QT_VERSION" -a ! -f qt-$QT_VERSION-done ]; then
    echo "Downloading, building, and installing Qt:"
    QT_MAJOR_VERSION="`expr $QT_VERSION : '\([0-9][0-9]*\).*'`"
    QT_MINOR_VERSION="`expr $QT_VERSION : '[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
    QT_DOTDOT_VERSION="`expr $QT_VERSION : '[0-9][0-9]*\.[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
    QT_MAJOR_MINOR_VERSION=$QT_MAJOR_VERSION.$QT_MINOR_VERSION
    #
    # What you get for this URL might just be a 302 Found reply, so use
    # -L so we get redirected.
    #
    curl -L -O http://download.qt-project.org/official_releases/qt/$QT_MAJOR_MINOR_VERSION/$QT_VERSION/single/qt-everywhere-opensource-src-$QT_VERSION.tar.gz
    #
    # Qt 5.1.x sets QMAKE_MACOSX_DEPLOYMENT_TARGET = 10.6
    # in qtbase/mkspecs/$TARGET_PLATFORM/qmake.conf
    # We may need to adjust this manually in the future.
    #
    # The -no-c++11 flag is needed to work around
    # https://bugreports.qt-project.org/browse/QTBUG-30487
    #
    tar xf qt-everywhere-opensource-src-$QT_VERSION.tar.gz
    cd qt-everywhere-opensource-src-$QT_VERSION
    #
    # We don't build Qt in its Full Shining Glory, as we don't need all
    # of its components, and it takes *forever* to build in that form.
    #
    # Qt 5.2.0 beta1 fails to build on OS X without -no-xcb due to bug
    # QTBUG-34382.
    #
    # Qt 5.x fails to build on OS X with -no-opengl due to bug
    # QTBUG-31151.
    #
    ./configure -v -sdk macosx$min_osx_target -platform $TARGET_PLATFORM \
        -opensource -confirm-license -no-c++11 -no-dbus \
        -no-sql-sqlite -no-xcb -nomake examples \
        -skip qtdoc -skip qtquickcontrols -skip qtwebkit \
        -skip qtwebkit-examples -skip qtxmlpatterns
    make || exit 1
    $DO_MAKE_INSTALL || exit 1
    cd ..
    touch qt-$QT_VERSION-done
fi

if [ "$GTK_VERSION" ]; then
    #
    # GTK+ 3 requires a newer Cairo build than the one that comes with
    # 10.6, so we build Cairo if we are using GTK+ 3.
    #
    # In 10.6 and 10.7, it's an X11 library; if we build with "native" GTK+
    # rather than X11 GTK+, we might have to build and install Cairo.
    # In 10.8 and later, there is no X11, but it's included in Xquartz;
    # again, if we build with "native" GTK+, we'd have to build and install
    # it.
    #
    if [[ "$GTK_MAJOR_VERSION" -eq 3 || "$cairo_not_in_the_os" = yes ]]; then
        #
        # Requirements for Cairo first
        #
        # The libpng that comes with the X11 for Leopard has a bogus
        # pkg-config file that lies about where the header files are,
        # which causes other packages not to be able to find its
        # headers.
        #
        # The libpng in later versions is not what the version of
        # libpixman we build below wants - it wants libpng15.
        #
        if [ ! -f libpng-$PNG_VERSION-done ] ; then
            echo "Downloading, building, and installing libpng:"
            #
            # The FTP site puts libpng x.y.* into a libpngxy directory.
            #
            subdir=`echo $PNG_VERSION | sed 's/\([1-9][0-9]*\)\.\([1-9][0-9]*\).*/libpng\1\2'/`
            [ -f libpng-$PNG_VERSION.tar.xz ] || curl -O ftp://ftp.simplesystems.org/pub/libpng/png/src/$subdir/libpng-$PNG_VERSION.tar.xz
            xzcat libpng-$PNG_VERSION.tar.xz | tar xf - || exit 1
            cd libpng-$PNG_VERSION
            CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
            make $MAKE_BUILD_OPTS || exit 1
            $DO_MAKE_INSTALL || exit 1
            cd ..
            touch libpng-$PNG_VERSION-done
        fi

        #
        # The libpixman versions that come with the X11s for Leopard,
        # Snow Leopard, and Lion is too old to support Cairo's image
        # surface backend feature (which requires pixman-1 >= 0.22.0).
        #
        # XXX - what about the one that comes with the latest version
        # of Xquartz?
        #
        if [ ! -f pixman-$PIXMAN_VERSION-done ] ; then
            echo "Downloading, building, and installing pixman:"
            [ -f pixman-$PIXMAN_VERSION.tar.gz ] || curl -O http://www.cairographics.org/releases/pixman-$PIXMAN_VERSION.tar.gz
            gzcat pixman-$PIXMAN_VERSION.tar.gz | tar xf - || exit 1
            cd pixman-$PIXMAN_VERSION
            CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
            make V=1 $MAKE_BUILD_OPTS || exit 1
            $DO_MAKE_INSTALL || exit 1
            cd ..
            touch pixman-$PIXMAN_VERSION-done
        fi

        #
        # And now Cairo itself.
        # XXX - with the libxcb that comes with 10.6,
        #
        # xcb_discard_reply() is missing, and the build fails.
        #
        if [ ! -f cairo-$CAIRO_VERSION-done ] ; then
            echo "Downloading, building, and installing Cairo:"
            CAIRO_MAJOR_VERSION="`expr $CAIRO_VERSION : '\([0-9][0-9]*\).*'`"
            CAIRO_MINOR_VERSION="`expr $CAIRO_VERSION : '[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
            CAIRO_DOTDOT_VERSION="`expr $CAIRO_VERSION : '[0-9][0-9]*\.[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
            if [[ $CAIRO_MAJOR_VERSION -gt 1 ||
                  $CAIRO_MINOR_VERSION -gt 12 ||
                  ($CAIRO_MINOR_VERSION -eq 12 && $CAIRO_DOTDOT_VERSION -ge 2) ]]
            then
                #
                # Starting with Cairo 1.12.2, the tarballs are compressed with
                # xz rather than gzip.
                #
                [ -f cairo-$CAIRO_VERSION.tar.xz ] || curl -O http://cairographics.org/releases/cairo-$CAIRO_VERSION.tar.xz || exit 1
                xzcat cairo-$CAIRO_VERSION.tar.xz | tar xf - || exit 1
            else
                [ -f cairo-$CAIRO_VERSION.tar.gz ] || curl -O http://cairographics.org/releases/cairo-$CAIRO_VERSION.tar.gz || exit 1
                gzcat cairo-$CAIRO_VERSION.tar.gz | tar xf - || exit 1
            fi
            cd cairo-$CAIRO_VERSION
            # CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --enable-quartz=no || exit 1
            # Maybe follow http://cairographics.org/end_to_end_build_for_mac_os_x/
            CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --enable-quartz=yes || exit 1
            #
            # We must avoid the version of libpng that comes with X11; the
            # only way I've found to force that is to forcibly set INCLUDES
            # when we do the build, so that this comes before CAIRO_CFLAGS,
            # which has -I/usr/X11/include added to it before anything
            # connected to libpng is.
            #
            INCLUDES="-I/usr/local/include/libpng15" make $MAKE_BUILD_OPTS || exit 1
            $DO_MAKE_INSTALL || exit 1
            cd ..
            touch cairo-$CAIRO_VERSION-done
        fi
    fi

    if [ ! -f atk-$ATK_VERSION-done ] ; then
        echo "Downloading, building, and installing ATK:"
        atk_dir=`expr $ATK_VERSION : '\([0-9][0-9]*\.[0-9][0-9]*\).*'`
        ATK_MAJOR_VERSION="`expr $ATK_VERSION : '\([0-9][0-9]*\).*'`"
        ATK_MINOR_VERSION="`expr $ATK_VERSION : '[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
        ATK_DOTDOT_VERSION="`expr $ATK_VERSION : '[0-9][0-9]*\.[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
        if [[ $ATK_MAJOR_VERSION -gt 2 ||
              ($ATK_MAJOR_VERSION -eq 2 && $ATK_MINOR_VERSION -gt 0) ||
              ($ATK_MANOR_VERSION -eq 2 && $ATK_MINOR_VERSION -eq 0 && $ATK_DOTDOT_VERSION -ge 1) ]]
        then
            #
            # Starting with ATK 2.0.1, xz-compressed tarballs are available.
            #
            [ -f atk-$ATK_VERSION.tar.xz ] || curl -O http://ftp.gnome.org/pub/gnome/sources/atk/$atk_dir/atk-$ATK_VERSION.tar.xz || exit 1
            xzcat atk-$ATK_VERSION.tar.xz | tar xf - || exit 1
        else
            [ -f atk-$ATK_VERSION.tar.bz2 ] || curl -O http://ftp.gnome.org/pub/gnome/sources/atk/$atk_dir/atk-$ATK_VERSION.tar.bz2 || exit 1
            bzcat atk-$ATK_VERSION.tar.bz2 | tar xf - || exit 1
        fi
        cd atk-$ATK_VERSION
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch atk-$ATK_VERSION-done
    fi

    if [ ! -f pango-$PANGO_VERSION-done ] ; then
        echo "Downloading, building, and installing Pango:"
        pango_dir=`expr $PANGO_VERSION : '\([0-9][0-9]*\.[0-9][0-9]*\).*'`
        PANGO_MAJOR_VERSION="`expr $PANGO_VERSION : '\([0-9][0-9]*\).*'`"
        PANGO_MINOR_VERSION="`expr $PANGO_VERSION : '[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
        if [[ $PANGO_MAJOR_VERSION -gt 1 ||
              $PANGO_MINOR_VERSION -ge 29 ]]
        then
            #
            # Starting with Pango 1.29, the tarballs are compressed with
            # xz rather than bzip2.
            #
            [ -f pango-$PANGO_VERSION.tar.xz ] || curl -L -O http://ftp.gnome.org/pub/gnome/sources/pango/$pango_dir/pango-$PANGO_VERSION.tar.xz || exit 1
            xzcat pango-$PANGO_VERSION.tar.xz | tar xf - || exit 1
        else
            [ -f pango-$PANGO_VERSION.tar.bz2 ] || curl -L -O http://ftp.gnome.org/pub/gnome/sources/pango/$pango_dir/pango-$PANGO_VERSION.tar.bz2 || exit 1
            bzcat pango-$PANGO_VERSION.tar.bz2 | tar xf - || exit 1
        fi
        cd pango-$PANGO_VERSION
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch pango-$PANGO_VERSION-done
    fi

    if [ "$GDK_PIXBUF_VERSION" -a ! -f gdk-pixbuf-$GDK_PIXBUF_VERSION-done ] ; then
        echo "Downloading, building, and installing gdk-pixbuf:"
        gdk_pixbuf_dir=`expr $GDK_PIXBUF_VERSION : '\([0-9][0-9]*\.[0-9][0-9]*\).*'`
        [ -f gdk-pixbuf-$GDK_PIXBUF_VERSION.tar.xz ] || curl -L -O http://ftp.gnome.org/pub/gnome/sources/gdk-pixbuf/$gdk_pixbuf_dir/gdk-pixbuf-$GDK_PIXBUF_VERSION.tar.xz || exit 1
        xzcat gdk-pixbuf-$GDK_PIXBUF_VERSION.tar.xz | tar xf - || exit 1
        cd gdk-pixbuf-$GDK_PIXBUF_VERSION
        #
        # If we're building for 10.6, use libpng12; if you have 10.7.5, including
        # X11, and Xcode 4.3.3, the system has libpng15, complete with pkg-config
        # files, as part of X11, but 10.6's X11 has only libpng12, and the 10.6
        # SDK in Xcode 4.3.3 also has only libpng12, and has no pkg-config files
        # of its own, so we have to explicitly set LIBPNG to override the
        # configure script, and also force the CFLAGS to look for the header
        # files for libpng12 (note that -isysroot doesn't affect the arguments
        # to -I, so we need to include the SDK path explicitly).
        #
        if [[ "$min_osx_target" = 10.6 ]]
        then
            LIBPNG="-L/usr/X11/lib -lpng12" CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS -I$SDKPATH/usr/X11/include/libpng12" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --without-libtiff --without-libjpeg || exit 1
        else
            CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --without-libtiff --without-libjpeg || exit 1
        fi
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch gdk-pixbuf-$GDK_PIXBUF_VERSION-done
    fi

    if [ ! -f gtk+-$GTK_VERSION-done ] ; then
        echo "Downloading, building, and installing GTK+:"
        gtk_dir=`expr $GTK_VERSION : '\([0-9][0-9]*\.[0-9][0-9]*\).*'`
        if [[ $GTK_MAJOR_VERSION -gt 2 ||
              $GTK_MINOR_VERSION -gt 24 ||
             ($GTK_MINOR_VERSION -eq 24 && $GTK_DOTDOT_VERSION -ge 5) ]]
        then
            #
            # Starting with GTK+ 2.24.5, the tarballs are compressed with
            # xz rather than gzip, in addition to bzip2; use xz, as we've
            # built and installed it, and as xz compresses better than
            # bzip2 so the tarballs take less time to download.
            #
            [ -f gtk+-$GTK_VERSION.tar.xz ] || curl -L -O http://ftp.gnome.org/pub/gnome/sources/gtk+/$gtk_dir/gtk+-$GTK_VERSION.tar.xz || exit 1
            xzcat gtk+-$GTK_VERSION.tar.xz | tar xf - || exit 1
        else
            [ -f gtk+-$GTK_VERSION.tar.bz2 ] || curl -L -O http://ftp.gnome.org/pub/gnome/sources/gtk+/$gtk_dir/gtk+-$GTK_VERSION.tar.bz2 || exit 1
            bzcat gtk+-$GTK_VERSION.tar.bz2 | tar xf - || exit 1
        fi
        cd gtk+-$GTK_VERSION
        if [ $DARWIN_MAJOR_VERSION -ge "12" ]
        then
            #
            # GTK+ 2.24.10, at least, doesn't build on Mountain Lion with the
            # CUPS printing backend - either the CUPS API changed incompatibly
            # or the backend was depending on non-API implementation details.
            #
            # Configure it out, on Mountain Lion and later, for now.
            # (12 is the Darwin major version number in Mountain Lion.)
            #
            # Also, configure out libtiff and libjpeg; configure scripts
            # just ignore unknown --enable/--disable and --with/--without
            # options (at least they've always do so up to now).
            #
            CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --disable-cups --without-libtiff --without-libjpeg || exit 1
        else
            CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --without-libtiff --without-libjpeg || exit 1
        fi
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch gtk+-$GTK_VERSION-done
    fi
fi

#
# Now we have reached a point where we can build everything including
# the GUI (Wireshark), but not with any optional features such as
# SNMP OID resolution, some forms of decryption, Lua scripting, playback
# of audio, or GeoIP mapping of IP addresses.
#
# We now conditionally download optional libraries to support them;
# the default is to download them all.
#

if [ "$LIBSMI_VERSION" -a ! -f libsmi-$LIBSMI_VERSION-done ] ; then
    echo "Downloading, building, and installing libsmi:"
    [ -f libsmi-$LIBSMI_VERSION.tar.gz ] || curl -L -O https://www.ibr.cs.tu-bs.de/projects/libsmi/download/libsmi-$LIBSMI_VERSION.tar.gz || exit 1
    gzcat libsmi-$LIBSMI_VERSION.tar.gz | tar xf - || exit 1
    cd libsmi-$LIBSMI_VERSION
    CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
    make $MAKE_BUILD_OPTS || exit 1
    $DO_MAKE_INSTALL || exit 1
    cd ..
    touch libsmi-$LIBSMI_VERSION-done
fi

if [ "$LIBGPG_ERROR_VERSION" -a ! -f libgpg-error-$LIBGPG_ERROR_VERSION-done ] ; then
    echo "Downloading, building, and installing libgpg-error:"
    [ -f libgpg-error-$LIBGPG_ERROR_VERSION.tar.bz2 ] || curl -L -O ftp://ftp.gnupg.org/gcrypt/libgpg-error/libgpg-error-$LIBGPG_ERROR_VERSION.tar.bz2 || exit 1
    bzcat libgpg-error-$LIBGPG_ERROR_VERSION.tar.bz2 | tar xf - || exit 1
    cd libgpg-error-$LIBGPG_ERROR_VERSION
    CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
    make $MAKE_BUILD_OPTS || exit 1
    $DO_MAKE_INSTALL || exit 1
    cd ..
    touch libgpg-error-$LIBGPG_ERROR_VERSION-done
fi

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
    [ -f libgcrypt-$LIBGCRYPT_VERSION.tar.gz ] || curl -L -O ftp://ftp.gnupg.org/gcrypt/libgcrypt/libgcrypt-$LIBGCRYPT_VERSION.tar.gz || exit 1
    gzcat libgcrypt-$LIBGCRYPT_VERSION.tar.gz | tar xf - || exit 1
    cd libgcrypt-$LIBGCRYPT_VERSION
    #
    # The assembler language code is not compatible with the OS X
    # x86 assembler (or is it an x86-64 vs. x86-32 issue?).
    #
    # libgcrypt expects gnu89, not c99/gnu99, semantics for
    # "inline".  See, for example:
    #
    #    http://lists.freebsd.org/pipermail/freebsd-ports-bugs/2010-October/198809.html
    #
    CFLAGS="$CFLAGS -std=gnu89 $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --disable-asm || exit 1
    make $MAKE_BUILD_OPTS || exit 1
    $DO_MAKE_INSTALL || exit 1
    cd ..
    touch libgcrypt-$LIBGCRYPT_VERSION-done
fi

if [ "$GNUTLS_VERSION" -a ! -f gnutls-$GNUTLS_VERSION-done ] ; then
    #
    # GnuTLS requires libgcrypt (or nettle, in newer versions).
    #
    if [ -z $LIBGCRYPT_VERSION ]
    then
        echo "GnuTLS requires libgcrypt, but you didn't install libgcrypt" 1>&2
        exit 1
    fi

    echo "Downloading, building, and installing GnuTLS:"
    [ -f gnutls-$GNUTLS_VERSION.tar.bz2 ] || curl -L -O http://ftp.gnu.org/gnu/gnutls/gnutls-$GNUTLS_VERSION.tar.bz2 || exit 1
    bzcat gnutls-$GNUTLS_VERSION.tar.bz2 | tar xf - || exit 1
    cd gnutls-$GNUTLS_VERSION
    #
    # Use libgcrypt, not nettle.
    # XXX - is there some reason to prefer nettle?  Or does
    # Wireshark directly use libgcrypt routines?
    #
    CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --with-libgcrypt --without-p11-kit || exit 1
    make $MAKE_BUILD_OPTS || exit 1
    #
    # The pkgconfig file for GnuTLS says "requires zlib", but OS X,
    # while it supplies zlib, doesn't supply a pkgconfig file for
    # it.
    #
    # Patch the GnuTLS pkgconfig file not to require zlib.
    # (If the capabilities of GnuTLS that Wireshark uses don't
    # depend on building GnuTLS with zlib, an alternative would be
    # to configure it not to use zlib.)
    #
    patch -p0 lib/gnutls.pc.in <../../macosx-support-lib-patches/gnutls-pkgconfig.patch || exit 1
    $DO_MAKE_INSTALL || exit 1
    cd ..
    touch gnutls-$GNUTLS_VERSION-done
fi

if [ "$LUA_VERSION" -a ! -f lua-$LUA_VERSION-done ] ; then
    echo "Downloading, building, and installing Lua:"
    [ -f lua-$LUA_VERSION.tar.gz ] || curl -L -O http://www.lua.org/ftp/lua-$LUA_VERSION.tar.gz || exit 1
    gzcat lua-$LUA_VERSION.tar.gz | tar xf - || exit 1
    cd lua-$LUA_VERSION
    make $MAKE_BUILD_OPTS macosx || exit 1
    $DO_MAKE_INSTALL || exit 1
    cd ..
    touch lua-$LUA_VERSION-done
fi

if [ "$PORTAUDIO_VERSION" -a ! -f portaudio-done ] ; then
    echo "Downloading, building, and installing PortAudio:"
    [ -f $PORTAUDIO_VERSION.tgz ] || curl -L -O http://www.portaudio.com/archives/$PORTAUDIO_VERSION.tgz || exit 1
    gzcat $PORTAUDIO_VERSION.tgz | tar xf - || exit 1
    cd portaudio
    #
    # Un-comment an include that's required on Lion.
    #
    patch -p0 include/pa_mac_core.h <../../macosx-support-lib-patches/portaudio-pa_mac_core.h.patch
    #
    # Fix a bug that showed up with clang (but is a bug with any
    # compiler).
    #
    patch -p0 src/hostapi/coreaudio/pa_mac_core.c <../../macosx-support-lib-patches/portaudio-pa_mac_core.c.patch
    #
    # Disable fat builds - the configure script doesn't work right
    # with Xcode 4 if you leave them enabled, and we don't build
    # any other libraries fat (GLib, for example, would be very
    # hard to build fat), so there's no advantage to having PortAudio
    # built fat.
    #
    # Set the minimum OS X version to 10.4, to suppress some
    # deprecation warnings.  (Good luck trying to make any of
    # this build on an OS+Xcode with a pre-10.4 SDK; we don't
    # worry about the user requesting that.)
    #
    CFLAGS="$CFLAGS -mmacosx-version-min=10.4 $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --disable-mac-universal || exit 1
    make $MAKE_BUILD_OPTS || exit 1
    $DO_MAKE_INSTALL || exit 1
    cd ..
    touch portaudio-done
fi

if [ "$GEOIP_VERSION" -a ! -f geoip-$GEOIP_VERSION-done ]
then
    echo "Downloading, building, and installing GeoIP API:"
    [ -f GeoIP-$GEOIP_VERSION.tar.gz ] || curl -L -O http://geolite.maxmind.com/download/geoip/api/c/GeoIP-$GEOIP_VERSION.tar.gz || exit 1
    gzcat GeoIP-$GEOIP_VERSION.tar.gz | tar xf - || exit 1
    cd GeoIP-$GEOIP_VERSION
    CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
    #
    # Grr.  Their man pages "helpfully" have an ISO 8859-1
    # copyright symbol in the copyright notice, but OS X's
    # default character encoding is UTF-8.  sed on Mountain
    # Lion barfs at the "illegal character sequence" represented
    # by an ISO 8859-1 copyright symbol, as it's not a valid
    # UTF-8 sequence.
    #
    # iconv the relevant man pages into UTF-8.
    #
    for i in geoipupdate.1.in geoiplookup6.1.in geoiplookup.1.in
    do
        iconv -f iso8859-1 -t utf-8 man/"$i" >man/"$i".tmp &&
            mv man/"$i".tmp man/"$i"
    done
    make $MAKE_BUILD_OPTS || exit 1
    $DO_MAKE_INSTALL || exit 1
    cd ..
    touch geoip-$GEOIP_VERSION-done
fi

if [ "$CARES_VERSION" -a ! -f geoip-$CARES_VERSION-done ]
then
    echo "Downloading, building, and installing C-Ares API:"
    [ -f c-ares-$CARES_VERSION.tar.gz ] || curl -L -O http://c-ares.haxx.se/download/c-ares-$CARES_VERSION.tar.gz || exit 1
    gzcat c-ares-$CARES_VERSION.tar.gz | tar xf - || exit 1
    cd c-ares-$CARES_VERSION
    CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
    make $MAKE_BUILD_OPTS || exit 1
    $DO_MAKE_INSTALL || exit 1
    cd ..
    touch geoip-$CARES_VERSION-done
fi

echo ""

echo "You are now prepared to build Wireshark. To do so do:"
echo "export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/X11/lib/pkgconfig"
echo ""
if [ -n "$CMAKE" ]; then
    echo "mkdir build; cd build"
    echo "cmake .."
    echo
    echo "or"
    echo
fi
echo "./autogen.sh"
echo "mkdir build; cd build"
echo "../configure"
echo ""
echo "make $MAKE_BUILD_OPTS"
echo "make install"

echo ""

echo "Make sure you are allowed capture access to the network devices"
echo "See: http://wiki.wireshark.org/CaptureSetup/CapturePrivileges"

echo ""

exit 0
