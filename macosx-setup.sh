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
# To install cmake
#
CMAKE=1
#
# To install autotools
#
AUTOTOOLS=1
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
XZ_VERSION=5.0.8

#
# In case we want to build with cmake.
#
CMAKE_VERSION=${CMAKE_VERSION-2.8.12.2}

#
# The following libraries and tools are required even to build only TShark.
#
GETTEXT_VERSION=0.18.2
GLIB_VERSION=2.36.0
PKG_CONFIG_VERSION=0.28

#
# One or more of the following libraries are required to build Wireshark.
#
# To override the versions of Qt and GTK call the script with some of the
# variables set to the new values. Setting a variable to empty will disable
# building the toolkit and will un-install any version previously installed
# by the script, e.g. "GTK_VERSION=3.5.2 QT_VERSION= ./macos-setup.sh"
# will build and install with GTK+ 3.5.2 and will not install Qt (and,
# if the script installed Qt earlier, will un-install that version of Qt).
#
# Note that Qt 5, prior to 5.5.0, mishandles context menus in ways that,
# for example, cause them not to work reliably in the packet detail or
# packet data pane; see, for example, Qt bugs QTBUG-31937, QTBUG-41017,
# and QTBUG-43464, all of which seem to be the same bug.
#
QT_VERSION=${QT_VERSION-5.5.0}
GTK_VERSION=${GTK_VERSION-2.24.17}
if [ "$GTK_VERSION" ]; then
    #
    # We'll be building GTK+, so we need some additional libraries.
    #
    GTK_MAJOR_VERSION="`expr $GTK_VERSION : '\([0-9][0-9]*\).*'`"
    GTK_MINOR_VERSION="`expr $GTK_VERSION : '[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
    GTK_DOTDOT_VERSION="`expr $GTK_VERSION : '[0-9][0-9]*\.[0-9][0-9]*\.\([0-9][0-9]*\).*'`"

    ATK_VERSION=2.8.0
    PANGO_VERSION=1.30.1
    PNG_VERSION=1.6.20
    PIXMAN_VERSION=0.26.0
    CAIRO_VERSION=1.12.2
    GDK_PIXBUF_VERSION=2.28.0
fi
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
#
# libgpg-error is required for libgcrypt.
#
LIBGPG_ERROR_VERSION=1.10
#
# libgcrypt is required for GnuTLS.
#
LIBGCRYPT_VERSION=1.5.0
GNUTLS_VERSION=2.12.19
# Use 5.2.4, not 5.3, for now; lua_bitop.c hasn't been ported to 5.3
# yet, and we need to check for compatibility issues (we'd want Lua
# scripts to work with 5.1, 5.2, and 5.3, as long as they only use Lua
# features present in all three versions)
LUA_VERSION=5.2.4
PORTAUDIO_VERSION=pa_stable_v19_20111121
#
# XXX - they appear to have an unversioned gzipped tarball for the
# current version; should we just download that, with some other
# way of specifying whether to download the GeoIP API?
#
GEOIP_VERSION=1.4.8

CARES_VERSION=1.10.0

LIBSSH_VERSION=0.7.3

DARWIN_MAJOR_VERSION=`uname -r | sed 's/\([0-9]*\).*/\1/'`

#
# GNU autotools; they're provided with releases up to Snow Leopard, but
# not in later releases, and the Snow Leopard version is too old for
# current Wireshark, so we install them unconditionally.
#
AUTOCONF_VERSION=2.69
AUTOMAKE_VERSION=1.13.3
LIBTOOL_VERSION=2.4.6

install_xz() {
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

install_autoconf() {
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
        [ -f automake-$AUTOMAKE_VERSION.tar.xz ] || curl -O ftp://ftp.gnu.org/gnu/automake/automake-$AUTOMAKE_VERSION.tar.xz || exit 1
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
        [ -f libtool-$LIBTOOL_VERSION.tar.xz ] || curl -O ftp://ftp.gnu.org/gnu/libtool/libtool-$LIBTOOL_VERSION.tar.xz || exit 1
        xzcat libtool-$LIBTOOL_VERSION.tar.xz | tar xf - || exit 1
        cd libtool-$LIBTOOL_VERSION
        ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        $DO_MV /usr/local/bin/libtool /usr/local/bin/glibtool
        $DO_MV /usr/local/bin/libtoolize /usr/local/bin/glibtoolize
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

install_cmake() {
    if [ -n "$CMAKE" -a ! -f cmake-$CMAKE_VERSION-done ]; then
        echo "Downloading and installing CMake:"
        CMAKE_MAJOR_VERSION="`expr $CMAKE_VERSION : '\([0-9][0-9]*\).*'`"
        CMAKE_MINOR_VERSION="`expr $CMAKE_VERSION : '[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
        CMAKE_DOTDOT_VERSION="`expr $CMAKE_VERSION : '[0-9][0-9]*\.[0-9][0-9]*\.\([0-9][0-9]*\).*'`"
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
            [ -f cmake-$CMAKE_VERSION-Darwin64-universal.dmg ] || curl -O https://cmake.org/files/v$CMAKE_MAJOR_MINOR_VERSION/cmake-$CMAKE_VERSION-Darwin64-universal.dmg || exit 1
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
            [ -f cmake-$CMAKE_VERSION-$type.dmg ] || curl -O https://cmake.org/files/v$CMAKE_MAJOR_MINOR_VERSION/cmake-$CMAKE_VERSION-$type.dmg || exit 1
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
        [ -f gettext-$GETTEXT_VERSION.tar.gz ] || curl -O http://ftp.gnu.org/pub/gnu/gettext/gettext-$GETTEXT_VERSION.tar.gz || exit 1
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
        [ -f pkg-config-$PKG_CONFIG_VERSION.tar.gz ] || curl -O https://pkgconfig.freedesktop.org/releases/pkg-config-$PKG_CONFIG_VERSION.tar.gz || exit 1
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
}

uninstall_glib() {
    if [ ! -z "$installed_glib_version" ] ; then
        #
        # ATK, Pango, and GTK depend on this, so uninstall them.
        #
        uninstall_gtk
        uninstall_pango
        uninstall_atk

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
            rm -rf glib-$installed_glib_version.tar.xz glib-$installed_glib_version.tar.bz2
        fi

        installed_glib_version=""
    fi
}

install_qt() {
    if [ "$QT_VERSION" -a ! -f qt-$QT_VERSION-done ]; then
        echo "Downloading, building, and installing Qt:"
        #
        # What you get for this URL might just be a 302 Found reply, so use
        # -L so we get redirected.
        #
        if [ "$QT_MAJOR_VERSION" -ge 5 ]
        then
            QT_VOLUME=qt-opensource-mac-x64-clang-$QT_VERSION
        else
            QT_VOLUME=qt-opensource-mac-$QT_VERSION
        fi
        [ -f $QT_VOLUME.dmg ] || curl -L -O http://download.qt.io/archive/qt/$QT_MAJOR_MINOR_VERSION/$QT_MAJOR_MINOR_DOTDOT_VERSION/$QT_VOLUME.dmg || exit 1
        sudo hdiutil attach $QT_VOLUME.dmg || exit 1

        if [ "$QT_MAJOR_VERSION" -ge 5 ]
        then
            #
            # Run the installer executable directly, so that we wait for
            # it to finish.  Then unmount the volume.
            #
            /Volumes/$QT_VOLUME/$QT_VOLUME.app/Contents/MacOS/$QT_VOLUME
            sudo hdiutil detach /Volumes/$QT_VOLUME
        else
            #
            # Open the installer package; use -W, so that we wait for
            # the installer to finish.  Then unmount the volume.
            #
            open -W "/Volumes/Qt $QT_MAJOR_MINOR_DOTDOT_VERSION/Qt.mpkg"
            sudo hdiutil detach "/Volumes/Qt $QT_MAJOR_MINOR_DOTDOT_VERSION"
        fi

        #
        # Versions 5.3.x through 5.5.0, at least, have bogus .pc files.
        # See bugs QTBUG-35256 and QTBUG-47162.
        #
        # Fix the files.
        #
        for i in $HOME/Qt$QT_VERSION/$QT_MAJOR_MINOR_VERSION/clang_64/lib/pkgconfig/*.pc
        do
            ed - $i <<EOF
H
g/Cflags: /s;;Cflags: -F\${libdir} ;
g/Cflags: /s;-I\${includedir}/Qt\([a-zA-Z0-9_]*\);-I\${libdir}/Qt\1.framework/Versions/5/Headers;
g/Libs: /s;';;g
w
q
EOF
        done
        touch qt-$QT_VERSION-done
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
            rm -rf qt-opensource-mac-x64-clang-$installed_qt_version.dmg
        fi

        installed_qt_version=""
    fi
}

install_libpng() {
    if [ ! -f libpng-$PNG_VERSION-done ] ; then
        echo "Downloading, building, and installing libpng:"
        #
        # The FTP site puts libpng x.y.* into a libpngxy directory.
        #
        subdir=`echo $PNG_VERSION | sed 's/\([1-9][0-9]*\)\.\([1-9][0-9]*\).*/libpng\1\2'/`
        [ -f libpng-$PNG_VERSION.tar.xz ] || curl -O ftp://ftp.simplesystems.org/pub/libpng/png/src/$subdir/libpng-$PNG_VERSION.tar.xz
        xzcat libpng-$PNG_VERSION.tar.xz | tar xf - || exit 1
        cd libpng-$PNG_VERSION
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch libpng-$PNG_VERSION-done
    fi
}

uninstall_libpng() {
    if [ ! -z "$installed_libpng_version" ] ; then
        #
        # Cairo depends on this, so uninstall it.
        #
        uninstall_cairo "$@"

        echo "Uninstalling libpng:"
        cd libpng-$installed_libpng_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm libpng-$installed_libpng_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf libpng-$installed_libpng_version
            rm -rf libpng-$installed_libpng_version.tar.xz
        fi

        installed_libpng_version=""
    fi
}

install_pixman() {
    if [ ! -f pixman-$PIXMAN_VERSION-done ] ; then
        echo "Downloading, building, and installing pixman:"
        [ -f pixman-$PIXMAN_VERSION.tar.gz ] || curl -O http://www.cairographics.org/releases/pixman-$PIXMAN_VERSION.tar.gz
        gzcat pixman-$PIXMAN_VERSION.tar.gz | tar xf - || exit 1
        cd pixman-$PIXMAN_VERSION
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch pixman-$PIXMAN_VERSION-done
    fi
}

uninstall_pixman() {
    if [ ! -z "$installed_pixman_version" ] ; then
        #
        # Cairo depends on this, so uninstall it.
        #
        uninstall_cairo "$@"

        echo "Uninstalling pixman:"
        cd pixman-$installed_pixman_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm pixman-$installed_pixman_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf pixman-$installed_pixman_version
            rm -rf pixman-$installed_pixman_version.tar.gz
        fi

        installed_pixman_version=""
    fi
}

install_cairo() {
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
        # CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --enable-quartz=no || exit 1
        # Maybe follow http://cairographics.org/end_to_end_build_for_mac_os_x/
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --enable-quartz=yes || exit 1
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
}

uninstall_cairo() {
    if [ ! -z "$installed_cairo_version" ] ; then
        #
        # GTK+ depends on this, so uninstall it.
        #
        uninstall_gtk "$@"

        echo "Uninstalling Cairo:"
        cd cairo-$installed_cairo_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm cairo-$installed_cairo_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf cairo-$installed_cairo_version
            rm -rf cairo-$installed_cairo_version.tar.xz cairo-$installed_cairo_version.tar.gz
        fi

        installed_cairo_version=""
    fi
}

install_atk() {
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
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch atk-$ATK_VERSION-done
    fi
}

uninstall_atk() {
    if [ ! -z "$installed_atk_version" ] ; then
        #
        # GTK+ depends on this, so uninstall it.
        #
        uninstall_gtk "$@"

        echo "Uninstalling ATK:"
        cd atk-$installed_atk_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm atk-$installed_atk_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf atk-$installed_atk_version
            rm -rf atk-$installed_atk_version.tar.xz atk-$installed_atk_version.tar.bz2
        fi

        installed_atk_version=""
    fi
}

install_pango() {
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
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch pango-$PANGO_VERSION-done
    fi
}

uninstall_pango() {
    if [ ! -z "$installed_pango_version" ] ; then
        #
        # GTK+ depends on this, so uninstall it.
        #
        uninstall_gtk "$@"

        echo "Uninstalling Pango:"
        cd pango-$installed_pango_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm pango-$installed_pango_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf pango-$installed_pango_version
            rm -rf pango-$installed_pango_version.tar.xz pango-$installed_pango_version.tar.bz2
        fi

        installed_pango_version=""
    fi
}

install_gdk_pixbuf() {
    if [ "$GDK_PIXBUF_VERSION" -a ! -f gdk-pixbuf-$GDK_PIXBUF_VERSION-done ] ; then
        echo "Downloading, building, and installing gdk-pixbuf:"
        gdk_pixbuf_dir=`expr $GDK_PIXBUF_VERSION : '\([0-9][0-9]*\.[0-9][0-9]*\).*'`
        [ -f gdk-pixbuf-$GDK_PIXBUF_VERSION.tar.xz ] || curl -L -O http://ftp.gnome.org/pub/gnome/sources/gdk-pixbuf/$gdk_pixbuf_dir/gdk-pixbuf-$GDK_PIXBUF_VERSION.tar.xz || exit 1
        xzcat gdk-pixbuf-$GDK_PIXBUF_VERSION.tar.xz | tar xf - || exit 1
        cd gdk-pixbuf-$GDK_PIXBUF_VERSION
        #
        # If we're building using the 10.6 SDK, force the use of libpng12.
        #
        # The OS's X11, and corresponding SDK, didn't introduce libpng15,
        # or pkg-config files, until 10.7, so, for 10.6 have to explicitly
        # set LIBPNG to override the configure script, and also force the
        # CFLAGS to look for the header files for libpng12 (note that
        # -isysroot doesn't affect the arguments to -I, so we need to
        # include the SDK path explicitly).
        #
        if [[ "$sdk_target" = 10.6 ]]
        then
            LIBPNG="-L/usr/X11/lib -lpng12" CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS -I$SDKPATH/usr/X11/include/libpng12" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS -I$SDKPATH/usr/X11/include/libpng12" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --without-libtiff --without-libjpeg || exit 1
        else
            CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --without-libtiff --without-libjpeg || exit 1
        fi
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch gdk-pixbuf-$GDK_PIXBUF_VERSION-done
    fi
}

uninstall_gdk_pixbuf() {
    if [ ! -z "$installed_gdk_pixbuf_version" ] ; then
        #
        # GTK+ depends on this, so uninstall it.
        #
        uninstall_gtk "$@"

        echo "Uninstalling gdk-pixbuf:"
        cd gdk-pixbuf-$installed_gdk_pixbuf_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm gdk-pixbuf-$installed_gdk_pixbuf_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf gdk-pixbuf-$installed_gdk_pixbuf_version
            rm -rf gdk-pixbuf-$installed_gdk_pixbuf_version.tar.xz
        fi

        installed_gdk_pixbuf_version=""
    fi
}

install_gtk() {
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
            CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --disable-cups --without-libtiff --without-libjpeg || exit 1
        else
            CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --without-libtiff --without-libjpeg || exit 1
        fi
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch gtk+-$GTK_VERSION-done
    fi
}

uninstall_gtk() {
    if [ ! -z "$installed_gtk_version" ] ; then
        echo "Uninstalling GTK+:"
        cd gtk+-$installed_gtk_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm gtk+-$installed_gtk_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf gtk+-$installed_gtk_version
            rm -rf gtk+-$installed_gtk_version.tar.xz gtk+-$installed_gtk_version.tar.bz2
        fi

        installed_gtk_version=""
    fi
}

install_libsmi() {
    if [ "$LIBSMI_VERSION" -a ! -f libsmi-$LIBSMI_VERSION-done ] ; then
        echo "Downloading, building, and installing libsmi:"
        [ -f libsmi-$LIBSMI_VERSION.tar.gz ] || curl -L -O https://www.ibr.cs.tu-bs.de/projects/libsmi/download/libsmi-$LIBSMI_VERSION.tar.gz || exit 1
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
        [ -f libgpg-error-$LIBGPG_ERROR_VERSION.tar.bz2 ] || curl -L -O ftp://ftp.gnupg.org/gcrypt/libgpg-error/libgpg-error-$LIBGPG_ERROR_VERSION.tar.bz2 || exit 1
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
        CFLAGS="$CFLAGS -std=gnu89 $VERSION_MIN_FLAGS $SDKFLAGS" CFLAGS="$CFLAGS -std=gnu89 $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --disable-asm || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch libgcrypt-$LIBGCRYPT_VERSION-done
    fi
}

uninstall_libgcrypt() {
    if [ ! -z "$installed_libgcrypt_version" ] ; then
        #
        # GnuTLS depends on this, so uninstall it.
        #
        uninstall_gnutls "$@"

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

install_gnutls() {
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
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --with-libgcrypt --without-p11-kit || exit 1
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

install_portaudio() {
    #
    # Check for both the old versionless portaudio-done and the new
    # versioned -done file.
    #
    if [ "$PORTAUDIO_VERSION" -a ! -f portaudio-$PORTAUDIO_VERSION-done ] ; then
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
        # Explicitly disable deprecation, so the damn thing will build
        # on El Capitan with Xcode 7.
        #
        CFLAGS="$CFLAGS -Wno-deprecated-declarations -mmacosx-version-min=10.4 $SDKFLAGS" CXXFLAGS="$CXXFLAGS -mmacosx-version-min=10.4 $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure --disable-mac-universal || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch portaudio-$PORTAUDIO_VERSION-done
    fi
}

uninstall_portaudio() {
    if [ ! -z "$installed_portaudio_version" ] ; then
        echo "Uninstalling PortAudio:"
        cd portaudio
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm portaudio-$installed_portaudio_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf portaudio
            rm -rf $installed_portaudio_version.tgz
        fi

        installed_portaudio_version=""
    fi
}

install_geoip() {
    if [ "$GEOIP_VERSION" -a ! -f geoip-$GEOIP_VERSION-done ] ; then
        echo "Downloading, building, and installing GeoIP API:"
        [ -f GeoIP-$GEOIP_VERSION.tar.gz ] || curl -L -O http://geolite.maxmind.com/download/geoip/api/c/GeoIP-$GEOIP_VERSION.tar.gz || exit 1
        gzcat GeoIP-$GEOIP_VERSION.tar.gz | tar xf - || exit 1
        cd GeoIP-$GEOIP_VERSION
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
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
}

uninstall_geoip() {
    if [ ! -z "$installed_geoip_version" ] ; then
        echo "Uninstalling GeoIP API:"
        cd GeoIP-$installed_geoip_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm geoip-$installed_geoip_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf GeoIP-$installed_geoip_version
            rm -rf GeoIP-$installed_geoip_version.tar.gz
        fi

        installed_geoip_version=""
    fi
}

install_c_ares() {
    if [ "$CARES_VERSION" -a ! -f c-ares-$CARES_VERSION-done ] ; then
        echo "Downloading, building, and installing C-Ares API:"
        [ -f c-ares-$CARES_VERSION.tar.gz ] || curl -L -O http://c-ares.haxx.se/download/c-ares-$CARES_VERSION.tar.gz || exit 1
        gzcat c-ares-$CARES_VERSION.tar.gz | tar xf - || exit 1
        cd c-ares-$CARES_VERSION
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS"  LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" ./configure || exit 1
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
        [ -f libssh-$LIBSSH_VERSION.tar.xz ] || curl -L -O https://red.libssh.org/attachments/download/195/libssh-$LIBSSH_VERSION.tar.xz || exit 1
        xzcat libssh-$LIBSSH_VERSION.tar.xz | tar xf - || exit 1
        cd libssh-$LIBSSH_VERSION
        mkdir build
        cd build
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS"  LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" cmake -DWITH_GCRYPT=1 ../ || exit 1
        make $MAKE_BUILD_OPTS || exit 1
        $DO_MAKE_INSTALL || exit 1
        cd ../..
        touch libssh-$LIBSSH_VERSION-done
    fi
}

uninstall_libssh() {
    if [ ! -z "$installed_libssh_version" ] ; then
        echo "Sadly, libssh uses cmake, and doesn't support uninstall."
    fi
}

install_all() {
    #
    # Check whether the versions we have installed are the versions
    # requested; if not, uninstall the installed versions.
    #
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

    if [ ! -z "$installed_geoip_version" -a \
              "$installed_geoip_version" != "$GEOIP_VERSION" ] ; then
        echo "Installed GeoIP API version is $installed_geoip_version"
        if [ -z "$GEOIP_VERSION" ] ; then
            echo "GeoIP is not requested"
        else
            echo "Requested GeoIP version is $GEOIP_VERSION"
        fi
        uninstall_geoip -r
    fi

    if [ ! -z "$installed_portaudio_version" -a \
              "$installed_portaudio_version" != "$PORTAUDIO_VERSION" ] ; then
        echo "Installed PortAudio version is $installed_portaudio_version"
        if [ -z "$PORTAUDIO_VERSION" ] ; then
            echo "PortAudio is not requested"
        else
            echo "Requested PortAudio version is $PORTAUDIO_VERSION"
        fi
        uninstall_portaudio -r
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

    if [ ! -z "$installed_gtk_version" -a \
              "$installed_gtk_version" != "$GTK_VERSION" ] ; then
        echo "Installed GTK+ version is $installed_gtk_version"
        if [ -z "$GTK_VERSION" ] ; then
            echo "GTK+ is not requested"
        else
            echo "Requested GTK+ version is $GTK_VERSION"
        fi
        uninstall_gtk -r
    fi

    if [ ! -z "$installed_gdk_pixbuf_version" -a \
              "$installed_gdk_pixbuf_version" != "$GDK_PIXBUF_VERSION" ] ; then
        echo "Installed gdk-pixbuf version is $installed_gdk_pixbuf_version"
        if [ -z "$GDK_PIXBUF_VERSION" ] ; then
            echo "gdk-pixbuf is not requested"
        else
            echo "Requested gdk-pixbuf version is $GDK_PIXBUF_VERSION"
        fi
        uninstall_gdk_pixbuf -r
    fi

    if [ ! -z "$installed_pango_version" -a \
              "$installed_pango_version" != "$PANGO_VERSION" ] ; then
        echo "Installed Pango version is $installed_pango_version"
        if [ -z "$PANGO_VERSION" ] ; then
            echo "Pango is not requested"
        else
            echo "Requested Pango version is $PANGO_VERSION"
        fi
        uninstall_pango -r
    fi

    if [ ! -z "$installed_atk_version" -a \
              "$installed_atk_version" != "$ATK_VERSION" ] ; then
        echo "Installed ATK version is $installed_atk_version"
        if [ -z "$ATK_VERSION" ] ; then
            echo "ATK is not requested"
        else
            echo "Requested ATK version is $ATK_VERSION"
        fi
        uninstall_atk -r
    fi

    if [ ! -z "$installed_cairo_version" -a \
              "$installed_cairo_version" != "$CAIRO_VERSION" ] ; then
        echo "Installed Cairo version is $installed_cairo_version"
        if [ -z "$CAIRO_VERSION" ] ; then
            echo "Cairo is not requested"
        else
            echo "Requested Cairo version is $CAIRO_VERSION"
        fi
        uninstall_cairo -r
    fi

    if [ ! -z "$installed_pixman_version" -a \
              "$installed_pixman_version" != "$PIXMAN_VERSION" ] ; then
        echo "Installed pixman version is $installed_pixman_version"
        if [ -z "$PIXMAN_VERSION" ] ; then
            echo "pixman is not requested"
        else
            echo "Requested pixman version is $PIXMAN_VERSION"
        fi
        uninstall_pixman -r
    fi

    if [ ! -z "$installed_libpng_version" -a \
              "$installed_libpng_version" != "$PNG_VERSION" ] ; then
        echo "Installed libpng version is $installed_libpng_version"
        if [ -z "$PNG_VERSION" ] ; then
            echo "libpng is not requested"
        else
            echo "Requested libpng version is $PNG_VERSION"
        fi
        uninstall_libpng -r
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

    if [ ! -z "$installed_cmake_version" -a \
              "$installed_cmake_version" != "$CMAKE_VERSION" ] ; then
        echo "Installed CMake version is $installed_cmake_version"
        if [ -z "$CMAKE_VERSION" ] ; then
            echo "CMake is not requested"
        else
            echo "Requested CMake version is $CMAKE_VERSION"
        fi
        #
        # XXX - really remove this?
        # Or should we remember it as installed only if this script
        # installed it?
        #
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

    #
    # Start with xz: It is the sole download format of glib later than 2.31.2
    #
    install_xz

    install_autoconf

    install_automake

    install_libtool

    install_cmake

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
            install_libpng

            #
            # The libpixman versions that come with the X11s for Leopard,
            # Snow Leopard, and Lion is too old to support Cairo's image
            # surface backend feature (which requires pixman-1 >= 0.22.0).
            #
            # XXX - what about the one that comes with the latest version
            # of Xquartz?
            #
            install_pixman

            #
            # And now Cairo itself.
            # XXX - with the libxcb that comes with 10.6,
            # xcb_discard_reply() is missing, and the build fails.
            #
            install_cairo
        fi

        install_atk

        install_pango

        install_gdk_pixbuf

        install_gtk
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

    install_libsmi

    install_libgpg_error

    install_libgcrypt

    install_gnutls

    install_lua

    install_portaudio

    install_geoip

    install_c_ares

    install_libssh
}

uninstall_all() {
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
        uninstall_libssh

        uninstall_c_ares

        uninstall_geoip

        uninstall_portaudio

        uninstall_lua

        uninstall_gnutls

        uninstall_libgcrypt

        uninstall_libgpg_error

        uninstall_libsmi

        uninstall_gtk

        uninstall_gdk_pixbuf

        uninstall_pango

        uninstall_atk

        uninstall_cairo

        uninstall_pixman

        uninstall_libpng

        uninstall_qt

        uninstall_glib

        uninstall_pkg_config

        uninstall_gettext

        #
        # XXX - really remove this?
        # Or should we remember it as installed only if this script
        # installed it?
        #
        uninstall_cmake

        uninstall_libtool

        uninstall_automake

        uninstall_autoconf

        uninstall_xz
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

        #
        # That's also the OS whose SDK we'd be using.
        #
        sdk_target=$min_osx_target
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

#
# Get the version numbers of installed packages, if any.
#
if [ -d macosx-support-libs ]
then
    cd macosx-support-libs

    installed_xz_version=`ls xz-*-done 2>/dev/null | sed 's/xz-\(.*\)-done/\1/'`
    installed_autoconf_version=`ls autoconf-*-done 2>/dev/null | sed 's/autoconf-\(.*\)-done/\1/'`
    installed_automake_version=`ls automake-*-done 2>/dev/null | sed 's/automake-\(.*\)-done/\1/'`
    installed_libtool_version=`ls libtool-*-done 2>/dev/null | sed 's/libtool-\(.*\)-done/\1/'`
    installed_cmake_version=`ls cmake-*-done 2>/dev/null | sed 's/cmake-\(.*\)-done/\1/'`
    installed_gettext_version=`ls gettext-*-done 2>/dev/null | sed 's/gettext-\(.*\)-done/\1/'`
    installed_pkg_config_version=`ls pkg-config-*-done 2>/dev/null | sed 's/pkg-config-\(.*\)-done/\1/'`
    installed_glib_version=`ls glib-*-done 2>/dev/null | sed 's/glib-\(.*\)-done/\1/'`
    installed_qt_version=`ls qt-*-done 2>/dev/null | sed 's/qt-\(.*\)-done/\1/'`
    installed_libpng_version=`ls libpng-*-done 2>/dev/null | sed 's/libpng-\(.*\)-done/\1/'`
    installed_pixman_version=`ls pixman-*-done 2>/dev/null | sed 's/pixman-\(.*\)-done/\1/'`
    installed_cairo_version=`ls cairo-*-done 2>/dev/null | sed 's/cairo-\(.*\)-done/\1/'`
    installed_atk_version=`ls atk-*-done 2>/dev/null | sed 's/atk-\(.*\)-done/\1/'`
    installed_pango_version=`ls pango-*-done 2>/dev/null | sed 's/pango-\(.*\)-done/\1/'`
    installed_gdk_pixbuf_version=`ls gdk-pixbuf-*-done 2>/dev/null | sed 's/gdk-pixbuf-\(.*\)-done/\1/'`
    installed_gtk_version=`ls gtk+-*-done 2>/dev/null | sed 's/gtk+-\(.*\)-done/\1/'`
    installed_libsmi_version=`ls libsmi-*-done 2>/dev/null | sed 's/libsmi-\(.*\)-done/\1/'`
    installed_libgpg_error_version=`ls libgpg-error-*-done 2>/dev/null | sed 's/libgpg-error-\(.*\)-done/\1/'`
    installed_libgcrypt_version=`ls libgcrypt-*-done 2>/dev/null | sed 's/libgcrypt-\(.*\)-done/\1/'`
    installed_gnutls_version=`ls gnutls-*-done 2>/dev/null | sed 's/gnutls-\(.*\)-done/\1/'`
    installed_lua_version=`ls lua-*-done 2>/dev/null | sed 's/lua-\(.*\)-done/\1/'`
    installed_portaudio_version=`ls portaudio-*-done 2>/dev/null | sed 's/portaudio-\(.*\)-done/\1/'`
    installed_geoip_version=`ls geoip-*-done 2>/dev/null | sed 's/geoip-\(.*\)-done/\1/'`
    installed_cares_version=`ls c-ares-*-done 2>/dev/null | sed 's/c-ares-\(.*\)-done/\1/'`
    installed_libssh_version=`ls libssh-*-done 2>/dev/null | sed 's/libssh-\(.*\)-done/\1/'`

    #
    # If we don't have a versioned -done file for portaudio, but do have
    # an unversioned -done file for it, assume the installed version is the
    # requested version, and rename the -done file to include that version.
    #
    if [ -z "$installed_portaudio_version" -a -f portaudio-done ] ; then
        mv portaudio-done portaudio-$PORTAUDIO_VERSION-done
        installed_portaudio_version=`ls portaudio-*-done 2>/dev/null | sed 's/portaudio-\(.*\)-done/\1/'`
    fi

    cd ..
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
    # We'll worry about that if, as, and when there's ever
    # an OS XI.
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
                qt_sdk_arg="-sdk $sdk"
                break 2
            fi
        done
    done

    if [ -z "$sdkpath" ]
    then
        echo "macosx-setup.sh: Couldn't find an SDK for OS X $min_osx_target or later" 1>&2
        exit 1
    fi

    SDKPATH="$sdkpath"
    sdk_target=10.$sdk_real_version
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
        if [ "$CAIRO_VERSION" ]
        then
            CAIRO_VERSION=1.6.4
        fi
        if [ "$ATK_VERSION" ]
        then
            ATK_VERSION=1.24.0
        fi
        if [ "$PANGO_VERSION" ]
        then
            PANGO_VERSION=1.20.2
        fi
        if [ "$GTK_VERSION" ]
        then
            GTK_VERSION=2.12.9
        fi

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
if [ "$GTK_VERSION" ]; then
    #
    # If we're building with GTK+, you also need the X11 SDK; with at least
    # some versions of OS X and Xcode, that is, I think, an optional install.
    # (Or it might be installed with X11, but I think *that* is an optional
    # install on at least some versions of OS X.)
    #
    if [ ! -d /usr/X11/include ]; then
        echo "Please install X11 and the X11 SDK first."
        echo "  You can either download the latest package from"
        echo "  http://www.xquartz.org/ and install it or install"
        echo "  the native Apple package if you are on Lion or below."
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

install_all

echo ""

#
# Indicate what paths to use for pkg-config and cmake.
#
pkg_config_path=/usr/local/lib/pkgconfig
if [ "$QT_VERSION" ]; then
    qt_base_path=$HOME/Qt$QT_VERSION/$QT_MAJOR_MINOR_VERSION/clang_64
    pkg_config_path="$pkg_config_path":"$qt_base_path/lib/pkgconfig"
    CMAKE_PREFIX_PATH="$CMAKE_PREFIX_PATH":"$qt_base_path/lib/cmake"
fi
pkg_config_path="$pkg_config_path":/usr/X11/lib/pkgconfig

echo "You are now prepared to build Wireshark."
echo
if [[ $CMAKE ]]; then
    echo "To build with CMAKE:"
    echo
    echo "export PKG_CONFIG_PATH=$pkg_config_path"
    echo "export CMAKE_PREFIX_PATH=$CMAKE_PREFIX_PATH"
    echo "export PATH=$PATH:$qt_base_path/bin"
    echo
    echo "mkdir build; cd build"
    echo "cmake .."
    echo "make $MAKE_BUILD_OPTS app_bundle"
    echo "make install/strip"
    echo
fi
if [[ $AUTOTOOLS ]]; then
    echo "To build with AUTOTOOLS:"
    echo
    echo "export PKG_CONFIG_PATH=$pkg_config_path"
    echo
    echo "./autogen.sh"
    echo "mkdir build; cd build"
    echo "../configure"
    echo "make $MAKE_BUILD_OPTS"
    echo "make install"
    echo
fi
echo "Make sure you are allowed capture access to the network devices"
echo "See: https://wiki.wireshark.org/CaptureSetup/CapturePrivileges"
echo

exit 0
