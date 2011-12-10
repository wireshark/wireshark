#!/bin/sh
# Setup development environment on Mac OS X (tested with 10.6.8 and Xcode 3.2.6)
#
# $Id$
#
# Trying to follow "Building Wireshark on SnowLeopard"
# given by Michael Tuexen at
# http://nplab.fh-muenster.de/groups/wiki/wiki/fb7a4/Building_Wireshark_on_SnowLeopard.html 
#

#
# Versions to download and install.
#
# The following libraries are required.
#
GETTEXT_VERSION=0.18.1.1
GLIB_VERSION=2.31.2
#
# pkg-config 0.26 appears to have broken the "we have our own GLib"
# stuff, even if you explicitly set GLIB_CFLAGS and GLIB_LIBS.
# Life's too short to work around the circular dependency in a script,
# so we use 0.25 instead.
#
PKG_CONFIG_VERSION=0.26
ATK_VERSION=2.0.1
PANGO_VERSION=1.29.5
GDK_PIXBUF_VERSION=2.24.0
GTK_VERSION=2.24.8

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
LIBGCRYPT_VERSION=1.4.6
GNUTLS_VERSION=2.12.7
LUA_VERSION=5.1.4
PORTAUDIO_VERSION=pa_stable_v19_20111121
#
# XXX - they appear to have an unversioned gzipped tarball for the
# current version; should we just download that, with some other
# way of specifying whether to download the GeoIP API?
#
GEOIP_VERSION=1.4.8

#
# You need Xcode installed to get the compilers.
#
if [ ! -x /usr/bin/xcodebuild ]; then
	echo "Please install Xcode first (should be available on DVD or from http://developer.apple.com/xcode/index.php)."
	exit 1
fi

#
# You also need the X11 SDK; with at least some versions of OS X and
# Xcode, that is, I think, an optional install.  (Or it might be
# installed with X11, but I think *that* is an optional install on
# at least some versions of OS X.)
#
if [ ! -d /usr/X11/include ]; then
	echo "Please install X11 and the X11 SDK first."
	exit 1
fi

#
# Do we have permission to write in /usr/local?
#
# If so, assume we have permission to write in its subdirectories.
# (If that's not the case, this test needs to check the subdirectories
# as well.)
#
# If not, do "make install" with sudo.
#
if [ -w /usr/local ]
then
	DO_MAKE_INSTALL="make install"
else
	DO_MAKE_INSTALL="sudo make install"
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
echo "Downloading, building, and installing GNU gettext:"
curl -O http://ftp.gnu.org/pub/gnu/gettext/gettext-$GETTEXT_VERSION.tar.gz || exit 1
tar xf gettext-$GETTEXT_VERSION.tar.gz || exit 1
cd gettext-$GETTEXT_VERSION
CFLAGS="-D_FORTIFY_SOURCE=0" ./configure || exit 1
make -j 3 || exit 1
$DO_MAKE_INSTALL || exit 1
cd ..

echo "Downloading, building, and installing GLib:"
glib_dir=`expr $GLIB_VERSION : '\([0-9][0-9]*\.[0-9][0-9]*\).*'`
curl -L -O http://ftp.gnome.org/pub/gnome/sources/glib/$glib_dir/glib-$GLIB_VERSION.tar.bz2 || exit 1
bzcat glib-$GLIB_VERSION.tar.bz2 | tar xf - || exit 1
cd glib-$GLIB_VERSION
#
# OS X ships with libffi, but doesn't provide its pkg-config file;
# explicitly specify LIBFFI_CFLAGS and LIBFFI_LIBS, so the configure
# script doesn't try to use pkg-config to get the appropriate
# CFLAGS and LIBS.
#
LIBFFI_CFLAGS="-I/usr/include/ffi" LIBFFI_LIBS="-L/usr/lib" ./configure || exit 1
#
# Mac OS X on 64-bit platforms provides libiconv, but in a form that
# confuses GLib.
#
patch -p1 < ../../macosx-support-lib-patches/glib-gconvert.patch || exit 1
make -j 3 || exit 1
# Apply patch: we depend on libffi, but pkg-config doesn't get told.
patch -p0 <../../macosx-support-lib-patches/glib-pkgconfig.patch || exit 1
$DO_MAKE_INSTALL || exit 1
cd ..

echo "Downloading, building, and installing pkg-config:"
curl -O http://pkgconfig.freedesktop.org/releases/pkg-config-$PKG_CONFIG_VERSION.tar.gz || exit 1
tar xf pkg-config-$PKG_CONFIG_VERSION.tar.gz || exit 1
cd pkg-config-$PKG_CONFIG_VERSION
# Avoid another pkgconfig call
GLIB_CFLAGS="-I/usr/local/include/glib-2.0 -I/usr/local/lib/glib-2.0/include" GLIB_LIBS="-L/usr/local/lib -lglib-2.0 -lintl" ./configure || exit 1
# ./configure || exit 1
make -j 3 || exit 1
$DO_MAKE_INSTALL || exit 1
cd ..

#
# Now we have reached a point where we can build everything but
# the GUI (Wireshark).
#

#
# Cairo is part of Mac OS X 10.6 (and, I think, 10.5).
# However, it's an X11 library; if we build with "native" GTK+ rather
# than X11 GTK+, we might have to build and install Cairo.
#
# echo "Downloading, building, and installing Cairo:"
# curl -O http://cairographics.org/releases/cairo-1.10.2.tar.gz || exit 1
# tar xvfz cairo-1.10.2.tar.gz || exit 1
# cd cairo-1.10.2
# ./configure --enable-quartz=no || exit 1
# make -j 3 || exit 1
# $DO_MAKE_INSTALL || exit 1
# cd ..

echo "Downloading, building, and installing ATK:"
atk_dir=`expr $ATK_VERSION : '\([0-9][0-9]*\.[0-9][0-9]*\).*'`
curl -O http://ftp.gnome.org/pub/gnome/sources/atk/$atk_dir/atk-$ATK_VERSION.tar.bz2 || exit 1
bzcat atk-$ATK_VERSION.tar.bz2 | tar xf - || exit 1
cd atk-$ATK_VERSION
./configure || exit 1
make -j 3 || exit 1
$DO_MAKE_INSTALL || exit 1
cd ..

echo "Downloading, building, and installing Pango:"
pango_dir=`expr $PANGO_VERSION : '\([0-9][0-9]*\.[0-9][0-9]*\).*'`
curl -L -O http://ftp.gnome.org/pub/gnome/sources/pango/$pango_dir/pango-$PANGO_VERSION.tar.bz2
bzcat pango-$PANGO_VERSION.tar.bz2 | tar xf - || exit 1
cd pango-$PANGO_VERSION
./configure || exit 1
make -j 3 || exit 1
$DO_MAKE_INSTALL || exit 1
cd ..

echo "Downloading, building, and installing gdk-pixbuf:"
gdk_pixbuf_dir=`expr $GDK_PIXBUF_VERSION : '\([0-9][0-9]*\.[0-9][0-9]*\).*'`
curl -L -O http://ftp.gnome.org/pub/gnome/sources/gdk-pixbuf/$gdk_pixbuf_dir/gdk-pixbuf-$GDK_PIXBUF_VERSION.tar.bz2 || exit 1
bzcat gdk-pixbuf-$GDK_PIXBUF_VERSION.tar.bz2 | tar xf - || exit 1
cd gdk-pixbuf-$GDK_PIXBUF_VERSION
./configure --without-libtiff --without-libjpeg || exit 1
make -j 3 || exit 1
$DO_MAKE_INSTALL || exit 1
cd ..

echo "Downloading, building, and installing GTK+:"
gtk_dir=`expr $GTK_VERSION : '\([0-9][0-9]*\.[0-9][0-9]*\).*'`
curl -L -O http://ftp.gnome.org/pub/gnome/sources/gtk+/$gtk_dir/gtk+-$GTK_VERSION.tar.bz2
bzcat gtk+-$GTK_VERSION.tar.bz2 | tar xf - || exit 1
cd gtk+-$GTK_VERSION
./configure || exit 1
make -j 3 || exit 1
$DO_MAKE_INSTALL || exit 1
cd ..

#
# Now we have reached a point where we can build everything including
# the GUI (Wireshark), but not with any optional features such as
# SNMP OID resolution, some forms of decryption, Lua scripting, playback
# of audio, or GeoIP mapping of IP addresses.
#
# We now conditionally download optional libraries to support them;
# the default is to download them all.
#

if [ ! -z $LIBSMI_VERSION ]
then
	echo "Downloading, building, and installing libsmi:"
	curl -L -O ftp://ftp.ibr.cs.tu-bs.de/pub/local/libsmi/libsmi-$LIBSMI_VERSION.tar.gz || exit 1
	tar xf libsmi-$LIBSMI_VERSION.tar.gz || exit 1
	cd libsmi-$LIBSMI_VERSION
	./configure || exit 1
	make -j 3 || exit 1
	$DO_MAKE_INSTALL || exit 1
	cd ..
fi

if [ ! -z $LIBGPG_ERROR_VERSION ]
then
	echo "Downloading, building, and installing libgpg-error:"
	curl -L -O ftp://ftp.gnupg.org/gcrypt/libgpg-error/libgpg-error-$LIBGPG_ERROR_VERSION.tar.bz2 || exit 1
	bzcat libgpg-error-$LIBGPG_ERROR_VERSION.tar.bz2 | tar xf - || exit 1
	cd libgpg-error-$LIBGPG_ERROR_VERSION
	./configure || exit 1
	make -j 3 || exit 1
	$DO_MAKE_INSTALL || exit 1
	cd ..
fi

if [ ! -z $LIBGCRYPT_VERSION ]
then
	#
	# libgpg-error is required for libgcrypt.
	#
	if [ -z $LIBGPG_ERROR_VERSION ]
	then
		echo "libgcrypt requires libgpg-error, but you didn't install libgpg-error." 1>&2
		exit 1
	fi

	echo "Downloading, building, and installing libgcrypt:"
	curl -L -O ftp://ftp.gnupg.org/gcrypt/libgcrypt/libgcrypt-$LIBGCRYPT_VERSION.tar.gz || exit 1
	tar xf libgcrypt-$LIBGCRYPT_VERSION.tar.gz || exit 1
	cd libgcrypt-$LIBGCRYPT_VERSION
	#
	# The assembler language code is not compatible with the OS X
	# x86 assembler (or is it an x86-64 vs. x86-32 issue?).
	#
	./configure --disable-asm || exit 1
	make -j 3 || exit 1
	$DO_MAKE_INSTALL || exit 1
	cd ..
fi

if [ ! -z $GNUTLS_VERSION ]
then
	#
	# GnuTLS requires libgcrypt (or nettle, in newer versions).
	#
	if [ -z $LIBGCRYPT_VERSION ]
	then
		echo "GnuTLS requires libgcrypt, but you didn't install libgcrypt" 1>&2
		exit 1
	fi

	echo "Downloading, building, and installing GnuTLS:"
	curl -L -O http://ftp.gnu.org/gnu/gnutls/gnutls-$GNUTLS_VERSION.tar.bz2 || exit 1
	bzcat gnutls-$GNUTLS_VERSION.tar.bz2 | tar xf - || exit 1
	cd gnutls-$GNUTLS_VERSION
	#
	# Use libgcrypt, not nettle.
	# XXX - is there some reason to prefer nettle?  Or does
	# Wireshark directly use libgcrypt routines?
	#
	./configure --with-libgcrypt || exit 1
	make -j 3 || exit 1
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
	patch -p0 lib/gnutls.pc <../../macosx-support-lib-patches/gnutls-pkgconfig.patch || exit 1
	$DO_MAKE_INSTALL || exit 1
	cd ..
fi

if [ ! -z $LUA_VERSION ]
then
	echo "Downloading, building, and installing Lua:"
	curl -L -O http://www.lua.org/ftp/lua-$LUA_VERSION.tar.gz || exit 1
	tar xf lua-$LUA_VERSION.tar.gz || exit 1
	cd lua-$LUA_VERSION
	make -j 3 macosx || exit 1
	$DO_MAKE_INSTALL || exit 1
	cd ..
fi

if [ ! -z $PORTAUDIO_VERSION ]
then
	echo "Downloading, building, and installing PortAudio:"
	curl -L -O http://www.portaudio.com/archives/$PORTAUDIO_VERSION.tgz || exit 1
	tar xf $PORTAUDIO_VERSION.tgz || exit 1
	cd portaudio
	./configure || exit 1
	make -j 3 || exit 1
	$DO_MAKE_INSTALL || exit 1
	cd ..
fi

if [ ! -z $GEOIP_VERSION ]
then
	echo "Downloading, building, and installing GeoIP API:"
	curl -L -O http://geolite.maxmind.com/download/geoip/api/c/GeoIP-$GEOIP_VERSION.tar.gz || exit 1
	tar xf GeoIP-$GEOIP_VERSION.tar.gz || exit 1
	cd GeoIP-$GEOIP_VERSION
	./configure || exit 1
	make -j 3 || exit 1
	$DO_MAKE_INSTALL || exit 1
	cd ..
fi

echo ""

echo "You are now prepared to build Wireshark. To do so do:"
echo "./autogen.sh"
echo "./configure"
echo "make -j 3"
echo "make install"

echo ""

echo "Make sure you are allowed capture access to the network devices"
echo "See: http://wiki.wireshark.org/CaptureSetup/CapturePrivileges"

echo ""

exit 0
