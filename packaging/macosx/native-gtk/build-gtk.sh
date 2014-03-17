#!/bin/sh
#
# Based on the Imendio 'build-gtk.sh' script.
#
# Inkscape (Wireshark) build additions by Michael Wybrow <mjwybrow@users.sf.net>
#
# See the following page for build instructions:
# http://developer.imendio.com/projects/gtk-macosx/build-instructions
#
# Usage:
# export PREFIX=/your/install/prefix
# ./build-gtk bootstrap
# ./build-gtk build wireshark
#

# XXX: Check for xargs with -i
#
# In lib/pkgconfig/freetpe2.pc
#
# -  Libs: -L${libdir} -lfreetype -lz
# +  Libs: -L${libdir} -lfreetype -lz -Wl,-framework,CoreServices,-framework,ApplicationServices
#
# bin/freetype-config
#
# -  libs="-lfreetype -lz"
# +  libs="-lfreetype -lz -Wl,-framework,CoreServices,-framework,ApplicationServices"
#
# In lib/pkgconfig/fontconfig.pc
#	Add -lexpat
#

version=1.3.1-wireshark


SCRIPTDIR=`dirname $0`

export PREFIX=${PREFIX-/opt/gtk}
export PATH=$PREFIX/bin:/usr/bin:$PATH
#export PATH=$PREFIX/bin:/bin:/sbin:/usr/bin:/usr/sbin:/usr/X11R6/bin:
export LIBTOOLIZE=$PREFIX/bin/libtoolize

# FIXME: We might need some more intelligent way to get the path here.
export PYTHONPATH=$PREFIX/lib/python2.3/site-packages

# Needed for glib etc to pick up gettext
export LDFLAGS=-L$PREFIX/lib
export CPPFLAGS=-I$PREFIX/include

export XDG_DATA_DIRS=$PREFIX/share

COMMON_OPTIONS="--prefix=$PREFIX --disable-static --enable-shared \
--disable-gtk-doc --disable-scrollkeeper"

#export MAKEFLAGS=-j2

if [ "x$PANTHER_BUILD" = "xYes" ]; then
    # XXX: Check the machine is PPC
    #      or rework to have things like pkg-config built natively.

    # Overwrite some build settings.
    export SDK="/Developer/SDKs/MacOSX10.3.9.sdk"
    export MACOSX_DEPLOYMENT_TARGET=10.3
    export CFLAGS="-isysroot ${SDK} -arch ppc"
    export CXXFLAGS="-isysroot ${SDK} -arch ppc"

    export STABLE_BUILD=Yes
fi

if [ "x$UNIVERSAL_BUILD" = "xYes" ]; then
    COMMON_OPTIONS="$COMMON_OPTIONS --disable-dependency-tracking"

    export SDK="/Developer/SDKs/MacOSX10.4u.sdk"
    export MACOSX_DEPLOYMENT_TARGET=10.4
    #export MACOSX_DEPLOYMENT_TARGET_i386=10.4
    #export MACOSX_DEPLOYMENT_TARGET_ppc=10.3
    export CFLAGS="-isysroot ${SDK} -arch ppc -arch i386"
    export CXXFLAGS="-isysroot ${SDK} -arch ppc -arch i386"

    CONFIGURE_pkg_config="--with-pc-path=$PREFIX/lib/pkgconfig:/usr/X11R6/lib/pkgconfig --enable-indirect-deps --disable-dependency-tracking"

    CONFIGURE_libpng="--disable-dependency-tracking"
    PRECONFIGURE_libpng="eval CPPFLAGS='$CPPFLAGS -DPNG_NO_ASSEMBLER_CODE'"

    CONFIGURE_tiff="--disable-dependency-tracking"

    POSTCONFIGURE_jpeg_6b="patch_libtool_dylib"

    CONFIGURE_gc="--disable-dependency-tracking"
    POSTCONFIGURE_gc="patch_libtool_dylib"
    PRECONFIGURE_gc="eval CFLAGS='$CFLAGS -DUSE_GENERIC_PUSH_REGS'"

    POSTCONFIGURE_freetype="eval cd builds/unix/ && pwd && patch_libtool_dylib && cd ../.."

    CONFIGURE_fontconfig="--disable-dependency-tracking --disable-docs"
    POSTCONFIGURE_fontconfig="eval cd fc-arch && make all && cd .. && perl -pi~ -e 's|#define FC_ARCHITECTURE \"x86\"|#ifdef __ppc__\n#define FC_ARCHITECTURE \"ppc\"\n#else\n#define FC_ARCHITECTURE \"x86\"\n#endif|g' fc-arch/fcarch.h"

    PRECONFIGURE_cairo="export ax_cv_c_float_words_bigendian=no"
    CONFIGURE_cairo="--disable-dependency-tracking --enable-shared --disable-quartz --disable-atsui --enable-glitz"
    POSTCONFIGURE_cairo="eval patch_libtool_dylib && export ax_cv_c_float_words_bigendian='' && perl -pi~ -e 's|/\* #undef FLOAT_WORDS_BIGENDIAN \*/|#ifdef __ppc__\n#define FLOAT_WORDS_BIGENDIAN 1\n#endif|g;s|/\* #undef WORDS_BIGENDIAN \*/|#ifdef __ppc__\n#define WORDS_BIGENDIAN 1\n#endif|g' config.h && perl -pi~ -e 's|DIST_SUBDIRS = pixman src boilerplate test perf doc|DIST_SUBDIRS = pixman src test perf doc|g;s|am__append_1 = boilerplate test|am__append_1 = test|g' Makefile"

    CONFIGURE_glitz="--disable-dependency-tracking"

    CONFIGURE_lcms="--disable-dependency-tracking"

    CONFIGURE_glib="$COMMON_OPTIONS"
    POSTCONFIGURE_glib="eval make glibconfig.h config.h && cp $DIRNAME/{glib,}config.h ."
    #POSTCONFIGURE_glib="eval make glibconfig.h && perl -pi~ -e 's|#define G_BYTE_ORDER G_LITTLE_ENDIAN|#include <machine/endian.h>\n#define G_BYTE_ORDER __DARWIN_BYTE_ORDER|g' glibconfig.h"

    CONFIGURE_pango="$COMMON_OPTIONS"
    POSTCONFIGURE_pango="eval perl -pi~ -e 's|SUBDIRS = pango modules examples docs tools tests|SUBDIRS = pango modules docs tools tests|g' Makefile && perl -pi~ -e 's|harfbuzz_dump_LDADD = |harfbuzz_dump_LDADD = -Xlinker -framework -Xlinker CoreServices -Xlinker -framework -Xlinker ApplicationServices|g' pango/opentype/Makefile"

    CONFIGURE_gtk="$COMMON_OPTIONS"

    CONFIGURE_atk="$COMMON_OPTIONS"

    CONFIGURE_libxml2="$COMMON_OPTIONS"

    CONFIGURE_libsigc="$COMMON_OPTIONS"
    POSTCONFIGURE_libsigc="patch_libtool_dylib"

    CONFIGURE_glibmm="$COMMON_OPTIONS"

    CONFIGURE_cairomm="$COMMON_OPTIONS"

    CONFIGURE_gtkmm="$COMMON_OPTIONS --disable-examples --disable-demos"
    POSTCONFIGURE_gtkmm="patch_libtool_dylib"

    CONFIGURE_libxslt="$COMMON_OPTIONS"

    CONFIGURE_popt="$COMMON_OPTIONS"
    POSTCONFIGURE_popt="patch_libtool_dylib"
elif [ "x$STABLE_BUILD" = "xYes" ]; then
    COMMON_OPTIONS="$COMMON_OPTIONS --disable-dependency-tracking"

    CONFIGURE_pkg_config="--with-pc-path=$PREFIX/lib/pkgconfig:/usr/X11R6/lib/pkgconfig --enable-indirect-deps --disable-dependency-tracking"

    CONFIGURE_libpng="--disable-dependency-tracking"

    CONFIGURE_tiff="--disable-dependency-tracking"

    CONFIGURE_gc="--disable-dependency-tracking"

    CONFIGURE_fontconfig="--disable-dependency-tracking --disable-docs"

    CONFIGURE_cairo="--disable-dependency-tracking --enable-shared --disable-quartz --disable-atsui --enable-glitz"

    CONFIGURE_glitz="--disable-dependency-tracking"

    CONFIGURE_lcms="--disable-dependency-tracking"

    CONFIGURE_glib="$COMMON_OPTIONS"

    CONFIGURE_pango="$COMMON_OPTIONS"
    POSTCONFIGURE_pango="eval perl -pi~ -e 's|SUBDIRS = pango modules examples docs tools tests|SUBDIRS = pango modules docs tools tests|g' Makefile && perl -pi~ -e 's|harfbuzz_dump_LDADD = |harfbuzz_dump_LDADD = -Xlinker -framework -Xlinker CoreServices -Xlinker -framework -Xlinker ApplicationServices|g' pango/opentype/Makefile"

    CONFIGURE_gtk="$COMMON_OPTIONS"

    CONFIGURE_atk="$COMMON_OPTIONS"

    CONFIGURE_libxml2="$COMMON_OPTIONS"

    CONFIGURE_libsigc="$COMMON_OPTIONS"

    CONFIGURE_glibmm="$COMMON_OPTIONS"

    CONFIGURE_cairomm="$COMMON_OPTIONS"

    CONFIGURE_gtkmm="$COMMON_OPTIONS --disable-examples --disable-demos"

    CONFIGURE_libxslt="$COMMON_OPTIONS"

    CONFIGURE_popt="$COMMON_OPTIONS"
fi


# Support install-check from jhbuild to speed up compilation
if [ -x $PREFIX/bin/install-check ]; then
    export INSTALL=$PREFIX/bin/install-check
fi


SOURCE=${SOURCE-$HOME/Source/gtk}
CAIROCVSROOT=${CAIROCVSROOT-:pserver:anoncvs@cvs.freedesktop.org:/cvs/cairo}
WIRESHARKSVNURL="http://anonsvn.wireshark.org/wireshark/trunk
GNOMESVNURL=${GNOMESVNURL-https://svn.gnome.org/svn}

if [ x$1 = xrun ]; then
    cmd="$2"
    shift 2
    exec $cmd $*
fi

if [ $# -eq 0 -o "x`echo "$*" | grep shell`" = xshell ]; then
    # Can be used in .bashrc to set a fancy prompt...
    export INSIDE_GTK_BUILD=1
    bash
    exit 0
fi

CORE_MODULES="glitz cairo gnome-common glib pango atk gtk+"
EXTRA_MODULES="libxml2 libxslt loudmouth libglade gossip gtk-engines"
PYGTK_MODULES=" pycairo pygobject pygtk"
WIRESHARK_MODULES="$CORE_MODULES libxml2 libxslt gc lcms libsigc++ doxygen glibmm cairomm gtkmm popt wireshark"

# Could add those (orbit requires popt though)
MORE_MODULES="libIDL ORBit2 gconf"

function print_usage
{
    echo
    echo "GTK+ on Mac OS X build script version $version."
    echo
    echo "Usage:"
    echo "`basename $0` [bootstrap|[shell]|run <cmd>|build [<modules>]], modules are:"
    echo " Core: $CORE_MODULES"
    echo " Extra: $EXTRA_MODULES"
    echo " Python: $PYGTK_MODULES"
    echo " Wireshark: $WIRESHARK_MODULES"
    echo
    echo "Setup: This script defaults to downloading source to ~/Source/gtk and"
    echo "installing in /opt/gtk. Make sure your user has write access to the"
    echo "latter directory. You can override those directories by setting the"
    echo "SOURCE and PREFIX environment variables. Anoncvs is used by default"
    echo "for access to GNOME SVN, if you wish to override, set the environment"
    echo "variable GNOMESVNURL to your own account."
    echo
    echo "While in the shell that this script provides, the environment variable"
    echo "INSIDE_GTK_BUILD is set, which makes it possible to put something like"
    echo "the following in ~/.bashrc:"
    echo
    echo " if [ x\$INSIDE_GTK_BUILD != x ]; then"
    echo "     PS1=\"[GTK] \u@\h \W $ \""
    echo " fi"
    echo
    echo "Start by bootstrapping. This will install the necessary build tools."
    echo "Then build GTK+ & co by using the \"build\" command. If no modules are"
    echo "specified, only the ones needed for GTK+ will be built. The special"
    echo "modules \"core\" and \"all\" can be used to build just the core or all"
    echo "modules."
    echo
    echo "If you want to build something manually or run something, use the "
    echo "\"shell\" command (or no command) to get a shell with the environment"
    echo "properly setup."
    echo
    echo "Tip: if you build and install \"install-check\" from jhbuild into your"
    echo "PREFIX, recompiling when hacking on GTK+ & co will be a lot faster."
    echo
}

function download
{
    BASENAME=`basename $1`

    if [ -s $BASENAME ]; then
	echo "Already downloaded"
	return 0
    fi

    curl $1 > $BASENAME || return 1

    return 0
}

function should_build
{
    if [ -f $1/BUILT ]; then
	echo "Already built"
	return 1
    fi

    return 0
}

function tarball_get_and_build
{
    BASENAME=`basename $1`
    DIRNAME=`echo $BASENAME | sed -e s,.src.,., | sed -e s,.tar.*,,`
    INSTCMD="make install"
    PREFIXARG="--prefix=$PREFIX"
    COMMONOPTS="$COMMON_OPTIONS"

    SHORTNAME=`echo $DIRNAME | sed -e s,-*[0-9\.]*$,,`
    if !(echo "$MODULES" | grep -w $SHORTNAME) >/dev/null; then
	return 0
    fi

    echo
    echo "Building $DIRNAME"
    echo -ne "\033]0;Building $DIRNAME\007"

    # Special case jpeg... :/
    if [ x`echo $DIRNAME | grep jpeg` != x ]; then
	INSTCMD="make install-lib"
    fi

    if [ x`echo $BASENAME | grep bz2` != x ]; then
	COMP="j"
    else
	COMP="z"
    fi

    # Doxygen doesn't have a standard configure script.
    if [ x`echo $BASENAME | grep doxygen` != x ]; then
	PREFIXARG="--prefix $PREFIX"
    	COMMONOPTS="--shared"
    fi

    # Modify specific configure options
    UNDERSCORENAME=`echo $SHORTNAME | sed -e s,-,_, | tr -d '+'`
    CONFIGURE_EXTRA=`eval echo '\$'{CONFIGURE_$UNDERSCORENAME}`
    if [ "x$CONFIGURE_EXTRA" != "x" ]; then
        COMMONOPTS="$COMMONOPTS $CONFIGURE_EXTRA"
    fi
    PRECONFIGURE=`eval echo '\$'{PRECONFIGURE_$UNDERSCORENAME}`
    if [ "x$PRECONFIGURE" == "x" ]; then
        PRECONFIGURE="true"
    fi
    POSTCONFIGURE=`eval echo '\$'{POSTCONFIGURE_$UNDERSCORENAME}`
    if [ "x$POSTCONFIGURE" == "x" ]; then
        POSTCONFIGURE="true"
    fi

    cd $SOURCE || return 1
    download $1 || return 1
    should_build $DIRNAME || return 0
    tar ${COMP}xf $BASENAME && \
	cd $DIRNAME && \
	$PRECONFIGURE && \
	echo "./configure $PREFIXARG $COMMONOPTS $2" && \
	./configure $PREFIXARG $COMMONOPTS $2 && \
	$POSTCONFIGURE && \
	make && $INSTCMD && touch BUILT
}


function cpan_get_and_build
{
    BASENAME=`basename $1`
    DIRNAME=`echo $BASENAME | sed -e s,.tar.*,,`

    SHORTNAME=`echo $DIRNAME | sed -e s,-*[0-9\.]*$,,`
    if !(echo "$MODULES" | grep -w $SHORTNAME) >/dev/null; then
	return 0
    fi

    echo
    echo "Building $DIRNAME"
    echo -ne "\033]0;Building $DIRNAME\007"

    if [ x`echo $BASENAME | grep bz2` != x ]; then
	COMP="j"
    else
	COMP="z"
    fi

    cd $SOURCE || return 1
    download $1 || return 1
    should_build $DIRNAME || return 0
    tar ${COMP}xf $BASENAME && \
	cd $DIRNAME && \
	perl Makefile.PL $2 && \
	make && \
	(echo "Enter your password to istall $BASENAME"; make install) && \
	touch BUILT
}

function git_get_and_build
{
    if !(echo "$MODULES" | grep -w $2) >/dev/null; then
	return 0
    fi

    echo
    echo "Building $2"
    echo -ne "\033]0;Building $2\007"

    cd $SOURCE
    if [ -d $2 ]; then
	cd $2
	cg-update || return
    else
	cg-clone $1/$2 || return
	cd $2
    fi

    echo "./autogen.sh $COMMON_OPTIONS $3"
    (./autogen.sh $COMMON_OPTIONS $3 && make && make install)
}

function cvs_get_and_build
{
    if !(echo "$MODULES" | grep -w $2) >/dev/null; then
	return 0
    fi

    echo
    echo "Building $2"
    echo -ne "\033]0;Building $2\007"

    cd $SOURCE
    if [ -d $2 ]; then
	cd $2
	cvs up -dP || return
    else
	cvs -d $1 co -P $2 || return
	cd $2
    fi

    echo "./autogen.sh $COMMON_OPTIONS $3"
    (./autogen.sh $COMMON_OPTIONS $3 && make && make install)
}

function svn_get_and_build
{
    if !(echo "$MODULES" | grep -w $2) >/dev/null; then
	return 0
    fi

    echo
    echo "Building $2"
    echo -ne "\033]0;Building $2\007"

    cd $SOURCE
    if [ -d $2 ]; then
	cd $2
	svn up || return
    else
	svn co $1/$2/trunk $2 || return
	cd $2
    fi

    echo "./autogen.sh $COMMON_OPTIONS $3"
    #(./autogen.sh $COMMON_OPTIONS $3 && ./configure --prefix=$PREFIX $COMMON_OPTIONS $3 && make && make install)
    (./autogen.sh $COMMON_OPTIONS $3 && make && make install)
}

function set_automake
{
    old_AUTOMAKE=$AUTOMAKE
    old_ACLOCAL=$ACLOCAL

    export AUTOMAKE=automake-$1
    export ACLOCAL=aclocal-$1
}

function restore_automake
{
    if [ x$old_AUTOMAKE != x ]; then
	export AUTOMAKE=$old_AUTOMAKE
    else
	unset AUTOMAKE
    fi

    if [ x$old_ACLOCAL != x ]; then
	export ACLOCAL=$old_ACLOCAL
    else
	unset ACLOCAL
    fi
}

function do_exit
{
    echo -ne "\033]0;\007"
    exit
}

# Make sure to restore the title when done.
trap do_exit EXIT SIGINT SIGTERM


# configure doesn't pass CFLAGS through to generated libtool
function patch_libtool_dylib()
{
    # Only do this for universal builds.
    if [ "x$UNIVERSAL_BUILD" != "xYes" ]; then
        return 0
    fi

    cp libtool libtool.old
    perl -pi -e "s@-dynamiclib@$CFLAGS \$&@" libtool
    if test "x$1" = "xwithbundle"; then
        perl -pi -e "s@-bundle@$CFLAGS \$&@" libtool
    fi
}


function process_modules()
{
    # Bootstrap packages.
    PACKAGES=" \
	http://pkgconfig.freedesktop.org/releases/pkg-config-0.21.tar.gz \
	http://ftp.gnu.org/gnu/libtool/libtool-1.5.22.tar.gz \
	http://ftp.gnu.org/gnu/autoconf/autoconf-2.61.tar.bz2 \
	http://ftp.gnu.org/pub/gnu/automake/automake-1.7.9.tar.bz2 \
	http://ftp.gnu.org/gnu/automake/automake-1.9.6.tar.bz2 \
	http://heanet.dl.sourceforge.net/sourceforge/libpng/libpng-1.2.15.tar.bz2 \
	ftp://ftp.remotesensing.org/pub/libtiff/tiff-3.8.2.tar.gz \
	http://people.imendio.com/richard/gtk-osx/files/jpeg-6b.tar.gz \
	http://ftp.gnu.org/gnu/gettext/gettext-0.16.tar.gz \
	http://heanet.dl.sourceforge.net/sourceforge/expat/expat-2.0.0.tar.gz \
	http://heanet.dl.sourceforge.net/sourceforge/freetype/freetype-2.3.0.tar.bz2 \
	http://fontconfig.org/release/fontconfig-2.4.2.tar.gz \
	http://people.imendio.com/richard/gtk-osx/files/docbook-files-1.tar.gz \
	http://www.cs.mu.oz.au/~mjwybrow/gtk-osx/gnome-doc-utils-fake-1.tar.gz \
	"

	#http://people.imendio.com/richard/gtk-osx/files/popt-1.7.tar.gz

    for PACKAGE in $PACKAGES; do
	tarball_get_and_build $PACKAGE || exit 1
    done

    PACKAGE=http://ftp.gnome.org/pub/GNOME/sources/gtk-doc/1.6/gtk-doc-1.6.tar.bz2
    tarball_get_and_build $PACKAGE "--with-xml-catalog=$PREFIX/etc/xml/catalog" || exit 1

    PACKAGE=ftp://ftp4.freebsd.org/pub/FreeBSD/ports/distfiles/XML-Parser-2.34.tar.gz
    cpan_get_and_build $PACKAGE "PREFIX=$PREFIX INSTALLDIRS=perl EXPATLIBPATH=$PREFIX/lib EXPATINCPATH=$PREFIX/include" || exit 1

    PACKAGES=" \
	http://ftp.gnome.org/pub/GNOME/sources/intltool/0.35/intltool-0.35.0.tar.bz2 \
	http://icon-theme.freedesktop.org/releases/hicolor-icon-theme-0.9.tar.gz \
	http://ftp.gnome.org/pub/GNOME/sources/gnome-icon-theme/2.14/gnome-icon-theme-2.14.2.tar.bz2 \
	"

    for PACKAGE in $PACKAGES; do
	tarball_get_and_build $PACKAGE || exit 1
    done


    # Other packages:
    if [ "x$UNIVERSAL_BUILD" == "xYes" -o "x$STABLE_BUILD" = "xYes"  ];
    then
    	tarball_get_and_build http://cairographics.org/snapshots/glitz-0.5.6.tar.gz || exit 1
    	tarball_get_and_build http://cairographics.org/releases/cairo-1.4.0.tar.gz || exit 1
        tarball_get_and_build http://www.hpl.hp.com/personal/Hans_Boehm/gc/gc_source/gc6.8.tar.gz || exit 1
        tarball_get_and_build http://www.littlecms.com/lcms-1.16.tar.gz || exit 1
        tarball_get_and_build ftp://ftp.gnome.org/mirror/gnome.org/sources/glib/2.12/glib-2.12.11.tar.bz2 || exit 1
        tarball_get_and_build ftp://ftp.gnome.org/mirror/gnome.org/sources/pango/1.14/pango-1.14.10.tar.bz2 || exit 1
        tarball_get_and_build ftp://ftp.gnome.org/mirror/gnome.org/sources/atk/1.12/atk-1.12.4.tar.bz2 || exit 1
        tarball_get_and_build ftp://ftp.gnome.org/mirror/gnome.org/sources/gtk+/2.10/gtk+-2.10.11.tar.bz2 || exit 1
        tarball_get_and_build ftp://ftp.gnome.org/mirror/gnome.org/sources/libxml2/2.6/libxml2-2.6.27.tar.bz2 || exit 1
        tarball_get_and_build ftp://ftp.gnome.org/mirror/gnome.org/sources/libsigc++/2.0/libsigc++-2.0.17.tar.bz2 || exit 1
        tarball_get_and_build ftp://ftp.gnome.org/mirror/gnome.org/sources/glibmm/2.12/glibmm-2.12.7.tar.bz2 || exit 1
        tarball_get_and_build http://cairographics.org/releases/cairomm-1.2.4.tar.gz || exit 1
        tarball_get_and_build ftp://ftp.gnome.org/mirror/gnome.org/sources/gtkmm/2.10/gtkmm-2.10.8.tar.bz2 || exit 1
        tarball_get_and_build ftp://ftp.gnome.org/mirror/gnome.org/sources/libxslt/1.1/libxslt-1.1.20.tar.bz2 || exit 1
	tarball_get_and_build ftp://ftp.rpm.org/pub/rpm/dist/rpm-4.1.x/popt-1.7.tar.gz || exit 1

        svn_get_and_build $WIRESHARKSVNURL wireshark || exit 1

	exit 0
    else
	    git_get_and_build git://git.cairographics.org/git cairo "--enable-pdf --enable-atsui --enable-quartz --disable-xlib" || exit 1

	    tarball_get_and_build http://www.hpl.hp.com/personal/Hans_Boehm/gc/gc_source/gc6.7.tar.gz || exit 1
	    tarball_get_and_build ftp://ftp.gnome.org/mirror/gnome.org/sources/libsigc++/2.0/libsigc++-2.0.17.tar.gz || exit 1
	    tarball_get_and_build http://ftp.stack.nl/pub/users/dimitri/doxygen-1.5.1.src.tar.gz || exit 1
	    tarball_get_and_build ftp://ftp.rpm.org/pub/rpm/dist/rpm-4.1.x/popt-1.7.tar.gz || exit 1
    fi

    svn_get_and_build $GNOMESVNURL libxml2 || exit 1
    svn_get_and_build $GNOMESVNURL libxslt || exit 1
    svn_get_and_build $GNOMESVNURL gnome-common || exit 1
    svn_get_and_build $GNOMESVNURL glib || exit 1
    svn_get_and_build $GNOMESVNURL atk || exit 1
    svn_get_and_build $GNOMESVNURL pango "--without-x" || exit 1
    svn_get_and_build $GNOMESVNURL gtk+ "--with-gdktarget=quartz" || exit 1
    svn_get_and_build $GNOMESVNURL gtk-engines || exit 1
    svn_get_and_build $GNOMESVNURL loudmouth "--with-ssl=openssl" || exit 1
    svn_get_and_build $GNOMESVNURL libglade || exit 1
    # gossip needs xml2po from gnome-doc-utils.
    svn_get_and_build $GNOMESVNURL gossip "--with-backend=cocoa" || exit 1
    svn_get_and_build $CAIROCVSROOT pycairo || exit 1
    svn_get_and_build $GNOMESVNURL pygobject "--disable-docs" || exit 1
    svn_get_and_build $GNOMESVNURL pygtk "--disable-docs" || exit 1

    svn_get_and_build $GNOMESVNURL glibmm "--disable-docs --disable-fulldocs" || exit 1
    cvs_get_and_build $CAIROCVSROOT cairomm || exit 1
    svn_get_and_build $GNOMESVNURL gtkmm "--disable-docs --disable-examples --disable-demos" || exit 1

    svn_get_and_build $WIRESHARKSVNURL wireshark || exit 1


    #svn_get_and_build $GNOMESVNURL gimp || exit 1
    # For gimp:
    # libart_lgpl, needs automake 1.4 and doesn't run libtoolize
    # gtkhtml2 (optional)
    # libpoppler (optional)
    # ./autogen.sh --prefix=/opt/gimp --disable-gtk-doc
}

if (echo "$*" | grep bootstrap) >/dev/null; then
    if [ "x`cg-version 2>/dev/null`" == "x" ]; then
	echo "You need the cogito to get cairo from git. It's available e.g. in Darwin ports."
	exit 1
    fi
    if [ "x`which svn 2>/dev/null`" == "x" ]; then
	echo "You need the svn client to get wireshark"
	exit 1
    fi

    mkdir -p $SOURCE 2>/dev/null || \
        (echo "Error: Couldn't create source checkout dir $SOURCE"; exit 1)
    mkdir -p $PREFIX/bin 2>/dev/null || \
        (echo "Error: Couldn't create bin dir $PREFIX/bin"; exit 1)

    echo "Building bootstrap packages."

    MODULES="pkg-config libtool autoconf automake libpng tiff jpeg-6b gettext \
             expat fontconfig docbook-files intltool \
	     "
	     # freetype
	     # XML-Parser hicolor-icon-theme gnome-icon-theme"
	     # gnome-doc-utils-fake gtk-doc \
    process_modules

    # Setup glibtool* links since some stuff expects them to be named like
    # that on OSX
    if [ -z $PREFIX/bin/glibtoolize ]; then
	ln -s $PREFIX/bin/libtoolize $PREFIX/bin/glibtoolize
	ln -s $PREFIX/bin/libtool $PREFIX/bin/glibtool
    fi

    echo
    echo "Done bootstrapping. Continue with \"build\" or \"shell\"."
    exit 0
fi

if [ "x$1" != xbuild ]; then
    print_usage
    exit 1
fi

shift

MODULES=$*
if [ $# -eq 0 ]; then
    echo "Building core modules."
    MODULES="$CORE_MODULES"
elif [ "x$1" = xcore ]; then
    echo "Building core modules."
    MODULES="$CORE_MODULES"
elif [ "x$1" = xpython ]; then
    echo "Building python modules."
    MODULES="$PYGTK_MODULES"
elif [ "x$1" = xall ]; then
    echo "Building core+extra+python modules."
    MODULES="$CORE_MODULES $EXTRA_MODULES $PYGTK_MODULES"
elif [ "x$1" = xwireshark ]; then
    echo "Building wireshark modules."
    MODULES="$WIRESHARK_MODULES"
fi

process_modules
echo "Done."



