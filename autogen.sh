#!/bin/sh
#
# Run this to generate all the initial makefiles.
#
# $Id: autogen.sh,v 1.26 2003/06/22 22:50:40 jmayer Exp $

DIE=true
PROJECT="Ethereal"


# Check for python. There's no "--version" option!
python -c "print 'Checking for python.'"
if [ $? != 0 ] ; then
  cat >&2 <<_EOF_

  	You must have Python in order to compile $PROJECT.
	Download the appropriate package for your distribution/OS,
	or get the source tarball at http://www.python.org/
_EOF_
  DIE="exit 1"
fi


ACVER=`autoconf --version | grep '^autoconf' | sed 's/.*)//'`
case "$ACVER" in
0* | 1\.* | 2\.[0-9] | 2\.[0-9][a-z]* | \
2\.1[0-2] | 2\.1[0-2][a-z]* )
  cat >&2 <<_EOF_

	You must have autoconf 2.13 or later installed to compile $PROJECT.
	Download the appropriate package for your distribution/OS,
	or get the source tarball at ftp://ftp.gnu.org/pub/gnu/autoconf/
_EOF_
  DIE="exit 1"
  ;;
esac


AMVER=`automake --version | grep '^automake' | sed 's/.*)//'`
case "$AMVER" in
0* | 1\.[0-3] | 1\.[0-3][a-z]* )

  cat >&2 <<_EOF_

	You must have automake 1.4 or later installed to compile $PROJECT.
	Download the appropriate package for your distribution/OS,
	or get the source tarball at ftp://ftp.gnu.org/pub/gnu/automake/
_EOF_
  DIE="exit 1"
  ;;
esac


#
# Apple's Developer Tools have a "libtool" that has nothing to do with
# the GNU libtool; they call the latter "glibtool".  They also call
# libtoolize "glibtoolize".
#
# Check for "glibtool" first.
#
LTVER=`glibtool --version 2>/dev/null | grep ' libtool)' | \
    sed 's/.*) \([0-9][0-9.]*\) .*/\1/'`
if test -z "$LTVER"
then
	LTVER=`libtool --version | grep ' libtool)' | \
	    sed 's/.*) \([0-9][0-9.]*\) .*/\1/' `
	LIBTOOLIZE=libtoolize
else
	LIBTOOLIZE=glibtoolize
fi
case "$LTVER" in
0* | 1\.[0-2] | 1\.[0-2][a-z]* | \
1\.3\.[0-2] | 1\.3\.[0-2][a-z]* )

  cat >&2 <<_EOF_

	You must have libtool 1.3.3 or later installed to compile $PROJECT.
	Download the appropriate package for your distribution/OS,
	or get the source tarball at ftp://ftp.gnu.org/pub/gnu/libtool/
_EOF_
  DIE="exit 1"
  ;;
esac

$DIE

#
# We do NOT want libtoolize overwriting our versions of config.guess and
# config.sub, so move them away and then move them back.
# We don't omit "--force", as we want libtoolize to install other files
# without whining.
#
mv config.guess config.guess.save-libtool
mv config.sub config.sub.save-libtool
LTARGS=" --copy --force"
echo $LIBTOOLIZE $LTARGS
$LIBTOOLIZE $LTARGS || exit 1
rm -f config.guess config.sub
mv config.guess.save-libtool config.guess
mv config.sub.save-libtool config.sub

if glib-config --version >/dev/null 2>&1 ; then
	rm -f aclocal-missing/glib.m4
else
	cp aclocal-fallback/glib.m4 aclocal-missing/
fi
if gtk-config --version >/dev/null 2>&1 ; then
	rm -f aclocal-missing/gtk.m4
else
	cp aclocal-fallback/gtk.m4 aclocal-missing/
fi
if pkg-config glib-2.0 >/dev/null 2>&1 ; then
	rm -f aclocal-missing/glib-2.0.m4
else
	cp aclocal-fallback/glib-2.0.m4 aclocal-missing/
fi
if pkg-config gtk+-2.0 >/dev/null 2>&1 ; then
	rm -f aclocal-missing/gtk-2.0.m4
else
	cp aclocal-fallback/gtk-2.0.m4 aclocal-missing/
fi

for dir in . epan wiretap ;  do
  echo processing $dir
  (
    cd $dir
    if [ "$dir" = "." ] ; then
        topdir=.
    else
        topdir=..
    fi
    aclocal_flags=`$topdir/aclocal-flags`
    aclocalinclude="$ACLOCAL_FLAGS $aclocal_flags";
    echo aclocal $aclocalinclude
    aclocal $aclocalinclude || exit 1
    echo autoheader
    autoheader || exit 1
    echo automake --add-missing --gnu $am_opt
    automake --add-missing --gnu $am_opt || exit 1
    echo autoconf
    autoconf || exit 1
  ) || exit 1
done

#./configure "$@" || exit 1

echo
echo "Now type \"./configure [options]\" and \"make\" to compile $PROJECT."
