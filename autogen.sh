#!/bin/sh
#
# Run this to generate all the initial makefiles.
#
# $Id$

DIE=true
PROJECT="Wireshark"

# If you are going to use the non-default name for automake becase your OS
# installaion has multiple versions, you need to call both aclocal and automake
# with that version number, as they come from the same package.
#AM_VERSION='-1.8'

ACLOCAL=aclocal$AM_VERSION
AUTOHEADER=autoheader
AUTOMAKE=automake$AM_VERSION
AUTOCONF=autoconf

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


ACVER=`$AUTOCONF --version | grep '^autoconf' | sed 's/.*) *//'`
case "$ACVER" in
'' | 0.* | 1.* | 2.[0-4]* | \
2.5[0-1] | 2.5[0-1][a-z]* )
  cat >&2 <<_EOF_

	You must have autoconf 2.52 or later installed to compile $PROJECT.
	Download the appropriate package for your distribution/OS,
	or get the source tarball at ftp://ftp.gnu.org/pub/gnu/autoconf/
_EOF_
  DIE="exit 1"
  ;;
esac


AMVER=`$AUTOMAKE --version | grep '^automake' | sed 's/.*) *//'`
case "$AMVER" in
1.[6-9]* | 1.[1][0-9]*)
  ;;

*)

  cat >&2 <<_EOF_

	You must have automake 1.6 or later installed to compile $PROJECT.
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
    sed 's/.*libtool) \([0-9][0-9.]*\)[^ ]* .*/\1/'`
if test -z "$LTVER"
then
	LTVER=`libtool --version | grep ' libtool)' | \
	    sed 's/.*) \([0-9][0-9.]*\)[^ ]* .*/\1/' `
	LIBTOOLIZE=libtoolize
else
	LIBTOOLIZE=glibtoolize
fi
case "$LTVER" in
'' | 0.* | 1.[0-3]* )

  cat >&2 <<_EOF_

	You must have libtool 1.4 or later installed to compile $PROJECT.
	Download the appropriate package for your distribution/OS,
	or get the source tarball at ftp://ftp.gnu.org/pub/gnu/libtool/
_EOF_
  DIE="exit 1"
  ;;
esac

$DIE

for dir in . wiretap ;  do
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
    echo $ACLOCAL $aclocalinclude
    $ACLOCAL $aclocalinclude || exit 1
    if [ "$dir" = "." ] ; then
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
    fi
    echo $AUTOHEADER
    $AUTOHEADER || exit 1
    echo $AUTOMAKE --add-missing --gnu $am_opt
    $AUTOMAKE --add-missing --gnu $am_opt || exit 1
    echo $AUTOCONF
    $AUTOCONF || exit 1
  ) || exit 1
done

#./configure "$@" || exit 1

echo
echo "Now type \"./configure [options]\" and \"make\" to compile $PROJECT."
