#!/bin/sh
#
# Run this to generate all the initial makefiles.
#
# $Id: autogen.sh,v 1.7 1999/12/30 21:34:58 guy Exp $

DIE=0
PROJECT="Ethereal"

#
# XXX - we should really get the version numbers into variables, and
# check to make sure they have a recent enough version, but I'm
# not sure that the version strings you get are amenable to ordered
# comparisons (e.g., I think some versions of Red Hat Linux may have
# version numbers such as "1.4a"); that may be soluble, but it might
# take some work.
#
(autoconf --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have autoconf 2.13 or later installed to compile $PROJECT."
	echo "Download the appropriate package for your distribution/OS,"
	echo "or get the source tarball at ftp://ftp.gnu.org/pub/gnu/autoconf/"
	DIE=1
}

(automake --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have automake 1.4 or later installed to compile $PROJECT."
	echo "Download the appropriate package for your distribution/OS,"
	echo "or get the source tarball at ftp://ftp.gnu.org/pub/gnu/automake/"
	DIE=1
}

(libtool --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have libtool 1.3.4 or later installed to compile $PROJECT."
	echo "Download the appropriate package for your distribution/OS,"
	echo "or get the source tarball at ftp://ftp.gnu.org/pub/gnu/libtool/"
	DIE=1
}

if test "$DIE" -eq 1 ; then
	exit 1
fi

if test -z "$*"; then
	echo "Running ./configure with no arguments. If you wish to pass any,"
	echo "please specify them on the $0 command line."
fi

for dir in . wiretap ;  do
	echo processing $dir
	(cd $dir; \
		aclocalinclude="$ACLOCAL_FLAGS"; \
		aclocal $aclocalinclude; \
		autoheader; automake --add-missing --gnu $am_opt; autoconf)
done

./configure "$@"

echo
echo "Now type 'make' to compile $PROJECT."
