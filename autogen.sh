#!/bin/sh
#
# Run this to generate all the initial makefiles.
#
# $Id: autogen.sh,v 1.1 1999/07/27 04:43:01 gram Exp $

DIE=0
PROJECT="Ethereal"

(autoconf --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have autoconf installed to compile $PROJECT."
	echo "Download the appropriate package for your distribution,"
	echo "or get the source tarball at ftp://ftp.gnu.org/pub/gnu/"
	DIE=1
}

(automake --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have autoconf installed to compile $PROJECT."
	echo "Download the appropriate package for your distribution,"
	echo "or get the source tarball at ftp://ftp.gnu.org/pub/gnu/"
	DIE=1
}

if test "$DIE" -eq 1 ; then
	exit 1
fi

if test -z "$*"; then
	echo "Running ./configure with no arguments. If you wish to pass any,",
	echo "please specify them on the $0 command line."
fi

for dir in . wiretap ;  do
	echo processing $dir
	(cd $dir; \
		aclocalinclude="$ACLOCAL_FLAGS"; \
		aclocal $aclocalinclude; \
		autoheader; automake --add-missing --gnu $am_opt; autoconf)
done

for dir in doc;  do
	echo processing $dir
	(cd $dir; \
		aclocalinclude="$ACLOCAL_FLAGS"; \
		aclocal $aclocalinclude; \
		autoheader; autoconf)
done

./configure "$@"

echo
echo "Now type 'make' to compile $PROJECT."
