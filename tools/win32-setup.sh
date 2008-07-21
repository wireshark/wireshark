#!/bin/sh
#
# $Id$

# This MUST be in the form
#   http://anonsvn.wireshark.org/wireshark-win32-libs/tags/<date>/packages
# in order to provide backward compatibility with older trees (e.g. a
# previous release or an older SVN checkout).
# Save previous tag.
#DOWNLOAD_PREFIX="http://anonsvn.wireshark.org/wireshark-win32-libs/tags/2008-07-15/packages/"

# Set DOWNLOAD_PREFIX to /packages to test uploads before creating the tag.
DOWNLOAD_PREFIX="http://anonsvn.wireshark.org/wireshark-win32-libs/trunk/packages/"

err_exit () {
	echo ""
	echo "ERROR: $1"
	echo ""
	exit 1
}

usage () {
	echo "Usage:"
	echo "	$0 --appverify <appname> [<appname>] ..."
	echo "  $0 --libverify <destination> <subdirectory> <package>"
	echo "	$0 --download  <destination> <subdirectory> <package>"
	echo ""
	exit 1
}


case "$1" in
--appverify)
	shift
	if [ -z "$*" ] ; then
		usage
	fi
	echo "Checking for required applications:"
	which which > /dev/null 2>&1 || \
		err_exit "Can't find 'which'.  Unable to proceed."
	for APP in $* ; do
		APP_PATH=`cygpath --unix $APP`
		if [ -x "$APP_PATH" -a ! -d "$APP_PATH" ] ; then
			APP_LOC="$APP_PATH"
		else
			APP_LOC=`which $APP_PATH 2> /dev/null`
		fi
		if [ "$APP_LOC" = "" ] ; then
			err_exit "Can't find $APP. This is probably an optional cygwin package not yet installed. Try to install it using cygwin's setup.exe!"
		fi
		echo "	$APP: $APP_LOC $res"
	done
	;;
--libverify)
	if [ -z "$2" -o -z "$3" -o -z "$4" ] ; then
		usage
	fi
	DEST_PATH=`cygpath --dos "$2"`
	PACKAGE_PATH=$4
	PACKAGE=`basename "$PACKAGE_PATH"`
	if [ ! -e $DEST_PATH/$PACKAGE ] ; then
	    err_exit "Package $PACKAGE is needed but is apparently not downloaded; 'nmake -f ... setup' required ?"
	fi
        ;;
--download)
	if [ -z "$2" -o -z "$3" -o -z "$4" ] ; then
		usage
	fi
	DEST_PATH=`cygpath --dos "$2"`
	DEST_SUBDIR=$3
	PACKAGE_PATH=$4
	PACKAGE=`basename "$PACKAGE_PATH"`
	echo ""
	echo "****** $PACKAGE ******"
	if [ -z "$http_proxy" -a -z "$HTTP_PROXY" ] ; then
		echo "No HTTP proxy specified (http_proxy and HTTP_PROXY are empty)."
		# a proxy might also be specified using .wgetrc, so don't switch off the proxy
		#use_proxy="-Y off"
	else
		use_proxy="-Y on"
		if [ -z "$http_proxy" ] ; then
			echo "HTTP proxy ($HTTP_PROXY) has been specified and will be used."
			export http_proxy=$HTTP_PROXY
		else
			echo "HTTP proxy ($http_proxy) has been specified and will be used."
		fi
	fi
	echo "Downloading $4 into $DEST_PATH, installing into $3"
	if [ ! -d "$DEST_PATH/$DEST_SUBDIR" ] ; then
		mkdir -p "$DEST_PATH/$DEST_SUBDIR" || \
			err_exit "Can't create $DEST_PATH/$DEST_SUBDIR"
	fi
	cd "$DEST_PATH" || err_exit "Can't find $DEST_PATH"
	wget $use_proxy -nc "$DOWNLOAD_PREFIX/$PACKAGE_PATH" || \
		err_exit "Can't download $DOWNLOAD_PREFIX/$PACKAGE_PATH"
	cd "$DEST_SUBDIR" || err_exit "Can't find $DEST_SUBDIR"
	echo "Extracting $DEST_PATH/$PACKAGE into $DEST_PATH/$DEST_SUBDIR"
	unzip -oq "$DEST_PATH/$PACKAGE" ||
		err_exit "Couldn't unpack $DEST_PATH/$PACKAGE"
	echo "Verifying that the DLLs and EXEs in $DEST_SUBDIR are executable."
        # XX: Note that find will check *all* dlls/exes in DEST_SUBDIR and below
        #     which may be more than those just unzipped depending upon DEST_SUBDIR.
        #     This may cause extra repeated checks but will do no harm.
	for i in `/usr/bin/find . \( -name '*\.dll' -o -name '*\.exe' \)` ; do
		if [ ! -x "$i" ] ; then
			echo "Changing file permissions (add executable bit) to:"
			echo "$i"
			chmod a+x "$i"
		fi
	done
	;;
*)
	usage
	;;
esac

exit 0
