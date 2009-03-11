#!/bin/bash
#
# $Id$

# This MUST be in the form
#   http://anonsvn.wireshark.org/wireshark-win32-libs/tags/<date>/packages
# or
#   http://anonsvn.wireshark.org/wireshark-win64-libs/tags/<date>/packages
# in order to provide backward compatibility with older trees (e.g. a
# previous release or an older SVN checkout).
# Save previous tag.
DOWNLOAD_TAG=${DOWNLOAD_TAG:-"2009-02-09"}
WIRESHARK_TARGET_PLATFORM=${WIRESHARK_TARGET_PLATFORM:-"win32"}

DOWNLOAD_PREFIX="http://anonsvn.wireshark.org/wireshark-$WIRESHARK_TARGET_PLATFORM-libs/tags/$DOWNLOAD_TAG/packages/"

TAG_FILE="current_tag.txt"

# Set DOWNLOAD_PREFIX to /packages to test uploads before creating the tag.
#DOWNLOAD_PREFIX="http://anonsvn.wireshark.org/wireshark-win32-libs/trunk/packages/"

err_exit () {
	echo ""
	for str in "$@" ; do
	    echo "ERROR: $str"
	done
	echo ""
	exit 1
}

usage () {
	echo "Usage:"
	echo "	$0 --appverify <appname> [<appname>] ..."
	echo "  $0 --libverify <destination> <subdirectory> <package>"
	echo "	$0 --download  <destination> <subdirectory> <package>"
	echo "	$0 --settag  <destination>"
	echo "	$0 --checktag  <destination>"
	echo ""
	exit 1
}

# Try to find our proxy settings, and set http_proxy/use_proxy accordingly.
find_proxy() {
	# Someone went to the trouble of configuring wget.
	if grep "^use_proxy *= *on" $HOME/.wgetrc > /dev/null 2>&1 ; then
		return
	fi

	# ...and wget can't fetch two registry keys because...?
	proxy_enabled=`regtool get /HKCU/Software/Microsoft/Windows/CurrentVersion/Internet\ Settings/ProxyEnable 2>/dev/null`
	if [ -n "$proxy_enabled" -a $proxy_enabled -ne 0 ] ; then
		export http_proxy=`regtool get /HKCU/Software/Microsoft/Windows/CurrentVersion/Internet\ Settings/ProxyServer 2>/dev/null`
		echo "Using Internet Explorer proxy settings."
	fi

	if [ -z "$http_proxy" -a -z "$HTTP_PROXY" ] ; then
		echo "No HTTP proxy specified (http_proxy and HTTP_PROXY are empty)."
		# a proxy might also be specified using .wgetrc, so don't switch off the proxy
		#use_proxy="-Y off"
		return
	fi

	# We found a proxy somewhere
	use_proxy="-Y on"
	if [ -z "$http_proxy" ] ; then
		echo "HTTP proxy ($HTTP_PROXY) has been specified and will be used."
		export http_proxy=$HTTP_PROXY
	else
		echo "HTTP proxy ($http_proxy) has been specified and will be used."
	fi
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

	MISSING_APPS=        
	for APP in $* ; do
		APP_PATH=`cygpath --unix $APP`
		if [ -x "$APP_PATH" -a ! -d "$APP_PATH" ] ; then
			APP_LOC="$APP_PATH"
		else
			APP_LOC=`which $APP_PATH 2> /dev/null`
		fi
		if [ "$APP_LOC" = "" ] ; then
			MISSING_APPS="$MISSING_APPS $APP"
		else
			echo "	$APP: $APP_LOC $res"
		fi
	done

	if [ -n "$MISSING_APPS" ]; then
		echo 
		echo "Can't find: $MISSING_APPS"
		err_exit "These are probably optional cygwin packages not yet installed. Try to install them using cygwin's setup.exe!"
	fi
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
	find_proxy
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
--settag)
	if [ -z "$2" ] ; then
		usage
	fi
	DEST_PATH=`cygpath --dos "$2"`
	echo "$DOWNLOAD_TAG" > $DEST_PATH/$TAG_FILE
	;;
--checktag)
	if [ -z "$2" ] ; then
		usage
	fi
	DEST_PATH=`cygpath --dos "$2"`
	WIN_PATH=`cygpath --windows "$2"`
	LAST_TAG=`cat $DEST_PATH/$TAG_FILE 2> /dev/null`
	if [ "$DOWNLOAD_TAG" != "$LAST_TAG" ] ; then
		if [ -z "$LAST_TAG" ] ; then
			LAST_TAG="(unknown)"
		fi
		err_exit \
			"The contents of $WIN_PATH\\$TAG_FILE is $LAST_TAG." \
			"It should be $DOWNLOAD_TAG." \
			"Do you need to run \"nmake -f makefile.nmake setup\"?"
	fi
	;;
*)
	usage
	;;
esac

exit 0
