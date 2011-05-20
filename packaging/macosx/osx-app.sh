#!/bin/bash
#
# $Id$
#
# USAGE
# osx-app [-s] [-l /path/to/libraries] -bp /path/to/wireshark/bin -p /path/to/Info.plist
#
# This script attempts to build an Wireshark.app package for OS X, resolving
# dynamic libraries, etc.
# It strips the executable and libraries if '-s' is given.
# It adds python modules if the '-py option' is given
# The Info.plist file can be found in the base wireshark directory once
# configure has been run.
#
# AUTHORS
#		 Kees Cook <kees@outflux.net>
#		 Michael Wybrow <mjwybrow@users.sourceforge.net>
#		 Jean-Olivier Irisson <jo.irisson@gmail.com>
#
# Copyright (C) 2005 Kees Cook
# Copyright (C) 2005-2007 Michael Wybrow
# Copyright (C) 2007 Jean-Olivier Irisson
#
# Released under GNU GPL, read the file 'COPYING' for more information
#
# Thanks to GNUnet's "build_app" script for help with library dep resolution.
#		https://gnunet.org/svn/GNUnet/contrib/OSX/build_app
#
# NB:
# When packaging Wireshark for OS X, configure should be run with the
# "--enable-osxapp" option which sets the correct paths for support
# files inside the app bundle.
#

# Defaults
strip=false
binary_path="/tmp/inst/bin"
plist="./Info.plist"
util_dir="./Utilities"
cli_dir="$util_dir/Command Line"
chmodbpf_dir="$util_dir/ChmodBPF"

binary_list="
	capinfos
	dftest
	dumpcap
	editcap
	idl2wrs
	mergecap
	randpkt
	rawshark
	text2pcap
	tshark
	wireshark
"

# Location for libraries (MacPorts defaults to /opt/local)
if [ -z $LIBPREFIX ]; then
	LIBPREFIX="/opt/local"
fi


# Help message
#----------------------------------------------------------
help()
{
echo -e "
Create an app bundle for OS X

USAGE
	$0 [-s] [-l /path/to/libraries] -bp /path/to/wireshark/binaries -p /path/to/Info.plist

OPTIONS
	-h,--help
		display this help message
	-s
		strip the libraries and executables from debugging symbols
	-l,--libraries
		specify the path to the librairies Wireshark depends on
		(typically /sw or /opt/local)
	-bp,--binary-path
		specify the path to the Wireshark binaries. By default it
		is in $binary_path
	-p,--plist
		specify the path to Info.plist. Info.plist can be found
		in the base directory of the source code once configure
		has been run

EXAMPLE
	$0 -s -l /opt/local -bp ../../Build/bin -p Info.plist
"
}


# Parse command line arguments
#----------------------------------------------------------
while [ "$1" != "" ]
do
	case $1 in
		-s)
			strip=true ;;
		-l|--libraries)
			LIBPREFIX="$2"
			shift 1 ;;
		-bp|--binary-path)
			binary_path="$2"
			shift 1 ;;
		-p|--plist)
			plist="$2"
			shift 1 ;;
		-h|--help)
			help
			exit 0 ;;
		*)
			echo "Invalid command line option: $1"
			exit 2 ;;
	esac
	shift 1
done

echo -e "\nCREATE WIRESHARK APP BUNDLE\n"

# Safety tests
if [ ! -e "$LIBPREFIX" ]; then
	echo "Cannot find the directory containing the libraries: $LIBPREFIX" >&2
	exit 1
fi

for binary in wireshark $binary_list ; do
	if [ ! -x "$binary_path/$binary" ]; then
		echo "Couldn't find $binary (or it's not executable)" >&2
		exit 1
	fi
done

if [ ! -f "$plist" ]; then
	echo "Need plist file" >&2
	exit 1
fi


# Handle some version specific details.
VERSION=`/usr/bin/sw_vers | grep ProductVersion | cut -f2 -d'.'`
if [ "$VERSION" -ge "4" ]; then
	# We're on Tiger (10.4) or later.
	# XCode behaves a little differently in Tiger and later.
	XCODEFLAGS="-configuration Deployment"
	SCRIPTEXECDIR="ScriptExec/build/Deployment/ScriptExec.app/Contents/MacOS"
	EXTRALIBS=""
else
	# Panther (10.3) or earlier.
	XCODEFLAGS="-buildstyle Deployment"
	SCRIPTEXECDIR="ScriptExec/build/ScriptExec.app/Contents/MacOS"
	EXTRALIBS=""
fi


# Package always has the same name. Version information is stored in
# the Info.plist file which is filled in by the configure script.
package="Wireshark.app"

# Remove a previously existing package if necessary
if [ -d $package ]; then
	echo "Removing previous Wireshark.app"
	rm -Rf $package
fi

# Remove a previously existing utility directory if necessary
if [ -d "$util_dir" ]; then
	echo "Removing $util_dir directory"
	rm -Rf "$util_dir"
fi

# Set the 'macosx' directory, usually the current directory.
resdir=`pwd`


# Prepare Package
#----------------------------------------------------------
pkgexec="$package/Contents/MacOS"
pkgres="$package/Contents/Resources"
pkgbin="$pkgres/bin"
pkglib="$pkgres/lib"
pkgplugin="$pkglib/wireshark/plugins"
pkgpython="$pkglib/wireshark/python"

mkdir -p "$pkgexec"
mkdir -p "$pkgbin"
mkdir -p "$pkgplugin"
mkdir -p "$pkgpython"

mkdir -p "$cli_dir"

# Build and add the launcher
#----------------------------------------------------------
(
	# Build fails if CC happens to be set (to anything other than CompileC)
	unset CC

	cd "$resdir/ScriptExec"
	echo -e "Building launcher...\n"
	xcodebuild $XCODEFLAGS clean build
)
cp "$resdir/$SCRIPTEXECDIR/ScriptExec" "$pkgexec/Wireshark"


# Copy all files into the bundle
#----------------------------------------------------------
echo -e "\nFilling app bundle and utility directory...\n"

# Wireshark executables
for binary in $binary_list ; do
	# Copy the binary to its destination
	dest_path="$pkgbin/$binary-bin"
	cp -v "$binary_path/$binary" "$dest_path"
	# TODO Add a "$verbose" variable and command line switch, which sets wether these commands are verbose or not

	case $binary in
	wireshark)
		cp -v utility-launcher "$cli_dir/$binary"
		;;
	*)
		ln -sv ./wireshark "$pkgbin/$binary"
		ln -sv ./wireshark "$cli_dir/$binary"
		;;
	esac
done

# ChmodBPF
mkdir -p "$chmodbpf_dir"
cp -v ChmodBPF/* "$chmodbpf_dir"
chmod -R g-w "$chmodbpf_dir"

# The rest of the Wireshark installation (we handled bin above)
rsync -av \
	--exclude bin/ \
	--exclude lib/wireshark/plugins/ \
	--exclude lib/wireshark/python/ \
	"$binary_path/.."/* "$pkgres"

# Remove the version number from the plugin path
find "$binary_path/../lib/wireshark/plugins" -type f \
	-exec cp -fv "{}" "$pkgplugin/" \;

# Remove the version number from the python path
find "$binary_path/../lib/wireshark/python" -type f \
	-exec cp -fv "{}" "$pkgpython/" \;

cp "$plist" "$package/Contents/Info.plist"

# Icons and the rest of the script framework
rsync -av --exclude ".svn" "$resdir"/Resources/* "$package"/Contents/Resources/

# PkgInfo must match bundle type and creator code from Info.plist
echo "APPLWshk" > $package/Contents/PkgInfo

# Pull in extra requirements for Pango and GTK
pkgetc="$package/Contents/Resources/etc"
mkdir -p $pkgetc/pango
cp $LIBPREFIX/etc/pango/pangox.aliases $pkgetc/pango/
# Need to adjust path and quote in case of spaces in path.
sed -e "s,$LIBPREFIX,\"\${CWD},g" -e 's,\.so ,.so" ,g' $LIBPREFIX/etc/pango/pango.modules > $pkgetc/pango/pango.modules
cat > $pkgetc/pango/pangorc <<END_PANGO
[Pango]
ModuleFiles=\${HOME}/.wireshark-etc/pango.modules
[PangoX]
AliasFiles=\${HOME}/.wireshark-etc/pangox.aliases
END_PANGO

# We use a modified fonts.conf file so only need the dtd
mkdir -p $pkgetc/fonts
cp $LIBPREFIX/etc/fonts/fonts.dtd $pkgetc/fonts/
cp -r $LIBPREFIX/etc/fonts/conf.avail $pkgetc/fonts/
cp -r $LIBPREFIX/etc/fonts/conf.d $pkgetc/fonts/

mkdir -p $pkgetc/gtk-2.0
sed -e "s,$LIBPREFIX,\${CWD},g" $LIBPREFIX/etc/gtk-2.0/gdk-pixbuf.loaders > $pkgetc/gtk-2.0/gdk-pixbuf.loaders
sed -e "s,$LIBPREFIX,\${CWD},g" $LIBPREFIX/etc/gtk-2.0/gtk.immodules > $pkgetc/gtk-2.0/gtk.immodules

pango_version=`pkg-config --variable=pango_module_version pango`
mkdir -p $pkglib/pango/$pango_version/modules
cp $LIBPREFIX/lib/pango/$pango_version/modules/*.so $pkglib/pango/$pango_version/modules/

gtk_version=`pkg-config --variable=gtk_binary_version gtk+-2.0`
mkdir -p $pkglib/gtk-2.0/$gtk_version/{engines,immodules,loaders}
cp -r $LIBPREFIX/lib/gtk-2.0/$gtk_version/* $pkglib/gtk-2.0/$gtk_version/

gdk_pixbuf_version=`pkg-config --variable=gdk_pixbuf_binary_version gdk-pixbuf-2.0`
if [ ! -z $gdk_pixbuf_version ]; then
	mkdir -p $pkglib/gdk-pixbuf-2.0/$gdk_pixbuf_version/loaders
	cp -r $LIBPREFIX/lib/gdk-pixbuf-2.0/$gdk_pixbuf_version/loaders/* $pkglib/gdk-pixbuf-2.0/$gdk_pixbuf_version/loaders
fi

# Find out libs we need from fink, darwinports, or from a custom install
# (i.e. $LIBPREFIX), then loop until no changes.
a=1
nfiles=0
endl=true
lib_dep_search_list="
	$pkglib/gtk-2.0/$gtk_version/loaders/*
	$pkglib/gtk-2.0/$gtk_version/immodules/*
	$pkglib/gtk-2.0/$gtk_version/engines/*.so
	$pkglib/pango/$pango_version/modules/*
	$pkglib/gdk-pixbuf-2.0/$gdk_pixbuf_version/loaders/*
	$package/Contents/Resources/lib/*
	$pkgbin/*-bin
	"
while $endl; do
	echo -e "Looking for dependencies. Round" $a
	libs="`otool -L $lib_dep_search_list 2>/dev/null | fgrep compatibility | cut -d\( -f1 | grep $LIBPREFIX | sort | uniq`"
	cp -vn $libs "$pkglib"
	let "a+=1"
	nnfiles=`ls "$pkglib" | wc -l`
	if [ $nnfiles = $nfiles ]; then
		endl=false
	else
		nfiles=$nnfiles
	fi
done

# Add extra libraries of necessary
for libfile in $EXTRALIBS
do
	cp -f $libfile "$pkglib"
done

# Strip libraries and executables if requested
#----------------------------------------------------------
if [ "$strip" = "true" ]; then
	echo -e "\nStripping debugging symbols...\n"
	chmod +w "$pkglib"/*.dylib
	strip -x "$pkglib"/*.dylib
	strip -ur "$binpath"
fi

# NOTE: This works for all the dylibs but causes GTK to crash at startup.
#				Instead we leave them with their original install_names and set
#				DYLD_LIBRARY_PATH within the app bundle before running Wireshark.
#
# fixlib () {
#		# Fix a given executable or library to be relocatable
#		if [ ! -d "$1" ]; then
#			echo $1
#			libs="`otool -L $1 | fgrep compatibility | cut -d\( -f1`"
#			for lib in $libs; do
#				echo "	$lib"
#				base=`echo $lib | awk -F/ '{print $NF}'`
#				first=`echo $lib | cut -d/ -f1-3`
#				to=@executable_path/../lib/$base
#				if [ $first != /usr/lib -a $first != /usr/X11R6 ]; then
#					/usr/bin/install_name_tool -change $lib $to $1
#					if [ "`echo $lib | fgrep libcrypto`" = "" ]; then
#						/usr/bin/install_name_tool -id $to ../lib/$base
#						for ll in $libs; do
#							base=`echo $ll | awk -F/ '{print $NF}'`
#							first=`echo $ll | cut -d/ -f1-3`
#							to=@executable_path/../lib/$base
#							if [ $first != /usr/lib -a $first != /usr/X11R6 -a "`echo $ll | fgrep libcrypto`" = "" ]; then
#								/usr/bin/install_name_tool -change $ll $to ../lib/$base
#							fi
#						done
#					fi
#				fi
#			done
#		fi
# }
#
# Fix package deps
#(cd "$package/Contents/MacOS/bin"
# for file in *; do
#		 fixlib "$file"
# done
# cd ../lib
# for file in *; do
#		 fixlib "$file"
# done)

exit 0
