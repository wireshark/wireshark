#!/bin/bash
#
# USAGE
# osx-app [-s] [-l /path/to/libraries] -bp /path/to/wireshark/bin
#     -lp /path/to/wireshark/lib -ep /path/to/wireshark/extcap/binaries
#     -pp /path/to/wireshark/plugins -p /path/to/Info.plist
#
# This script attempts to build an Wireshark.app bundle for OS X, resolving
# dynamic libraries, etc.
# It strips the executable and libraries if '-s' is given.
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
# This originally came from Inkscape; Inkscape's configure script has an
# "--enable-osxapp", which causes some of Inkscape's installation data
# files to have OS X-ish paths under Contents/Resources of the bundle
# or under /Library/Application Support.  We don't have such an option;
# we just put them in "bin", "etc", "lib", and "share" directories
# under Contents/Resources, rather than in the "bin", "etc", "lib",
# and "share" directories under the installation directory.
#

# Defaults
strip=false
binary_path="/tmp/inst/bin"
library_path="/tmp/inst/lib"
plugin_path="/tmp/inst/lib/wireshark/plugins"
extcap_path="/tmp/inst/lib/wireshark/extcap"
plist="./Info.plist"
exclude_prefixes="/System/|/Library/|/usr/lib/|/usr/X11/|/opt/X11/|@rpath|@executable_path"
create_bundle=false

# Bundle always has the same name. Version information is stored in
# the Info.plist file which is filled in by the configure script.
bundle="Wireshark.app"

# Name of the Wireshark executable
wireshark_bin_name="wireshark"

#
# Command-line executables
#
cli_binary_list="
	capinfos
	dftest
	dumpcap
	editcap
	mergecap
	randpkt
	rawshark
	text2pcap
	tshark
"

extcap_binaries="androiddump randpktdump sshdump ciscodump"

for extcap_binary in $extcap_binaries
do
	if [ -x "extcap/$extcap_binary" ]; then
		extcap_binary_list="$extcap_binary_list extcap/$extcap_binary"
	fi
done

cs_binary_list=

# Location for libraries (macosx-setup.sh defaults to whatever the
# various support libraries use as their standard installation location,
# which is /usr/local)
if [ -z $LIBPREFIX ]; then
	LIBPREFIX="/usr/local"
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
		Display this help message.
	-s
		Strip the libraries and executables from debugging symbols.
	-l,--libraries
		Specify the path to the libraries Wireshark depends on
		(typically /sw or /opt/local). By default it is
		/usr/local.
	-cb,--create-bundle
		Create the application bundle (Wireshark.app). This flag
		should be supplied when building using Autotools. It
		should not be specified when building using CMake.
	-bp,--binary-path
		Specify the path to the Wireshark binaries. By default it
		is /tmp/inst/bin.
	-lp,--library-path
		Specify the path to the Wireshark libraries. By default it
		is /tmp/inst/lib.
	-pp,--plugin-path
		Specify the path to the Wireshark plugins. By default it
		is /tmp/inst/lib/wireshark/plugins.
	-ep,--extcap-path
		Specify the path to the Wireshark extcap binaries. By
		default it is /tmp/inst/lib/wireshark/extcap.
	-p,--plist
		Specify the path to Info.plist. Info.plist can be found
		in the base directory of the source code once configure
		has been run.
	-sdkroot
		Specify the root of the SDK to use.

EXAMPLE
	$0 -s -l /opt/local -bp ../../Build/bin -p Info.plist -sdkroot /Developer/SDKs/MacOSX10.5.sdk
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
		-lp|--library-path)
			library_path="$2"
			shift 1 ;;
		-pp|--plugin-path)
			plugin_path="$2"
			shift 1 ;;
		-ep|--extcap-path)
			extcap_path="$2"
			shift 1 ;;
		-cb|--create-bundle)
			create_bundle=true;;
		-p|--plist)
			plist="$2"
			shift 1 ;;
		-h|--help)
			help
			exit 0 ;;
		-sdkroot)
			sdkroot="$2"
			shift 1 ;;
		*)
			echo "Invalid command line option: $1"
			exit 2 ;;
	esac
	shift 1
done

# Safety tests
if [ ! -e "$LIBPREFIX" ]; then
	echo "Cannot find the directory containing the libraries: $LIBPREFIX" >&2
	exit 1
fi

if [ "$create_bundle" = "true" ]; then
	echo -e "\nCREATE WIRESHARK APP BUNDLE\n"

	if [ ! -x "$binary_path/$wireshark_bin_name" ]; then
		echo "Couldn't find $binary_path/$wireshark_bin_name (or it's not executable)" >&2
		exit 1
	fi

	for binary in $cli_binary_list ; do
		binary=$( basename $binary )
		if [ ! -x "$binary_path/$binary" ]; then
			echo "Couldn't find $binary (or it's not executable)" >&2
			exit 1
		fi
	done

	for binary in $extcap_binary_list ; do
		binary=$( basename $binary )
		if [ ! -x "$extcap_path/$binary" ]; then
			echo "Couldn't find $binary (or it's not executable)" >&2
			exit 1
		fi
	done

	if [ ! -f "$plist" ]; then
		echo "Need plist file" >&2
		exit 1
	fi
elif [ ! -d "$bundle" ] ; then
	echo "$bundle not found" >&2
	exit 1
fi

for i in 5 ""
do
	qt_frameworks_dir=`pkg-config --libs Qt${i}Core | sed -e 's/-F//' -e 's/ -framework.*//'`
	if [ ! -z "$qt_frameworks_dir" ] ; then
		# found it
		break;
	fi
done
if [ -z "$qt_frameworks_dir" ] ; then
	echo "Can't find the Qt frameworks directory" >&2
	exit 1
fi

#
# Leave the Qt frameworks out of the special processing.
#
exclude_prefixes="$exclude_prefixes|$qt_frameworks_dir"

# Package paths
pkgexec="$bundle/Contents/MacOS"
pkgres="$bundle/Contents/Resources"
pkgbin="$pkgres/bin"
pkglib="$bundle/Contents/Frameworks"
pkgplugin="$bundle/Contents/PlugIns/wireshark"

# Set the 'macosx' directory, usually the current directory.
resdir=`pwd`

# Create the application bundle.
# This is only used by Autotools. This can be removed if we start using
# CMake exclusively.
create_bundle() {
	# Remove a previously existing bundle if necessary
	if [ -d $bundle ]; then
		echo "Removing previous $bundle"
		rm -Rf $bundle
	fi

	# Prepare Package
	#----------------------------------------------------------

	mkdir -p "$pkgexec"
	mkdir -p "$pkgexec/extcap"
	mkdir -p "$pkgbin"
	mkdir -p "$pkgplugin"

	# Copy all files into the bundle
	#----------------------------------------------------------
	echo -e "\nFilling app bundle and utility directory...\n"

	# Wireshark executables
	cp -v "$binary_path/$wireshark_bin_name" "$pkgexec/Wireshark"
	cs_binary_list="$cs_binary_list $pkgexec/Wireshark"
	for binary in $cli_binary_list ; do
		# Copy the binary to the executable directory
		cp -v "$binary_path/$binary" "$pkgexec"
		cs_binary_list="$cs_binary_list $pkgexec/$binary"
	done

	#
	# extcap binaries
	#
	for binary in $extcap_binary_list ; do
		# Copy the binary to its destination
		binary=$( basename $binary )
		bin_dest="$pkgexec/extcap"
		cp -v "$extcap_path/$binary" "$bin_dest"
		cs_binary_list="$cs_binary_list $bin_dest/$binary"
	done

	#
	# Executable launchers in $pkgbin
	#
	# We can't just symbolically link to the executables, as
	# that means that the executable won't be in Contents/MacOS,
	# which means that all @executable_path-relative references
	# will go to the wrong place if we run the executables using
	# the symlink, which means that the executables could fail
	# (they *do* fail to find the Cocoa Qt plugin, for example).
	#
	cp utility-launcher/wireshark $pkgbin
	for binary in $cli_binary_list ; do
		ln -s ./wireshark $pkgbin/$binary
	done

	# The rest of the Wireshark installation (we handled bin above)
	rsync -av \
		--exclude bin/ \
		--exclude lib/ \
		"$binary_path/.."/* "$pkgres"

	rsync -av $library_path/*.dylib "$pkglib/"

	# Copy the plugins from the "make install" location for them
	# to the plugin directory, removing the version number
	find "$plugin_path" \
		-type f \
		\( -name "*.so" -o -name "*.dylib" \) \
		-exec cp -fv "{}" "$pkgplugin/" \;

	cp "$plist" "$bundle/Contents/Info.plist"

	# Icons and the rest of the script framework
	res_list="
		Wireshark.icns
		Wiresharkdoc.icns
	"

	for rl_entry in $res_list ; do
		rsync -av "$resdir"/$rl_entry "$bundle"/Contents/Resources/
	done

	# PkgInfo must match bundle type and creator code from Info.plist
	echo "APPLWshk" > $bundle/Contents/PkgInfo

} # create_bundle

if [ "$create_bundle" = "true" ]; then
	create_bundle
fi

if [ -z "$cs_binary_list" ]; then
	for binary in Wireshark $cli_binary_list ; do
		cs_binary_list="$cs_binary_list $pkgexec/$binary"
	done
fi


echo -e "\nFixing up $bundle...\n"

# Find out libs we need from Fink, MacPorts, or from a custom install
# (i.e. $LIBPREFIX), then loop until no changes.
a=1
nfiles=0
endl=true
lib_dep_search_list="
	$pkglib/*
	$pkgexec/*
	$pkgexec/extcap/*
	"

while $endl; do
	echo -e "Looking for dependencies. Round" $a
	#
	# libssh, for some reason, has its "install name" set to
	# just libssh.4.dylib, rather than /usr/local/lib/libssh.4.dylib,
	# when built by macosx-setup.sh.  We have to fix that; that's
	# what the sed command does.
	#
	libs="`\
		otool -L $lib_dep_search_list 2>/dev/null \
		| fgrep compatibility \
		| cut -d\( -f1 \
		| sed '1,$s;^	libssh;	/usr/local/lib/libssh;' \
		| egrep -v "$exclude_prefixes" \
		| sort \
		| uniq \
		`"
	cp -vn $libs "$pkglib"
	let "a+=1"
	nnfiles=`ls "$pkglib" | wc -l`
	if [ $nnfiles = $nfiles ]; then
		endl=false
	else
		nfiles=$nnfiles
	fi
done

chmod 755 "$pkglib"/*.dylib

# Strip libraries and executables if requested
#----------------------------------------------------------
if [ "$strip" = "true" ]; then
	echo -e "\nStripping debugging symbols...\n"
	strip -x "$pkglib"/*.dylib
	strip -ur "$binpath"
fi

#
# This may not work on Qt 5.5.0 or 5.5.1:
# https://bugreports.qt.io/browse/QTBUG-47868
#
macdeployqt "$bundle" -verbose=2 || exit 1

#
# The build process added to the Wireshark binary an rpath entry
# pointing to the directory containing the Qt frameworks; remove
# that entry from the Wireshark binary in the package.
#
/usr/bin/install_name_tool -delete_rpath "$qt_frameworks_dir" $pkgexec/Wireshark

# NOTE: we must rpathify *all* files, *including* Qt libraries etc.,
#
rpathify_file () {
	# Fix a given executable, library, or plugin to be relocatable
	if [ ! -f "$1" ]; then
		return 0;
	fi

	#
	# OK, what type of file is this?
	#
	filetype=$( otool -hv "$1" | sed -n '4p' | awk '{print $5}' ; exit ${PIPESTATUS[0]} )
	if [ $? -ne 0 ] ; then
		echo "Unable to rpathify $1 in $( pwd ): file type failed."
		exit 1
	fi

	case "$filetype" in

	EXECUTE|DYLIB|BUNDLE)
		#
		# Executable, library, or plugin.  (Plugins
		# can be either DYLIB or BUNDLE; shared
		# libraries are DYLIB.)
		#
		# For DYLIB and BUNDLE, fix the shared
		# library identification.
		#
		if [[ "$filetype" = "DYLIB" || "$filetype" = "BUNDLE" ]]; then
			echo "Changing shared library identification of $1"
			base=`echo $1 | awk -F/ '{print $NF}'`
			#
			# The library will end up in a directory in
			# the rpath; this is what we should change its
			# ID to.
			#
			to=@rpath/$base
			/usr/bin/install_name_tool -id $to $1

			#
			# If we're a library and we depend on something in
			# @executable_path/../Frameworks, replace that with
			# @rpath.
			#
			otool -L $1 | grep @executable_path/../Frameworks | awk '{print $1}' | \
			while read dep_lib ; do
				base=`echo $dep_lib | awk -F/ '{print $NF}'`
				to="@rpath/$base"
				echo "Changing reference to $dep_lib to $to in $1"
				/usr/bin/install_name_tool -change $dep_lib $to $1
			done
		fi

		#
		# Find our local rpaths and remove them.
		#
		otool -l $1 | grep -A2 LC_RPATH \
			| awk '$1=="path" && $2 !~ /^@/ {print $2}' \
			| egrep -v "$exclude_prefixes" | \
		while read lc_rpath ; do
			echo "Stripping LC_RPATH $lc_rpath from $1"
			install_name_tool -delete_rpath $lc_rpath $1
		done

		#
		# Add -Wl,-rpath,@executable_path/../Frameworks
		# to the rpath, so it'll find the bundled
		# frameworks and libraries if they're referred
		# to by @rpath/, rather than having a wrapper
		# script tweak DYLD_LIBRARY_PATH.
		#
		if [[ "$filetype" = "EXECUTE" ]]; then
			if [ -d ../Frameworks ] ; then
				framework_path=../Frameworks
			elif [ -d ../../Frameworks ] ; then
				framework_path=../../Frameworks
			else
				echo "Unable to find relative path to Frameworks for $1 from $( pwd )"
				exit 1
			fi

			echo "Adding @executable_path/$framework_path to rpath of $1"
			/usr/bin/install_name_tool -add_rpath @executable_path/$framework_path $1
		fi

		#
		# Show the minimum supported version of OS X
		# for each executable or library
		#
		if [[ "$filetype" = "EXECUTE" || "$filetype" = "DYLIB" ]] && [[ "$VERSION" -ge "7" ]] ; then
			echo "Minimum OS X version for $1:"
			otool -l $1 | grep -A3 LC_VERSION_MIN_MACOSX
		fi

		#
		# Get the list of dynamic libraries on which this
		# file depends, and select only the libraries that
		# are in $LIBPREFIX, as those are the only ones
		# that we'll be shipping in the app bundle; the
		# other libraries are system-supplied or supplied
		# as part of X11, will be expected to be on the
		# system on which the bundle will be installed,
		# and should be referred to by their full pathnames.
		#
		libs="`\
			otool -L $1 \
			| fgrep compatibility \
			| cut -d\( -f1 \
			| egrep -v "$exclude_prefixes" \
			| sort \
			| uniq \
			`"

		for lib in $libs; do
			#
			# Get the file name of the library.
			#
			base=`echo $lib | awk -F/ '{print $NF}'`
			#
			# The library will end up in a directory in
			# the rpath; this is what we should change its
			# file name to.
			#
			to=@rpath/$base
			#
			# Change the reference to that library.
			#
			echo "Changing reference to $lib to $to in $1"
			/usr/bin/install_name_tool -change $lib $to $1
		done
		;;
	esac
}

rpathify_dir () {
	#
	# Make sure we *have* that directory
	#
	if [ -d "$1" ]; then
		(cd "$1"
		#
		# Make sure we *have* files to fix
		#
		files=`ls $2 2>/dev/null`
		if [ ! -z "$files" ]; then
			for file in $files; do
				rpathify_file "$file" "`pwd`"
			done
		fi
		)
		rf_ret=$?
		if [ $rf_ret -ne 0 ] ; then exit $rf_ret ; fi
	fi
}

rpathify_files () {
	#
	# Fix bundle deps
	#
	rpathify_dir "$pkglib" "*.dylib"
	rpathify_dir "$pkgexec" "*"
	rpathify_dir "$pkgplugin" "*"

	rpathify_dir "$pkgexec/extcap" "*"
}

PATHLENGTH=`echo $LIBPREFIX | wc -c`
if [ "$PATHLENGTH" -ge "6" ]; then
	# If the LIBPREFIX path is long enough to allow
	# path rewriting, then do this.
	# 6 is the length of @rpath, which replaces LIBPREFIX.
	rpathify_files
else
	echo "Could not rewrite dylib paths for bundled libraries.  This requires" >&2
	echo "the support libraries to be installed in a PREFIX of at least 6 characters in length." >&2
	echo "" >&2
	echo "The bundle will still work if the following line is uncommented in" >&2
	echo "Wireshark.app/Contents/Resources/bin/{various scripts}:" >&2
	echo '        export DYLD_LIBRARY_PATH="$TOP/lib"' >&2
	exit 1

fi

codesign_file () {
	codesign --sign "Developer ID Application: $CODE_SIGN_IDENTITY" --verbose "$1"
	codesign --verify --verbose "$1" || exit 1
	spctl --assess --type execute "$1" || exit 1
}

if [ -n "$CODE_SIGN_IDENTITY" ] ; then
	security find-identity -v -s "$CODE_SIGN_IDENTITY" -p codesigning

	echo "Signing executables"
	if [ -z "$cs_binary_list" ] ; then
		echo "No executables specified for code signing."
		exit 1
	fi
	for binary in $cs_binary_list ; do
		if [ -e "$binary" ];then
			codesign_file "$binary"
		fi
	done

	echo "Signing frameworks"
	for framework in $pkglib/*.framework/Versions/*/* ; do
		codesign_file "$framework"
	done

	echo "Signing libraries"
	for library in $pkglib/*.dylib ; do
		codesign_file "$library"
	done

	echo "Signing plugins"
	for plugin in $pkgplugin/*.so ; do
		codesign_file "$plugin"
	done

	echo "Signing $bundle"
	codesign_file "$bundle"
else
	echo "Code signing not performed (no identity)"
fi

exit 0
