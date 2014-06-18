#!/bin/bash
#
# USAGE
# osx-app [-s] [-l /path/to/libraries] -bp /path/to/wireshark/bin -p /path/to/Info.plist
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
plist="./Info.plist"
exclude_prefixes="/System/|/Library/|/usr/lib/|/usr/X11/|/opt/X11/|@rpath|@executable_path"


# "qt" or "gtk"
ui_toolkit="gtk"
# Name of the Wireshark executable
wireshark_bin_name="wireshark"

binary_list="
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
	$0 [-s] [-l /path/to/libraries] [-qt] -bp /path/to/wireshark/binaries -p /path/to/Info.plist

OPTIONS
	-h,--help
		display this help message
	-s
		strip the libraries and executables from debugging symbols
	-l,--libraries
		specify the path to the libraries Wireshark depends on
		(typically /sw or /opt/local).  By default it is
		/usr/local.
	-bp,--binary-path
		specify the path to the Wireshark binaries. By default it
		is /tmp/inst/bin.
	-p,--plist
		specify the path to Info.plist. Info.plist can be found
		in the base directory of the source code once configure
		has been run.
	-sdkroot
		specify the root of the SDK to use
	-qt,--qt-flavor
		use the Qt flavor

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
		-p|--plist)
			plist="$2"
			shift 1 ;;
		-qt|--qt-flavor)
			ui_toolkit="qt"
			wireshark_bin_name="wireshark-qt"
			;;
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

echo -e "\nCREATE WIRESHARK APP BUNDLE\n"

# Safety tests
if [ ! -e "$LIBPREFIX" ]; then
	echo "Cannot find the directory containing the libraries: $LIBPREFIX" >&2
	exit 1
fi

for binary in $wireshark_bin_name $binary_list ; do
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

# Set the SDK root, if an SDK was specified.
# (-sdk is only supported by the xcodebuild in the version of the
# developer tools that came with Snow Leopard and later versions)
if [ ! -z "$sdkroot" ]
then
	XCODEFLAGS="$XCODEFLAGS SDKROOT=$sdkroot"
fi

# Bundle always has the same name. Version information is stored in
# the Info.plist file which is filled in by the configure script.
bundle="Wireshark.app"

# Remove a previously existing bundle if necessary
if [ -d $bundle ]; then
	echo "Removing previous $bundle"
	rm -Rf $bundle
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
pkgexec="$bundle/Contents/MacOS"
pkgres="$bundle/Contents/Resources"
pkgbin="$pkgexec"
pkglib="$bundle/Contents/Frameworks"
pkgplugin="$bundle/Contents/PlugIns/wireshark"

#
# For Qt, the Wireshark binary is the main binary of the app bundle.
# For GTK+, the Wireshark binary is wireshark-bin in
# Contents/Resources/bin, so some of the above setting have to change.
#
if [ "$ui_toolkit" = "gtk" ] ; then
	pkgbin="$pkgres/bin"
	pkglib="$pkgres/lib"
fi

mkdir -p "$pkgexec"
mkdir -p "$pkgbin"
mkdir -p "$pkgplugin"

if [ "$ui_toolkit" = "qt" ] ; then
	cp "$binary_path/$wireshark_bin_name" "$pkgexec/Wireshark"
else
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

fi

# Copy all files into the bundle
#----------------------------------------------------------
echo -e "\nFilling app bundle and utility directory...\n"

# Wireshark executables
if [ "$ui_toolkit" = "gtk" ] ; then
	for binary in $binary_list wireshark ; do
		# Copy the binary to its destination
		dest_path="$pkgbin/$binary-bin"
		cs_binary_list="$cs_binary_list $dest_path"
		cp -v "$binary_path/$binary" "$dest_path"
		# TODO Add a "$verbose" variable and command line switch, which sets wether these commands are verbose or not

		if [ "$binary" != "wireshark" ] ; then
			ln -sv ./wireshark "$pkgbin/$binary"
		fi
	done
elif [ "$ui_toolkit" = "qt" ] ; then
	for binary in $binary_list ; do
		# Copy the binary to its destination
		cp -v "$binary_path/$binary" "$pkgexec"
		cs_binary_list="$cs_binary_list $pkgexec/$binary"
	done
fi

# The rest of the Wireshark installation (we handled bin above)
rsync -av \
	--exclude bin/ \
	--exclude lib/ \
	"$binary_path/.."/* "$pkgres"

rsync -av $binary_path/../lib/*.dylib "$pkglib/"

# Copy the plugins from the "make install" location for them
# to the plugin directory, removing the version number
find "$binary_path/../lib/wireshark/plugins" -type f \
	-exec cp -fv "{}" "$pkgplugin/" \;

cp "$plist" "$bundle/Contents/Info.plist"

# Icons and the rest of the script framework
res_list="
	Wireshark.icns
	Wiresharkdoc.icns
"

if [ "$ui_toolkit" = "gtk" ] ; then
	res_list="
		$res_list
		bin
		etc
		openDoc
		script
		MenuBar.nib
		ProgressWindow.nib
		themes
	"
fi

for rl_entry in $res_list ; do
	rsync -av "$resdir"/Resources/$rl_entry "$bundle"/Contents/Resources/
done

# PkgInfo must match bundle type and creator code from Info.plist
echo "APPLWshk" > $bundle/Contents/PkgInfo

if [ "$ui_toolkit" = "gtk" ] ; then

	# Pull in extra requirements for Pango and GTK
	pkgetc="$bundle/Contents/Resources/etc"
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
	#
	# In newer versions of GTK+, the gdk-pixbuf library was split off from
	# GTK+, and the gdk-pixbuf.loaders file moved, so we check for its
	# existence here.
	#
	# The file is ultimately copied to the user's home directory, with
	# the pathnames adjusted to refer to the installed bundle, so we
	# always put it in the same location in the installed bundle,
	# regardless of where it lives in the machine on which it's built.
	#
	if [ -e $LIBPREFIX/etc/gtk-2.0/gdk-pixbuf.loaders ]
	then
		sed -e "s,$LIBPREFIX,\${CWD},g" $LIBPREFIX/etc/gtk-2.0/gdk-pixbuf.loaders > $pkgetc/gtk-2.0/gdk-pixbuf.loaders
	fi
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
		#
		# As per the above, check whether we have a loaders.cache file
		# in $LIBPREFIX/lib/gdk-pixbuf-2.0/$gdk_pixbuf_version, as
		# that's where the output of gdk-pixbuf-query-loaders gets
		# put if gdk-pixbuf and GTK+ are separated.
		#
		# The file is ultimately copied to the user's home directory,
		# with the pathnames adjusted to refer to the installed bundle,
		# so we always put it in the same location in the installed
		# bundle, regardless of where it lives in the machine on which
		# it's built.
		#
		if [ -e $LIBPREFIX/lib/gdk-pixbuf-2.0/$gdk_pixbuf_version/loaders.cache ]
		then
			sed -e "s,$LIBPREFIX,\${CWD},g" $LIBPREFIX/lib/gdk-pixbuf-2.0/$gdk_pixbuf_version/loaders.cache > $pkgetc/gtk-2.0/gdk-pixbuf.loaders
		fi
		cp -r $LIBPREFIX/lib/gdk-pixbuf-2.0/$gdk_pixbuf_version/loaders/* $pkglib/gdk-pixbuf-2.0/$gdk_pixbuf_version/loaders
	fi
fi # GTK+ / Qt

# Find out libs we need from Fink, MacPorts, or from a custom install
# (i.e. $LIBPREFIX), then loop until no changes.
a=1
nfiles=0
endl=true
lib_dep_search_list="
	$pkglib/*
	$pkgbin/*-bin
	"
if [ "$ui_toolkit" = "gtk" ] ; then
	lib_dep_search_list="
		$lib_dep_search_list
		$pkglib/gtk-2.0/$gtk_version/loaders/*
		$pkglib/gtk-2.0/$gtk_version/immodules/*
		$pkglib/gtk-2.0/$gtk_version/engines/*.so
		$pkglib/pango/$pango_version/modules/*
		$pkglib/gdk-pixbuf-2.0/$gdk_pixbuf_version/loaders/*
		"
elif [ "$ui_toolkit" = "qt" ] ; then
	lib_dep_search_list="
		$pkgexec/Wireshark
		$lib_dep_search_list
		"
fi

while $endl; do
	echo -e "Looking for dependencies. Round" $a
	libs="`\
		otool -L $lib_dep_search_list 2>/dev/null \
		| fgrep compatibility \
		| cut -d\( -f1 \
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

# Add extra libraries of necessary
for libfile in $EXTRALIBS
do
	cp -f $libfile "$pkglib"
done
chmod 755 "$pkglib"/*.dylib

# Strip libraries and executables if requested
#----------------------------------------------------------
if [ "$strip" = "true" ]; then
	echo -e "\nStripping debugging symbols...\n"
	strip -x "$pkglib"/*.dylib
	strip -ur "$binpath"
fi

# NOTE: we must rpathify *all* files, *including* plugins for GTK+ etc.,
#	to keep	GTK+ from crashing at startup.
#
rpathify_file () {
	# Fix a given executable, library, or plugin to be relocatable
	if [ ! -d "$1" ]; then
		#
		# OK, what type of file is this?
		#
		filetype=`otool -hv "$1" | sed -n '4p' | awk '{print $5}'`
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
			fi

			#
			# Show the minimum supported version of Mac OS X
			# for each executable or library
			#
			if [[ "$filetype" = "EXECUTE" || "$filetype" = "DYLIB" ]] && [[ "$VERSION" -ge "7" ]] ; then
				echo "Minimum Mac OS X version for $1:"
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
	fi
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
	fi
}

rpathify_files () {
	#
	# Fix bundle deps
	#
	rpathify_dir "$pkglib" "*.dylib"
	if [ "$ui_toolkit" = "gtk" ] ; then
		rpathify_dir "$pkglib/gtk-2.0/$gtk_version/loaders" "*.so"
		rpathify_dir "$pkglib/gtk-2.0/$gtk_version/engines" "*.so"
		rpathify_dir "$pkglib/gtk-2.0/$gtk_version/immodules" "*.so"
		rpathify_dir "$pkglib/gtk-2.0/$gtk_version/printbackends" "*.so"
		rpathify_dir "$pkglib/gnome-vfs-2.0/modules" "*.so"
		rpathify_dir "$pkglib/gdk-pixbuf-2.0/$gtk_version/loaders" "*.so"
		rpathify_dir "$pkglib/pango/$pango_version/modules" "*.so"
	fi
	rpathify_dir "$pkgbin" "*"
}

if [ "$ui_toolkit" = "qt" ] ; then
	macdeployqt "$bundle" -verbose=2 || exit 1
fi

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
	for binary in $cs_binary_list ; do
		codesign_file "$binary"
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
