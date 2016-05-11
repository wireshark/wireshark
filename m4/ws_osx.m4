#
# Autoconf script for Wireshark
#

#
# AC_WIRESHARK_OSX_DEPLOY_TARGET
#
# Checks for OSX deployment target and selects version.
#
AC_DEFUN([AC_WIRESHARK_OSX_DEPLOY_TARGET],
[dnl
AC_ARG_ENABLE(osx-deploy-target,
  AC_HELP_STRING( [--enable-osx-deploy-target],
    [choose an OS X deployment target @<:@default=major release on which you're building@:>@]),
[
	#
	# Is this OS X?
	#
	case "$host_os" in
	darwin*)
		#
		# Yes.
		#
		# Let the user specify an OS X release to use as a
		# deplayment target; if they specify that we should
		# have a deployment target but don't specify the
		# deployment target, then, if we have SDKs available,
		# pick the OS version on which the build is being done.
		# This also causes the build to be done against an SDK
		# rather than against the headers and libraries in
		# /usr/include and /usr/lib.
		#
		# Check for an OS X deployment target early, so that
		# as many tests using the compiler are done using the
		# flags that we'll be using when building.
		#
		if test $enableval = no
		then
			#
			# The user explicitly said
			# --disable-osx-deploy-target, so don't build
			# against an SDK.
			#
			deploy_target=
		elif test $enableval = yes
		then
			#
			# The user said --enable-osx-deploy-target, but
			# didn't say what version to target; target the
			# major version number of the version of OS X on
			# which we're running.
			#
			# (We quote the command so that we can use
			# autoconf's M4 quoting characters, [ and ], in
			# the sed expression.)
			#
			[deploy_target=`sw_vers -productVersion | sed 's/\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.[0-9]*/\1.\2/'`]
		else
			deploy_target="$enableval"
		fi
		;;

	*)
		#
		# No.  Fail, because whatever the user intended for us to
		# do, we can't do it.
		#
		AC_MSG_ERROR([--enable-osx-deploy-target specified on an OS other than OS X])
		;;
	esac
],[
	#
	# Is this OS X?
	#
	case "$host_os" in
	darwin*)
		#
		# Yes.
		#
		# If we have SDKs available, default to targeting the major
		# version number of the version of OS X on which we're
		# running.
		#
		# (We quote the command so that we can use autoconf's
		# M4 quoting characters, [ and ], in the sed expression.)
		#
		for i in /Developer/SDKs \
		    /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs \
		    /Library/Developer/CommandLineTools/SDKs
		do
			if test -d "$i"
			then
				[deploy_target=`sw_vers -productVersion | sed 's/\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.[0-9]*/\1.\2/'`]
				break
			fi
		done
		;;

	*)
		#
		# No.  There's nothing to do.
		#
		;;
	esac
])

if test ! -z "$deploy_target"
then
	AC_MSG_CHECKING([whether we can build for OS X $deploy_target])
	case $deploy_target in

	10.0|10.1|10.2)
		#
		# I'm not sure this would even work.
		#
		AC_MSG_RESULT(no)
		AC_MSG_ERROR([We don't support building for OS X $deploy_target])
		;;

	10.3)
		#
		# XXX - never tested.
		#
		AC_MSG_RESULT(yes)
		SDKPATH="/Developer/SDKs/MacOSX10.3.9.sdk"
		;;

	*)
		#
		# Look for the oldest SDK we can find that's
		# for an OS equal to or later than this one.
		#
		# XXX - for 10.4, do we need 10.4u?  We're
		# not currently doing fat builds (we'd need
		# fat versions of the support libraries for
		# that to be useful), but, if we do, we'd
		# need to use 10.4u.
		#

		#
		# Get the real version - strip off the "10.".
		# We'll worry about that if, as, and when there's ever
		# an OS XI.
		#
		deploy_real_version=`echo "$deploy_target" | sed -n 's/10\.\(.*\)/\1/p'`

		#
		# Search each directory that might contain SDKs.
		#
		sdkpath=""
		for sdksdir in /Developer/SDKs \
		    /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs \
		    /Library/Developer/CommandLineTools/SDKs
		do
			#
			# Get a list of all the SDKs.
			#
			if ! test -d "$sdksdir"
			then
				#
				# There is no directory with that name.
				# Move on to the next one in the list,
				# if any.
				#
				continue
			fi

			#
			# Get a list of all the SDKs in that directory,
			# if any.
			#
			# We have to use @<:@ for [ and @:>@ for ] to
			# avoid m4 removing the square brackets.
			#
			sdklist=`(cd "$sdksdir"; ls -d MacOSX10.@<:@0-9@:>@*.sdk 2>/dev/null)`

			for sdk in $sdklist
			do
				#
				# Get the real version for this SDK.
				#
				sdk_real_version=`echo "$sdk" | sed -n 's/MacOSX10\.\(.*\)\.sdk/\1/p'`

				#
				# Is it for the deployment target or
				# some later release?
				#
				if test "$sdk_real_version" -ge "$deploy_real_version"
				then
					#
					# Yes, use it.
					#
					sdkpath="$sdksdir/$sdk"
					break 2
				fi
			done
		done
		if test -z "$sdkpath"
		then
			AC_MSG_RESULT(no)
			AC_MSG_ERROR([We couldn't find an SDK for OS X $deploy_target or later])
		fi
		SDKPATH="$sdkpath"
		AC_MSG_RESULT([yes, with the 10.$sdk_real_version SDK])
		;;
	esac

	#
	# Add a -mmacosx-version-min flag to force tests that
	# use the compiler, as well as the build itself, not to,
	# for example, use compiler or linker features not supported
	# by the minimum targeted version of the OS.
	#
	# Add an -isysroot flag to use the SDK.
	#
	WS_CFLAGS="-mmacosx-version-min=$deploy_target -isysroot $SDKPATH $WS_CFLAGS"
	WS_CXXFLAGS="-mmacosx-version-min=$deploy_target -isysroot $SDKPATH $WS_CXXFLAGS"
	WS_LDFLAGS="-mmacosx-version-min=$deploy_target -isysroot $SDKPATH $WS_LDFLAGS"

	#
	# Add a -sdkroot flag to use with osx-app.sh.
	#
	OSX_APP_FLAGS="-sdkroot $SDKPATH"

	#
	# XXX - do we need this to build the Wireshark wrapper?
	# XXX - is this still necessary with the -mmacosx-version-min
	# flag being set?
	#
	OSX_DEPLOY_TARGET="MACOSX_DEPLOYMENT_TARGET=$deploy_target"

	#
	# In the installer package XML file, give the deployment target
	# as the minimum version.
	#
	OSX_MIN_VERSION="$deploy_target"

	case $deploy_target in

	10.4|10.5)
		#
		# Only 32-bit builds are supported.  10.5
		# (and 10.4?) had a bug that causes some BPF
		# functions not to work with 64-bit userland
		# code, so capturing won't work.
		#
		WS_CFLAGS="-m32 $WS_CFLAGS"
		WS_CXXFLAGS="-m32 $WS_CXXFLAGS"
		WS_LDFLAGS="-m32 $WS_LDFLAGS"
		;;
	esac
else
	#
	# Is this OS X?
	#
	case "$host_os" in
	darwin*)
		#
		# Yes.
		#
		# In the installer package XML file, give the current OS
		# version, minor version and all, as the minimum version.
		# We can't guarantee that the resulting binary will work
		# on older OS versions, not even older minor versions
		# (original release or earlier software updates).
		#
		OSX_MIN_VERSION=`sw_vers -productVersion`
		;;
	esac
fi
AC_SUBST(OSX_MIN_VERSION)
])

#
# AC_WIRESHARK_OSX_INTEGRATION_CHECK
#
# Checks for the presence of OS X integration functions in the GTK+ framework
# or as a separate library.
#
# GTK+ for MAC OS X now lives on www.gtk.org at:
#
#   http://www.gtk.org/download/macos.php
#
# Details on building with GTK-OSX are available at:
#
#   http://live.gnome.org/GTK%2B/OSX/Building
#
# The GTK-OSX library has been renamed to gtkmacintegration.
# It was previously named igemacintegration.
#
# http://live.gnome.org/GTK%2B/OSX/Integration
#    for the old Carbon-based integration functions
#
AC_DEFUN([AC_WIRESHARK_OSX_INTEGRATION_CHECK],
[dnl
	AC_WIRESHARK_PUSH_FLAGS
	ac_save_LIBS="$LIBS"
	CFLAGS="$CFLAGS $GTK_CFLAGS"
	LIBS="$GTK_LIBS $LIBS"

	#
	# Check for the new integration functions in a -lgtkmacintegration
	# library.
	#
	AC_CHECK_LIB(gtkmacintegration, gtkosx_application_set_menu_bar,
	[
		AC_DEFINE(HAVE_GTKOSXAPPLICATION, 1,
			[Define to 1 if -lgtkmacintegration includes the GtkOSXApplication Integration functions.])
		have_ige_mac=yes
		# We don't want gtk stuff in LIBS (which is reset below) so
		# manually set GTK_LIBS (which is more appropriate)
		GTK_LIBS="$GTK_LIBS -lgtkmacintegration"
	])

	if test x$have_ige_mac = x
	then
		#
		# Not found - check for the old integration functions in
		# the Gtk framework.
		#
		AC_CHECK_LIB(Gtk, gtk_mac_menu_set_menu_bar,
		[
			AC_DEFINE(HAVE_IGE_MAC_INTEGRATION, 1,
				[Define to 1 if the the Gtk+ framework or a separate library includes the Imendio IGE Mac OS X Integration functions.])
			have_ige_mac=yes
			# We don't want gtk stuff in LIBS (which is reset below) so
			# manually set GTK_LIBS (which is more appropriate)
			GTK_LIBS="$GTK_LIBS -lGtk"
		])
	fi

	if test x$have_ige_mac = x
	then
		#
		# Not found - check for the old integration functions in
		# a -lgtkmacintegration library.
		#
		AC_CHECK_LIB(gtkmacintegration, gtk_mac_menu_set_menu_bar,
		[
			AC_DEFINE(HAVE_IGE_MAC_INTEGRATION, 1,
				[Define to 1 if the the Gtk+ framework or a separate library includes the Imendio IGE Mac OS X Integration functions.])
			have_ige_mac=yes
			# We don't want gtk stuff in LIBS (which is reset below) so
			# manually set GTK_LIBS (which is more appropriate)
			GTK_LIBS="$GTK_LIBS -lgtkmacintegration"
		])
	fi
	LIBS="$ac_save_LIBS"
	AC_WIRESHARK_POP_FLAGS
])
