#
# Autoconf script for Wireshark
#

#
# AC_WIRESHARK_OSX_INTEGRATION_CHECK
#
# Checks for the presence of macOS integration functions in the GTK+ framework
# or as a separate library.
#
# GTK+ for macOS now lives on www.gtk.org at:
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
				[Define to 1 if the the Gtk+ framework or a separate library includes the Imendio IGE macOS Integration functions.])
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
				[Define to 1 if the the Gtk+ framework or a separate library includes the Imendio IGE macOS Integration functions.])
			have_ige_mac=yes
			# We don't want gtk stuff in LIBS (which is reset below) so
			# manually set GTK_LIBS (which is more appropriate)
			GTK_LIBS="$GTK_LIBS -lgtkmacintegration"
		])
	fi
	LIBS="$ac_save_LIBS"
	AC_WIRESHARK_POP_FLAGS
])
