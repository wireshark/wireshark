dnl Macros that test for specific features.
dnl This file is part of the Autoconf packaging for Wireshark.
dnl Copyright (C) 1998-2000 by Gerald Combs.
dnl
dnl $Id$
dnl

#
# AC_WIRETAP_ADD_DASH_L
#
# Add to the variable specified as the first argument a "-L" flag for the
# directory specified as the second argument, and, on Solaris, add a
# "-R" flag for it as well.
#
# XXX - IRIX, and other OSes, may require some flag equivalent to
# "-R" here.
#
AC_DEFUN([AC_WIRETAP_ADD_DASH_L],
[$1="$$1 -L$2"
case "$host_os" in
  solaris*)
    $1="$$1 -R$2"
  ;;
esac
])

#
# AC_WIRETAP_PCAP_CHECK
#
AC_DEFUN([AC_WIRETAP_PCAP_CHECK],
[
	if test -z "$pcap_dir"
	then
	  #
	  # The user didn't specify a directory in which libpcap resides;
	  # we assume that the current library search path will work,
	  # but we may have to look for the header in a "pcap"
	  # subdirectory of "/usr/include" or "/usr/local/include",
	  # as some systems apparently put "pcap.h" in a "pcap"
	  # subdirectory, and we also check "$prefix/include".
	  #
	  # XXX - should we just add "$prefix/include" to the include
	  # search path?
	  #
	  AC_MSG_CHECKING(for extraneous pcap header directories)
	  found_pcap_dir=""
	  for pcap_dir in /usr/include/pcap $prefix/include /usr/local/include/pcap
	  do
	    if test -d $pcap_dir ; then
	      if test x$pcap_dir != x/usr/include; then
		CFLAGS="$CFLAGS -I$pcap_dir"
		CPPFLAGS="$CPPFLAGS -I$pcap_dir"
	      fi
	      found_pcap_dir=" $found_pcap_dir -I$pcap_dir"
	      break
	    fi
	  done

	  if test "$found_pcap_dir" != "" ; then
	    AC_MSG_RESULT(found --$found_pcap_dir added to CFLAGS)
	  else
	    AC_MSG_RESULT(not found)
	  fi
	else
	  #
	  # The user specified a directory in which libpcap resides,
	  # so add the "include" subdirectory of that directory to
	  # the include file search path.
	  #
	  # XXX - if there's also a libpcap in a directory that's
	  # already in CFLAGS or CPPFLAGS, this won't make us find
	  # the version in the specified directory, as the compiler
	  # will search that other directory before it searches the
	  # specified directory.
	  #
	  CFLAGS="$CFLAGS -I$pcap_dir/include"
	  CPPFLAGS="$CPPFLAGS -I$pcap_dir/include"
	fi

	# Pcap header check
	AC_CHECK_HEADERS(pcap.h)
])

#
# AC_WIRETAP_ZLIB_CHECK
#
AC_DEFUN([AC_WIRETAP_ZLIB_CHECK],
[
	if test "x$zlib_dir" != "x"
	then
	  #
	  # The user specified a directory in which zlib resides,
	  # so add the "include" subdirectory of that directory to
	  # the include file search path and the "lib" subdirectory
	  # of that directory to the library search path.
	  #
	  # XXX - if there's also a zlib in a directory that's
	  # already in CFLAGS, CPPFLAGS, or LDFLAGS, this won't
	  # make us find the version in the specified directory,
	  # as the compiler and/or linker will search that other
	  # directory before it searches the specified directory.
	  #
	  wiretap_save_CFLAGS="$CFLAGS"
	  CFLAGS="$CFLAGS -I$zlib_dir/include"
	  wiretap_save_CPPFLAGS="$CPPFLAGS"
	  CPPFLAGS="$CPPFLAGS -I$zlib_dir/include"
	  wiretap_save_LIBS="$LIBS"
	  AC_WIRETAP_ADD_DASH_L(LIBS, $zlib_dir/lib)
	fi

	#
	# Make sure we have "zlib.h".  If we don't, it means we probably
	# don't have zlib, so don't use it.
	#
	AC_CHECK_HEADER(zlib.h,,
	  [
	    if test "x$zlib_dir" != "x"
	    then
	      #
	      # The user used "--with-zlib=" to specify a directory
	      # containing zlib, but we didn't find the header file
	      # there; that either means they didn't specify the
	      # right directory or are confused about whether zlib
	      # is, in fact, installed.  Report the error and give up.
	      #
	      AC_MSG_ERROR([zlib header not found in directory specified in --with-zlib])
	    else
	      if test "x$want_zlib" = "xyes"
	      then
		#
		# The user tried to force us to use the library, but we
		# couldn't find the header file; report an error.
		#
		AC_MSG_ERROR(Header file zlib.h not found.)
	      else
		#
		# We couldn't find the header file; don't use the
		# library, as it's probably not present.
		#
		want_zlib=no
	      fi
	    fi
	  ])

	if test "x$want_zlib" != "xno"
	then
		#
		# Well, we at least have the zlib header file.
		#
		# Check for "gzgets()" in zlib, because we need it, but
		# some older versions of zlib don't have it.  It appears
		# from the zlib ChangeLog that any released version of zlib
		# with "gzgets()" should have the other routines we
		# depend on, such as "gzseek()", "gztell()", and "zError()".
		#
		# Another reason why we require "gzgets()" is that
		# some versions of zlib that didn't have it, such
		# as 1.0.8, had a bug in "gzseek()" that meant that it
		# doesn't work correctly on uncompressed files; this
		# means we cannot use version 1.0.8.  (Unfortunately,
		# that's the version that comes with recent X11 source,
		# and many people who install XFree86 on their Slackware
		# boxes don't realize that they should configure it to
		# use the native zlib rather than building and installing
		# the crappy old version that comes with XFree86.)
		#
		# I.e., we can't just avoid using "gzgets()", as
		# versions of zlib without "gzgets()" are likely to have
		# a broken "gzseek()".
		#
		AC_CHECK_LIB(z, gzgets,
		[
			if test "x$zlib_dir" != "x"
			then
				#
				# Put the "-I" and "-L" flags for zlib at
				# the beginning of CFLAGS, CPPFLAGS, and
				# LIBS.
				#
				LIBS=""
				AC_WIRETAP_ADD_DASH_L(LIBS, $zlib_dir/lib)
				LIBS="$LIBS -lz $wiretap_save_LIBS"
			else
				LIBS="-lz $LIBS"
			fi
			AC_DEFINE(HAVE_LIBZ, 1, [Define to use libz library])
		],[
			if test "x$zlib_dir" != "x"
			then
				#
				# Restore the versions of CFLAGS, CPPFLAGS,
				# and LIBS before we added the "-with-zlib="
				# directory, as we didn't actually find
				# zlib there, or didn't find a zlib that
				# contains gzgets there.
				#
			        CFLAGS="$wiretap_save_CFLAGS"
				CPPFLAGS="$wiretap_save_CPPFLAGS"
				LIBS="$wiretap_save_LIBS"
			fi
			want_zlib=no
		])
	fi

	if test "x$want_zlib" != "xno"
	then
		#
		# Well, we at least have the zlib header file and a zlib
		# with "gzgets()".
		#
		# Now check for "gzgets()" in zlib when linking with the
		# linker flags for GTK+ applications; people often grab
		# XFree86 source and build and install it on their systems,
		# and they appear sometimes to misconfigure XFree86 so that,
		# even on systems with zlib, it assumes there is no zlib,
		# so the XFree86 build process builds and installs its
		# own zlib in the X11 library directory.
		#
		# The XFree86 zlib is an older version that lacks
		# "gzgets()", and that's the zlib with which Ethereal
		# gets linked, so the build of Ethereal fails.
		#
		ac_save_CFLAGS="$CFLAGS"
		ac_save_LIBS="$LIBS"
		CFLAGS="$CFLAGS $GTK_CFLAGS"
		LIBS="$GTK_LIBS -lz $LIBS"
		AC_MSG_CHECKING([for gzgets missing when linking with X11])
	        AC_TRY_LINK_FUNC(gzgets, AC_MSG_RESULT(no),
		  [
		    AC_MSG_RESULT(yes)
		    AC_MSG_ERROR(old zlib found when linking with X11 - get rid of old zlib.)
		  ])
		CFLAGS="$ac_save_CFLAGS"
		LIBS="$ac_save_LIBS"
	fi
])

dnl
dnl Check whether a given format can be used to print 64-bit integers
dnl
AC_DEFUN([AC_WIRETAP_CHECK_64BIT_FORMAT],
[
  AC_MSG_CHECKING([whether %$1x can be used to format 64-bit integers])
  AC_RUN_IFELSE(
    [
      AC_LANG_SOURCE(
	[[
	  #include <glib.h>
	  #if GTK_MAJOR_VERSION >= 2
	  #include <glib/gprintf.h>
	  #endif
	  #include <stdio.h>

	  main()
	  {
	    guint64 t = 1;
	    char strbuf[16+1];
	    g_snprintf(strbuf, sizeof strbuf, "%016$1x", t << 32);
	    if (strcmp(strbuf, "0000000100000000") == 0)
	      exit(0);
	    else
	      exit(1);
	  }
	]])
    ],
    [
      AC_DEFINE(G_GINT64_MODIFIER, "$1", [Format modifier for printing 64-bit numbers])
      AC_MSG_RESULT(yes)
    ],
    [
      AC_MSG_RESULT(no)
      $2
    ])
])
