dnl Macros that test for specific features.
dnl This file is part of the Autoconf packaging for Ethereal.
dnl Copyright (C) 1998-2000 by Gerald Combs.
dnl
dnl $Id: acinclude.m4,v 1.12 2001/09/28 05:41:45 guy Exp $
dnl

#
# AC_WIRETAP_PCAP_CHECK
#
AC_DEFUN(AC_WIRETAP_PCAP_CHECK,
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
	  for pcap_dir in /usr/include/pcap /usr/local/include/pcap $prefix/include
	  do
	    if test -d $pcap_dir ; then
	      CFLAGS="$CFLAGS -I$pcap_dir"
	      CPPFLAGS="$CPPFLAGS -I$pcap_dir"
	      found_pcap_dir=" $found_pcap_dir -I$pcap_dir"
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
	  # already in CFLAGS, CPPFLAGS, or LDFLAGS, this won't
	  # make us find the version in the specified directory,
	  # as the compiler and/or linker will search that other
	  # directory before it searches the specified directory.
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
AC_DEFUN(AC_WIRETAP_ZLIB_CHECK,
[
	AC_CHECK_HEADER(zlib.h,,enable_zlib=no)

	if test x$enable_zlib != xno
	then
		#
		# Well, we at least have the zlib header file.
		#
		# Check for "gzseek()" in zlib, because we need it, but
		# some older versions of zlib don't have it.  It appears
		# from the zlib ChangeLog that any released version of zlib
		# with "gzseek()" should have the other routines we
		# depend on, such as "gztell()" and "zError()".
		#
		AC_CHECK_LIB(z, gzseek,,enable_zlib=no)
	fi
])
