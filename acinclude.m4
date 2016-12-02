dnl Macros that test for specific features.
dnl This file is part of the Autoconf packaging for Wireshark.
dnl Copyright (C) 1998-2000 by Gerald Combs.
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2, or (at your option)
dnl any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
dnl 02111-1307, USA.
dnl
dnl As a special exception, the Free Software Foundation gives unlimited
dnl permission to copy, distribute and modify the configure scripts that
dnl are the output of Autoconf.  You need not follow the terms of the GNU
dnl General Public License when using or distributing such scripts, even
dnl though portions of the text of Autoconf appear in them.  The GNU
dnl General Public License (GPL) does govern all other use of the material
dnl that constitutes the Autoconf program.
dnl
dnl Certain portions of the Autoconf source text are designed to be copied
dnl (in certain cases, depending on the input) into the output of
dnl Autoconf.  We call these the "data" portions.  The rest of the Autoconf
dnl source text consists of comments plus executable code that decides which
dnl of the data portions to output in any given case.  We call these
dnl comments and executable code the "non-data" portions.  Autoconf never
dnl copies any of the non-data portions into its output.
dnl
dnl This special exception to the GPL applies to versions of Autoconf
dnl released by the Free Software Foundation.  When you make and
dnl distribute a modified version of Autoconf, you may extend this special
dnl exception to the GPL to apply to your modified version as well, *unless*
dnl your modified version has the potential to copy into its output some
dnl of the text that was the non-data portion of the version that you started
dnl with.  (In other words, unless your change moves or copies text from
dnl the non-data portions to the data portions.)  If your modification has
dnl such potential, you must delete any notice of this special exception
dnl to the GPL from your modified version.
dnl
dnl Written by David MacKenzie, with help from
dnl Franc,ois Pinard, Karl Berry, Richard Pixley, Ian Lance Taylor,
dnl Roland McGrath, Noah Friedman, david d zuhn, and many others.

#
# AC_WIRESHARK_ADD_DASH_L
#
# Add to the variable specified as the first argument a "-L" flag for the
# directory specified as the second argument, and, on Solaris, add a
# "-R" flag for it as well.
#
# XXX - IRIX, and other OSes, may require some flag equivalent to
# "-R" here.
#
AC_DEFUN([AC_WIRESHARK_ADD_DASH_L],
[AX_APPEND_FLAG(-L$2, $1)
case "$host_os" in
  solaris*)
    AX_APPEND_FLAG(-R$2, $1)
  ;;
esac
])

#
# AC_WIRESHARK_PUSH_FLAGS
#
# Push our flags to CFLAGS/etc.
#
AC_DEFUN([AC_WIRESHARK_PUSH_FLAGS],
[
  ac_ws_CPPLAGS_saved="$CPPFLAGS"
  ac_ws_CFLAGS_saved="$CFLAGS"
  ac_ws_CXXFLAGS_saved="$CXXFLAGS"
  ac_ws_LDFLAGS_saved="$LDFLAGS"
  CPPFLAGS="$WS_CPPFLAGS $CPPFLAGS"
  CFLAGS="$WS_CFLAGS $CFLAGS"
  CXXFLAGS="$WS_CXXFLAGS $CXXFLAGS"
  LDFLAGS="$WS_LDFLAGS $LDFLAGS"
])

#
# AC_WIRESHARK_POP_FLAGS
#
# Restore user build flags.
#
AC_DEFUN([AC_WIRESHARK_POP_FLAGS],
[
  CPPFLAGS="$ac_ws_CPPLAGS_saved"
  CFLAGS="$ac_ws_CFLAGS_saved"
  CXXFLAGS="$ac_ws_CXXFLAGS_saved"
  LDFLAGS="$ac_ws_LDFLAGS_saved"
])


#
# AC_WIRESHARK_BREAKLOOP_TRY_LINK
#
AC_DEFUN([AC_WIRESHARK_PCAP_BREAKLOOP_TRY_LINK],
[
  AC_LINK_IFELSE(
  [
      AC_LANG_SOURCE(
      [[
#	include <pcap.h>
	int main(void)
	{
	  pcap_t  *pct = NULL;
	  pcap_breakloop(pct);
	  return 0;
	}
      ]])
  ],
  [
    ws_breakloop_compiled=yes
  ],
  [
    ws_breakloop_compiled=no
  ])
])



#
# AC_WIRESHARK_PCAP_CHECK
#
AC_DEFUN([AC_WIRESHARK_PCAP_CHECK],
[
	AC_WIRESHARK_PUSH_FLAGS

	if test -z "$pcap_dir"
	then
	  # Pcap header checks
	  # XXX need to set a var AC_CHECK_HEADER(pcap.h,,)

	  #
	  # The user didn't specify a directory in which libpcap resides.
	  # First, look for a pcap-config script.
	  #
	  AC_PATH_TOOL(PCAP_CONFIG, pcap-config)

	  if test -n "$PCAP_CONFIG" ; then
	    #
	    # Found it.
	    #
	    # Now check whether it's the libpcap 1.0 version, which
	    # put a space after "-L" - on some platforms, that doesn't
	    # work.
	    #
	    AC_MSG_CHECKING(for broken pcap-config)
	    case "`\"$PCAP_CONFIG\" --libs`" in

	    "-L "*)
	      #
	      # Space after -L.  Pretend pcap-config doesn't exist.
	      #
	      AC_MSG_RESULT(yes)
	      PCAP_CONFIG=""
	      ;;

	    *)
	      #
	      # No space after -L.
	      #
	      AC_MSG_RESULT(no)
	      ;;
	    esac
	  fi
	  if test -n "$PCAP_CONFIG" ; then
	    #
	    # Found it, and it's usable; use it to get the include flags
	    # for libpcap.
	    #
	    CPPFLAGS="$CPPFLAGS `\"$PCAP_CONFIG\" --cflags`"
	  else
	    #
	    # Didn't find it; we have to look for libpcap ourselves.
	    # We assume that the current library search path will work,
	    # but we may have to look for the header in a "pcap"
	    # subdirectory of "/usr/include" or "/usr/local/include",
	    # as some systems apparently put "pcap.h" in a "pcap"
	    # subdirectory, and we also check "$prefix/include" - and
	    # "$prefix/include/pcap", in case $prefix is set to
	    # "/usr/include" or "/usr/local/include".
	    #
	    # XXX - should we just add "$prefix/include" to the include
	    # search path and "$prefix/lib" to the library search path?
	    #
	    AC_MSG_CHECKING(for extraneous pcap header directories)
	    found_pcap_dir=""
	    pcap_dir_list="/usr/local/include/pcap /usr/include/pcap $prefix/include/pcap $prefix/include"
	    for pcap_dir in $pcap_dir_list
	    do
	      if test -d $pcap_dir ; then
		if test x$pcap_dir != x/usr/include -a x$pcap_dir != x/usr/local/include ; then
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
	  fi
	else
	  #
	  # The user specified a directory in which libpcap resides,
	  # so add the "include" subdirectory of that directory to
	  # the include file search path and the "lib" subdirectory
	  # of that directory to the library search path.
	  #
	  # XXX - if there's also a libpcap in a directory that's
	  # already in CPPFLAGS or LDFLAGS, this won't make us find
	  # the version in the specified directory, as the compiler
	  # and/or linker will search that other directory before it
	  # searches the specified directory.
	  #
	  CPPFLAGS="$CPPFLAGS -I$pcap_dir/include"
	  AC_WIRESHARK_ADD_DASH_L(LDFLAGS, $pcap_dir/lib)
	fi

	# Pcap header check
	AC_CHECK_HEADER(pcap.h,,
	    AC_MSG_ERROR([[Header file pcap.h not found; if you installed libpcap
from source, did you also do \"make install-incl\", and if you installed a
binary package of libpcap, is there also a developer's package of libpcap,
and did you also install that package?]]))

	if test -n "$PCAP_CONFIG" ; then
	  #
	  # We have pcap-config; we assume that means we have libpcap
	  # installed and that pcap-config will tell us whatever
	  # libraries libpcap needs.
	  #
	  if test x$enable_static = xyes; then
	    PCAP_LIBS="`\"$PCAP_CONFIG\" --libs --static`"
	  else
	    PCAP_LIBS="`\"$PCAP_CONFIG\" --libs`"
	  fi
	  AC_DEFINE(HAVE_LIBPCAP, 1, [Define to use libpcap library])
	else
	  #
	  # Check to see if we find "pcap_open_live" in "-lpcap".
	  # Also check for various additional libraries that libpcap might
	  # require.
	  #
	  AC_CHECK_LIB(pcap, pcap_open_live,
	    [
	      PCAP_LIBS=-lpcap
	      AC_DEFINE(HAVE_LIBPCAP, 1, [Define to use libpcap library])
	    ], [
	      ac_wireshark_extras_found=no
	      ac_save_LIBS="$LIBS"
	      for extras in "-lcfg -lodm" "-lpfring"
	      do
		AC_MSG_CHECKING([for pcap_open_live in -lpcap with $extras])
		LIBS="-lpcap $extras $ac_save_LIBS"
		#
		# XXX - can't we use AC_CHECK_LIB here?
		#
		AC_TRY_LINK(
		    [
#	include <pcap.h>
		    ],
		    [
	pcap_open_live(NULL, 0, 0, 0, NULL);
		    ],
		    [
			ac_wireshark_extras_found=yes
			AC_MSG_RESULT([yes])
			PCAP_LIBS="-lpcap $extras"
			AC_DEFINE(HAVE_LIBPCAP, 1, [Define to use libpcap library])
		    ],
		    [
			AC_MSG_RESULT([no])
		    ])
		if test x$ac_wireshark_extras_found = xyes
		then
		    break
		fi
	      done
	      if test x$ac_wireshark_extras_found = xno
	      then
		AC_MSG_ERROR([Can't link with library libpcap.])
	      fi
	      LIBS=$ac_save_LIBS
	    ])
	fi
	AC_SUBST(PCAP_LIBS)

	#
	# Check whether various variables and functions are defined by
	# libpcap.
	#
	ac_save_LIBS="$LIBS"
	LIBS="$PCAP_LIBS $LIBS"
	AC_CHECK_FUNCS(pcap_open_dead pcap_freecode)
	#
	# pcap_breakloop may be present in the library but not declared
	# in the pcap.h header file.  If it's not declared in the header
	# file, attempts to use it will get warnings, and, if we're
	# building with warnings treated as errors, that warning will
	# cause compilation to fail.
	#
	# We are therefore first testing whether the function is present
	# and then, if we're compiling with warnings as errors, testing
	# whether it is usable.  It is usable if it compiles without
	# a -Wimplicit warning (the "compile with warnings as errors"
	# option requires GCC). If it is not usable, we fail and tell
	# the user that the pcap.h header needs to be updated.
	#
	# Ceteris paribus, this should only happen with Mac OS X 10.3[.x] which
	# can have an up-to-date pcap library without the corresponding pcap
	# header.
	#
	# However, it might also happen on some others OSes with some erroneous
	# system manipulations where multiple versions of libpcap might co-exist
	# e.g. hand made symbolic link from libpcap.so -> libpcap.so.0.8 but
	# having the pcap header version 0.7.
	#
	AC_MSG_CHECKING([whether pcap_breakloop is present])
	ac_CFLAGS_saved="$CFLAGS"
	AC_WIRESHARK_PCAP_BREAKLOOP_TRY_LINK
	if test "x$ws_breakloop_compiled" = "xyes"; then
	  AC_MSG_RESULT(yes)
	  AC_DEFINE(HAVE_PCAP_BREAKLOOP, 1, [Define if pcap_breakloop is known])
	  if test "x$with_warnings_as_errors" = "xyes"; then
	    AC_MSG_CHECKING([whether pcap_breakloop is usable])
	    CFLAGS="$CFLAGS -Werror -Wimplicit"
	    AC_WIRESHARK_PCAP_BREAKLOOP_TRY_LINK
	    if test "x$ws_breakloop_compiled" = "xyes"; then
	      AC_MSG_RESULT(yes)
	    else
	      AC_MSG_RESULT(no)
	      AC_MSG_ERROR(
[Your pcap library is more recent than your pcap header.
As you are building with compiler warnings treated as errors, Wireshark
won't be able to use functions not declared in that header.
If you wish to build with compiler warnings treated as errors, You should
install a newer version of the header file.])
	    fi
	    CFLAGS="$ac_CFLAGS_saved"
	  fi
	else
	  AC_MSG_RESULT(no)
	fi

	#
	# Later versions of Mac OS X 10.3[.x] ship a pcap.h that
	# doesn't define pcap_if_t but ship an 0.8[.x] libpcap,
	# so the library has "pcap_findalldevs()", but pcap.h
	# doesn't define "pcap_if_t" so you can't actually *use*
	# "pcap_findalldevs()".
	#
	# That even appears to be true of systems shipped with
	# 10.3.4, so it doesn't appear only to be a case of
	# Software Update not updating header files.
	#
	# (You can work around this by installing the 0.8 header
	# files.)
	#
	AC_CACHE_CHECK([whether pcap_findalldevs is present and usable],
	  [ac_cv_func_pcap_findalldevs],
	  [
	    AC_LINK_IFELSE(
	      [
		AC_LANG_SOURCE(
		  [[
		    #include <pcap.h>
		    main()
		    {
		      pcap_if_t *devpointer;
		      char errbuf[1];

		      pcap_findalldevs(&devpointer, errbuf);
		    }
		  ]])
	      ],
	      [
		ac_cv_func_pcap_findalldevs=yes
	      ],
	      [
		ac_cv_func_pcap_findalldevs=no
	      ])
	  ])
	#
	# Don't check for other new routines that showed up after
	# "pcap_findalldevs()" if we don't have a usable
	# "pcap_findalldevs()", so we don't end up using them if the
	# "pcap.h" is crufty and old and doesn't declare them.
	#
	if test $ac_cv_func_pcap_findalldevs = "yes" ; then
	  AC_DEFINE(HAVE_PCAP_FINDALLDEVS, 1,
	   [Define to 1 if you have the `pcap_findalldevs' function and a pcap.h that declares pcap_if_t.])
	  AC_CHECK_FUNCS(pcap_datalink_val_to_name pcap_datalink_name_to_val)
	  AC_CHECK_FUNCS(pcap_datalink_val_to_description)
	  AC_CHECK_FUNCS(pcap_list_datalinks pcap_set_datalink pcap_lib_version)
	  AC_CHECK_FUNCS(pcap_get_selectable_fd pcap_free_datalinks)
	  AC_CHECK_FUNC(pcap_create,
	  [
	    AC_DEFINE(HAVE_PCAP_CREATE, 1,
	     [Define to 1 if you have the `pcap_create' function.])
	    AC_DEFINE(CAN_SET_CAPTURE_BUFFER_SIZE, 1,
	     [Define to 1 if the capture buffer size can be set.])
	  ])
	  AC_CHECK_FUNCS(bpf_image pcap_set_tstamp_precision)
	fi

	AC_WIRESHARK_POP_FLAGS
	LIBS="$ac_save_LIBS"
])

AC_DEFUN([AC_WIRESHARK_PCAP_REMOTE_CHECK],
[
    ac_save_LIBS="$LIBS"
    LIBS="$PCAP_LIBS $LIBS"
    AC_DEFINE(HAVE_REMOTE, 1, [Define to 1 to enable remote
              capturing feature in WinPcap library])
    AC_CHECK_FUNCS(pcap_open)
    if test $ac_cv_func_pcap_open = "yes" ; then
        AC_DEFINE(HAVE_PCAP_REMOTE, 1,
            [Define to 1 if you have WinPcap remote capturing support and prefer to use these new API features.])
    fi
    AC_CHECK_FUNCS(pcap_setsampling)
    LIBS="$ac_save_LIBS"
])

#
# AC_WIRESHARK_ZLIB_CHECK
#
AC_DEFUN([AC_WIRESHARK_ZLIB_CHECK],
[
	AC_WIRESHARK_PUSH_FLAGS

	if test "x$zlib_dir" != "x"
	then
	  #
	  # The user specified a directory in which zlib resides,
	  # so add the "include" subdirectory of that directory to
	  # the include file search path and the "lib" subdirectory
	  # of that directory to the library search path.
	  #
	  # XXX - if there's also a zlib in a directory that's
	  # already in CPPFLAGS or LDFLAGS, this won't make us find
	  # the version in the specified directory, as the compiler
	  # and/or linker will search that other directory before it
	  # searches the specified directory.
	  #
	  CPPFLAGS="$CPPFLAGS -I$zlib_dir/include"
	  AC_WIRESHARK_ADD_DASH_L(LDFLAGS, $zlib_dir/lib)
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
		# We link with zlib to support uncompression of
		# gzipped network traffic, e.g. in an HTTP request
		# or response body.
		#
		if test "x$zlib_dir" != "x"
		then
		  WS_CPPFLAGS="$WS_CPPFLAGS -I$zlib_dir/include"
		  AC_WIRESHARK_ADD_DASH_L(WS_LDFLAGS, $zlib_dir/lib)
		fi
		LIBS="-lz $LIBS"
		AC_DEFINE(HAVE_ZLIB, 1, [Define to use zlib library])
		#
		# Check for "inflatePrime()" in zlib, which we need
		# in order to read compressed capture files.
		#
		AC_CHECK_FUNCS(inflatePrime)

		if test "x$ac_cv_func_inflatePrime" = "xyes" ; then
			#
			# Now check for "inflatePrime()" in zlib when
			# linking with the linker flags for GTK+
			# applications; people often grab XFree86 source
			# and build and install it on their systems,
			# and they appear sometimes to misconfigure
			# XFree86 so that, even on systems with zlib,
			# it assumes there is no zlib, so the XFree86
			# build process builds and installs its
			# own zlib in the X11 library directory.
			#
			# The zlib in at least some versions of XFree86
			# is an older version that may lack "inflatePrime()",
			# and that's the zlib with which Wireshark gets
			# linked, so the build of Wireshark fails.
			#
			AC_MSG_CHECKING([for inflatePrime missing when linking with X11])
			AC_TRY_LINK_FUNC(inflatePrime, AC_MSG_RESULT(no),
			  [
			    AC_MSG_RESULT(yes)
			    AC_MSG_ERROR(old zlib found when linking with X11 - get rid of old zlib.)
			  ])
		fi
	fi

	AC_WIRESHARK_POP_FLAGS
])

#
# AC_WIRESHARK_LIBLUA_CHECK
#
# Sets $have_lua to yes or no.
# If it's yes, it also sets $LUA_CFLAGS and $LUA_LIBS.
AC_DEFUN([AC_WIRESHARK_LIBLUA_CHECK],[

	AC_WIRESHARK_PUSH_FLAGS

	if test "x$want_lua_dir" = "x"
	then
		# The user didn't tell us where to find Lua.  Let's go look for it.

		# First, try the standard (pkg-config) way.
		# Unfortunately Lua's pkg-config file isn't standardly named.
		# Some distributions allow installation of multiple versions of
		# Lua at the same time.  On such systems each version has its
		# own package name.
		#
		# We use a for loop instead of giving all the package names to
		# PKG_CHECK_MODULES because doing the latter doesn't appear to
		# work reliably (some package names are not searched for).
		for pkg in "lua < 5.3" lua5.2 lua-5.2 lua52 lua5.1 lua-5.1 lua51 lua5.0 lua-5.0 lua50
		do
			AC_MSG_CHECKING(if you have $pkg)
			PKG_CHECK_EXISTS($pkg,
			[
			 AC_MSG_RESULT(yes)
			 have_lua=yes
			],
			[
			 AC_MSG_RESULT(no)
			])

			if test "x$have_lua" = "xyes"
			then
				PKG_WIRESHARK_CHECK_SYSTEM_MODULES(LUA, $pkg)
				CPPFLAGS="$LUA_CFLAGS $CPPFLAGS"
				AC_CHECK_HEADERS(lua.h lualib.h lauxlib.h)
				break
			fi
		done
	fi

	if test "x$have_lua" != "xyes"
	then
		# We don't have pkg-config or the user specified the path to
		# Lua (in $want_lua_dir).
		# Let's look for the header file.

		AC_MSG_CHECKING(for the location of lua.h)
		if test "x$want_lua_dir" = "x"
		then
			# The user didn't tell us where to look so we'll look in some
			# standard locations.
			want_lua_dir="/usr/local /usr $prefix"
		fi
		for dir in $want_lua_dir
		do
			if test -r "$dir/include/lua.h"
			then
				header_dir="$dir/include"
				lua_dir=$dir
				break
			fi

			for ver in 5.2 52 5.1 51 5.0 50
			do
				if test -r "$dir/include/lua$ver/lua.h"
				then
					header_dir="$dir/include/lua$ver"
					lua_dir=$dir
					break
				fi
			done
		done

		if test "x$header_dir" = "x"
		then
			have_lua=no
			AC_MSG_RESULT(not found)
		else
			AC_MSG_RESULT($header_dir)

			AC_MSG_CHECKING(the Lua version)
			lua_ver=`$AWK AS_ESCAPE('/LUA_VERSION_NUM/ { print $NF; }' $header_dir/lua.h | sed 's/0/./')`

			if test "x$lua_ver" = "x5.3"
			then
				# Wireshark doesn't compile with Lua 5.3 today
				AC_MSG_RESULT($lua_ver - disabling Lua support)
				have_lua=no
			else
				AC_MSG_RESULT($lua_ver)

				CPPFLAGS="$CPPFLAGS -I$header_dir"
				AC_CHECK_HEADERS(lua.h lualib.h lauxlib.h, ,
				[
					have_lua=no
				])
			fi

			if test "x$have_lua" = "x"
			then
				# Set LUA_CFLAGS
				LUA_CFLAGS="-I$header_dir"

				# We have the header files and they work.  Now let's check if we
				# have the library and it works.
				#
				# XXX - if there's also a liblua in a directory that's
				# already in CPPFLAGS or LDFLAGS, this won't make us find
				# the version in the specified directory, as the compiler
				# and/or linker will search that other directory before it
				# searches the specified directory.
				#
				# XXX - lib64?
				LDFLAGS="-L$lua_dir/lib $LDFLAGS"
				AC_SEARCH_LIBS(luaL_openlibs, [lua-${lua_ver} lua${lua_ver} lua],
				[
					LUA_LIBS="-L$lua_dir/lib $ac_cv_search_luaL_openlibs -lm"
					have_lua=yes
				],[
					have_lua=no
				], -lm)
			fi
		fi
	fi

	AC_WIRESHARK_POP_FLAGS
])

#
# AC_WIRESHARK_LIBPORTAUDIO_CHECK
#
AC_DEFUN([AC_WIRESHARK_LIBPORTAUDIO_CHECK],[

	AC_WIRESHARK_PUSH_FLAGS
	wireshark_save_LIBS="$LIBS"

	if test "x$portaudio_dir" != "x"
	then
		#
		# The user specified a directory in which libportaudio
		# resides, so add the "include" subdirectory of that directory to
		# the include file search path and the "lib" subdirectory
		# of that directory to the library search path.
		#
		# XXX - if there's also a libportaudio in a directory that's
		# already in CPPFLAGS or LDFLAGS, this won't make us find
		# the version in the specified directory, as the compiler
		# and/or linker will search that other directory before it
		# searches the specified directory.
		#
		CPPFLAGS="$CPPFLAGS -I$portaudio_dir/include"
		LDFLAGS="$LDFLAGS -L$portaudio_dir/lib"
	fi
	LIBS="-lportaudio $LIBS"

	#
	# Make sure we have "portaudio.h".  If we don't, it means we probably
	# don't have libportaudio, so don't use it.
	#
	AC_CHECK_HEADERS(portaudio.h,,
	[
		if test "x$portaudio_dir" != "x"
		then
			#
			# The user used "--with-portaudio=" to specify a directory
			# containing libportaudio, but we didn't find the header file
			# there; that either means they didn't specify the
			# right directory or are confused about whether libportaudio
			# is, in fact, installed.  Report the error and give up.
			#
			AC_MSG_ERROR([libportaudio header not found in directory specified in --with-portaudio])
		else
			if test "x$want_portaudio" = "xyes"
			then
				#
				# The user tried to force us to use the library, but we
				# couldn't find the header file; report an error.
				#
				AC_MSG_ERROR(Header file portaudio.h not found.)
			else
				#
				# We couldn't find the header file; don't use the
				# library, as it's probably not present.
				#
				want_portaudio=no
			fi
		fi
	])

	#
	# Check whether we have the right version of portaudio
	#
	if test "x$want_portaudio" != "xno"
	then
		AC_CHECK_TYPE(PortAudioStream,
		AC_DEFINE(PORTAUDIO_API_1, 1, [Define if we are using version of of the Portaudio library API]),
		,
		[#include <portaudio.h>])
	fi

	if test "x$want_portaudio" != "xno"
	then
		#
		# Well, we at least have the portaudio header file.
		#
		# let's check if the libs are there
		#
		PORTAUDIO_LIBS=""
		PORTAUDIO_INCLUDES=""

		AC_CHECK_LIB(portaudio, Pa_Initialize,
		[
			if test "x$portaudio_dir" != "x"
			then
				#
				# Put the "-I" and "-L" flags for portaudio
				# into PORTAUDIO_INCLUDES and PORTAUDIO_LIBS,
				# respectively.
				#
				PORTAUDIO_LIBS="-L$portaudio_dir/lib -lportaudio"
				PORTAUDIO_INCLUDES="-I$portaudio_dir/include"
			else
				PORTAUDIO_LIBS="-lportaudio"
			fi
			AC_DEFINE(HAVE_LIBPORTAUDIO, 1, [Define to use libportaudio library])
			want_portaudio=yes
		],[
			# User requested --with-portaudio but it isn't available
			if test "x$want_portaudio" = "xyes"
			then
				AC_MSG_ERROR(Linking with libportaudio failed.)
			fi
			want_portaudio=no
		])
		AC_SUBST(PORTAUDIO_LIBS)
		AC_SUBST(PORTAUDIO_INCLUDES)

	fi

	LIBS="$wireshark_save_LIBS"
	AC_WIRESHARK_POP_FLAGS
])


#
# AC_WIRESHARK_C_ARES_CHECK
#
AC_DEFUN([AC_WIRESHARK_C_ARES_CHECK],
[
	want_c_ares=defaultyes

	if test "x$want_c_ares" = "xdefaultyes"; then
		want_c_ares=yes
	fi

	if test "x$want_c_ares" = "xyes"; then
		AC_CHECK_LIB(cares, ares_init,
		  [
		    C_ARES_LIBS=-lcares
		    AC_DEFINE(HAVE_C_ARES, 1, [Define to use c-ares library])
		    have_good_c_ares=yes
		  ])
	else
		AC_MSG_RESULT(not required)
	fi
])


#
# AC_WIRESHARK_LIBCAP_CHECK
#
AC_DEFUN([AC_WIRESHARK_LIBCAP_CHECK],
[
	want_libcap=defaultyes

	if test "x$want_libcap" = "xdefaultyes"; then
		want_libcap=yes
	fi

	if test "x$want_libcap" = "xyes"; then
		AC_CHECK_LIB(cap, cap_set_flag,
		  [
		    LIBCAP_LIBS=-lcap
		    AC_DEFINE(HAVE_LIBCAP, 1, [Define to use the libcap library])
		    have_good_libcap=yes
		  ],,
		)
	else
		AC_MSG_RESULT(not required)
	fi
])


#
# AC_WIRESHARK_KRB5_CHECK
#
AC_DEFUN([AC_WIRESHARK_KRB5_CHECK],
[
	AC_WIRESHARK_PUSH_FLAGS
	wireshark_save_LIBS="$LIBS"

	if test "x$krb5_dir" != "x"
	then
	  #
	  # The user specified a directory in which kerberos resides,
	  # so add the "include" subdirectory of that directory to
	  # the include file search path and the "lib" subdirectory
	  # of that directory to the library search path.
	  #
	  # XXX - if there's also a kerberos in a directory that's
	  # already in CPPFLAGS or LDFLAGS, this won't make us find
	  # the version in the specified directory, as the compiler
	  # and/or linker will search that other directory before it
	  # searches the specified directory.
	  #
	  KRB5_CFLAGS="-I$krb5_dir/include"
	  ac_heimdal_version=`grep heimdal $krb5_dir/include/krb5.h | head -n 1 | sed 's/^.*heimdal.*$/HEIMDAL/'`
	  # MIT Kerberos moved krb5.h to krb5/krb5.h starting with release 1.5
	  ac_mit_version_olddir=`grep 'Massachusetts' $krb5_dir/include/krb5.h | head -n 1 | sed 's/^.*Massachusetts.*$/MIT/'`
	  ac_mit_version_newdir=`grep 'Massachusetts' $krb5_dir/include/krb5/krb5.h | head -n 1 | sed 's/^.*Massachusetts.*$/MIT/'`
	  ac_krb5_version="$ac_heimdal_version$ac_mit_version_olddir$ac_mit_version_newdir"
	  if test "x$ac_krb5_version" = "xHEIMDAL"
	  then
	      KRB5_LIBS="-L$krb5_dir/lib -lkrb5 -lasn1 $SSL_LIBS -lroken -lcrypt"
	  else
	      KRB5_LIBS="-L$krb5_dir/lib -lkrb5 -lk5crypto -lcom_err"
	  fi
	  if test "x$ac_krb5_version" = "xMIT"
	  then
	    AC_DEFINE(HAVE_MIT_KERBEROS, 1, [Define to use MIT kerberos])
	  fi
	else
	  AC_PATH_TOOL(KRB5_CONFIG, krb5-config)
	  if test -x "$KRB5_CONFIG"
	  then
	    KRB5_CFLAGS=`"$KRB5_CONFIG" --cflags`
	    KRB5_LIBS=`"$KRB5_CONFIG" --libs`
	    #
	    # If -lcrypto is in KRB5_FLAGS, we require it to build
	    # with Heimdal/MIT.  We don't want to built with it by
	    # default, due to annoying license incompatibilities
	    # between the OpenSSL license and the GPL, so:
	    #
	    #	if SSL_LIBS is set to a non-empty string, we
	    #	remove -lcrypto from KRB5_LIBS and replace
	    #	it with SSL_LIBS;
	    #
	    #	if SSL_LIBS is not set to a non-empty string
	    #	we fail with an appropriate error message.
	    #
	    case "$KRB5_LIBS" in
	    *-lcrypto*)
		if test ! -z "$SSL_LIBS"
		then
		    KRB5_LIBS=`echo $KRB5_LIBS | sed 's/-lcrypto//'`
		    KRB5_LIBS="$KRB5_LIBS $SSL_LIBS"
		else
		    AC_MSG_ERROR([Kerberos library requires -lcrypto, so you must specify --with-ssl])
		fi
		;;
	    esac
	    ac_krb5_version=`"$KRB5_CONFIG" --version | head -n 1 | sed -e 's/^.*heimdal.*$/HEIMDAL/' -e 's/^Kerberos .*$/MIT/' -e 's/^Solaris Kerberos .*$/MIT/'`
 	  fi
	fi

	CPPFLAGS="$CPPFLAGS $KRB5_CFLAGS"

	#
	# Make sure we have "krb5.h".  If we don't, it means we probably
	# don't have kerberos, so don't use it.
	#
	AC_CHECK_HEADER(krb5.h,,
	  [
	    if test "x$krb5_dir" != "x"
	    then
	      #
	      # The user used "--with-krb5=" to specify a directory
	      # containing kerberos, but we didn't find the header file
	      # there; that either means they didn't specify the
	      # right directory or are confused about whether kerberos
	      # is, in fact, installed.  Report the error and give up.
	      #
	      AC_MSG_ERROR([kerberos header not found in directory specified in --with-krb5])
	    else
	      if test "x$want_krb5" = "xyes"
	      then
		#
		# The user tried to force us to use the library, but we
		# couldn't find the header file; report an error.
		#
		AC_MSG_ERROR(Header file krb5.h not found.)
	      else
		#
		# We couldn't find the header file; don't use the
		# library, as it's probably not present.
		#
		KRB5_CFLAGS=""
		KRB5_LIBS=""
		want_krb5=no
		AC_MSG_RESULT(No Heimdal or MIT header found - disabling dissection for some kerberos data in packet decoding)
	      fi
	    fi
	  ])

	if test "x$want_krb5" != "xno"
	then
	    #
	    # Well, we at least have the krb5 header file.
	    # Check whether this is Heimdal or MIT.
	    #
	    AC_MSG_CHECKING(whether the Kerberos library is Heimdal or MIT)
	    if test "x$ac_krb5_version" = "xHEIMDAL" -o "x$ac_krb5_version" = "xMIT"
	    then
		#
		# Yes.
		# Check whether we have krb5_kt_resolve - and whether
		# we need to link with -lresolv when linking with
		# the Kerberos library.
		#
		AC_MSG_RESULT($ac_krb5_version)
		found_krb5_kt_resolve=no
		for extras in "" "-lresolv"
		do
		    LIBS="$KRB5_LIBS $extras $wireshark_save_LIBS"
		    if test -z "$extras"
		    then
			AC_MSG_CHECKING([whether $ac_krb5_version includes krb5_kt_resolve])
		    else
			AC_MSG_CHECKING([whether $ac_krb5_version includes krb5_kt_resolve (linking with $extras)])
		    fi
		    AC_TRY_LINK(
			[
			],
			[
			    krb5_kt_resolve();
			],
			[
			    #
			    # We found "krb5_kt_resolve()".
			    #
			    AC_MSG_RESULT(yes)
			    if test -n "$extras"; then
			      KRB5_LIBS="$KRB5_LIBS $extras"
			    fi
			    AC_DEFINE(HAVE_KERBEROS, 1, [Define to use kerberos])
	    		    if test "x$ac_krb5_version" = "xHEIMDAL"
			    then
				AC_DEFINE(HAVE_HEIMDAL_KERBEROS, 1, [Define to use heimdal kerberos])
			    elif test "x$ac_krb5_version" = "xMIT"
			    then
				AC_DEFINE(HAVE_MIT_KERBEROS, 1, [Define to use MIT kerberos])
			    fi
			    found_krb5_kt_resolve=yes
			    break
			],
			[
			    AC_MSG_RESULT(no)
			])
		done
		if test "$found_krb5_kt_resolve" = no
		then
		    #
		    # We didn't find "krb5_kt_resolve()" in the
		    # Kerberos library, even when we tried linking
		    # with -lresolv; we can't link with kerberos.
		    #
		    if test "x$want_krb5" = "xyes"
		    then
			#
			# The user tried to force us to use the library,
			# but we can't do so; report an error.
			#
			AC_MSG_ERROR(Usable $ac_krb5_version not found)
		    else
			#
			# Don't use
			#
			AC_MSG_RESULT(Usable $ac_krb5_version not found - disabling dissection for some kerberos data in packet decoding)
			KRB5_CFLAGS=""
			KRB5_LIBS=""
			want_krb5=no
		    fi
		else
		    #
		    # We can link with Kerberos; see whether krb5.h
		    # defines KEYTYPE_ARCFOUR_56 (where "defines" means
		    # "as a #define or as an enum member).
		    #
		    AC_MSG_CHECKING([whether krb5.h defines KEYTYPE_ARCFOUR_56])
		    AC_COMPILE_IFELSE(
		      [
			AC_LANG_SOURCE(
			  [[
			    #include <krb5.h>
			    #include <stdio.h>

			    main()
			    {
			      printf("%u\n", KEYTYPE_ARCFOUR_56);
			    }
			  ]])
		      ],
		      [
			AC_MSG_RESULT(yes)
			AC_DEFINE(HAVE_KEYTYPE_ARCFOUR_56, 1, [Define if krb5.h defines KEYTYPE_ARCFOUR_56])
		      ],
		      [
			AC_MSG_RESULT(no)
		      ])
		fi
	    else
		#
		# It's not Heimdal or MIT.
		#
		AC_MSG_RESULT(no)
		if test "x$want_krb5" = "xyes"
		then
		    #
		    # The user tried to force us to use the library,
		    # but we can't do so; report an error.
		    #
		    AC_MSG_ERROR(Kerberos not found)
		else
		    #
		    # Don't use.
		    #
		    AC_MSG_RESULT(Kerberos not found - disabling dissection for some kerberos data in packet decoding)
		    KRB5_CFLAGS=""
		    KRB5_LIBS=""
		    want_krb5=no
		fi
	    fi
	else
	    #
	    # The user asked us not to use Kerberos, or they didn't
	    # say whether they wanted us to use it but we found
	    # that we couldn't.
	    #
	    KRB5_CFLAGS=""
	    KRB5_LIBS=""
	    want_krb5=no
	fi
	AC_SUBST(KRB5_CFLAGS)
	AC_SUBST(KRB5_LIBS)

	LIBS="$wireshark_save_LIBS"
	AC_WIRESHARK_POP_FLAGS
])

#
# AC_WIRESHARK_GEOIP_CHECK
#
AC_DEFUN([AC_WIRESHARK_GEOIP_CHECK],
[
	want_geoip=defaultyes

	if test "x$want_geoip" = "xdefaultyes"; then
		want_geoip=yes
	fi

	if test "x$want_geoip" = "xyes"; then
		AC_CHECK_LIB(GeoIP, GeoIP_new,
		  [
		    GEOIP_LIBS=-lGeoIP
	    	AC_DEFINE(HAVE_GEOIP, 1, [Define to use GeoIP library])
		have_good_geoip=yes
		  ],,
		)
		if test "x$have_good_geoip" = "xyes"; then
			AC_CHECK_LIB(GeoIP, GeoIP_country_name_by_ipnum_v6,
			  [
				AC_DEFINE(HAVE_GEOIP_V6, 1, [Define if GeoIP supports IPv6 (GeoIP 1.4.5 and later)])
			  ],,
			)
		fi
	else
		AC_MSG_RESULT(not required)
	fi
])

#
# AC_WIRESHARK_LIBSSH_CHECK
#
AC_DEFUN([AC_WIRESHARK_LIBSSH_CHECK],
[
	want_libssh=defaultyes

	if test "x$want_libssh" = "xdefaultyes"; then
		want_libssh=yes
	fi

	if test "x$want_libssh" = "xyes"; then
		AC_CHECK_LIB(ssh, ssh_new,
		  [
		    LIBSSH_LIBS=-lssh
			AC_DEFINE(HAVE_LIBSSH, 1, [Define to use libssh library])
			have_good_libssh=yes
		  ],,
		)
		AC_MSG_CHECKING([whether libssh >= 0.6.0 for sshdump, ciscodump])
		PKG_CHECK_EXISTS([libssh >= 0.6.0],
		  [
		   AC_MSG_RESULT(yes)
		   AC_DEFINE(HAVE_LIBSSH_POINTSIX, 1, [Defined if libssh >= 0.6.0])
		   have_libssh_pointsix=yes
		  ],
		  [AC_MSG_RESULT(no)]
		)
		if test "x$have_libssh_pointsix" = "xyes"; then
			# ssh_userauth_agent exists only >= 0.6.0, but not on Windows
			# so check explicitly
			AC_CHECK_LIB(ssh, ssh_userauth_agent,
			  [
			    AC_DEFINE(HAVE_SSH_USERAUTH_AGENT, 1, [Libssh library has ssh_userauth_agent])
			    have_ssh_userauth_agent=yes
			  ],,
			)
		fi
	else
		AC_MSG_RESULT(not required)
	fi
])

#AC_WIRESHARK_LDFLAGS_CHECK
#
# $1 : ldflag(s) to test
#
# We attempt to compile and link a test program with the specified linker
# flag. The defined flag is added to LDFLAGS only if the link succeeds.
#
AC_DEFUN([AC_WIRESHARK_LDFLAGS_CHECK],
[LD_OPTION="$1"
AC_MSG_CHECKING(whether we can add $LD_OPTION to LDFLAGS)
AC_WIRESHARK_PUSH_FLAGS
LDFLAGS="$LDFLAGS $LD_OPTION"
can_add_to_ldflags=""
AC_LINK_IFELSE(
  [
    AC_LANG_SOURCE([[main() { return; }]])
  ],
  [
    AC_MSG_RESULT(yes)
    AX_APPEND_FLAG([$LD_OPTION], [WS_LDFLAGS])
    can_add_to_ldflags=yes
  ],
  [
    AC_MSG_RESULT(no)
    can_add_to_ldflags=no
  ])
  AC_WIRESHARK_POP_FLAGS
])

dnl
dnl Check whether, if you pass an unknown warning option to the
dnl compiler, it fails or just prints a warning message and succeeds.
dnl Set ac_wireshark_unknown_warning_option_error to the appropriate flag
dnl to force an error if it would otherwise just print a warning message
dnl and succeed.
dnl
AC_DEFUN([AC_WIRESHARK_CHECK_UNKNOWN_WARNING_OPTION_ERROR],
    [
	AC_MSG_CHECKING([whether the compiler fails when given an unknown warning option])
	AC_WIRESHARK_PUSH_FLAGS
	CFLAGS="$CFLAGS -Wxyzzy-this-will-never-succeed-xyzzy"
	AC_TRY_COMPILE(
	    [],
	    [return 0],
	    [
		AC_MSG_RESULT([no, adding -Werror=unknown-warning-option])
		#
		# We're assuming this is clang, where
		# -Werror=unknown-warning-option is the appropriate
		# option to force the compiler to fail.
		#
		ac_wireshark_unknown_warning_option_error="-Werror=unknown-warning-option"
	    ],
	    [
		AC_MSG_RESULT([yes])
	    ])
	AC_WIRESHARK_POP_FLAGS
    ])

dnl
dnl Check whether, if you pass a valid-for-C-but-not-C++ option to the
dnl compiler, it fails or just prints a warning message and succeeds.
dnl Set ac_wireshark_non_cxx_warning_option_error to the appropriate flag
dnl to force an error if it would otherwise just print a warning message
dnl and succeed.
dnl
AC_DEFUN([AC_WIRESHARK_CHECK_NON_CXX_WARNING_OPTION_ERROR],
    [
	AC_MSG_CHECKING([whether the compiler fails when given an warning option not supported for C++])
	#
	# Some C+ compilers warn about -Wmissing-prototypes, and some warn
	# about -Wmissing-declarations.  Check both.
	#
	AC_LANG_PUSH(C++)
	AC_WIRESHARK_PUSH_FLAGS
	save_CXXFLAGS="$CXXFLAGS"
	for flag in -Wmissing-prototypes -Wmissing-declarations; do
	    CXXFLAGS="$save_CXXFLAGS $flag"
	    AC_TRY_COMPILE(
		[],
		[return 0],
		[
		    #
		    # We're assuming this is g++, where -Werror is the
		    # appropriate option to force the compiler to fail.
		    # Check whether it fails with -Werror.
		    #
		    # NOTE: it's important to put -Werror *before*
		    # the flag, otherwise, when it sees the flag,
		    # it doesn't yet know that warnings should be
		    # treated as errors, and doesn't treat the
		    # "that's C-only" warning as an error.
		    #
		    CXXFLAGS="$save_CXXFLAGS -Werror $flag"
		    AC_TRY_COMPILE(
			[],
			[return 0],
			[
			    #
			    # No, so this option is actually OK
			    # with our C++ compiler.
			    #
			    # (We need an empty command here to
			    # prevent some versions of autoconf
			    # from generating a script with an
			    # empty "then" clause for an if statement.)
			    #
			    :
			],
			[
			    #
			    # Yes, so we need -Werror for the tests.
			    #
			    ac_wireshark_non_cxx_warning_option_error="-Werror"
			    break
			])
		])
	done
	AC_WIRESHARK_POP_FLAGS
	AC_LANG_POP
	if test x$ac_wireshark_non_cxx_warning_option_error = x; then
	    AC_MSG_RESULT([yes])
	else
	    AC_MSG_RESULT([no, adding -Werror])
	fi
    ])

#
# AC_WIRESHARK_COMPILER_FLAGS_CHECK
#
# $1 : flags to test
# $2 : if supplied, C for C-only flags, CXX for C++-only flags
# $3 : if supplied, a program to try to compile with the flag
#      and, if the compile fails when -Werror is turned on,
#      we don't add the flag - used for warning flags that
#      issue incorrect or non-useful warnings with some
#      compiler versions
# $4 : must be supplied if $3 is supplied - a message describing
#      for what the test program is testing
#
# The macro first determines if the compiler supports GCC-style flags.
# Then it attempts to compile with the defined cflags.  The defined
# flags are added to WS_CHECKED_CFLAGS only if the compilation succeeds.
# CFLAGS remains unchanged. can_add_to_cflags is set to "no" when the
# flag is checked but unavailable. (Like-wise for CXXFLAGS.)
#
# We do this because not all such options are necessarily supported by
# the version of the particular compiler we're using.
#
AC_DEFUN([AC_WIRESHARK_COMPILER_FLAGS_CHECK],
[GCC_OPTION="$1"
can_add_to_cflags=""
can_add_to_cxxflags=""
if test "x$ac_supports_gcc_flags" = "xyes" ; then
  if test "$2" != CXX ; then
    #
    # Not C++-only; if this can be added to the C compiler flags, add them.
    #
    # If the option begins with "-W", add
    # $ac_wireshark_unknown_warning_option_error to make sure that
    # we'll get an error if it's an unknown warning option; not all
    # compilers treat unknown warning options as errors (I'm looking at
    # you, clang).
    #
    # If the option begins with "-f" or "-m", add -Werror to make sure
    # that we'll get an error if we get "argument unused during compilation"
    # warnings, as those will either cause a failure for files compiled
    # with -Werror or annoying noise for files compiled without it.
    # (Yeah, you, clang.)
    #
    AC_MSG_CHECKING(whether we can add $GCC_OPTION to CFLAGS)
    AC_WIRESHARK_PUSH_FLAGS
    if expr "x$GCC_OPTION" : "x-W.*" >/dev/null
    then
      CFLAGS="$CFLAGS $ac_wireshark_unknown_warning_option_error $GCC_OPTION"
    elif expr "x$GCC_OPTION" : "x-f.*" >/dev/null
    then
      CFLAGS="$CFLAGS -Werror $GCC_OPTION"
    elif expr "x$GCC_OPTION" : "x-m.*" >/dev/null
    then
      CFLAGS="$CFLAGS -Werror $GCC_OPTION"
    else
      CFLAGS="$CFLAGS $GCC_OPTION"
    fi
    AC_COMPILE_IFELSE(
      [
        AC_LANG_SOURCE([[int foo;]])
      ],
      [
        AC_MSG_RESULT(yes)
        can_add_to_cflags=yes
        #
        # OK, do we have a test program?  If so, check
        # whether it fails with this option and -Werror,
        # and, if so, don't include it.
        #
        # We test arg 4 here because arg 3 is a program which
        # could contain quotes (breaking the comparison).
        #
        if test "x$4" != "x" ; then
          CFLAGS="$CFLAGS -Werror"
          AC_MSG_CHECKING(whether $GCC_OPTION $4)
          AC_COMPILE_IFELSE(
            [AC_LANG_SOURCE($3)],
            [
              AC_MSG_RESULT(no)
              #
              # Remove "force an error for a warning" options, if we
              # added them, by setting CFLAGS to the saved value plus
              # just the new option.
              #
              AX_APPEND_FLAG([$GCC_OPTION], [WS_CFLAGS])
              if test "$CC" = "$CC_FOR_BUILD"; then
                #
                # We're building the build tools with the same compiler
                # with which we're building Wireshark, so add the flags
                # to the flags for that compiler as well.
                #
                AX_APPEND_FLAG([$GCC_OPTION], [WS_CFLAGS_FOR_BUILD])
              fi
            ],
            [
              AC_MSG_RESULT(yes)
            ])
        else
          #
          # Remove "force an error for a warning" options, if we
          # added them, by setting CFLAGS to the saved value plus
          # just the new option.
          #
          AX_APPEND_FLAG([$GCC_OPTION], [WS_CFLAGS])
          if test "$CC" = "$CC_FOR_BUILD"; then
            #
            # We're building the build tools with the same compiler
            # with which we're building Wireshark, so add the flags
            # to the flags for that compiler as well.
            #
            AX_APPEND_FLAG([$GCC_OPTION], [WS_CFLAGS_FOR_BUILD])
          fi
        fi
      ],
      [
        AC_MSG_RESULT(no)
        can_add_to_cflags=no
      ])
      AC_WIRESHARK_POP_FLAGS
  fi
  #
  # Did we find a C++ compiler?
  #
  if test "x$CXX" != "x" ; then
    #
    # Yes.  Is this option only for the C compiler?
    #
    if test "$2" != C ; then
      #
      # Not C-only; if this option can be added to the C++ compiler
      # options, add it.
      #
      # If the option begins with "-W", add
      # $ac_wireshark_unknown_warning_option_error, as per the above, and
      # also add $ac_wireshark_non_cxx_warning_option_error, because at
      # lease some versions of g++ whine about -Wmissing-prototypes, the
      # fact that at least one of those versions refuses to warn about
      # function declarations without an earlier declaration nonwithstanding;
      # perhaps there's a reason not to warn about that with C++ even though
      # warning about it can be a Good Idea with C, but it's not obvious to
      # me).
      #
      # If the option begins with "-f" or "-m", add -Werror to make sure
      # that we'll get an error if we get "argument unused during compilation"
      # warnings, as those will either cause a failure for files compiled
      # with -Werror or annoying noise for files compiled without it.
      # (Yeah, you, clang++.)
      #
      AC_MSG_CHECKING(whether we can add $GCC_OPTION to CXXFLAGS)
      AC_WIRESHARK_PUSH_FLAGS
      if expr "x$GCC_OPTION" : "x-W.*" >/dev/null
      then
        CXXFLAGS="$CXXFLAGS $ac_wireshark_unknown_warning_option_error $ac_wireshark_non_cxx_warning_option_error $GCC_OPTION"
      elif expr "x$GCC_OPTION" : "x-f.*" >/dev/null
      then
        CXXFLAGS="$CXXFLAGS -Werror $GCC_OPTION"
      elif expr "x$GCC_OPTION" : "x-m.*" >/dev/null
      then
        CXXFLAGS="$CXXFLAGS -Werror $GCC_OPTION"
      else
        CXXFLAGS="$CXXFLAGS $GCC_OPTION"
      fi
      AC_LANG_PUSH([C++])
      AC_COMPILE_IFELSE(
        [
          AC_LANG_SOURCE([[int foo;]])
        ],
        [
          AC_MSG_RESULT(yes)
          can_add_to_cxxflags=yes
          #
          # OK, do we have a test program?  If so, check
          # whether it fails with this option and -Werror,
          # and, if so, don't include it.
          #
          # We test arg 4 here because arg 3 is a program which
          # could contain quotes (breaking the comparison).
          #
          if test "x$4" != "x" ; then
            CXXFLAGS="$CXXFLAGS -Werror"
            AC_MSG_CHECKING(whether $GCC_OPTION $4)
            AC_COMPILE_IFELSE(
              [AC_LANG_SOURCE($3)],
              [
                AC_MSG_RESULT(no)
                #
                # Remove "force an error for a warning" options, if we
                # added them, by setting CXXFLAGS to the saved value plus
                # just the new option.
                #
                AX_APPEND_FLAG([$GCC_OPTION], [WS_CXXFLAGS])
              ],
              [
                AC_MSG_RESULT(yes)
              ])
          else
            #
            # Remove "force an error for a warning" options, if we
            # added them, by setting CXXFLAGS to the saved value plus
            # just the new option.
            #
            AX_APPEND_FLAG([$GCC_OPTION], [WS_CXXFLAGS])
          fi
        ],
        [
          AC_MSG_RESULT(no)
          can_add_to_cxxflags=no
        ])
      AC_WIRESHARK_POP_FLAGS
      AC_LANG_POP([C++])
    fi
    if test "(" "$can_add_to_cflags" = "yes" -a "$can_add_to_cxxflags" = "no" ")" \
         -o "(" "$can_add_to_cflags" = "no" -a "$can_add_to_cxxflags" = "yes" ")"
    then
      #
      # Confusingly, some C++ compilers like -Wmissing-prototypes but
      # don't like -Wmissing-declarations and others like
      # -Wmissing-declarations but don't like -Wmissing-prototypes,
      # the fact that the corresponding C compiler likes both.  Don't
      # warn about them.
      #
      if test "(" x$GCC_OPTION != x-Wmissing-prototypes ")" \
           -a "(" x$GCC_OPTION != x-Wmissing-declarations ")"
      then
         AC_MSG_WARN([$CC and $CXX appear to be a mismatched pair])
      fi
    fi
  fi
fi
])

# AC_WIRESHARK_GCC_FORTIFY_SOURCE_CHECK
#
# Checks if '-D_FORTIFY_SOURCE=...' is OK to use in CPPFLAGS.
#  Use '-D_FORTIFY_SOURCE=...' in CPPFLAGS only if the GCC 'optimization level' is > 0.
#  The use of '-D_FORTIFY_SOURCE=...' will cause a warning with at least some versions
#    of glibc if the  GCC "optimization level" is 0 (default or -O or -O0)
#    when using GCC to compile a source file which references the macro definition.
#
# See: http://gcc.gnu.org/ml/gcc-patches/2004-09/msg02055.html
# See: http://sourceware.org/bugzilla/show_bug.cgi?id=13979
#
#   We'll use '-D_FORTIFY_SOURCE=2' only if there's no warning; Among other things this means
#    that the  use of '-D_FORTIFY_SOURCE=2' with '-Werror' and '-O0' won't cause
#    the compiler to stop on error.
#   Assumption: CFLAGS already contains whatever optimization option including none) is
#    to be used.
#

AC_DEFUN([AC_WIRESHARK_GCC_FORTIFY_SOURCE_CHECK],
[
if test "x$GCC" = "xyes" -o "x$CC" = "xclang" ; then
  AC_MSG_CHECKING([whether -D_FORTIFY_SOURCE=2 can be used (without generating a warning)])
  AC_WIRESHARK_PUSH_FLAGS
  CFLAGS="$CFLAGS -Werror"
  CPPFLAGS="$CPPFLAGS -D_FORTIFY_SOURCE=2"
  AC_COMPILE_IFELSE([
    AC_LANG_SOURCE([[
                  #include <stdio.h>
                      int foo;
                  ]])],
                  [
                    AC_MSG_RESULT(yes)
                    AX_APPEND_FLAG([-D_FORTIFY_SOURCE=2], [WS_CPPFLAGS])
                  ],
                  [
                    AC_MSG_RESULT(no)
                  ])
  AC_WIRESHARK_POP_FLAGS
fi
])

#
# AC_WIRESHARK_GCC_SYSTEM_INCLUDE
#
# Replace -I include flag for -isystem in FLAGS argument
#
AC_DEFUN([AC_WIRESHARK_GCC_SYSTEM_INCLUDE],
[
	if test "x$GCC" = "xyes" -o "x$CC" = "xclang" ; then
		$1=`echo " $$1" \
			| sed -e 's/  *-I *\// -isystem\//g' -e 's/^ *//'`
	fi
])

#
# PKG_WIRESHARK_CHECK_SYSTEM_MODULES
#
AC_DEFUN([PKG_WIRESHARK_CHECK_SYSTEM_MODULES],
[
	PKG_CHECK_MODULES($@)
	AC_WIRESHARK_GCC_SYSTEM_INCLUDE($1_CFLAGS)
])

# Based on AM_PATH_GTK in gtk-2.0.m4.

dnl AC_WIRESHARK_QT_MODULE_CHECK_WITH_QT_VERSION([MODULE, MINIMUM-VERSION,
dnl     REQUESTED-MAJOR_VERSION, [ACTION-IF-FOUND, [ACTION-IF-NOT-FOUND]]])
dnl Test for a particular Qt module, for a particular Qt major version,
dnl and, if we find it add the flags and libraries for it to Qt_CFLAGS
dnl and Qt_LIBS.
dnl
AC_DEFUN([AC_WIRESHARK_QT_MODULE_CHECK_WITH_QT_VERSION],
[
	case "$3" in

	4)
		#
		# Check for Qt 4.
		#
		modprefix="Qt"
		#
		# Version of the module we're checking for.
		# Default to 4.0.0.
		#
		min_qt_version=ifelse([$2], ,4.0.0,$2)
		;;

	5)
		#
		# Check for Qt 5.
		#
		modprefix="Qt5"
		#
		# Version of the module we're checking for.
		# Default to 5.0.0.
		#
		min_qt_version=5.0.0
		;;

	*)
		AC_MSG_ERROR([Qt version $3 is not a known Qt version])
		;;
	esac

	pkg_config_module="${modprefix}$1"
	AC_MSG_CHECKING(for $pkg_config_module - version >= $min_qt_version)
	if $PKG_CONFIG --atleast-version $min_qt_version $pkg_config_module; then
		mod_version=`$PKG_CONFIG --modversion $pkg_config_module`
		AC_MSG_RESULT(yes (version $mod_version))
		mod_cflags=`$PKG_CONFIG --cflags $pkg_config_module`
		AC_WIRESHARK_GCC_SYSTEM_INCLUDE(mod_cflags)
		Qt_CFLAGS="$Qt_CFLAGS $mod_cflags"
		Qt_LIBS="$Qt_LIBS `$PKG_CONFIG --libs $pkg_config_module`"
		# Run Action-If-Found
		ifelse([$4], , :, [$4])
	else
		AC_MSG_RESULT(no)
		# Run Action-If-Not-Found
		ifelse([$5], , :, [$5])
	fi
])

dnl AC_WIRESHARK_QT_MODULE_CHECK([MODULE, MINIMUM-VERSION,
dnl     REQUESTED-MAJOR_VERSION, [ACTION-IF-FOUND, [ACTION-IF-NOT-FOUND]]])
dnl Test for a particular Qt module and add the flags and libraries
dnl for it to Qt_CFLAGS and Qt_LIBS.
dnl
AC_DEFUN([AC_WIRESHARK_QT_MODULE_CHECK],
[
	#
	# Prior to Qt 5, modules were named QtXXX.
	# In Qt 5, they're named Qt5XXX.
	# This will need to change to handle future major Qt releases.
	#
	case "$3" in

	yes|unspecified)
		#
		# Check for all versions of Qt we support.
		# Try the Qt 5 version first.
		#
		versions="5 4"
		;;

	4)
		#
		# Check for Qt 4.
		#
		versions="4"
		;;

	5)
		#
		# Check for Qt 5.
		#
		versions="5"
		;;

	*)
		AC_MSG_ERROR([Qt version $3 is not a known Qt version])
		;;
	esac

	for version in $versions
	do
		AC_WIRESHARK_QT_MODULE_CHECK_WITH_QT_VERSION($1, $2,
		    $version, [foundit=yes], [foundit=no])
		if test "x$foundit" = "xyes"; then
                        break
		fi
	done

	if test "x$foundit" = "xyes"; then
		# Remember which version of Qt we found
		qt_version=$version
		# Run Action-If-Found
		ifelse([$4], , :, [$4])
	else
		# Run Action-If-Not-Found
		ifelse([$5], , :, [$5])
	fi
])

AC_DEFUN([AC_WIRESHARK_QT_ADD_PIC_IF_NEEDED],
[
    AC_LANG_PUSH([C++])
	AC_WIRESHARK_PUSH_FLAGS
	CPPFLAGS="$CPPFLAGS $Qt_CFLAGS"
	AC_MSG_CHECKING([whether Qt works without -fPIC])
	AC_PREPROC_IFELSE(
		[AC_LANG_SOURCE([[#include <QtCore>]])],
		[AC_MSG_RESULT(yes)],
		[
			AC_MSG_RESULT(no)
			AC_MSG_CHECKING([whether Qt works with -fPIC])
			CPPFLAGS="$CPPFLAGS -fPIC"
			AC_PREPROC_IFELSE(
				[AC_LANG_SOURCE([[#include <QtCore>]])],
				[
					AC_MSG_RESULT(yes)
					Qt_CFLAGS="$Qt_CFLAGS -fPIC"
				],
				[
					AC_MSG_RESULT(no)
					AC_MSG_ERROR(Couldn't compile Qt without -fPIC nor with -fPIC)
				])
		])
	AC_WIRESHARK_POP_FLAGS
    AC_LANG_POP([C++])
])

dnl AC_WIRESHARK_QT_CHECK([MINIMUM-VERSION, REQUESTED-MAJOR_VERSION,
dnl     [ACTION-IF-FOUND, [ACTION-IF-NOT-FOUND]]])
dnl Test for Qt and define Qt_CFLAGS and Qt_LIBS.
dnl
AC_DEFUN([AC_WIRESHARK_QT_CHECK],
[
	qt_version_to_check="$2"

	#
	# Check for the Core module; if we don't have that,
	# we don't have Qt.  If we *do* have it, we know what
	# version it is, so only check for that version of
	# other modules.
	#
	AC_WIRESHARK_QT_MODULE_CHECK(Core, $1, $qt_version_to_check,
	    [
	      qt_version_to_check=$qt_version
	      QT_VERSION=$mod_version
	      QT_VERSION_MAJOR=`echo "$QT_VERSION" | cut -f1 -d.`
	      QT_VERSION_MINOR=`echo "$QT_VERSION" | cut -f2 -d.`
	      QT_VERSION_MICRO=`echo "$QT_VERSION" | cut -f3 -d.`

	      # Qt 5.7 and later requires C++11
	      AS_IF([test $QT_VERSION_MAJOR -eq 5 -a $QT_VERSION_MINOR -ge 7],
		[AS_IF([test "$HAVE_CXX11" -eq 0], [AC_MSG_ERROR([Qt 5.7 and later requires C++11])])])

	    ],
	    [no_qt=yes])

	if test x"$no_qt" = x ; then
		#
		# We need the Gui module as well.
		#
		AC_WIRESHARK_QT_MODULE_CHECK(Gui, $1, $qt_version_to_check, ,
		    [no_qt=yes])
	fi

	if test x"$no_qt" = x ; then
		#
		# Qt 5.0 appears to move the widgets out of Qt GUI
		# to Qt Widgets; look for the Widgets module, but
		# don't fail if we don't have it.
		#
		AC_WIRESHARK_QT_MODULE_CHECK(Widgets, $1, $qt_version_to_check)

		#
		# Qt 5.0 also appears to move the printing support into
		# the Qt PrintSupport module.
		#
		AC_WIRESHARK_QT_MODULE_CHECK(PrintSupport, $1, $qt_version_to_check)

		#
		# Qt 5.0 added multimedia in the Qt
		# Multimedia module.
		#
		have_qt_multimedia_lib=no
		AC_WIRESHARK_QT_MODULE_CHECK(Multimedia, $1, $qt_version_to_check,
			have_qt_multimedia_lib=yes
			AC_DEFINE(QT_MULTIMEDIA_LIB, 1, [Define if we have QtMultimedia]))

		#
		# While we're at it, look for QtMacExtras.  (Presumably
		# if we're not building for OS X, it won't be present.)
		#
		# XXX - is there anything in QtX11Extras or QtWinExtras
		# that we should be using?
		#
		AC_WIRESHARK_QT_MODULE_CHECK(MacExtras, $1, $qt_version_to_check,
			AC_DEFINE(QT_MACEXTRAS_LIB, 1, [Define if we have QtMacExtras]))

		AC_WIRESHARK_QT_ADD_PIC_IF_NEEDED

		# Run Action-If-Found
		ifelse([$3], , :, [$3])
	else
		# Run Action-If-Not-Found
		ifelse([$4], , :, [$4])
	fi

])

dnl AC_WIRESHARK_QT_TOOL_CHECK([TOOLPATHVAR, TOOL, REQUESTED-MAJOR_VERSION])
dnl Test for a particular Qt tool for some specific version of Qt
dnl
AC_DEFUN([AC_WIRESHARK_QT_TOOL_CHECK],
[
	#
	# At least in some versions of Debian/Ubuntu, and perhaps
	# other OSes, the Qt build tools are just links to a
	# program called "qtchooser", and even if you want to
	# build with Qt 5, running the tool might give you the
	# Qt 4 version of the tool unless you run the tool with
	# a -qt=5 argument.
	#
	# So we look for qtchooser and, if we find it, use the
	# -qt={version} argument, otherwise we look for particular
	# tool versions using tool name suffixes.
	#
	AC_PATH_PROG(QTCHOOSER, qtchooser)
	if test ! -z "$QTCHOOSER"; then
		#
		# We found qtchooser; we assume that means that
		# the tool is linked to qtchooser, so that we
		# can run it with the -qt={version} flag to get
		# the appropriate version of the tool.
		#
		AC_PATH_PROG($1, $2)
		if test "x$$1" = x; then
			#
			# We can't build Qt Wireshark without that
			# tool..
			#
			AC_MSG_ERROR(I couldn't find $2; make sure it's installed and in your path)
		fi

		#
		# Add the -qt={version} argument to it.
		#
		$1="$$1 -qt=$qt_version"
	else
		#
		# Annoyingly, on some Linux distros (e.g. Debian)
		# the Qt 5 tools have no suffix and the Qt 4 tools
		# have suffix -qt4. On other distros (e.g. openSUSE)
		# the Qt 5 tools have suffix -qt5 and the Qt 4 tools
		# have no suffix.
		#
		# So we check for the tool first with the -qtN suffix
		# and then with no suffix.
		#
		AC_PATH_PROGS($1, [$2-qt$qt_version $2])
		if test "x$$1" = x; then
			#
			# We can't build Qt Wireshark without that
			# tool..
			#
			AC_MSG_ERROR(I couldn't find $2-qt$qt_version or $2; make sure it's installed and in your path)
		fi
	fi
])

AC_DEFUN([AC_WIRESHARK_QT_TOOL_CHECK_LRELEASE],
[
  AC_WIRESHARK_QT_TOOL_CHECK(LRELEASE, lrelease, $2)
  AC_MSG_CHECKING(whether lrelease -version works)
  lrelease_version=`$LRELEASE -version 2>&AS_MESSAGE_LOG_FD`
  AS_IF([test $? -ne 0],
    [
      AC_MSG_RESULT(no)
      AC_MSG_ERROR([$LRELEASE -version returned non-zero exit status])
    ])
  AC_MSG_RESULT([ok, $lrelease_version])
])
