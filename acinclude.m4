dnl Macros that test for specific features.
dnl This file is part of Autoconf.
dnl Copyright (C) 1992, 1993, 1994, 1995, 1996 Free Software Foundation, Inc.
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
# AC_ETHEREAL_STRUCT_SA_LEN
#
dnl AC_STRUCT_ST_BLKSIZE extracted from the file in qustion,
dnl "acspecific.m4" in GNU Autoconf 2.12, and turned into
dnl AC_ETHEREAL_STRUCT_SA_LEN, which checks if "struct sockaddr"
dnl has the 4.4BSD "sa_len" member, and defines HAVE_SA_LEN; that's
dnl what's in this file.
dnl Done by Guy Harris <guy@netapp.com> on 1998-11-14. 

dnl ### Checks for structure members

AC_DEFUN(AC_ETHEREAL_STRUCT_SA_LEN,
[AC_CACHE_CHECK([for sa_len in struct sockaddr], ac_cv_ethereal_struct_sa_len,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/socket.h>], [struct sockaddr s; s.sa_len;],
ac_cv_ethereal_struct_sa_len=yes, ac_cv_ethereal_struct_sa_len=no)])
if test $ac_cv_ethereal_struct_sa_len = yes; then
  AC_DEFINE(HAVE_SA_LEN)
fi
])


#
# AC_ETHEREAL_IPV6_STACK
#
# By Jun-ichiro "itojun" Hagino, <itojun@iijlab.net>

AC_DEFUN(AC_ETHEREAL_IPV6_STACK,
[
	v6type=unknown
	v6lib=none

	AC_MSG_CHECKING([ipv6 stack type])
	for i in v6d toshiba kame inria zeta linux; do
		case $i in
		v6d)
			AC_EGREP_CPP(yes, [dnl
#include </usr/local/v6/include/sys/types.h>
#ifdef __V6D__
yes
#endif],
				[v6type=$i; v6lib=v6;
				v6libdir=/usr/local/v6/lib;
				CFLAGS="-I/usr/local/v6/include $CFLAGS"])
			;;
		toshiba)
			AC_EGREP_CPP(yes, [dnl
#include <sys/param.h>
#ifdef _TOSHIBA_INET6
yes
#endif],
				[v6type=$i; v6lib=inet6;
				v6libdir=/usr/local/v6/lib;
				CFLAGS="-DINET6 $CFLAGS"])
			;;
		kame)
			AC_EGREP_CPP(yes, [dnl
#include <netinet/in.h>
#ifdef __KAME__
yes
#endif],
				[v6type=$i; v6lib=inet6;
				v6libdir=/usr/local/v6/lib;
				CFLAGS="-DINET6 $CFLAGS"])
			;;
		inria)
			AC_EGREP_CPP(yes, [dnl
#include <netinet/in.h>
#ifdef IPV6_INRIA_VERSION
yes
#endif],
				[v6type=$i; CFLAGS="-DINET6 $CFLAGS"])
			;;
		zeta)
			AC_EGREP_CPP(yes, [dnl
#include <sys/param.h>
#ifdef _ZETA_MINAMI_INET6
yes
#endif],
				[v6type=$i; v6lib=inet6;
				v6libdir=/usr/local/v6/lib;
				CFLAGS="-DINET6 $CFLAGS"])
			;;
		linux)
			if test -d /usr/inet6; then
				v6type=$i
				v6lib=inet6
				v6libdir=/usr/inet6
				CFLAGS="-DINET6 $CFLAGS"
			fi
			;;
		esac
		if test "$v6type" != "unknown"; then
			break
		fi
	done

	if test "$v6lib" != "none"; then
		for dir in $v6libdir /usr/local/v6/lib /usr/local/lib; do
			if test -d $dir -a -f $dir/lib$v6lib.a; then
				LIBS="-L$dir $LIBS -l$v6lib"
				break
			fi
		done
		enable_ipv6="yes"
	else
		enable_ipv6="no"
	fi
	AC_MSG_RESULT(["$v6type, $v6lib"])
])

#
# AC_ETHEREAL_PCAP_CHECK
#
AC_DEFUN(AC_ETHEREAL_PCAP_CHECK,
[
	# Evidently, some systems have pcap.h, etc. in */include/pcap
	AC_MSG_CHECKING(for extraneous pcap header directories)
	found_pcap_dir=""
	for pcap_dir in /usr/include/pcap /usr/local/include/pcap $prefix/include
	do
	  if test -d $pcap_dir ; then
	    LIBS="$LIBS -L$pcap_dir"
	    CFLAGS="$CFLAGS -I$pcap_dir"
	    CPPFLAGS="$CPPFLAGS -I$pcap_dir"
	    found_pcap_dir=" $found_pcap_dir -L$pcap_dir"
	  fi
	done

	if test "$found_pcap_dir" != "" ; then
	  AC_MSG_RESULT(found --$found_pcap_dir added to LIBS and CFLAGS)
	else
	  AC_MSG_RESULT(not found)
	fi

	# Pcap checks
	AC_CHECK_HEADER(net/bpf.h,,
	    AC_MSG_ERROR([[Header file net/bpf.h not found; if you installed libpcap from source, did you also do \"make install-incl\"?]]))
	AC_CHECK_HEADER(pcap.h,, AC_MSG_ERROR(Header file pcap.h not found.))
	AC_CHECK_LIB(pcap, pcap_open_offline,, AC_MSG_ERROR(Library libpcap not found.))
])

#
# AC_ETHEREAL_ZLIB_CHECK
#
AC_DEFUN(AC_ETHEREAL_ZLIB_CHECK,
[
        AC_CHECK_HEADER(zlib.h,,enable_zlib=no)
        AC_CHECK_LIB(z, gzopen,,enable_zlib=no)
])

#
# AC_ETHEREAL_UCDSNMP_CHECK
#
AC_DEFUN(AC_ETHEREAL_UCDSNMP_CHECK,
[
	want_ucdsnmp=yes

	AC_ARG_WITH(ucdsnmp,
	[  --with-ucdsnmp=DIR      use UCD SNMP client library, located in directory DIR.], [
	if test $withval = no
	then
		want_ucdsnmp=no
	else
		want_ucdsnmp=yes
		ucdsnmp_user_dir=$withval
	fi
	])

	if test $want_ucdsnmp = yes
	then
		ucdsnmpdir=""

		for d in $ucdsnmp_user_dir $prefix
		do
			AC_MSG_CHECKING($d)

			if test x$d != x/usr/local && test -f $d/include/ucd-snmp/snmp.h
			then
				AC_MSG_RESULT(found ucd-snmp in $d)
				ucdsnmpdir=$d
				break
			fi
		done

		if test x$ucdsnmpdir != x
		then
			AC_MSG_RESULT(added $d to paths)
			CFLAGS="$CFLAGS -I${ucdsnmpdir}/include/ucdsnmp"
			LIBS="$LIBS -L${ucdsnmpdir}/lib"
		fi
	fi
])
