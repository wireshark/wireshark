# Based on gtk-2.0.m4.
# $Id$

dnl AM_PATH_QT([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]]])
dnl Test for Qt+
dnl Should also define QT_CFLAGS and QT_LIBS but not done yet...
dnl
AC_DEFUN([AM_PATH_QT],
[

  pkg_config_module=QtCore

  no_qt=""

  AC_PATH_PROG(PKG_CONFIG, pkg-config, no)

  if test x$PKG_CONFIG != xno ; then
    if pkg-config --atleast-pkgconfig-version 0.7 ; then
      :
    else
      echo *** pkg-config too old; version 0.7 or better required.
      no_qt=yes
      PKG_CONFIG=no
    fi
  else
    no_qt=yes
  fi

  min_qt_version=ifelse([$1], ,4.0.0,$1)
  AC_MSG_CHECKING(for Qt - version >= $min_qt_version)

  if test x"$no_qt" = x ; then
    QT_CFLAGS=`$PKG_CONFIG --cflags $pkg_config_module`
    QT_LIBS=`$PKG_CONFIG --libs $pkg_config_module`
    qt_config_major_version=`$PKG_CONFIG --modversion $pkg_config_module | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\1/'`
    qt_config_minor_version=`$PKG_CONFIG --modversion $pkg_config_module | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\2/'`
    qt_config_micro_version=`$PKG_CONFIG --modversion $pkg_config_module | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\3/'`

    if $PKG_CONFIG --atleast-version $min_qt_version $pkg_config_module; then
	  :
    else
	  no_qt=yes
    fi
  fi

  if test x"$no_qt" = x ; then
    AC_MSG_RESULT(yes (version $qt_config_major_version.$qt_config_minor_version.$qt_config_micro_version))
     ifelse([$2], , :, [$2])
  else
     ifelse([$3], , :, [$3])
  fi

])
