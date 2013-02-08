# Based on gtk-2.0.m4.
# $Id$

dnl AM_PATH_QT([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]]])
dnl Test for Qt+ and define Qt_CFLAGS and Qt_LIBS.
dnl
AC_DEFUN([AM_PATH_QT],
[

	pkg_config_module="QtCore QtGui"

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

	if test x"$no_qt" = x ; then
		min_qt_version=ifelse([$1], ,4.0.0,$1)
		AC_MSG_CHECKING(for Qt - version >= $min_qt_version)

		qt_config_major_version=`$PKG_CONFIG --modversion $pkg_config_module | \
			head -1 | sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\1/'`
		qt_config_minor_version=`$PKG_CONFIG --modversion $pkg_config_module | \
			head -1 | sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\2/'`
		qt_config_micro_version=`$PKG_CONFIG --modversion $pkg_config_module | \
			head -1 | sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\3/'`

		if $PKG_CONFIG --atleast-version $min_qt_version $pkg_config_module; then
			AC_MSG_RESULT(yes (version $qt_config_major_version.$qt_config_minor_version.$qt_config_micro_version))
		else
			no_qt=yes
			AC_MSG_RESULT(no)
		fi
	fi

	if test x"$no_qt" = x ; then
		Qt_CFLAGS=`$PKG_CONFIG --cflags $pkg_config_module`
		Qt_LIBS=`$PKG_CONFIG --libs $pkg_config_module`

		#
		# Qt 5.0 appears to move the widgets out of Qt GUI
		# to Qt Widgets; look for QtWidgets and, if we find
		# it, add its flags to CFLAGS and CXXFLAGS, so that
		# we find the include files for the widgets.  (If
		# we don't find it, we assume it's Qt 4.)
		#
		if QtWidgets_CFLAGS=`$PKG_CONFIG --cflags QtWidgets 2>/dev/null`; then
			Qt_CFLAGS="$Qt_CFLAGS $QtWidgets_CFLAGS"
			Qt_LIBS="$Qt_LIBS `$PKG_CONFIG --libs QtWidgets 2>/dev/null`"
		else
			AC_MSG_NOTICE([QtWidgets not found. Assuming Qt4])
		fi

		#
		# It also appears to move the printing support into
		# the QtPrintSupport module.
		#
		if QtPrintSupport_CFLAGS=`$PKG_CONFIG --cflags QtPrintSupport 2>/dev/null`; then
			Qt_CFLAGS="$Qt_CFLAGS $QtPrintSupport_CFLAGS"
			Qt_LIBS="$Qt_LIBS `$PKG_CONFIG --libs QtPrintSupport 2>/dev/null`"
		else
			AC_MSG_NOTICE([QtPrintSupport not found. Assuming Qt4])
		fi

		AC_SUBST(Qt_LIBS)

		# Run Action-If-Found
		ifelse([$2], , :, [$2])
	else
		# Run Action-If-Not-Found
		ifelse([$3], , :, [$3])
	fi

])
