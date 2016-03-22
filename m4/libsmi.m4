# Configure paths for libsmi
# Shamelessly stolen from http://autoconf-archive.cryp.to/ax_lib_sqlite3.html

# Synopsis: AX_LIBSMI([minimum library version])
# The default minimum library version is 2

# This macro sets/substitutes the following:
# AC_DEFINE(HAVE_LIBSMI)
# AC_SUBST(LIBSMI_CFLAGS)
# AC_SUBST(LIBSMI_LDFLAGS)
# AC_SUBST(LIBSMI_VERSION)
# $libsmi_message is set to "yes" or "no"

AC_DEFUN([AX_LIBSMI],
[
    AC_ARG_WITH([libsmi],
        AC_HELP_STRING(
            [--with-libsmi=@<:@DIR@:>@],
            [use libsmi MIB/PIB library @<:@default=yes@:>@, optionally specify the prefix for libsmi]
        ),
        [
        if test "$withval" = "no"; then
            WANT_LIBSMI="no"
        elif test "$withval" = "yes"; then
            WANT_LIBSMI="yes"
            ac_libsmi_path=""
        else
            WANT_LIBSMI="yes"
            ac_libsmi_path="$withval"
        fi
        ],
        [WANT_LIBSMI="yes"]
    )

    libsmi_message="no"
    LIBSMI_CFLAGS=""
    LIBSMI_LDFLAGS=""
    LIBSMI_VERSION=""

    if test "x$WANT_LIBSMI" = "xyes"; then

        ac_libsmi_header="smi.h"

        libsmi_version_req=ifelse([$1], [], [2], [$1])

        AC_MSG_CHECKING([for libsmi >= $libsmi_version_req])

        if test "$ac_libsmi_path" != ""; then
            ac_libsmi_ldflags="-L$ac_libsmi_path/lib"
            ac_libsmi_cflags="-I$ac_libsmi_path/include"
        else
            for ac_libsmi_path_tmp in /usr /usr/local /opt $prefix; do
                if test -f "$ac_libsmi_path_tmp/include/$ac_libsmi_header" \
                    && test -r "$ac_libsmi_path_tmp/include/$ac_libsmi_header"; then
                    ac_libsmi_path=$ac_libsmi_path_tmp
                    ac_libsmi_ldflags="-L$ac_libsmi_path_tmp/lib"
                    ac_libsmi_cflags="-I$ac_libsmi_path_tmp/include"
                    break;
                fi
            done
        fi

        ac_libsmi_ldflags="$ac_libsmi_ldflags -lsmi"

        saved_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $ac_libsmi_cflags"

        AC_LANG_PUSH(C)
        AC_COMPILE_IFELSE(
            [
            AC_LANG_PROGRAM([[@%:@include <smi.h>]],
                [[
  int current, revision, age, n;
  const int required = $libsmi_version_req;
  if (smiInit(""))
    exit(1);
  if (strcmp(SMI_LIBRARY_VERSION, smi_library_version))
    exit(2);
  n = sscanf(smi_library_version, "%d:%d:%d", &current, &revision, &age);
  if (n != 3)
    exit(3);
  if (required < current - age || required > current)
    exit(4);
                ]]
            )
            ],
            [
            AC_MSG_RESULT([yes])
            libsmi_message="yes"
            ],
            [
            AC_MSG_RESULT([not found])
            libsmi_message="no"
            ]
        )
        AC_LANG_POP([C])

        CFLAGS="$saved_CFLAGS"

        if test "$libsmi_message" = "yes"; then

            LIBSMI_CFLAGS="$ac_libsmi_cflags"
            LIBSMI_LDFLAGS="$ac_libsmi_ldflags"

            ac_libsmi_header_path="$ac_libsmi_path/include/$ac_libsmi_header"

            dnl Retrieve libsmi release version
            if test "x$ac_libsmi_header_path" != "x"; then
                ac_libsmi_version=`cat $ac_libsmi_header_path \
                    | grep '#define.*SMI_LIBRARY_VERSION.*\"' | sed -e 's/.* "//' \
                        | sed -e 's/"//'`
                if test $ac_libsmi_version != ""; then
                    LIBSMI_VERSION=$ac_libsmi_version
                else
                    AC_MSG_WARN([Can not find SMI_LIBRARY_VERSION macro in smi.h header to retrieve libsmi version!])
                fi
            fi

            AC_SUBST(LIBSMI_CFLAGS)
            AC_SUBST(LIBSMI_LDFLAGS)
            AC_SUBST(LIBSMI_VERSION)
            AC_DEFINE(HAVE_LIBSMI, 1, [Define to 1 if you have the `smi' library (-lsmi).])
        fi
    fi
])
