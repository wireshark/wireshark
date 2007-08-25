# Configure paths for libsmi.

dnl AM_PATH_LIBSMI()
dnl Test for libsmi and defines the symbol LIBSMI if the test is
dnl successful. Also defines HAVE_LIBSMI_H and adds -llibsmi to the 
dnl LIBS variable.
dnl 
AC_DEFUN([AM_PATH_LIBSMI],
[
  AC_CHECK_HEADERS(smi.h)
  AC_CHECK_LIB(smi, smiInit)
  AC_MSG_CHECKING([whether to enable libsmi])
  AC_TRY_RUN([ /* libsmi available check */
#include <smi.h>
main()
{
  int current, revision, age, n;
  const int required = 2;
  if (smiInit(""))
    exit(1);
  if (strcmp(SMI_LIBRARY_VERSION, smi_library_version))
    exit(2);
  n = sscanf(smi_library_version, "%d:%d:%d", &current, &revision, &age);
  if (n != 3)
    exit(3);
  if (required < current - age || required > current)
    exit(4);
  exit(0);
}
],
  [ AC_MSG_RESULT(yes)
    libsmi=yes],
  [ AC_MSG_RESULT(no)
    libsmi=no],
  [ AC_MSG_RESULT(not when cross-compiling)
    libsmi=no]
  )
])
