/* clopts_common.c
 * Handle command-line arguments common to various programs
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>
#include <errno.h>

#include <wsutil/strtoi.h>
#include <ui/cmdarg_err.h>

#include "clopts_common.h"

int
get_natural_int(const char *string, const char *name)
{
  gint32 number;

  if (!ws_strtoi32(string, NULL, &number)) {
    if (errno == EINVAL) {
      cmdarg_err("The specified %s \"%s\" isn't a decimal number", name, string);
      exit(1);
    }
    if (number < 0) {
      cmdarg_err("The specified %s \"%s\" is a negative number", name, string);
      exit(1);
    }
    cmdarg_err("The specified %s \"%s\" is too large (greater than %d)",
               name, string, number);
    exit(1);
  }
  if (number < 0) {
    cmdarg_err("The specified %s \"%s\" is a negative number", name, string);
    exit(1);
  }
  return (int)number;
}

int
get_positive_int(const char *string, const char *name)
{
  int number;

  number = get_natural_int(string, name);

  if (number == 0) {
    cmdarg_err("The specified %s is zero", name);
    exit(1);
  }

  return number;
}

guint32
get_guint32(const char *string, const char *name)
{
  guint32 number;

  if (!ws_strtou32(string, NULL, &number)) {
    if (errno == EINVAL) {
      cmdarg_err("The specified %s \"%s\" isn't a decimal number", name, string);
      exit(1);
    }
    cmdarg_err("The specified %s \"%s\" is too large (greater than %d)",
               name, string, number);
    exit(1);
  }
  return number;
}

guint32
get_nonzero_guint32(const char *string, const char *name)
{
  guint32 number;

  number = get_guint32(string, name);

  if (number == 0) {
    cmdarg_err("The specified %s is zero", name);
    exit(1);
  }

  return number;
}

double
get_positive_double(const char *string, const char *name)
{
  double number = g_ascii_strtod(string, NULL);

  if (errno == EINVAL) {
    cmdarg_err("The specified %s \"%s\" isn't a floating point number", name, string);
    exit(1);
  }
  if (number < 0.0) {
    cmdarg_err("The specified %s \"%s\" is a negative number", name, string);
    exit(1);
  }

  return number;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
