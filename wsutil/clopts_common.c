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

#include "clopts_common.h"

#include <stdlib.h>
#include <errno.h>
#include <ws_exit_codes.h>
#include <wsutil/strtoi.h>
#include <wsutil/cmdarg_err.h>

bool
get_natural_int(const char *string, const char *name, int32_t* number)
{
    if (!ws_strtoi32(string, NULL, number)) {
        if (errno == EINVAL) {
            cmdarg_err("The specified %s \"%s\" isn't a decimal number", name, string);
            return false;
        }
        if (*number < 0) {
            cmdarg_err("The specified %s \"%s\" is a negative number", name, string);
            return false;
        }
        cmdarg_err("The specified %s \"%s\" is too large (greater than %d)",
                name, string, *number);
        return false;
    }
    if (*number < 0) {
        cmdarg_err("The specified %s \"%s\" is a negative number", name, string);
        return false;
    }
    return true;
}

bool
get_positive_int(const char *string, const char *name, int32_t* number)
{
    if (!get_natural_int(string, name, number))
        return false;

    if (*number == 0) {
        cmdarg_err("The specified %s is zero", name);
        return false;
    }

    return true;
}

bool
get_natural_int64(const char* string, const char* name, int64_t* number)
{
  if (!ws_strtoi64(string, NULL, number)) {
    if (errno == EINVAL) {
      cmdarg_err("The specified %s \"%s\" isn't a decimal number", name, string);
      return false;
    }
    if (*number < 0) {
      cmdarg_err("The specified %s \"%s\" is a negative number", name, string);
      return false;
    }
    cmdarg_err("The specified %s \"%s\" is too large (greater than %" PRId64 ")",
      name, string, *number);
    return false;
  }
  if (*number < 0) {
    cmdarg_err("The specified %s \"%s\" is a negative number", name, string);
    return false;
  }
  return true;
}

bool
get_positive_int64(const char* string, const char* name, int64_t* number)
{
  if (!get_natural_int64(string, name, number))
    return false;

  if (*number == 0) {
    cmdarg_err("The specified %s is zero", name);
    return false;
  }

  return true;
}

bool
get_uint32(const char *string, const char *name, uint32_t* number)
{
    if (!ws_strtou32(string, NULL, number)) {
        if (errno == EINVAL) {
            cmdarg_err("The specified %s \"%s\" isn't a decimal number", name, string);
            return false;
        }
        cmdarg_err("The specified %s \"%s\" is too large (greater than %d)",
                name, string, *number);
        return false;
    }
    return true;
}

bool
get_nonzero_uint32(const char *string, const char *name, uint32_t* number)
{
    if (!get_uint32(string, name, number))
        return false;

    if (*number == 0) {
        cmdarg_err("The specified %s is zero", name);
        return false;
    }

    return true;
}

bool
get_uint64(const char *string, const char *name, uint64_t* number)
{
    if (!ws_strtou64(string, NULL, number)) {
        if (errno == EINVAL) {
            cmdarg_err("The specified %s \"%s\" isn't a decimal number", name, string);
            return false;
        }
        cmdarg_err("The specified %s \"%s\" is too large (greater than %" PRIu64 ")",
                name, string, *number);
        return false;
    }
    return true;
}

bool
get_nonzero_uint64(const char *string, const char *name, uint64_t* number)
{
    if (!get_uint64(string, name, number))
        return false;

    if (*number == 0) {
        cmdarg_err("The specified %s is zero", name);
        return false;
    }

    return true;
}

bool
get_positive_double(const char *string, const char *name, double* number)
{
    *number = g_ascii_strtod(string, NULL);

    if (errno == EINVAL) {
        cmdarg_err("The specified %s \"%s\" isn't a floating point number", name, string);
        return false;
    }
    if (*number < 0.0) {
        cmdarg_err("The specified %s \"%s\" is a negative number", name, string);
        return false;
    }

    return true;
}
