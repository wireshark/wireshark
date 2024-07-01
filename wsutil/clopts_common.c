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

#include <wsutil/strtoi.h>
#include <wsutil/cmdarg_err.h>

int
get_natural_int(const char *string, const char *name)
{
    int32_t number;

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

uint32_t
get_guint32(const char *string, const char *name)
{
    uint32_t number;

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

uint32_t
get_nonzero_guint32(const char *string, const char *name)
{
    uint32_t number;

    number = get_guint32(string, name);

    if (number == 0) {
        cmdarg_err("The specified %s is zero", name);
        exit(1);
    }

    return number;
}

uint64_t
get_uint64(const char *string, const char *name)
{
    uint64_t number;

    if (!ws_strtou64(string, NULL, &number)) {
        if (errno == EINVAL) {
            cmdarg_err("The specified %s \"%s\" isn't a decimal number", name, string);
            exit(1);
        }
        cmdarg_err("The specified %s \"%s\" is too large (greater than %" PRIu64 ")",
                name, string, number);
        exit(1);
    }
    return number;
}

uint64_t
get_nonzero_uint64(const char *string, const char *name)
{
    uint64_t number;

    number = get_uint64(string, name);

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
