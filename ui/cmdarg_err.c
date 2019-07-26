/* cmdarg_err.c
 * Routines to report command-line argument errors.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "cmdarg_err.h"

static void (*print_err)(const char *, va_list ap);
static void (*print_err_cont)(const char *, va_list ap);

/*
 * Set the reporting functions for error messages.
 */
void
cmdarg_err_init(void (*err)(const char *, va_list),
                void (*err_cont)(const char *, va_list))
{
    print_err = err;
    print_err_cont = err_cont;
}

/*
 * Report an error in command-line arguments.
 */
void
cmdarg_err(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    print_err(fmt, ap);
    va_end(ap);
}

/*
 * Report additional information for an error in command-line arguments.
 */
void
cmdarg_err_cont(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    print_err_cont(fmt, ap);
    va_end(ap);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
