/* cmdarg_err.c
 * Routines to report command-line argument errors.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"


#include <wsutil/cmdarg_err.h>

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
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
