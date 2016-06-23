/* win32-utils.c
 * Win32 utility routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2006 Gerald Combs
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

#include "win32-utils.h"

/* Quote the argument element if necessary, so that it will get
 * reconstructed correctly in the C runtime startup code.  Note that
 * the unquoting algorithm in the C runtime is really weird, and
 * rather different than what Unix shells do. See stdargv.c in the C
 * runtime sources (in the Platform SDK, in src/crt).
 *
 * Stolen from GLib's protect_argv(), an internal routine that quotes
 * string in an argument list so that they arguments will be handled
 * correctly in the command-line string passed to CreateProcess()
 * if that string is constructed by gluing those strings together.
 */
gchar *
protect_arg (const gchar *argv)
{
    gchar *new_arg;
    const gchar *p = argv;
    gchar *q;
    gint len = 0;
    gboolean need_dblquotes = FALSE;

    while (*p) {
        if (*p == ' ' || *p == '\t')
            need_dblquotes = TRUE;
        else if (*p == '"')
            len++;
        else if (*p == '\\') {
            const gchar *pp = p;

            while (*pp && *pp == '\\')
                pp++;
            if (*pp == '"')
                len++;
        }
        len++;
        p++;
    }

    q = new_arg = g_malloc (len + need_dblquotes*2 + 1);
    p = argv;

    if (need_dblquotes)
        *q++ = '"';

    while (*p) {
        if (*p == '"')
            *q++ = '\\';
        else if (*p == '\\') {
            const gchar *pp = p;

            while (*pp && *pp == '\\')
                pp++;
            if (*pp == '"')
                *q++ = '\\';
        }
        *q++ = *p;
        p++;
    }

    if (need_dblquotes)
        *q++ = '"';
    *q++ = '\0';

    return new_arg;
}

/*
 * Generate a string for a Win32 error.
 */
#define ERRBUF_SIZE    1024
const char *
win32strerror(DWORD error)
{
    static char errbuf[ERRBUF_SIZE+1];
    size_t errlen;
    char *p;

    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, error, 0, errbuf, ERRBUF_SIZE, NULL);

    /*
     * "FormatMessage()" "helpfully" sticks CR/LF at the end of the
     * message.  Get rid of it.
     */
    errlen = strlen(errbuf);
    if (errlen >= 2) {
        errbuf[errlen - 1] = '\0';
        errbuf[errlen - 2] = '\0';
    }
    p = strchr(errbuf, '\0');
    g_snprintf(p, (gulong)(sizeof errbuf - (p-errbuf)), " (%lu)", error);
    return errbuf;
}

/*
 * Generate a string for a Win32 exception code.
 */
const char *
win32strexception(DWORD exception)
{
    static char errbuf[ERRBUF_SIZE+1];
    static const struct exception_msg {
        int code;
        char *msg;
    } exceptions[] = {
        { EXCEPTION_ACCESS_VIOLATION, "Access violation" },
        { EXCEPTION_ARRAY_BOUNDS_EXCEEDED, "Array bounds exceeded" },
        { EXCEPTION_BREAKPOINT, "Breakpoint" },
        { EXCEPTION_DATATYPE_MISALIGNMENT, "Data type misalignment" },
        { EXCEPTION_FLT_DENORMAL_OPERAND, "Denormal floating-point operand" },
        { EXCEPTION_FLT_DIVIDE_BY_ZERO, "Floating-point divide by zero" },
        { EXCEPTION_FLT_INEXACT_RESULT, "Floating-point inexact result" },
        { EXCEPTION_FLT_INVALID_OPERATION, "Invalid floating-point operation" },
        { EXCEPTION_FLT_OVERFLOW, "Floating-point overflow" },
        { EXCEPTION_FLT_STACK_CHECK, "Floating-point stack check" },
        { EXCEPTION_FLT_UNDERFLOW, "Floating-point underflow" },
        { EXCEPTION_GUARD_PAGE, "Guard page violation" },
        { EXCEPTION_ILLEGAL_INSTRUCTION, "Illegal instruction" },
        { EXCEPTION_IN_PAGE_ERROR, "Page-in error" },
        { EXCEPTION_INT_DIVIDE_BY_ZERO, "Integer divide by zero" },
        { EXCEPTION_INT_OVERFLOW, "Integer overflow" },
        { EXCEPTION_INVALID_DISPOSITION, "Invalid disposition" },
        { EXCEPTION_INVALID_HANDLE, "Invalid handle" },
        { EXCEPTION_NONCONTINUABLE_EXCEPTION, "Non-continuable exception" },
        { EXCEPTION_PRIV_INSTRUCTION, "Privileged instruction" },
        { EXCEPTION_SINGLE_STEP, "Single-step complete" },
        { EXCEPTION_STACK_OVERFLOW, "Stack overflow" },
        { 0, NULL }
    };
#define N_EXCEPTIONS    (sizeof exceptions / sizeof exceptions[0])
    int i;

    for (i = 0; i < N_EXCEPTIONS; i++) {
        if (exceptions[i].code == exception)
            return exceptions[i].msg;
    }
    g_snprintf(errbuf, (gulong)sizeof errbuf, "Exception 0x%08x", exception);
    return errbuf;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
