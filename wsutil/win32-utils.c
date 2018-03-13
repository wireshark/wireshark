/* win32-utils.c
 * Win32 utility routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2006 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "win32-utils.h"

#include <log.h>

#include <tchar.h>
#include <VersionHelpers.h>

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

// This appears to be the closest equivalent to SIGPIPE on Windows.
// https://blogs.msdn.microsoft.com/oldnewthing/20131209-00/?p=2433
// https://stackoverflow.com/a/53214/82195

static void win32_kill_child_on_exit(HANDLE child_handle) {
    static HANDLE cjo_handle = NULL;
    if (!cjo_handle) {
        cjo_handle = CreateJobObject(NULL, _T("Local\\Wireshark child process cleanup"));

        if (!cjo_handle) {
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "Could not create child cleanup job object: %s",
                win32strerror(GetLastError()));
            return;
        }

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION cjo_jel_info = { 0 };
        cjo_jel_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        BOOL sijo_ret = SetInformationJobObject(cjo_handle, JobObjectExtendedLimitInformation,
            &cjo_jel_info, sizeof(cjo_jel_info));
        if (!sijo_ret) {
            g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "Could not set child cleanup limits: %s",
                win32strerror(GetLastError()));
        }
    }

    BOOL aptjo_ret = AssignProcessToJobObject(cjo_handle, child_handle);
    if (!aptjo_ret) {
        g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_DEBUG, "Could not assign child cleanup process: %s",
            win32strerror(GetLastError()));
    }
}

BOOL win32_create_process(const char *application_name, const char *command_line, LPSECURITY_ATTRIBUTES process_attributes, LPSECURITY_ATTRIBUTES thread_attributes, BOOL inherit_handles, DWORD creation_flags, LPVOID environment, const char *current_directory, LPSTARTUPINFO startup_info, LPPROCESS_INFORMATION process_information)
{
    gunichar2 *wappname = NULL, *wcurrentdirectory = NULL;
    gunichar2 *wcommandline = g_utf8_to_utf16(command_line, -1, NULL, NULL, NULL);
    // CREATE_SUSPENDED: Suspend the child so that we can cleanly call
    //     AssignProcessToJobObject.
    DWORD wcreationflags = creation_flags|CREATE_SUSPENDED;
    // CREATE_BREAKAWAY_FROM_JOB: The main application might be associated with a job,
    //     e.g. if we're running under "Run As", ConEmu, or Visual Studio. On Windows
    //     <= 7 our child process needs to break away from it so that we can cleanly
    //     call AssignProcessToJobObject on *our* job.
    //     Windows >= 8 supports nested jobs so this isn't neccessary there.
    //     https://blogs.msdn.microsoft.com/winsdk/2014/09/22/job-object-insanity/
    //
    if (! IsWindowsVersionOrGreater(6, 2, 0)) { // Windows 8
        wcreationflags |= CREATE_BREAKAWAY_FROM_JOB;
    }

    if (application_name) {
        wappname = g_utf8_to_utf16(application_name, -1, NULL, NULL, NULL);
    }
    if (current_directory) {
        wcurrentdirectory = g_utf8_to_utf16(current_directory, -1, NULL, NULL, NULL);
    }
    BOOL cp_res = CreateProcess(wappname, wcommandline, process_attributes, thread_attributes,
        inherit_handles, wcreationflags, environment, wcurrentdirectory, startup_info,
        process_information);
    if (cp_res) {
        win32_kill_child_on_exit(process_information->hProcess);
        ResumeThread(process_information->hThread);
    }
    // XXX Else try again if CREATE_BREAKAWAY_FROM_JOB and GetLastError() == ERROR_ACCESS_DENIED?

    g_free(wappname);
    g_free(wcommandline);
    g_free(wcurrentdirectory);
    return cp_res;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
