/* file_dlg_win32.c
 * Native Windows file dialog routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2004 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifdef _WIN32

#include "config.h"

#include <tchar.h>

#include <windows.h>

#include <ws_attributes.h>
#include <ws_diag_control.h>

#include "file_dlg_win32.h"

/* As of Wireshark 4.2, we only support Windows 10 and later, so this
 * should always be defined. OTOH, Qt >= 6.0 uses DPI Awareness
 * Context Per Monitor Aware v2 by default, so maybe we should make
 * it a no-op there.  */
#ifdef DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
typedef DPI_AWARENESS_CONTEXT (WINAPI *GetThreadDpiAwarenessContextProc)(void);
typedef DPI_AWARENESS_CONTEXT (WINAPI *SetThreadDpiAwarenessContextProc)(DPI_AWARENESS_CONTEXT);

static GetThreadDpiAwarenessContextProc GetThreadDpiAwarenessContextP;
static SetThreadDpiAwarenessContextProc SetThreadDpiAwarenessContextP;
static bool got_proc_addresses;

DIAG_OFF(cast-function-type)
static bool get_proc_addresses(void) {
    if (got_proc_addresses) return true;

    HMODULE u32_module = LoadLibrary(_T("User32.dll"));
    if (!u32_module) {
        got_proc_addresses = false;
        return false;
    }
    bool got_all = true;
    GetThreadDpiAwarenessContextP = (GetThreadDpiAwarenessContextProc) GetProcAddress(u32_module, "GetThreadDpiAwarenessContext");
    if (!GetThreadDpiAwarenessContextP) got_all = false;
    SetThreadDpiAwarenessContextP = (SetThreadDpiAwarenessContextProc) GetProcAddress(u32_module, "SetThreadDpiAwarenessContext");
    if (!SetThreadDpiAwarenessContextP) got_all = false;

    got_proc_addresses = got_all;
    return got_all;
}
DIAG_ON(cast-function-type)

// Enabling DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 causes issues
// when dragging our open file dialog between differently-DPIed
// displays. It might be time to break down and switch to common
// item dialogs.
HANDLE set_thread_per_monitor_v2_awareness(void) {
    if (! get_proc_addresses()) return 0;
#if 0
    WCHAR info[100];
    StringCchPrintf(info, 100,
                    L"GetThrDpiAwarenessCtx: %d",
                    GetThreadDpiAwarenessContextP());
    MessageBox(NULL, info, _T("DPI info"), MB_OK);
#endif
    return (HANDLE) SetThreadDpiAwarenessContextP(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
}

void revert_thread_per_monitor_v2_awareness(HANDLE context) {
    if (! get_proc_addresses()) return;
    SetThreadDpiAwarenessContextP((DPI_AWARENESS_CONTEXT) context);
}
#else // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
HANDLE set_thread_per_monitor_v2_awareness(void) { return 0; }
void revert_thread_per_monitor_v2_awareness(HANDLE context _U_) { }
#endif // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2

#endif // _WIN32
