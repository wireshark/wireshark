/* file_util.c
 *
 * (Originally part of the Wiretap Library, now part of the Wireshark
 *  utility library)
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Windows file and DLL loading functions.
 *
 * ws_stdio_stat64() is based on g_stat() from the GLib file
 * glib/gstdio.c, but uses _wstati64(), so that we can get the sizes of
 * files of 2 GB or more. g_stat() can't do that: with MSVC on 64-bit
 * Windows, GStatBuf is struct stat, which has a 32-bit st_size. We use
 * the GLib wrappers for the other file functions; see file_util.h.
 *
 * DO NOT USE ws_stdio_stat64() DIRECTLY, USE ws_stat64() FROM
 * file_util.h INSTEAD!!!
 */

#ifndef _WIN32
#error "This is only for Windows"
#endif

#include "config.h"

#include <glib.h>

#include <windows.h>
#include <winsock2.h>
#include <errno.h>
#include <wchar.h>
#include <tchar.h>
#include <stdlib.h>

#include "file_util.h"
#include "ws_attributes.h"

static char *program_path;
static char *system_path;
static char *npcap_path;

/**
 * g_stat:
 * @filename: a pathname in the GLib file name encoding (UTF-8 on Windows)
 * @buf: a pointer to a <structname>stat</structname> struct, which
 *    will be filled with the file information
 *
 * A wrapper for the POSIX stat() function. The stat() function
 * returns information about a file.
 *
 * See the C library manual for more details about stat().
 *
 * Returns: 0 if the information was successfully retrieved, -1 if an error
 *    occurred
 *
 * Since: 2.6
 */
int
ws_stdio_stat64 (const char *filename, ws_statb64 *buf)
{
    wchar_t *wfilename = g_utf8_to_utf16 (filename, -1, NULL, NULL, NULL);
    int retval;
    int save_errno;
    size_t len;

    if (wfilename == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    len = wcslen (wfilename);
    while (len > 0 && G_IS_DIR_SEPARATOR (wfilename[len-1]))
        len--;
    if (len > 0 &&
            (!g_path_is_absolute (filename) || len > (size_t) (g_path_skip_root (filename) - filename)))
        wfilename[len] = '\0';

    retval = _wstati64 (wfilename, buf);
    save_errno = errno;

    g_free (wfilename);

    errno = save_errno;
    return retval;
}

/* DLL loading */
static bool
init_dll_load_paths(void)
{
    TCHAR path_w[MAX_PATH];

    if (program_path && system_path && npcap_path)
        return true;

    /* XXX - Duplicate code in filesystem.c:configuration_init */
    if (GetModuleFileName(NULL, path_w, MAX_PATH) == 0 || GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        return false;
    }

    if (!program_path) {
        char *app_path;
        app_path = g_utf16_to_utf8(path_w, -1, NULL, NULL, NULL);
        /* We could use PathRemoveFileSpec here but we'd have to link to Shlwapi.dll */
        program_path = g_path_get_dirname(app_path);
        g_free(app_path);
    }

    if (GetSystemDirectory(path_w, MAX_PATH) == 0) {
        return false;
    }

    if (!system_path) {
        system_path = g_utf16_to_utf8(path_w, -1, NULL, NULL, NULL);
    }

    _tcscat_s(path_w, MAX_PATH, _T("\\Npcap"));

    if (!npcap_path) {
        npcap_path = g_utf16_to_utf8(path_w, -1, NULL, NULL, NULL);
    }

    if (program_path && system_path && npcap_path)
        return true;

    return false;
}

bool
ws_init_dll_search_path(void)
{
    bool dll_dir_set = false;
    wchar_t *program_path_w;

    /* Remove the current directory from the default DLL search path. */
    SetDllDirectory(_T(""));

    if (init_dll_load_paths()) {
        /* Ensure that extcap executables can find wsutil, etc. */
        program_path_w = g_utf8_to_utf16(program_path, -1, NULL, NULL, NULL);
        dll_dir_set = SetDllDirectory(program_path_w);
        g_free(program_path_w);
    }

    return dll_dir_set;
}

/*
 * Internally g_module_open uses LoadLibrary on Windows and returns an
 * HMODULE cast to a GModule *. However there's no guarantee that this
 * will always be the case, so we call LoadLibrary and g_module_open
 * separately.
 */

void *
ws_load_library(const char *library_name)
{
    char    *full_path;
    wchar_t *full_path_w;
    HMODULE  dll_h;

    if (!init_dll_load_paths() || !library_name)
        return NULL;

    /* First try the program directory */
    full_path = g_strconcat(program_path, G_DIR_SEPARATOR_S, library_name, NULL);
    full_path_w = g_utf8_to_utf16(full_path, -1, NULL, NULL, NULL);

    if (full_path && full_path_w) {
        dll_h = LoadLibraryW(full_path_w);
        if (dll_h) {
            g_free(full_path);
            g_free(full_path_w);
            return dll_h;
        }
    }

    /* Next try the system directory */
    full_path = g_strconcat(system_path, G_DIR_SEPARATOR_S, library_name, NULL);
    full_path_w = g_utf8_to_utf16(full_path, -1, NULL, NULL, NULL);

    if (full_path && full_path_w) {
        dll_h = LoadLibraryW(full_path_w);
        if (dll_h) {
            g_free(full_path);
            g_free(full_path_w);
            return dll_h;
        }
    }

    return NULL;
}

static GModule *
load_npcap_module(const char *full_path, GModuleFlags flags)
{
    /*
     * Npcap's wpcap.dll requires packet.dll from the same directory. Either
     * SetDllDirectory or SetCurrentDirectory could make this work, but it
     * interferes with other uses of these settings. LoadLibraryEx is ideal as
     * it can be configured to put the directory containing the DLL to the
     * search path. Unfortunately g_module_open uses LoadLibrary internally, so
     * as a workaround manually load the Npcap libraries first and then use
     * g_module_open to obtain a GModule for the loaded library.
     */

    wchar_t *wpath = g_utf8_to_utf16(full_path, -1, NULL, NULL, NULL);
    HMODULE module = LoadLibraryEx(wpath, NULL, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR);
    g_free(wpath);
    if (!module) {
        return NULL;
    }
    GModule *mod = g_module_open(full_path, flags);
    FreeLibrary(module);
    return mod;
}

GModule *
load_wpcap_module(void)
{
    char    *module_name = "wpcap.dll";
    char    *full_path;
    GModule *mod;
    GModuleFlags flags = 0;

    if (!init_dll_load_paths())
        return NULL;

    /* First try the program directory */
    full_path = g_strconcat(program_path, G_DIR_SEPARATOR_S, module_name, NULL);

    if (full_path) {
        mod = g_module_open(full_path, flags);
        g_free(full_path);
        if (mod) {
            return mod;
        }
    }

    /* Next try the Npcap directory */
    full_path = g_strconcat(npcap_path, G_DIR_SEPARATOR_S, module_name, NULL);

    if (full_path) {
        mod = load_npcap_module(full_path, flags);
        g_free(full_path);
        if (mod) {
            return mod;
        }
    }

    /* At last try the system directory */
    full_path = g_strconcat(system_path, G_DIR_SEPARATOR_S, module_name, NULL);

    if (full_path) {
        mod = g_module_open(full_path, flags);
        g_free(full_path);
        if (mod) {
            return mod;
        }
    }

    return NULL;
}

/** Create or open a "Wireshark is running" mutex.
 */
#define WIRESHARK_IS_RUNNING_UUID "9CA78EEA-EA4D-4490-9240-FC01FCEF464B"

static HANDLE local_running_mutex;
static HANDLE global_running_mutex;

void create_app_running_mutex(void) {
    SECURITY_DESCRIPTOR sec_descriptor;
    SECURITY_ATTRIBUTES sec_attributes;
    SECURITY_ATTRIBUTES *sa;
    memset(&sec_descriptor, 0, sizeof(SECURITY_DESCRIPTOR));
    if (!InitializeSecurityDescriptor(&sec_descriptor, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorDacl(&sec_descriptor, true, NULL, false)) {
        /*
         * We couldn't set up the security descriptor, so use the default
         * security attributes when creating the mutexes.
         */
        sa = NULL;
    } else {
        /*
         * We could set it up, so set up some attributes that refer
         * to it.
         */
        memset(&sec_attributes, 0, sizeof(SECURITY_ATTRIBUTES));
        sec_attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
        sec_attributes.lpSecurityDescriptor = &sec_descriptor;
        sec_attributes.bInheritHandle = true;
        sa = &sec_attributes;
    }
    local_running_mutex = CreateMutex(sa, false, _T("Wireshark-is-running-{") _T(WIRESHARK_IS_RUNNING_UUID) _T("}"));
    global_running_mutex = CreateMutex(sa, false, _T("Global\\Wireshark-is-running-{") _T(WIRESHARK_IS_RUNNING_UUID) _T("}"));
}

void close_app_running_mutex(void) {
    if (local_running_mutex) {
        CloseHandle(local_running_mutex);
        local_running_mutex = NULL;
    }
    if (global_running_mutex) {
        CloseHandle(global_running_mutex);
        global_running_mutex = NULL;
    }
}

int ws_close_if_possible(int fd) {
    fd_set rfds;
    struct timeval tv = { 0, 1 };
    int retval;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    /* XXX - select() doesn't work on named pipes and other file descriptors
     * in Windows, only sockets. Does this ever work? Double-closing should
     * be prevented in other ways (e.g., checking that fd is not -1.)
     * https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-select
     */
    retval = select(1, &rfds, NULL, NULL, &tv);
    if (retval > -1)
        return _close(fd);

    return -1;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
