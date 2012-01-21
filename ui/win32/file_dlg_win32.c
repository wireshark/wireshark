/* win32-file-dlg.c
 * Native Windows file dialog routines
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2004 Gerald Combs
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <tchar.h>
#include <wchar.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <io.h>
#include <fcntl.h>

#include <windows.h>
#include <windowsx.h>
#include <commdlg.h>
#include <richedit.h>

#include <gtk/gtk.h>

#include "epan/filesystem.h"
#include "epan/addr_resolv.h"
#include "epan/prefs.h"
#include "epan/dissectors/packet-ssl.h"
#include "epan/dissectors/packet-ssl-utils.h"
#include "wsutil/file_util.h"
#include "wsutil/unicode-utils.h"

#include "../alert_box.h"
#include "../color.h"
#include "../print.h"
#include "../simple_dialog.h"
#include "../util.h"
#include "../color_filters.h"
#include "../merge.h"

#include "ui/last_open_dir.h"

#include "ui/gtk/file_dlg.h"
#include "ui/gtk/capture_file_dlg.h"
#include "ui/gtk/main.h"
#include "ui/gtk/menus.h"
#include "ui/gtk/drag_and_drop.h"
#include "ui/gtk/capture_dlg.h"
#include "file_dlg_win32.h"
#include "ui/gtk/help_dlg.h"
#include "ui/gtk/export_sslkeys.h"

typedef enum {
    merge_append,
    merge_chrono,
    merge_prepend
} merge_action_e;

#define FILE_OPEN_DEFAULT 1 /* All Files */

#define FILE_MERGE_DEFAULT FILE_OPEN_DEFAULT

#define FILE_SAVE_DEFAULT 1 /* Wireshark/tcpdump */

#define FILE_TYPES_EXPORT \
    _T("Plain text (*.txt)\0")                           _T("*.txt\0")   \
    _T("PostScript (*.ps)\0")                            _T("*.ps\0")    \
    _T("CSV (Comma Separated Values summary) (*.csv)\0") _T("*.csv\0")   \
    _T("PSML (XML packet summary) (*.psml)\0")           _T("*.psml\0")  \
    _T("PDML (XML packet detail) (*.pdml)\0")            _T("*.pdml\0")  \
    _T("C Arrays (packet bytes) (*.c)\0")                _T("*.c\0")

#define FILE_TYPES_RAW \
    _T("Raw data (*.bin, *.dat, *.raw)\0")               _T("*.bin;*.dat;*.raw\0") \
    _T("All Files (*.*)\0")                              _T("*.*\0")

#define FILE_RAW_DEFAULT 1

#define FILE_TYPES_SSLKEYS \
    _T("SSL Session Keys (*.keys)\0")                    _T("*.keys\0") \
    _T("All Files (*.*)\0")                              _T("*.*\0")

#define FILE_SSLKEYS_DEFAULT 1

#define FILE_TYPES_COLOR \
    _T("Text Files (*.txt)\0")                           _T("*.txt\0")   \
    _T("All Files (*.*)\0")                              _T("*.*\0")

#define FILE_DEFAULT_COLOR 2

/*
 * We should probably test the SDK version instead of the compiler version,
 * but this should work for our purposes.
 */
#if (_MSC_VER <= 1200)
static UINT CALLBACK open_file_hook_proc(HWND of_hwnd, UINT ui_msg, WPARAM w_param, LPARAM l_param);
static UINT CALLBACK save_as_file_hook_proc(HWND of_hwnd, UINT ui_msg, WPARAM w_param, LPARAM l_param);
static UINT CALLBACK merge_file_hook_proc(HWND mf_hwnd, UINT ui_msg, WPARAM w_param, LPARAM l_param);
static UINT CALLBACK export_file_hook_proc(HWND of_hwnd, UINT ui_msg, WPARAM w_param, LPARAM l_param);
static UINT CALLBACK export_raw_file_hook_proc(HWND of_hwnd, UINT ui_msg, WPARAM w_param, LPARAM l_param);
static UINT CALLBACK export_sslkeys_file_hook_proc(HWND of_hwnd, UINT ui_msg, WPARAM w_param, LPARAM l_param);
#else
static UINT_PTR CALLBACK open_file_hook_proc(HWND of_hwnd, UINT ui_msg, WPARAM w_param, LPARAM l_param);
static UINT_PTR CALLBACK save_as_file_hook_proc(HWND of_hwnd, UINT ui_msg, WPARAM w_param, LPARAM l_param);
static UINT_PTR CALLBACK merge_file_hook_proc(HWND mf_hwnd, UINT ui_msg, WPARAM w_param, LPARAM l_param);
static UINT_PTR CALLBACK export_file_hook_proc(HWND of_hwnd, UINT ui_msg, WPARAM w_param, LPARAM l_param);
static UINT_PTR CALLBACK export_raw_file_hook_proc(HWND of_hwnd, UINT ui_msg, WPARAM w_param, LPARAM l_param);
static UINT_PTR CALLBACK export_sslkeys_file_hook_proc(HWND of_hwnd, UINT ui_msg, WPARAM w_param, LPARAM l_param);
#endif /* (_MSC_VER <= 1200) */

static void range_update_dynamics(HWND sf_hwnd, packet_range_t *range);
static void range_handle_wm_initdialog(HWND dlg_hwnd, packet_range_t *range);
static void range_handle_wm_command(HWND dlg_hwnd, HWND ctrl, WPARAM w_param, packet_range_t *range);

static TCHAR *build_file_type_list(gboolean save, int *item_to_select);
static int file_type_from_list_index(gboolean save, int index);

static int            filetype;
static packet_range_t g_range;
static merge_action_e merge_action;
static print_args_t   print_args;
/* XXX - The reason g_sf_hwnd exists is so that we can call
 *       range_update_dynamics() from anywhere; it's currently
 *       static, but if we move to using the native Windows
 *       print dialog and put range widgets in it as well,
 *       it might be moved to a separate file.
 *
 *       However, the save file dialog hogs the foreground, so
 *       this may not be necessary (and, in fact, the file dialogs
 *       should arguably be modal to the window for the file
 *       being opened/saved/etc.).
 */
static HWND           g_sf_hwnd = NULL;
static char *dfilter_str = NULL;

/*
 * According to http://msdn.microsoft.com/en-us/library/bb776913.aspx
 * we should use IFileOpenDialog and IFileSaveDialog on Windows Vista
 * and later.
 */

gboolean
win32_open_file (HWND h_wnd) {
    OPENFILENAME *ofn;
    TCHAR  file_name[MAX_PATH] = _T("");
    int    err;
    char  *dirname;
    dfilter_t *dfp;
    int    ofnsize;
#if (_MSC_VER >= 1500)
    OSVERSIONINFO osvi;
#endif

    /* Remarks on OPENFILENAME_SIZE_VERSION_400:
     *
     * MSDN states that OPENFILENAME_SIZE_VERSION_400 should be used with
     * WINVER and _WIN32_WINNT >= 0x0500.
     * Unfortunately all these are compiler constants, while the underlying is a
     * problem based is a length check of the runtime version used.
     *
     * Instead of using OPENFILENAME_SIZE_VERSION_400, just malloc
     * the OPENFILENAME size plus 12 bytes.
     * These 12 bytes are the difference between the two versions of this struct.
     *
     * Interestingly this fixes a bug, so the places bar e.g. "My Documents"
     * is displayed - which wasn't the case with the former implementation.
     *
     * XXX - It's unclear if this length+12 works on all supported platforms,
     * NT4 is the question here. However, even if it fails, we must calculate
     * the length based on the runtime, not the compiler version anyway ...
     */
    /* This assumption does not work when compiling with MSVC2008EE as
     * the open dialog window does not appear.
     * Instead detect Windows version at runtime and choose size accordingly */
#if (_MSC_VER >= 1500)
    SecureZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osvi);
    if (osvi.dwMajorVersion >= 5) {
        ofnsize = sizeof(OPENFILENAME);
    } else {
        ofnsize = OPENFILENAME_SIZE_VERSION_400;
    }
#else
    ofnsize = sizeof(OPENFILENAME) + 12;
#endif
    ofn = g_malloc0(ofnsize);

    ofn->lStructSize = ofnsize;
    ofn->hwndOwner = h_wnd;
#if (_MSC_VER <= 1200)
    ofn->hInstance = (HINSTANCE) GetWindowLong(h_wnd, GWL_HINSTANCE);
#else
    ofn->hInstance = (HINSTANCE) GetWindowLongPtr(h_wnd, GWLP_HINSTANCE);
#endif
    ofn->lpstrFilter = build_file_type_list(FALSE /*!save*/, NULL);
    ofn->lpstrCustomFilter = NULL;
    ofn->nMaxCustFilter = 0;
    ofn->nFilterIndex = FILE_OPEN_DEFAULT;
    ofn->lpstrFile = file_name;
    ofn->nMaxFile = MAX_PATH;
    ofn->lpstrFileTitle = NULL;
    ofn->nMaxFileTitle = 0;
    if (prefs.gui_fileopen_style == FO_STYLE_SPECIFIED && prefs.gui_fileopen_dir[0] != '\0') {
        ofn->lpstrInitialDir = utf_8to16(prefs.gui_fileopen_dir);
    } else {
        ofn->lpstrInitialDir = utf_8to16(get_last_open_dir());
    }
    ofn->lpstrTitle = _T("Wireshark: Open Capture File");
    ofn->Flags = OFN_ENABLESIZING | OFN_ENABLETEMPLATE | OFN_EXPLORER     |
                 OFN_NOCHANGEDIR  | OFN_FILEMUSTEXIST  | OFN_HIDEREADONLY |
                 OFN_ENABLEHOOK   | OFN_SHOWHELP;
    ofn->lpstrDefExt = NULL;
    ofn->lpfnHook = open_file_hook_proc;
    ofn->lpTemplateName = _T("WIRESHARK_OPENFILENAME_TEMPLATE");

    if (GetOpenFileName(ofn)) {
        g_free( (void *) ofn->lpstrFilter);
        g_free( (void *) ofn);

        if (cf_open(&cfile, utf_16to8(file_name), FALSE, &err) != CF_OK) {
            return FALSE;
        }

        /* apply our filter */
        if (dfilter_compile(dfilter_str, &dfp)) {
            cf_set_rfcode(&cfile, dfp);
        }

        switch (cf_read(&cfile, FALSE)) {
            case CF_READ_OK:
            case CF_READ_ERROR:
                dirname = get_dirname(utf_16to8(file_name));
                set_last_open_dir(dirname);
                return TRUE;
                break;
        }
    } else {
        g_free( (void *) ofn->lpstrFilter);
        g_free( (void *) ofn);
    }
    return FALSE;
}


void
win32_save_as_file(HWND h_wnd, action_after_save_e action_after_save, gpointer action_after_save_data) {
    OPENFILENAME *ofn;
    TCHAR  file_name16[MAX_PATH] = _T("");
    GString *file_name8;
    gchar *file_last_dot;
    gchar *dirname;
    int save_index;
    int    ofnsize;
#if (_MSC_VER >= 1500)
    OSVERSIONINFO osvi;
#endif

    /* see OPENFILENAME comment in win32_open_file */
#if (_MSC_VER >= 1500)
    SecureZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osvi);
    if (osvi.dwMajorVersion >= 5) {
        ofnsize = sizeof(OPENFILENAME);
    } else {
        ofnsize = OPENFILENAME_SIZE_VERSION_400;
    }
#else
    ofnsize = sizeof(OPENFILENAME) + 12;
#endif
    ofn = g_malloc0(ofnsize);

    ofn->lStructSize = ofnsize;
    ofn->hwndOwner = h_wnd;
#if (_MSC_VER <= 1200)
    ofn->hInstance = (HINSTANCE) GetWindowLong(h_wnd, GWL_HINSTANCE);
#else
    ofn->hInstance = (HINSTANCE) GetWindowLongPtr(h_wnd, GWLP_HINSTANCE);
#endif
    ofn->lpstrFilter = build_file_type_list(TRUE /*save*/, &save_index);
    ofn->lpstrCustomFilter = NULL;
    ofn->nMaxCustFilter = 0;
    ofn->nFilterIndex = save_index;
    ofn->lpstrFile = file_name16;
    ofn->nMaxFile = MAX_PATH;
    ofn->lpstrFileTitle = NULL;
    ofn->nMaxFileTitle = 0;
    ofn->lpstrInitialDir = utf_8to16(get_last_open_dir());
    ofn->lpstrTitle = _T("Wireshark: Save file as");
    ofn->Flags = OFN_ENABLESIZING  | OFN_ENABLETEMPLATE  | OFN_EXPLORER     |
                 OFN_NOCHANGEDIR   | OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY |
                 OFN_PATHMUSTEXIST | OFN_ENABLEHOOK      | OFN_SHOWHELP;
    ofn->lpstrDefExt = NULL;
    ofn->lpfnHook = save_as_file_hook_proc;
    ofn->lpTemplateName = _T("WIRESHARK_SAVEFILENAME_TEMPLATE");

    if (GetSaveFileName(ofn)) {
        filetype = file_type_from_list_index(TRUE /*save*/, ofn->nFilterIndex);

        /* append the default file extension if there's none given by the user */
        /* (we expect a file extension to be at most 5 chars + the dot) */
        file_name8 = g_string_new(utf_16to8(file_name16));
        file_last_dot = strrchr(file_name8->str,'.');
        if(file_last_dot == NULL || strlen(file_name8->str)-(file_last_dot-file_name8->str) > 5+1) {
            if(wtap_file_extension_default_string(filetype) != NULL) {
                file_name8 = g_string_append(file_name8, wtap_file_extension_default_string(filetype));
            }
        }

        g_sf_hwnd = NULL;
        /* Write out the packets (all, or only the ones from the current
           range) to the file with the specified name. */

        /* GetSaveFileName() already asked the user if he wants to overwrite the old file,        */
        /* so if we are here, user already confirmed to overwrite - just delete the old file now. */
        /* Note: Windows ws_unlink cannot delete a currently open file; Therefore the             */
        /*       GetSaveFileName dialog has been coded to prevent doing a 'save as' to the        */
        /*       currently open capture file.                                                     */
        /* XX: Windows Wireshark is built with GLIB >= 2.6 these       */
        /*     days so ws_unlink will properly convert the             */
        /*     UTF8 filename to UTF16 & then do a _wunlink.            */
        /* XX: if the cf_save fails, it will do a GTK simple_dialog()  */
        /*     which is not useful while doing a Windows dialog.       */
        /*     (A GTK dialog box will be generated and basically will  */
        /*     only appear when the redisplayed Windows 'save_as-file' */
        /*     dialog is dismissed. It will then need to be dismissed. */
        /*     This should be fixed even though the cf_save()          */
        /*     presumably should rarely fail in this case.             */
        if ((ws_unlink(file_name8->str) != 0) && (errno == EACCES)) {
            /* XXX: Is MessageBox the best way to pop up an error ? How to make text bold ? */
            gchar *str = g_strdup_printf("Unable to delete file: %s\nPlease choose another name !", file_name8->str);
            MessageBox( NULL, utf_8to16(str), _T("Error"), MB_ICONERROR | MB_APPLMODAL | MB_OK);
            g_free(str);
            goto AGAIN;
        }
        if (cf_save(&cfile, file_name8->str, &g_range, filetype, FALSE) != CF_OK) {
            /* The write failed.  Try again. */
        AGAIN:
            g_string_free(file_name8, TRUE /* free_segment */);
            g_free( (void *) ofn->lpstrFilter);
            g_free( (void *) ofn);
            win32_save_as_file(h_wnd, action_after_save, action_after_save_data);
            return;
        }

        /* Save the directory name for future file dialogs. */
        dirname = get_dirname(file_name8->str);  /* Overwrites cf_name */
        set_last_open_dir(dirname);

        g_string_free(file_name8, TRUE /* free_segment */);

        /* we have finished saving, do we have pending things to do? */
        switch(action_after_save) {
            case(after_save_no_action):
                break;
            case(after_save_open_dialog):
                win32_open_file(h_wnd);
                break;
            case(after_save_open_recent_file):
                menu_open_recent_file_cmd(action_after_save_data);
                break;
            case(after_save_open_dnd_file):
                dnd_open_file_cmd(action_after_save_data);
                break;
            case(after_save_merge_dialog):
                win32_merge_file(h_wnd);
                break;
#ifdef HAVE_LIBPCAP
            case(after_save_capture_dialog):
                capture_start_confirmed();
                break;
#endif
            case(after_save_close_file):
                cf_close(&cfile);
                break;
            case(after_save_exit):
                main_do_quit();
                break;
            default:
                g_assert_not_reached();
        }
    }
    g_sf_hwnd = NULL;
    g_free( (void *) ofn->lpstrFilter);
    g_free( (void *) ofn);
}


void
win32_merge_file (HWND h_wnd) {
    OPENFILENAME *ofn;
    TCHAR       file_name[MAX_PATH] = _T("");
    char       *dirname;
    cf_status_t merge_status = CF_ERROR;
    char       *in_filenames[2];
    int         err;
    char       *tmpname;
    dfilter_t  *dfp;
    int         ofnsize;
#if (_MSC_VER >= 1500)
    OSVERSIONINFO osvi;
#endif

    /* see OPENFILENAME comment in win32_open_file */
#if (_MSC_VER >= 1500)
    SecureZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osvi);
    if (osvi.dwMajorVersion >= 5) {
        ofnsize = sizeof(OPENFILENAME);
    } else {
        ofnsize = OPENFILENAME_SIZE_VERSION_400;
    }
#else
    ofnsize = sizeof(OPENFILENAME) + 12;
#endif
    ofn = g_malloc0(ofnsize);

    ofn->lStructSize = ofnsize;
    ofn->hwndOwner = h_wnd;
#if (_MSC_VER <= 1200)
    ofn->hInstance = (HINSTANCE) GetWindowLong(h_wnd, GWL_HINSTANCE);
#else
    ofn->hInstance = (HINSTANCE) GetWindowLongPtr(h_wnd, GWLP_HINSTANCE);
#endif
    ofn->lpstrFilter = build_file_type_list(FALSE /*!save*/, NULL);
    ofn->lpstrCustomFilter = NULL;
    ofn->nMaxCustFilter = 0;
    ofn->nFilterIndex = FILE_MERGE_DEFAULT;
    ofn->lpstrFile = file_name;
    ofn->nMaxFile = MAX_PATH;
    ofn->lpstrFileTitle = NULL;
    ofn->nMaxFileTitle = 0;
    if (prefs.gui_fileopen_style == FO_STYLE_SPECIFIED && prefs.gui_fileopen_dir[0] != '\0') {
        ofn->lpstrInitialDir = utf_8to16(prefs.gui_fileopen_dir);
    } else {
        ofn->lpstrInitialDir = utf_8to16(get_last_open_dir());
    }
    ofn->lpstrTitle = _T("Wireshark: Merge with capture file");
    ofn->Flags = OFN_ENABLESIZING | OFN_ENABLETEMPLATE | OFN_EXPLORER     |
                 OFN_NOCHANGEDIR  | OFN_FILEMUSTEXIST  | OFN_HIDEREADONLY |
                 OFN_ENABLEHOOK   | OFN_SHOWHELP;
    ofn->lpstrDefExt = NULL;
    ofn->lpfnHook = merge_file_hook_proc;
    ofn->lpTemplateName = _T("WIRESHARK_MERGEFILENAME_TEMPLATE");

    if (GetOpenFileName(ofn)) {
        filetype = cfile.cd_t;
        g_free( (void *) ofn->lpstrFilter);
        g_free( (void *) ofn);

        /* merge or append the two files */

        tmpname = NULL;
        switch (merge_action) {
            case merge_append:
                /* append file */
                in_filenames[0] = cfile.filename;
                in_filenames[1] = utf_16to8(file_name);
                merge_status = cf_merge_files(&tmpname, 2, in_filenames, filetype, TRUE);
                break;
            case merge_chrono:
                /* chonological order */
                in_filenames[0] = cfile.filename;
                in_filenames[1] = utf_16to8(file_name);
                merge_status = cf_merge_files(&tmpname, 2, in_filenames, filetype, FALSE);
                break;
            case merge_prepend:
                /* prepend file */
                in_filenames[0] = utf_16to8(file_name);
                in_filenames[1] = cfile.filename;
                merge_status = cf_merge_files(&tmpname, 2, in_filenames, filetype, TRUE);
                break;
            default:
                g_assert_not_reached();
        }

        if(merge_status != CF_OK) {
            /* merge failed */
            g_free(tmpname);
            return;
        }

        cf_close(&cfile);

        /* Try to open the merged capture file. */
        if (cf_open(&cfile, tmpname, TRUE /* temporary file */, &err) != CF_OK) {
            /* We couldn't open it; don't dismiss the open dialog box,
               just leave it around so that the user can, after they
               dismiss the alert box popped up for the open error,
               try again. */
            return;
        }

        /* apply our filter */
        if (dfilter_compile(dfilter_str, &dfp)) {
            cf_set_rfcode(&cfile, dfp);
        }

        switch (cf_read(&cfile, FALSE)) {
            case CF_READ_OK:
            case CF_READ_ERROR:
                dirname = get_dirname(utf_16to8(file_name));
                set_last_open_dir(dirname);
                menu_name_resolution_changed();
                break;
            case CF_READ_ABORTED:
                break;
        }
    } else {
        g_free( (void *) ofn->lpstrFilter);
        g_free( (void *) ofn);
    }
}

void
win32_export_file(HWND h_wnd, export_type_e export_type) {
    OPENFILENAME     *ofn;
    TCHAR             file_name[MAX_PATH] = _T("");
    char             *dirname;
    cf_print_status_t status;
    int               ofnsize;
#if (_MSC_VER >= 1500)
    OSVERSIONINFO osvi;
#endif

    /* see OPENFILENAME comment in win32_open_file */
#if (_MSC_VER >= 1500)
    SecureZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osvi);
    if (osvi.dwMajorVersion >= 5) {
        ofnsize = sizeof(OPENFILENAME);
    } else {
        ofnsize = OPENFILENAME_SIZE_VERSION_400;
    }
#else
    ofnsize = sizeof(OPENFILENAME) + 12;
#endif
    ofn = g_malloc0(ofnsize);

    ofn->lStructSize = ofnsize;
    ofn->hwndOwner = h_wnd;
#if (_MSC_VER <= 1200)
    ofn->hInstance = (HINSTANCE) GetWindowLong(h_wnd, GWL_HINSTANCE);
#else
    ofn->hInstance = (HINSTANCE) GetWindowLongPtr(h_wnd, GWLP_HINSTANCE);
#endif
    ofn->lpstrFilter = FILE_TYPES_EXPORT;
    ofn->lpstrCustomFilter = NULL;
    ofn->nMaxCustFilter = 0;
    ofn->nFilterIndex = export_type;
    ofn->lpstrFile = file_name;
    ofn->nMaxFile = MAX_PATH;
    ofn->lpstrFileTitle = NULL;
    ofn->nMaxFileTitle = 0;
    ofn->lpstrInitialDir = utf_8to16(get_last_open_dir());
    ofn->lpstrTitle = _T("Wireshark: Export File");
    ofn->Flags = OFN_ENABLESIZING  | OFN_ENABLETEMPLATE  | OFN_EXPLORER     |
                 OFN_NOCHANGEDIR   | OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY |
                 OFN_PATHMUSTEXIST | OFN_ENABLEHOOK      | OFN_SHOWHELP;
    ofn->lpstrDefExt = NULL;
    ofn->lpfnHook = export_file_hook_proc;
    ofn->lpTemplateName = _T("WIRESHARK_EXPORTFILENAME_TEMPLATE");

    /* Fill in our print (and export) args */

    print_args.format              = PR_FMT_TEXT;
    print_args.to_file             = TRUE;
    print_args.cmd                 = NULL;
    print_args.print_summary       = TRUE;
    print_args.print_dissections   = print_dissections_as_displayed;
    print_args.print_hex           = FALSE;
    print_args.print_formfeed      = FALSE;

    if (GetSaveFileName(ofn)) {
        print_args.file = utf_16to8(file_name);
        switch (ofn->nFilterIndex) {
            case export_type_text:      /* Text */
                print_args.stream = print_stream_text_new(TRUE, print_args.file);
                if (print_args.stream == NULL) {
                    open_failure_alert_box(print_args.file, errno, TRUE);
                    g_free( (void *) ofn);
                    return;
                }
                status = cf_print_packets(&cfile, &print_args);
                break;
            case export_type_ps:        /* PostScript (r) */
                print_args.stream = print_stream_ps_new(TRUE, print_args.file);
                if (print_args.stream == NULL) {
                    open_failure_alert_box(print_args.file, errno, TRUE);
                    g_free( (void *) ofn);
                    return;
                }
                status = cf_print_packets(&cfile, &print_args);
                break;
            case export_type_csv:       /* CSV */
                status = cf_write_csv_packets(&cfile, &print_args);
                break;
            case export_type_carrays:   /* C Arrays */
                status = cf_write_carrays_packets(&cfile, &print_args);
                break;
            case export_type_psml:      /* PSML */
                status = cf_write_psml_packets(&cfile, &print_args);
                break;
            case export_type_pdml:      /* PDML */
                status = cf_write_pdml_packets(&cfile, &print_args);
                break;
            default:
                g_free( (void *) ofn);
                return;
        }

        switch (status) {
            case CF_PRINT_OK:
                break;
            case CF_PRINT_OPEN_ERROR:
                open_failure_alert_box(print_args.file, errno, TRUE);
                break;
            case CF_PRINT_WRITE_ERROR:
                write_failure_alert_box(print_args.file, errno);
                break;
        }
        /* Save the directory name for future file dialogs. */
        dirname = get_dirname(utf_16to8(file_name));  /* Overwrites cf_name */
        set_last_open_dir(dirname);
    }

    g_free( (void *) ofn);
}

void
win32_export_raw_file(HWND h_wnd) {
    OPENFILENAME *ofn;
    TCHAR         file_name[MAX_PATH] = _T("");
    char         *dirname;
    const guint8 *data_p;
    char         *file_name8;
    int           fd;
    int           ofnsize;
#if (_MSC_VER >= 1500)
    OSVERSIONINFO osvi;
#endif

    if (!cfile.finfo_selected) {
        /* This shouldn't happen */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "No bytes were selected.");
        return;
    }

    /* see OPENFILENAME comment in win32_open_file */
#if (_MSC_VER >= 1500)
    SecureZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osvi);
    if (osvi.dwMajorVersion >= 5) {
        ofnsize = sizeof(OPENFILENAME);
    } else {
        ofnsize = OPENFILENAME_SIZE_VERSION_400;
    }
#else
    ofnsize = sizeof(OPENFILENAME) + 12;
#endif
    ofn = g_malloc0(ofnsize);

    ofn->lStructSize = ofnsize;
    ofn->hwndOwner = h_wnd;
#if (_MSC_VER <= 1200)
    ofn->hInstance = (HINSTANCE) GetWindowLong(h_wnd, GWL_HINSTANCE);
#else
    ofn->hInstance = (HINSTANCE) GetWindowLongPtr(h_wnd, GWLP_HINSTANCE);
#endif
    ofn->lpstrFilter = FILE_TYPES_RAW;
    ofn->lpstrCustomFilter = NULL;
    ofn->nMaxCustFilter = 0;
    ofn->nFilterIndex = FILE_RAW_DEFAULT;
    ofn->lpstrFile = file_name;
    ofn->nMaxFile = MAX_PATH;
    ofn->lpstrFileTitle = NULL;
    ofn->nMaxFileTitle = 0;
    ofn->lpstrInitialDir = utf_8to16(get_last_open_dir());
    ofn->lpstrTitle = _T("Wireshark: Export Raw Data");
    ofn->Flags = OFN_ENABLESIZING  | OFN_ENABLETEMPLATE  | OFN_EXPLORER     |
                 OFN_NOCHANGEDIR   | OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY |
                 OFN_PATHMUSTEXIST | OFN_ENABLEHOOK      | OFN_SHOWHELP;
    ofn->lpstrDefExt = NULL;
    ofn->lCustData = cfile.finfo_selected->length;
    ofn->lpfnHook = export_raw_file_hook_proc;
    ofn->lpTemplateName = _T("WIRESHARK_EXPORTRAWFILENAME_TEMPLATE");

    /*
     * XXX - The GTK+ code uses get_byte_view_data_and_length().  We just
     * grab the info from cfile.finfo_selected.  Which is more "correct"?
     */

    if (GetSaveFileName(ofn)) {
        g_free( (void *) ofn);
        file_name8 = utf_16to8(file_name);
        data_p = tvb_get_ptr(cfile.finfo_selected->ds_tvb, 0, -1) +
                cfile.finfo_selected->start;
        fd = ws_open(file_name8, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 0666);
        if (fd == -1) {
            open_failure_alert_box(file_name8, errno, TRUE);
            return;
        }
        if (write(fd, data_p, cfile.finfo_selected->length) < 0) {
            write_failure_alert_box(file_name8, errno);
            close(fd);
            return;
        }
        if (close(fd) < 0) {
            write_failure_alert_box(file_name8, errno);
            return;
        }

        /* Save the directory name for future file dialogs. */
        dirname = get_dirname(file_name8);  /* Overwrites cf_name */
        set_last_open_dir(dirname);
    } else {
        g_free( (void *) ofn);
    }
}

void
win32_export_sslkeys_file(HWND h_wnd) {
    OPENFILENAME *ofn;
    TCHAR         file_name[MAX_PATH] = _T("");
    char         *dirname;
    StringInfo   *keylist;
    char         *file_name8;
    int           fd;
    int           ofnsize;
    int           keylist_size;
#if (_MSC_VER >= 1500)
    OSVERSIONINFO osvi;
#endif

    keylist_size = g_hash_table_size(ssl_session_hash);
    if (keylist_size==0) {
        /* This shouldn't happen */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "No SSL Session Keys to export.");
        return;
    }

    /* see OPENFILENAME comment in win32_open_file */
#if (_MSC_VER >= 1500)
    SecureZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osvi);
    if (osvi.dwMajorVersion >= 5) {
        ofnsize = sizeof(OPENFILENAME);
    } else {
        ofnsize = OPENFILENAME_SIZE_VERSION_400;
    }
#else
    ofnsize = sizeof(OPENFILENAME) + 12;
#endif
    ofn = g_malloc0(ofnsize);

    ofn->lStructSize = ofnsize;
    ofn->hwndOwner = h_wnd;
#if (_MSC_VER <= 1200)
    ofn->hInstance = (HINSTANCE) GetWindowLong(h_wnd, GWL_HINSTANCE);
#else
    ofn->hInstance = (HINSTANCE) GetWindowLongPtr(h_wnd, GWLP_HINSTANCE);
#endif
    ofn->lpstrFilter = FILE_TYPES_SSLKEYS;
    ofn->lpstrCustomFilter = NULL;
    ofn->nMaxCustFilter = 0;
    ofn->nFilterIndex = FILE_SSLKEYS_DEFAULT;
    ofn->lpstrFile = file_name;
    ofn->nMaxFile = MAX_PATH;
    ofn->lpstrFileTitle = NULL;
    ofn->nMaxFileTitle = 0;
    ofn->lpstrInitialDir = utf_8to16(get_last_open_dir());
    ofn->lpstrTitle = _T("Wireshark: Export SSL Session Keys");
    ofn->Flags = OFN_ENABLESIZING  | OFN_ENABLETEMPLATE  | OFN_EXPLORER     |
                 OFN_NOCHANGEDIR   | OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY |
                 OFN_PATHMUSTEXIST | OFN_ENABLEHOOK      | OFN_SHOWHELP;
    ofn->lpstrDefExt = NULL;
    ofn->lCustData = keylist_size;
    ofn->lpfnHook = export_sslkeys_file_hook_proc;
    ofn->lpTemplateName = _T("WIRESHARK_EXPORTSSLKEYSFILENAME_TEMPLATE");

    if (GetSaveFileName(ofn)) {
        g_free( (void *) ofn);
        file_name8 = utf_16to8(file_name);
        keylist = ssl_export_sessions(ssl_session_hash);
        fd = ws_open(file_name8, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 0666);
        if (fd == -1) {
            open_failure_alert_box(file_name8, errno, TRUE);
            g_free(keylist);
            return;
        }
        /*
         * Thanks, Microsoft, for not using size_t for the third argument to
         * _write().  Presumably this string will be <= 4GiB long....
         */
        if (ws_write(fd, keylist->data, (unsigned int)strlen(keylist->data)) < 0) {
            write_failure_alert_box(file_name8, errno);
            ws_close(fd);
            g_free(keylist);
            return;
        }
        if (ws_close(fd) < 0) {
            write_failure_alert_box(file_name8, errno);
            g_free(keylist);
            return;
        }

        /* Save the directory name for future file dialogs. */
        dirname = get_dirname(file_name8);  /* Overwrites cf_name */
        set_last_open_dir(dirname);
    } else {
        g_free( (void *) ofn);
    }
    g_free(keylist);
}

void
win32_export_color_file(HWND h_wnd, gpointer filter_list) {
    OPENFILENAME *ofn;
    TCHAR  file_name[MAX_PATH] = _T("");
    gchar *dirname;
    int    ofnsize;
#if (_MSC_VER >= 1500)
    OSVERSIONINFO osvi;
#endif

    /* see OPENFILENAME comment in win32_open_file */
#if (_MSC_VER >= 1500)
    SecureZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osvi);
    if (osvi.dwMajorVersion >= 5) {
        ofnsize = sizeof(OPENFILENAME);
    } else {
        ofnsize = OPENFILENAME_SIZE_VERSION_400;
    }
#else
    ofnsize = sizeof(OPENFILENAME) + 12;
#endif
    ofn = g_malloc0(ofnsize);

    ofn->lStructSize = ofnsize;
    ofn->hwndOwner = h_wnd;
#if (_MSC_VER <= 1200)
    ofn->hInstance = (HINSTANCE) GetWindowLong(h_wnd, GWL_HINSTANCE);
#else
    ofn->hInstance = (HINSTANCE) GetWindowLongPtr(h_wnd, GWLP_HINSTANCE);
#endif
    ofn->lpstrFilter = FILE_TYPES_COLOR;
    ofn->lpstrCustomFilter = NULL;
    ofn->nMaxCustFilter = 0;
    ofn->nFilterIndex = FILE_DEFAULT_COLOR;
    ofn->lpstrFile = file_name;
    ofn->nMaxFile = MAX_PATH;
    ofn->lpstrFileTitle = NULL;
    ofn->nMaxFileTitle = 0;
    ofn->lpstrInitialDir = utf_8to16(get_last_open_dir());
    ofn->lpstrTitle = _T("Wireshark: Export Color Filters");
    ofn->Flags = OFN_ENABLESIZING  | OFN_EXPLORER        |
                 OFN_NOCHANGEDIR   | OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY |
                 OFN_PATHMUSTEXIST | OFN_ENABLEHOOK;
    ofn->lpstrDefExt = NULL;
    ofn->lpfnHook = NULL;
    ofn->lpTemplateName = NULL;

    filetype = cfile.cd_t;

    /* XXX - Support marked filters */
    if (GetSaveFileName(ofn)) {
        g_free( (void *) ofn);
        if (!color_filters_export(utf_16to8(file_name), filter_list, FALSE /* all filters */))
            return;

        /* Save the directory name for future file dialogs. */
        dirname = get_dirname(utf_16to8(file_name));  /* Overwrites cf_name */
        set_last_open_dir(dirname);
    } else {
        g_free( (void *) ofn);
    }
}

void
win32_import_color_file(HWND h_wnd, gpointer color_filters) {
    OPENFILENAME *ofn;
    TCHAR  file_name[MAX_PATH] = _T("");
    gchar *dirname;
    int    ofnsize;
#if (_MSC_VER >= 1500)
    OSVERSIONINFO osvi;
#endif

    /* see OPENFILENAME comment in win32_open_file */
#if (_MSC_VER >= 1500)
    SecureZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osvi);
    if (osvi.dwMajorVersion >= 5) {
        ofnsize = sizeof(OPENFILENAME);
    } else {
        ofnsize = OPENFILENAME_SIZE_VERSION_400;
    }
#else
    ofnsize = sizeof(OPENFILENAME) + 12;
#endif
    ofn = g_malloc0(ofnsize);

    ofn->lStructSize = ofnsize;
    ofn->hwndOwner = h_wnd;
#if (_MSC_VER <= 1200)
    ofn->hInstance = (HINSTANCE) GetWindowLong(h_wnd, GWL_HINSTANCE);
#else
    ofn->hInstance = (HINSTANCE) GetWindowLongPtr(h_wnd, GWLP_HINSTANCE);
#endif
    ofn->lpstrFilter = FILE_TYPES_COLOR;
    ofn->lpstrCustomFilter = NULL;
    ofn->nMaxCustFilter = 0;
    ofn->nFilterIndex = FILE_DEFAULT_COLOR;
    ofn->lpstrFile = file_name;
    ofn->nMaxFile = MAX_PATH;
    ofn->lpstrFileTitle = NULL;
    ofn->nMaxFileTitle = 0;
    ofn->lpstrInitialDir = utf_8to16(get_last_open_dir());
    ofn->lpstrTitle = _T("Wireshark: Import Color Filters");
    ofn->Flags = OFN_ENABLESIZING  | OFN_EXPLORER        |
                 OFN_NOCHANGEDIR   | OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY |
                 OFN_PATHMUSTEXIST | OFN_ENABLEHOOK;
    ofn->lpstrDefExt = NULL;
    ofn->lpfnHook = NULL;
    ofn->lpTemplateName = NULL;

    /* XXX - Support export limited to selected filters */
    if (GetOpenFileName(ofn)) {
        g_free( (void *) ofn);
        if (!color_filters_import(utf_16to8(file_name), color_filters))
            return;

        /* Save the directory name for future file dialogs. */
        dirname = get_dirname(utf_16to8(file_name));  /* Overwrites cf_name */
        set_last_open_dir(dirname);
    } else {
        g_free( (void *) ofn);
    }
}


/*
 * Private routines
 */

/** Given a print_args_t struct, update a set of print/export format controls
 *  accordingly.
 *
 * @param dlg_hwnd HWND of the dialog in question.
 * @param args Pointer to a print args struct.
 */
static void
print_update_dynamic(HWND dlg_hwnd, print_args_t *args) {
    HWND cur_ctrl;

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_PKT_SUMMARY_CB);
    if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED)
        args->print_summary = TRUE;
    else
        args->print_summary = FALSE;

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_PKT_DETAIL_CB);
    if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED) {
        cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_PKT_DETAIL_COMBO);
        switch (SendMessage(cur_ctrl, CB_GETCURSEL, 0, 0)) {
            case 0:
                args->print_dissections = print_dissections_collapsed;
                break;
            case 1:
                args->print_dissections = print_dissections_as_displayed;
                break;
            case 2:
                args->print_dissections = print_dissections_expanded;
                break;
            default:
                g_assert_not_reached();
        }
        EnableWindow(cur_ctrl, TRUE);
    } else {
        args->print_dissections = print_dissections_none;
        cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_PKT_DETAIL_COMBO);
        EnableWindow(cur_ctrl, FALSE);
    }

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_PKT_BYTES_CB);
    if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED)
        args->print_hex = TRUE;
    else
        args->print_hex = FALSE;

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_PKT_NEW_PAGE_CB);
    if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED)
        args->print_formfeed = TRUE;
    else
        args->print_formfeed = FALSE;
}

static void
format_handle_wm_initdialog(HWND dlg_hwnd, print_args_t *args) {
    HWND cur_ctrl;

    /* Set the "Packet summary" box */
    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_PKT_SUMMARY_CB);
    SendMessage(cur_ctrl, BM_SETCHECK, args->print_summary, 0);

    /* Set the "Packet details" box */
    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_PKT_DETAIL_CB);
    SendMessage(cur_ctrl, BM_SETCHECK, args->print_dissections != print_dissections_none, 0);

    /* Set the "Packet details" combo */
    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_PKT_DETAIL_COMBO);
    SendMessage(cur_ctrl, CB_ADDSTRING, 0, (WPARAM) _T("All collapsed"));
    SendMessage(cur_ctrl, CB_ADDSTRING, 0, (WPARAM) _T("As displayed"));
    SendMessage(cur_ctrl, CB_ADDSTRING, 0, (WPARAM) _T("All expanded"));

    switch (args->print_dissections) {
        case print_dissections_none:
        case print_dissections_collapsed:
            SendMessage(cur_ctrl, CB_SETCURSEL, 0, 0);
            break;
        case print_dissections_as_displayed:
            SendMessage(cur_ctrl, CB_SETCURSEL, 1, 0);
            break;
        case print_dissections_expanded:
            SendMessage(cur_ctrl, CB_SETCURSEL, 2, 0);
        default:
            g_assert_not_reached();
    }

    /* Set the "Packet bytes" box */
    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_PKT_BYTES_CB);
    SendMessage(cur_ctrl, BM_SETCHECK, args->print_hex, 0);

    /* Set the "Each packet on a new page" box */
    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_PKT_NEW_PAGE_CB);
    SendMessage(cur_ctrl, BM_SETCHECK, args->print_formfeed, 0);

    print_update_dynamic(dlg_hwnd, args);
}


#define PREVIEW_STR_MAX      200

/* If preview_file is NULL, disable the elements.  If not, enable and
 * show the preview info. */
static gboolean
preview_set_filename(HWND of_hwnd, gchar *preview_file) {
    HWND        cur_ctrl;
    int         i;
    gboolean    enable = FALSE;
    wtap       *wth;
    const struct wtap_pkthdr *phdr;
    int         err = 0;
    gchar      *err_info;
    TCHAR       string_buff[PREVIEW_STR_MAX];
    gint64      data_offset;
    guint       packet = 0;
    gint64      filesize;
    time_t      ti_time;
    struct tm  *ti_tm;
    guint       elapsed_time;
    time_t      time_preview;
    time_t      time_current;
    double      start_time = 0;
    double      stop_time = 0;
    double      cur_time;
    gboolean    is_breaked = FALSE;

    if (preview_file != NULL && strlen(preview_file) > 0) {
        enable = TRUE;
    }

    for (i = EWFD_PT_FILENAME; i <= EWFD_PTX_ELAPSED; i++) {
        cur_ctrl = GetDlgItem(of_hwnd, i);
        if (cur_ctrl) {
            EnableWindow(cur_ctrl, enable);
        }
    }

    for (i = EWFD_PTX_FILENAME; i <= EWFD_PTX_ELAPSED; i++) {
        cur_ctrl = GetDlgItem(of_hwnd, i);
        if (cur_ctrl) {
            SetWindowText(cur_ctrl, _T("-"));
        }
    }

    if (enable) {
        cur_ctrl = GetDlgItem(of_hwnd, EWFD_PTX_FILENAME);
        SetWindowText(cur_ctrl, utf_8to16(get_basename(preview_file)));

        cur_ctrl = GetDlgItem(of_hwnd, EWFD_PTX_FORMAT);
        wth = wtap_open_offline(preview_file, &err, &err_info, TRUE);
        if (cur_ctrl && wth == NULL) {
            if(err == WTAP_ERR_FILE_UNKNOWN_FORMAT) {
                SetWindowText(cur_ctrl, _T("unknown file format"));
            } else {
                SetWindowText(cur_ctrl, _T("error opening file"));
            }
            return FALSE;
        }

        /* size */
        filesize = wtap_file_size(wth, &err);
        utf_8to16_snprintf(string_buff, PREVIEW_STR_MAX, "%" G_GINT64_FORMAT " bytes", filesize);
        cur_ctrl = GetDlgItem(of_hwnd, EWFD_PTX_SIZE);
        SetWindowText(cur_ctrl, string_buff);

        /* type */
        cur_ctrl = GetDlgItem(of_hwnd, EWFD_PTX_FORMAT);
        SetWindowText(cur_ctrl, utf_8to16(wtap_file_type_string(wtap_file_type(wth))));

        time(&time_preview);
        while ( (wtap_read(wth, &err, &err_info, &data_offset)) ) {
            phdr = wtap_phdr(wth);
            cur_time = nstime_to_sec( (const nstime_t *) &phdr->ts );
            if(packet == 0) {
                start_time  = cur_time;
                stop_time = cur_time;
            }
            if (cur_time < start_time) {
                start_time = cur_time;
            }
            if (cur_time > stop_time){
                stop_time = cur_time;
            }
            packet++;
            if(packet%100 == 0) {
                time(&time_current);
                if(time_current-time_preview >= (time_t) prefs.gui_fileopen_preview) {
                    is_breaked = TRUE;
                    break;
                }
            }
        }

        if(err != 0) {
            _snwprintf(string_buff, PREVIEW_STR_MAX, _T("error after reading %u packets"), packet);
            cur_ctrl = GetDlgItem(of_hwnd, EWFD_PTX_PACKETS);
            SetWindowText(cur_ctrl, string_buff);
            wtap_close(wth);
            return TRUE;
        }

        /* packet count */
        if(is_breaked) {
            _snwprintf(string_buff, PREVIEW_STR_MAX, _T("more than %u packets (preview timeout)"), packet);
        } else {
            _snwprintf(string_buff, PREVIEW_STR_MAX, _T("%u"), packet);
        }
        cur_ctrl = GetDlgItem(of_hwnd, EWFD_PTX_PACKETS);
        SetWindowText(cur_ctrl, string_buff);

        /* first packet */
        ti_time = (long)start_time;
        ti_tm = localtime( &ti_time );
        if(ti_tm) {
            _snwprintf(string_buff, PREVIEW_STR_MAX,
                     _T("%04d-%02d-%02d %02d:%02d:%02d"),
                     ti_tm->tm_year + 1900,
                     ti_tm->tm_mon + 1,
                     ti_tm->tm_mday,
                     ti_tm->tm_hour,
                     ti_tm->tm_min,
                     ti_tm->tm_sec);
        } else {
            _snwprintf(string_buff, PREVIEW_STR_MAX, _T("?"));
        }
        cur_ctrl = GetDlgItem(of_hwnd, EWFD_PTX_FIRST_PKT);
        SetWindowText(cur_ctrl, string_buff);

        /* elapsed time */
        elapsed_time = (unsigned int)(stop_time-start_time);
        if(elapsed_time/86400) {
            _snwprintf(string_buff, PREVIEW_STR_MAX, _T("%02u days %02u:%02u:%02u"),
            elapsed_time/86400, elapsed_time%86400/3600, elapsed_time%3600/60, elapsed_time%60);
        } else {
            _snwprintf(string_buff, PREVIEW_STR_MAX, _T("%02u:%02u:%02u"),
            elapsed_time%86400/3600, elapsed_time%3600/60, elapsed_time%60);
        }
        if(is_breaked) {
            _snwprintf(string_buff, PREVIEW_STR_MAX, _T("unknown"));
        }
        cur_ctrl = GetDlgItem(of_hwnd, EWFD_PTX_ELAPSED);
        SetWindowText(cur_ctrl, string_buff);

        wtap_close(wth);
    }

    return TRUE;

}


static char *
filter_tb_get(HWND hwnd) {
    TCHAR     *strval = NULL;
    gint       len;
    char *ret;

    /* If filter_text is non-NULL, use it.  Otherwise, grab the text from
     * the window */
    len = GetWindowTextLength(hwnd);
    if (len > 0) {
        len++;
        strval = g_malloc(len*sizeof(TCHAR));
        len = GetWindowText(hwnd, strval, len);
        ret = g_utf16_to_utf8(strval, -1, NULL, NULL, NULL);
        g_free(strval);
        return ret;
    } else {
        return NULL;
    }
}


/* XXX - Copied from "filter-util.c" in the wireshark-win32 branch */
/* XXX - The only reason for the "filter_text" parameter is to be able to feed
 * in the "real" filter string in the case of a CBN_SELCHANGE notification message.
 */
static void
filter_tb_syntax_check(HWND hwnd, TCHAR *filter_text) {
    TCHAR     *strval = NULL;
    gint       len;
    dfilter_t *dfp;

    /* If filter_text is non-NULL, use it.  Otherwise, grab the text from
     * the window */
    if (filter_text) {
        len = (lstrlen(filter_text) + 1) * sizeof(TCHAR);
        strval = g_malloc(len);
        memcpy(strval, filter_text, len);
    } else {
        len = GetWindowTextLength(hwnd);
        if (len > 0) {
            len++;
            strval = g_malloc(len*sizeof(TCHAR));
            len = GetWindowText(hwnd, strval, len);
        }
    }

    if (len == 0) {
        /* Default window background */
        SendMessage(hwnd, EM_SETBKGNDCOLOR, (WPARAM) 1, COLOR_WINDOW);
        return;
    } else if (dfilter_compile(utf_16to8(strval), &dfp)) { /* colorize filter string entry */
        if (dfp != NULL)
            dfilter_free(dfp);
        /* Valid (light green) */
        SendMessage(hwnd, EM_SETBKGNDCOLOR, 0, 0x00afffaf);
    } else {
        /* Invalid (light red) */
        SendMessage(hwnd, EM_SETBKGNDCOLOR, 0, 0x00afafff);
    }

    if (strval) g_free(strval);
}


#if (_MSC_VER <= 1200)
static UINT CALLBACK
#else
static UINT_PTR CALLBACK
#endif
open_file_hook_proc(HWND of_hwnd, UINT msg, WPARAM w_param, LPARAM l_param) {
    HWND      cur_ctrl, parent;
    OFNOTIFY *notify = (OFNOTIFY *) l_param;
    TCHAR     sel_name[MAX_PATH];

    switch(msg) {
        case WM_INITDIALOG:
            /* Retain the filter text, and fill it in. */
            if(dfilter_str != NULL) {
                cur_ctrl = GetDlgItem(of_hwnd, EWFD_FILTER_EDIT);
                SetWindowText(cur_ctrl, utf_8to16(dfilter_str));
            }

            /* Fill in our resolution values */
            cur_ctrl = GetDlgItem(of_hwnd, EWFD_MAC_NR_CB);
            SendMessage(cur_ctrl, BM_SETCHECK, gbl_resolv_flags & RESOLV_MAC, 0);
            cur_ctrl = GetDlgItem(of_hwnd, EWFD_NET_NR_CB);
            SendMessage(cur_ctrl, BM_SETCHECK, gbl_resolv_flags & RESOLV_NETWORK, 0);
            cur_ctrl = GetDlgItem(of_hwnd, EWFD_TRANS_NR_CB);
            SendMessage(cur_ctrl, BM_SETCHECK, gbl_resolv_flags & RESOLV_TRANSPORT, 0);

            preview_set_filename(of_hwnd, NULL);
            break;
        case WM_NOTIFY:
            switch (notify->hdr.code) {
                case CDN_FILEOK:
                    /* Fetch the read filter */
                    cur_ctrl = GetDlgItem(of_hwnd, EWFD_FILTER_EDIT);
                    if (dfilter_str)
                        g_free(dfilter_str);
                    dfilter_str = filter_tb_get(cur_ctrl);

                    /* Fetch our resolution values */
                    gbl_resolv_flags = prefs.name_resolve & RESOLV_CONCURRENT;
                    cur_ctrl = GetDlgItem(of_hwnd, EWFD_MAC_NR_CB);
                    if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED)
                        gbl_resolv_flags |= RESOLV_MAC;
                    cur_ctrl = GetDlgItem(of_hwnd, EWFD_NET_NR_CB);
                    if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED)
                        gbl_resolv_flags |= RESOLV_NETWORK;
                    cur_ctrl = GetDlgItem(of_hwnd, EWFD_TRANS_NR_CB);
                    if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED)
                        gbl_resolv_flags |= RESOLV_TRANSPORT;
                    break;
                case CDN_SELCHANGE:
                    /* This _almost_ works correctly. We need to handle directory
                       selections, etc. */
                    parent = GetParent(of_hwnd);
                    CommDlg_OpenSave_GetSpec(parent, sel_name, MAX_PATH);
                    preview_set_filename(of_hwnd, utf_16to8(sel_name));
                    break;
                case CDN_HELP:
                    topic_cb(NULL, HELP_OPEN_WIN32_DIALOG);
                    break;
                default:
                    break;
            }
            break;
        case WM_COMMAND:
            cur_ctrl = (HWND) l_param;
            switch(w_param) {
                case (EN_UPDATE << 16) | EWFD_FILTER_EDIT:
                    filter_tb_syntax_check(cur_ctrl, NULL);
                    break;
                    /*
                     * If we ever figure out a way to integrate the Windows
                     * and GTK+ event loops (or make a native filter dialog),
                     * we can re-enable the "Filter" button.
                     */
                    /*
                case EWFD_FILTER_BTN:
                    break;
                     */
                default:
                    break;
            }
            break;
        default:
            break;
    }
    return 0;
}

/* XXX - Copied verbatim from ui/gtk/capture_file_dlg.c.  Perhaps it
 * should be in wiretap instead?
 */

static gboolean
can_save_with_wiretap(int ft)
{
    /* To save a file with Wiretap, Wiretap has to handle that format,
     and its code to handle that format must be able to write a file
     with this file's encapsulation type. */
    return wtap_dump_can_open(ft) && wtap_dump_can_write_encap(ft, cfile.lnk_t);
}

/* Generate a list of the file types we can save this file as.

   "filetype" is the type it has now.

   "encap" is the encapsulation for its packets (which could be
   "unknown" or "per-packet").

   "filtered" is TRUE if we're to save only the packets that passed
   the display filter (in which case we have to save it using Wiretap)
   and FALSE if we're to save the entire file (in which case, if we're
   saving it in the type it has already, we can just copy it).

   The same applies for sel_curr, sel_all, sel_m_only, sel_m_range and sel_man_range
*/

static int
file_type_from_list_index(gboolean save, int index) {
    int   ft;
    int curr_index;

    /* Check all file types. */
    curr_index = 0;
    for (ft = 0; ft < WTAP_NUM_FILE_TYPES; ft++) {
        if (save && (!packet_range_process_all(&g_range) || ft != cfile.cd_t)) {
            /* not all unfiltered packets or a different file type.  We have to use Wiretap. */
            if (!can_save_with_wiretap(ft))
                continue;       /* We can't. */
        }

        /* OK, we can write it out in this type. */
        if(wtap_file_type_string(ft) == NULL) {
            continue;
        }

        curr_index++;
        if(curr_index == index) {
            return ft;
        }
    }

    return -1;
}


static TCHAR *
build_file_type_list(gboolean save, int *item_to_select) {
    int   ft;
    guint index;
    GString* pattern_str = g_string_new("");
    GString* description_str = g_string_new("");
    gchar sep;
    GSList *extensions_list, *extension;
    TCHAR *str16;
    GArray* sa = g_array_new(FALSE /*zero_terminated*/, FALSE /*clear_*/,2 /*element_size*/);
    guint16 zero = 0;


    /* Default to the first supported file type, if the file's current
       type isn't supported. */
    if(item_to_select) {
        if(save) {
            *item_to_select = FILE_SAVE_DEFAULT;
        } else {
            *item_to_select = FILE_OPEN_DEFAULT;
        }
    }

    /* append the "All Files" entry */
    if (!save) {
        str16 = utf_8to16("All Files (*.*)");
        sa = g_array_append_vals(sa, str16, (guint) strlen("All Files (*.*)"));
        sa = g_array_append_val(sa, zero);
        str16 = utf_8to16("*.*");
        sa = g_array_append_vals(sa, str16, (guint) strlen("*.*"));
        sa = g_array_append_val(sa, zero);
    }

    /* Check all file types. */
    index = 1;  /* the index is one based! */
    for (ft = 0; ft < WTAP_NUM_FILE_TYPES; ft++) {
        if (save && (!packet_range_process_all(&g_range) || ft != cfile.cd_t)) {
            /* not all unfiltered packets or a different file type.  We have to use Wiretap. */
            if (!can_save_with_wiretap(ft))
                continue;       /* We can't. */
        }

        /* OK, we can write it out in this type. */
        if(wtap_file_type_string(ft) == NULL)
            continue;
        extensions_list = wtap_get_file_extensions_list(ft);
        if (extensions_list == NULL)
            continue;

        /* Construct the list of patterns. */
        g_string_printf(pattern_str, "");
        sep = '\0';
        for (extension = extensions_list; extension != NULL;
             extension = g_slist_next(extension)) {
            if (sep != '\0')
                g_string_append_c(pattern_str, sep);
            g_string_append_printf(pattern_str, "%c*.%s", sep, (char *)extension->data);
            sep = ';';
        }

        /* Construct the description. */
        g_string_printf(description_str, "%s", wtap_file_type_string(ft));
        str16 = utf_8to16(description_str->str);
        sa = g_array_append_vals(sa, str16, (guint) strlen(description_str->str));
        sa = g_array_append_val(sa, zero);

        str16 = utf_8to16(pattern_str->str);
        sa = g_array_append_vals(sa, str16, (guint) strlen(pattern_str->str));
        sa = g_array_append_val(sa, zero);

        wtap_free_file_extensions_list(extensions_list);

        if (ft == cfile.cd_t && item_to_select != NULL) {
            /* Default to the same format as the file, if it's supported. */
            *item_to_select = index;
        }
        index++;
    }
    g_string_free(pattern_str);
    g_string_free(description_str);

    /* terminate the array */
    sa = g_array_append_val(sa, zero);

    return (TCHAR *) g_array_free(sa, FALSE /*free_segment*/);
}


#if 0
static void
build_file_format_list(HWND sf_hwnd) {
    HWND  format_cb;
    int   ft;
    guint index;
    guint item_to_select;
    gchar *s;

    /* Default to the first supported file type, if the file's current
       type isn't supported. */
    item_to_select = 0;

    format_cb = GetDlgItem(sf_hwnd, EWFD_FILE_TYPE_COMBO);
    SendMessage(format_cb, CB_RESETCONTENT, 0, 0);

    /* Check all file types. */
    index = 0;
    for (ft = 0; ft < WTAP_NUM_FILE_TYPES; ft++) {
        if (!packet_range_process_all(&g_range) || ft != cfile.cd_t) {
            /* not all unfiltered packets or a different file type.  We have to use Wiretap. */
            if (!can_save_with_wiretap(ft))
                continue;       /* We can't. */
        }

        /* OK, we can write it out in this type. */
        if(wtap_file_extensions_string(ft) != NULL) {
            s = g_strdup_printf("%s (%s)", wtap_file_type_string(ft), wtap_file_extensions_string(ft));
        } else {
            s = g_strdup_printf("%s (*.*)", wtap_file_type_string(ft));
        }
        SendMessage(format_cb, CB_ADDSTRING, 0, (LPARAM) utf_8to16(s));
        g_free(s);
        SendMessage(format_cb, CB_SETITEMDATA, (LPARAM) index, (WPARAM) ft);
        if (ft == filetype) {
            /* Default to the same format as the file, if it's supported. */
            item_to_select = index;
        }
        index++;
    }

    SendMessage(format_cb, CB_SETCURSEL, (WPARAM) item_to_select, 0);
}
#endif

#define RANGE_TEXT_MAX 128
#if (_MSC_VER <= 1200)
static UINT CALLBACK
#else
static UINT_PTR CALLBACK
#endif
save_as_file_hook_proc(HWND sf_hwnd, UINT msg, WPARAM w_param, LPARAM l_param) {
    HWND           cur_ctrl;
    OFNOTIFY      *notify = (OFNOTIFY *) l_param;
    /*int            new_filetype, index;*/

    switch(msg) {
        case WM_INITDIALOG:
            g_sf_hwnd = sf_hwnd;

            /* Default to saving all packets, in the file's current format. */
            filetype = cfile.cd_t;

            /* init the packet range */
            packet_range_init(&g_range);
            /* default to displayed packets */
            g_range.process_filtered   = TRUE;

            /* Fill in the file format list */
            /*build_file_format_list(sf_hwnd);*/

            range_handle_wm_initdialog(sf_hwnd, &g_range);

            break;
        case WM_COMMAND:
            cur_ctrl = (HWND) l_param;

            switch (w_param) {
#if 0
                case (CBN_SELCHANGE << 16) | EWFD_FILE_TYPE_COMBO:
                    index = SendMessage(cur_ctrl, CB_GETCURSEL, 0, 0);
                    if (index != CB_ERR) {
                        new_filetype = SendMessage(cur_ctrl, CB_GETITEMDATA, (WPARAM) index, 0);
                        if (new_filetype != CB_ERR) {
                            if (filetype != new_filetype) {
                                if (can_save_with_wiretap(new_filetype)) {
                                    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_CAPTURED_BTN);
                                    EnableWindow(cur_ctrl, TRUE);
                                    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_DISPLAYED_BTN);
                                    EnableWindow(cur_ctrl, TRUE);
                                } else {
                                    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_CAPTURED_BTN);
                                    SendMessage(cur_ctrl, BM_SETCHECK, 0, 0);
                                    EnableWindow(cur_ctrl, FALSE);
                                    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_DISPLAYED_BTN);
                                    EnableWindow(cur_ctrl, FALSE);
                                }
                                filetype = new_filetype;
                            }
                        }
                    }
                    break;
#endif
                default:
                    range_handle_wm_command(sf_hwnd, cur_ctrl, w_param, &g_range);
                    break;
            }
            break;
        case WM_NOTIFY:
            switch (notify->hdr.code) {
                case CDN_HELP:
                    topic_cb(NULL, HELP_SAVE_WIN32_DIALOG);
                    break;
                case CDN_FILEOK: {
                    HWND   parent;
                    TCHAR  file_name16_selected[MAX_PATH];
                    char  *file_name8_selected;
                    int    selected_size;

                    /* Check if trying to do 'save as' to the currently open file */
                    parent = GetParent(sf_hwnd);
                    selected_size = CommDlg_OpenSave_GetSpec(parent, file_name16_selected, MAX_PATH);
                    if (selected_size > 0) {
                        file_name8_selected = utf_16to8(file_name16_selected);
                        if (files_identical(cfile.filename, file_name8_selected)) {
                            /* XXX: Is MessageBox the best way to pop up an error ? How to make text bold ? */
                            gchar *str = g_strdup_printf(
                                "Capture File \"%s\" identical to loaded file !!\n\n"
                                "Please choose a different filename.",
                                file_name8_selected);
                            MessageBox( parent, utf_8to16(str), _T("Error"), MB_ICONERROR | MB_APPLMODAL | MB_OK);
                            g_free(str);
                            SetWindowLongPtr(sf_hwnd, DWLP_MSGRESULT, 1L); /* Don't allow ! */
                            return 1;
                        }
                    }
                }
                    break;
                default:
                    break;
            }
            break;
        default:
            break;
    }
    return 0;
}


#define STATIC_LABEL_CHARS 100
/* For each range static control, fill in its value and enable/disable it. */
static void
range_update_dynamics(HWND dlg_hwnd, packet_range_t *range) {
    HWND     cur_ctrl;
    gboolean filtered_active = FALSE;
    TCHAR    static_val[STATIC_LABEL_CHARS];
    gint     selected_num;
    guint32  ignored_cnt = 0, displayed_ignored_cnt = 0;

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_DISPLAYED_BTN);
    if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED)
        filtered_active = TRUE;

    /* RANGE_SELECT_ALL */
    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_ALL_PKTS_CAP);
    EnableWindow(cur_ctrl, !filtered_active);
    if (range->remove_ignored) {
        _snwprintf(static_val, STATIC_LABEL_CHARS, _T("%u"), cfile.count - range->ignored_cnt);
    } else {
        _snwprintf(static_val, STATIC_LABEL_CHARS, _T("%u"), cfile.count);
    }
    SetWindowText(cur_ctrl, static_val);

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_ALL_PKTS_DISP);
    EnableWindow(cur_ctrl, filtered_active);
    if (range->remove_ignored) {
        _snwprintf(static_val, STATIC_LABEL_CHARS, _T("%u"), range->displayed_cnt - range->displayed_ignored_cnt);
    } else {
        _snwprintf(static_val, STATIC_LABEL_CHARS, _T("%u"), range->displayed_cnt);
    }
    SetWindowText(cur_ctrl, static_val);

    /* RANGE_SELECT_CURR */
    selected_num = (cfile.current_frame) ? cfile.current_frame->num : 0;
    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_SEL_PKT_CAP);
    EnableWindow(cur_ctrl, selected_num && !filtered_active);
    if (range->remove_ignored && cfile.current_frame && cfile.current_frame->flags.ignored) {
        _snwprintf(static_val, STATIC_LABEL_CHARS, _T("0"));
    } else {
        _snwprintf(static_val, STATIC_LABEL_CHARS, _T("%u"), selected_num ? 1 : 0);
    }
    SetWindowText(cur_ctrl, static_val);

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_SEL_PKT_DISP);
    EnableWindow(cur_ctrl, selected_num && filtered_active);
    if (range->remove_ignored && cfile.current_frame && cfile.current_frame->flags.ignored) {
        _snwprintf(static_val, STATIC_LABEL_CHARS, _T("0"));
    } else {
        _snwprintf(static_val, STATIC_LABEL_CHARS, _T("%u"), selected_num ? 1 : 0);
    }
    SetWindowText(cur_ctrl, static_val);

    /* RANGE_SELECT_MARKED */
    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_MARKED_BTN);
    EnableWindow(cur_ctrl, cfile.marked_count);

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_MARKED_CAP);
    EnableWindow(cur_ctrl, cfile.marked_count && !filtered_active);
    if (range->remove_ignored) {
        _snwprintf(static_val, STATIC_LABEL_CHARS, _T("%u"), cfile.marked_count - range->ignored_marked_cnt);
    } else {
        _snwprintf(static_val, STATIC_LABEL_CHARS, _T("%u"), cfile.marked_count);
    }
    SetWindowText(cur_ctrl, static_val);

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_MARKED_DISP);
    EnableWindow(cur_ctrl, cfile.marked_count && filtered_active);
    if (range->remove_ignored) {
        _snwprintf(static_val, STATIC_LABEL_CHARS, _T("%u"), range->displayed_marked_cnt - range->displayed_ignored_marked_cnt);
    } else {
        _snwprintf(static_val, STATIC_LABEL_CHARS, _T("%u"), range->displayed_marked_cnt);
    }
    SetWindowText(cur_ctrl, static_val);

    /* RANGE_SELECT_MARKED_RANGE */
    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_FIRST_LAST_BTN);
    EnableWindow(cur_ctrl, range->mark_range_cnt);

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_FIRST_LAST_CAP);
    EnableWindow(cur_ctrl, range->mark_range_cnt && !filtered_active);
    if (range->remove_ignored) {
        _snwprintf(static_val, STATIC_LABEL_CHARS, _T("%u"), range->mark_range_cnt - range->ignored_mark_range_cnt);
    } else {
        _snwprintf(static_val, STATIC_LABEL_CHARS, _T("%u"), range->mark_range_cnt);
    }
    SetWindowText(cur_ctrl, static_val);

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_FIRST_LAST_DISP);
    EnableWindow(cur_ctrl, range->displayed_mark_range_cnt && filtered_active);
    if (range->remove_ignored) {
        _snwprintf(static_val, STATIC_LABEL_CHARS, _T("%u"), range->displayed_mark_range_cnt - range->displayed_ignored_mark_range_cnt);
    } else {
        _snwprintf(static_val, STATIC_LABEL_CHARS, _T("%u"), range->displayed_mark_range_cnt);
    }
    SetWindowText(cur_ctrl, static_val);

    /* RANGE_SELECT_USER */
    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_RANGE_CAP);
    EnableWindow(cur_ctrl, !filtered_active);
    if (range->remove_ignored) {
        _snwprintf(static_val, STATIC_LABEL_CHARS, _T("%u"), range->user_range_cnt - range->ignored_user_range_cnt);
    } else {
        _snwprintf(static_val, STATIC_LABEL_CHARS, _T("%u"), range->user_range_cnt);
    }
    SetWindowText(cur_ctrl, static_val);

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_RANGE_DISP);
    EnableWindow(cur_ctrl, filtered_active);
    if (range->remove_ignored) {
        _snwprintf(static_val, STATIC_LABEL_CHARS, _T("%u"), range->displayed_user_range_cnt - range->displayed_ignored_user_range_cnt);
    } else {
        _snwprintf(static_val, STATIC_LABEL_CHARS, _T("%u"), range->displayed_user_range_cnt);
    }
    SetWindowText(cur_ctrl, static_val);

    /* RANGE_REMOVE_IGNORED_PACKETS */
    switch(range->process) {
        case(range_process_all):
            ignored_cnt = range->ignored_cnt;
            displayed_ignored_cnt = range->displayed_ignored_cnt;
            break;
        case(range_process_selected):
            ignored_cnt = (cfile.current_frame && cfile.current_frame->flags.ignored) ? 1 : 0;
            displayed_ignored_cnt = ignored_cnt;
            break;
        case(range_process_marked):
            ignored_cnt = range->ignored_marked_cnt;
            displayed_ignored_cnt = range->displayed_ignored_marked_cnt;
            break;
        case(range_process_marked_range):
            ignored_cnt = range->ignored_mark_range_cnt;
            displayed_ignored_cnt = range->displayed_ignored_mark_range_cnt;
            break;
        case(range_process_user_range):
            ignored_cnt = range->ignored_user_range_cnt;
            displayed_ignored_cnt = range->displayed_ignored_user_range_cnt;
            break;
        default:
            g_assert_not_reached();
    }

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_REMOVE_IGN_CB);
    EnableWindow(cur_ctrl, ignored_cnt);

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_IGNORED_CAP);
    EnableWindow(cur_ctrl, ignored_cnt && !filtered_active);
    _snwprintf(static_val, STATIC_LABEL_CHARS, _T("%u"), ignored_cnt);
    SetWindowText(cur_ctrl, static_val);

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_IGNORED_DISP);
    EnableWindow(cur_ctrl, displayed_ignored_cnt && filtered_active);
    _snwprintf(static_val, STATIC_LABEL_CHARS, _T("%u"), displayed_ignored_cnt);
    SetWindowText(cur_ctrl, static_val);
}

static void
range_handle_wm_initdialog(HWND dlg_hwnd, packet_range_t *range) {
    HWND cur_ctrl;

    /* Set the appropriate captured/displayed radio */
    if (range->process_filtered)
        cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_DISPLAYED_BTN);
    else
        cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_CAPTURED_BTN);
    SendMessage(cur_ctrl, BM_SETCHECK, TRUE, 0);

    /* dynamic values in the range frame */
    range_update_dynamics(dlg_hwnd, range);

    /* Set the appropriate range radio */
    switch(range->process) {
        case(range_process_all):
            cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_ALL_PKTS_BTN);
            break;
        case(range_process_selected):
            cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_SEL_PKT_BTN);
            break;
        case(range_process_marked):
            cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_MARKED_BTN);
            break;
        case(range_process_marked_range):
            cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_FIRST_LAST_BTN);
            break;
        case(range_process_user_range):
            cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_RANGE_BTN);
            break;
        default:
            g_assert_not_reached();
    }
    SendMessage(cur_ctrl, BM_SETCHECK, TRUE, 0);
}

static void
range_handle_wm_command(HWND dlg_hwnd, HWND ctrl, WPARAM w_param, packet_range_t *range) {
    HWND  cur_ctrl;
    TCHAR range_text[RANGE_TEXT_MAX];

    switch(w_param) {
        case (BN_CLICKED << 16) | EWFD_CAPTURED_BTN:
        case (BN_CLICKED << 16) | EWFD_DISPLAYED_BTN:
            cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_CAPTURED_BTN);
            if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED)
                range->process_filtered = FALSE;
            else
                range->process_filtered = TRUE;
            range_update_dynamics(dlg_hwnd, range);
            break;
        case (BN_CLICKED << 16) | EWFD_ALL_PKTS_BTN:
            if (SendMessage(ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                range->process = range_process_all;
                range_update_dynamics(dlg_hwnd, range);
            }
            break;
        case (BN_CLICKED << 16) | EWFD_SEL_PKT_BTN:
            if (SendMessage(ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                range->process = range_process_selected;
                range_update_dynamics(dlg_hwnd, range);
            }
            break;
        case (BN_CLICKED << 16) | EWFD_MARKED_BTN:
            if (SendMessage(ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                range->process = range_process_marked;
                range_update_dynamics(dlg_hwnd, range);
            }
            break;
        case (BN_CLICKED << 16) | EWFD_FIRST_LAST_BTN:
            if (SendMessage(ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                range->process = range_process_marked_range;
                range_update_dynamics(dlg_hwnd, range);
            }
            break;
        case (BN_CLICKED << 16) | EWFD_RANGE_BTN:
            if (SendMessage(ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                range->process = range_process_user_range;
                range_update_dynamics(dlg_hwnd, range);
                cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_RANGE_EDIT);
                SetFocus(cur_ctrl);
            }
            break;
        case (EN_SETFOCUS << 16) | EWFD_RANGE_EDIT:
            cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_RANGE_BTN);
            SendMessage(cur_ctrl, BM_CLICK, 0, 0);
            break;
        case (EN_CHANGE << 16) | EWFD_RANGE_EDIT:
            SendMessage(ctrl, WM_GETTEXT, (WPARAM) RANGE_TEXT_MAX, (LPARAM) range_text);
            packet_range_convert_str(range, utf_16to8(range_text));
            range_update_dynamics(dlg_hwnd, range);
            break;
        case (BN_CLICKED << 16) | EWFD_REMOVE_IGN_CB:
            if (SendMessage(ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                range->remove_ignored = TRUE;
            } else {
                range->remove_ignored = FALSE;
            }
            range_update_dynamics(dlg_hwnd, range);
            break;
    }
}

#if (_MSC_VER <= 1200)
static UINT CALLBACK
#else
static UINT_PTR CALLBACK
#endif
merge_file_hook_proc(HWND mf_hwnd, UINT msg, WPARAM w_param, LPARAM l_param) {
    HWND      cur_ctrl, parent;
    OFNOTIFY *notify = (OFNOTIFY *) l_param;
    TCHAR     sel_name[MAX_PATH];

    switch(msg) {
        case WM_INITDIALOG:
            /* Retain the filter text, and fill it in. */
            if(dfilter_str != NULL) {
                cur_ctrl = GetDlgItem(mf_hwnd, EWFD_FILTER_EDIT);
                SetWindowText(cur_ctrl, utf_8to16(dfilter_str));
            }

            /* Append by default */
            cur_ctrl = GetDlgItem(mf_hwnd, EWFD_MERGE_PREPEND_BTN);
            SendMessage(cur_ctrl, BM_SETCHECK, TRUE, 0);
            merge_action = merge_append;

            preview_set_filename(mf_hwnd, NULL);
            break;
        case WM_NOTIFY:
            switch (notify->hdr.code) {
                case CDN_FILEOK:
                    /* Fetch the read filter */
                    cur_ctrl = GetDlgItem(mf_hwnd, EWFD_FILTER_EDIT);
                    if (dfilter_str)
                        g_free(dfilter_str);
                    dfilter_str = filter_tb_get(cur_ctrl);

                    cur_ctrl = GetDlgItem(mf_hwnd, EWFD_MERGE_CHRONO_BTN);
                    if(SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                        merge_action = merge_chrono;
                    } else {
                        cur_ctrl = GetDlgItem(mf_hwnd, EWFD_MERGE_PREPEND_BTN);
                        if(SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                            merge_action = merge_prepend;
                        }
                    }

                    break;
                case CDN_SELCHANGE:
                    /* This _almost_ works correctly.  We need to handle directory
                       selections, etc. */
                    parent = GetParent(mf_hwnd);
                    CommDlg_OpenSave_GetSpec(parent, sel_name, MAX_PATH);
                    preview_set_filename(mf_hwnd, utf_16to8(sel_name));
                    break;
                case CDN_HELP:
                    topic_cb(NULL, HELP_MERGE_WIN32_DIALOG);
                    break;
                default:
                    break;
            }
            break;
        case WM_COMMAND:
            cur_ctrl = (HWND) l_param;
            switch(w_param) {
                case (EN_UPDATE << 16) | EWFD_FILTER_EDIT:
                    filter_tb_syntax_check(cur_ctrl, NULL);
                    break;
                default:
                    break;
            }
            break;
        default:
            break;
    }
    return 0;
}


#if (_MSC_VER <= 1200)
static UINT CALLBACK
#else
static UINT_PTR CALLBACK
#endif
export_file_hook_proc(HWND ef_hwnd, UINT msg, WPARAM w_param, LPARAM l_param) {
    HWND           cur_ctrl;
    OFNOTIFY      *notify = (OFNOTIFY *) l_param;
    gboolean       pkt_fmt_enable;
    int            i, index;

    switch(msg) {
        case WM_INITDIALOG:
            /* init the printing range */
            packet_range_init(&print_args.range);
            /* default to displayed packets */
            print_args.range.process_filtered = TRUE;
            range_handle_wm_initdialog(ef_hwnd, &print_args.range);
            format_handle_wm_initdialog(ef_hwnd, &print_args);

            break;
        case WM_COMMAND:
            cur_ctrl = (HWND) l_param;
            switch (w_param) {
                case (CBN_SELCHANGE << 16) | EWFD_PKT_DETAIL_COMBO:
                default:
                    range_handle_wm_command(ef_hwnd, cur_ctrl, w_param, &print_args.range);
                    print_update_dynamic(ef_hwnd, &print_args);
                    break;
            }
            break;
        case WM_NOTIFY:
            switch (notify->hdr.code) {
                case CDN_FILEOK:
                    break;
                case CDN_TYPECHANGE:
                    index = notify->lpOFN->nFilterIndex;

                    if (index == 2)     /* PostScript */
                        print_args.format = PR_FMT_TEXT;
                    else
                        print_args.format = PR_FMT_PS;
                    if (index == 3 || index == 4 || index == 5 || index == 6)
                        pkt_fmt_enable = FALSE;
                    else
                        pkt_fmt_enable = TRUE;
                    for (i = EWFD_PKT_FORMAT_GB; i <= EWFD_PKT_NEW_PAGE_CB; i++) {
                        cur_ctrl = GetDlgItem(ef_hwnd, i);
                        EnableWindow(cur_ctrl, pkt_fmt_enable);
                    }
                    break;
                case CDN_HELP:
                    topic_cb(NULL, HELP_EXPORT_FILE_WIN32_DIALOG);
                    break;
                default:
                    break;
            }
            break;
        default:
            break;
    }
    return 0;
}

#if (_MSC_VER <= 1200)
static UINT CALLBACK
#else
static UINT_PTR CALLBACK
#endif
export_raw_file_hook_proc(HWND ef_hwnd, UINT msg, WPARAM w_param, LPARAM l_param) {
    HWND          cur_ctrl;
    OPENFILENAME *ofnp = (OPENFILENAME *) l_param;
    TCHAR         raw_msg[STATIC_LABEL_CHARS];
    OFNOTIFY      *notify = (OFNOTIFY *) l_param;

    switch(msg) {
        case WM_INITDIALOG:
            _snwprintf(raw_msg, STATIC_LABEL_CHARS, _T("%d byte%s of raw binary data will be written"),
                    ofnp->lCustData, utf_8to16(plurality(ofnp->lCustData, "", "s")));
            cur_ctrl = GetDlgItem(ef_hwnd, EWFD_EXPORTRAW_ST);
            SetWindowText(cur_ctrl, raw_msg);
            break;
        case WM_NOTIFY:
            switch (notify->hdr.code) {
                case CDN_HELP:
                    topic_cb(NULL, HELP_EXPORT_BYTES_WIN32_DIALOG);
                    break;
                default:
                    break;
            }
        default:
            break;
    }
    return 0;
}

#if (_MSC_VER <= 1200)
static UINT CALLBACK
#else
static UINT_PTR CALLBACK
#endif
export_sslkeys_file_hook_proc(HWND ef_hwnd, UINT msg, WPARAM w_param, LPARAM l_param) {
    HWND          cur_ctrl;
    OPENFILENAME *ofnp = (OPENFILENAME *) l_param;
    TCHAR         sslkeys_msg[STATIC_LABEL_CHARS];
    OFNOTIFY      *notify = (OFNOTIFY *) l_param;

    switch(msg) {
        case WM_INITDIALOG:
            _snwprintf(sslkeys_msg, STATIC_LABEL_CHARS, _T("%d SSL Session Key%s will be written"),
                    ofnp->lCustData, utf_8to16(plurality(ofnp->lCustData, "", "s")));
            cur_ctrl = GetDlgItem(ef_hwnd, EWFD_EXPORTSSLKEYS_ST);
            SetWindowText(cur_ctrl, sslkeys_msg);
            break;
        case WM_NOTIFY:
            switch (notify->hdr.code) {
                case CDN_HELP:
                    topic_cb(NULL, HELP_EXPORT_BYTES_WIN32_DIALOG);
                    break;
                default:
                    break;
            }
        default:
            break;
    }
    return 0;
}

/*
 * Editor modelines
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
