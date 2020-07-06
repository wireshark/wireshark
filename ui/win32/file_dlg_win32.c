/* file_dlg_win32.c
 * Native Windows file dialog routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2004 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <tchar.h>
#include <stdlib.h>
#include <fcntl.h>

#include <windows.h>
#include <commdlg.h>
#include <richedit.h>
#include <strsafe.h>

#include "file.h"

#include "wsutil/file_util.h"
#include "wsutil/str_util.h"
#include "wsutil/unicode-utils.h"

#include "wsutil/filesystem.h"
#include "epan/prefs.h"

#include "ui/alert_box.h"
#include "ui/help_url.h"
#include "ui/last_open_dir.h"
#include "ui/simple_dialog.h"
#include "ui/util.h"
#include "ui/ws_ui_util.h"
#include "ui/all_files_wildcard.h"

#include "file_dlg_win32.h"

typedef enum {
    merge_append,
    merge_chrono,
    merge_prepend
} merge_action_e;

#define FILE_OPEN_DEFAULT 1 /* All Files */

#define FILE_MERGE_DEFAULT FILE_OPEN_DEFAULT

#define FILE_TYPES_EXPORT \
    _T("Plain text (*.txt)\0")                           _T("*.txt\0")   \
    _T("PostScript (*.ps)\0")                            _T("*.ps\0")    \
    _T("CSV (Comma Separated Values summary) (*.csv)\0") _T("*.csv\0")   \
    _T("PSML (XML packet summary) (*.psml)\0")           _T("*.psml\0")  \
    _T("PDML (XML packet detail) (*.pdml)\0")            _T("*.pdml\0")  \
    _T("C Arrays (packet bytes) (*.c)\0")                _T("*.c\0")     \
    _T("JSON (*.json)\0")                                _T("*.json\0")

static TCHAR *FILE_EXT_EXPORT[] =
{
    _T(""), /* export type starts at 1 */
    _T("txt"),
    _T("ps"),
    _T("csv"),
    _T("psml"),
    _T("pdml"),
    _T("c"),
    _T("json")
};

static UINT_PTR CALLBACK open_file_hook_proc(HWND of_hwnd, UINT ui_msg, WPARAM w_param, LPARAM l_param);
static UINT_PTR CALLBACK save_as_file_hook_proc(HWND of_hwnd, UINT ui_msg, WPARAM w_param, LPARAM l_param);
static UINT_PTR CALLBACK export_specified_packets_file_hook_proc(HWND of_hwnd, UINT ui_msg, WPARAM w_param, LPARAM l_param);
static UINT_PTR CALLBACK merge_file_hook_proc(HWND mf_hwnd, UINT ui_msg, WPARAM w_param, LPARAM l_param);
static UINT_PTR CALLBACK export_file_hook_proc(HWND of_hwnd, UINT ui_msg, WPARAM w_param, LPARAM l_param);
static void range_update_dynamics(HWND sf_hwnd, packet_range_t *range);
static void range_handle_wm_initdialog(HWND dlg_hwnd, packet_range_t *range);
static void range_handle_wm_command(HWND dlg_hwnd, HWND ctrl, WPARAM w_param, packet_range_t *range);

static TCHAR *build_file_open_type_list(void);
static TCHAR *build_file_save_type_list(GArray *savable_file_types);

#ifdef DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
typedef DPI_AWARENESS_CONTEXT (WINAPI *GetThreadDpiAwarenessContextProc)(void);
typedef DPI_AWARENESS_CONTEXT (WINAPI *SetThreadDpiAwarenessContextProc)(DPI_AWARENESS_CONTEXT);

static GetThreadDpiAwarenessContextProc GetThreadDpiAwarenessContextP;
static SetThreadDpiAwarenessContextProc SetThreadDpiAwarenessContextP;
static gboolean got_proc_addresses = FALSE;

static gboolean get_proc_addresses(void) {
    if (got_proc_addresses) return TRUE;

    HMODULE u32_module = LoadLibrary(_T("User32.dll"));
    if (!u32_module) {
        got_proc_addresses = FALSE;
        return FALSE;
    }
    gboolean got_all = TRUE;
    GetThreadDpiAwarenessContextP = (GetThreadDpiAwarenessContextProc) GetProcAddress(u32_module, "GetThreadDpiAwarenessContext");
    if (!GetThreadDpiAwarenessContextP) got_all = FALSE;
    SetThreadDpiAwarenessContextP = (SetThreadDpiAwarenessContextProc) GetProcAddress(u32_module, "SetThreadDpiAwarenessContext");
    if (!SetThreadDpiAwarenessContextP) got_all = FALSE;

    got_proc_addresses = got_all;
    return got_all;
}

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

static int             g_filetype;
static gboolean        g_compressed;
static packet_range_t *g_range;
static capture_file   *g_cf;
static merge_action_e  g_merge_action;
static print_args_t    print_args;
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
static HWND  g_sf_hwnd = NULL;
static char *g_dfilter_str = NULL;
static unsigned int g_format_type = WTAP_TYPE_AUTO;

/*
 * According to https://docs.microsoft.com/en-us/windows/win32/shell/common-file-dialog
 * we should use IFileOpenDialog and IFileSaveDialog on Windows Vista
 * and later.
 */

gboolean
win32_open_file (HWND h_wnd, const wchar_t *title, GString *file_name, unsigned int *type, GString *display_filter) {
    OPENFILENAME *ofn;
    TCHAR file_name16[MAX_PATH] = _T("");
    int ofnsize = sizeof(OPENFILENAME);
    BOOL gofn_ok;

    if (!file_name || !display_filter)
        return FALSE;

    if (file_name->len > 0) {
        StringCchCopy(file_name16, MAX_PATH, utf_8to16(file_name->str));
    }

    if (display_filter->len > 0) {
        g_dfilter_str = g_strdup(display_filter->str);
    } else if (g_dfilter_str) {
        g_free(g_dfilter_str);
        g_dfilter_str = NULL;
    }

    ofn = g_malloc0(ofnsize);

    ofn->lStructSize = ofnsize;
    ofn->hwndOwner = h_wnd;
    ofn->hInstance = (HINSTANCE) GetWindowLongPtr(h_wnd, GWLP_HINSTANCE);
    ofn->lpstrFilter = build_file_open_type_list();
    ofn->lpstrCustomFilter = NULL;
    ofn->nMaxCustFilter = 0;
    ofn->nFilterIndex = FILE_OPEN_DEFAULT;
    ofn->lpstrFile = file_name16;
    ofn->nMaxFile = MAX_PATH;
    ofn->lpstrFileTitle = NULL;
    ofn->nMaxFileTitle = 0;
    if (prefs.gui_fileopen_style == FO_STYLE_SPECIFIED && prefs.gui_fileopen_dir[0] != '\0') {
        ofn->lpstrInitialDir = utf_8to16(prefs.gui_fileopen_dir);
    } else {
        ofn->lpstrInitialDir = utf_8to16(get_last_open_dir());
    }
    ofn->lpstrTitle = title;
    ofn->Flags = OFN_ENABLESIZING | OFN_ENABLETEMPLATE | OFN_EXPLORER     |
                 OFN_NOCHANGEDIR  | OFN_FILEMUSTEXIST  | OFN_HIDEREADONLY |
                 OFN_ENABLEHOOK   | OFN_SHOWHELP;
    ofn->lpstrDefExt = NULL;
    ofn->lpfnHook = open_file_hook_proc;
    ofn->lpTemplateName = _T("WIRESHARK_OPENFILENAME_TEMPLATE");

    HANDLE save_da_ctx = set_thread_per_monitor_v2_awareness();
    gofn_ok = GetOpenFileName(ofn);
    revert_thread_per_monitor_v2_awareness(save_da_ctx);

    if (gofn_ok) {
        g_string_printf(file_name, "%s", utf_16to8(file_name16));
        g_string_printf(display_filter, "%s", g_dfilter_str ? g_dfilter_str : "");
        *type = g_format_type;
    }

    g_free( (void *) ofn->lpstrFilter);
    g_free( (void *) ofn);
    g_free(g_dfilter_str);
    g_dfilter_str = NULL;
    return gofn_ok;
}

gboolean
win32_save_as_file(HWND h_wnd, const wchar_t *title, capture_file *cf, GString *file_name, int *file_type,
                   wtap_compression_type *compression_type,
                   gboolean must_support_all_comments)
{
    guint32 required_comment_types;
    GArray *savable_file_types;
    OPENFILENAME *ofn;
    TCHAR  file_name16[MAX_PATH] = _T("");
    int    ofnsize = sizeof(OPENFILENAME);
    BOOL gsfn_ok;

    if (!file_name || !file_type || !compression_type)
        return FALSE;

    if (file_name->len > 0) {
        StringCchCopy(file_name16, MAX_PATH, utf_8to16(file_name->str));
    }

    /* What types of comments do we have to support? */
    if (must_support_all_comments)
        required_comment_types = cf_comment_types(cf); /* all the ones the file has */
    else
        required_comment_types = 0; /* none of them */

    savable_file_types = wtap_get_savable_file_types_subtypes(cf->cd_t,
                                                              cf->linktypes,
                                                              required_comment_types);
    if (savable_file_types == NULL)
        return FALSE;  /* shouldn't happen - the "Save As..." item should be disabled if we can't save the file */
    g_compressed = FALSE;

    ofn = g_malloc0(ofnsize);

    ofn->lStructSize = ofnsize;
    ofn->hwndOwner = h_wnd;
    ofn->hInstance = (HINSTANCE) GetWindowLongPtr(h_wnd, GWLP_HINSTANCE);
    ofn->lpstrFilter = build_file_save_type_list(savable_file_types);
    ofn->lpstrCustomFilter = NULL;
    ofn->nMaxCustFilter = 0;
    ofn->nFilterIndex = 1;  /* the first entry is the best match; 1-origin indexing */
    ofn->lpstrFile = file_name16;
    ofn->nMaxFile = MAX_PATH;
    ofn->lpstrFileTitle = NULL;
    ofn->nMaxFileTitle = 0;
    ofn->lpstrInitialDir = utf_8to16(get_last_open_dir());
    ofn->lpstrTitle = title;
    ofn->Flags = OFN_ENABLESIZING  | OFN_ENABLETEMPLATE  | OFN_EXPLORER     |
                 OFN_NOCHANGEDIR   | OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY |
                 OFN_PATHMUSTEXIST | OFN_ENABLEHOOK      | OFN_SHOWHELP;
    ofn->lpstrDefExt = NULL;
    ofn->lCustData = (LPARAM) cf;
    ofn->lpfnHook = save_as_file_hook_proc;
    ofn->lpTemplateName = _T("WIRESHARK_SAVEASFILENAME_TEMPLATE");

    HANDLE save_da_ctx = set_thread_per_monitor_v2_awareness();
    gsfn_ok = GetSaveFileName(ofn);
    revert_thread_per_monitor_v2_awareness(save_da_ctx);

    if (gsfn_ok) {
        g_string_printf(file_name, "%s", utf_16to8(file_name16));
        /* What file format was specified? */
        *file_type = g_array_index(savable_file_types, int, ofn->nFilterIndex - 1);
        *compression_type = g_compressed ? WTAP_GZIP_COMPRESSED : WTAP_UNCOMPRESSED;
    } else {
        /* User cancelled or closed the dialog, or an error occurred. */
        if (CommDlgExtendedError() != 0) {
            /* XXX - pop up some error here. FNERR_INVALIDFILENAME
             * might be a user error; if so, they should know about
             * it. For now we force a do-over.
             */
            g_string_truncate(file_name, 0);
            gsfn_ok = TRUE;
        }
    }

    g_sf_hwnd = NULL;
    g_array_free(savable_file_types, TRUE);
    g_free( (void *) ofn->lpstrFilter);
    g_free( (void *) ofn);
    return gsfn_ok;
}

gboolean
win32_export_specified_packets_file(HWND h_wnd, const wchar_t *title,
                                    capture_file *cf,
                                    GString *file_name,
                                    int *file_type,
                                    wtap_compression_type *compression_type,
                                    packet_range_t *range) {
    GArray *savable_file_types;
    OPENFILENAME *ofn;
    TCHAR  file_name16[MAX_PATH] = _T("");
    int    ofnsize = sizeof(OPENFILENAME);
    BOOL gsfn_ok;

    if (!file_name || !file_type || !compression_type || !range)
        return FALSE;

    if (file_name->len > 0) {
        StringCchCopy(file_name16, MAX_PATH, utf_8to16(file_name->str));
    }

    savable_file_types = wtap_get_savable_file_types_subtypes(cf->cd_t,
                                                              cf->linktypes, 0);
    if (savable_file_types == NULL)
        return FALSE;  /* shouldn't happen - the "Save As..." item should be disabled if we can't save the file */

    g_range = range;
    g_cf = cf;
    g_compressed = FALSE;

    ofn = g_malloc0(ofnsize);

    ofn->lStructSize = ofnsize;
    ofn->hwndOwner = h_wnd;
    ofn->hInstance = (HINSTANCE) GetWindowLongPtr(h_wnd, GWLP_HINSTANCE);
    ofn->lpstrFilter = build_file_save_type_list(savable_file_types);
    ofn->lpstrCustomFilter = NULL;
    ofn->nMaxCustFilter = 0;
    ofn->nFilterIndex = 1;  /* the first entry is the best match; 1-origin indexing */
    ofn->lpstrFile = file_name16;
    ofn->nMaxFile = MAX_PATH;
    ofn->lpstrFileTitle = NULL;
    ofn->nMaxFileTitle = 0;
    ofn->lpstrInitialDir = utf_8to16(get_last_open_dir());
    ofn->lpstrTitle = title;
    ofn->Flags = OFN_ENABLESIZING  | OFN_ENABLETEMPLATE  | OFN_EXPLORER     |
                 OFN_NOCHANGEDIR   | OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY |
                 OFN_PATHMUSTEXIST | OFN_ENABLEHOOK      | OFN_SHOWHELP;
    ofn->lpstrDefExt = NULL;
    ofn->lCustData = (LPARAM) cf;
    ofn->lpfnHook = export_specified_packets_file_hook_proc;
    ofn->lpTemplateName = _T("WIRESHARK_EXPORT_SPECIFIED_PACKETS_FILENAME_TEMPLATE");

    HANDLE save_da_ctx = set_thread_per_monitor_v2_awareness();
    gsfn_ok = GetSaveFileName(ofn);
    revert_thread_per_monitor_v2_awareness(save_da_ctx);

    if (gsfn_ok) {
        g_string_printf(file_name, "%s", utf_16to8(file_name16));
        /* What file format was specified? */
        *file_type = g_array_index(savable_file_types, int, ofn->nFilterIndex - 1);
        *compression_type = g_compressed ? WTAP_GZIP_COMPRESSED : WTAP_UNCOMPRESSED;
    } else {
        /* User cancelled or closed the dialog, or an error occurred. */
        if (CommDlgExtendedError() != 0) {
            /* XXX - pop up some error here. FNERR_INVALIDFILENAME
             * might be a user error; if so, they should know about
             * it. For now we force a do-over.
             */
            g_string_truncate(file_name, 0);
            gsfn_ok = TRUE;
        }
    }

    g_sf_hwnd = NULL;
    g_range = NULL;
    g_cf = NULL;
    g_array_free(savable_file_types, TRUE);
    g_free( (void *) ofn->lpstrFilter);
    g_free( (void *) ofn);
    return gsfn_ok;
}


gboolean
win32_merge_file (HWND h_wnd, const wchar_t *title, GString *file_name, GString *display_filter, int *merge_type) {
    OPENFILENAME *ofn;
    TCHAR         file_name16[MAX_PATH] = _T("");
    int           ofnsize = sizeof(OPENFILENAME);
    BOOL          gofn_ok;

    if (!file_name || !display_filter || !merge_type)
        return FALSE;

    if (file_name->len > 0) {
        StringCchCopy(file_name16, MAX_PATH, utf_8to16(file_name->str));
    }

    if (display_filter->len > 0) {
        g_dfilter_str = g_strdup(display_filter->str);
    } else if (g_dfilter_str) {
        g_free(g_dfilter_str);
        g_dfilter_str = NULL;
    }

    ofn = g_malloc0(ofnsize);

    ofn->lStructSize = ofnsize;
    ofn->hwndOwner = h_wnd;
    ofn->hInstance = (HINSTANCE) GetWindowLongPtr(h_wnd, GWLP_HINSTANCE);
    ofn->lpstrFilter = build_file_open_type_list();
    ofn->lpstrCustomFilter = NULL;
    ofn->nMaxCustFilter = 0;
    ofn->nFilterIndex = FILE_MERGE_DEFAULT;
    ofn->lpstrFile = file_name16;
    ofn->nMaxFile = MAX_PATH;
    ofn->lpstrFileTitle = NULL;
    ofn->nMaxFileTitle = 0;
    if (prefs.gui_fileopen_style == FO_STYLE_SPECIFIED && prefs.gui_fileopen_dir[0] != '\0') {
        ofn->lpstrInitialDir = utf_8to16(prefs.gui_fileopen_dir);
    } else {
        ofn->lpstrInitialDir = utf_8to16(get_last_open_dir());
    }
    ofn->lpstrTitle = title;
    ofn->Flags = OFN_ENABLESIZING | OFN_ENABLETEMPLATE | OFN_EXPLORER     |
                 OFN_NOCHANGEDIR  | OFN_FILEMUSTEXIST  | OFN_HIDEREADONLY |
                 OFN_ENABLEHOOK   | OFN_SHOWHELP;
    ofn->lpstrDefExt = NULL;
    ofn->lpfnHook = merge_file_hook_proc;
    ofn->lpTemplateName = _T("WIRESHARK_MERGEFILENAME_TEMPLATE");

    HANDLE save_da_ctx = set_thread_per_monitor_v2_awareness();
    gofn_ok = GetOpenFileName(ofn);
    revert_thread_per_monitor_v2_awareness(save_da_ctx);

    if (gofn_ok) {
        g_string_printf(file_name, "%s", utf_16to8(file_name16));
        g_string_printf(display_filter, "%s", g_dfilter_str ? g_dfilter_str : "");

        switch (g_merge_action) {
            case merge_append:
                *merge_type = 1;
                break;
            case merge_chrono:
                *merge_type = 0;
                break;
            case merge_prepend:
                *merge_type = -1;
                break;
            default:
                g_assert_not_reached();
        }
    }

    g_free( (void *) ofn->lpstrFilter);
    g_free( (void *) ofn);
    g_free(g_dfilter_str);
    g_dfilter_str = NULL;
    return gofn_ok;
}

void
win32_export_file(HWND h_wnd, const wchar_t *title, capture_file *cf, export_type_e export_type, const gchar *range_) {
    OPENFILENAME     *ofn;
    TCHAR             file_name[MAX_PATH] = _T("");
    char             *dirname;
    cf_print_status_t status;
    int               ofnsize = sizeof(OPENFILENAME);

    g_cf = cf;

    ofn = g_malloc0(ofnsize);

    ofn->lStructSize = ofnsize;
    ofn->hwndOwner = h_wnd;
    ofn->hInstance = (HINSTANCE) GetWindowLongPtr(h_wnd, GWLP_HINSTANCE);
    ofn->lpstrFilter = FILE_TYPES_EXPORT;
    ofn->lpstrCustomFilter = NULL;
    ofn->nMaxCustFilter = 0;
    ofn->nFilterIndex = export_type;
    ofn->lpstrFile = file_name;
    ofn->nMaxFile = MAX_PATH;
    ofn->lpstrFileTitle = NULL;
    ofn->nMaxFileTitle = 0;
    ofn->lpstrInitialDir = utf_8to16(get_last_open_dir());
    ofn->lpstrTitle = title;
    ofn->Flags = OFN_ENABLESIZING  | OFN_ENABLETEMPLATE  | OFN_EXPLORER     |
                 OFN_NOCHANGEDIR   | OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY |
                 OFN_PATHMUSTEXIST | OFN_ENABLEHOOK      | OFN_SHOWHELP;
    ofn->lpstrDefExt = FILE_EXT_EXPORT[export_type];
    ofn->lCustData = (LPARAM) cf;
    ofn->lpfnHook = export_file_hook_proc;
    ofn->lpTemplateName = _T("WIRESHARK_EXPORTFILENAME_TEMPLATE");

    /* Fill in our print (and export) args */

    /* init the printing range */
    packet_range_init(&print_args.range, cf);

    if (strlen(range_) > 0)
        packet_range_convert_selection_str(&print_args.range, range_);

    print_args.format              = PR_FMT_TEXT;
    print_args.to_file             = TRUE;
    print_args.cmd                 = NULL;
    print_args.print_summary       = TRUE;
    print_args.print_col_headings  = TRUE;
    print_args.print_dissections   = print_dissections_as_displayed;
    print_args.print_hex           = FALSE;
    print_args.print_formfeed      = FALSE;
    print_args.stream              = NULL;

    HANDLE save_da_ctx = set_thread_per_monitor_v2_awareness();
    BOOL gsfn_ok = GetSaveFileName(ofn);
    revert_thread_per_monitor_v2_awareness(save_da_ctx);

    if (gsfn_ok) {
        print_args.file = utf_16to8(file_name);
        switch (ofn->nFilterIndex) {
            case export_type_text:      /* Text */
                print_args.stream = print_stream_text_new(TRUE, print_args.file);
                if (print_args.stream == NULL) {
                    open_failure_alert_box(print_args.file, errno, TRUE);
                    g_free( (void *) ofn);
                    return;
                }
                status = cf_print_packets(cf, &print_args, TRUE);
                break;
            case export_type_ps:        /* PostScript (r) */
                print_args.stream = print_stream_ps_new(TRUE, print_args.file);
                if (print_args.stream == NULL) {
                    open_failure_alert_box(print_args.file, errno, TRUE);
                    g_free( (void *) ofn);
                    return;
                }
                status = cf_print_packets(cf, &print_args, TRUE);
                break;
            case export_type_csv:       /* CSV */
                status = cf_write_csv_packets(cf, &print_args);
                break;
            case export_type_carrays:   /* C Arrays */
                status = cf_write_carrays_packets(cf, &print_args);
                break;
            case export_type_psml:      /* PSML */
                status = cf_write_psml_packets(cf, &print_args);
                break;
            case export_type_pdml:      /* PDML */
                status = cf_write_pdml_packets(cf, &print_args);
                break;
            case export_type_json:      /* JSON */
                status = cf_write_json_packets(cf, &print_args);
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

    g_cf = NULL;
    g_free( (void *) ofn);
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
    if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED) {
        args->print_summary = TRUE;
        cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_COL_HEADINGS_CB);
        EnableWindow(cur_ctrl, TRUE);
        if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED)
            args->print_col_headings = TRUE;
        else
            args->print_col_headings = FALSE;
    } else {
        args->print_summary = FALSE;
        args->print_col_headings = FALSE;
        cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_COL_HEADINGS_CB);
        EnableWindow(cur_ctrl, FALSE);
    }

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

    /* Set the "Packet summary" and "Include column headings" boxes */
    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_PKT_SUMMARY_CB);
    SendMessage(cur_ctrl, BM_SETCHECK, args->print_summary, 0);
    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_COL_HEADINGS_CB);
    SendMessage(cur_ctrl, BM_SETCHECK, args->print_col_headings, 0);

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
preview_set_file_info(HWND of_hwnd, gchar *preview_file) {
    HWND        cur_ctrl;
    int         i;
    wtap       *wth;
    int         err;
    gchar      *err_info;
    ws_file_preview_stats stats;
    ws_file_preview_stats_status status;
    TCHAR       string_buff[PREVIEW_STR_MAX];
    TCHAR       first_buff[PREVIEW_STR_MAX];
    gint64      filesize;
    gchar      *size_str;
    time_t      ti_time;
    struct tm  *ti_tm;
    guint       elapsed_time;

    for (i = EWFD_PTX_FORMAT; i <= EWFD_PTX_START_ELAPSED; i++) {
        cur_ctrl = GetDlgItem(of_hwnd, i);
        if (cur_ctrl) {
            EnableWindow(cur_ctrl, FALSE);
        }
    }

    for (i = EWFD_PTX_FORMAT; i <= EWFD_PTX_START_ELAPSED; i++) {
        cur_ctrl = GetDlgItem(of_hwnd, i);
        if (cur_ctrl) {
            SetWindowText(cur_ctrl, _T("-"));
        }
    }

    if (preview_file == NULL || strlen(preview_file) < 1) {
        return FALSE;
    }

    /* Format: directory */
    cur_ctrl = GetDlgItem(of_hwnd, EWFD_PTX_FORMAT);
    if (test_for_directory(preview_file) == EISDIR) {
        SetWindowText(cur_ctrl, _T("directory"));
        return FALSE;
    }

    wth = wtap_open_offline(preview_file, WTAP_TYPE_AUTO, &err, &err_info, TRUE);
    if (cur_ctrl && wth == NULL) {
        if(err == WTAP_ERR_FILE_UNKNOWN_FORMAT) {
            SetWindowText(cur_ctrl, _T("unknown file format"));
        } else {
            SetWindowText(cur_ctrl, _T("error opening file"));
        }
        return FALSE;
    }

    /* Success! */
    for (i = EWFD_PT_FORMAT; i <= EWFD_PTX_START_ELAPSED; i++) {
        cur_ctrl = GetDlgItem(of_hwnd, i);
        if (cur_ctrl) {
            EnableWindow(cur_ctrl, TRUE);
        }
    }

    /* Format */
    cur_ctrl = GetDlgItem(of_hwnd, EWFD_PTX_FORMAT);
    SetWindowText(cur_ctrl, utf_8to16(wtap_file_type_subtype_string(wtap_file_type_subtype(wth))));

    /* Size */
    filesize = wtap_file_size(wth, &err);
    // Windows Explorer uses IEC.
    size_str = format_size(filesize, format_size_unit_bytes|format_size_prefix_iec);

    status = get_stats_for_preview(wth, &stats, &err, &err_info);

    if(status == PREVIEW_READ_ERROR) {
        /* XXX - give error details? */
        g_free(err_info);
        utf_8to16_snprintf(string_buff, PREVIEW_STR_MAX, "%s, error after %u records",
            size_str, stats.records);
        g_free(size_str);
        cur_ctrl = GetDlgItem(of_hwnd, EWFD_PTX_SIZE);
        SetWindowText(cur_ctrl, string_buff);
        wtap_close(wth);
        return TRUE;
    }

    /* Packet count */
    if(status == PREVIEW_TIMED_OUT) {
        utf_8to16_snprintf(string_buff, PREVIEW_STR_MAX, "%s, timed out at %u data records",
            size_str, stats.data_records);
    } else {
        utf_8to16_snprintf(string_buff, PREVIEW_STR_MAX, "%s, %u data records",
            size_str, stats.data_records);
    }
    g_free(size_str);
    cur_ctrl = GetDlgItem(of_hwnd, EWFD_PTX_SIZE);
    SetWindowText(cur_ctrl, string_buff);

    /* First packet / elapsed time */
    if(stats.have_times) {
        /*
         * We saw at least one record with a time stamp, so we can give
         * a start time (if we have a mix of records with and without
         * time stamps, and there were records without time stamps
         * before the one with a time stamp, this may be inaccurate).
         */
        ti_time = (long)stats.start_time;
        ti_tm = localtime( &ti_time );
        if(ti_tm) {
            StringCchPrintf(first_buff, PREVIEW_STR_MAX,
                     _T("%04d-%02d-%02d %02d:%02d:%02d"),
                     ti_tm->tm_year + 1900,
                     ti_tm->tm_mon + 1,
                     ti_tm->tm_mday,
                     ti_tm->tm_hour,
                     ti_tm->tm_min,
                     ti_tm->tm_sec);
        } else {
            StringCchPrintf(first_buff, PREVIEW_STR_MAX, _T("?"));
        }
    } else {
        StringCchPrintf(first_buff, PREVIEW_STR_MAX, _T("unknown"));
    }

    /* Elapsed time */
    if(status == PREVIEW_SUCCEEDED && stats.have_times) {
        /*
         * We didn't time out, so we looked at all packets, and we got
         * at least one packet with a time stamp, so we can calculate
         * an elapsed time from the time stamp of the last packet with
         * with a time stamp (if we have a mix of records with and without
         * time stamps, and there were records without time stamps after
         * the last one with a time stamp, this may be inaccurate).
         */
        elapsed_time = (unsigned int)(stats.stop_time-stats.start_time);
        if(status == PREVIEW_TIMED_OUT) {
            StringCchPrintf(string_buff, PREVIEW_STR_MAX, _T("%s / unknown"), first_buff);
        } else if(elapsed_time/86400) {
            StringCchPrintf(string_buff, PREVIEW_STR_MAX, _T("%s / %02u days %02u:%02u:%02u"),
                first_buff, elapsed_time/86400, elapsed_time%86400/3600, elapsed_time%3600/60, elapsed_time%60);
        } else {
            StringCchPrintf(string_buff, PREVIEW_STR_MAX, _T("%s / %02u:%02u:%02u"),
                first_buff, elapsed_time%86400/3600, elapsed_time%3600/60, elapsed_time%60);
        }
    } else {
        StringCchPrintf(string_buff, PREVIEW_STR_MAX, _T("%s / unknown"),
            first_buff);
    }
    cur_ctrl = GetDlgItem(of_hwnd, EWFD_PTX_START_ELAPSED);
    SetWindowText(cur_ctrl, string_buff);

    wtap_close(wth);

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
    } else if (dfilter_compile(utf_16to8(strval), &dfp, NULL)) { /* colorize filter string entry */
        dfilter_free(dfp);
        /* Valid (light green) */
        SendMessage(hwnd, EM_SETBKGNDCOLOR, 0, RGB(0xe4, 0xff, 0xc7)); /* tango_chameleon_1 */
    } else {
        /* Invalid (light red) */
        SendMessage(hwnd, EM_SETBKGNDCOLOR, 0, RGB(0xff, 0xcc, 0xcc)); /* tango_scarlet_red_1 */
    }

    g_free(strval);
}

static gint alpha_sort(gconstpointer a, gconstpointer b)
{
    return g_ascii_strcasecmp(*(const char **)a, *(const char **)b);
}

static UINT_PTR CALLBACK
open_file_hook_proc(HWND of_hwnd, UINT msg, WPARAM w_param, LPARAM l_param) {
    HWND      cur_ctrl, parent;
    OFNOTIFY *notify = (OFNOTIFY *) l_param;
    TCHAR     sel_name[MAX_PATH];
    gint      i;

    switch(msg) {
        case WM_INITDIALOG:
            /* Retain the filter text, and fill it in. */
            if(g_dfilter_str != NULL) {
                cur_ctrl = GetDlgItem(of_hwnd, EWFD_FILTER_EDIT);
                SetWindowText(cur_ctrl, utf_8to16(g_dfilter_str));
            }

            /* Put Auto, as well as pcap and pcapng (which are the first two entries in
               open_routines), at the top of the file type list. */
            cur_ctrl = GetDlgItem(of_hwnd, EWFD_FORMAT_TYPE);
            SendMessage(cur_ctrl, CB_ADDSTRING, 0, (WPARAM) _T("Automatically detect file type"));
            for (i = 0; i < 2; i += 1) {
                SendMessage(cur_ctrl, CB_ADDSTRING, 0, (WPARAM) utf_8to16(open_routines[i].name));
            }
            /* Generate a sorted list of the remaining file types.
               The magic number 60 is a rough starting point for how big the
               GPtrArray should start. It'll automatically grow if needed, so
               the exact number isn't critical. (This is good, because we don't have
               an easy way to get the exact number.) */
            GPtrArray *routine_names = g_ptr_array_sized_new(60);
            for ( /* keep using i */ ; open_routines[i].name != NULL; i += 1) {
                g_ptr_array_add(routine_names, (gpointer)open_routines[i].name);
            }
            g_ptr_array_sort(routine_names, alpha_sort);
            for (guint i = 0; i < routine_names->len; i += 1) {
                SendMessage(cur_ctrl, CB_ADDSTRING, 0, (WPARAM) utf_8to16((const char *)g_ptr_array_index(routine_names, i)));
            }
            g_ptr_array_free(routine_names, TRUE);
            SendMessage(cur_ctrl, CB_SETCURSEL, 0, 0);

            preview_set_file_info(of_hwnd, NULL);
            break;
        case WM_NOTIFY:
            switch (notify->hdr.code) {
                case CDN_FILEOK:
                    /* Fetch the read filter */
                    cur_ctrl = GetDlgItem(of_hwnd, EWFD_FILTER_EDIT);
                    g_free(g_dfilter_str);
                    g_dfilter_str = filter_tb_get(cur_ctrl);

                    cur_ctrl = GetDlgItem(of_hwnd, EWFD_FORMAT_TYPE);
                    g_format_type = (unsigned int) SendMessage(cur_ctrl, CB_GETCURSEL, 0, 0);

                    /* The list of file formats is sorted. Get the format by name. */
                    guint label_len;
                    label_len = (guint) SendMessage(cur_ctrl, CB_GETLBTEXTLEN, (WPARAM) g_format_type, 0);
                    if (label_len != CB_ERR) {
                        TCHAR *label = g_malloc((label_len+1)*sizeof(TCHAR));
                        SendMessage(cur_ctrl, CB_GETLBTEXT, (WPARAM) g_format_type, (LPARAM) label);
                        g_format_type = open_info_name_to_type(utf_16to8(label));
                        g_free(label);
                    }
                    else {
                        /* Problem, fall back on automatic */
                        g_format_type = WTAP_TYPE_AUTO;
                    }

                    break;
                case CDN_SELCHANGE:
                    /* This _almost_ works correctly. We need to handle directory
                       selections, etc. */
                    parent = GetParent(of_hwnd);
                    CommDlg_OpenSave_GetFilePath(parent, sel_name, MAX_PATH);
                    preview_set_file_info(of_hwnd, utf_16to8(sel_name));
                    break;
                case CDN_HELP:
                    topic_action(HELP_OPEN_WIN32_DIALOG);
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

/* Generate a list of the file types we can filter for in the open dialog. */
static void
append_file_extension_type(GArray *sa, int et)
{
    GString* pattern_str = g_string_new("");
    GString* description_str = g_string_new("");
    gchar sep;
    GSList *extensions_list, *extension;
    const TCHAR *str16;
    guint16 zero = 0;

    /* Construct the list of patterns. */
    extensions_list = wtap_get_file_extension_type_extensions(et);
    g_string_printf(pattern_str, "");
    sep = '\0';
    for (extension = extensions_list; extension != NULL;
         extension = g_slist_next(extension)) {
        if (sep != '\0')
            g_string_append_c(pattern_str, sep);
        g_string_append_printf(pattern_str, "*.%s", (char *)extension->data);
        sep = ';';
    }
    wtap_free_extensions_list(extensions_list);

    /* Construct the description. */
    g_string_printf(description_str, "%s (%s)",
                    wtap_get_file_extension_type_name(et),
                    pattern_str->str);
    str16 = utf_8to16(description_str->str);
    sa = g_array_append_vals(sa, str16, (guint) strlen(description_str->str));
    sa = g_array_append_val(sa, zero);
    g_string_free(description_str, TRUE);

    str16 = utf_8to16(pattern_str->str);
    sa = g_array_append_vals(sa, str16, (guint) strlen(pattern_str->str));
    sa = g_array_append_val(sa, zero);
    g_string_free(pattern_str, TRUE);
}

static TCHAR *
build_file_open_type_list(void) {
    const TCHAR *str16;
    int et;
    GArray* sa;
    static const guint16 zero = 0;
    GString* pattern_str;
    gchar sep;
    GSList *extensions_list, *extension;

    /*
     * Microsoft's UI guidelines say, of the file filters in open and
     * save dialogs:
     *
     *    For meta-filters, remove the file extension list to eliminate
     *    clutter. Examples: "All files," "All pictures," "All music,"
     *    and "All videos."
     *
     * so we omit them (for "All Capture Files", the filter would be
     * *really* long).  On both Windows XP and Windows 7, Wordpad doesn't
     * do that, but Paint does.
     */

    /*
     * Array of hexadectets used as a sequence of null-terminated
     * UTF-16 strings.
     */
    sa = g_array_new(FALSE /*zero_terminated*/, FALSE /*clear_*/,2 /*element_size*/);

    /* Add the "All Files" entry. */
    str16 = utf_8to16("All Files");
    sa = g_array_append_vals(sa, str16, (guint) strlen("All Files"));
    sa = g_array_append_val(sa, zero);
    str16 = utf_8to16(ALL_FILES_WILDCARD);
    sa = g_array_append_vals(sa, str16, (guint) strlen(ALL_FILES_WILDCARD));
    sa = g_array_append_val(sa, zero);

    /*
     * Add an "All Capture Files" entry, with all the capture file
     * extensions we know about.
     */
    str16 = utf_8to16("All Capture Files");
    sa = g_array_append_vals(sa, str16, (guint) strlen("All Capture Files"));
    sa = g_array_append_val(sa, zero);

    /*
     * Construct its list of patterns.
     */
    pattern_str = g_string_new("");
    extensions_list = wtap_get_all_capture_file_extensions_list();
    sep = '\0';
    for (extension = extensions_list; extension != NULL;
         extension = g_slist_next(extension)) {
        if (sep != '\0')
            g_string_append_c(pattern_str, sep);
        g_string_append_printf(pattern_str, "*.%s", (char *)extension->data);
        sep = ';';
    }
    wtap_free_extensions_list(extensions_list);
    str16 = utf_8to16(pattern_str->str);
    sa = g_array_append_vals(sa, str16, (guint) strlen(pattern_str->str));
    sa = g_array_append_val(sa, zero);

    /* Include all the file type extensions Wireshark supports. */
    for (et = 0; et < wtap_get_num_file_type_extensions(); et++) {
        append_file_extension_type(sa, et);
    }

    /* terminate the array */
    sa = g_array_append_val(sa, zero);

    return (TCHAR *) g_array_free(sa, FALSE /*free_segment*/);
}

/* Generate a list of the file types we can save this file as.

   "g_filetype" is the type it has now.

   "encap" is the encapsulation for its packets (which could be
   "unknown" or "per-packet").

   "filtered" is TRUE if we're to save only the packets that passed
   the display filter (in which case we have to save it using Wiretap)
   and FALSE if we're to save the entire file (in which case, if we're
   saving it in the type it has already, we can just copy it).

   The same applies for sel_curr, sel_all, sel_m_only, sel_m_range and sel_man_range
*/
static void
append_file_type(GArray *sa, int ft)
{
    GString* pattern_str = g_string_new("");
    GString* description_str = g_string_new("");
    gchar sep;
    GSList *extensions_list, *extension;
    const TCHAR *str16;
    guint16 zero = 0;

    extensions_list = wtap_get_file_extensions_list(ft, TRUE);
    if (extensions_list == NULL) {
        /* This file type doesn't have any particular extension
           conventionally used for it, so we'll just use a
           wildcard that matches all file names - even those with
           no extension, so we don't need to worry about compressed
           file extensions. */
           g_string_printf(pattern_str, ALL_FILES_WILDCARD);
    } else {
        /* Construct the list of patterns. */
        g_string_printf(pattern_str, "");
        sep = '\0';
        for (extension = extensions_list; extension != NULL;
             extension = g_slist_next(extension)) {
            if (sep != '\0')
                g_string_append_c(pattern_str, sep);
            g_string_append_printf(pattern_str, "*.%s", (char *)extension->data);
            sep = ';';
        }
        wtap_free_extensions_list(extensions_list);
    }

    /* Construct the description. */
    g_string_printf(description_str, "%s (%s)", wtap_file_type_subtype_string(ft),
                    pattern_str->str);
    str16 = utf_8to16(description_str->str);
    sa = g_array_append_vals(sa, str16, (guint) strlen(description_str->str));
    sa = g_array_append_val(sa, zero);
    g_string_free(description_str, TRUE);

    str16 = utf_8to16(pattern_str->str);
    sa = g_array_append_vals(sa, str16, (guint) strlen(pattern_str->str));
    sa = g_array_append_val(sa, zero);
    g_string_free(pattern_str, TRUE);
}

static TCHAR *
build_file_save_type_list(GArray *savable_file_types) {
    guint i;
    int   ft;
    GArray* sa = g_array_new(FALSE /*zero_terminated*/, FALSE /*clear_*/,2 /*element_size*/);
    guint16 zero = 0;

    /* Get only the file types as which we can save this file. */
    for (i = 0; i < savable_file_types->len; i++) {
        ft = g_array_index(savable_file_types, int, i);
        append_file_type(sa, ft);
    }

    /* terminate the array */
    sa = g_array_append_val(sa, zero);

    return (TCHAR *) g_array_free(sa, FALSE /*free_segment*/);
}

static UINT_PTR CALLBACK
save_as_file_hook_proc(HWND sf_hwnd, UINT msg, WPARAM w_param _U_, LPARAM l_param) {
    HWND           cur_ctrl;
    OFNOTIFY      *notify = (OFNOTIFY *) l_param;
    /*int            new_filetype, file_index;*/

    switch(msg) {
        case WM_INITDIALOG: {
            OPENFILENAME *ofnp = (OPENFILENAME *) l_param;
            capture_file *cf = (capture_file *) ofnp->lCustData;
            g_sf_hwnd = sf_hwnd;

            /* Default to saving in the file's current format. */
            g_filetype = cf->cd_t;

            /* Fill in the file format list */
            /*build_file_format_list(sf_hwnd);*/
            /* Fill in the compression checkbox */
            cur_ctrl = GetDlgItem(sf_hwnd, EWFD_GZIP_CB);
            SendMessage(cur_ctrl, BM_SETCHECK, g_compressed, 0);

            break;
        }
        case WM_COMMAND:
            break;
        case WM_NOTIFY:
            switch (notify->hdr.code) {
                case CDN_HELP:
                    topic_action(HELP_SAVE_WIN32_DIALOG);
                    break;
                case CDN_FILEOK: {
                    HWND   parent;
                    char  *file_name8;
                    OPENFILENAME *ofnp = (OPENFILENAME *) notify->lpOFN;
                    capture_file *cf = (capture_file *) ofnp->lCustData;

                    /* Fetch our compression value */
                    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_GZIP_CB);
                    if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED)
                        g_compressed = TRUE;
                    else
                        g_compressed = FALSE;

                    /* Check if we're trying to overwrite the currently open file */
                    parent = GetParent(sf_hwnd);
                    file_name8 = utf_16to8(notify->lpOFN->lpstrFile);
                    if (files_identical(cf->filename, file_name8)) {
                        /* XXX: Is MessageBox the best way to pop up an error ? How to make text bold ? */
                        gchar *str = g_strdup_printf(
                            "Capture File \"%s\" identical to loaded file.\n\n"
                            "Please choose a different filename.",
                            file_name8);
                        MessageBox( parent, utf_8to16(str), _T("Error"), MB_ICONERROR | MB_APPLMODAL | MB_OK);
                        g_free(str);
                        SetWindowLongPtr(sf_hwnd, DWLP_MSGRESULT, 1L); /* Don't allow ! */
                        return 1;
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

#define RANGE_TEXT_MAX 128
static UINT_PTR CALLBACK
export_specified_packets_file_hook_proc(HWND sf_hwnd, UINT msg, WPARAM w_param, LPARAM l_param) {
    HWND           cur_ctrl;
    OFNOTIFY      *notify = (OFNOTIFY *) l_param;
    /*int            new_filetype, file_index;*/

    switch(msg) {
        case WM_INITDIALOG: {
            g_sf_hwnd = sf_hwnd;

            /* Default to saving all packets, in the file's current format. */
            g_filetype = g_cf->cd_t;

            /* Fill in the file format list */
            /*build_file_format_list(sf_hwnd);*/

            range_handle_wm_initdialog(sf_hwnd, g_range);

            /* Fill in the compression checkbox */
            cur_ctrl = GetDlgItem(sf_hwnd, EWFD_GZIP_CB);
            SendMessage(cur_ctrl, BM_SETCHECK, g_compressed, 0);

            break;
        }
        case WM_COMMAND:
            cur_ctrl = (HWND) l_param;
            range_handle_wm_command(sf_hwnd, cur_ctrl, w_param, g_range);
            break;
        case WM_NOTIFY:
            switch (notify->hdr.code) {
                case CDN_HELP:
                    topic_action(HELP_SAVE_WIN32_DIALOG);
                    break;
                case CDN_FILEOK: {
                    HWND   parent;
                    char  *file_name8;
                    OPENFILENAME *ofnp = (OPENFILENAME *) notify->lpOFN;
                    capture_file *cf = (capture_file *) ofnp->lCustData;

                    /* Fetch our compression value */
                    cur_ctrl = GetDlgItem(sf_hwnd, EWFD_GZIP_CB);
                    if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED)
                        g_compressed = TRUE;
                    else
                        g_compressed = FALSE;

                    /* Check if we're trying to overwrite the currently open file */
                    parent = GetParent(sf_hwnd);
                    file_name8 = utf_16to8(notify->lpOFN->lpstrFile);
                    if (files_identical(cf->filename, file_name8)) {
                        /* XXX: Is MessageBox the best way to pop up an error ? How to make text bold ? */
                        gchar *str = g_strdup_printf(
                            "Capture File \"%s\" identical to loaded file.\n\n"
                            "Please choose a different filename.",
                            file_name8);
                        MessageBox( parent, utf_8to16(str), _T("Error"), MB_ICONERROR | MB_APPLMODAL | MB_OK);
                        g_free(str);
                        SetWindowLongPtr(sf_hwnd, DWLP_MSGRESULT, 1L); /* Don't allow ! */
                        return 1;
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
    guint32  ignored_cnt = 0, displayed_ignored_cnt = 0;
    guint32  displayed_cnt;
    gboolean range_valid = TRUE;

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_DISPLAYED_BTN);
    if (SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED)
        filtered_active = TRUE;

    /* RANGE_SELECT_ALL */
    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_ALL_PKTS_CAP);
    EnableWindow(cur_ctrl, !filtered_active);
    if (range->remove_ignored) {
        StringCchPrintf(static_val, STATIC_LABEL_CHARS, _T("%u"), g_cf->count - range->ignored_cnt);
    } else {
        StringCchPrintf(static_val, STATIC_LABEL_CHARS, _T("%u"), g_cf->count);
    }
    SetWindowText(cur_ctrl, static_val);

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_ALL_PKTS_DISP);
    EnableWindow(cur_ctrl, filtered_active);
    if (range->include_dependents)
      displayed_cnt = range->displayed_plus_dependents_cnt;
    else
      displayed_cnt = range->displayed_cnt;
    if (range->remove_ignored) {
        StringCchPrintf(static_val, STATIC_LABEL_CHARS, _T("%u"), displayed_cnt - range->displayed_ignored_cnt);
    } else {
        StringCchPrintf(static_val, STATIC_LABEL_CHARS, _T("%u"), displayed_cnt);
    }
    SetWindowText(cur_ctrl, static_val);

    /* RANGE_SELECT_CURR */
    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_SEL_PKT_CAP);
    EnableWindow(cur_ctrl, range->selection_range_cnt > 0 && !filtered_active);
    if (range->remove_ignored) {
        StringCchPrintf(static_val, STATIC_LABEL_CHARS, _T("%d"), range->selection_range_cnt - range->ignored_selection_range_cnt);
    } else {
        StringCchPrintf(static_val, STATIC_LABEL_CHARS, _T("%d"), range->selection_range_cnt);
    }
    SetWindowText(cur_ctrl, static_val);

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_SEL_PKT_DISP);
    EnableWindow(cur_ctrl, range->displayed_selection_range_cnt > 0 && filtered_active);
    if (range->remove_ignored) {
        StringCchPrintf(static_val, STATIC_LABEL_CHARS, _T("%d"), range->displayed_selection_range_cnt - range->displayed_ignored_selection_range_cnt);
    } else {
        StringCchPrintf(static_val, STATIC_LABEL_CHARS, _T("%d"), range->displayed_selection_range_cnt);
    }
    SetWindowText(cur_ctrl, static_val);

    /* RANGE_SELECT_MARKED */
    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_MARKED_BTN);
    EnableWindow(cur_ctrl, g_cf->marked_count);

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_MARKED_CAP);
    EnableWindow(cur_ctrl, g_cf->marked_count && !filtered_active);
    if (range->remove_ignored) {
        StringCchPrintf(static_val, STATIC_LABEL_CHARS, _T("%u"), g_cf->marked_count - range->ignored_marked_cnt);
    } else {
        StringCchPrintf(static_val, STATIC_LABEL_CHARS, _T("%u"), g_cf->marked_count);
    }
    SetWindowText(cur_ctrl, static_val);

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_MARKED_DISP);
    EnableWindow(cur_ctrl, g_cf->marked_count && filtered_active);
    if (range->remove_ignored) {
        StringCchPrintf(static_val, STATIC_LABEL_CHARS, _T("%u"), range->displayed_marked_cnt - range->displayed_ignored_marked_cnt);
    } else {
        StringCchPrintf(static_val, STATIC_LABEL_CHARS, _T("%u"), range->displayed_marked_cnt);
    }
    SetWindowText(cur_ctrl, static_val);

    /* RANGE_SELECT_MARKED_RANGE */
    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_FIRST_LAST_BTN);
    EnableWindow(cur_ctrl, range->mark_range_cnt);

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_FIRST_LAST_CAP);
    EnableWindow(cur_ctrl, range->mark_range_cnt && !filtered_active);
    if (range->remove_ignored) {
        StringCchPrintf(static_val, STATIC_LABEL_CHARS, _T("%u"), range->mark_range_cnt - range->ignored_mark_range_cnt);
    } else {
        StringCchPrintf(static_val, STATIC_LABEL_CHARS, _T("%u"), range->mark_range_cnt);
    }
    SetWindowText(cur_ctrl, static_val);

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_FIRST_LAST_DISP);
    EnableWindow(cur_ctrl, range->displayed_mark_range_cnt && filtered_active);
    if (range->remove_ignored) {
        StringCchPrintf(static_val, STATIC_LABEL_CHARS, _T("%u"), range->displayed_mark_range_cnt - range->displayed_ignored_mark_range_cnt);
    } else {
        StringCchPrintf(static_val, STATIC_LABEL_CHARS, _T("%u"), range->displayed_mark_range_cnt);
    }
    SetWindowText(cur_ctrl, static_val);

    /* RANGE_SELECT_USER */
    switch (packet_range_check(range)) {
        case CVT_NO_ERROR:
            cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_RANGE_EDIT);
            SendMessage(cur_ctrl, EM_SETBKGNDCOLOR, (WPARAM) 1, COLOR_WINDOW);

            cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_RANGE_CAP);
            EnableWindow(cur_ctrl, !filtered_active);
            if (range->remove_ignored) {
                StringCchPrintf(static_val, STATIC_LABEL_CHARS, _T("%u"), range->user_range_cnt - range->ignored_user_range_cnt);
            } else {
                StringCchPrintf(static_val, STATIC_LABEL_CHARS, _T("%u"), range->user_range_cnt);
            }
            SetWindowText(cur_ctrl, static_val);

            cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_RANGE_DISP);
            EnableWindow(cur_ctrl, filtered_active);
            if (range->remove_ignored) {
                StringCchPrintf(static_val, STATIC_LABEL_CHARS, _T("%u"), range->displayed_user_range_cnt - range->displayed_ignored_user_range_cnt);
            } else {
                StringCchPrintf(static_val, STATIC_LABEL_CHARS, _T("%u"), range->displayed_user_range_cnt);
            }
            SetWindowText(cur_ctrl, static_val);
            break;
        case CVT_SYNTAX_ERROR:
            if (range->process == range_process_user_range) range_valid = FALSE;
            cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_RANGE_EDIT);
            SendMessage(cur_ctrl, EM_SETBKGNDCOLOR, 0, RGB(0xff, 0xcc, 0xcc));
            cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_RANGE_CAP);
            SetWindowText(cur_ctrl, _T("Bad range"));
            cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_RANGE_DISP);
            SetWindowText(cur_ctrl, _T("-"));
            break;
        case CVT_NUMBER_TOO_BIG:
            if (range->process == range_process_user_range) range_valid = FALSE;
            cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_RANGE_EDIT);
            SendMessage(cur_ctrl, EM_SETBKGNDCOLOR, 0, RGB(0xff, 0xcc, 0xcc));
            cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_RANGE_CAP);
            SetWindowText(cur_ctrl, _T("Too large"));
            cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_RANGE_DISP);
            SetWindowText(cur_ctrl, _T("-"));
           break;

        default:
            g_assert_not_reached();
    }

    /* RANGE_REMOVE_IGNORED_PACKETS */
    switch(range->process) {
        case(range_process_all):
            ignored_cnt = range->ignored_cnt;
            displayed_ignored_cnt = range->displayed_ignored_cnt;
            break;
        case(range_process_selected):
            ignored_cnt = range->ignored_selection_range_cnt;
            displayed_ignored_cnt = range->displayed_ignored_selection_range_cnt;
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
    StringCchPrintf(static_val, STATIC_LABEL_CHARS, _T("%u"), ignored_cnt);
    SetWindowText(cur_ctrl, static_val);

    cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_IGNORED_DISP);
    EnableWindow(cur_ctrl, displayed_ignored_cnt && filtered_active);
    StringCchPrintf(static_val, STATIC_LABEL_CHARS, _T("%u"), displayed_ignored_cnt);
    SetWindowText(cur_ctrl, static_val);

    cur_ctrl = GetDlgItem(GetParent(dlg_hwnd), IDOK);
    EnableWindow(cur_ctrl, range_valid);
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

    /* Retain the filter text, and fill it in. */
    if(range->user_range != NULL) {
        char* tmp_str;
        cur_ctrl = GetDlgItem(dlg_hwnd, EWFD_RANGE_EDIT);
        tmp_str = range_convert_range(NULL, range->user_range);
        SetWindowText(cur_ctrl, utf_8to16(tmp_str));
        wmem_free(NULL, tmp_str);
    }

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

    if (!range) return;

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
        case (EN_UPDATE << 16) | EWFD_RANGE_EDIT:
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

static UINT_PTR CALLBACK
merge_file_hook_proc(HWND mf_hwnd, UINT msg, WPARAM w_param, LPARAM l_param) {
    HWND      cur_ctrl, parent;
    OFNOTIFY *notify = (OFNOTIFY *) l_param;
    TCHAR     sel_name[MAX_PATH];

    switch(msg) {
        case WM_INITDIALOG:
            /* Retain the filter text, and fill it in. */
            if(g_dfilter_str != NULL) {
                cur_ctrl = GetDlgItem(mf_hwnd, EWFD_FILTER_EDIT);
                SetWindowText(cur_ctrl, utf_8to16(g_dfilter_str));
            }

            /* Chrono by default */
            cur_ctrl = GetDlgItem(mf_hwnd, EWFD_MERGE_CHRONO_BTN);
            SendMessage(cur_ctrl, BM_SETCHECK, TRUE, 0);
            g_merge_action = merge_append;

            preview_set_file_info(mf_hwnd, NULL);
            break;
        case WM_NOTIFY:
            switch (notify->hdr.code) {
                case CDN_FILEOK:
                    /* Fetch the read filter */
                    cur_ctrl = GetDlgItem(mf_hwnd, EWFD_FILTER_EDIT);
                    g_free(g_dfilter_str);
                    g_dfilter_str = filter_tb_get(cur_ctrl);

                    cur_ctrl = GetDlgItem(mf_hwnd, EWFD_MERGE_CHRONO_BTN);
                    if(SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                        g_merge_action = merge_chrono;
                    } else {
                        cur_ctrl = GetDlgItem(mf_hwnd, EWFD_MERGE_PREPEND_BTN);
                        if(SendMessage(cur_ctrl, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                            g_merge_action = merge_prepend;
                        }
                    }

                    break;
                case CDN_SELCHANGE:
                    /* This _almost_ works correctly.  We need to handle directory
                       selections, etc. */
                    parent = GetParent(mf_hwnd);
                    CommDlg_OpenSave_GetFilePath(parent, sel_name, MAX_PATH);
                    preview_set_file_info(mf_hwnd, utf_16to8(sel_name));
                    break;
                case CDN_HELP:
                    topic_action(HELP_MERGE_WIN32_DIALOG);
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


static UINT_PTR CALLBACK
export_file_hook_proc(HWND ef_hwnd, UINT msg, WPARAM w_param, LPARAM l_param) {
    HWND           cur_ctrl;
    OFNOTIFY      *notify = (OFNOTIFY *) l_param;
    gboolean       pkt_fmt_enable;
    int            i, filter_index;

    switch(msg) {
        case WM_INITDIALOG: {
            /* default to displayed packets */
            print_args.range.process_filtered = TRUE;
            range_handle_wm_initdialog(ef_hwnd, &print_args.range);
            format_handle_wm_initdialog(ef_hwnd, &print_args);

            break;
        }
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
                    filter_index = notify->lpOFN->nFilterIndex;

                    if (filter_index == 2)     /* PostScript */
                        print_args.format = PR_FMT_TEXT;
                    else
                        print_args.format = PR_FMT_PS;
                    if (filter_index == 3 || filter_index == 4 || filter_index == 5 || filter_index == 6)
                        pkt_fmt_enable = FALSE;
                    else
                        pkt_fmt_enable = TRUE;
                    for (i = EWFD_PKT_FORMAT_GB; i <= EWFD_PKT_NEW_PAGE_CB; i++) {
                        cur_ctrl = GetDlgItem(ef_hwnd, i);
                        EnableWindow(cur_ctrl, pkt_fmt_enable);
                    }
                    break;
                case CDN_HELP:
                    topic_action(HELP_EXPORT_FILE_WIN32_DIALOG);
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
