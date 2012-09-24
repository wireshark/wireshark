/* file_dlg_win32.h
 * Native Windows file dialog routines
 *
 * $Id$
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

#ifndef __FILE_DLG_WIN32_H__
#define __FILE_DLG_WIN32_H__

#include "ui/file_dialog.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {
    export_type_text = 1,
    export_type_ps,
    export_type_csv,
    export_type_psml,
    export_type_pdml,
    export_type_carrays
} export_type_e;

/** Open the "Open" dialog box.
 *
 * @param h_wnd HWND of the parent window.
 */
gboolean win32_open_file (HWND h_wnd, GString *file_name, GString *display_filter);

/** Verify that our proposed capture file format supports comments. If it can't
 *  ask the user what to do and return his or her response.
 *
 * @param h_wnd HWND of the parent window.
 * @param cf Capture file.
 * @param file_format Proposed file format.
 *
 * @return
 */
check_savability_t win32_check_save_as_with_comments(HWND parent, capture_file *cf, int file_type);

/** Open the "Save As" dialog box.
 *
 * @param h_wnd HWND of the parent window.
 * @param cf capture_file structure for the capture to be saved
 * @param must_support_comments TRUE if the file format list should
 * include only file formats that support comments
 * @param dont_reopen TRUE if the file is to be closed after it's
 * saved, so we don't need to reopen it after saving it
 *
 * @return TRUE if packets were discarded when saving, FALSE otherwise
 */
gboolean win32_save_as_file(HWND h_wnd, capture_file *cf,
                            GString *file_name, int *file_type,
                            gboolean *compressed,
                            gboolean must_support_comments);

/** Open the "Export Specified Packets" dialog box.
 *
 * @param h_wnd HWND of the parent window.
 */
void win32_export_specified_packets_file(HWND h_wnd);

/** Open the "Merge" dialog box.
 *
 * @param h_wnd HWND of the parent window.
 */
gboolean win32_merge_file (HWND h_wnd, GString *file_name, GString *display_filter, int *merge_type);

/** Open the "Export" dialog box.
 *
 * @param h_wnd HWND of the parent window.
 * @param export_type The export type.
 */
void win32_export_file (HWND h_wnd, export_type_e export_type);

/** Open the "Export raw bytes" dialog box.
 *
 * @param h_wnd HWND of the parent window.
 */
void win32_export_raw_file (HWND h_wnd);

/** Open the "Export SSL Session Keys" dialog box.
 *
 * @param h_wnd HWND of the parent window.
 */
void win32_export_sslkeys_file (HWND h_wnd);

/** Open the "Export Color Filters" dialog box
 *
 * @param h_wnd HWND of the parent window
 * @param filter_list the list to export
 */
void win32_export_color_file(HWND h_wnd, gpointer filter_list);

/** Open the "Import Color Filters" dialog box
 *
 * @param h_wnd HWND of the parent window
 * @param color_filters the calling widget
 */
void win32_import_color_file(HWND h_wnd, gpointer color_filters);

void file_set_save_marked_sensitive();

/* Open dialog defines */
/* #define EWFD_FILTER_BTN    1000 */
#define EWFD_FILTER_LBL    1000
#define EWFD_FILTER_EDIT   1001

#define EWFD_MAC_NR_CB     1002
#define EWFD_NET_NR_CB     1003
#define EWFD_TRANS_NR_CB   1004
#define EWFD_EXTERNAL_NR_CB   1005

/* Note: The preview title (PT) and text (PTX) MUST have sequential IDs;
   they're used in a for loop. EWFD_PT_FILENAME MUST be first, and
   EWFD_PTX_ELAPSED MUST be last.  (so why don't we just use an enum? */
#define EWFD_PT_FORMAT     1006
#define EWFD_PT_SIZE       1007
#define EWFD_PT_PACKETS    1008
#define EWFD_PT_FIRST_PKT  1009
#define EWFD_PT_ELAPSED    1010

#define EWFD_PTX_FORMAT    1011
#define EWFD_PTX_SIZE      1012
#define EWFD_PTX_PACKETS   1013
#define EWFD_PTX_FIRST_PKT 1014
#define EWFD_PTX_ELAPSED   1015

/* Save as dialog defines */
#define EWFD_GZIP_CB     1000

/* Export dialog defines */
#define EWFD_CAPTURED_BTN    1000
#define EWFD_DISPLAYED_BTN   1001
#define EWFD_ALL_PKTS_BTN    1002
#define EWFD_SEL_PKT_BTN     1003
#define EWFD_MARKED_BTN      1004
#define EWFD_FIRST_LAST_BTN  1005
#define EWFD_RANGE_BTN       1006
#define EWFD_RANGE_EDIT      1007
#define EWFD_REMOVE_IGN_CB   1008

#define EWFD_ALL_PKTS_CAP    1009
#define EWFD_SEL_PKT_CAP     1010
#define EWFD_MARKED_CAP      1011
#define EWFD_FIRST_LAST_CAP  1012
#define EWFD_RANGE_CAP       1013
#define EWFD_IGNORED_CAP     1014

#define EWFD_ALL_PKTS_DISP   1015
#define EWFD_SEL_PKT_DISP    1016
#define EWFD_MARKED_DISP     1017
#define EWFD_FIRST_LAST_DISP 1018
#define EWFD_RANGE_DISP      1019
#define EWFD_IGNORED_DISP    1020

/* Export raw dialog defines. */
#define EWFD_EXPORTRAW_ST 1000

/* Export SSL Session Keys dialog defines. */
#define EWFD_EXPORTSSLKEYS_ST 1000

/* Merge dialog defines.  Overlays Open dialog defines above. */
#define EWFD_MERGE_PREPEND_BTN 1050
#define EWFD_MERGE_CHRONO_BTN  1051
#define EWFD_MERGE_APPEND_BTN  1052

/* Export dialog defines.  Overlays Save dialog defines above. */
/* These MUST be contiguous */
#define EWFD_PKT_FORMAT_GB    1050
#define EWFD_PKT_SUMMARY_CB   1051
#define EWFD_PKT_DETAIL_CB    1052
#define EWFD_PKT_DETAIL_COMBO 1053
#define EWFD_PKT_BYTES_CB     1054
#define EWFD_PKT_NEW_PAGE_CB  1055

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FILE_DLG_WIN32_H__ */
