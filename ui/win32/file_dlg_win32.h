/* file_dlg_win32.h
 * Native Windows file dialog routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2006 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __FILE_DLG_WIN32_H__
#define __FILE_DLG_WIN32_H__

#ifndef RC_INVOKED // RC warns about gatomic's long identifiers.
#include "ui/file_dialog.h"
#include "ui/packet_range.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief set_thread_per_monitor_v2_awareness
 *
 * Qt <= 5.9 supports setting old (Windows 8.1) per-monitor DPI awareness
 * via Qt:AA_EnableHighDpiScaling. We do this in main.cpp. In order for
 * native dialogs to be rendered correctly we need to to set per-monitor
 * *v2* awareness prior to creating the dialog, which we can do here.
 * Qt doesn't render correctly when per-monitor v2 awareness is enabled, so
 * we need to revert our thread context when we're done.
 *
 * @return The current thread DPI awareness context, which should
 * be passed to revert_thread_per_monitor_v2_awareness.
 */
HANDLE set_thread_per_monitor_v2_awareness(void);

/**
 * @brief revert_thread_per_monitor_v2_awareness
 * @param context
 */
void revert_thread_per_monitor_v2_awareness(HANDLE context);

/** Open the "Open" dialog box.
 *
 * @param h_wnd HWND of the parent window.
 * @param file_name File name
 * @param type File type
 * @param display_filter a display filter
 */
gboolean win32_open_file (HWND h_wnd, const wchar_t *title, GString *file_name, unsigned int *type, GString *display_filter);

/** Open the "Save As" dialog box.
 *
 * @param h_wnd HWND of the parent window.
 * @param cf capture_file Structure for the capture to be saved
 * @param file_name File name. May be empty.
 * @param file_type Wiretap file type.
 * @param compression_type Compression type to use, or uncompressed.
 * @param must_support_comments TRUE if the file format list should
 * include only file formats that support comments
 *
 * @return TRUE if packets were discarded when saving, FALSE otherwise
 */
gboolean win32_save_as_file(HWND h_wnd, const wchar_t *title, capture_file *cf,
                            GString *file_name, int *file_type,
                            wtap_compression_type *compression_type,
                            gboolean must_support_comments);

/** Open the "Export Specified Packets" dialog box.
 *
 * @param h_wnd HWND of the parent window.
 * @param cf capture_file Structure for the capture to be saved
 * @param file_name File name. May be empty.
 * @param file_type Wiretap file type.
 * @param compression_type Compression type to use, or uncompressed.
 * @param range Range of packets to export.
 *
 * @return TRUE if packets were discarded when saving, FALSE otherwise
 */
gboolean win32_export_specified_packets_file(HWND h_wnd,
                                         const wchar_t *title,
                                         capture_file *cf,
                                         GString *file_name,
                                         int *file_type,
                                         wtap_compression_type *compression_type,
                                         packet_range_t *range);


/** Open the "Merge" dialog box.
 *
 * @param h_wnd HWND of the parent window.
 * @param file_name File name
 * @param display_filter a display filter
 * @param merge_type type of merge
 */
gboolean win32_merge_file (HWND h_wnd, const wchar_t *title, GString *file_name, GString *display_filter, int *merge_type);

/** Open the "Export" dialog box.
 *
 * @param h_wnd HWND of the parent window.
 * @param cf capture_file Structure for the capture to be saved
 * @param export_type The export type.
 * @param range a possible range
 */
void win32_export_file (HWND h_wnd, const wchar_t *title, capture_file *cf, export_type_e export_type, const gchar *range);

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
#define EWFD_PT_FORMAT         1006
#define EWFD_PT_SIZE           1007
#define EWFD_PT_START_ELAPSED  1008

#define EWFD_PTX_FORMAT        1009
#define EWFD_PTX_SIZE          1010
#define EWFD_PTX_START_ELAPSED 1011

#define EWFD_FORMAT_TYPE   1020

/* Save as and export dialog defines */
#define EWFD_GZIP_CB     1040

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

/* Merge dialog defines.  Overlays Open dialog defines above. */
#define EWFD_MERGE_PREPEND_BTN 1050
#define EWFD_MERGE_CHRONO_BTN  1051
#define EWFD_MERGE_APPEND_BTN  1052

/* Export dialog defines.  Overlays Save dialog defines above. */
/* These MUST be contiguous */
#define EWFD_PKT_FORMAT_GB    1050
#define EWFD_PKT_SUMMARY_CB   1051
#define EWFD_COL_HEADINGS_CB  1052
#define EWFD_PKT_DETAIL_CB    1053
#define EWFD_PKT_DETAIL_COMBO 1054
#define EWFD_PKT_BYTES_CB     1055
#define EWFD_PKT_NEW_PAGE_CB  1056

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FILE_DLG_WIN32_H__ */
