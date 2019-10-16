/* recent_utils.h
 * Routines called to write stuff to the recent file; their implementations
 * are GUI-dependent, but the API's aren't
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __UI_RECENT_UTILS_H__
#define __UI_RECENT_UTILS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Add a new recent capture filename to the "Recent Files" submenu
   (duplicates will be ignored) */
extern void add_menu_recent_capture_file(const gchar *cf_name);

/** Write all recent capture filenames to the user's recent file.
 * @param rf recent file
 */
extern void menu_recent_file_write_all(FILE *rf);

/** Write all non-empty capture filters (until maximum count)
 *  of the combo box GList to the user's recent file.
 *
 * @param rf the recent file
 */
extern void cfilter_combo_recent_write_all(FILE *rf);

/** Add a display filter coming from the user's recent file to the dfilter combo box.
 *
 * @param dftext the filter string
 */
extern gboolean dfilter_combo_add_recent(const gchar *dftext);

/** Write all non-empty display filters (until maximum count)
 *  of the combo box GList to the user's recent file.
 *
 * @param rf the recent file
 */
extern void dfilter_recent_combo_write_all(FILE *rf);

/** Write all packet list geometry values to the recent file.
 *
 *  @param rf recent file handle from caller
 */
extern void packet_list_recent_write_all(FILE *rf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UI_RECENT_UTILS_H__ */

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
