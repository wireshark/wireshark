/* recent_utils.h
 * Routines called to write stuff to the recent file; their implementations
 * are GUI-dependent, but the API's aren't
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __UI_RECENT_UTILS_H__
#define __UI_RECENT_UTILS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Add a new recent capture filename to the "Recent Files" submenu
   (duplicates will be ignored) */
extern void add_menu_recent_capture_file(gchar *cf_name);

/** Write all recent capture filenames to the user's recent file.
 * @param rf recent file
 */
extern void menu_recent_file_write_all(FILE *rf);

/** Add a capture filter coming from the user's recent file to the cfilter combo box.
 *
 * @param dftext the filter string
 */
extern gboolean cfilter_combo_add_recent(gchar *s);

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
extern gboolean dfilter_combo_add_recent(gchar *dftext);

/** Write all non-empty display filters (until maximum count)
 *  of the combo box GList to the user's recent file.
 *
 * @param rf the recent file
 */
extern void dfilter_recent_combo_write_all(FILE *rf);

#ifdef HAVE_PCAP_REMOTE
/** Write all remote hosts to the recent file
 *
 * @param rf recent file
 */
void
capture_remote_combo_recent_write_all(FILE *rf);

/** Add a new remote host from the recent file
 *
 * @param s string with hostname,port,auth_type
 * @return TRUE if correctly added
 */
gboolean
capture_remote_combo_add_recent(gchar *s);
#endif

/** Read in a single geometry key value pair from the recent file.
 *
 * @param name the geom_name of the window
 * @param key the subkey of this pair (e.g. "x")
 * @param value the new value (e.g. "123")
 */
extern void window_geom_recent_read_pair(const char *name, const char *key, const char *value);

/** Write all geometry values of all windows to the recent file.
 * Will call write_recent_geom() for every existing window type.
 *
 * @param rf recent file handle from caller
 */
extern void window_geom_recent_write_all(gpointer rf);

/** Write all packet list geometry values to the recent file.
 *
 *  @param rf recent file handle from caller
 */
extern void new_packet_list_recent_write_all(FILE *rf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UI_RECENT_UTILS_H__ */
