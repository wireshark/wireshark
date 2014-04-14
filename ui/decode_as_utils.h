/* decode_as_utils.h
 *
 * "Decode As" UI utility routines.
 *
 * By David Hampton <dhampton@mac.com>
 * Copyright 2001 David Hampton
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
 *
 */

#ifndef __DECODE_AS_UTILS_H__
#define __DECODE_AS_UTILS_H__

#include "ws_symbol_export.h"

/** @file
 *  "Decode As" / "User Specified Decodes" dialog box.
 *  @ingroup main_ui_group
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Reset the "decode as" entries and reload ones of the current profile.
 */
void load_decode_as_entries(void);

/** This routine creates one entry in the list of protocol dissector
 * that need to be reset. It is called by the g_hash_table_foreach
 * routine once for each changed entry in a dissector table.
 * Unfortunately it cannot delete the entry immediately as this screws
 * up the foreach function, so it builds a list of dissectors to be
 * reset once the foreach routine finishes.
 *
 * @param table_name The table name in which this dissector is found.
 *
 * @param key A pointer to the key for this entry in the dissector
 * hash table.  This is generally the numeric selector of the
 * protocol, i.e. the ethernet type code, IP port number, TCP port
 * number, etc.
 *
 * @param selector_type The type of the selector in that dissector table
 *
 * @param value A pointer to the value for this entry in the dissector
 * hash table.  This is an opaque pointer that can only be handed back
 * to routine in the file packet.c - but it's unused.
 *
 * @param user_data Unused.
 */
void decode_build_reset_list (const gchar *table_name, ftenum_t selector_type,
                         gpointer key, gpointer value _U_,
                         gpointer user_data _U_);

/** Clear all "decode as" settings.
 */
void decode_clear_all(void);

/** Open the "decode_as_entries" configuration file and write its header.
 *
 * Entries should be written with decode_as_write_entry(). The file should
 * be closed with fclose().
 *
 * @return A valid FILE pointer on success, NULL on failure.
 */
FILE *decode_as_open(void);

/** Write an entry to the "decode_as_entries" file.
 *
 * @param[in] da_file FILE pointer returned by decode_as_open().
 * @param[in] table_name A short decode_as table name.
 * @param[in] selector Integer or string selector, e.g. 80 for TCP port 80.
 * @param[in] default_proto The default protocol for the selector, or "(none)".
 * @param[in] current_proto The desired protocol for the selector, or "(none)" to disable.
 */
void decode_as_write_entry(FILE *da_file, const char *table_name, const char *selector, const char *default_proto, const char *current_proto);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __DECODE_AS_UTILS_H__ */
