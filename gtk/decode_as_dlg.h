/* decode_as_dlg.h
 *
 * $Id$
 *
 * Routines to modify dissector tables on the fly.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#ifndef __DECODE_AS_DLG_H__
#define __DECODE_AS_DLG_H__

/** @file
 *  "Decode As" / "User Specified Decodes" dialog box.
 *  @ingroup dialog_group
 */

/*
 * Filename of the "decode as" entry preferences
 */
#define DECODE_AS_ENTRIES_FILE_NAME "decode_as_entries"

#define DECODE_AS_ENTRY "decode_as_entry"

/** Init the "Decode As" module
 */
void decode_as_init(void);

/** User requested the "Decode As" dialog box by menu or toolbar.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
void decode_as_cb(GtkWidget *widget, gpointer data);

/** User requested the "User Specified Decodes" dialog box by menu or toolbar.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
void decode_show_cb(GtkWidget *widget, gpointer data);

/** Have any pages in the notebook in a "Decode As" dialog box? If there
 * wouldn't be, we inactivate the menu item for "Decode As".
 *
 * @return TRUE, if we have at least one notebook page in "Decode As"
 */
gboolean decode_as_ok(void);

/*
 * Reset the "decode as"entries and reload ones of the current profile
 */
void load_decode_as_entries(void);

#endif
