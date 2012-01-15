/* filter_autocomplete.h
 * Definitions for filter autocomplete
 *
 * Copyright 2008, Bahaa Naamneh <b.naamneh@gmail.com>
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

#ifndef _FILTER_AUTO_COMPLETE_H_
#define _FILTER_AUTO_COMPLETE_H_


#define E_FILT_AUTOCOMP_PTR_KEY       "filter_autocomplete_window"

/** @file
 *  "Filter Auto Complete" dialog box.
 *  @ingroup dialog_group
 */

/** Callback function that is called when a "key-press-event" signal occur.
 *
 * @param filter_te text-editing filter widget
 * @param event
 * @param  user_data pointer to user_data (unused)
 */
extern gboolean filter_string_te_key_pressed_cb(GtkWidget *filter_te, GdkEventKey *event, gpointer user_data _U_);

/** Callback function that is called when a "key-press-event" signal occur.
 *
 * @param win parent window of the text-editing filter widget
 * @param event
 * @param user_data pointer to user_data (unused)
 */
extern gboolean filter_parent_dlg_key_pressed_cb(GtkWidget *win, GdkEventKey *event, gpointer user_data _U_);


#endif
