/* about_dlg.h
 * Declarations of routines for the "About" dialog
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

#ifndef __ABOUT_DLG_H__
#define __ABOUT_DLG_H__

/** @file
 *  "About" dialog box.
 *  @ingroup dialog_group
 */

/** Create a splash screen showed when Wireshark is started. 
 *
 * @param message the new message to be displayed
 * @return the newly created window handle
 */
extern GtkWidget *splash_new(char *message);

/** Update the splash screen message. 
 *
 * @param win the window handle from splash_new()
 * @param message the new message to be displayed
 */
extern void splash_update(GtkWidget *win, char *message);

/** Destroy the splash screen. 
 *
 * @param win the window handle from splash_new()
 * @return always FALSE, so this function can be used as a callback for gtk_timeout_add()
 */
extern guint splash_destroy(GtkWidget *win);

/** User requested the "About" dialog box by menu or toolbar.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void about_wireshark_cb( GtkWidget *widget, gpointer data);


#endif /* __ABOUT_DLG_H__ */
