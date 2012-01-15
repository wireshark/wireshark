/* proto_dlg.h
 *
 * $Id$
 *
 * Laurent Deniel <laurent.deniel@free.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
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

#ifndef __PROTO_DLG_H__
#define __PROTO_DLG_H__

/** @file
 *  "Enabled Protocols" dialog box.
 *  @ingroup dialog_group
 */

/** Show the enabled protocols dialog.
 * 
 * @param widget parent widget (unused)
 * @param data unused
 */
void proto_cb(GtkWidget *widget, gpointer data);

/** Disable (temporarily) the selected protocol.
 * 
 * @param widget parent widget (unused)
 * @param data unused
 */
void proto_disable_cb(GtkWidget *widget, gpointer data);

#endif
