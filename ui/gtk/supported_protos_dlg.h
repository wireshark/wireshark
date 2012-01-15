/* supported_protos_dlg.h
 *
 * Laurent Deniel <laurent.deniel@free.fr>
 *
 * $Id$
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

#ifndef __SUPPORTED_PROTOS_DLG_H__
#define __SUPPORTED_PROTOS_DLG_H__

/** @file
 *  "Supported Protocols" dialog box.
 */

/**
 * Create the supported protos dialog box.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
void supported_cb(GtkWidget *widget, gpointer data);

/** Redraw all the supported protos text widgets, to use a new font. */
void supported_redraw(void);

#endif /* __SUPPORTED_PROTOS_DLG_H__ */
