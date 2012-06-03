/* main_titlebar.h
 * Declarations of GTK+-specific UI utility routines
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

#ifndef __MAIN_TITLEBAR_H__
#define __MAIN_TITLEBAR_H__

/** Construct the main window's title with the current main_window_name optionally appended
 *  with the user-specified title and/or wireshark version. 
 *  Display the result in the main window's title bar and in its icon title
 */
extern void main_titlebar_update(void);

/* Set the name of the top-level window. */
extern void main_set_window_name(const gchar *);

#endif /* __MAIN_TITLEBAR_H__ */
