/* statusbar.h
 * Definitions for status bar UI routines
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

#ifndef __STATUSBAR_H__
#define __STATUSBAR_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Push a message referring to file access onto the statusbar.
 */
void statusbar_push_file_msg(gchar *msg);

/*
 * Pop a message referring to file access off the statusbar.
 */
void statusbar_pop_file_msg(void);

/*
 * Push a message referring to the currently-selected field onto the statusbar.
 */
void statusbar_push_field_msg(gchar *msg);

/*
 * Pop a message referring to the currently-selected field off the statusbar.
 */
void statusbar_pop_field_msg(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __STATUSBAR_H__ */
