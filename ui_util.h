/* ui_util.h
 * Definitions for UI utility routines
 *
 * $Id: ui_util.h,v 1.8 2001/03/24 02:14:54 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifndef __UI_UTIL_H__
#define __UI_UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Set the name of the top-level window and its icon. */
void set_main_window_name(gchar *);

/* Given a pointer to a GtkWidget for a top-level window, raise it and
   de-iconify it.  This routine is used if the user has done something to
   ask that a window of a certain type be popped up when there can be only
   one such window and such a window has already been popped up - we
   pop up the existing one rather than creating a new one. */
void reactivate_window(GtkWidget *);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UI_UTIL_H__ */
