/* decode_as_dlg.c
 *
 * $Id: decode_as_dlg.h,v 1.2 2001/02/11 23:02:05 guy Exp $
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

void decode_as_cb(GtkWidget *, gpointer);
void decode_show_cb(GtkWidget *, gpointer);
gboolean decode_as_ok(void);

#endif
