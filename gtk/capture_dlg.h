/* capture_dlg.h
 * Definitions for packet capture windows
 *
 * $Id: capture_dlg.h,v 1.2 2000/10/11 06:01:16 guy Exp $
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

#ifndef __CAPTURE_DLG_H__
#define __CAPTURE_DLG_H__

void   capture_prep_cb(GtkWidget *, gpointer);
void   capture_stop_cb(GtkWidget *, gpointer);

#endif /* capture.h */
