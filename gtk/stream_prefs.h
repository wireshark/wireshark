/* stream_prefs.h
 * Definitions for stream preferences window
 *
 * $Id: stream_prefs.h,v 1.2 2000/08/11 13:32:56 deniel Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1999 Gerald Combs
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

#ifndef __STREAM_PREFS_H__
#define __STREAM_PREFS_H__

GtkWidget *stream_prefs_show(void);
void stream_prefs_ok(GtkWidget *w);
void stream_prefs_save(GtkWidget *w);
void stream_prefs_cancel(GtkWidget *w);
void stream_prefs_delete(GtkWidget *w);

#endif
