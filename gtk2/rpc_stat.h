/* rpc_stat.h
 * rpc_stat   2002 Ronnie Sahlberg
 *
 * $Id: rpc_stat.h,v 1.1 2002/09/07 09:28:05 sahlberg Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifndef __RPCSTAT_H__
#define __RPCSTAT_H__

void gtk_rpcstat_init(guint32 program, guint32 version);
void gtk_rpcstat_cb(GtkWidget *w, gpointer d);

#endif
