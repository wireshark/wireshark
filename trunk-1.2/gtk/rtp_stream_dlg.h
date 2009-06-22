/* rtp_stream_dlg.h
 * RTP streams summary addition for Wireshark
 *
 * $Id$
 *
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
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
 * Foundation,  Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef RTP_STREAM_DLG_H_INCLUDED
#define RTP_STREAM_DLG_H_INCLUDED

#include <gtk/gtk.h>

/** @file
 *  "RTP Stream Analysis" dialog box.
 */

/**
 * Create or reactivate the rtp streams dialog box.
 *
 * @param list pointer to list of rtp_stream_info_t*
 */
void rtpstream_dlg_show(GList *list);

/**
 * Update the contents of the dialog box clist with that of list.
 *
 * @param list pointer to list of rtp_stream_info_t*
 */
void rtpstream_dlg_update(GList *list);

#endif /*RTP_STREAM_DLG_H_INCLUDED*/
