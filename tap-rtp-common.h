/* tap-rtp-common.h
 * RTP streams handler functions used by tshark and wireshark
 *
 * $Id$
 *
 * Copyright 2008, Ericsson AB
 * By Balint Reczey <balint.reczey@ericsson.com>
 *
 * most functions are copied from ui/gtk/rtp_stream.c and ui/gtk/rtp_analisys.c
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

#ifndef TAP_RTP_COMMON_H_INCLUDED
#define TAP_RTP_COMMON_H_INCLUDED

#include "ui/gtk/rtp_stream.h"

gint rtp_stream_info_cmp(gconstpointer, gconstpointer);
void rtpstream_reset_cb(void*);
void rtp_write_header(rtp_stream_info_t*, FILE*);
void rtp_write_sample(rtp_sample_t*, FILE*);
int rtpstream_packet(void*, packet_info*, epan_dissect_t *, const void *);

#endif /*TAP_RTP_COMMON_H_INCLUDED*/
