/* packet-rtcp.h
 *
 * $Id: packet-rtcp.h,v 1.9 2004/06/15 18:26:08 etxrab Exp $
 *
 * Routines for RTCP dissection
 * RTCP = Real-time Transport Control Protocol
 *
 * Copyright 2000, Philips Electronics N.V.
 * Written by Andreas Sikkema <andreas.sikkema@philips.com>
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

/* Info to save in RTCP conversation / packet-info */
#define MAX_RTCP_SETUP_METHOD_SIZE 8
struct _rtcp_conversation_info
{
	gchar   method[MAX_RTCP_SETUP_METHOD_SIZE];
	guint32 frame_number;
};


/* Add an RTCP conversation with the given details */
void rtcp_add_address(packet_info *pinfo,
                      const unsigned char* ip_addr, int port,
                      int other_port,
                      gchar *setup_method, guint32 setup_frame_number);

