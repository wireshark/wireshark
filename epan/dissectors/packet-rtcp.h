/* packet-rtcp.h
 *
 * Routines for RTCP dissection
 * RTCP = Real-time Transport Control Protocol
 *
 * Copyright 2000, Philips Electronics N.V.
 * Written by Andreas Sikkema <andreas.sikkema@philips.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "ws_symbol_export.h"

/* Info to save in RTCP conversation / packet-info.
   Note that this structure applies to the destination end of
   an RTP session */
#define MAX_RTCP_SETUP_METHOD_SIZE 7
struct _rtcp_conversation_info
{
    /* Setup info is relevant to traffic whose dest is the conversation address */
    guchar  setup_method_set;
    gchar   setup_method[MAX_RTCP_SETUP_METHOD_SIZE + 1];
    guint32 setup_frame_number;

    /* Info used for roundtrip calculations */
    guchar   last_received_set;
    guint32  last_received_frame_number;
    nstime_t last_received_timestamp;
    guint32  last_received_ts;

    /* Stored result of calculation */
    guchar  lsr_matched;
    guint32 calculated_delay_used_frame;
    gint    calculated_delay_report_gap;
    gint32  calculated_delay;

    /* SRTCP context */
    struct srtp_info *srtcp_info;
};


/* Add an RTCP conversation with the given details */
WS_DLL_PUBLIC
void rtcp_add_address(packet_info *pinfo,
                      address *addr, int port,
                      int other_port,
                      const gchar *setup_method, guint32 setup_frame_number);

/* Add an SRTP conversation with the given details */
WS_DLL_PUBLIC
void srtcp_add_address(packet_info *pinfo,
                      address *addr, int port,
                      int other_port,
                      const gchar *setup_method, guint32 setup_frame_number,
                      struct srtp_info *srtcp_info);
