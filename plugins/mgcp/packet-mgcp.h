/* packet-mgcp.h
 * Routines for mgcp packet disassembly
 * RFC 2705
 *
 * $Id$
 *
 * Copyright (c) 2000 by Ed Warnicke <hagbard@physics.rutgers.edu>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1999 Gerald Combs
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
 
 /* A simple MGCP type that is occasionally handy */
typedef enum _mgcp_type
{
	MGCP_REQUEST,
	MGCP_RESPONSE,
	MGCP_OTHERS
} mgcp_type_t;

/* Container for tapping relevant data */
typedef struct _mgcp_info_t
{
	mgcp_type_t mgcp_type;
	char code[5];
	guint32 transid;
	nstime_t req_time;
	gboolean is_duplicate;
	gboolean request_available;
	guint32 req_num; /* frame number request seen */
	gchar *endpointId;
	gchar *observedEvents;
	guint32 rspcode;
	gchar *signalReq;
	gboolean hasDigitMap;
} mgcp_info_t;

/* Item of request list */
typedef struct _mgcp_call_t
{
	guint32 transid;
	char code[5];
	guint32 req_num; /* frame number request seen */
	guint32 rsp_num; /* frame number response seen */
	guint32 rspcode;
	nstime_t req_time;
	gboolean responded;
} mgcp_call_t;

void proto_register_mgcp(void);
void proto_reg_handoff_mgcp(void);

