/*
 * h225-persistentdata.h
 * Definitions for lists and hash tables used in wireshark's h225 dissector
 * for calculation of delays in h225-calls
 *
 * Copyright 2003 Lars Roland
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __h225_HASH__
#define __h225_HASH__

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>


/* Item of ras request list*/
typedef struct _h225ras_call_t {
	guint32 requestSeqNum;
	e_guid_t guid;
	guint32	req_num;	/* frame number request seen */
	guint32	rsp_num;	/* frame number response seen */
	nstime_t req_time;	/* arrival time of request */
	gboolean responded;	/* true, if request has been responded */
	struct _h225ras_call_t *next_call; /* pointer to next ras request with same SequenceNumber and conversation handle */
} h225ras_call_t;


/* Item of ras-request key list*/
typedef struct _h225ras_call_info_key {
	guint	reqSeqNum;
	conversation_t *conversation;
} h225ras_call_info_key;

/* functions, needed using ras-request and halfcall matching*/
h225ras_call_t * find_h225ras_call(h225ras_call_info_key *h225ras_call_key ,int category);
h225ras_call_t * new_h225ras_call(h225ras_call_info_key *h225ras_call_key, packet_info *pinfo, e_guid_t *guid, int category);
h225ras_call_t * append_h225ras_call(h225ras_call_t *prev_call, packet_info *pinfo, e_guid_t *guid, int category);

void h225_init_routine(void); /* init routine, used by wireshark */

#endif /* __h225_HASH__*/
