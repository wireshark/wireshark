/* packet-rmt-norm.h
 * Reliable Multicast Transport (RMT)
 * NORM Protocol Instantiation function definitions
 * Copyright 2005, Stefano Pettini <spettini@users.sourceforge.net>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Extensive changes to decode more information Julian Onions
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef __PACKET_RMT_NORM__
#define __PACKET_RMT_NORM__

#include "packet-rmt-common.h"
#include "packet-rmt-fec.h"
#include "packet-rmt-lct.h"

/* Type definitions */
/* ================ */

/* Logical NORM packet representation */
struct _norm
{
	guint8 version;
	guint8 type;
	guint8 hlen;
	guint16 sequence;
	guint32 source_id;

	struct _fec fec;
};

enum {
	NORM_INFO = 1,
	NORM_DATA = 2,
	NORM_CMD = 3,
	NORM_NACK = 4,
	NORM_ACK = 5,
	NORM_REPORT = 6,

	NORM_CMD_FLUSH = 1,
	NORM_CMD_EOT = 2,
	NORM_CMD_SQUELCH = 3,
	NORM_CMD_CC = 4,
	NORM_CMD_REPAIR_ADV = 5,
	NORM_CMD_ACK_REQ = 6,
	NORM_CMD_APPLICATION = 7,


	NORM_FLAG_REPAIR = 0x01,
	NORM_FLAG_EXPLICIT = 0x02,
	NORM_FLAG_INFO = 0x04,
	NORM_FLAG_UNRELIABLE = 0x08,
	NORM_FLAG_FILE = 0x10,
	NORM_FLAG_STREAM = 0x20,
	NORM_FLAG_MSG_START = 0x40,

	NORM_ACK_CC = 1,
	NORM_ACK_FLUSH = 2,

	NORM_NACK_ITEMS = 1,
	NORM_NACK_RANGES = 2,
	NORM_NACK_ERASURES = 3,

	NORM_NACK_SEGMENT = 0x01,
	NORM_NACK_BLOCK = 0x02,
	NORM_NACK_INFO = 0x04,
	NORM_NACK_OBJECT = 0x08,


	NORM_FLAG_CC_CLR = 0x01,
	NORM_FLAG_CC_PLR = 0x02,
	NORM_FLAG_CC_RTT = 0x04,
	NORM_FLAG_CC_START = 0x08,
	NORM_FLAG_CC_LEAVE = 0x10,

};


/* Ethereal stuff */
/* ============== */

/* NORM header field definitions*/
struct _norm_hf
{
	int version;
	int type;
	int hlen;
	int sequence;
	int source_id;
	int instance_id;
	int grtt;
	int backoff;
	int gsize;
	int flags;
	int cmd_flavor;
	int reserved;
	int cc_sequence;
	int cc_sts;
	int cc_stus;
	int cc_node_id;
	int cc_flags;
	int cc_flags_clr;
	int cc_flags_plr;
	int cc_flags_rtt;
	int cc_flags_start;
	int cc_flags_leave;
	int cc_rtt;
	int cc_rate;
	int cc_transport_id;
	int ack_source;
	int ack_type;
	int ack_id;
	int ack_grtt_sec;
	int ack_grtt_usec;
	int nack_server;
	int nack_grtt_sec;
	int nack_grtt_usec;
	int nack_form;
	int nack_length;
	int nack_flags;
	int nack_flags_segment;
	int nack_flags_block;
	int nack_flags_info;
	int nack_flags_object;
	struct flaglist {
		int repair;
		int explicit;
		int info;
		int unreliable;
		int file;
		int stream;
		int msgstart;
	} flag;
	int object_transport_id;
	int extension;
	int payload_len;
	int payload_offset;
	struct _fec_hf fec;

	int payload;
};

/* NORM subtrees */
struct _norm_ett
{
	gint main;
	gint hdrext;
	gint flags;
	gint streampayload;
	gint congestioncontrol;
	gint nackdata;
	struct _fec_ett fec;
};

/* NORM preferences */
struct _norm_prefs
{
	struct _fec_prefs fec;
};

/* Function declarations */
/* ===================== */

#endif
