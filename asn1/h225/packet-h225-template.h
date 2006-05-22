/* packet-h225.h
 * Routines for h225 packet dissection
 * Copyright 2005, Anders Broman <anders.broman@ericsson.com>
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

#ifndef PACKET_H225_H
#define PACKET_H225_H

typedef enum _h225_msg_type {
	H225_RAS,
	H225_CS,
	H225_OTHERS
} h225_msg_type;

typedef enum _h225_cs_type {
    H225_SETUP,
    H225_CALL_PROCEDING,
    H225_CONNECT,
    H225_ALERTING,
    H225_INFORMATION,
    H225_RELEASE_COMPLET,
    H225_FACILITY,
    H225_PROGRESS,
    H225_EMPTY,
    H225_STATUS,
    H225_STATUS_INQUIRY,
    H225_SETUP_ACK,
    H225_NOTIFY,
    H225_OTHER
} h225_cs_type;

typedef struct _h225_packet_info {
	h225_msg_type msg_type;		/* ras or cs message */
	h225_cs_type cs_type;		/* cs message type */
	gint msg_tag;			/* message tag*/
	gint reason;			/* reason tag, if available */
	guint requestSeqNum;		/* request sequence number of ras-message, if available */
	e_guid_t guid;			/* globally unique call id */
	gboolean is_duplicate;		/* true, if this is a repeated message */
	gboolean request_available;	/* true, if response matches to a request */
	nstime_t delta_time; 		/* this is the RAS response time delay */
	/* added for h225 conversations analysis */
	gboolean is_faststart;		/* true, if faststart field is included */
	gboolean is_h245;
	gboolean is_h245Tunneling;
	guint32 h245_address;
	guint16 h245_port;
	gchar dialedDigits[129]; /* Dialed Digits in the LRQ and LCF used for voip analysis */
	gboolean is_destinationInfo;
	gchar frame_label[50]; /* the Fram label used by graph_analysis, what is a abreviation of cinfo */
} h225_packet_info;

/*
 * the following allows TAP code access to the messages
 * without having to duplicate it. With MSVC and a 
 * libethereal.dll, we need a special declaration.
 */

#include "packet-per.h"

#include "packet-h225-exp.h" 

#endif  /* PACKET_H225_H */


