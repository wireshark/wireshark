/* packet-rx.h
 * Definitions for packet disassembly structures and routines
 *
 * $Id: packet-rx.h,v 1.3 2000/04/14 06:42:52 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 * Joerg Mayer <jmayer@telemation.de>
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

#ifndef PACKET_RX_H
#define PACKET_RX_H

struct rx_header {
	guint32 epoch;
	guint32 cid;
	guint32 callNumber;
	guint32 seq;
	guint32 serial;
	u_char type;
#define RX_PACKET_TYPE_DATA		1
#define RX_PACKET_TYPE_ACK		2
#define RX_PACKET_TYPE_BUSY		3
#define RX_PACKET_TYPE_ABORT		4
#define RX_PACKET_TYPE_ACKALL		5
#define RX_PACKET_TYPE_CHALLENGE	6
#define RX_PACKET_TYPE_RESPONSE		7
#define RX_PACKET_TYPE_DEBUG		8
#define RX_PACKET_TYPE_PARAMS		9
#define RX_PACKET_TYPE_VERSION		13
	u_char flags; 
#define RX_CLIENT_INITIATED 1
#define RX_REQUEST_ACK 2
#define RX_LAST_PACKET 4
#define RX_MORE_PACKETS 8
#define RX_FREE_PACKET 16
	u_char userStatus;
	u_char securityIndex;
	guint16 spare;			/* How clever: even though the AFS */
	guint16 serviceId;		/* header files indicate that the */
};					/* serviceId is first, it's really */
					/* encoded _after_ the spare field */
					/* I wasted a day figuring that out! */

struct rx_ack_header {
     guint16 bufferspace;       /* # of packet buffers available */
     guint16 maxskew;
     guint32 firstpacket;        /* First packet in acks below */
     guint32 prevpacket;
     guint32 serial;             /* Packet that prompted this one */
     u_char reason;             /* rx_ack_reason */
	/* some other stuff I think */
};

#define RX_ACK_TYPE_NACK 0
#define RX_ACK_TYPE_ACK 1

#define RX_ACK_REQUESTED 1
#define RX_ACK_DUPLICATE 2
#define RX_ACK_OUT_OF_SEQUENCE 3
#define RX_ACK_EXEEDS_WINDOW 4
#define RX_ACK_NOSPACE 5
#define RX_ACK_PING 6
#define RX_ACK_PING_RESPONSE 7
#define RX_ACK_DELAY 8

#endif

