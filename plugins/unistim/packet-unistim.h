/* packet-unistim.h
  * header field declarations, value_string definitions, true_false_string
  * definitions and function prototypes for main dissectors
  * Copyright 2007 Don Newton <dnewton@cypresscom.net>
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

#ifndef PACKET_UNISTIM_H
#define PACKET_UNISTIM_H

typedef struct _unistim_info_t
{
	guint8  rudp_type;	/* NAK, ACK, Payload */
	guint8	payload_type;	/* unistim payload type (aggregate, non-aggregate, encapsulated) */
	guint32 sequence;	/* rudp sequence number */
	guint32 termid;		/* termid if available */
	address it_ip;		/* IP addr of it, determined by who is sending termids */
	guint32 it_port;	/* port of it (phone) */
	address ni_ip;		/* IP addr of ni (server) as determined by who's sending termids */
	gint	key_val;	/* actual key pressed (-1 if not used) */
	gint	key_state;	/* Key state 1=down 0=up */
	gint	hook_state;	/* Hook state 1=offhook 0=onhook */
	gint	stream_connect;	/* Audio stream connect 1=connect 0=disconnect */
	gint	trans_connect;	/* Transducer connect? 1=connect 0=disconnect */
	gint	set_termid;     /* Set the termid 1=set termid */
	guint8  *string_data;	/* Any time a string is written to the display, this has the string */
	gint	call_state;     /* Not used? */
	guchar  *key_buffer;	/* Used in voip-calls.c tap, holds call keys pressed */
} unistim_info_t;

#endif

