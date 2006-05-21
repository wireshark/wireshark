/* packet-q931.h
 * Declarations of exported routines and tables for Q.931 and Q.2931 frame
 * disassembly
 * Guy Harris <guy@alum.mit.edu>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
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

#ifndef __PACKET_Q931_H__
#define __PACKET_Q931_H__

extern void dissect_q931_bearer_capability_ie(tvbuff_t *, int, int,
    proto_tree *);

extern void dissect_q931_cause_ie(tvbuff_t *, int, int,
    proto_tree *, int, guint8 *);

extern void dissect_q931_progress_indicator_ie(tvbuff_t *, int, int,
    proto_tree *);

extern void dissect_q931_high_layer_compat_ie(tvbuff_t *, int, int,
    proto_tree *);

extern void dissect_q931_user_user_ie(tvbuff_t *tvb, int offset, int len,
    proto_tree *tree);

extern const value_string q931_cause_location_vals[];

typedef struct _q931_packet_info {
       gchar *calling_number;
       gchar *called_number;
       guint8 cause_value;
       gint32 crv;
	   guint8 message_type;
} q931_packet_info;

/*
 * the following allows TAP code access to the messages
 * without having to duplicate it. With MSVC and a
 * libwireshark.dll, we need a special declaration.
 */
ETH_VAR_IMPORT const value_string q931_cause_code_vals[];
ETH_VAR_IMPORT const value_string q931_message_type_vals[];

extern const value_string q931_protocol_discriminator_vals[];

/*
 * Q.931 message types.
 */
#define	Q931_ESCAPE		0x00
#define	Q931_ALERTING		0x01
#define	Q931_CALL_PROCEEDING	0x02
#define	Q931_CONNECT		0x07
#define	Q931_CONNECT_ACK	0x0F
#define	Q931_PROGRESS		0x03
#define	Q931_SETUP		0x05
#define	Q931_SETUP_ACK		0x0D
#define	Q931_HOLD		0x24
#define	Q931_HOLD_ACK		0x28
#define	Q931_HOLD_REJECT	0x30
#define	Q931_RESUME		0x26
#define	Q931_RESUME_ACK		0x2E
#define	Q931_RESUME_REJECT	0x22
#define	Q931_RETRIEVE		0x31
#define	Q931_RETRIEVE_ACK	0x33
#define	Q931_RETRIEVE_REJECT	0x37
#define	Q931_SUSPEND		0x25
#define	Q931_SUSPEND_ACK	0x2D
#define	Q931_SUSPEND_REJECT	0x21
#define	Q931_USER_INFORMATION	0x20
#define	Q931_DISCONNECT		0x45
#define	Q931_RELEASE		0x4D
#define	Q931_RELEASE_COMPLETE	0x5A
#define	Q931_RESTART		0x46
#define	Q931_RESTART_ACK	0x4E
#define	Q931_CONGESTION_CONTROL	0x79
#define	Q931_FACILITY		0x62
#define	Q931_INFORMATION	0x7B
#define	Q931_NOTIFY		0x6E
#define	Q931_REGISTER		0x64
#define	Q931_SEGMENT		0x60
#define	Q931_STATUS		0x7D
#define	Q931_STATUS_ENQUIRY	0x75
#define	Q931_VERSION		0x0a
#define	Q931_GROUIP_SERVICE	0x06
#define	Q931_GROUIP_SERVICE_ACK	0x0b
#define	Q931_RESYNC_REQ		0x08
#define	Q931_RESYNC_RESP	0x09

#endif
