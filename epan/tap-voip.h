/* tap-voip.h
 * VoIP packet tap interface   2007 Tomas Kukosa
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

#ifndef _TAP_VOIP_H_
#define _TAP_VOIP_H_

/* defines voip call state */
typedef enum _voip_call_state {
        VOIP_NO_STATE,
        VOIP_CALL_SETUP,
        VOIP_RINGING,
        VOIP_IN_CALL,
        VOIP_CANCELLED,
        VOIP_COMPLETED,
        VOIP_REJECTED,
        VOIP_UNKNOWN
} voip_call_state;

typedef enum _voip_call_active_state {
        VOIP_ACTIVE,
        VOIP_INACTIVE
} voip_call_active_state;

/* structure for common/proprietary VoIP calls TAP */
typedef struct _voip_packet_info_t
{
	gchar *protocol_name;
	gchar *call_id;
	voip_call_state call_state;
	voip_call_active_state call_active_state;
	gchar *from_identity;
	gchar *to_identity;
	gchar *call_comment;
	gchar *frame_label;
	gchar *frame_comment;
} voip_packet_info_t;

#endif  /* _TAP_VOIP_H_ */
