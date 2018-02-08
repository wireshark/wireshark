/* tap-voip.h
 * VoIP packet tap interface   2007 Tomas Kukosa
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
