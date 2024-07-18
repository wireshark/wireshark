/* packet-rtp-events.h
 *
 * Defines for RFC 2833 RTP Events dissection
 * Copyright 2003, Kevin A. Noll <knoll[AT]poss.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

WS_DLL_PUBLIC value_string_ext rtp_event_type_values_ext;

struct _rtp_event_info {
	uint8_t     info_rtp_evt;
	uint32_t		info_setup_frame_num; /* the frame num of the packet that set this RTP connection */
	uint16_t		info_duration;
	bool	info_end;
};

