/* packet-rtsp.h
 *
 * by Stephane GORSE (Orange Labs / France Telecom)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_RTSP_H__
#define __PACKET_RTSP_H__

/* Used for RTSP statistics */
typedef struct _rtsp_info_value_t {
	uint32_t framenum;
	char	*request_method;
	unsigned	 response_code;
	char    *rtsp_host;
	char    *request_uri;
} rtsp_info_value_t;

#endif /* __PACKET_RTSP_H__ */
