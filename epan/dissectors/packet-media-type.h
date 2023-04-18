/* packet-media-type.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_MEDIA_TYPE_H__
#define __PACKET_MEDIA_TYPE_H__

typedef enum {
	MEDIA_CONTAINER_HTTP_REQUEST,		/* HTTP request */
	MEDIA_CONTAINER_HTTP_RESPONSE,		/* HTTP reply */
	MEDIA_CONTAINER_HTTP_NOTIFICATION,	/* HTTP notification */
	MEDIA_CONTAINER_HTTP_OTHERS,		/* other HTTP */
	MEDIA_CONTAINER_SIP_DATA,		/* SIP message */
	MEDIA_CONTAINER_OTHER			/* Everything else */
} media_container_type_t;

/** Should be passed to dissectors called through the media_type
 *  dissector table. */
typedef struct {
	media_container_type_t type; /**< Container of media; may be MEDIA_CONTAINER_OTHER if not called by HTTP */
	const char *media_str;  /**< Content-Type parameters */
	const char *content_id; /**< Content-ID parameter */
	/** In http1.0/1.1, data contains the header name/value mappings, valid only within the packet scope.
	    In other protocols, the http_type is used to indicate the data transported. */
	void *data;		/**< Protocol-specific data */
} media_content_info_t;

#endif /* __PACKET_MEDIA_TYPE_H__ */
