/* packet-gnutella.h
 * Declarations for gnutella dissection
 * Copyright 2001, B. Johannessen <bob@havoq.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

void proto_register_gnutella(void);

#define GNUTELLA_TCP_PORT	6346

/*
 * Used to determine whether a chunk of data looks like a Gnutella packet
 * or not - it might be a transfer stream, or it might be part of a
 * Gnutella packet that starts in an earlier missing TCP segment.
 *
 * One Gnutella spec says packets SHOULD be no bigger than 4K, although
 * that's SHOULD, not MUST.
 */
#define GNUTELLA_MAX_SNAP_SIZE	4096

#define GNUTELLA_UNKNOWN_NAME	"Unknown"
#define GNUTELLA_PING		0x00
#define GNUTELLA_PING_NAME	"Ping"
#define GNUTELLA_PONG		0x01
#define GNUTELLA_PONG_NAME	"Pong"
#define GNUTELLA_PUSH		0x40
#define GNUTELLA_PUSH_NAME	"Push"
#define GNUTELLA_QUERY		0x80
#define GNUTELLA_QUERY_NAME	"Query"
#define GNUTELLA_QUERYHIT	0x81
#define GNUTELLA_QUERYHIT_NAME	"QueryHit"

#define GNUTELLA_HEADER_LENGTH		23
#define GNUTELLA_SERVENT_ID_LENGTH	16
#define GNUTELLA_PORT_LENGTH		2
#define GNUTELLA_IP_LENGTH		4
#define GNUTELLA_LONG_LENGTH		4
#define GNUTELLA_SHORT_LENGTH		2
#define GNUTELLA_BYTE_LENGTH		1

#define GNUTELLA_PONG_LENGTH		14
#define GNUTELLA_PONG_PORT_OFFSET	0
#define GNUTELLA_PONG_IP_OFFSET		2
#define GNUTELLA_PONG_FILES_OFFSET	6
#define GNUTELLA_PONG_KBYTES_OFFSET	10

#define GNUTELLA_QUERY_SPEED_OFFSET	0
#define GNUTELLA_QUERY_SEARCH_OFFSET	2

#define GNUTELLA_QUERYHIT_HEADER_LENGTH		11
#define GNUTELLA_QUERYHIT_COUNT_OFFSET		0
#define GNUTELLA_QUERYHIT_PORT_OFFSET		1
#define GNUTELLA_QUERYHIT_IP_OFFSET		3
#define GNUTELLA_QUERYHIT_SPEED_OFFSET		7
#define GNUTELLA_QUERYHIT_FIRST_HIT_OFFSET	11
#define GNUTELLA_QUERYHIT_HIT_INDEX_OFFSET	0
#define GNUTELLA_QUERYHIT_HIT_SIZE_OFFSET	4
#define GNUTELLA_QUERYHIT_END_OF_STRING_LENGTH	2

#define GNUTELLA_PUSH_SERVENT_ID_OFFSET		0
#define GNUTELLA_PUSH_INDEX_OFFSET		16
#define GNUTELLA_PUSH_IP_OFFSET			20
#define GNUTELLA_PUSH_PORT_OFFSET		24

#define GNUTELLA_HEADER_ID_OFFSET		0
#define GNUTELLA_HEADER_PAYLOAD_OFFSET		16
#define GNUTELLA_HEADER_TTL_OFFSET		17
#define GNUTELLA_HEADER_HOPS_OFFSET		18
#define GNUTELLA_HEADER_SIZE_OFFSET		19
