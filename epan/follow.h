/* follow.h
 *
 * $Id$
 *
 * Copyright 1998 Mike Hall <mlh@io.com>
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
 *
 */

#ifndef __FOLLOW_H__
#define __FOLLOW_H__

#include <epan/packet.h>
#include "ws_symbol_export.h"

#define MAX_IPADDR_LEN	16

/* With MSVC and a libwireshark.dll, we need a special declaration. */
WS_DLL_PUBLIC gboolean empty_tcp_stream;
WS_DLL_PUBLIC gboolean incomplete_tcp_stream;

typedef struct _tcp_stream_chunk {
  guint8      src_addr[MAX_IPADDR_LEN];
  guint16     src_port;
  guint32     dlen;
} tcp_stream_chunk;

WS_DLL_PUBLIC
char* build_follow_filter( packet_info * );
WS_DLL_PUBLIC
gboolean follow_tcp_addr( const address *, guint, const address *, guint );
WS_DLL_PUBLIC
gboolean follow_tcp_index( guint32 );
void reassemble_tcp( guint32, guint32, guint32, guint32, const char*, guint32,
                     int, address *, address *, guint, guint );
WS_DLL_PUBLIC
void  reset_tcp_reassembly( void );

typedef struct {
	guint8		ip_address[2][MAX_IPADDR_LEN];
	guint32		port[2];
	unsigned int	bytes_written[2];
	gboolean        is_ipv6;
} follow_stats_t;

WS_DLL_PUBLIC
void follow_stats(follow_stats_t* stats);

#endif
