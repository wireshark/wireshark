/* packet-http.h
 *
 * $Id: packet-http.h,v 1.8 2003/09/02 22:47:57 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PACKET_HTTP_H__
#define __PACKET_HTTP_H__
#include <epan/packet.h>

void http_dissector_add(guint32 port, dissector_handle_t handle);

typedef struct _http_info_value_t
{
	guint	 response_method;
	gchar	*request_method;	
} http_info_value_t ;
#endif
