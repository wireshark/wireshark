/* packet-gssapi.h
 * Dissector for GSS-API tokens as described in rfc2078, section 3.1
 * Copyright 2002, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-gssapi.h,v 1.9 2003/11/16 23:17:19 guy Exp $
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

#ifndef __PACKET_GSSAPI_H
#define __PACKET_GSSAPI_H

/* Structures needed outside */

typedef struct _gssapi_oid_value {
	protocol_t *proto;
	int ett;
	dissector_handle_t handle;
	dissector_handle_t wrap_handle;
	gchar *comment;  /* For the comment */
} gssapi_oid_value;

/* Function prototypes */

void
gssapi_init_oid(char *oid, int proto, int ett, dissector_handle_t handle,
		dissector_handle_t wrap_handle, gchar *comment);

gssapi_oid_value *
gssapi_lookup_oid(subid_t *oid, guint oid_len);

#endif /* __PACKET_GSSAPI_H */
