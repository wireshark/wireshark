/* format-oid.h
 * Declare routine for formatting OIDs
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Didier Jorand
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

#ifndef __FORMAT_OID_H__
#define __FORMAT_OID_H__


extern int oid_to_subid_buf(const guint8 *oid, gint oid_len, subid_t *buf, int buf_len);
extern gchar *format_oid(subid_t *oid, guint oid_length);
extern void new_format_oid(subid_t *oid, guint oid_length, 
			   gchar **non_decoded, gchar **decoded);

#endif
