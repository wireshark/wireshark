/* oid_resolv.h
 * Definitions for OBJECT IDENTIFIER name resolution
 *
 * $Id$
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
/* The buffers returned by these functions are all allocated with a 
 * packet lifetime or are static buffers and does not have have to be freed. 
 * However, take into account that when the packet dissection
 * completes, these buffers will be automatically reclaimed/freed.
 * If you need the buffer to remain for a longer scope than packet lifetime
 * you must copy the content to an se_alloc() buffer.
 */

#ifndef __OID_RESOLV_H__
#define __OID_RESOLV_H__

/* init and clenup funcions called from epan.h */
extern void oid_resolv_init(void);
extern void oid_resolv_cleanup(void);

extern gboolean oid_resolv_enabled(void);

/* get_oid_name returns OID name from oid_table or MIBs database */
extern const gchar *get_oid_name(const guint8 *oid, gint oid_len);
extern const gchar *get_oid_str_name(const gchar *oid_str);

/* add OID name into oid_table */
extern void add_oid_name(const guint8 *oid, gint oid_len, const gchar *name);
extern void add_oid_str_name(const gchar *oid_str, const gchar *name);


#endif /* __OID_RESOLV_H__ */
