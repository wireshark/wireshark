/* guid-utils.h
 * Definitions for GUID handling
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 *
 * Copyright 1998 Gerald Combs
 *
 * MobileIPv6 support added by Tomislav Borosa <tomislav.borosa@siemens.hr>
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

#ifndef __GUID_UTILS_H__
#define __GUID_UTILS_H__

#define GUID_LEN	16

/* Note: this might be larger than GUID_LEN, so don't overlay data in packets
   with this. */
typedef struct _e_guid_t {
    guint32 data1;
    guint16 data2;
    guint16 data3;
    guint8  data4[8];
} e_guid_t;


/* GUID "registry" */
typedef struct _guid_key {
    e_guid_t guid;
} guid_key;

typedef struct _guid_value {
    const gchar *name;
} guid_value;


extern GHashTable *guids_new(void);

/* add a GUID (don't forget to init the GHashTable) */
extern void guids_add_guid(GHashTable *guids, e_guid_t *guid, gchar *name, void *private_data);

/* try to get registered name for this guid */
extern const gchar *guids_get_guid_name(GHashTable *guids, e_guid_t *guid);

#endif /* __GUID_UTILS_H__ */
