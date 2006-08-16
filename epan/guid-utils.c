/* guid-utils.c
 * GUID handling
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include <glib.h>
#include "guid-utils.h"

static gint
guid_equal (gconstpointer k1, gconstpointer k2)
{
    const guid_key *key1 = (const guid_key *)k1;
    const guid_key *key2 = (const guid_key *)k2;
    return ((memcmp (&key1->guid, &key2->guid, sizeof (e_guid_t)) == 0));
}

static guint
guid_hash (gconstpointer k)
{
    const guid_key *key = (const guid_key *)k;
    /* This isn't perfect, but the Data1 part of these is almost always
       unique. */
    return key->guid.data1;
}


GHashTable *guids_new(void)
{
    return g_hash_table_new (guid_hash, guid_equal);
}

void guids_add_guid(GHashTable *guids, e_guid_t *guid, gchar *name, void *private_data)
{
    guid_key *key = g_malloc (sizeof (*key));
    guid_value *value = g_malloc (sizeof (*value));

    key->guid = *guid;

    value->name = name;

    g_hash_table_insert (guids, key, value);
}


/* try to get registered name for this guid */
const gchar *guids_get_guid_name(GHashTable *guids, e_guid_t *guid)
{
    guid_key key;
    guid_value *value;


	/* try to get registered guid "name" of if_id */
	key.guid = *guid;

    if ((value = g_hash_table_lookup (guids, &key)) != NULL) {
		return value->name;
	}

	return NULL;
}
