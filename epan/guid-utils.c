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
#include <epan/epan.h>
#include <epan/strutil.h>
#include "guid-utils.h"

#ifdef _WIN32
#include <tchar.h>
#include <windows.h>
#endif


/* GUID "registry" */
typedef struct _guid_key {
    e_guid_t guid;
} guid_key;

typedef struct _guid_value {
    const gchar *name;
} guid_value;


/* global guid to name collection */
GHashTable *guids = NULL;


#ifdef _WIN32
/* try to resolve an DCE/RPC interface name to it's name using the Windows registry entries */
/* XXX - might be better to fill all interfaces into our database at startup instead of searching each time */
int ResolveWin32UUID(e_guid_t if_id, char *uuid_name, int uuid_name_max_len)
{
	TCHAR reg_uuid_name[MAX_PATH];
	HKEY hKey = NULL;
	DWORD uuid_max_size = MAX_PATH;
	TCHAR reg_uuid_str[MAX_PATH];

	if(uuid_name_max_len < 2)
		return 0;
	reg_uuid_name[0] = '\0';
	_snwprintf(reg_uuid_str, MAX_PATH, _T("SOFTWARE\\Classes\\Interface\\{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}"),
			if_id.data1, if_id.data2, if_id.data3,
			if_id.data4[0], if_id.data4[1],
			if_id.data4[2], if_id.data4[3],
			if_id.data4[4], if_id.data4[5],
			if_id.data4[6], if_id.data4[7]);
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, reg_uuid_str, 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
	{
		if (RegQueryValueEx(hKey, NULL, NULL, NULL, (LPBYTE)reg_uuid_name, &uuid_max_size) == ERROR_SUCCESS && uuid_max_size <= MAX_PATH)
			{
			g_snprintf(uuid_name, uuid_name_max_len, "%s", utf_16to8(reg_uuid_name));
			RegCloseKey(hKey);
			return strlen(uuid_name);
		}
		RegCloseKey(hKey);
	}
	return 0; /* we didn't find anything anyhow. Please don't use the string! */

}
#endif


/* Tries to match a guid against its name.
   Returns the associated string ptr on a match.
   Formats uuid number and returns the resulting string, if name is unknown.
   (derived from val_to_str) */
const gchar* guids_resolve_guid_to_str(e_guid_t *guid) {
  const gchar *ret;
  static gchar  str[3][64];
  static gchar *cur;


  ret = guids_get_guid_name(guid);
  if (ret != NULL)
    return ret;
  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {  
    cur = &str[2][0];
  } else {  
    cur = &str[0][0];
  }
  g_snprintf(cur, 64, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                      guid->data1, guid->data2, guid->data3,
                      guid->data4[0], guid->data4[1],
                      guid->data4[2], guid->data4[3],
                      guid->data4[4], guid->data4[5],
                      guid->data4[6], guid->data4[7]);
  return cur;
}


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

void guids_init(void)
{
    g_assert(guids == NULL);

    guids = g_hash_table_new (guid_hash, guid_equal);
}

void guids_add_guid(e_guid_t *guid, const gchar *name)
{
    guid_key *key = g_malloc (sizeof (*key));
    guid_value *value = g_malloc (sizeof (*value));

    key->guid = *guid;

    /* XXX - do we need to copy the name? */
    value->name = name;

    g_hash_table_insert (guids, key, value);
}


/* try to get registered name for this GUID */
const gchar *guids_get_guid_name(e_guid_t *guid)
{
    guid_key key;
    guid_value *value;
#ifdef _WIN32
    /* XXX - we need three time circulating buffer here */
    /* XXX - is there a maximum length of the name? */
    static char uuid_name[128];
#endif

	/* try to get registered guid "name" of guid */
	key.guid = *guid;

    if ((value = g_hash_table_lookup (guids, &key)) != NULL) {
		return value->name;
	}

#ifdef _WIN32
    /* try to resolve the mapping from the Windows registry */
    /* XXX - prefill the resolving database with all the Windows registry entries once at init only (instead of searching each time)? */
    if(ResolveWin32UUID(*guid, uuid_name, 128)) {
        return uuid_name;
    }
#endif

	return NULL;
}
