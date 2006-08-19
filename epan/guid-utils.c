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
#include <epan/emem.h>
#include "guid-utils.h"

#ifdef _WIN32
#include <tchar.h>
#include <windows.h>
#endif

static emem_tree_t *guid_to_name_tree = NULL;


/* store a guid to name mapping */
void 
guids_add_guid(e_guid_t *guid, const gchar *name)
{
	emem_tree_key_t guidkey[2];
	guint32 g[4];

	g[0]=guid->data1;

	g[1]=guid->data2;
	g[1]<<=16;
	g[1]|=guid->data3;

	g[2]=guid->data4[0];
	g[2]<<=8;
	g[2]|=guid->data4[1];
	g[2]<<=8;
	g[2]|=guid->data4[2];
	g[2]<<=8;
	g[2]|=guid->data4[3];

	g[3]=guid->data4[4];
	g[3]<<=8;
	g[3]|=guid->data4[5];
	g[3]<<=8;
	g[3]|=guid->data4[6];
	g[3]<<=8;
	g[3]|=guid->data4[7];

	guidkey[0].key=g;
	guidkey[0].length=4;
	guidkey[1].length=0;
	
	pe_tree_insert32_array(guid_to_name_tree, &guidkey[0], name);
}


/* retreive the registered name for this GUID */
const gchar *
guids_get_guid_name(e_guid_t *guid)
{
	emem_tree_key_t guidkey[2];
	guint32 g[4];
	char *name;
#ifdef _WIN32
	static char *uuid_name;
#endif

	g[0]=guid->data1;

	g[1]=guid->data2;
	g[1]<<=16;
	g[1]|=guid->data3;

	g[2]=guid->data4[0];
	g[2]<<=8;
	g[2]|=guid->data4[1];
	g[2]<<=8;
	g[2]|=guid->data4[2];
	g[2]<<=8;
	g[2]|=guid->data4[3];

	g[3]=guid->data4[4];
	g[3]<<=8;
	g[3]|=guid->data4[5];
	g[3]<<=8;
	g[3]|=guid->data4[6];
	g[3]<<=8;
	g[3]|=guid->data4[7];

	guidkey[0].key=g;
	guidkey[0].length=4;
	guidkey[1].length=0;
	
	if((name = pe_tree_lookup32_array(guid_to_name_tree, &guidkey[0]))){
		return name;
	}

#ifdef _WIN32
	/* try to resolve the mapping from the Windows registry */
	/* XXX - prefill the resolving database with all the Windows registry entries once at init only (instead of searching each time)? */
	uuid_name=ep_alloc(128);
	if(ResolveWin32UUID(*guid, uuid_name, 128)) {
		return uuid_name;
	}
#endif

	return NULL;
}


void 
guids_init(void)
{
	guid_to_name_tree=pe_tree_create(EMEM_TREE_TYPE_RED_BLACK, "guid_to_name");
	/* XXX here is a good place to read a config file with wellknown guids */
}



#ifdef _WIN32
/* try to resolve an DCE/RPC interface name to it's name using the Windows registry entries */
/* XXX - might be better to fill all interfaces into our database at startup instead of searching each time */
int 
ResolveWin32UUID(e_guid_t if_id, char *uuid_name, int uuid_name_max_len)
{
	TCHAR *reg_uuid_name;
	HKEY hKey = NULL;
	DWORD uuid_max_size = MAX_PATH;
	TCHAR *reg_uuid_str;

	reg_uuid_name=ep_alloc(MAX_PATH*sizeof(TCHAR));
	reg_uuid_str=ep_alloc(MAX_PATH*sizeof(TCHAR));

	if(uuid_name_max_len < 2){
		return 0;
	}
	reg_uuid_name[0] = '\0';
	_snwprintf(reg_uuid_str, MAX_PATH, _T("SOFTWARE\\Classes\\Interface\\{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}"),
			if_id.data1, if_id.data2, if_id.data3,
			if_id.data4[0], if_id.data4[1],
			if_id.data4[2], if_id.data4[3],
			if_id.data4[4], if_id.data4[5],
			if_id.data4[6], if_id.data4[7]);
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, reg_uuid_str, 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
		if (RegQueryValueEx(hKey, NULL, NULL, NULL, (LPBYTE)reg_uuid_name, &uuid_max_size) == ERROR_SUCCESS && uuid_max_size <= MAX_PATH) {
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
const gchar *
guids_resolve_guid_to_str(e_guid_t *guid)
{
	const gchar *name;
	gchar *namebuf;

	name=guids_get_guid_name(guid);
	if(name){
		return name;
	}


	namebuf=ep_alloc(64);
	g_snprintf(namebuf, 64, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                      guid->data1, guid->data2, guid->data3,
                      guid->data4[0], guid->data4[1],
                      guid->data4[2], guid->data4[3],
                      guid->data4[4], guid->data4[5],
                      guid->data4[6], guid->data4[7]);
	return namebuf;
}


