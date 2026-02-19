/* guid-utils.c
 * GUID handling
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 *
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <glib.h>
#include <epan/epan.h>
#include <wsutil/unicode-utils.h>
#include <epan/wmem_scopes.h>
#include "guid-utils.h"
#include "uuid_types.h"

#ifdef _WIN32
#include <tchar.h>
#include <windows.h>
#include <strsafe.h>
#endif

static int guid_id;

#ifdef _WIN32
/* try to resolve an DCE/RPC interface name to its name using the Windows registry entries */
/* XXX - might be better to fill all interfaces into our database at startup instead of searching each time */
static int
ResolveWin32UUID(e_guid_t if_id, char *uuid_name, int uuid_name_max_len)
{
	TCHAR *reg_uuid_name;
	HKEY hKey = NULL;
	DWORD uuid_max_size = MAX_PATH;
	TCHAR *reg_uuid_str;

	reg_uuid_name=wmem_alloc(NULL, (MAX_PATH*sizeof(TCHAR))+1);
	reg_uuid_str=wmem_alloc(NULL, (MAX_PATH*sizeof(TCHAR))+1);

	if(uuid_name_max_len < 2){
		return 0;
	}
	reg_uuid_name[0] = '\0';
	StringCchPrintf(reg_uuid_str, MAX_PATH, _T("SOFTWARE\\Classes\\Interface\\{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}"),
			if_id.data1, if_id.data2, if_id.data3,
			if_id.data4[0], if_id.data4[1],
			if_id.data4[2], if_id.data4[3],
			if_id.data4[4], if_id.data4[5],
			if_id.data4[6], if_id.data4[7]);
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, reg_uuid_str, 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
		if (RegQueryValueEx(hKey, NULL, NULL, NULL, (LPBYTE)reg_uuid_name, &uuid_max_size) == ERROR_SUCCESS && uuid_max_size <= MAX_PATH) {
			snprintf(uuid_name, uuid_name_max_len, "%s", utf_16to8(reg_uuid_name));
			RegCloseKey(hKey);
			wmem_free(NULL, reg_uuid_name);
			wmem_free(NULL, reg_uuid_str);
			return (int) strlen(uuid_name);
		}
		RegCloseKey(hKey);
	}
	wmem_free(NULL, reg_uuid_name);
	wmem_free(NULL, reg_uuid_str);
	return 0; /* we didn't find anything anyhow. Please don't use the string! */

}
#endif

/* Wrapper of guid_hash to use in uuid_type_dissector_register() */
static unsigned
uuid_guid_hash(const void* guid)
{
	return guid_hash((const e_guid_t*)guid);
}

/* Wrapper of guid_cmp to use in uuid_type_dissector_register() */
static gboolean
uuid_guid_equal(const void* g1, const void* g2)
{
	return (guid_cmp((const e_guid_t*)g1, (const e_guid_t*)g2) == 0);
}

/* Wrapper of guids_get_guid_name to use in uuid_type_dissector_register() */
static const char*
uuid_guid_to_str(void* uuid, wmem_allocator_t* scope)
{
	return guids_get_guid_name((const e_guid_t*)uuid, scope);
}

void
guids_init(void)
{
	guid_id = uuid_type_dissector_register("guid_global", uuid_guid_hash, uuid_guid_equal, uuid_guid_to_str);
	/* XXX here is a good place to read a config file with wellknown guids */
}

void
guids_add_guid(const e_guid_t* guid, const char* name)
{
	/* The previous implementation used a wmem_tree with an array
	 * of 32-bit keys, allowing callers to pass in a pointer to a
	 * e_guid_t allocated on the stack. To insert into a map, the
	 * e_guid_t key needs to be copied to heap-allocated memory.
	 */
	e_guid_t* guid_key = wmem_new(wmem_epan_scope(), e_guid_t);
	*guid_key = *guid;
	uuid_type_insert(guid_id, (void*)guid_key, (void*)name);
}

void
guids_delete_guid(const e_guid_t* guid)
{
	uuid_type_remove_if_present(guid_id, (void*)guid);
}

const char*
guids_get_guid_name(const e_guid_t* guid, wmem_allocator_t* scope _U_)
{
	char* name;
#ifdef _WIN32
	static char* uuid_name;
#endif

	if ((name = (char*)uuid_type_lookup(guid_id, (void*)guid))) {
		return name;
	}

#ifdef _WIN32
	/* try to resolve the mapping from the Windows registry */
	/* XXX - prefill the resolving database with all the Windows registry entries once at init only (instead of searching each time)? */
	uuid_name = wmem_alloc(scope, 128);
	if (ResolveWin32UUID(*guid, uuid_name, 128)) {
		return uuid_name;
	}
#endif

	return NULL;
}

const char *
guids_resolve_guid_to_str(const e_guid_t *guid, wmem_allocator_t *scope)
{
	const char *name;

	name=guids_get_guid_name(guid, scope);
	if(name){
		return name;
	}

	return wmem_strdup_printf(scope, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
				guid->data1, guid->data2, guid->data3,
				guid->data4[0], guid->data4[1],
				guid->data4[2], guid->data4[3],
				guid->data4[4], guid->data4[5],
				guid->data4[6], guid->data4[7]);
}

int guid_cmp(const e_guid_t *g1, const e_guid_t *g2)
{
	if (g1->data1 != g2->data1) {
		return (g1->data1 < g2->data1) ? -1 : 1;
	}

	if (g1->data2 != g2->data2) {
		return (g1->data2 < g2->data2) ? -1 : 1;
	}

	if (g1->data3 != g2->data3) {
		return (g1->data3 < g2->data3) ? -1 : 1;
	}

	return memcmp(&g1->data4[0], &g2->data4[0], 8);
}

unsigned guid_hash(const e_guid_t *guid)
{
	return g_int64_hash((const int64_t *)guid);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
