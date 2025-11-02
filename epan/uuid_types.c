/** @file
 * UUID type handling
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <glib.h>
#include <epan/proto.h>

#include "uuid_types.h"

typedef struct _uuid_table_data_t
{
    int id;
    wmem_map_t* uuids;
    UUIDToString tostr;
} uuid_table_data_t;

static wmem_map_t* all_uuids;
static int num_dissector_uuid_type;

#define MAX_UUID_TYPE_VALUE     10

/* Keep track of UUID tables via their id number */
static uuid_table_data_t* uuid_type_list[MAX_UUID_TYPE_VALUE + 1];

void uuid_types_initialize(void)
{
    num_dissector_uuid_type = 0;
    all_uuids = wmem_map_new(wmem_epan_scope(), g_str_hash, g_str_equal);
}

int uuid_type_dissector_register(const char* name,
    GHashFunc hash_func, GEqualFunc key_equal_func, UUIDToString tostr_func)
{
    uuid_table_data_t* table_data = wmem_new(wmem_epan_scope(), uuid_table_data_t);
    table_data->uuids = wmem_map_new_autoreset(wmem_epan_scope(), wmem_epan_scope(), hash_func, key_equal_func);
    table_data->tostr = tostr_func;

    DISSECTOR_ASSERT(num_dissector_uuid_type < MAX_UUID_TYPE_VALUE);

    if (wmem_map_insert(all_uuids, (void *)name, table_data) != NULL)
        return 0;

    num_dissector_uuid_type++;
    table_data->id = num_dissector_uuid_type;
    uuid_type_list[num_dissector_uuid_type] = table_data;

    return num_dissector_uuid_type;
}

int uuid_type_get_id_by_name(const char* name)
{
    uuid_table_data_t* uuid_table = (uuid_table_data_t*)wmem_map_lookup(all_uuids, name);
    if (uuid_table)
        return uuid_table->id;

    return 0;
}

void uuid_type_foreach(const char* name, GHFunc func, void* param)
{
    uuid_table_data_t* uuid_table = (uuid_table_data_t*)wmem_map_lookup(all_uuids, name);
    if (uuid_table)
        wmem_map_foreach(uuid_table->uuids, func, param);
}

void uuid_type_foreach_by_id(int id, GHFunc func, void* param)
{
    DISSECTOR_ASSERT((id <= num_dissector_uuid_type) && (id > 0));
    uuid_table_data_t* uuid_table = uuid_type_list[id];

    if (uuid_table)
        wmem_map_foreach(uuid_table->uuids, func, param);
}

void uuid_type_insert(int id, void* uuid, void* value)
{
    DISSECTOR_ASSERT((id <= num_dissector_uuid_type) && (id > 0));
    uuid_table_data_t* uuid_table = uuid_type_list[id];

    if (uuid_table)
        wmem_map_insert(uuid_table->uuids, uuid, value);
}

void* uuid_type_lookup(int id, void* uuid)
{
    DISSECTOR_ASSERT((id <= num_dissector_uuid_type) && (id > 0));
    uuid_table_data_t* uuid_table = uuid_type_list[id];

    if (uuid_table)
    {
        //Ensure a valid UUID
        if (uuid == NULL)
            return NULL;

        return wmem_map_lookup(uuid_table->uuids, uuid);
    }

    return NULL;
}

bool uuid_type_remove_if_present(int id, void* uuid)
{
    DISSECTOR_ASSERT((id <= num_dissector_uuid_type) && (id > 0));
    uuid_table_data_t* uuid_table = uuid_type_list[id];

    if (uuid_table == NULL)
        return false;

    if (!wmem_map_contains(uuid_table->uuids, uuid))
        return false;

    return (wmem_map_remove(uuid_table->uuids, uuid) != NULL);
}

const char* uuid_type_get_uuid_name(const char* name, void* uuid, wmem_allocator_t* scope)
{
    uuid_table_data_t* uuid_table = (uuid_table_data_t*)wmem_map_lookup(all_uuids, name);
    DISSECTOR_ASSERT(uuid_table);
    DISSECTOR_ASSERT(uuid_table->tostr);
    if ((uuid_table == NULL) || (uuid_table->tostr == NULL))
        return wmem_strdup(scope, "<Unknown>");

    return uuid_table->tostr(uuid, scope);
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
