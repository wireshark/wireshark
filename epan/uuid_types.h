/** @file
 * Definitions for UUID type handling
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __UUID_TYPES_H__
#define __UUID_TYPES_H__

#include "ws_symbol_export.h"
#include <epan/wmem_scopes.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Initialize the UUID handling component
 *
 * Called during epan initialization, this sets up the table for
 * components to register their specific UUID handling
 */
WS_DLL_PUBLIC void uuid_types_initialize(void);

typedef const char* (*UUIDToString)(void* uuid, wmem_allocator_t* scope);

/**
 * @brief Register a UUID type for handling
 *
 * Create a UUID type and provide its processing functions
 *
 * @param name Name of the UUID to be referenced by external components
 * @param hash_func Function to hash the UUID to a 32-bit value
 * @param key_equal_func Function to determine if two UUID values are equal
 * @param tostr_func Function that converts UUID into a friendly string value (may resolve to name)
 * @return Identifier to be used for subsequent calls of the UUID type
 */
WS_DLL_PUBLIC int uuid_type_dissector_register(const char* name,
    GHashFunc hash_func, GEqualFunc key_equal_func, UUIDToString tostr_func);


/**
 * @brief Get the ID of a registered UUID type
 *
 * Get the identifier of a registered UUID type to use for other API calls
 *
 * @param name Name of the UUID type
 * @return Identifier of the UUID type if found, 0 otherwise
 */
WS_DLL_PUBLIC int uuid_type_get_id_by_name(const char* name);

/**
 * @brief Process all of the UUIDs in the table
 *
 * Iterate through all of the UUIDs in the table with a callback function.  The
 * callback function is responsible for knowing the data structure of the UUID
 *
 * @param name Name of the UUID type
 * @param func Function to be called on each UUID
 * @param param Optional data to be passed into the function as well
 */
WS_DLL_PUBLIC void uuid_type_foreach(const char* name, GHFunc func, void* param);

/**
 * @brief Process all of the UUIDs in the table
 *
 * Iterate through all of the UUIDs in the table with a callback function.  The
 * callback function is responsible for knowing the data structure of the UUID
 *
 * @param id Identifier of the UUID type
 * @param func Function to be called on each UUID
 * @param param Optional data to be passed into the function as well
 */
WS_DLL_PUBLIC void uuid_type_foreach_by_id(int id, GHFunc func, void* param);

/**
 * @brief Insert a UUID with value into a table
 *
 * Adds a UUID to data value into the table.  The data structure of the
 * UUID and value are type dependent by the identifier
 *
 * @param id Identifier of the UUID type table
 * @param uuid UUID key for the value
 * @param value Value associated with UUID
 */
WS_DLL_PUBLIC void uuid_type_insert(int id, void* uuid, void* value);

/**
 * @brief Find value associated with UUID from table
 *
 * Lookup the UUID to find the associated data with it.The data structure of the
 * UUID and value are type dependent by the identifier
 *
 * @param id Identifier of the UUID type table
 * @param uuid UUID key for the value
 * @return UUID value if found, NULL otherwise
 */
WS_DLL_PUBLIC void* uuid_type_lookup(int id, void* uuid);

/**
 * @brief Remove UUID from table
 *
 * Remove the UUID from the table if found. The data structure of the
 * UUID is type dependent by the identifier
 *
 * @param id Identifier of the UUID type table
 * @param uuid UUID key to be removed
 * @return true if value was found and removed, false otherwise
 */
WS_DLL_PUBLIC bool uuid_type_remove_if_present(int id, void* uuid);

/**
 * @brief Retrieve UUID "string name"
 *
 * Convert UUID to a string value.  What string returned is
 * based on the identifier type.  It may look up the UUID in
 * its table or just know how to turn the datatype into a string
 *
 * @param name Name of the UUID type
 * @param uuid UUID to be converted to a string
 * @param scope memory scope the name should be returned in
 * @return Converted UUID string value, may be NULL if UUID isn't found in the table
 */
WS_DLL_PUBLIC const char* uuid_type_get_uuid_name(const char* name, void* uuid, wmem_allocator_t* scope);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UUID_TYPES_H__ */
