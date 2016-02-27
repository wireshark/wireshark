/* wtap_opttypes.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef WTAP_OPT_TYPES_H
#define WTAP_OPT_TYPES_H

#include "ws_symbol_export.h"

/* Currently supported option blocks */
typedef enum {
    WTAP_OPTION_BLOCK_IF_DESCR = 0,
    WTAP_OPTION_BLOCK_IF_STATS,
    WTAP_OPTION_BLOCK_NG_SECTION,
    WTAP_OPTION_BLOCK_NG_NRB
} wtap_optionblock_type_t;

/* Currently supported option types */
typedef enum {
    WTAP_OPTTYPE_UINT8,
    WTAP_OPTTYPE_UINT64,
    WTAP_OPTTYPE_STRING,
    WTAP_OPTTYPE_CUSTOM
} wtap_opttype_e;

typedef enum {
    WTAP_OPTTYPE_SUCCESS = 0,
    WTAP_OPTTYPE_NOT_FOUND = -1,
    WTAP_OPTTYPE_TYPE_MISMATCH = -2,
    WTAP_OPTTYPE_ALREADY_EXISTS = -3
} wtap_opttype_return_val;

typedef void (*wtap_opttype_free_custom_func)(void* data);

struct wtap_opttype_custom
{
    void* data;
    guint size;
    wtap_opttype_free_custom_func free_func;
};

typedef struct wtap_opttype {
    const char *name;                /**< name of option */
    const char *description;         /**< human-readable description of option */
    guint number;                    /**< Option index */
    wtap_opttype_e type;             /**< type of that option */
    union {
        guint8 uint8val;
        guint64 uint64val;
        char *stringval;
        struct wtap_opttype_custom customval;
    } option;                          /**< pointer to variable storing the value */
    union {
        guint8 uint8val;
        guint64 uint64val;
        char *stringval;
        struct wtap_opttype_custom customval;
    } default_val;                   /**< the default value of the option */
} wtap_opttype_t;

struct wtap_optionblock;
typedef struct wtap_optionblock *wtap_optionblock_t;

/** Initialize option block types.
 *
 * This is currently just a placeholder as nothing needs to be
 * initialized yet.  Should handle "registration" when code is
 * refactored to do so.
 */
void wtap_opttypes_initialize(void);

/** Create an option block by type
 *
 * Return a newly allocated option block with default options provided
 *
 * @param[in] block_type Option block type to be created
 * @return Newly allocated option block
 */
WS_DLL_PUBLIC wtap_optionblock_t wtap_optionblock_create(wtap_optionblock_type_t block_type);

/** Free an option block
 *
 * Needs to be called to clean up any allocated option block
 *
 * @param[in] block Block to be freed
 */
WS_DLL_PUBLIC void wtap_optionblock_free(wtap_optionblock_t block);

/** Provide mandatory data of an option block
 *
 * @param[in] block Block to retrieve mandatory data
 * @return Option block mandatory data.  Structure varies based on option block type
 */
WS_DLL_PUBLIC void* wtap_optionblock_get_mandatory_data(wtap_optionblock_t block);

/** Add a string option to the option block
 *
 * @param[in] block Block to add option
 * @param[in] option_id Identifier value for option
 * @param[in] name Name of option
 * @param[in] description Description of option
 * @param[in] opt_value Current value of option
 * @param[in] default_value Default value of option
 * @return 0 if successful
 */
int wtap_optionblock_add_option_string(wtap_optionblock_t block, guint option_id,
                                       const char *name, const char *description, char* opt_value, char* default_value);

/** Set string option value to an option block
 *
 * @param[in] block Block to add option
 * @param[in] option_id Identifier value for option
 * @param[in] opt_value New value of option
 * @return 0 if successful
 */
WS_DLL_PUBLIC int wtap_optionblock_set_option_string(wtap_optionblock_t block, guint option_id, char* opt_value);

/** Get string option value from an option block
 *
 * @param[in] block Block to add option
 * @param[in] option_id Identifier value for option
 * @param[out] opt_value Returned value of option
 * @return 0 if successful
 */
WS_DLL_PUBLIC int wtap_optionblock_get_option_string(wtap_optionblock_t block, guint option_id, char** opt_value);

/** Add UINT64 option to the option block
 *
 * @param[in] block Block to add option
 * @param[in] option_id Identifier value for option
 * @param[in] name Name of option
 * @param[in] description Description of option
 * @param[in] opt_value Current value of option
 * @param[in] default_value Default value of option
 * @return 0 if successful
 */
int wtap_optionblock_add_option_uint64(wtap_optionblock_t block, guint option_id,
                                       const char *name, const char *description, guint64 opt_value, guint64 default_value);

/** Set UINT64 option value to an option block
 *
 * @param[in] block Block to add option
 * @param[in] option_id Identifier value for option
 * @param[in] opt_value New value of option
 * @return 0 if successful
 */
WS_DLL_PUBLIC int wtap_optionblock_set_option_uint64(wtap_optionblock_t block, guint option_id, guint64 opt_value);

/** Get UINT64 option value from an option block
 *
 * @param[in] block Block to add option
 * @param[in] option_id Identifier value for option
 * @param[out] opt_value Returned value of option
 * @return 0 if successful
 */
WS_DLL_PUBLIC int wtap_optionblock_get_option_uint64(wtap_optionblock_t block, guint option_id, guint64* opt_value);

/** Add UINT8 option to the option block
 *
 * @param[in] block Block to add option
 * @param[in] option_id Identifier value for option
 * @param[in] name Name of option
 * @param[in] description Description of option
 * @param[in] opt_value Current value of option
 * @param[in] default_value Default value of option
 * @return 0 if successful
 */
int wtap_optionblock_add_option_uint8(wtap_optionblock_t block, guint option_id,
                                       const char *name, const char *description, guint8 opt_value, guint8 default_value);

/** Set UINT8 option value to an option block
 *
 * @param[in] block Block to add option
 * @param[in] option_id Identifier value for option
 * @param[in] opt_value New value of option
 * @return 0 if successful
 */
WS_DLL_PUBLIC int wtap_optionblock_set_option_uint8(wtap_optionblock_t block, guint option_id, guint8 opt_value);

/** Get UINT8 option value from an option block
 *
 * @param[in] block Block to add option
 * @param[in] option_id Identifier value for option
 * @param[out] opt_value Returned value of option
 * @return 0 if successful
 */
WS_DLL_PUBLIC int wtap_optionblock_get_option_uint8(wtap_optionblock_t block, guint option_id, guint8* opt_value);

/** Add a "custom" option to the option block
 *
 * @param[in] block Block to add option
 * @param[in] option_id Identifier value for option
 * @param[in] name Name of option
 * @param[in] description Description of option
 * @param[in] opt_value Current value of option
 * @param[in] default_value Default value of option
 * @param[in] size Size of the option structure
 * @param[in] free_func Function to free to the option structure
 * @return 0 if successful
 */
int wtap_optionblock_add_option_custom(wtap_optionblock_t block, guint option_id,
                                       const char *name, const char *description, void* opt_value, void* default_value,
                                       guint size, wtap_opttype_free_custom_func free_func);

/** Set a "custom" option value to an option block
 *
 * @param[in] block Block to add option
 * @param[in] option_id Identifier value for option
 * @param[in] opt_value New value of option
 * @return 0 if successful
 */
WS_DLL_PUBLIC int wtap_optionblock_set_option_custom(wtap_optionblock_t block, guint option_id, void* opt_value);

/** Get a "custom" option value from an option block
 *
 * @param[in] block Block to add option
 * @param[in] option_id Identifier value for option
 * @param[out] opt_value Returned value of option
 * @return 0 if successful
 */
WS_DLL_PUBLIC int wtap_optionblock_get_option_custom(wtap_optionblock_t block, guint option_id, void** opt_value);

/** Copy an option block to another.
 *
 * Any options that are in the destination but not the source are not removed.
 * Options that are just in source will be added to destination
 *
 * @param[in] dest_block Block to be copied to
 * @param[in] src_block Block to be copied from
 */
void wtap_optionblock_copy_options(wtap_optionblock_t dest_block, wtap_optionblock_t src_block);

#endif /* WTAP_OPT_TYPES_H */

