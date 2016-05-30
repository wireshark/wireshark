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

struct wtap_optionblock;
typedef struct wtap_optionblock *wtap_optionblock_t;

/* Currently supported option blocks */
typedef enum {
    WTAP_OPTION_BLOCK_IF_DESCR = 0,
    WTAP_OPTION_BLOCK_IF_STATS,
    WTAP_OPTION_BLOCK_NG_SECTION,
    WTAP_OPTION_BLOCK_NG_NRB,
    WTAP_OPTION_BLOCK_END_OF_LIST
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

typedef union {
    guint8 uint8val;
    guint64 uint64val;
    char *stringval;
    struct wtap_opttype_custom customval;
} wtap_option_type;

struct wtap_dumper;

typedef void (*wtap_block_create_func)(wtap_optionblock_t block);
typedef void (*wtap_mand_free_func)(wtap_optionblock_t block);
typedef void (*wtap_mand_copy_func)(wtap_optionblock_t dest_block, wtap_optionblock_t src_block);

typedef struct wtap_optblock_reg {
    const char *name;                /**< name of option */
    const char *description;         /**< human-readable description of option */
    wtap_opttype_e type;             /**< type of that option */
    wtap_option_type option;         /**< pointer to variable storing the value */
    wtap_option_type default_val;    /**< the default value of the option */
} wtap_optblock_reg_t;

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
WS_DLL_PUBLIC wtap_optionblock_t wtap_optionblock_create(int block_type);

/** Free an option block
 *
 * Needs to be called to clean up any allocated option block
 *
 * @param[in] block Block to be freed
 */
WS_DLL_PUBLIC void wtap_optionblock_free(wtap_optionblock_t block);

/** Provide mandatory data of an option block
 *
 * @param[in] block Block from which to retrieve mandatory data
 * @return Option block mandatory data.  Structure varies based on option block type
 */
WS_DLL_PUBLIC void* wtap_optionblock_get_mandatory_data(wtap_optionblock_t block);

/** Add an option to the option block
 *
 * @param[in] block Block to which to add option
 * @param[in] option_id Identifier value for option
 * @param[in] option structure explaining it
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_optionblock_add_option(wtap_optionblock_t block, guint option_id, wtap_optblock_reg_t* option);

/** Set string option value in an option block
 *
 * @param[in] block Block in which to set the option value
 * @param[in] option_id Identifier value for option
 * @param[in] value New value of option
 * @param[in] value_length Maximum length of string to copy.
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_optionblock_set_option_string(wtap_optionblock_t block, guint option_id, char* value, gsize value_length);

/** Set string option value in an option block to a printf-formatted string
 *
 * @param[in] block Block in which to set the option value
 * @param[in] option_id Identifier value for option
 * @param[in] format printf-like format string
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_optionblock_set_option_string_format(wtap_optionblock_t block, guint option_id, const char *format, ...)
                                          G_GNUC_PRINTF(3,4);

/** Get string option value from an option block
 *
 * @param[in] block Block from which to get the option value
 * @param[in] option_id Identifier value for option
 * @param[out] value Returned value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_optionblock_get_option_string(wtap_optionblock_t block, guint option_id, char** value);

/** Set UINT64 option value in an option block
 *
 * @param[in] block Block in which to set the option value
 * @param[in] option_id Identifier value for option
 * @param[in] value New value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_optionblock_set_option_uint64(wtap_optionblock_t block, guint option_id, guint64 value);

/** Get UINT64 option value from an option block
 *
 * @param[in] block Block from which to get the option value
 * @param[in] option_id Identifier value for option
 * @param[out] value Returned value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_optionblock_get_option_uint64(wtap_optionblock_t block, guint option_id, guint64* value);

/** Set UINT8 option value in an option block
 *
 * @param[in] block Block in which to set the option value
 * @param[in] option_id Identifier value for option
 * @param[in] value New value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_optionblock_set_option_uint8(wtap_optionblock_t block, guint option_id, guint8 value);

/** Get UINT8 option value from an option block
 *
 * @param[in] block Block from which to get the option value
 * @param[in] option_id Identifier value for option
 * @param[out] value Returned value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_optionblock_get_option_uint8(wtap_optionblock_t block, guint option_id, guint8* value);

/** Set a "custom" option value in an option block
 *
 * @param[in] block Block in which to set the option value
 * @param[in] option_id Identifier value for option
 * @param[in] value New value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_optionblock_set_option_custom(wtap_optionblock_t block, guint option_id, void* value);

/** Get a "custom" option value from an option block
 *
 * @param[in] block Block from which to get the option value
 * @param[in] option_id Identifier value for option
 * @param[out] value Returned value of option
 * @return wtap_opttype_return_val - WTAP_OPTTYPE_SUCCESS if successful,
 * error code otherwise
 */
WS_DLL_PUBLIC wtap_opttype_return_val
wtap_optionblock_get_option_custom(wtap_optionblock_t block, guint option_id, void** value);

/** Copy an option block to another.
 *
 * Any options that are in the destination but not the source are not removed.
 * Options that are just in source will be added to destination
 *
 * @param[in] dest_block Block to be copied to
 * @param[in] src_block Block to be copied from
 */
void wtap_optionblock_copy_options(wtap_optionblock_t dest_block, wtap_optionblock_t src_block);


typedef void (*wtap_optionblock_foreach_func)(wtap_optionblock_t block, guint option_id, wtap_opttype_e option_type, wtap_option_type* option, void* user_data);
WS_DLL_PUBLIC void wtap_optionblock_foreach_option(wtap_optionblock_t block, wtap_optionblock_foreach_func func, void* user_data);

WS_DLL_PUBLIC int wtap_opttype_register_custom_block_type(const char* name, const char* description, wtap_block_create_func create,
                                                wtap_mand_free_func free_mand, wtap_mand_copy_func copy_mand);


#endif /* WTAP_OPT_TYPES_H */

