/* wtap_opttypes.c
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
#include "config.h"

#include <glib.h>
#include <string.h>

#include "wtap.h"
#include "wtap_opttypes.h"
#include "wtap-int.h"
#include "pcapng.h"
#include "pcapng_module.h"

#if 0
#define wtap_debug(...) g_warning(__VA_ARGS__)
#else
#define wtap_debug(...)
#endif

typedef struct wtap_opt_register
{
    const char *name;                /**< name of block */
    const char *description;         /**< human-readable description of block */
    wtap_block_create_func create;
    wtap_mand_free_func free_mand;
    wtap_mand_copy_func copy_mand;
} wtap_opt_register_t;

typedef struct wtap_optblock_internal {
    const char *name;                /**< name of option */
    const char *description;         /**< human-readable description of option */
    guint number;                    /**< Option index */
    wtap_opttype_e type;             /**< type of that option */
} wtap_optblock_internal_t;

typedef struct wtap_optblock_value {
    wtap_optblock_internal_t* info;
    wtap_option_type option;         /**< pointer to variable storing the value */
    wtap_option_type default_val;    /**< the default value of the option */
} wtap_optblock_value_t;

struct wtap_optionblock
{
    wtap_opt_register_t* info;
    void* mandatory_data;
    GArray* option_infos; /* Only want to keep 1 copy of "static" option information */
    GArray* option_values;
};

#define MAX_WTAP_OPTION_BLOCK_CUSTOM    10
#define MAX_WTAP_OPTION_BLOCK_TYPE_VALUE (WTAP_OPTION_BLOCK_END_OF_LIST+MAX_WTAP_OPTION_BLOCK_CUSTOM)

/* Keep track of wtap_opt_register_t's via their id number */
static wtap_opt_register_t* block_list[MAX_WTAP_OPTION_BLOCK_TYPE_VALUE];
static guint num_custom_blocks;
static wtap_opt_register_t custom_block_list[MAX_WTAP_OPTION_BLOCK_CUSTOM];

static void wtap_opttype_block_register(int block_type, wtap_opt_register_t *block)
{
    /* Check input */
    g_assert(block_type < WTAP_OPTION_BLOCK_END_OF_LIST);

    /* Don't re-register. */
    g_assert(block_list[block_type] == NULL);

    /* Sanity check */
    g_assert(block->name);
    g_assert(block->description);
    g_assert(block->create);

    block_list[block_type] = block;
}

int wtap_opttype_register_custom_block_type(const char* name, const char* description, wtap_block_create_func create,
                                                wtap_mand_free_func free_mand, wtap_mand_copy_func copy_mand)
{
    int block_type;

    /* Ensure valid data/functions for required fields */
    g_assert(name);
    g_assert(description);
    g_assert(create);

    /* This shouldn't happen, so flag it for fixing */
    g_assert(num_custom_blocks < MAX_WTAP_OPTION_BLOCK_CUSTOM);

    block_type = WTAP_OPTION_BLOCK_END_OF_LIST+num_custom_blocks;

    custom_block_list[num_custom_blocks].name = name;
    custom_block_list[num_custom_blocks].description = description;
    custom_block_list[num_custom_blocks].create = create;
    custom_block_list[num_custom_blocks].free_mand = free_mand;
    custom_block_list[num_custom_blocks].copy_mand = copy_mand;
    block_list[block_type] = &custom_block_list[num_custom_blocks];

    num_custom_blocks++;
    return block_type;
}

void* wtap_optionblock_get_mandatory_data(wtap_optionblock_t block)
{
    return block->mandatory_data;
}

static wtap_optblock_value_t* wtap_optionblock_get_option(wtap_optionblock_t block, guint option_id)
{
    guint i;
    wtap_optblock_value_t* opttype = NULL;

    for (i = 0; i < block->option_values->len; i++)
    {
        opttype = g_array_index(block->option_values, wtap_optblock_value_t*, i);
        if (opttype->info->number == option_id)
            return opttype;
    }

    return NULL;
}

wtap_optionblock_t wtap_optionblock_create(int block_type)
{
    wtap_optionblock_t block;

    if (block_type >= (int)(WTAP_OPTION_BLOCK_END_OF_LIST+num_custom_blocks))
        return NULL;

    block = g_new(struct wtap_optionblock, 1);
    block->info = block_list[block_type];
    block->option_infos = g_array_new(FALSE, FALSE, sizeof(wtap_optblock_internal_t*));
    block->option_values = g_array_new(FALSE, FALSE, sizeof(wtap_optblock_value_t*));
    block->info->create(block);

    return block;
}

static void wtap_optionblock_free_options(wtap_optionblock_t block)
{
    guint i;
    wtap_optblock_value_t* opttype = NULL;

    for (i = 0; i < block->option_values->len; i++) {
        opttype = g_array_index(block->option_values, wtap_optblock_value_t*, i);
        switch(opttype->info->type)
        {
        case WTAP_OPTTYPE_STRING:
            g_free(opttype->option.stringval);
            break;
        case WTAP_OPTTYPE_CUSTOM:
            opttype->option.customval.free_func(opttype->option.customval.data);
            g_free(opttype->option.customval.data);
            opttype->default_val.customval.free_func(opttype->default_val.customval.data);
            g_free(opttype->default_val.customval.data);
            break;
        default:
            break;
        }
        g_free(opttype);
    }
}

void wtap_optionblock_free(wtap_optionblock_t block)
{
    unsigned i;
    if (block != NULL)
    {
        if (block->info->free_mand != NULL)
            block->info->free_mand(block);

        g_free(block->mandatory_data);
        wtap_optionblock_free_options(block);
        for (i = 0; i < block->option_infos->len; i++)
            g_free(g_array_index(block->option_infos, wtap_optblock_internal_t*, i));
        if (block->option_infos != NULL)
            g_array_free(block->option_infos, TRUE);
        if (block->option_values != NULL)
            g_array_free(block->option_values, TRUE);
        g_free(block);
    }
}

void wtap_optionblock_copy_options(wtap_optionblock_t dest_block, wtap_optionblock_t src_block)
{
    guint i;
    wtap_optblock_internal_t *src_internal;
    wtap_optblock_value_t *dest_value, *src_value;

    if (dest_block->info->copy_mand != NULL)
        dest_block->info->copy_mand(dest_block, src_block);

    /* Copy the options.  For now, don't remove any options that are in destination
     * but not source.
     */
    for (i = 0; i < src_block->option_values->len; i++)
    {
        src_internal = g_array_index(src_block->option_infos, wtap_optblock_internal_t*, i);
        src_value = g_array_index(src_block->option_values, wtap_optblock_value_t*, i);
        dest_value = wtap_optionblock_get_option(dest_block, src_internal->number);
        if (dest_value == NULL)
        {
            wtap_optblock_reg_t reg_optblock;

            reg_optblock.name = src_internal->name;
            reg_optblock.description = src_internal->description;
            reg_optblock.type = src_internal->type;
            reg_optblock.option = src_value->option;
            reg_optblock.default_val = src_value->default_val;

            wtap_optionblock_add_option(dest_block, src_internal->number, &reg_optblock);
        }
        else
        {
            /* Option exists, replace it */
            switch(src_internal->type)
            {
            case WTAP_OPTTYPE_UINT8:
                dest_value->option.uint8val = src_value->option.uint8val;
                break;
            case WTAP_OPTTYPE_UINT64:
                dest_value->option.uint64val = src_value->option.uint64val;
                break;
            case WTAP_OPTTYPE_STRING:
                g_free(dest_value->option.stringval);
                dest_value->option.stringval = g_strdup(src_value->option.stringval);
                break;
            case WTAP_OPTTYPE_CUSTOM:
                dest_value->option.customval.free_func(dest_value->option.customval.data);
                g_free(dest_value->option.customval.data);
                dest_value->option.customval.data = g_memdup(src_value->option.customval.data, src_value->option.customval.size);
                break;
            }
        }
    }
}

void wtap_optionblock_foreach_option(wtap_optionblock_t block, wtap_optionblock_foreach_func func, void* user_data)
{
    guint i;
    wtap_optblock_internal_t *internal_data;
    wtap_optblock_value_t *value;

    for (i = 0; i < block->option_values->len; i++)
    {
        internal_data = g_array_index(block->option_infos, wtap_optblock_internal_t*, i);
        value = g_array_index(block->option_values, wtap_optblock_value_t*, i);
        func(block, internal_data->number, value->info->type, &value->option, user_data);
    }
}

int wtap_optionblock_add_option(wtap_optionblock_t block, guint option_id, wtap_optblock_reg_t* option)
{
    wtap_optblock_value_t* opt_value = wtap_optionblock_get_option(block, option_id);
    wtap_optblock_internal_t *opt_internal;

    /* Option already exists */
    if (opt_value != NULL)
        return WTAP_OPTTYPE_ALREADY_EXISTS;

    opt_value = g_new0(wtap_optblock_value_t, 1);
    opt_internal = g_new(wtap_optblock_internal_t, 1);

    opt_internal->name = option->name;
    opt_internal->description = option->description;
    opt_internal->number = option_id;
    opt_internal->type = option->type;

    opt_value->info = opt_internal;

    switch(option->type)
    {
    case WTAP_OPTTYPE_UINT8:
        opt_value->option.uint8val = option->option.uint8val;
        opt_value->default_val.uint8val = option->default_val.uint8val;
        break;
    case WTAP_OPTTYPE_UINT64:
        opt_value->option.uint64val = option->option.uint64val;
        opt_value->default_val.uint64val = option->default_val.uint64val;
        break;
    case WTAP_OPTTYPE_STRING:
        opt_value->option.stringval = g_strdup(option->option.stringval);
        opt_value->default_val.stringval = option->default_val.stringval;
        break;
    case WTAP_OPTTYPE_CUSTOM:
        opt_value->option.customval.size = option->option.customval.size;
        opt_value->option.customval.data = g_memdup(option->option.customval.data, option->option.customval.size);
        opt_value->option.customval.free_func = option->option.customval.free_func;
        opt_value->default_val.customval.size = option->default_val.customval.size;
        opt_value->default_val.customval.data = g_memdup(option->default_val.customval.data, option->default_val.customval.size);
        opt_value->default_val.customval.free_func = option->default_val.customval.free_func;
        break;
    }

    g_array_append_val(block->option_infos, opt_internal);
    g_array_append_val(block->option_values, opt_value);
    return WTAP_OPTTYPE_SUCCESS;
}

int wtap_optionblock_set_option_string(wtap_optionblock_t block, guint option_id, char* value, gsize value_length)
{
    wtap_optblock_value_t* opt_value = wtap_optionblock_get_option(block, option_id);

    /* Didn't find the option */
    if (opt_value == NULL)
        return WTAP_OPTTYPE_NOT_FOUND;

    if (opt_value->info->type != WTAP_OPTTYPE_STRING)
        return WTAP_OPTTYPE_TYPE_MISMATCH;

    g_free(opt_value->option.stringval);
    opt_value->option.stringval = g_strndup(value, value_length);
    return WTAP_OPTTYPE_SUCCESS;
}

int wtap_optionblock_set_option_string_format(wtap_optionblock_t block, guint option_id, const char *format, ...)
{
    va_list va;
    wtap_optblock_value_t* opt_value = wtap_optionblock_get_option(block, option_id);

    /* Didn't find the option */
    if (opt_value == NULL)
        return WTAP_OPTTYPE_NOT_FOUND;

    if (opt_value->info->type != WTAP_OPTTYPE_STRING)
        return WTAP_OPTTYPE_TYPE_MISMATCH;

    g_free(opt_value->option.stringval);
    va_start(va, format);
    opt_value->option.stringval = g_strdup_vprintf(format, va);
    va_end(va);
    return WTAP_OPTTYPE_SUCCESS;
}

int wtap_optionblock_get_option_string(wtap_optionblock_t block, guint option_id, char** value)
{
    wtap_optblock_value_t* opt_value = wtap_optionblock_get_option(block, option_id);

    /* Didn't find the option */
    if (opt_value == NULL)
        return WTAP_OPTTYPE_NOT_FOUND;

    if (opt_value->info->type != WTAP_OPTTYPE_STRING)
        return WTAP_OPTTYPE_TYPE_MISMATCH;

    *value = opt_value->option.stringval;
    return WTAP_OPTTYPE_SUCCESS;
}

int wtap_optionblock_set_option_uint64(wtap_optionblock_t block, guint option_id, guint64 value)
{
    wtap_optblock_value_t* opt_value = wtap_optionblock_get_option(block, option_id);

    /* Didn't find the option */
    if (opt_value == NULL)
        return WTAP_OPTTYPE_NOT_FOUND;

    if (opt_value->info->type != WTAP_OPTTYPE_UINT64)
        return WTAP_OPTTYPE_TYPE_MISMATCH;

    opt_value->option.uint64val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

int wtap_optionblock_get_option_uint64(wtap_optionblock_t block, guint option_id, guint64* value)
{
    wtap_optblock_value_t* opt_value = wtap_optionblock_get_option(block, option_id);

    /* Didn't find the option */
    if (opt_value == NULL)
        return WTAP_OPTTYPE_NOT_FOUND;

    if (opt_value->info->type != WTAP_OPTTYPE_UINT64)
        return WTAP_OPTTYPE_TYPE_MISMATCH;

    *value = opt_value->option.uint64val;
    return WTAP_OPTTYPE_SUCCESS;
}


int wtap_optionblock_set_option_uint8(wtap_optionblock_t block, guint option_id, guint8 value)
{
    wtap_optblock_value_t* opt_value = wtap_optionblock_get_option(block, option_id);

    /* Didn't find the option */
    if (opt_value == NULL)
        return WTAP_OPTTYPE_NOT_FOUND;

    if (opt_value->info->type != WTAP_OPTTYPE_UINT8)
        return WTAP_OPTTYPE_TYPE_MISMATCH;

    opt_value->option.uint8val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

int wtap_optionblock_get_option_uint8(wtap_optionblock_t block, guint option_id, guint8* value)
{
    wtap_optblock_value_t* opt_value = wtap_optionblock_get_option(block, option_id);

    /* Didn't find the option */
    if (opt_value == NULL)
        return WTAP_OPTTYPE_NOT_FOUND;

    if (opt_value->info->type != WTAP_OPTTYPE_UINT8)
        return WTAP_OPTTYPE_TYPE_MISMATCH;

    *value = opt_value->option.uint8val;
    return WTAP_OPTTYPE_SUCCESS;
}

int wtap_optionblock_set_option_custom(wtap_optionblock_t block, guint option_id, void* value)
{
    wtap_optblock_value_t* opt_value = wtap_optionblock_get_option(block, option_id);
    void* prev_value;

    /* Didn't find the option */
    if (opt_value == NULL)
        return WTAP_OPTTYPE_NOT_FOUND;

    if (opt_value->info->type != WTAP_OPTTYPE_CUSTOM)
        return WTAP_OPTTYPE_TYPE_MISMATCH;

    prev_value = opt_value->option.customval.data;
    opt_value->option.customval.data = g_memdup(value, opt_value->option.customval.size);
    /* Free after memory is duplicated in case structure was manipulated with a "get then set" */
    g_free(prev_value);
    return WTAP_OPTTYPE_SUCCESS;
}

int wtap_optionblock_get_option_custom(wtap_optionblock_t block, guint option_id, void** value)
{
    wtap_optblock_value_t* opt_value = wtap_optionblock_get_option(block, option_id);

    /* Didn't find the option */
    if (opt_value == NULL)
        return WTAP_OPTTYPE_NOT_FOUND;

    if (opt_value->info->type != WTAP_OPTTYPE_CUSTOM)
        return WTAP_OPTTYPE_TYPE_MISMATCH;

    *value = opt_value->option.customval.data;
    return WTAP_OPTTYPE_SUCCESS;
}

static void shb_create(wtap_optionblock_t block)
{
    static wtap_optblock_reg_t comment_option = {"opt_comment", "Optional comment", WTAP_OPTTYPE_STRING, {0}, {0}};
    static wtap_optblock_reg_t hardware_option = {"hardware", "SBH Hardware", WTAP_OPTTYPE_STRING, {0}, {0}};
    static wtap_optblock_reg_t os_option = {"os", "SBH Operating System", WTAP_OPTTYPE_STRING, {0}, {0}};
    static wtap_optblock_reg_t user_appl_option = {"user_appl", "SBH User Application", WTAP_OPTTYPE_STRING, {0}, {0}};

    wtapng_mandatory_section_t* section_mand = g_new(wtapng_mandatory_section_t, 1);

    /* Set proper values for the union */
    comment_option.option.stringval = NULL;
    comment_option.default_val.stringval = NULL;
    hardware_option.option.stringval = NULL;
    hardware_option.default_val.stringval = NULL;
    os_option.option.stringval = NULL;
    os_option.default_val.stringval = NULL;
    user_appl_option.option.stringval = NULL;
    user_appl_option.default_val.stringval = NULL;

    section_mand->section_length = -1;

    block->mandatory_data = section_mand;

    wtap_optionblock_add_option(block, OPT_COMMENT, &comment_option);
    wtap_optionblock_add_option(block, OPT_SHB_HARDWARE, &hardware_option);
    wtap_optionblock_add_option(block, OPT_SHB_OS, &os_option);
    wtap_optionblock_add_option(block, OPT_SHB_USERAPPL, &user_appl_option);
}

static void shb_copy_mand(wtap_optionblock_t dest_block, wtap_optionblock_t src_block)
{
    memcpy(dest_block->mandatory_data, src_block->mandatory_data, sizeof(wtapng_mandatory_section_t));
}

static void nrb_create(wtap_optionblock_t block)
{
    static wtap_optblock_reg_t comment_option = {"opt_comment", "Optional comment", WTAP_OPTTYPE_STRING, {0}, {0}};

    /* Set proper values for the union */
    comment_option.option.stringval = NULL;
    comment_option.default_val.stringval = NULL;

    block->mandatory_data = NULL;

    wtap_optionblock_add_option(block, OPT_COMMENT, &comment_option);
}

static void isb_create(wtap_optionblock_t block)
{
    static wtap_optblock_reg_t comment_option = {"opt_comment", "Optional comment", WTAP_OPTTYPE_STRING, {0}, {0}};
    static wtap_optblock_reg_t starttime_option = {"start_time", "Start Time", WTAP_OPTTYPE_UINT64, {0}, {0}};
    static wtap_optblock_reg_t endtime_option = {"end_time", "End Time", WTAP_OPTTYPE_UINT64, {0}, {0}};
    static wtap_optblock_reg_t rcv_pkt_option = {"recv", "Receive Packets", WTAP_OPTTYPE_UINT64, {0}, {0}};
    static wtap_optblock_reg_t drop_pkt_option = {"drop", "Dropped Packets", WTAP_OPTTYPE_UINT64, {0}, {0}};
    static wtap_optblock_reg_t filteraccept_option = {"filter_accept", "Filter Accept", WTAP_OPTTYPE_UINT64, {0}, {0}};
    static wtap_optblock_reg_t os_drop_option = {"os_drop", "OS Dropped Packets", WTAP_OPTTYPE_UINT64, {0}, {0}};
    static wtap_optblock_reg_t user_deliv_option = {"user_deliv", "User Delivery", WTAP_OPTTYPE_UINT64, {0}, {0}};

    block->mandatory_data = g_new0(wtapng_if_stats_mandatory_t, 1);

    /* Set proper values for the union */
    comment_option.option.stringval = NULL;
    comment_option.default_val.stringval = NULL;
    starttime_option.option.uint64val = 0;
    starttime_option.default_val.uint64val = 0;
    endtime_option.option.uint64val = 0;
    endtime_option.default_val.uint64val = 0;
    rcv_pkt_option.option.uint64val = G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF);
    rcv_pkt_option.default_val.uint64val = G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF);
    drop_pkt_option.option.uint64val = G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF);
    drop_pkt_option.default_val.uint64val = G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF);
    filteraccept_option.option.uint64val = G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF);
    filteraccept_option.default_val.uint64val = G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF);
    os_drop_option.option.uint64val = G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF);
    os_drop_option.default_val.uint64val = G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF);
    user_deliv_option.option.uint64val = G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF);
    user_deliv_option.default_val.uint64val = G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF);

    wtap_optionblock_add_option(block, OPT_COMMENT, &comment_option);
    wtap_optionblock_add_option(block, OPT_ISB_STARTTIME, &starttime_option);
    wtap_optionblock_add_option(block, OPT_ISB_ENDTIME, &endtime_option);
    wtap_optionblock_add_option(block, OPT_ISB_IFRECV, &rcv_pkt_option);
    wtap_optionblock_add_option(block, OPT_ISB_IFDROP, &drop_pkt_option);
    wtap_optionblock_add_option(block, OPT_ISB_FILTERACCEPT, &filteraccept_option);
    wtap_optionblock_add_option(block, OPT_ISB_OSDROP, &os_drop_option);
    wtap_optionblock_add_option(block, OPT_ISB_USRDELIV, &user_deliv_option);
}

static void isb_copy_mand(wtap_optionblock_t dest_block, wtap_optionblock_t src_block)
{
    memcpy(dest_block->mandatory_data, src_block->mandatory_data, sizeof(wtapng_if_stats_mandatory_t));
}

static void idb_filter_free(void* data)
{
    wtapng_if_descr_filter_t* filter = (wtapng_if_descr_filter_t*)data;
    g_free(filter->if_filter_str);
    g_free(filter->if_filter_bpf_bytes);
}

static void idb_create(wtap_optionblock_t block)
{
    static wtap_optblock_reg_t comment_option = {"opt_comment", "Optional comment", WTAP_OPTTYPE_STRING, {0}, {0}};
    static wtap_optblock_reg_t name_option = {"name", "Device name", WTAP_OPTTYPE_STRING, {0}, {0}};
    static wtap_optblock_reg_t description_option = {"description", "Device description", WTAP_OPTTYPE_STRING, {0}, {0}};
    static wtap_optblock_reg_t speed_option = {"speed", "Interface speed (in bps)", WTAP_OPTTYPE_UINT64, {0}, {0}};
    static wtap_optblock_reg_t tsresol_option = {"ts_resolution", "Resolution of timestamps", WTAP_OPTTYPE_UINT8, {0}, {0}};
    static wtap_optblock_reg_t filter_option = {"filter", "Filter string", WTAP_OPTTYPE_CUSTOM, {0}, {0}};
    static wtap_optblock_reg_t os_option = {"os", "Operating System", WTAP_OPTTYPE_STRING, {0}, {0}};
    static wtap_optblock_reg_t fcslen_option = {"fcslen", "FCS Length", WTAP_OPTTYPE_UINT8, {0}, {0}};

    wtapng_if_descr_filter_t default_filter;
    memset(&default_filter, 0, sizeof(default_filter));

    block->mandatory_data = g_new0(wtapng_if_descr_mandatory_t, 1);

    /* Set proper values for the union */
    comment_option.option.stringval = NULL;
    comment_option.default_val.stringval = NULL;
    name_option.option.stringval = NULL;
    name_option.default_val.stringval = NULL;
    description_option.option.stringval = NULL;
    description_option.default_val.stringval = NULL;
    speed_option.option.uint64val = G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF);
    speed_option.default_val.uint64val = G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF);
    tsresol_option.option.uint8val = 6;
    tsresol_option.default_val.uint8val = 6;
    filter_option.option.customval.size = sizeof(wtapng_if_descr_filter_t);
    filter_option.option.customval.data = &default_filter;
    filter_option.option.customval.free_func = idb_filter_free;
    filter_option.default_val.customval.size = sizeof(wtapng_if_descr_filter_t);
    filter_option.default_val.customval.data = &default_filter;
    filter_option.default_val.customval.free_func = idb_filter_free;
    os_option.option.stringval = NULL;
    os_option.default_val.stringval = NULL;
    fcslen_option.option.uint8val = -1;
    fcslen_option.default_val.uint8val = -1;

    wtap_optionblock_add_option(block, OPT_COMMENT, &comment_option);
    wtap_optionblock_add_option(block, OPT_IDB_NAME, &name_option);
    wtap_optionblock_add_option(block, OPT_IDB_DESCR, &description_option);
    wtap_optionblock_add_option(block, OPT_IDB_SPEED, &speed_option);
    wtap_optionblock_add_option(block, OPT_IDB_TSRESOL, &tsresol_option);
    wtap_optionblock_add_option(block, OPT_IDB_FILTER, &filter_option);
    wtap_optionblock_add_option(block, OPT_IDB_OS, &os_option);
    wtap_optionblock_add_option(block, OPT_IDB_FCSLEN, &fcslen_option);
}

static void idb_free_mand(wtap_optionblock_t block)
{
    guint j;
    wtap_optionblock_t if_stats;
    wtapng_if_descr_mandatory_t* mand = (wtapng_if_descr_mandatory_t*)block->mandatory_data;

    for(j = 0; j < mand->num_stat_entries; j++) {
        if_stats = g_array_index(mand->interface_statistics, wtap_optionblock_t, j);
        wtap_optionblock_free(if_stats);
    }

    if (mand->interface_statistics)
        g_array_free(mand->interface_statistics, TRUE);
}

static void idb_copy_mand(wtap_optionblock_t dest_block, wtap_optionblock_t src_block)
{
    guint j;
    wtap_optionblock_t src_if_stats, dest_if_stats;
    wtapng_if_descr_mandatory_t *src_mand = (wtapng_if_descr_mandatory_t*)src_block->mandatory_data,
                                *dest_mand = (wtapng_if_descr_mandatory_t*)dest_block->mandatory_data;

    /* Need special consideration for copying of the interface_statistics member */
    if (dest_mand->num_stat_entries != 0)
        g_array_free(dest_mand->interface_statistics, TRUE);

    memcpy(dest_mand, src_mand, sizeof(wtapng_if_descr_mandatory_t));
    if (src_mand->num_stat_entries != 0)
    {
        dest_mand->interface_statistics = g_array_new(FALSE, FALSE, sizeof(wtap_optionblock_t));
        for (j = 0; j < src_mand->num_stat_entries; j++)
        {
            src_if_stats = g_array_index(src_mand->interface_statistics, wtap_optionblock_t, j);
            dest_if_stats = wtap_optionblock_create(WTAP_OPTION_BLOCK_IF_STATS);
            wtap_optionblock_copy_options(dest_if_stats, src_if_stats);
            dest_mand->interface_statistics = g_array_append_val(dest_mand->interface_statistics, dest_if_stats);
        }
    }
}

void wtap_opttypes_initialize(void)
{
    static wtap_opt_register_t shb_block = {
        "SHB",              /* name */
        "Section Header Block",  /* description */
        shb_create,         /* create */
        NULL,               /* free_mand */
        shb_copy_mand,      /* copy_mand */
    };

    static wtap_opt_register_t nrb_block = {
        "NRB",              /* name */
        "Name Resolution Block",  /* description */
        nrb_create,         /* create */
        NULL,               /* free_mand */
        NULL,               /* copy_mand */
    };

    static wtap_opt_register_t isb_block = {
        "ISB",              /* name */
        "Interface Statistics Block",  /* description */
        isb_create,         /* create */
        NULL,               /* free_mand */
        isb_copy_mand,      /* copy_mand */
    };

    static wtap_opt_register_t idb_block = {
        "IDB",              /* name */
        "Interface Description Block",  /* description */
        idb_create,         /* create */
        idb_free_mand,      /* free_mand */
        idb_copy_mand,      /* copy_mand */
    };

    /* Initialize the custom block array.  This is for future proofing
       "outside registered" block types (for NULL checking) */
    memset(block_list, 0, MAX_WTAP_OPTION_BLOCK_TYPE_VALUE*sizeof(wtap_opt_register_t*));
    num_custom_blocks = 0;

    wtap_opttype_block_register(WTAP_OPTION_BLOCK_NG_SECTION, &shb_block );
    wtap_opttype_block_register(WTAP_OPTION_BLOCK_NG_NRB, &nrb_block );
    wtap_opttype_block_register(WTAP_OPTION_BLOCK_IF_STATS, &isb_block );
    wtap_opttype_block_register(WTAP_OPTION_BLOCK_IF_DESCR, &idb_block );
}
