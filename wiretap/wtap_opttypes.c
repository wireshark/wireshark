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

struct wtap_optionblock
{
    const char *name;                /**< name of block */
    const char *description;         /**< human-readable description of block */
    wtap_optionblock_type_t type;
    void* mandatory_data;
    GArray* options;
};

void wtap_opttypes_initialize(void)
{
}

static void wtap_if_descr_filter_free(void* data)
{
    wtapng_if_descr_filter_t* filter = (wtapng_if_descr_filter_t*)data;
    g_free(filter->if_filter_str);
    g_free(filter->if_filter_bpf_bytes);
}

wtap_optionblock_t wtap_optionblock_create(wtap_optionblock_type_t block_type)
{
    wtap_optionblock_t block = NULL;

    switch(block_type)
    {
    case WTAP_OPTION_BLOCK_NG_SECTION:
        {
        wtapng_mandatory_section_t* section_mand;

        block = g_new(struct wtap_optionblock, 1);
        block->name = "SHB";
        block->description = "Section Header block";
        block->type = WTAP_OPTION_BLOCK_NG_SECTION;
        block->mandatory_data = g_new(wtapng_mandatory_section_t, 1);
        section_mand = (wtapng_mandatory_section_t*)block->mandatory_data;
        section_mand->section_length = -1;
        block->options = g_array_new(FALSE, FALSE, sizeof(wtap_opttype_t*));

        wtap_optionblock_add_option_string(block, OPT_COMMENT, "opt_comment", "Optional comment", NULL, NULL);
        wtap_optionblock_add_option_string(block, OPT_SHB_HARDWARE, "hardware", "SBH Hardware", NULL, NULL);
        wtap_optionblock_add_option_string(block, OPT_SHB_OS, "os", "SBH Operating System", NULL, NULL);
        wtap_optionblock_add_option_string(block, OPT_SHB_USERAPPL, "user_appl", "SBH User Application", NULL, NULL);
        }
        break;
    case WTAP_OPTION_BLOCK_NG_NRB:
        block = g_new(struct wtap_optionblock, 1);
        block->name = "NRB";
        block->description = "Name Resolution Block";
        block->type = WTAP_OPTION_BLOCK_NG_NRB;
        block->mandatory_data = NULL;
        block->options = g_array_new(FALSE, FALSE, sizeof(wtap_opttype_t*));

        wtap_optionblock_add_option_string(block, OPT_COMMENT, "opt_comment", "Optional comment", NULL, NULL);
        break;

    case WTAP_OPTION_BLOCK_IF_STATS:
        block = g_new(struct wtap_optionblock, 1);
        block->name = "ISB";
        block->description = "Interface Statistics Block";
        block->type = WTAP_OPTION_BLOCK_IF_STATS;
        block->mandatory_data = g_new0(wtapng_if_stats_mandatory_t, 1);
        block->options = g_array_new(FALSE, FALSE, sizeof(wtap_opttype_t*));

        wtap_optionblock_add_option_string(block, OPT_COMMENT, "opt_comment", "Optional comment", NULL, NULL);
        wtap_optionblock_add_option_uint64(block, OPT_ISB_STARTTIME, "start_time", "Start Time", 0, 0);
        wtap_optionblock_add_option_uint64(block, OPT_ISB_ENDTIME, "end_time", "End Time", 0, 0);
        wtap_optionblock_add_option_uint64(block, OPT_ISB_IFRECV, "recv", "Receive Packets", G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF), G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF));
        wtap_optionblock_add_option_uint64(block, OPT_ISB_IFDROP, "drop", "Dropped Packets", G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF), G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF));
        wtap_optionblock_add_option_uint64(block, OPT_ISB_FILTERACCEPT, "filter_accept", "Filter Accept", G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF), G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF));
        wtap_optionblock_add_option_uint64(block, OPT_ISB_OSDROP, "os_drop", "OS Dropped Packets", G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF), G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF));
        wtap_optionblock_add_option_uint64(block, OPT_ISB_USRDELIV, "user_deliv", "User Delivery", G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF), G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF));
        break;
    case WTAP_OPTION_BLOCK_IF_DESCR:
        {
        wtapng_if_descr_filter_t default_filter;
        memset(&default_filter, 0, sizeof(default_filter));

        block = g_new(struct wtap_optionblock, 1);
        block->name = "IDB";
        block->description = "Interface Description Block";
        block->type = WTAP_OPTION_BLOCK_IF_DESCR;
        block->mandatory_data = g_new0(wtapng_if_descr_mandatory_t, 1);
        block->options = g_array_new(FALSE, FALSE, sizeof(wtap_opttype_t*));

        wtap_optionblock_add_option_string(block, OPT_COMMENT, "opt_comment", "Optional comment", NULL, NULL);
        wtap_optionblock_add_option_string(block, OPT_IDB_NAME, "name", "Device name", NULL, NULL);
        wtap_optionblock_add_option_string(block, OPT_IDB_DESCR, "description", "Device description", NULL, NULL);
        wtap_optionblock_add_option_uint64(block, OPT_IDB_SPEED, "speed", "Interface speed (in bps)", G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF), G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF));
        wtap_optionblock_add_option_uint8(block, OPT_IDB_TSRESOL, "ts_resolution", "Resolution of timestamps", 6, 6);
        wtap_optionblock_add_option_custom(block, OPT_IDB_FILTER, "filter", "Filter string", &default_filter, &default_filter, sizeof(wtapng_if_descr_filter_t), wtap_if_descr_filter_free);
        wtap_optionblock_add_option_string(block, OPT_IDB_OS, "os", "Operating System", NULL, NULL);
        wtap_optionblock_add_option_uint8(block, OPT_IDB_FCSLEN, "fcslen", "FCS Length", -1, -1);
        }
        break;
    }

    return block;
}

static void wtap_optionblock_free_options(wtap_optionblock_t block)
{
    guint i;
    wtap_opttype_t* opttype = NULL;

    for (i = 0; i < block->options->len; i++) {
        opttype = g_array_index(block->options, wtap_opttype_t*, i);
        switch(opttype->type)
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
    if (block != NULL)
    {
        /* Need special consideration for freeing of the interface_statistics member */
        if (block->type == WTAP_OPTION_BLOCK_IF_DESCR)
        {
            wtapng_if_descr_mandatory_t* mand = (wtapng_if_descr_mandatory_t*)block->mandatory_data;
            if (mand->num_stat_entries != 0)
            {
                g_array_free(mand->interface_statistics, TRUE);
            }
        }

        g_free(block->mandatory_data);
        wtap_optionblock_free_options(block);
        g_array_free(block->options, FALSE);
        g_free(block);
    }
}

void* wtap_optionblock_get_mandatory_data(wtap_optionblock_t block)
{
    return block->mandatory_data;
}

static wtap_opttype_t* wtap_optionblock_get_option(wtap_optionblock_t block, guint option_id)
{
    guint i;
    wtap_opttype_t* opttype = NULL;

    for (i = 0; i < block->options->len; i++)
    {
        opttype = g_array_index(block->options, wtap_opttype_t*, i);
        if (opttype->number == option_id)
            return opttype;
    }

    return NULL;
}

int wtap_optionblock_add_option_string(wtap_optionblock_t block, guint option_id,
                                       const char *name, const char *description, char* opt_value, char* default_value)
{
    wtap_opttype_t* opttype = wtap_optionblock_get_option(block, option_id);

    /* Option already exists */
    if (opttype != NULL)
        return WTAP_OPTTYPE_ALREADY_EXISTS;

    opttype = g_new(wtap_opttype_t, 1);

    opttype->name = name;
    opttype->description = description;
    opttype->number = option_id;
    opttype->type = WTAP_OPTTYPE_STRING;
    opttype->option.stringval = g_strdup(opt_value);
    opttype->default_val.stringval = default_value;

    g_array_append_val(block->options, opttype);
    return WTAP_OPTTYPE_SUCCESS;
}

int wtap_optionblock_set_option_string(wtap_optionblock_t block, guint option_id, char* opt_value)
{
    wtap_opttype_t* opttype = wtap_optionblock_get_option(block, option_id);

    /* Didn't find the option */
    if (opttype == NULL)
        return WTAP_OPTTYPE_NOT_FOUND;

    if (opttype->type != WTAP_OPTTYPE_STRING)
        return WTAP_OPTTYPE_TYPE_MISMATCH;

    g_free(opttype->option.stringval);
    opttype->option.stringval = g_strdup(opt_value);
    return WTAP_OPTTYPE_SUCCESS;
}

int wtap_optionblock_get_option_string(wtap_optionblock_t block, guint option_id, char** opt_value)
{
    wtap_opttype_t* opttype = wtap_optionblock_get_option(block, option_id);

    /* Didn't find the option */
    if (opttype == NULL)
        return WTAP_OPTTYPE_NOT_FOUND;

    if (opttype->type != WTAP_OPTTYPE_STRING)
        return WTAP_OPTTYPE_TYPE_MISMATCH;

    *opt_value = opttype->option.stringval;
    return WTAP_OPTTYPE_SUCCESS;
}

int wtap_optionblock_add_option_uint64(wtap_optionblock_t block, guint option_id,
                                       const char *name, const char *description, guint64 opt_value, guint64 default_value)
{
    wtap_opttype_t* opttype = wtap_optionblock_get_option(block, option_id);

    /* Option already exists */
    if (opttype != NULL)
        return WTAP_OPTTYPE_ALREADY_EXISTS;

    opttype = g_new(wtap_opttype_t, 1);

    opttype->name = name;
    opttype->description = description;
    opttype->number = option_id;
    opttype->type = WTAP_OPTTYPE_UINT64;
    opttype->option.uint64val = opt_value;
    opttype->default_val.uint64val = default_value;

    g_array_append_val(block->options, opttype);
    return WTAP_OPTTYPE_SUCCESS;
}

int wtap_optionblock_set_option_uint64(wtap_optionblock_t block, guint option_id, guint64 opt_value)
{
    wtap_opttype_t* opttype = wtap_optionblock_get_option(block, option_id);

    /* Didn't find the option */
    if (opttype == NULL)
        return WTAP_OPTTYPE_NOT_FOUND;

    if (opttype->type != WTAP_OPTTYPE_UINT64)
        return WTAP_OPTTYPE_TYPE_MISMATCH;

    opttype->option.uint64val = opt_value;
    return WTAP_OPTTYPE_SUCCESS;
}

int wtap_optionblock_get_option_uint64(wtap_optionblock_t block, guint option_id, guint64* opt_value)
{
    wtap_opttype_t* opttype = wtap_optionblock_get_option(block, option_id);

    /* Didn't find the option */
    if (opttype == NULL)
        return WTAP_OPTTYPE_NOT_FOUND;

    if (opttype->type != WTAP_OPTTYPE_UINT64)
        return WTAP_OPTTYPE_TYPE_MISMATCH;

    *opt_value = opttype->option.uint64val;
    return WTAP_OPTTYPE_SUCCESS;
}

int wtap_optionblock_add_option_uint8(wtap_optionblock_t block, guint option_id,
                                       const char *name, const char *description, guint8 opt_value, guint8 default_value)
{
    wtap_opttype_t* opttype = wtap_optionblock_get_option(block, option_id);

    /* Option already exists */
    if (opttype != NULL)
        return WTAP_OPTTYPE_ALREADY_EXISTS;

    opttype = g_new(wtap_opttype_t, 1);

    opttype->name = name;
    opttype->description = description;
    opttype->number = option_id;
    opttype->type = WTAP_OPTTYPE_UINT8;
    opttype->option.uint8val = opt_value;
    opttype->default_val.uint8val = default_value;

    g_array_append_val(block->options, opttype);
    return WTAP_OPTTYPE_SUCCESS;
}

int wtap_optionblock_set_option_uint8(wtap_optionblock_t block, guint option_id, guint8 opt_value)
{
    wtap_opttype_t* opttype = wtap_optionblock_get_option(block, option_id);

    /* Didn't find the option */
    if (opttype == NULL)
        return WTAP_OPTTYPE_NOT_FOUND;

    if (opttype->type != WTAP_OPTTYPE_UINT8)
        return WTAP_OPTTYPE_TYPE_MISMATCH;

    opttype->option.uint8val = opt_value;
    return WTAP_OPTTYPE_SUCCESS;
}

int wtap_optionblock_get_option_uint8(wtap_optionblock_t block, guint option_id, guint8* opt_value)
{
    wtap_opttype_t* opttype = wtap_optionblock_get_option(block, option_id);

    /* Didn't find the option */
    if (opttype == NULL)
        return WTAP_OPTTYPE_NOT_FOUND;

    if (opttype->type != WTAP_OPTTYPE_UINT8)
        return WTAP_OPTTYPE_TYPE_MISMATCH;

    *opt_value = opttype->option.uint8val;
    return WTAP_OPTTYPE_SUCCESS;
}

int wtap_optionblock_add_option_custom(wtap_optionblock_t block, guint option_id,
                                       const char *name, const char *description, void* opt_value, void* default_value,
                                       guint size, wtap_opttype_free_custom_func free_func)
{
    wtap_opttype_t* opttype = wtap_optionblock_get_option(block, option_id);

    /* Option already exists */
    if (opttype != NULL)
        return WTAP_OPTTYPE_ALREADY_EXISTS;

    opttype = g_new(wtap_opttype_t, 1);

    opttype->name = name;
    opttype->description = description;
    opttype->number = option_id;
    opttype->type = WTAP_OPTTYPE_CUSTOM;
    opttype->option.customval.size = size;
    opttype->option.customval.data = g_memdup(opt_value, size);
    opttype->option.customval.free_func = free_func;
    opttype->default_val.customval.size = size;
    opttype->default_val.customval.data = g_memdup(default_value, size);
    opttype->default_val.customval.free_func = free_func;

    g_array_append_val(block->options, opttype);
    return WTAP_OPTTYPE_SUCCESS;
}

int wtap_optionblock_set_option_custom(wtap_optionblock_t block, guint option_id, void* opt_value)
{
    wtap_opttype_t* opttype = wtap_optionblock_get_option(block, option_id);
    void* prev_value;

    /* Didn't find the option */
    if (opttype == NULL)
        return WTAP_OPTTYPE_NOT_FOUND;

    if (opttype->type != WTAP_OPTTYPE_CUSTOM)
        return WTAP_OPTTYPE_TYPE_MISMATCH;

    prev_value = opttype->option.customval.data;
    opttype->option.customval.data = g_memdup(opt_value, opttype->option.customval.size);
    /* Free after memory is duplicated in case structure was manipulated with a "get then set" */
    g_free(prev_value);
    return WTAP_OPTTYPE_SUCCESS;
}

int wtap_optionblock_get_option_custom(wtap_optionblock_t block, guint option_id, void** opt_value)
{
    wtap_opttype_t* opttype = wtap_optionblock_get_option(block, option_id);

    /* Didn't find the option */
    if (opttype == NULL)
        return WTAP_OPTTYPE_NOT_FOUND;

    if (opttype->type != WTAP_OPTTYPE_CUSTOM)
        return WTAP_OPTTYPE_TYPE_MISMATCH;

    *opt_value = opttype->option.customval.data;
    return WTAP_OPTTYPE_SUCCESS;
}

void wtap_optionblock_copy_options(wtap_optionblock_t dest_block, wtap_optionblock_t src_block)
{
    guint i;
    wtap_opttype_t *dest_opttype, *src_opttype;

    switch(src_block->type)
    {
    case WTAP_OPTION_BLOCK_NG_SECTION:
        memcpy(dest_block->mandatory_data, src_block->mandatory_data, sizeof(wtapng_mandatory_section_t));
        break;
    case WTAP_OPTION_BLOCK_NG_NRB:
        /* No mandatory data */
        break;
    case WTAP_OPTION_BLOCK_IF_STATS:
        memcpy(dest_block->mandatory_data, src_block->mandatory_data, sizeof(wtapng_if_stats_mandatory_t));
        break;
    case WTAP_OPTION_BLOCK_IF_DESCR:
        {
        wtapng_if_descr_mandatory_t *src_mand = (wtapng_if_descr_mandatory_t*)src_block->mandatory_data,
                                    *dest_mand = (wtapng_if_descr_mandatory_t*)dest_block->mandatory_data;
        /* Need special consideration for copying of the interface_statistics member */
        if (dest_mand->num_stat_entries != 0)
        {
            g_array_free(dest_mand->interface_statistics, TRUE);
        }

        memcpy(dest_mand, src_mand, sizeof(wtapng_if_descr_mandatory_t));
        if (src_mand->num_stat_entries != 0)
        {
            dest_mand->interface_statistics = NULL;
            dest_mand->interface_statistics = g_array_append_vals(dest_mand->interface_statistics, src_mand->interface_statistics->data, src_mand->interface_statistics->len);
        }
        }
        break;
    }

    /* Copy the options.  For now, don't remove any options that are in destination
     * but not source.
     */
    for (i = 0; i < src_block->options->len; i++)
    {
        src_opttype = g_array_index(src_block->options, wtap_opttype_t*, i);
        dest_opttype = wtap_optionblock_get_option(dest_block, src_opttype->number);
        if (dest_opttype == NULL)
        {
            /* Option doesn't exist, add it */
            switch(src_opttype->type)
            {
            case WTAP_OPTTYPE_UINT8:
                wtap_optionblock_add_option_uint8(dest_block, src_opttype->number, src_opttype->name, src_opttype->description,
                                                  src_opttype->option.uint8val, src_opttype->default_val.uint8val);
                break;
            case WTAP_OPTTYPE_UINT64:
                wtap_optionblock_add_option_uint64(dest_block, src_opttype->number, src_opttype->name, src_opttype->description,
                                                  src_opttype->option.uint64val, src_opttype->default_val.uint64val);
                break;
            case WTAP_OPTTYPE_STRING:
                wtap_optionblock_add_option_string(dest_block, src_opttype->number, src_opttype->name, src_opttype->description,
                                                  src_opttype->option.stringval, src_opttype->default_val.stringval);
                break;
            case WTAP_OPTTYPE_CUSTOM:
                wtap_optionblock_add_option_custom(dest_block, src_opttype->number, src_opttype->name, src_opttype->description,
                                                 src_opttype->option.customval.data, src_opttype->default_val.customval.data,
                                                 src_opttype->option.customval.size, src_opttype->option.customval.free_func);
                break;
            }
        }
        else
        {
            /* Option exists, replace it */
            switch(src_opttype->type)
            {
            case WTAP_OPTTYPE_UINT8:
                dest_opttype->option.uint8val = src_opttype->option.uint8val;
                break;
            case WTAP_OPTTYPE_UINT64:
                dest_opttype->option.uint64val = src_opttype->option.uint64val;
                break;
            case WTAP_OPTTYPE_STRING:
                g_free(dest_opttype->option.stringval);
                dest_opttype->option.stringval = g_strdup(src_opttype->option.stringval);
                break;
            case WTAP_OPTTYPE_CUSTOM:
                dest_opttype->option.customval.free_func(dest_opttype->option.customval.data);
                g_free(dest_opttype->option.customval.data);
                dest_opttype->option.customval.data = g_memdup(src_opttype->option.customval.data, src_opttype->option.customval.size);
                break;
            }
        }
    }
}
