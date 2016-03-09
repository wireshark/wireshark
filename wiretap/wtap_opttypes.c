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

typedef void (*wtap_block_create_func)(wtap_optionblock_t block);
typedef void (*wtap_mand_free_func)(wtap_optionblock_t block);
typedef void (*wtap_mand_copy_func)(wtap_optionblock_t dest_block, wtap_optionblock_t src_block);
typedef gboolean (*wtap_write_func)(struct wtap_dumper *wdh, wtap_optionblock_t block, int *err);

typedef struct wtap_opt_register
{
    const char *name;                /**< name of block */
    const char *description;         /**< human-readable description of block */
    wtap_block_create_func create;
    wtap_write_func write;
    wtap_mand_free_func free_mand;
    wtap_mand_copy_func copy_mand;
} wtap_opt_register_t;

typedef struct wtap_optblock_internal {
    const char *name;                /**< name of option */
    const char *description;         /**< human-readable description of option */
    guint number;                    /**< Option index */
    wtap_opttype_e type;             /**< type of that option */
    wtap_opttype_option_write_size write_size; /**< Number of bytes to write to file (0 for don't write) */
    wtap_opttype_option_write write_data; /**< write option data to dumper */
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

/* Keep track of wtap_opt_register_t's via their id number */
static wtap_opt_register_t* block_list[WTAP_OPTION_BLOCK_MAX_TYPE];

static void wtap_opttype_block_register(int block_type, wtap_opt_register_t *block)
{
    /* Check input */
    g_assert(block_type < WTAP_OPTION_BLOCK_MAX_TYPE);

    /* Don't re-register. */
    g_assert(block_list[block_type] == NULL);

    /* Sanity check */
    g_assert(block->name);
    g_assert(block->description);
    g_assert(block->create);

    block_list[block_type] = block;
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

wtap_optionblock_t wtap_optionblock_create(wtap_optionblock_type_t block_type)
{
    wtap_optionblock_t block;

    if (block_type >= WTAP_OPTION_BLOCK_MAX_TYPE)
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
    if (block != NULL)
    {
        if (block->info->free_mand != NULL)
            block->info->free_mand(block);

        g_free(block->mandatory_data);
        wtap_optionblock_free_options(block);
        if (block->option_infos != NULL)
            g_array_free(block->option_infos, FALSE);
        if (block->option_values != NULL)
            g_array_free(block->option_values, FALSE);
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
            reg_optblock.write_size_func = src_internal->write_size;
            reg_optblock.write_func = src_internal->write_data;
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

gboolean wtap_optionblock_write(struct wtap_dumper *wdh, wtap_optionblock_t block, int *err)
{
    if ((block == NULL) || (block->info->write == NULL))
    {
        *err = WTAP_ERR_INTERNAL;
        return FALSE;
    }

    return block->info->write(wdh, block, err);
}

static guint32 wtap_optionblock_get_option_write_size(wtap_optionblock_t block)
{
    guint i;
    guint32 options_total_length = 0, length;
    wtap_optblock_value_t *value;

    for (i = 0; i < block->option_values->len; i++)
    {
        value = g_array_index(block->option_values, wtap_optblock_value_t*, i);
        if ((value->info->write_size != NULL) && (value->info->write_data != NULL))
        {
            length = value->info->write_size(&value->option);
            options_total_length += length;
            /* Add bytes for option header if option should be written */
            if (length > 0)
                options_total_length += 4;
        }
    }

    return options_total_length;
}

static gboolean wtap_optionblock_write_options(struct wtap_dumper *wdh, wtap_optionblock_t block, guint32 options_total_length, int *err)
{
    guint i;
    wtap_optblock_value_t *value;
    struct pcapng_option_header option_hdr;
    guint32 length;

    /* Check if we have at least 1 option to write */
    if (options_total_length == 0)
        return TRUE;

    for (i = 0; i < block->option_values->len; i++)
    {
        value = g_array_index(block->option_values, wtap_optblock_value_t*, i);
        if ((value->info->write_size != NULL) && (value->info->write_data != NULL) &&
            ((length = value->info->write_size(&value->option)) > 0))
        {
            /* Write the option */
            wtap_debug("wtap_optionblock_write %s, field:'%s' length: %u", block->description, value->info->description, length);

            /* String options don't consider pad bytes part of the length, so readjust here */
            if (value->info->type == WTAP_OPTTYPE_STRING)
                length = (guint32)strlen(value->option.stringval) & 0xffff;

            option_hdr.type         = value->info->number;
            option_hdr.value_length = length;
            if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
                return FALSE;
            wdh->bytes_dumped += 4;

            if (!value->info->write_data(wdh, &value->option, err))
                return FALSE;
        }
    }

    /* Write end of options */
    option_hdr.type = OPT_EOFOPT;
    option_hdr.value_length = 0;
    if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
        return FALSE;
    wdh->bytes_dumped += 4;
    return TRUE;
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
    opt_internal->write_size = option->write_size_func;
    opt_internal->write_data = option->write_func;

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

int wtap_optionblock_set_option_string(wtap_optionblock_t block, guint option_id, char* value)
{
    wtap_optblock_value_t* opt_value = wtap_optionblock_get_option(block, option_id);

    /* Didn't find the option */
    if (opt_value == NULL)
        return WTAP_OPTTYPE_NOT_FOUND;

    if (opt_value->info->type != WTAP_OPTTYPE_STRING)
        return WTAP_OPTTYPE_TYPE_MISMATCH;

    g_free(opt_value->option.stringval);
    opt_value->option.stringval = g_strdup(value);
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

guint32 wtap_opttype_write_size_string(wtap_option_type* data)
{
    guint32 size, pad;
    if ((data == NULL) ||(data->stringval == NULL))
        return 0;

    size = (guint32)strlen(data->stringval) & 0xffff;
    if ((size % 4)) {
        pad = 4 - (size % 4);
    } else {
        pad = 0;
    }

    return size+pad;
}

gboolean wtap_opttype_write_data_string(struct wtap_dumper* wdh, wtap_option_type* data, int *err)
{
    guint32 size = (guint32)strlen(data->stringval) & 0xffff;
    guint32 pad;
    const guint32 zero_pad = 0;

    if (!wtap_dump_file_write(wdh, data->stringval, size, err))
        return FALSE;
    wdh->bytes_dumped += size;

    if ((size % 4)) {
        pad = 4 - (size % 4);
    } else {
        pad = 0;
    }

    /* write padding (if any) */
    if (pad != 0) {
        if (!wtap_dump_file_write(wdh, &zero_pad, pad, err))
            return FALSE;
        wdh->bytes_dumped += pad;
    }

    return TRUE;
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

guint32 wtap_opttype_write_uint64_not0(wtap_option_type* data)
{
    if (data == NULL)
        return 0;

    if (data->uint64val == 0)
        return 0;

    /* value */
    return 8;
}

guint32 wtap_opttype_write_uint64_not_minus1(wtap_option_type* data)
{
    if (data == NULL)
        return 0;

    if (data->uint64val == G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF))
        return 0;

    /* value */
    return 8;
}

gboolean wtap_opttype_write_data_uint64(struct wtap_dumper* wdh, wtap_option_type* data, int *err)
{
    if (!wtap_dump_file_write(wdh, &data->uint64val, sizeof(guint64), err))
        return FALSE;
    wdh->bytes_dumped += 8;
    return TRUE;
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

guint32 wtap_opttype_write_uint8_not0(wtap_option_type* data)
{
    if (data == NULL)
        return 0;

    if (data->uint8val == 0)
        return 0;

    /* padding to 32 bits */
    return 4;
}

gboolean wtap_opttype_write_data_uint8(struct wtap_dumper* wdh, wtap_option_type* data, int *err)
{
    const guint32 zero_pad = 0;

    if (!wtap_dump_file_write(wdh, &data->uint8val, 1, err))
        return FALSE;
    wdh->bytes_dumped += 1;

    if (!wtap_dump_file_write(wdh, &zero_pad, 3, err))
        return FALSE;
    wdh->bytes_dumped += 3;

    return TRUE;
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
    static wtap_optblock_reg_t comment_option = {"opt_comment", "Optional comment", WTAP_OPTTYPE_STRING, wtap_opttype_write_size_string, wtap_opttype_write_data_string, {0}, {0}};
    static wtap_optblock_reg_t hardware_option = {"hardware", "SBH Hardware", WTAP_OPTTYPE_STRING, wtap_opttype_write_size_string, wtap_opttype_write_data_string, {0}, {0}};
    static wtap_optblock_reg_t os_option = {"os", "SBH Operating System", WTAP_OPTTYPE_STRING, wtap_opttype_write_size_string, wtap_opttype_write_data_string, {0}, {0}};
    static wtap_optblock_reg_t user_appl_option = {"user_appl", "SBH User Application", WTAP_OPTTYPE_STRING, wtap_opttype_write_size_string, wtap_opttype_write_data_string, {0}, {0}};

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

static gboolean shb_write(struct wtap_dumper *wdh, wtap_optionblock_t block, int *err)
{
    pcapng_block_header_t bh;
    pcapng_section_header_block_t shb;
    wtapng_mandatory_section_t* mand_data = (wtapng_mandatory_section_t*)block->mandatory_data;
    guint32 options_total_length;

    wtap_debug("write_section_header_block: Have shb_hdr");

    options_total_length = wtap_optionblock_get_option_write_size(block);
    if (options_total_length > 0)
    {
        /* End-of-options tag */
        options_total_length += 4;
    }

    /* write block header */
    bh.block_type = BLOCK_TYPE_SHB;
    bh.block_total_length = (guint32)(sizeof(bh) + sizeof(shb) + options_total_length + 4);

    if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err))
        return FALSE;
    wdh->bytes_dumped += sizeof bh;

    /* write block fixed content */
    shb.magic = 0x1A2B3C4D;
    shb.version_major = 1;
    shb.version_minor = 0;
    shb.section_length = mand_data->section_length;

    if (!wtap_dump_file_write(wdh, &shb, sizeof shb, err))
        return FALSE;
    wdh->bytes_dumped += sizeof shb;

    if (!wtap_optionblock_write_options(wdh, block, options_total_length, err))
        return FALSE;

    /* write block footer */
    if (!wtap_dump_file_write(wdh, &bh.block_total_length,
                              sizeof bh.block_total_length, err))
        return FALSE;
    wdh->bytes_dumped += sizeof bh.block_total_length;

    return TRUE;
}

static void shb_copy_mand(wtap_optionblock_t dest_block, wtap_optionblock_t src_block)
{
    memcpy(dest_block->mandatory_data, src_block->mandatory_data, sizeof(wtapng_mandatory_section_t));
}

static void nrb_create(wtap_optionblock_t block)
{
    static wtap_optblock_reg_t comment_option = {"opt_comment", "Optional comment", WTAP_OPTTYPE_STRING, wtap_opttype_write_size_string, wtap_opttype_write_data_string, {0}, {0}};

    /* Set proper values for the union */
    comment_option.option.stringval = NULL;
    comment_option.default_val.stringval = NULL;

    block->mandatory_data = NULL;

    wtap_optionblock_add_option(block, OPT_COMMENT, &comment_option);
}

static void isb_create(wtap_optionblock_t block)
{
    static wtap_optblock_reg_t comment_option = {"opt_comment", "Optional comment", WTAP_OPTTYPE_STRING, wtap_opttype_write_size_string, wtap_opttype_write_data_string, {0}, {0}};
    static wtap_optblock_reg_t starttime_option = {"start_time", "Start Time", WTAP_OPTTYPE_UINT64, wtap_opttype_write_uint64_not0, wtap_opttype_write_data_uint64, {0}, {0}};
    static wtap_optblock_reg_t endtime_option = {"end_time", "End Time", WTAP_OPTTYPE_UINT64, wtap_opttype_write_uint64_not0, wtap_opttype_write_data_uint64, {0}, {0}};
    static wtap_optblock_reg_t rcv_pkt_option = {"recv", "Receive Packets", WTAP_OPTTYPE_UINT64, wtap_opttype_write_uint64_not_minus1, wtap_opttype_write_data_uint64, {0}, {0}};
    static wtap_optblock_reg_t drop_pkt_option = {"drop", "Dropped Packets", WTAP_OPTTYPE_UINT64, wtap_opttype_write_uint64_not_minus1, wtap_opttype_write_data_uint64, {0}, {0}};
    static wtap_optblock_reg_t filteraccept_option = {"filter_accept", "Filter Accept", WTAP_OPTTYPE_UINT64, wtap_opttype_write_uint64_not_minus1, wtap_opttype_write_data_uint64, {0}, {0}};
    static wtap_optblock_reg_t os_drop_option = {"os_drop", "OS Dropped Packets", WTAP_OPTTYPE_UINT64, wtap_opttype_write_uint64_not_minus1, wtap_opttype_write_data_uint64, {0}, {0}};
    static wtap_optblock_reg_t user_deliv_option = {"user_deliv", "User Delivery", WTAP_OPTTYPE_UINT64, wtap_opttype_write_uint64_not_minus1, wtap_opttype_write_data_uint64, {0}, {0}};

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

static gboolean isb_write(struct wtap_dumper *wdh, wtap_optionblock_t block, int *err)
{
    pcapng_block_header_t bh;
    pcapng_interface_statistics_block_t isb;
    guint32 options_total_length;
    wtapng_if_stats_mandatory_t* mand_data = (wtapng_if_stats_mandatory_t*)block->mandatory_data;

    wtap_debug("write_interface_statistics_block");

    options_total_length = wtap_optionblock_get_option_write_size(block);
    if (options_total_length > 0)
    {
        /* End-of-options tag */
        options_total_length += 4;
    }

    /* write block header */
    bh.block_type = BLOCK_TYPE_ISB;
    bh.block_total_length = (guint32)(sizeof(bh) + sizeof(isb) + options_total_length + 4);

    if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err))
        return FALSE;
    wdh->bytes_dumped += sizeof bh;

    /* write block fixed content */
    isb.interface_id                = mand_data->interface_id;
    isb.timestamp_high              = mand_data->ts_high;
    isb.timestamp_low               = mand_data->ts_low;

    if (!wtap_dump_file_write(wdh, &isb, sizeof isb, err))
        return FALSE;
    wdh->bytes_dumped += sizeof isb;

    if (!wtap_optionblock_write_options(wdh, block, options_total_length, err))
        return FALSE;

    /* write block footer */
    if (!wtap_dump_file_write(wdh, &bh.block_total_length,
                              sizeof bh.block_total_length, err))
        return FALSE;
    wdh->bytes_dumped += sizeof bh.block_total_length;

    return TRUE;
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

static guint32 idb_filter_write_size(wtap_option_type* data)
{
    wtapng_if_descr_filter_t* filter;
    guint32 size, pad;

    if (data == NULL)
        return 0;

    filter = (wtapng_if_descr_filter_t*)data->customval.data;
    if ((filter == NULL) || (filter->if_filter_str == NULL))
        return 0;

    size = (guint32)(strlen(filter->if_filter_str) + 1) & 0xffff;
    if ((size % 4)) {
        pad = 4 - (size % 4);
    } else {
        pad = 0;
    }

    return pad + size;
}

static gboolean idb_filter_write(struct wtap_dumper* wdh, wtap_option_type* data, int *err)
{
    wtapng_if_descr_filter_t* filter = (wtapng_if_descr_filter_t*)data->customval.data;
    guint32 size, pad;
    const guint32 zero_pad = 0;

    size = (guint32)(strlen(filter->if_filter_str) + 1) & 0xffff;
    if ((size % 4)) {
        pad = 4 - (size % 4);
    } else {
        pad = 0;
    }

    /* Write the zero indicating libpcap filter variant */
    if (!wtap_dump_file_write(wdh, &zero_pad, 1, err))
        return FALSE;
    wdh->bytes_dumped += 1;

    /* if_filter_str_len includes the leading byte indicating filter type (libpcap str or BPF code) */
    if (!wtap_dump_file_write(wdh, filter->if_filter_str, size-1, err))
        return FALSE;
    wdh->bytes_dumped += size - 1;

    /* write padding (if any) */
    if (pad != 0) {
        if (!wtap_dump_file_write(wdh, &zero_pad, pad, err))
            return FALSE;
        wdh->bytes_dumped += pad;
    }

    return TRUE;
}

static void idb_create(wtap_optionblock_t block)
{
    static wtap_optblock_reg_t comment_option = {"opt_comment", "Optional comment", WTAP_OPTTYPE_STRING, wtap_opttype_write_size_string, wtap_opttype_write_data_string, {0}, {0}};
    static wtap_optblock_reg_t name_option = {"name", "Device name", WTAP_OPTTYPE_STRING, wtap_opttype_write_size_string, wtap_opttype_write_data_string, {0}, {0}};
    static wtap_optblock_reg_t description_option = {"description", "Device description", WTAP_OPTTYPE_STRING, wtap_opttype_write_size_string, wtap_opttype_write_data_string, {0}, {0}};
    static wtap_optblock_reg_t speed_option = {"speed", "Interface speed (in bps)", WTAP_OPTTYPE_UINT64, wtap_opttype_write_uint64_not0, wtap_opttype_write_data_uint64, {0}, {0}};
    static wtap_optblock_reg_t tsresol_option = {"ts_resolution", "Resolution of timestamps", WTAP_OPTTYPE_UINT8, wtap_opttype_write_uint8_not0, wtap_opttype_write_data_uint8, {0}, {0}};
    static wtap_optblock_reg_t filter_option = {"filter", "Filter string", WTAP_OPTTYPE_CUSTOM, idb_filter_write_size, idb_filter_write, {0}, {0}};
    static wtap_optblock_reg_t os_option = {"os", "Operating System", WTAP_OPTTYPE_STRING, wtap_opttype_write_size_string, wtap_opttype_write_data_string, {0}, {0}};
    static wtap_optblock_reg_t fcslen_option = {"fcslen", "FCS Length", WTAP_OPTTYPE_UINT8, NULL, NULL, {0}, {0}};

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

static gboolean idb_write(struct wtap_dumper *wdh, wtap_optionblock_t block, int *err)
{
    pcapng_block_header_t bh;
    pcapng_interface_description_block_t idb;
    wtapng_if_descr_mandatory_t* mand_data = (wtapng_if_descr_mandatory_t*)block->mandatory_data;
    guint32 options_total_length;

    wtap_debug("write_interface_description_block: encap = %d (%s), snaplen = %d",
                  mand_data->link_type,
                  wtap_encap_string(wtap_pcap_encap_to_wtap_encap(mand_data->link_type)),
                  mand_data->snap_len);

    if (mand_data->link_type == (guint16)-1) {
        *err = WTAP_ERR_UNWRITABLE_ENCAP;
        return FALSE;
    }

    options_total_length = wtap_optionblock_get_option_write_size(block);
    if (options_total_length > 0)
    {
        /* End-of-options tag */
        options_total_length += 4;
    }

    /* write block header */
    bh.block_type = BLOCK_TYPE_IDB;
    bh.block_total_length = (guint32)(sizeof(bh) + sizeof(idb) + options_total_length + 4);

    if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err))
        return FALSE;
    wdh->bytes_dumped += sizeof bh;

    /* write block fixed content */
    idb.linktype    = mand_data->link_type;
    idb.reserved    = 0;
    idb.snaplen     = mand_data->snap_len;

    if (!wtap_dump_file_write(wdh, &idb, sizeof idb, err))
        return FALSE;
    wdh->bytes_dumped += sizeof idb;

    if (!wtap_optionblock_write_options(wdh, block, options_total_length, err))
        return FALSE;

    /* write block footer */
    if (!wtap_dump_file_write(wdh, &bh.block_total_length,
                              sizeof bh.block_total_length, err))
        return FALSE;
    wdh->bytes_dumped += sizeof bh.block_total_length;
    return TRUE;
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
        shb_write,          /* write */
        NULL,               /* free_mand */
        shb_copy_mand,      /* copy_mand */
    };

    static wtap_opt_register_t nrb_block = {
        "NRB",              /* name */
        "Name Resolution Block",  /* description */
        nrb_create,         /* create */
        NULL,               /* write */
        NULL,               /* free_mand */
        NULL,               /* copy_mand */
    };

    static wtap_opt_register_t isb_block = {
        "ISB",              /* name */
        "Interface Statistics Block",  /* description */
        isb_create,         /* create */
        isb_write,          /* write */
        NULL,               /* free_mand */
        isb_copy_mand,      /* copy_mand */
    };

    static wtap_opt_register_t idb_block = {
        "IDB",              /* name */
        "Interface Description Block",  /* description */
        idb_create,         /* create */
        idb_write,          /* write */
        idb_free_mand,      /* free_mand */
        idb_copy_mand,      /* copy_mand */
    };

    /* Initialize the block array.  This is mostly for future proofing
       "outside registered" block types (for NULL checking) */
    memset(block_list, 0, WTAP_OPTION_BLOCK_MAX_TYPE*sizeof(wtap_opt_register_t*));

    wtap_opttype_block_register(WTAP_OPTION_BLOCK_NG_SECTION, &shb_block );
    wtap_opttype_block_register(WTAP_OPTION_BLOCK_NG_NRB, &nrb_block );
    wtap_opttype_block_register(WTAP_OPTION_BLOCK_IF_STATS, &isb_block );
    wtap_opttype_block_register(WTAP_OPTION_BLOCK_IF_DESCR, &idb_block );
}
