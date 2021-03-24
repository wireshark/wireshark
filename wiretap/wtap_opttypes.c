/* wtap_opttypes.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <glib.h>
#include <string.h>

#include "wtap.h"
#include "wtap_opttypes.h"
#include "wtap-int.h"
#include "pcapng_module.h"

#include <wsutil/glib-compat.h>

#if 0
#define wtap_debug(...) g_warning(__VA_ARGS__)
#else
#define wtap_debug(...)
#endif

/*
 * Structure describing a type of block.
 */
typedef struct {
    wtap_block_type_t block_type;    /**< internal type code for block */
    const char *name;                /**< name of block */
    const char *description;         /**< human-readable description of block */
    wtap_block_create_func create;
    wtap_mand_free_func free_mand;
    wtap_mand_copy_func copy_mand;
    GHashTable *options;             /**< hash table of known options */
} wtap_blocktype_t;

#define GET_OPTION_TYPE(options, option_id) \
    (const wtap_opttype_t *)g_hash_table_lookup((options), GUINT_TO_POINTER(option_id))

/*
 * Structure describing a type of option.
 */
typedef struct {
    const char *name;                            /**< name of option */
    const char *description;                     /**< human-readable description of option */
    wtap_opttype_e data_type;                    /**< data type of that option */
    guint flags;                                 /**< flags for the option */
} wtap_opttype_t;

/* Flags */
#define WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED 0x00000001 /* multiple instances allowed */

struct wtap_block
{
    wtap_blocktype_t* info;
    void* mandatory_data;
    GArray* options;
};

/* Keep track of wtap_blocktype_t's via their id number */
static wtap_blocktype_t* blocktype_list[MAX_WTAP_BLOCK_TYPE_VALUE];

static if_filter_opt_t if_filter_dup(if_filter_opt_t* filter_src)
{
    if_filter_opt_t filter_dest;

    memset(&filter_dest, 0, sizeof(filter_dest));

    /* Deep copy. */
    filter_dest.type = filter_src->type;
    switch (filter_src->type) {

    case if_filter_pcap:
        /* pcap filter string */
        filter_dest.data.filter_str =
            g_strdup(filter_src->data.filter_str);
        break;

    case if_filter_bpf:
        /* BPF program */
        filter_dest.data.bpf_prog.bpf_prog_len =
            filter_src->data.bpf_prog.bpf_prog_len;
        filter_dest.data.bpf_prog.bpf_prog =
            (wtap_bpf_insn_t *)g_memdup2(filter_src->data.bpf_prog.bpf_prog,
                                        filter_src->data.bpf_prog.bpf_prog_len * sizeof (wtap_bpf_insn_t));
        break;

    default:
        break;
    }
    return filter_dest;
}

static void if_filter_free(if_filter_opt_t* filter_src)
{
    switch (filter_src->type) {

    case if_filter_pcap:
        /* pcap filter string */
        g_free(filter_src->data.filter_str);
        break;

    case if_filter_bpf:
        /* BPF program */
        g_free(filter_src->data.bpf_prog.bpf_prog);
        break;

    default:
        break;
    }
}

static void wtap_opttype_block_register(wtap_blocktype_t *blocktype)
{
    wtap_block_type_t block_type;
    static const wtap_opttype_t opt_comment = {
        "opt_comment",
        "Comment",
        WTAP_OPTTYPE_STRING,
        WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED
    };

    block_type = blocktype->block_type;

    /* Check input */
    g_assert(block_type < MAX_WTAP_BLOCK_TYPE_VALUE);

    /* Don't re-register. */
    g_assert(blocktype_list[block_type] == NULL);

    /* Sanity check */
    g_assert(blocktype->name);
    g_assert(blocktype->description);
    g_assert(blocktype->create);

    /*
     * Initialize the set of supported options.
     * All blocks that support options at all support OPT_COMMENT.
     *
     * XXX - there's no "g_uint_hash()" or "g_uint_equal()",
     * so we use "g_direct_hash()" and "g_direct_equal()".
     */
    blocktype->options = g_hash_table_new(g_direct_hash, g_direct_equal);
    g_hash_table_insert(blocktype->options, GUINT_TO_POINTER(OPT_COMMENT),
                        (gpointer)&opt_comment);

    blocktype_list[block_type] = blocktype;
}

static void wtap_opttype_option_register(wtap_blocktype_t *blocktype, guint opttype, const wtap_opttype_t *option)
{
    g_hash_table_insert(blocktype->options, GUINT_TO_POINTER(opttype),
                        (gpointer) option);
}

wtap_block_type_t wtap_block_get_type(wtap_block_t block)
{
    return block->info->block_type;
}

void* wtap_block_get_mandatory_data(wtap_block_t block)
{
    return block->mandatory_data;
}

static wtap_optval_t *
wtap_block_get_option(wtap_block_t block, guint option_id)
{
    guint i;
    wtap_option_t *opt;

    for (i = 0; i < block->options->len; i++) {
        opt = &g_array_index(block->options, wtap_option_t, i);
        if (opt->option_id == option_id)
            return &opt->value;
    }

    return NULL;
}

static wtap_optval_t *
wtap_block_get_nth_option(wtap_block_t block, guint option_id, guint idx)
{
    guint i;
    wtap_option_t *opt;
    guint opt_idx;

    opt_idx = 0;
    for (i = 0; i < block->options->len; i++) {
        opt = &g_array_index(block->options, wtap_option_t, i);
        if (opt->option_id == option_id) {
            if (opt_idx == idx)
                return &opt->value;
            opt_idx++;
        }
    }

    return NULL;
}

wtap_block_t wtap_block_create(wtap_block_type_t block_type)
{
    wtap_block_t block;

    if (block_type >= MAX_WTAP_BLOCK_TYPE_VALUE)
        return NULL;

    block = g_new(struct wtap_block, 1);
    block->info = blocktype_list[block_type];
    block->options = g_array_new(FALSE, FALSE, sizeof(wtap_option_t));
    block->info->create(block);

    return block;
}

static void wtap_block_free_option(wtap_block_t block, wtap_option_t *opt)
{
    const wtap_opttype_t *opttype;

    opttype = GET_OPTION_TYPE(block->info->options, opt->option_id);
    switch (opttype->data_type) {

    case WTAP_OPTTYPE_STRING:
        g_free(opt->value.stringval);
        break;

    case WTAP_OPTTYPE_IF_FILTER:
        if_filter_free(&opt->value.if_filterval);
        break;

    default:
        break;
    }
}

static void wtap_block_free_options(wtap_block_t block)
{
    guint i;
    wtap_option_t *opt;

    for (i = 0; i < block->options->len; i++) {
        opt = &g_array_index(block->options, wtap_option_t, i);
        wtap_block_free_option(block, opt);
    }
}

void wtap_block_free(wtap_block_t block)
{
    if (block != NULL)
    {
        if (block->info->free_mand != NULL)
            block->info->free_mand(block);

        g_free(block->mandatory_data);
        wtap_block_free_options(block);
        g_array_free(block->options, TRUE);
        g_free(block);
    }
}

void wtap_block_array_free(GArray* block_array)
{
    guint block;

    if (block_array == NULL)
        return;

    for (block = 0; block < block_array->len; block++) {
        wtap_block_free(g_array_index(block_array, wtap_block_t, block));
    }
    g_array_free(block_array, TRUE);
}

/*
 * Make a copy of a block.
 */
void
wtap_block_copy(wtap_block_t dest_block, wtap_block_t src_block)
{
    guint i;
    wtap_option_t *src_opt;
    const wtap_opttype_t *opttype;

    /*
     * Copy the mandatory data.
     */
    if (dest_block->info->copy_mand != NULL)
        dest_block->info->copy_mand(dest_block, src_block);

    /* Copy the options.  For now, don't remove any options that are in destination
     * but not source.
     */
    for (i = 0; i < src_block->options->len; i++)
    {
        src_opt = &g_array_index(src_block->options, wtap_option_t, i);
        opttype = GET_OPTION_TYPE(src_block->info->options, src_opt->option_id);

        switch(opttype->data_type) {

        case WTAP_OPTTYPE_UINT8:
            wtap_block_add_uint8_option(dest_block, src_opt->option_id, src_opt->value.uint8val);
            break;

        case WTAP_OPTTYPE_UINT64:
            wtap_block_add_uint64_option(dest_block, src_opt->option_id, src_opt->value.uint64val);
            break;

        case WTAP_OPTTYPE_IPv4:
            wtap_block_add_ipv4_option(dest_block, src_opt->option_id, src_opt->value.ipv4val);
            break;

        case WTAP_OPTTYPE_IPv6:
            wtap_block_add_ipv6_option(dest_block, src_opt->option_id, &src_opt->value.ipv6val);
            break;

        case WTAP_OPTTYPE_STRING:
            wtap_block_add_string_option(dest_block, src_opt->option_id, src_opt->value.stringval, strlen(src_opt->value.stringval));
            break;

        case WTAP_OPTTYPE_IF_FILTER:
            wtap_block_add_if_filter_option(dest_block, src_opt->option_id, &src_opt->value.if_filterval);
            break;
        }
    }
}

wtap_block_t wtap_block_make_copy(wtap_block_t block)
{
    wtap_block_t block_copy;

    block_copy = wtap_block_create(block->info->block_type);
    wtap_block_copy(block_copy, block);
    return block_copy;
}

void wtap_block_foreach_option(wtap_block_t block, wtap_block_foreach_func func, void* user_data)
{
    guint i;
    wtap_option_t *opt;
    const wtap_opttype_t *opttype;

    for (i = 0; i < block->options->len; i++) {
        opt = &g_array_index(block->options, wtap_option_t, i);
        opttype = GET_OPTION_TYPE(block->info->options, opt->option_id);
        func(block, opt->option_id, opttype->data_type, &opt->value, user_data);
    }
}

static wtap_opttype_return_val
wtap_block_add_option_common(wtap_block_t block, guint option_id, wtap_opttype_e type, wtap_option_t **optp)
{
    wtap_option_t *opt;
    const wtap_opttype_t *opttype;
    guint i;

    opttype = GET_OPTION_TYPE(block->info->options, option_id);
    if (opttype == NULL) {
        /* There's no option for this block with that option ID */
        return WTAP_OPTTYPE_NO_SUCH_OPTION;
    }

    /*
     * Is this an option of the specified data type?
     */
    if (opttype->data_type != type) {
        /*
         * No.
         */
        return WTAP_OPTTYPE_TYPE_MISMATCH;
    }

    /*
     * Can there be more than one instance of this option?
     */
    if (!(opttype->flags & WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED)) {
        /*
         * No. Is there already an instance of this option?
         */
        if (wtap_block_get_option(block, option_id) != NULL) {
            /*
             * Yes. Fail.
             */
            return WTAP_OPTTYPE_ALREADY_EXISTS;
        }
    }

    /*
     * Add an instance.
     */
    i = block->options->len;
    g_array_set_size(block->options, i + 1);
    opt = &g_array_index(block->options, wtap_option_t, i);
    opt->option_id = option_id;
    *optp = opt;
    return WTAP_OPTTYPE_SUCCESS;
}

static wtap_opttype_return_val
wtap_block_get_option_common(wtap_block_t block, guint option_id, wtap_opttype_e type, wtap_optval_t **optvalp)
{
    const wtap_opttype_t *opttype;
    wtap_optval_t *optval;

    opttype = GET_OPTION_TYPE(block->info->options, option_id);
    if (opttype == NULL) {
        /* There's no option for this block with that option ID */
        return WTAP_OPTTYPE_NO_SUCH_OPTION;
    }

    /*
     * Is this an option of the specified data type?
     */
    if (opttype->data_type != type) {
        /*
         * No.
         */
        return WTAP_OPTTYPE_TYPE_MISMATCH;
    }

    /*
     * Can there be more than one instance of this option?
     */
    if (opttype->flags & WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED) {
        /*
         * Yes.  You can't ask for "the" value.
         */
        return WTAP_OPTTYPE_NUMBER_MISMATCH;
    }

    optval = wtap_block_get_option(block, option_id);
    if (optval == NULL) {
        /* Didn't find the option */
        return WTAP_OPTTYPE_NOT_FOUND;
    }

    *optvalp = optval;
    return WTAP_OPTTYPE_SUCCESS;
}

static wtap_opttype_return_val
wtap_block_get_nth_option_common(wtap_block_t block, guint option_id, wtap_opttype_e type, guint idx, wtap_optval_t **optvalp)
{
    const wtap_opttype_t *opttype;
    wtap_optval_t *optval;

    opttype = GET_OPTION_TYPE(block->info->options, option_id);
    if (opttype == NULL) {
        /* There's no option for this block with that option ID */
        return WTAP_OPTTYPE_NO_SUCH_OPTION;
    }

    /*
     * Is this an option of the specified data type?
     */
    if (opttype->data_type != type) {
        /*
         * No.
         */
        return WTAP_OPTTYPE_TYPE_MISMATCH;
    }

    /*
     * Can there be more than one instance of this option?
     */
    if (!(opttype->flags & WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED)) {
        /*
         * No.
         */
        return WTAP_OPTTYPE_NUMBER_MISMATCH;
    }

    optval = wtap_block_get_nth_option(block, option_id, idx);
    if (optval == NULL) {
        /* Didn't find the option */
        return WTAP_OPTTYPE_NOT_FOUND;
    }

    *optvalp = optval;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_uint8_option(wtap_block_t block, guint option_id, guint8 value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_UINT8, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.uint8val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_uint8_option_value(wtap_block_t block, guint option_id, guint8 value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_UINT8, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    optval->uint8val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_uint8_option_value(wtap_block_t block, guint option_id, guint8* value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_UINT8, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->uint8val;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_uint64_option(wtap_block_t block, guint option_id, guint64 value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_UINT64, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.uint64val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_uint64_option_value(wtap_block_t block, guint option_id, guint64 value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_UINT64, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    optval->uint64val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_uint64_option_value(wtap_block_t block, guint option_id, guint64 *value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_UINT64, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->uint64val;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_ipv4_option(wtap_block_t block, guint option_id, guint32 value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_IPv4, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.ipv4val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_ipv4_option_value(wtap_block_t block, guint option_id, guint32 value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_IPv4, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    optval->ipv4val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_ipv4_option_value(wtap_block_t block, guint option_id, guint32* value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_IPv4, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->ipv4val;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_ipv6_option(wtap_block_t block, guint option_id, ws_in6_addr *value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_IPv6, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.ipv6val = *value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_ipv6_option_value(wtap_block_t block, guint option_id, ws_in6_addr *value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_IPv6, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    optval->ipv6val = *value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_ipv6_option_value(wtap_block_t block, guint option_id, ws_in6_addr* value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_IPv4, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->ipv6val;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_string_option(wtap_block_t block, guint option_id, const char *value, gsize value_length)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_STRING, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.stringval = g_strndup(value, value_length);
    return WTAP_OPTTYPE_SUCCESS;
}

static wtap_opttype_return_val
wtap_block_add_string_option_vformat(wtap_block_t block, guint option_id, const char *format, va_list va)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_STRING, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.stringval = g_strdup_vprintf(format, va);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_string_option_format(wtap_block_t block, guint option_id, const char *format, ...)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;
    va_list va;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_STRING, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    va_start(va, format);
    opt->value.stringval = g_strdup_vprintf(format, va);
    va_end(va);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_string_option_value(wtap_block_t block, guint option_id, const char *value, size_t value_length)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_STRING, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS) {
        if (ret == WTAP_OPTTYPE_NOT_FOUND) {
            /*
             * There's no instance to set, so just try to create a new one
             * with the value.
             */
            return wtap_block_add_string_option(block, option_id, value, value_length);
        }
        /* Otherwise fail. */
        return ret;
    }
    g_free(optval->stringval);
    optval->stringval = g_strndup(value, value_length);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_nth_string_option_value(wtap_block_t block, guint option_id, guint idx, const char *value, size_t value_length)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_nth_option_common(block, option_id, WTAP_OPTTYPE_STRING, idx, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    g_free(optval->stringval);
    optval->stringval = g_strndup(value, value_length);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_string_option_value_format(wtap_block_t block, guint option_id, const char *format, ...)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;
    va_list va;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_STRING, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS) {
        if (ret == WTAP_OPTTYPE_NOT_FOUND) {
            /*
             * There's no instance to set, so just try to create a new one
             * with the formatted string.
             */
            va_start(va, format);
            ret = wtap_block_add_string_option_vformat(block, option_id, format, va);
            va_end(va);
            return ret;
        }
        /* Otherwise fail. */
        return ret;
    }
    g_free(optval->stringval);
    va_start(va, format);
    optval->stringval = g_strdup_vprintf(format, va);
    va_end(va);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_nth_string_option_value_format(wtap_block_t block, guint option_id, guint idx, const char *format, ...)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;
    va_list va;

    ret = wtap_block_get_nth_option_common(block, option_id, WTAP_OPTTYPE_STRING, idx, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    g_free(optval->stringval);
    va_start(va, format);
    optval->stringval = g_strdup_vprintf(format, va);
    va_end(va);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_string_option_value(wtap_block_t block, guint option_id, char** value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_STRING, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->stringval;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_nth_string_option_value(wtap_block_t block, guint option_id, guint idx, char** value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_nth_option_common(block, option_id, WTAP_OPTTYPE_STRING, idx, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->stringval;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_if_filter_option(wtap_block_t block, guint option_id, if_filter_opt_t* value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_IF_FILTER, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.if_filterval = if_filter_dup(value);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_if_filter_option_value(wtap_block_t block, guint option_id, if_filter_opt_t* value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;
    if_filter_opt_t prev_value;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_IF_FILTER, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    prev_value = optval->if_filterval;
    optval->if_filterval = if_filter_dup(value);
    /* Free after memory is duplicated in case structure was manipulated with a "get then set" */
    if_filter_free(&prev_value);

    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_if_filter_option_value(wtap_block_t block, guint option_id, if_filter_opt_t* value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_IF_FILTER, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->if_filterval;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_remove_option(wtap_block_t block, guint option_id)
{
    const wtap_opttype_t *opttype;
    guint i;
    wtap_option_t *opt;

    opttype = GET_OPTION_TYPE(block->info->options, option_id);
    if (opttype == NULL) {
        /* There's no option for this block with that option ID */
        return WTAP_OPTTYPE_NO_SUCH_OPTION;
    }

    /*
     * Can there be more than one instance of this option?
     */
    if (opttype->flags & WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED) {
        /*
         * Yes.  You can't remove "the" value.
         */
        return WTAP_OPTTYPE_NUMBER_MISMATCH;
    }

    for (i = 0; i < block->options->len; i++) {
        opt = &g_array_index(block->options, wtap_option_t, i);
        if (opt->option_id == option_id) {
            /* Found it - free up the value */
            wtap_block_free_option(block, opt);
            /* Remove the option from the array of options */
            g_array_remove_index(block->options, i);
            return WTAP_OPTTYPE_SUCCESS;
        }
    }

    /* Didn't find the option */
    return WTAP_OPTTYPE_NOT_FOUND;
}

wtap_opttype_return_val
wtap_block_remove_nth_option_instance(wtap_block_t block, guint option_id,
                                      guint idx)
{
    const wtap_opttype_t *opttype;
    guint i;
    wtap_option_t *opt;
    guint opt_idx;

    opttype = GET_OPTION_TYPE(block->info->options, option_id);
    if (opttype == NULL) {
        /* There's no option for this block with that option ID */
        return WTAP_OPTTYPE_NO_SUCH_OPTION;
    }

    /*
     * Can there be more than one instance of this option?
     */
    if (!(opttype->flags & WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED)) {
        /*
         * No.
         */
        return WTAP_OPTTYPE_NUMBER_MISMATCH;
    }

    opt_idx = 0;
    for (i = 0; i < block->options->len; i++) {
        opt = &g_array_index(block->options, wtap_option_t, i);
        if (opt->option_id == option_id) {
            if (opt_idx == idx) {
                /* Found it - free up the value */
                wtap_block_free_option(block, opt);
                /* Remove the option from the array of options */
                g_array_remove_index(block->options, i);
                return WTAP_OPTTYPE_SUCCESS;
            }
            opt_idx++;
        }
    }

    /* Didn't find the option */
    return WTAP_OPTTYPE_NOT_FOUND;
}

static void shb_create(wtap_block_t block)
{
    wtapng_mandatory_section_t* section_mand = g_new(wtapng_mandatory_section_t, 1);

    section_mand->section_length = -1;

    block->mandatory_data = section_mand;
}

static void shb_copy_mand(wtap_block_t dest_block, wtap_block_t src_block)
{
    memcpy(dest_block->mandatory_data, src_block->mandatory_data, sizeof(wtapng_mandatory_section_t));
}

static void nrb_create(wtap_block_t block)
{
    block->mandatory_data = NULL;
}

static void isb_create(wtap_block_t block)
{
    block->mandatory_data = g_new0(wtapng_if_stats_mandatory_t, 1);
}

static void isb_copy_mand(wtap_block_t dest_block, wtap_block_t src_block)
{
    memcpy(dest_block->mandatory_data, src_block->mandatory_data, sizeof(wtapng_if_stats_mandatory_t));
}

static void idb_create(wtap_block_t block)
{
    block->mandatory_data = g_new0(wtapng_if_descr_mandatory_t, 1);
}

static void idb_free_mand(wtap_block_t block)
{
    guint j;
    wtap_block_t if_stats;
    wtapng_if_descr_mandatory_t* mand = (wtapng_if_descr_mandatory_t*)block->mandatory_data;

    for(j = 0; j < mand->num_stat_entries; j++) {
        if_stats = g_array_index(mand->interface_statistics, wtap_block_t, j);
        wtap_block_free(if_stats);
    }

    if (mand->interface_statistics)
        g_array_free(mand->interface_statistics, TRUE);
}

static void idb_copy_mand(wtap_block_t dest_block, wtap_block_t src_block)
{
    guint j;
    wtap_block_t src_if_stats, dest_if_stats;
    wtapng_if_descr_mandatory_t *src_mand = (wtapng_if_descr_mandatory_t*)src_block->mandatory_data,
                                *dest_mand = (wtapng_if_descr_mandatory_t*)dest_block->mandatory_data;

    /* Need special consideration for copying of the interface_statistics member */
    if (dest_mand->num_stat_entries != 0)
        g_array_free(dest_mand->interface_statistics, TRUE);

    memcpy(dest_mand, src_mand, sizeof(wtapng_if_descr_mandatory_t));
    if (src_mand->num_stat_entries != 0)
    {
        dest_mand->interface_statistics = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));
        for (j = 0; j < src_mand->num_stat_entries; j++)
        {
            src_if_stats = g_array_index(src_mand->interface_statistics, wtap_block_t, j);
            dest_if_stats = wtap_block_make_copy(src_if_stats);
            dest_mand->interface_statistics = g_array_append_val(dest_mand->interface_statistics, dest_if_stats);
        }
    }
}

static void dsb_create(wtap_block_t block)
{
    block->mandatory_data = g_new0(wtapng_dsb_mandatory_t, 1);
}

static void dsb_free_mand(wtap_block_t block)
{
    wtapng_dsb_mandatory_t *mand = (wtapng_dsb_mandatory_t *)block->mandatory_data;
    g_free(mand->secrets_data);
}

static void dsb_copy_mand(wtap_block_t dest_block, wtap_block_t src_block)
{
    wtapng_dsb_mandatory_t *src = (wtapng_dsb_mandatory_t *)src_block->mandatory_data;
    wtapng_dsb_mandatory_t *dst = (wtapng_dsb_mandatory_t *)dest_block->mandatory_data;
    dst->secrets_type = src->secrets_type;
    dst->secrets_len = src->secrets_len;
    g_free(dst->secrets_data);
    dst->secrets_data = (guint8 *)g_memdup2(src->secrets_data, src->secrets_len);
}

void wtap_opttypes_initialize(void)
{
    static wtap_blocktype_t shb_block = {
        WTAP_BLOCK_SECTION,     /* block_type */
        "SHB",                  /* name */
        "Section Header Block", /* description */
        shb_create,             /* create */
        NULL,                   /* free_mand */
        shb_copy_mand,          /* copy_mand */
        NULL                    /* options */
    };
    static const wtap_opttype_t shb_hardware = {
        "hardware",
        "SHB Hardware",
        WTAP_OPTTYPE_STRING,
        0
    };
    static const wtap_opttype_t shb_os = {
        "os",
        "SHB Operating System",
        WTAP_OPTTYPE_STRING,
        0
    };
    static const wtap_opttype_t shb_userappl = {
        "user_appl",
        "SHB User Application",
        WTAP_OPTTYPE_STRING,
        0
    };

    static wtap_blocktype_t idb_block = {
        WTAP_BLOCK_IF_ID_AND_INFO,     /* block_type */
        "IDB",                         /* name */
        "Interface Description Block", /* description */
        idb_create,                    /* create */
        idb_free_mand,                 /* free_mand */
        idb_copy_mand,                 /* copy_mand */
        NULL                           /* options */
    };
    static const wtap_opttype_t if_name = {
        "name",
        "IDB Name",
        WTAP_OPTTYPE_STRING,
        0
    };
    static const wtap_opttype_t if_description = {
        "description",
        "IDB Description",
        WTAP_OPTTYPE_STRING,
        0
    };
    static const wtap_opttype_t if_speed = {
        "speed",
        "IDB Speed",
        WTAP_OPTTYPE_UINT64,
        0
    };
    static const wtap_opttype_t if_tsresol = {
        "tsresol",
        "IDB Time Stamp Resolution",
        WTAP_OPTTYPE_UINT8, /* XXX - signed? */
        0
    };
    static const wtap_opttype_t if_filter = {
        "filter",
        "IDB Filter",
        WTAP_OPTTYPE_IF_FILTER,
        0
    };
    static const wtap_opttype_t if_os = {
        "os",
        "IDB Operating System",
        WTAP_OPTTYPE_STRING,
        0
    };
    static const wtap_opttype_t if_fcslen = {
        "fcslen",
        "IDB FCS Length",
        WTAP_OPTTYPE_UINT8,
        0
    };
    static const wtap_opttype_t if_hardware = {
        "hardware",
        "IDB Hardware",
        WTAP_OPTTYPE_STRING,
        0
    };

    static wtap_blocktype_t dsb_block = {
        WTAP_BLOCK_DECRYPTION_SECRETS,
        "DSB",
        "Decryption Secrets Block",
        dsb_create,
        dsb_free_mand,
        dsb_copy_mand,
        NULL
    };

    static wtap_blocktype_t nrb_block = {
        WTAP_BLOCK_NAME_RESOLUTION, /* block_type */
        "NRB",                      /* name */
        "Name Resolution Block",    /* description */
        nrb_create,                 /* create */
        NULL,                       /* free_mand */
        NULL,                       /* copy_mand */
        NULL                        /* options */
    };
    static const wtap_opttype_t ns_dnsname = {
        "dnsname",
        "NRB DNS server name",
        WTAP_OPTTYPE_STRING,
        0
    };
    static const wtap_opttype_t ns_dnsIP4addr = {
        "dnsIP4addr",
        "NRB DNS server IPv4 address",
        WTAP_OPTTYPE_IPv4,
        0
    };
    static const wtap_opttype_t ns_dnsIP6addr = {
        "dnsIP6addr",
        "NRB DNS server IPv6 address",
        WTAP_OPTTYPE_IPv6,
        0
    };

    static wtap_blocktype_t isb_block = {
        WTAP_BLOCK_IF_STATISTICS,     /* block_type */
        "ISB",                        /* name */
        "Interface Statistics Block", /* description */
        isb_create,                   /* create */
        NULL,                         /* free_mand */
        isb_copy_mand,                /* copy_mand */
        NULL                          /* options */
    };
    static const wtap_opttype_t isb_starttime = {
        "starttime",
        "ISB Start Time",
        WTAP_OPTTYPE_UINT64,
        0
    };
    static const wtap_opttype_t isb_endtime = {
        "endtime",
        "ISB End Time",
        WTAP_OPTTYPE_UINT64,
        0
    };
    static const wtap_opttype_t isb_ifrecv = {
        "ifrecv",
        "ISB Received Packets",
        WTAP_OPTTYPE_UINT64,
        0
    };
    static const wtap_opttype_t isb_ifdrop = {
        "ifdrop",
        "ISB Dropped Packets",
        WTAP_OPTTYPE_UINT64,
        0
    };
    static const wtap_opttype_t isb_filteraccept = {
        "filteraccept",
        "ISB Packets Accepted By Filter",
        WTAP_OPTTYPE_UINT64,
        0
    };
    static const wtap_opttype_t isb_osdrop = {
        "osdrop",
        "ISB Packets Dropped By The OS",
        WTAP_OPTTYPE_UINT64,
        0
    };
    static const wtap_opttype_t isb_usrdeliv = {
        "usrdeliv",
        "ISB Packets Delivered To The User",
        WTAP_OPTTYPE_UINT64,
        0
    };

    /*
     * Register the SHB and the options that can appear in it.
     */
    wtap_opttype_block_register(&shb_block);
    wtap_opttype_option_register(&shb_block, OPT_SHB_HARDWARE, &shb_hardware);
    wtap_opttype_option_register(&shb_block, OPT_SHB_OS, &shb_os);
    wtap_opttype_option_register(&shb_block, OPT_SHB_USERAPPL, &shb_userappl);

    /*
     * Register the IDB and the options that can appear in it.
     */
    wtap_opttype_block_register(&idb_block);
    wtap_opttype_option_register(&idb_block, OPT_IDB_NAME, &if_name);
    wtap_opttype_option_register(&idb_block, OPT_IDB_DESCR, &if_description);
    wtap_opttype_option_register(&idb_block, OPT_IDB_SPEED, &if_speed);
    wtap_opttype_option_register(&idb_block, OPT_IDB_TSRESOL, &if_tsresol);
    wtap_opttype_option_register(&idb_block, OPT_IDB_FILTER, &if_filter);
    wtap_opttype_option_register(&idb_block, OPT_IDB_OS, &if_os);
    wtap_opttype_option_register(&idb_block, OPT_IDB_FCSLEN, &if_fcslen);
    wtap_opttype_option_register(&idb_block, OPT_IDB_HARDWARE, &if_hardware);

    /*
     * Register the NRB and the options that can appear in it.
     */
    wtap_opttype_block_register(&nrb_block);
    wtap_opttype_option_register(&nrb_block, OPT_NS_DNSNAME, &ns_dnsname);
    wtap_opttype_option_register(&nrb_block, OPT_NS_DNSIP4ADDR, &ns_dnsIP4addr);
    wtap_opttype_option_register(&nrb_block, OPT_NS_DNSIP6ADDR, &ns_dnsIP6addr);

    /*
     * Register the ISB and the options that can appear in it.
     */
    wtap_opttype_block_register(&isb_block);
    wtap_opttype_option_register(&isb_block, OPT_ISB_STARTTIME, &isb_starttime);
    wtap_opttype_option_register(&isb_block, OPT_ISB_ENDTIME, &isb_endtime);
    wtap_opttype_option_register(&isb_block, OPT_ISB_IFRECV, &isb_ifrecv);
    wtap_opttype_option_register(&isb_block, OPT_ISB_IFDROP, &isb_ifdrop);
    wtap_opttype_option_register(&isb_block, OPT_ISB_FILTERACCEPT, &isb_filteraccept);
    wtap_opttype_option_register(&isb_block, OPT_ISB_OSDROP, &isb_osdrop);
    wtap_opttype_option_register(&isb_block, OPT_ISB_USRDELIV, &isb_usrdeliv);

    /*
     * Register the DSB, currently no options are defined.
     */
    wtap_opttype_block_register(&dsb_block);
}

void wtap_opttypes_cleanup(void)
{
    guint block_type;

    for (block_type = (guint)WTAP_BLOCK_SECTION;
         block_type < (guint)MAX_WTAP_BLOCK_TYPE_VALUE; block_type++) {
        if (blocktype_list[block_type]) {
            if (blocktype_list[block_type]->options)
                g_hash_table_destroy(blocktype_list[block_type]->options);
            blocktype_list[block_type] = NULL;
        }
    }
}
