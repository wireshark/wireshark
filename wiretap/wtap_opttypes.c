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
#include <wsutil/ws_assert.h>

#include <wsutil/glib-compat.h>
#include <wsutil/inet_ipv6.h>

#if 0
#define wtap_debug(...) ws_warning(__VA_ARGS__)
#define DEBUG_COUNT_REFS
#else
#define wtap_debug(...)
#endif

#define ROUND_TO_4BYTE(len) (((len) + 3) & ~3)

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

/* Debugging reference counting */
#ifdef DEBUG_COUNT_REFS
static guint block_count = 0;
static guint8 blocks_active[sizeof(guint)/8];

static void rc_set(guint refnum)
{
    guint cellno = refnum / 8;
    guint bitno = refnum % 8;
    blocks_active[cellno] |= (guint8)(1 << bitno);
}

static void rc_clear(guint refnum)
{
    guint cellno = refnum / 8;
    guint bitno = refnum % 8;
    blocks_active[cellno] &= (guint8)~(1 << bitno);
}

#endif /* DEBUG_COUNT_REFS */

struct wtap_block
{
    wtap_blocktype_t* info;
    void* mandatory_data;
    GArray* options;
    gint ref_count;
#ifdef DEBUG_COUNT_REFS
    guint id;
#endif
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

static packet_verdict_opt_t
packet_verdict_dup(packet_verdict_opt_t* verdict_src)
{
    packet_verdict_opt_t verdict_dest;

    memset(&verdict_dest, 0, sizeof(verdict_dest));

    /* Deep copy. */
    verdict_dest.type = verdict_src->type;
    switch (verdict_src->type) {

    case packet_verdict_hardware:
        /* array of octets */
        verdict_dest.data.verdict_bytes =
            g_byte_array_new_take((guint8 *)g_memdup2(verdict_src->data.verdict_bytes->data,
                                                      verdict_src->data.verdict_bytes->len),
                                  verdict_src->data.verdict_bytes->len);
        break;

    case packet_verdict_linux_ebpf_tc:
        /* eBPF TC_ACT_ value */
        verdict_dest.data.verdict_linux_ebpf_tc =
            verdict_src->data.verdict_linux_ebpf_tc;
        break;

    case packet_verdict_linux_ebpf_xdp:
        /* xdp_action value */
        verdict_dest.data.verdict_linux_ebpf_xdp =
            verdict_src->data.verdict_linux_ebpf_xdp;
        break;

    default:
        break;
    }
    return verdict_dest;
}

void wtap_packet_verdict_free(packet_verdict_opt_t* verdict)
{
    switch (verdict->type) {

    case packet_verdict_hardware:
        /* array of bytes */
        g_byte_array_free(verdict->data.verdict_bytes, TRUE);
        break;

    default:
        break;
    }
}

static packet_hash_opt_t
packet_hash_dup(packet_hash_opt_t* hash_src)
{
    packet_hash_opt_t hash_dest;

    memset(&hash_dest, 0, sizeof(hash_dest));

    /* Deep copy. */
    hash_dest.type = hash_src->type;
    /* array of octets */
    hash_dest.hash_bytes =
        g_byte_array_new_take((guint8 *)g_memdup2(hash_src->hash_bytes->data,
                                                  hash_src->hash_bytes->len),
                              hash_src->hash_bytes->len);
    return hash_dest;
}

void wtap_packet_hash_free(packet_hash_opt_t* hash)
{
    /* array of bytes */
    g_byte_array_free(hash->hash_bytes, TRUE);
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
    static const wtap_opttype_t opt_custom = {
        "opt_custom",
        "Custom Option",
        WTAP_OPTTYPE_CUSTOM,
        WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED
    };

    block_type = blocktype->block_type;

    /* Check input */
    ws_assert(block_type < MAX_WTAP_BLOCK_TYPE_VALUE);

    /* Don't re-register. */
    ws_assert(blocktype_list[block_type] == NULL);

    /* Sanity check */
    ws_assert(blocktype->name);
    ws_assert(blocktype->description);
    ws_assert(blocktype->create);

    /*
     * Initialize the set of supported options.
     * All blocks that support options at all support
     * OPT_COMMENT and OPT_CUSTOM.
     *
     * XXX - there's no "g_uint_hash()" or "g_uint_equal()",
     * so we use "g_direct_hash()" and "g_direct_equal()".
     */
    blocktype->options = g_hash_table_new(g_direct_hash, g_direct_equal);
    g_hash_table_insert(blocktype->options, GUINT_TO_POINTER(OPT_COMMENT),
                        (gpointer)&opt_comment);
    g_hash_table_insert(blocktype->options, GUINT_TO_POINTER(OPT_CUSTOM_STR_COPY),
                        (gpointer)&opt_custom);
    g_hash_table_insert(blocktype->options, GUINT_TO_POINTER(OPT_CUSTOM_BIN_COPY),
                        (gpointer)&opt_custom);
    g_hash_table_insert(blocktype->options, GUINT_TO_POINTER(OPT_CUSTOM_STR_NO_COPY),
                        (gpointer)&opt_custom);
    g_hash_table_insert(blocktype->options, GUINT_TO_POINTER(OPT_CUSTOM_BIN_NO_COPY),
                        (gpointer)&opt_custom);

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

    if (block == NULL) {
        return NULL;
    }

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

    if (block == NULL) {
        return NULL;
    }

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
    block->ref_count = 1;
#ifdef DEBUG_COUNT_REFS
    block->id = block_count++;
    rc_set(block->id);
    wtap_debug("Created #%d %s", block->id, block->info->name);
#endif /* DEBUG_COUNT_REFS */

    return block;
}

static void wtap_block_free_option(wtap_block_t block, wtap_option_t *opt)
{
    const wtap_opttype_t *opttype;

    if (block == NULL) {
        return;
    }

    opttype = GET_OPTION_TYPE(block->info->options, opt->option_id);
    switch (opttype->data_type) {

    case WTAP_OPTTYPE_STRING:
        g_free(opt->value.stringval);
        break;

    case WTAP_OPTTYPE_BYTES:
        g_bytes_unref(opt->value.byteval);
        break;

    case WTAP_OPTTYPE_CUSTOM:
        switch (opt->value.custom_opt.pen) {
        case PEN_NFLX:
            g_free(opt->value.custom_opt.data.nflx_data.custom_data);
            break;
        default:
            g_free(opt->value.custom_opt.data.generic_data.custom_data);
            break;
        }
        break;

    case WTAP_OPTTYPE_IF_FILTER:
        if_filter_free(&opt->value.if_filterval);
        break;

    case WTAP_OPTTYPE_PACKET_VERDICT:
        wtap_packet_verdict_free(&opt->value.packet_verdictval);
        break;

    case WTAP_OPTTYPE_PACKET_HASH:
        wtap_packet_hash_free(&opt->value.packet_hash);
        break;

    default:
        break;
    }
}

static void wtap_block_free_options(wtap_block_t block)
{
    guint i;
    wtap_option_t *opt;

    if (block == NULL || block->options == NULL) {
        return;
    }

    for (i = 0; i < block->options->len; i++) {
        opt = &g_array_index(block->options, wtap_option_t, i);
        wtap_block_free_option(block, opt);
    }
    g_array_remove_range(block->options, 0, block->options->len);
}

wtap_block_t wtap_block_ref(wtap_block_t block)
{
    if (block == NULL) {
        return NULL;
    }

    g_atomic_int_inc(&block->ref_count);
#ifdef DEBUG_COUNT_REFS
        wtap_debug("Ref     #%d %s", block->id, block->info->name);
#endif /* DEBUG_COUNT_REFS */
    return block;
}

void wtap_block_unref(wtap_block_t block)
{
    if (block != NULL)
    {
        if (g_atomic_int_dec_and_test(&block->ref_count)) {
#ifdef DEBUG_COUNT_REFS
            wtap_debug("Destroy #%d %s", block->id, block->info->name);
            rc_clear(block->id);
#endif /* DEBUG_COUNT_REFS */
            if (block->info->free_mand != NULL)
                block->info->free_mand(block);

            g_free(block->mandatory_data);
            wtap_block_free_options(block);
            g_array_free(block->options, TRUE);
            g_free(block);
        }
#ifdef DEBUG_COUNT_REFS
        else {
            wtap_debug("Unref   #%d %s", block->id, block->info->name);
        }
#endif /* DEBUG_COUNT_REFS */
    }
}

void wtap_block_array_free(GArray* block_array)
{
    guint block;

    if (block_array == NULL)
        return;

    for (block = 0; block < block_array->len; block++) {
        wtap_block_unref(g_array_index(block_array, wtap_block_t, block));
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

        case WTAP_OPTTYPE_UINT32:
            wtap_block_add_uint32_option(dest_block, src_opt->option_id, src_opt->value.uint32val);
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

        case WTAP_OPTTYPE_BYTES:
            wtap_block_add_bytes_option_borrow(dest_block, src_opt->option_id, src_opt->value.byteval);
            break;

        case WTAP_OPTTYPE_CUSTOM:
            switch (src_opt->value.custom_opt.pen) {
            case PEN_NFLX:
                wtap_block_add_nflx_custom_option(dest_block, src_opt->value.custom_opt.data.nflx_data.type, src_opt->value.custom_opt.data.nflx_data.custom_data, src_opt->value.custom_opt.data.nflx_data.custom_data_len);
                break;
            default:
                wtap_block_add_custom_option(dest_block, src_opt->option_id, src_opt->value.custom_opt.pen, src_opt->value.custom_opt.data.generic_data.custom_data, src_opt->value.custom_opt.data.generic_data.custom_data_len);
                break;
            }
            break;

        case WTAP_OPTTYPE_IF_FILTER:
            wtap_block_add_if_filter_option(dest_block, src_opt->option_id, &src_opt->value.if_filterval);
            break;

        case WTAP_OPTTYPE_PACKET_VERDICT:
            wtap_block_add_packet_verdict_option(dest_block, src_opt->option_id, &src_opt->value.packet_verdictval);
            break;
        case WTAP_OPTTYPE_PACKET_HASH:
            wtap_block_add_packet_hash_option(dest_block, src_opt->option_id, &src_opt->value.packet_hash);
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

guint
wtap_block_count_option(wtap_block_t block, guint option_id)
{
    guint i;
    guint ret_val = 0;
    wtap_option_t *opt;

    if (block == NULL) {
        return 0;
    }

    for (i = 0; i < block->options->len; i++) {
        opt = &g_array_index(block->options, wtap_option_t, i);
        if (opt->option_id == option_id)
            ret_val++;
    }

    return ret_val;
}


gboolean wtap_block_foreach_option(wtap_block_t block, wtap_block_foreach_func func, void* user_data)
{
    guint i;
    wtap_option_t *opt;
    const wtap_opttype_t *opttype;

    if (block == NULL) {
        return TRUE;
    }

    for (i = 0; i < block->options->len; i++) {
        opt = &g_array_index(block->options, wtap_option_t, i);
        opttype = GET_OPTION_TYPE(block->info->options, opt->option_id);
        if (!func(block, opt->option_id, opttype->data_type, &opt->value, user_data))
            return FALSE;
    }
    return TRUE;
}

static wtap_opttype_return_val
wtap_block_add_option_common(wtap_block_t block, guint option_id, wtap_opttype_e type, wtap_option_t **optp)
{
    wtap_option_t *opt;
    const wtap_opttype_t *opttype;
    guint i;

    if (block == NULL) {
        return WTAP_OPTTYPE_BAD_BLOCK;
    }

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

    if (block == NULL) {
        return WTAP_OPTTYPE_BAD_BLOCK;
    }

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

    if (block == NULL) {
        return WTAP_OPTTYPE_BAD_BLOCK;
    }

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
wtap_block_add_uint32_option(wtap_block_t block, guint option_id, guint32 value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_UINT32, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.uint32val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_uint32_option_value(wtap_block_t block, guint option_id, guint32 value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_UINT32, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    optval->uint32val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_uint32_option_value(wtap_block_t block, guint option_id, guint32* value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_UINT32, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->uint32val;
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

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_IPv6, &optval);
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
    opt->value.stringval = ws_strdup_vprintf(format, va);
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
    opt->value.stringval = ws_strdup_vprintf(format, va);
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
    optval->stringval = ws_strdup_vprintf(format, va);
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
    optval->stringval = ws_strdup_vprintf(format, va);
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
wtap_block_add_bytes_option(wtap_block_t block, guint option_id, const guint8 *value, gsize value_length)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_BYTES, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.byteval = g_bytes_new(value, value_length);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_bytes_option_borrow(wtap_block_t block, guint option_id, GBytes *value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_BYTES, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.byteval = g_bytes_ref(value);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_bytes_option_value(wtap_block_t block, guint option_id, const guint8 *value, size_t value_length)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_BYTES, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS) {
        if (ret == WTAP_OPTTYPE_NOT_FOUND) {
            /*
             * There's no instance to set, so just try to create a new one
             * with the value.
             */
            return wtap_block_add_bytes_option(block, option_id, value, value_length);
        }
        /* Otherwise fail. */
        return ret;
    }
    g_bytes_unref(optval->byteval);
    optval->byteval = g_bytes_new(value, value_length);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_nth_bytes_option_value(wtap_block_t block, guint option_id, guint idx, GBytes *value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_nth_option_common(block, option_id, WTAP_OPTTYPE_BYTES, idx, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    g_bytes_unref(optval->byteval);
    optval->byteval = g_bytes_ref(value);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_bytes_option_value(wtap_block_t block, guint option_id, GBytes** value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_BYTES, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->byteval;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_nth_bytes_option_value(wtap_block_t block, guint option_id, guint idx, GBytes** value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_nth_option_common(block, option_id, WTAP_OPTTYPE_BYTES, idx, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->byteval;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_nflx_custom_option(wtap_block_t block, guint32 type, const char *custom_data, gsize custom_data_len)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, OPT_CUSTOM_BIN_COPY, WTAP_OPTTYPE_CUSTOM, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.custom_opt.pen = PEN_NFLX;
    opt->value.custom_opt.data.nflx_data.type = type;
    opt->value.custom_opt.data.nflx_data.custom_data_len = custom_data_len;
    opt->value.custom_opt.data.nflx_data.custom_data = g_memdup2(custom_data, custom_data_len);
    opt->value.custom_opt.data.nflx_data.use_little_endian = (block->info->block_type == WTAP_BLOCK_CUSTOM);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_nflx_custom_option(wtap_block_t block, guint32 nflx_type, char *nflx_custom_data _U_, gsize nflx_custom_data_len)
{
    const wtap_opttype_t *opttype;
    wtap_option_t *opt;
    guint i;

    if (block == NULL) {
        return WTAP_OPTTYPE_BAD_BLOCK;
    }
    opttype = GET_OPTION_TYPE(block->info->options, OPT_CUSTOM_BIN_COPY);
    if (opttype == NULL) {
        return WTAP_OPTTYPE_NO_SUCH_OPTION;
    }
    if (opttype->data_type != WTAP_OPTTYPE_CUSTOM) {
        return WTAP_OPTTYPE_TYPE_MISMATCH;
    }

    for (i = 0; i < block->options->len; i++) {
        opt = &g_array_index(block->options, wtap_option_t, i);
        if ((opt->option_id == OPT_CUSTOM_BIN_COPY) &&
            (opt->value.custom_opt.pen == PEN_NFLX) &&
            (opt->value.custom_opt.data.nflx_data.type == nflx_type)) {
            break;
        }
    }
    if (i == block->options->len) {
        return WTAP_OPTTYPE_NOT_FOUND;
    }
    if (nflx_custom_data_len < opt->value.custom_opt.data.nflx_data.custom_data_len) {
        return WTAP_OPTTYPE_TYPE_MISMATCH;
    }
    switch (nflx_type) {
    case NFLX_OPT_TYPE_VERSION: {
        guint32 *src, *dst;

        ws_assert(nflx_custom_data_len == sizeof(guint32));
        src = (guint32 *)opt->value.custom_opt.data.nflx_data.custom_data;
        dst = (guint32 *)nflx_custom_data;
        *dst = GUINT32_FROM_LE(*src);
        break;
    }
    case NFLX_OPT_TYPE_TCPINFO: {
        struct nflx_tcpinfo *src, *dst;

        ws_assert(nflx_custom_data_len == sizeof(struct nflx_tcpinfo));
        src = (struct nflx_tcpinfo *)opt->value.custom_opt.data.nflx_data.custom_data;
        dst = (struct nflx_tcpinfo *)nflx_custom_data;
        dst->tlb_tv_sec = GUINT64_FROM_LE(src->tlb_tv_sec);
        dst->tlb_tv_usec = GUINT64_FROM_LE(src->tlb_tv_usec);
        dst->tlb_ticks = GUINT32_FROM_LE(src->tlb_ticks);
        dst->tlb_sn = GUINT32_FROM_LE(src->tlb_sn);
        dst->tlb_stackid = src->tlb_stackid;
        dst->tlb_eventid = src->tlb_eventid;
        dst->tlb_eventflags = GUINT16_FROM_LE(src->tlb_eventflags);
        dst->tlb_errno = GINT32_FROM_LE(src->tlb_errno);
        dst->tlb_rxbuf_tls_sb_acc = GUINT32_FROM_LE(src->tlb_rxbuf_tls_sb_acc);
        dst->tlb_rxbuf_tls_sb_ccc = GUINT32_FROM_LE(src->tlb_rxbuf_tls_sb_ccc);
        dst->tlb_rxbuf_tls_sb_spare = GUINT32_FROM_LE(src->tlb_rxbuf_tls_sb_spare);
        dst->tlb_txbuf_tls_sb_acc = GUINT32_FROM_LE(src->tlb_txbuf_tls_sb_acc);
        dst->tlb_txbuf_tls_sb_ccc = GUINT32_FROM_LE(src->tlb_txbuf_tls_sb_ccc);
        dst->tlb_txbuf_tls_sb_spare = GUINT32_FROM_LE(src->tlb_txbuf_tls_sb_spare);
        dst->tlb_state = GINT32_FROM_LE(src->tlb_state);
        dst->tlb_starttime = GUINT32_FROM_LE(src->tlb_starttime);
        dst->tlb_iss = GUINT32_FROM_LE(src->tlb_iss);
        dst->tlb_flags = GUINT32_FROM_LE(src->tlb_flags);
        dst->tlb_snd_una = GUINT32_FROM_LE(src->tlb_snd_una);
        dst->tlb_snd_max = GUINT32_FROM_LE(src->tlb_snd_max);
        dst->tlb_snd_cwnd = GUINT32_FROM_LE(src->tlb_snd_cwnd);
        dst->tlb_snd_nxt = GUINT32_FROM_LE(src->tlb_snd_nxt);
        dst->tlb_snd_recover = GUINT32_FROM_LE(src->tlb_snd_recover);
        dst->tlb_snd_wnd = GUINT32_FROM_LE(src->tlb_snd_wnd);
        dst->tlb_snd_ssthresh = GUINT32_FROM_LE(src->tlb_snd_ssthresh);
        dst->tlb_srtt = GUINT32_FROM_LE(src->tlb_srtt);
        dst->tlb_rttvar = GUINT32_FROM_LE(src->tlb_rttvar);
        dst->tlb_rcv_up = GUINT32_FROM_LE(src->tlb_rcv_up);
        dst->tlb_rcv_adv = GUINT32_FROM_LE(src->tlb_rcv_adv);
        dst->tlb_flags2 = GUINT32_FROM_LE(src->tlb_flags2);
        dst->tlb_rcv_nxt = GUINT32_FROM_LE(src->tlb_rcv_nxt);
        dst->tlb_rcv_wnd = GUINT32_FROM_LE(src->tlb_rcv_wnd);
        dst->tlb_dupacks = GUINT32_FROM_LE(src->tlb_dupacks);
        dst->tlb_segqlen = GINT32_FROM_LE(src->tlb_segqlen);
        dst->tlb_snd_numholes = GINT32_FROM_LE(src->tlb_snd_numholes);
        dst->tlb_flex1 = GUINT32_FROM_LE(src->tlb_flex1);
        dst->tlb_flex2 = GUINT32_FROM_LE(src->tlb_flex2);
        dst->tlb_fbyte_in = GUINT32_FROM_LE(src->tlb_fbyte_in);
        dst->tlb_fbyte_out = GUINT32_FROM_LE(src->tlb_fbyte_out);
        dst->tlb_snd_scale = src->tlb_snd_scale;
        dst->tlb_rcv_scale = src->tlb_rcv_scale;
        for (i = 0; i < 3; i++) {
            dst->_pad[i] = src->_pad[i];
        }
        dst->tlb_stackinfo_bbr_cur_del_rate = GUINT64_FROM_LE(src->tlb_stackinfo_bbr_cur_del_rate);
        dst->tlb_stackinfo_bbr_delRate = GUINT64_FROM_LE(src->tlb_stackinfo_bbr_delRate);
        dst->tlb_stackinfo_bbr_rttProp = GUINT64_FROM_LE(src->tlb_stackinfo_bbr_rttProp);
        dst->tlb_stackinfo_bbr_bw_inuse = GUINT64_FROM_LE(src->tlb_stackinfo_bbr_bw_inuse);
        dst->tlb_stackinfo_bbr_inflight = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_inflight);
        dst->tlb_stackinfo_bbr_applimited = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_applimited);
        dst->tlb_stackinfo_bbr_delivered = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_delivered);
        dst->tlb_stackinfo_bbr_timeStamp = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_timeStamp);
        dst->tlb_stackinfo_bbr_epoch = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_epoch);
        dst->tlb_stackinfo_bbr_lt_epoch = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_lt_epoch);
        dst->tlb_stackinfo_bbr_pkts_out = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_pkts_out);
        dst->tlb_stackinfo_bbr_flex1 = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_flex1);
        dst->tlb_stackinfo_bbr_flex2 = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_flex2);
        dst->tlb_stackinfo_bbr_flex3 = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_flex3);
        dst->tlb_stackinfo_bbr_flex4 = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_flex4);
        dst->tlb_stackinfo_bbr_flex5 = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_flex5);
        dst->tlb_stackinfo_bbr_flex6 = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_flex6);
        dst->tlb_stackinfo_bbr_lost = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_lost);
        dst->tlb_stackinfo_bbr_pacing_gain = GUINT16_FROM_LE(src->tlb_stackinfo_bbr_lost);
        dst->tlb_stackinfo_bbr_cwnd_gain = GUINT16_FROM_LE(src->tlb_stackinfo_bbr_lost);
        dst->tlb_stackinfo_bbr_flex7 = GUINT16_FROM_LE(src->tlb_stackinfo_bbr_flex7);
        dst->tlb_stackinfo_bbr_bbr_state = src->tlb_stackinfo_bbr_bbr_state;
        dst->tlb_stackinfo_bbr_bbr_substate = src->tlb_stackinfo_bbr_bbr_substate;
        dst->tlb_stackinfo_bbr_inhpts = src->tlb_stackinfo_bbr_inhpts;
        dst->tlb_stackinfo_bbr_ininput = src->tlb_stackinfo_bbr_ininput;
        dst->tlb_stackinfo_bbr_use_lt_bw = src->tlb_stackinfo_bbr_use_lt_bw;
        dst->tlb_stackinfo_bbr_flex8 = src->tlb_stackinfo_bbr_flex8;
        dst->tlb_stackinfo_bbr_pkt_epoch = GUINT32_FROM_LE(src->tlb_stackinfo_bbr_pkt_epoch);
        dst->tlb_len = GUINT32_FROM_LE(src->tlb_len);
        break;
    }
    case NFLX_OPT_TYPE_DUMPINFO: {
        struct nflx_dumpinfo *src, *dst;

        ws_assert(nflx_custom_data_len == sizeof(struct nflx_dumpinfo));
        src = (struct nflx_dumpinfo *)opt->value.custom_opt.data.nflx_data.custom_data;
        dst = (struct nflx_dumpinfo *)nflx_custom_data;
        dst->tlh_version = GUINT32_FROM_LE(src->tlh_version);
        dst->tlh_type = GUINT32_FROM_LE(src->tlh_type);
        dst->tlh_length = GUINT64_FROM_LE(src->tlh_length);
        dst->tlh_ie_fport = src->tlh_ie_fport;
        dst->tlh_ie_lport = src->tlh_ie_lport;
        for (i = 0; i < 4; i++) {
            dst->tlh_ie_faddr_addr32[i] = src->tlh_ie_faddr_addr32[i];
            dst->tlh_ie_laddr_addr32[i] = src->tlh_ie_laddr_addr32[i];
        }
        dst->tlh_ie_zoneid = src->tlh_ie_zoneid;
        dst->tlh_offset_tv_sec = GUINT64_FROM_LE(src->tlh_offset_tv_sec);
        dst->tlh_offset_tv_usec = GUINT64_FROM_LE(src->tlh_offset_tv_usec);
        memcpy(dst->tlh_id, src->tlh_id, 64);
        memcpy(dst->tlh_reason, src->tlh_reason, 32);
        memcpy(dst->tlh_tag, src->tlh_tag, 32);
        dst->tlh_af = src->tlh_af;
        memcpy(dst->_pad, src->_pad, 7);
        break;
    }
    case NFLX_OPT_TYPE_DUMPTIME: {
        guint64 *src, *dst;

        ws_assert(nflx_custom_data_len == sizeof(guint64));
        src = (guint64 *)opt->value.custom_opt.data.nflx_data.custom_data;
        dst = (guint64 *)nflx_custom_data;
        *dst = GUINT64_FROM_LE(*src);
        break;
    }
    case NFLX_OPT_TYPE_STACKNAME:
        ws_assert(nflx_custom_data_len >= 2);
        memcpy(nflx_custom_data, opt->value.custom_opt.data.nflx_data.custom_data, nflx_custom_data_len);
        break;
    default:
        return WTAP_OPTTYPE_NOT_FOUND;
    }
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_custom_option(wtap_block_t block, guint option_id, guint32 pen, const char *custom_data, gsize custom_data_len)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_CUSTOM, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.custom_opt.pen = pen;
    opt->value.custom_opt.data.generic_data.custom_data_len = custom_data_len;
    opt->value.custom_opt.data.generic_data.custom_data = g_memdup2(custom_data, custom_data_len);
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
wtap_block_add_packet_verdict_option(wtap_block_t block, guint option_id, packet_verdict_opt_t* value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_PACKET_VERDICT, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.packet_verdictval = packet_verdict_dup(value);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_nth_packet_verdict_option_value(wtap_block_t block, guint option_id, guint idx, packet_verdict_opt_t* value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;
    packet_verdict_opt_t prev_value;

    ret = wtap_block_get_nth_option_common(block, option_id, WTAP_OPTTYPE_PACKET_VERDICT, idx, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    prev_value = optval->packet_verdictval;
    optval->packet_verdictval = packet_verdict_dup(value);
    /* Free after memory is duplicated in case structure was manipulated with a "get then set" */
    wtap_packet_verdict_free(&prev_value);

    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_nth_packet_verdict_option_value(wtap_block_t block, guint option_id, guint idx, packet_verdict_opt_t* value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_nth_option_common(block, option_id, WTAP_OPTTYPE_STRING, idx, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->packet_verdictval;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_packet_hash_option(wtap_block_t block, guint option_id, packet_hash_opt_t* value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_PACKET_HASH, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.packet_hash = packet_hash_dup(value);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_remove_option(wtap_block_t block, guint option_id)
{
    const wtap_opttype_t *opttype;
    guint i;
    wtap_option_t *opt;

    if (block == NULL) {
        return WTAP_OPTTYPE_BAD_BLOCK;
    }

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

    if (block == NULL) {
        return WTAP_OPTTYPE_BAD_BLOCK;
    }

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
    wtapng_section_mandatory_t* section_mand = g_new(wtapng_section_mandatory_t, 1);

    section_mand->section_length = -1;

    block->mandatory_data = section_mand;
}

static void shb_copy_mand(wtap_block_t dest_block, wtap_block_t src_block)
{
    memcpy(dest_block->mandatory_data, src_block->mandatory_data, sizeof(wtapng_section_mandatory_t));
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
        wtap_block_unref(if_stats);
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

static void pkt_create(wtap_block_t block)
{
    /* Commented out for now, there's no mandatory data that isn't handled by
     * Wireshark in other ways.
     */
    //block->mandatory_data = g_new0(wtapng_packet_mandatory_t, 1);

    /* Ensure this is null, so when g_free is called on it, it simply returns */
    block->mandatory_data = NULL;
}

static void sjeb_create(wtap_block_t block)
{
    /* Ensure this is null, so when g_free is called on it, it simply returns */
    block->mandatory_data = NULL;
}

static void cb_create(wtap_block_t block)
{
    /* Ensure this is null, so when g_free is called on it, it simply returns */
    block->mandatory_data = NULL;
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

    static wtap_blocktype_t pkt_block = {
        WTAP_BLOCK_PACKET,            /* block_type */
        "EPB/SPB/PB",                 /* name */
        "Packet Block",               /* description */
        pkt_create,                   /* create */
        NULL,                         /* free_mand */
        NULL,                         /* copy_mand */
        NULL                          /* options */
    };
    static const wtap_opttype_t pkt_flags = {
        "flags",
        "Link-layer flags",
        WTAP_OPTTYPE_UINT32,
        0
    };
    static const wtap_opttype_t pkt_dropcount = {
        "dropcount",
        "Packets Dropped since last packet",
        WTAP_OPTTYPE_UINT64,
        0
    };
    static const wtap_opttype_t pkt_id = {
        "packetid",
        "Unique Packet Identifier",
        WTAP_OPTTYPE_UINT64,
        0
    };
    static const wtap_opttype_t pkt_queue = {
        "queue",
        "Queue ID in which packet was received",
        WTAP_OPTTYPE_UINT32,
        0
    };
    static const wtap_opttype_t pkt_hash = {
        "hash",
        "Hash of packet data",
        WTAP_OPTTYPE_PACKET_HASH,
        WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED
    };
    static const wtap_opttype_t pkt_verdict = {
        "verdict",
        "Packet Verdict",
        WTAP_OPTTYPE_PACKET_VERDICT,
        WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED
    };

    static wtap_blocktype_t journal_block = {
        WTAP_BLOCK_SYSTEMD_JOURNAL_EXPORT, /* block_type */
        "SJEB",                         /* name */
        "systemd Journal Export Block", /* description */
        sjeb_create,                    /* create */
        NULL,                           /* free_mand */
        NULL,                           /* copy_mand */
        NULL                            /* options */
    };

    static wtap_blocktype_t cb_block = {
        WTAP_BLOCK_CUSTOM,            /* block_type */
        "CB",                         /* name */
        "Custom Block",               /* description */
        cb_create,                    /* create */
        NULL,                         /* free_mand */
        NULL,                         /* copy_mand */
        NULL                          /* options */
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
    wtap_opttype_option_register(&idb_block, OPT_IDB_DESCRIPTION, &if_description);
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

    /*
     * Register EPB/SPB/PB and the options that can appear in it/them.
     * NB: Simple Packet Blocks have no options.
     * NB: obsolete Packet Blocks have dropcount as a mandatory member instead
     * of an option.
     */
    wtap_opttype_block_register(&pkt_block);
    wtap_opttype_option_register(&pkt_block, OPT_PKT_FLAGS, &pkt_flags);
    wtap_opttype_option_register(&pkt_block, OPT_PKT_DROPCOUNT, &pkt_dropcount);
    wtap_opttype_option_register(&pkt_block, OPT_PKT_PACKETID, &pkt_id);
    wtap_opttype_option_register(&pkt_block, OPT_PKT_QUEUE, &pkt_queue);
    wtap_opttype_option_register(&pkt_block, OPT_PKT_HASH, &pkt_hash);
    wtap_opttype_option_register(&pkt_block, OPT_PKT_VERDICT, &pkt_verdict);

    /*
     * Register the SJEB and the (no) options that can appear in it.
     */
    wtap_opttype_block_register(&journal_block);

    /*
     * Register the CB and the options that can appear in it.
     */
    wtap_opttype_block_register(&cb_block);

#ifdef DEBUG_COUNT_REFS
    memset(blocks_active, 0, sizeof(blocks_active));
#endif
}

void wtap_opttypes_cleanup(void)
{
    guint block_type;
#ifdef DEBUG_COUNT_REFS
    guint i;
    guint cellno;
    guint bitno;
    guint8 mask;
#endif /* DEBUG_COUNT_REFS */

    for (block_type = (guint)WTAP_BLOCK_SECTION;
         block_type < (guint)MAX_WTAP_BLOCK_TYPE_VALUE; block_type++) {
        if (blocktype_list[block_type]) {
            if (blocktype_list[block_type]->options)
                g_hash_table_destroy(blocktype_list[block_type]->options);
            blocktype_list[block_type] = NULL;
        }
    }

#ifdef DEBUG_COUNT_REFS
    for (i = 0 ; i < block_count; i++) {
        cellno = i / 8;
        bitno = i % 8;
        mask = 1 << bitno;

        if ((blocks_active[cellno] & mask) == mask) {
            wtap_debug("wtap_opttypes_cleanup: orphaned block #%d", i);
        }
    }
#endif /* DEBUG_COUNT_REFS */
}
