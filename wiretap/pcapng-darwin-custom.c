/**
 * Support for Apple Legacy and Custom pcapng blocks and options
 * Copyright 2025, Omer Shapira <oesh@apple.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include "wtap-int.h"
#include "pcapng.h"
#include "pcapng_module.h"
#include "wtap_opttypes.h"
#include "wsutil/ws_padding_to.h"


/* pcapng: legacy DPIB (Darwin Process Info Block) file encoding. */
typedef struct pcapng_legacy_darwin_process_info_block_s {
    uint32_t process_id;
    /* Options */
}  pcapng_legacy_darwin_process_info_block_t;


/* Minimum DPIB size = minimum block size + size of fixed length portion of DPIB. */
 #define MIN_DPIB_SIZE    ((uint32_t)sizeof(pcapng_legacy_darwin_process_info_block_t))


static uint32_t
compute_dpib_option_size(wtap_block_t block _U_, unsigned option_code,  wtap_opttype_e option_type _U_, wtap_optval_t* optval)
{
    uint32_t size = 0;

    switch (option_code) {
    case(OPT_DPIB_NAME): /* dpib_process_name */
        size = (uint32_t)strlen(optval->stringval) & 0xffff;
        break;
    case(OPT_DPIB_UUID): /* dpib_process_uuid */
        size = 16;
        break;
    default:
        ws_warning("Unrecognized DPIB option code %u", option_code);
    }
    return size;
}

static bool
put_dpib_option(wtap_block_t block _U_, unsigned option_code, wtap_opttype_e option_type _U_, wtap_optval_t* optval, void* user_data)
{
    struct pcapng_option_header option_hdr;
    size_t                      size        = 0;
    size_t                      pad         = 0;
    uint8_t                     **opt_ptrp  = (uint8_t **)user_data;
    const void                  *uuid_bytes;

    switch (option_code) {
    case OPT_DPIB_NAME:
        size = strlen(optval->stringval);
        if (size > 65535) {
            /* Too big to fit */
            return true;
        }
        if (size == 0) {
            /* If the name is an empty string, it won't be accounted for
             * by `pcapng_compute_options_size`. We have two alternatives
             * available if we want to avoid creating a corrupted file:
             * 1. Skip writing the empty string; or
             * 2. Don't use `pcapng_compute_options_size`; implement
             *    a similar function that will account for the size
             *    of an option header while calculating the options size.
             * Here, we are opting for the first alternative: skip
             * writing the empty option. This creates a file that is
             * readable by Darwin tcpdump.
             */
            return true;
        }
        option_hdr.type         = (uint16_t)option_code;
        option_hdr.value_length = (uint16_t)size;
        memcpy(*opt_ptrp, &option_hdr, 4);
        *opt_ptrp += 4;
        memcpy(*opt_ptrp, optval->stringval, size);
        *opt_ptrp += size;
        /* write padding (if any) */
        if ((pad = WS_PADDING_TO_4(size)) != 0) {
            memset(*opt_ptrp, 0, pad);
            *opt_ptrp += pad;
        }

        break;
    case OPT_DPIB_UUID:
        uuid_bytes = g_bytes_get_data(optval->byteval, &size);
        option_hdr.type         = (uint16_t)option_code;
        option_hdr.value_length = (uint16_t)size;
        memcpy(*opt_ptrp, &option_hdr, 4);
        *opt_ptrp += 4;
        memcpy(*opt_ptrp, uuid_bytes, size);
        *opt_ptrp += size;
        break;
    default:
        break;
    }
    return true;
}

bool
pcapng_write_legacy_darwin_process_event_block(wtap_dumper *wdh, wtap_block_t sdata, int *err)
{
    pcapng_block_header_t              bh;
    wtapng_ft_specific_mandatory_t     *dpib_mand;
    uint32_t                           options_size;
    uint8_t                            *block_data;
    uint8_t                            *opt_ptr;
    uint32_t                           block_off;

    /* Note: the process id is represented by the `record_type` field
     * of the generic type `wtap_ft_specific_mandatory_t`
     */
    dpib_mand = (wtapng_ft_specific_mandatory_t*)wtap_block_get_mandatory_data(sdata);

    if (!dpib_mand) {
        return true;
    }

    /* pcapng_compute_options_size takes care of the 4 bytes for the end-of-options. */
    options_size = pcapng_compute_options_size(sdata, compute_dpib_option_size);


    bh.block_type = BLOCK_TYPE_LEGACY_DPIB;
    bh.block_total_length = sizeof(bh) + sizeof(dpib_mand->record_type) + options_size + sizeof(bh.block_total_length);

    /* Allocate the block data */
    block_data = (uint8_t *)g_malloc0(bh.block_total_length);

    /* Copy the block header */
    memcpy(block_data, &bh, sizeof(bh));
    block_off = sizeof(bh);

    /* Copy the process id */
    memcpy(block_data + block_off, &dpib_mand->record_type, 4);
    block_off += 4;

    /* Populate the options */
    opt_ptr = block_data + block_off;
    wtap_block_foreach_option(sdata, put_dpib_option, &opt_ptr);
    block_off += options_size;

    /* Copy the block trailer */
    memcpy(block_data + block_off, &bh.block_total_length, sizeof(bh.block_total_length));

    if (!wtap_dump_file_write(wdh, block_data, bh.block_total_length, err)) {
        g_free(block_data);
        return false;
    }

    return true;
}

static bool
pcapng_write_darwin_legacy_uint32_option(wtap_dumper *wdh, unsigned option_id, wtap_optval_t *optval, int *err)
{
    struct pcapng_option_header option_hdr;

    option_hdr.type         = (uint16_t)option_id;
    option_hdr.value_length = (uint16_t)4;

    ws_noisy("%s: type: %hu len: %hu value: %u", __func__,
        option_hdr.type, option_hdr.value_length, optval->uint32val);

    if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
        return false;

    if (!wtap_dump_file_write(wdh, &optval->uint32val, 4, err))
        return false;

    return true;
}

static bool
pcapng_write_darwin_legacy_uint16_option(wtap_dumper *wdh, unsigned option_id, wtap_optval_t *optval, int *err)
{
    struct pcapng_option_header option_hdr;
    uint16_t                    option_val;

    option_val              = (uint16_t)optval->uint32val;
    option_hdr.type         = (uint16_t)option_id;
    option_hdr.value_length = (uint16_t)2;


    ws_noisy("%s: type: %hu len: %hu value: %u", __func__,
        option_hdr.type, option_hdr.value_length, optval->uint32val);

    if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
        return false;

    if (!wtap_dump_file_write(wdh, &option_val, 2, err))
        return false;

    return true;
}

static bool
pcapng_write_darwin_legacy_string_option(wtap_dumper *wdh, unsigned option_id, wtap_optval_t *optval, int *err)
{
    struct pcapng_option_header option_hdr;
    size_t size = strlen(optval->stringval);

    if (size == 0)
        return true;

    if (size > 65535) {
        /*
         * Too big to fit in the option.
         * Don't write anything.
         *
         * XXX - truncate it?  Report an error?
         */
        return true;
    }

    /* write option header */
    /* String options don't consider pad bytes part of the length */
    option_hdr.type         = (uint16_t)option_id;
    option_hdr.value_length = (uint16_t)size;


    ws_noisy("%s: type: %hu len: %hu value: %s ", __func__,
        option_hdr.type, option_hdr.value_length, optval->stringval);

    if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
        return false;

    if (!wtap_dump_file_write(wdh, optval->stringval, size, err))
        return false;

    /* write padding (if any) */
    return pcapng_write_padding(wdh, WS_PADDING_TO_4(size), err);
}


uint32_t
pcapng_compute_epb_legacy_darwin_size(unsigned option_id, wtap_optval_t *optval)
{
    switch (option_id) {
        /* 32-bit options */
        case OPT_PKT_DARWIN_PIB_ID:
        case OPT_PKT_DARWIN_EFFECTIVE_PIB_ID:
        case OPT_PKT_DARWIN_SVC_CODE:
        case OPT_PKT_DARWIN_MD_FLAGS:
        case OPT_PKT_DARWIN_FLOW_ID:
        case OPT_PKT_DARWIN_DROP_REASON:
        case OPT_PKT_DARWIN_COMP_GENCNT:
            return 4;
            break;
        /* 16-bit options (independent of DPIBs) */
        case OPT_PKT_DARWIN_DROP_LINE:
        case OPT_PKT_DARWIN_TRACE_TAG:
            return 2;
            break;
        /* String options */
        case OPT_PKT_DARWIN_DROP_FUNC:
            return WS_PADDING_TO_4(strlen(optval->stringval));
            break;
        default:
            break;
    }

    return 0;
}


bool
pcapng_write_epb_legacy_darwin_option(wtap_dumper *wdh, wtap_block_t sdata _U_,
        unsigned option_id, wtap_opttype_e option_type _U_, wtap_optval_t *optval, int *err, char **err_info _U_)
{
    switch (option_id) {
    /* 32-bit options that refer to the DPIBs */
    case OPT_PKT_DARWIN_PIB_ID:
    case OPT_PKT_DARWIN_EFFECTIVE_PIB_ID: {
        /* The referenced Darwin PIB id should be present in the wdh->dpibs */
        if ((wdh->dpibs_growing == NULL) || (wdh->dpibs_growing->len <= (uint32_t)optval->int32val)) {
            /* The `optval` is unlikely to be a Darwin PIB id reference, ignore. */
            ws_warning("Attempting to write a DPIB option while no DPIBs are present. Writing anyway.");
            // return true;
        }
        if (!pcapng_write_darwin_legacy_uint32_option(wdh, option_id, optval, err)) {
            /* Write error */
            return false;
        }
        break;
    }
    /* 32-bit options that are independent of DPIBs */
    case OPT_PKT_DARWIN_SVC_CODE:
    case OPT_PKT_DARWIN_MD_FLAGS:
    case OPT_PKT_DARWIN_FLOW_ID:
    case OPT_PKT_DARWIN_DROP_REASON:
    case OPT_PKT_DARWIN_COMP_GENCNT: {
        if (!pcapng_write_darwin_legacy_uint32_option(wdh, option_id, optval, err)) {
            /* Write error */
            return false;
        }
        break;
    }
    /* 16-bit options (independent of DPIBs) */
    case OPT_PKT_DARWIN_DROP_LINE:
    case OPT_PKT_DARWIN_TRACE_TAG: {
        if (!pcapng_write_darwin_legacy_uint16_option(wdh, option_id, optval, err)) {
            /* Write error */
            return false;
        }
        break;
    }
    /* String options */
    case OPT_PKT_DARWIN_DROP_FUNC: {
        if (!pcapng_write_darwin_legacy_string_option(wdh, option_id, optval, err)) {
            /* Write error */
            return false;
        }
        break;
    }
    default:
        break;
    }

    /* We return true for unrecognized options */
    return true;
}

static bool
pcapng_process_apple_legacy_block_option(wtapng_block_t *wblock, section_info_t *section_info _U_,
                                         uint16_t option_code, uint16_t option_length, const uint8_t *option_content,
                                         int *err, char **err_info)
{
    /* Handle the DPIB option content. */
    switch (option_code) {
        case(OPT_DPIB_NAME): /* dpip_process_name */
            pcapng_process_string_option(wblock, option_code, option_length, option_content);
            break;
        case(OPT_DPIB_UUID): /* dpib_process_uuid */
            pcapng_process_bytes_option(wblock, option_code, option_length, option_content);
            break;
        default:
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("pcapng: unrecognized option %u in legacy DPIB block", option_code);
            return false;
    }

    return true;
}

static bool
pcapng_read_darwin_legacy_block(wtap* wth, FILE_T fh, uint32_t block_size _U_,
    uint32_t block_content_size,
    section_info_t* section_info,
    wtapng_block_t* wblock,
    int* err, char** err_info)
{
    unsigned                                    opt_cont_buf_len;
    pcapng_legacy_darwin_process_info_block_t   process_info;
    wtapng_ft_specific_mandatory_t              *dpib_mand;
    wtap_block_t                                dpib;

    /* Is this block long enough to be a DPIB? */
    if (block_content_size < sizeof(uint32_t)) {
        /* Too short */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: total block length %u of an DPIB is too small (< %u)",
                                    block_content_size, MIN_DPIB_SIZE);
        return false;
    }

    /* Read the fixed part of the DPIB */
    if (!wtap_read_bytes(fh, &process_info, sizeof process_info, err, err_info)) {
        ws_debug("failed to read packet data");
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: can not read %lu bytes for process info",
                                    sizeof(process_info));
        return false;
    }

    /* Initialize the wblock->block to poitn to a new DPIB block */
    dpib_mand = g_malloc0(sizeof(wtapng_ft_specific_mandatory_t));
    dpib = wtap_block_create( WTAP_BLOCK_FT_SPECIFIC_INFORMATION);
    dpib->mandatory_data = dpib_mand;
    wblock->block = dpib;
    wtap_add_dpib(wth, dpib);

    /* We don't return these to the caller in pcapng_read(). */
    wblock->internal = true;

    /* Populate the mandatory values for the block. */
    if (section_info->byte_swapped) {
        dpib_mand->record_type       = GUINT32_SWAP_LE_BE(process_info.process_id);
    } else {
        dpib_mand->record_type       = process_info.process_id;
    }
    ws_debug("process_id %u", dpib_mand->record_type);

    /* Process options. Note: encountering an unknown option should not discard the block. */
    opt_cont_buf_len = block_content_size - MIN_DPIB_SIZE; /* fixed part */
    pcapng_process_options(fh, wblock, section_info, opt_cont_buf_len,
                                pcapng_process_apple_legacy_block_option,
                                OPT_SECTION_BYTE_ORDER, err, err_info);

    return true;
}

static bool
pcapng_parse_darwin_legacy_uint32(wtap_block_t block, unsigned option_code,
    unsigned option_length, const uint8_t* option_content,
    int* err, char** err_info)
{
    uint32_t uint32;

    if (option_length != 4) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: Darwin option 0x%hx length expected %u, actual %u",
            (uint16_t)option_code, 4, option_length);
        return false;
    }

    memcpy(&uint32, option_content, sizeof(uint32_t));
    wtap_block_add_uint32_option(block, option_code, uint32);

    ws_noisy("Processed integer option 0x%08x (len: %u) == %d", option_code, option_length, *(int32_t*)option_content);
    return true;
}

static bool
pcapng_parse_darwin_legacy_uint16(wtap_block_t block, unsigned option_code,
    unsigned option_length, const uint8_t* option_content,
    int* err, char** err_info)
{
    uint32_t uint32;
    if (option_length != 2) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: Darwin option 0x%hx length expected %u, actual %u",
            (uint16_t)option_code, 2, option_length);
        return false;
    }

    /* NOTE: Internally, the 16-bit options are stored as 32-bit.
     * Because of that, we are using uint32_t as the option length,
     * and not the real option length.
     */
    memcpy(&uint32, option_content, sizeof(uint32_t));
    wtap_block_add_uint32_option(block, option_code, uint32);

    ws_noisy("Processed integer option 0x%08x (len: %u) == %d", option_code, option_length, *(int32_t*)option_content);
    return true;
}

static bool
pcapng_parse_darwin_legacy_dpib_id(wtap_block_t block, bool byte_swapped _U_,
    unsigned option_length, const uint8_t* option_content,
    int* err, char** err_info)
{
    return pcapng_parse_darwin_legacy_uint32(block, OPT_PKT_DARWIN_PIB_ID, option_length, option_content, err, err_info);
}

static bool
pcapng_parse_darwin_legacy_svc_code(wtap_block_t block, bool byte_swapped _U_,
    unsigned option_length, const uint8_t* option_content,
    int* err, char** err_info)
{
    return pcapng_parse_darwin_legacy_uint32(block, OPT_PKT_DARWIN_SVC_CODE, option_length, option_content, err, err_info);
}

static bool
pcapng_parse_darwin_legacy_effective_dpib_id(wtap_block_t block, bool byte_swapped _U_,
    unsigned option_length, const uint8_t* option_content,
    int* err, char** err_info)
{
    return pcapng_parse_darwin_legacy_uint32(block, OPT_PKT_DARWIN_EFFECTIVE_PIB_ID, option_length, option_content, err, err_info);
}

static bool
pcapng_parse_darwin_legacy_md_flags(wtap_block_t block, bool byte_swapped _U_,
    unsigned option_length, const uint8_t* option_content,
    int* err, char** err_info)
{
    return pcapng_parse_darwin_legacy_uint32(block, OPT_PKT_DARWIN_MD_FLAGS, option_length, option_content, err, err_info);
}

static bool
pcapng_parse_darwin_legacy_flow_id(wtap_block_t block, bool byte_swapped _U_,
    unsigned option_length, const uint8_t* option_content,
    int* err, char** err_info)
{
    return pcapng_parse_darwin_legacy_uint32(block, OPT_PKT_DARWIN_FLOW_ID, option_length, option_content, err, err_info);
}

static bool
pcapng_parse_darwin_legacy_drop_reason(wtap_block_t block, bool byte_swapped _U_,
    unsigned option_length, const uint8_t* option_content,
    int* err, char** err_info)
{
    return pcapng_parse_darwin_legacy_uint32(block, OPT_PKT_DARWIN_DROP_REASON, option_length, option_content, err, err_info);
}

static bool
pcapng_parse_darwin_legacy_comp_gencnt(wtap_block_t block, bool byte_swapped _U_,
    unsigned option_length, const uint8_t* option_content,
    int* err, char** err_info)
{
    return pcapng_parse_darwin_legacy_uint32(block, OPT_PKT_DARWIN_COMP_GENCNT, option_length, option_content, err, err_info);
}

static bool
pcapng_parse_darwin_legacy_trace_tag(wtap_block_t block, bool byte_swapped _U_,
    unsigned option_length, const uint8_t* option_content,
    int* err, char** err_info)
{
    return pcapng_parse_darwin_legacy_uint16(block, OPT_PKT_DARWIN_TRACE_TAG, option_length, option_content, err, err_info);
}

static bool
pcapng_parse_darwin_legacy_drop_line(wtap_block_t block, bool byte_swapped _U_,
    unsigned option_length, const uint8_t* option_content,
    int* err, char** err_info)
{
    return pcapng_parse_darwin_legacy_uint16(block, OPT_PKT_DARWIN_DROP_LINE, option_length, option_content, err, err_info);
}

static bool
pcapng_parse_darwin_legacy_drop_func(wtap_block_t block, bool byte_swapped _U_,
    unsigned option_length, const uint8_t* option_content,
    int* err _U_, char** err_info _U_)
{
    wtap_opttype_return_val ret = wtap_block_add_string_option(block, OPT_PKT_DARWIN_DROP_FUNC, (const char*)option_content, option_length);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return false;

    ws_noisy("Processed string option 0x%08x (len: %u)", OPT_PKT_DARWIN_DROP_FUNC, option_length);
    return true;
}

static const wtap_opttype_t dpib_name = {
    "name",
    "Darwin Process Name",
    WTAP_OPTTYPE_STRING,
    0
};
static const wtap_opttype_t dpib_uuid = {
    "name",
    "Darwin Process UUID",
    WTAP_OPTTYPE_BYTES,
    0
};

void register_darwin(void)
{
    static pcapng_block_type_information_t LEGACY = { BLOCK_TYPE_LEGACY_DPIB, pcapng_read_darwin_legacy_block, NULL, NULL, true, NULL };
    static wtap_block_t dpib = NULL;

    if (dpib == NULL) {
        wtap_blocktype_t *blocktype;
        dpib = wtap_block_create( WTAP_BLOCK_FT_SPECIFIC_INFORMATION);
        blocktype = dpib->info;
        g_hash_table_insert(blocktype->options, GUINT_TO_POINTER(OPT_DPIB_NAME),
                        (void *)&dpib_name);
        g_hash_table_insert(blocktype->options, GUINT_TO_POINTER(OPT_DPIB_UUID),
                        (void *)&dpib_uuid);
    }

    register_pcapng_block_type_information(&LEGACY);

    register_pcapng_option_handler(BLOCK_TYPE_EPB, OPT_PKT_DARWIN_PIB_ID, pcapng_parse_darwin_legacy_dpib_id, NULL, NULL);
    register_pcapng_option_handler(BLOCK_TYPE_EPB, OPT_PKT_DARWIN_SVC_CODE, pcapng_parse_darwin_legacy_svc_code, NULL, NULL);
    register_pcapng_option_handler(BLOCK_TYPE_EPB, OPT_PKT_DARWIN_EFFECTIVE_PIB_ID, pcapng_parse_darwin_legacy_effective_dpib_id, NULL, NULL);
    register_pcapng_option_handler(BLOCK_TYPE_EPB, OPT_PKT_DARWIN_MD_FLAGS, pcapng_parse_darwin_legacy_md_flags, NULL, NULL);
    register_pcapng_option_handler(BLOCK_TYPE_EPB, OPT_PKT_DARWIN_FLOW_ID, pcapng_parse_darwin_legacy_flow_id, NULL, NULL);
    register_pcapng_option_handler(BLOCK_TYPE_EPB, OPT_PKT_DARWIN_TRACE_TAG, pcapng_parse_darwin_legacy_trace_tag, NULL, NULL);
    register_pcapng_option_handler(BLOCK_TYPE_EPB, OPT_PKT_DARWIN_DROP_REASON, pcapng_parse_darwin_legacy_drop_reason, NULL, NULL);
    register_pcapng_option_handler(BLOCK_TYPE_EPB, OPT_PKT_DARWIN_DROP_LINE, pcapng_parse_darwin_legacy_drop_line, NULL, NULL);
    register_pcapng_option_handler(BLOCK_TYPE_EPB, OPT_PKT_DARWIN_COMP_GENCNT, pcapng_parse_darwin_legacy_comp_gencnt, NULL, NULL);
    register_pcapng_option_handler(BLOCK_TYPE_EPB, OPT_PKT_DARWIN_DROP_FUNC, pcapng_parse_darwin_legacy_drop_func, NULL, NULL);
}
