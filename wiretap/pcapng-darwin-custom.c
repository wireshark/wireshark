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

#include "wtap_module.h"
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

/*
 * DPIB option codes.  A DPIB is read into, and written from, a
 * WTAP_BLOCK_PROCESS_INFORMATION block, so these are mapped to and
 * from the corresponding OPT_PIB_ option codes.
 */
#define OPT_DPIB_NAME        2   /**< Process name: UTF-8 string, limited to 15 characters */
#define OPT_DPIB_UUID        4   /**< Process UUID: 16 bytes */


static uint32_t
compute_dpib_option_size(wtap_block_t block _U_, unsigned option_code,  wtap_opttype_e option_type _U_, wtap_optval_t* optval)
{
    uint32_t size = 0;

    switch (option_code) {
    case(OPT_PIB_NAME): /* dpib_process_name */
        size = (uint32_t)strlen(optval->stringval);
        /* Don't write it if it's too big. */
        if (size > UINT16_MAX)
            size = 0;
        break;
    case(OPT_PIB_UUID): /* dpib_process_uuid */
        size = (uint32_t)g_bytes_get_size(optval->byteval);
        /* Don't write it if it's an invalid size. */
        if (size != 16)
            size = 0;
        break;
    default:
        /* Not something a DPIB can hold; don't write it. */
        break;
    }
    return size;
}

static bool
write_dpib_option(wtap_dumper *wdh, wtap_block_t block _U_, unsigned option_code, wtap_opttype_e option_type _U_, wtap_optval_t* optval, int *err, char **err_info _U_)
{
    struct pcapng_option_header option_hdr;
    const void                 *data;
    size_t                      size;

    switch (option_code) {
    case OPT_PIB_NAME:
        data = optval->stringval;
        size = strlen(optval->stringval);
        if (size == 0 || size > UINT16_MAX) {
            /* Not written; compute_dpib_option_size() didn't count it. */
            return true;
        }
        option_hdr.type = OPT_DPIB_NAME;
        break;
    case OPT_PIB_UUID:
        data = g_bytes_get_data(optval->byteval, &size);
        if (size != 16) {
            /* Not written; compute_dpib_option_size() didn't count it. */
            return true;
        }
        option_hdr.type = OPT_DPIB_UUID;
        break;
    default:
        /* Not something a DPIB can hold; don't write it. */
        return true;
    }

    option_hdr.value_length = (uint16_t)size;
    if (!wtap_dump_file_write(wdh, &option_hdr, sizeof option_hdr, err))
        return false;
    if (!wtap_dump_file_write(wdh, data, size, err))
        return false;
    return pcapng_write_padding(wdh, WS_PADDING_TO_4(size), err);
}

bool
pcapng_write_legacy_darwin_process_info_block(wtap_dumper *wdh, wtap_block_t pib,
                                              int *err, char **err_info)
{
    wtapng_process_info_mandatory_t           *pib_mand;
    pcapng_legacy_darwin_process_info_block_t  dpib;
    uint32_t                                   options_size;
    uint32_t                                   block_content_length;

    pib_mand = (wtapng_process_info_mandatory_t *)wtap_block_get_mandatory_data(pib);

    /* pcapng_compute_options_size takes care of the 4 bytes for the end-of-options. */
    options_size = pcapng_compute_options_size(pib, compute_dpib_option_size);
    block_content_length = MIN_DPIB_SIZE + options_size;

    /* write block header */
    if (!pcapng_write_block_header(wdh, BLOCK_TYPE_LEGACY_DPIB,
                                   block_content_length, err))
        return false;

    /* write the process id */
    dpib.process_id = pib_mand->process_id;
    if (!wtap_dump_file_write(wdh, &dpib, sizeof dpib, err))
        return false;

    /* write options, if we have any */
    if (options_size != 0) {
        if (!pcapng_write_options(wdh, OPT_SECTION_BYTE_ORDER, pib,
                                  write_dpib_option, err, err_info))
            return false;
    }

    /* write block footer */
    return pcapng_write_block_footer(wdh, block_content_length, err);
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

    return pcapng_write_padding(wdh, 2, err);
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
        {
            /* 65535 is too large to be written */
            uint32_t size = (uint32_t)strlen(optval->stringval);
            return size <= 65535 ? size : 0;
            break;
        }
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
        if ((wdh->pibs_growing == NULL) || (wdh->pibs_growing->len <= (uint32_t)optval->int32val)) {
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
                                         int *err _U_, char **err_info _U_)
{
    /* Handle the DPIB option content, as the corresponding PIB option. */
    switch (option_code) {
        case(OPT_DPIB_NAME): /* dpib_process_name */
            pcapng_process_string_option(wblock, OPT_PIB_NAME, option_length, option_content);
            break;
        case(OPT_DPIB_UUID): /* dpib_process_uuid */
            pcapng_process_bytes_option(wblock, OPT_PIB_UUID, option_length, option_content);
            break;
        default:
            /* Unknown option; ignore it. */
            ws_debug("pcapng: unrecognized option %u in legacy DPIB block", option_code);
            break;
    }

    return true;
}

static bool
pcapng_read_darwin_legacy_block(wtap* wth _U_, FILE_T fh, uint32_t block_size _U_,
    uint32_t block_content_size,
    section_info_t* section_info,
    wtapng_block_t* wblock,
    int* err, char** err_info)
{
    unsigned                                    opt_cont_buf_len;
    pcapng_legacy_darwin_process_info_block_t   process_info;
    wtapng_process_info_mandatory_t             *pib_mand;

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
        *err_info = ws_strdup_printf("pcapng: can not read %zu bytes for process info",
                                    sizeof(process_info));
        return false;
    }

    /*
     * Initialize the wblock->block to point to a new process information
     * block; pcapng_process_darwin_legacy_block() adds it to the file's
     * table of process information blocks once the block has been read.
     */
    wblock->block = wtap_block_create(WTAP_BLOCK_PROCESS_INFORMATION);

    /* We don't return these to the caller in pcapng_read(). */
    wblock->internal = true;

    /* Populate the mandatory values for the block. */
    pib_mand = (wtapng_process_info_mandatory_t *)wtap_block_get_mandatory_data(wblock->block);
    if (section_info->byte_swapped) {
        pib_mand->process_id = GUINT32_SWAP_LE_BE(process_info.process_id);
    } else {
        pib_mand->process_id = process_info.process_id;
    }
    pib_mand->block_type = BLOCK_TYPE_LEGACY_DPIB;
    ws_debug("process_id %u", pib_mand->process_id);

    /* Process options. Note: unknown options are ignored, so they don't discard the block. */
    opt_cont_buf_len = block_content_size - MIN_DPIB_SIZE; /* fixed part */
    if (!pcapng_process_options(fh, wblock, section_info, opt_cont_buf_len,
                                pcapng_process_apple_legacy_block_option,
                                OPT_SECTION_BYTE_ORDER, err, err_info)) {
        return false;
    }

    return true;
}

/* Process a DPIB that we have just read. */
static bool
pcapng_process_darwin_legacy_block(wtap *wth, section_info_t *section_info _U_,
                                   wtapng_block_t *wblock)
{
    /* Store it such that it can be looked up and saved by the dumper. */
    wtap_add_pib(wth, wblock->block);

    /* Do not free wblock->block, it is consumed above */

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

void register_darwin(void)
{
    static pcapng_block_type_information_t LEGACY = { BLOCK_TYPE_LEGACY_DPIB, pcapng_read_darwin_legacy_block, pcapng_process_darwin_legacy_block, NULL, true, NULL };

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
