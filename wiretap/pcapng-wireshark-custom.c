/* pcapng-wireshark-custom.c
 *
 * Support for Wireshark custom pcapng blocks
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <glib.h>

#include "wtap_module.h"
#include "wtap_opttypes.h"
#include "pcapng.h"
#include "pcapng_module.h"
#include "pcapng-wireshark-custom.h"

#include <wsutil/ws_padding_to.h>
#include <wsutil/ws_roundup.h>

/*
 * Wireshark custom blocks are Custom Blocks with the Wireshark Foundation's
 * PEN, 32622, in which the custom data starts with a Block Entry Type and
 * a Block Entry Length, followed by the entry-specific data, padded to a
 * multiple of 4 octets, and then by the options of the block.  Everything
 * in an entry, including the entry type and length, is little-endian,
 * regardless of the byte order of the section.  See
 * https://wiki.wireshark.org/Development/PcapngCustom for the details.
 *
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +---------------------------------------------------------------+
 *   0 |               Block Type = 0x00000BAD or 0x40000BAD           |
 *     +---------------------------------------------------------------+
 *   4 |                      Block Total Length                       |
 *     +---------------------------------------------------------------+
 *   8 |           Wireshark Private Enterprise Number (PEN)           |
 *     +---------------------------------------------------------------+
 *  12 |                       Block Entry Type                        |
 *     +---------------------------------------------------------------+
 *  16 |                      Block Entry Length                       |
 *     +---------------------------------------------------------------+
 *  20 /                   Block Entry-specific Data                   /
 *     /              variable length, padded to 32 bits               /
 *     +---------------------------------------------------------------+
 *     /                      Options (variable)                       /
 *     +---------------------------------------------------------------+
 *     |                      Block Total Length                       |
 *     +---------------------------------------------------------------+
 *
 * The Process Information entry (type 3) carries the body of a Process
 * Information Block, as proposed for the pcapng specification in
 * https://github.com/IETF-OPSAWG-WG/draft-ietf-opsawg-pcap/pull/209:
 * a 32-bit process ID followed by options describing the process.
 *
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +---------------------------------------------------------------+
 *   0 |                          Process ID                           |
 *     +---------------------------------------------------------------+
 *   4 /                      Options (variable)                       /
 *     +---------------------------------------------------------------+
 *
 * It is read into, and written from, a WTAP_BLOCK_PROCESS_INFORMATION
 * block in the file's table of process information blocks, and is not
 * returned as a record.  Once a block type is assigned for the Process
 * Information Block, the same body can be read from and written to it.
 */

/* Fixed part of the custom data of a Wireshark custom block. */
typedef struct pcapng_wireshark_cb_entry_s {
    uint32_t entry_type;    /* Block Entry Type */
    uint32_t entry_length;  /* Block Entry Length, not including padding */
    /* Block Entry-specific Data and options follow */
} pcapng_wireshark_cb_entry_t;

/* Fixed part of a process information block body. */
typedef struct pcapng_process_info_block_s {
    uint32_t process_id;
    /* ... Options ... */
} pcapng_process_info_block_t;

#define MIN_PIB_SIZE ((uint32_t)sizeof(pcapng_process_info_block_t))

/*
 * Process an option of a process information block body, given the byte
 * order of the body.
 */
static bool
pcapng_process_pib_option(wtapng_block_t *wblock, section_info_t *section_info,
                          pcapng_opt_byte_order_e byte_order,
                          uint16_t option_code, uint16_t option_length,
                          const uint8_t *option_content,
                          int *err, char **err_info)
{
    switch (option_code) {
        case(OPT_PIB_NAME): /* pib_name */
        case(OPT_PIB_PATH): /* pib_path */
        case(OPT_PIB_USER): /* pib_user */
            pcapng_process_string_option(wblock, option_code, option_length,
                                         option_content);
            break;
        case(OPT_PIB_CMDLINE): /* pib_cmdline */
            pcapng_process_bytes_option(wblock, option_code, option_length,
                                        option_content);
            break;
        case(OPT_PIB_PPID): /* pib_ppid */
        case(OPT_PIB_UID): /* pib_uid */
            if (option_length != 4) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = ws_strdup_printf("pcapng: process information block option %u length %u is not 4",
                                             option_code, option_length);
                return false;
            }
            pcapng_process_uint32_option(wblock, section_info, byte_order,
                                         option_code, option_length,
                                         option_content);
            break;
        case(OPT_PIB_UUID): /* pib_uuid */
            if (option_length != 16) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = ws_strdup_printf("pcapng: process information block option %u length %u is not 16",
                                             option_code, option_length);
                return false;
            }
            pcapng_process_bytes_option(wblock, option_code, option_length,
                                        option_content);
            break;
        case(OPT_PIB_STARTTIME): /* pib_starttime */
            if (option_length != 8) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = ws_strdup_printf("pcapng: process information block option %u length %u is not 8",
                                             option_code, option_length);
                return false;
            }
            pcapng_process_uint64_option(wblock, section_info, byte_order,
                                         option_code, option_length,
                                         option_content);
            break;
        default:
            /* Unknown option; ignore it. */
            ws_debug("pcapng: unknown process information block option %u (length %u) ignored",
                     option_code, option_length);
            break;
    }

    return true;
}

/*
 * Process an option of the process information block body in a Wireshark
 * custom block, which is little-endian.
 */
static bool
pcapng_process_wireshark_pib_option(wtapng_block_t *wblock,
                                    section_info_t *section_info,
                                    uint16_t option_code,
                                    uint16_t option_length,
                                    const uint8_t *option_content,
                                    int *err, char **err_info)
{
    return pcapng_process_pib_option(wblock, section_info, OPT_LITTLE_ENDIAN,
                                     option_code, option_length,
                                     option_content, err, err_info);
}

/*
 * Process an option of a Wireshark custom block itself, after the
 * entry-specific data.  Comments and custom options are handled by
 * pcapng_process_options(); nothing else is defined.
 */
static bool
pcapng_process_wireshark_cb_option(wtapng_block_t *wblock _U_,
                                   section_info_t *section_info _U_,
                                   uint16_t option_code,
                                   uint16_t option_length,
                                   const uint8_t *option_content _U_,
                                   int *err _U_, char **err_info _U_)
{
    /* Unknown option; ignore it. */
    ws_debug("pcapng: unknown Wireshark custom block option %u (length %u) ignored",
             option_code, option_length);
    return true;
}

/*
 * Read the Process Information entry of a Wireshark custom block, and
 * any options of the custom block after it, into a new process
 * information block, which replaces the custom block in wblock->block
 * and is processed internally.
 */
static bool
pcapng_read_process_info_entry(FILE_T fh, section_info_t *section_info,
                               wtapng_block_t *wblock,
                               uint32_t entry_length, uint32_t options_length,
                               int *err, char **err_info)
{
    pcapng_process_info_block_t pib;
    wtapng_process_info_mandatory_t *pib_mand;
    uint32_t pad_len;

    if (entry_length < MIN_PIB_SIZE) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: entry length %u of a process information block is too small (< %u)",
                                     entry_length, MIN_PIB_SIZE);
        return false;
    }

    /* Read the fixed part of the block body. */
    if (!wtap_read_bytes(fh, &pib, sizeof pib, err, err_info)) {
        ws_debug("failed to read process ID");
        return false;
    }

    /*
     * Replace the custom block with a process information block.
     * pcapng_process_cb() adds it to the file's table of process
     * information blocks once the block has been read; if that fails,
     * pcapng_read() frees it.
     */
    wtap_block_unref(wblock->block);
    wblock->block = wtap_block_create(WTAP_BLOCK_PROCESS_INFORMATION);
    wblock->internal = true;

    pib_mand = (wtapng_process_info_mandatory_t *)wtap_block_get_mandatory_data(wblock->block);
    pib_mand->process_id = GUINT32_FROM_LE(pib.process_id);
    pib_mand->block_type = BLOCK_TYPE_CB_COPY;
    ws_debug("process ID %u", pib_mand->process_id);

    /* The options of the block body, which are little-endian. */
    if (!pcapng_process_options(fh, wblock, section_info,
                                entry_length - MIN_PIB_SIZE,
                                pcapng_process_wireshark_pib_option,
                                OPT_LITTLE_ENDIAN, err, err_info))
        return false;

    /* Skip the padding of the entry-specific data. */
    pad_len = WS_PADDING_TO_4(entry_length);
    if (pad_len != 0 && !wtap_read_bytes(fh, NULL, pad_len, err, err_info))
        return false;

    /*
     * The options of the custom block itself, if any, which are in the
     * byte order of the section.
     */
    if (options_length != 0 &&
        !pcapng_process_options(fh, wblock, section_info, options_length,
                                pcapng_process_wireshark_cb_option,
                                OPT_SECTION_BYTE_ORDER, err, err_info))
        return false;

    return true;
}

static bool
pcapng_read_wireshark_custom_block(FILE_T fh, section_info_t *section_info,
                                   wtapng_block_t *wblock,
                                   int *err, char **err_info)
{
    uint32_t payload_length = wblock->rec->rec_header.custom_block_header.length;
    pcapng_wireshark_cb_entry_t entry;
    uint32_t entry_type, entry_length, entry_padded_length;

    if (payload_length < sizeof entry) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: payload length %u of a Wireshark custom block is too small (< %zu)",
                                     payload_length, sizeof entry);
        return false;
    }

    /* Read the entry type and length. */
    if (!wtap_read_bytes(fh, &entry, sizeof entry, err, err_info)) {
        ws_debug("failed to read entry type and length");
        return false;
    }
    entry_type = GUINT32_FROM_LE(entry.entry_type);
    entry_length = GUINT32_FROM_LE(entry.entry_length);
    entry_padded_length = WS_ROUNDUP_4(entry_length);
    if (entry_padded_length < entry_length ||
        entry_padded_length > payload_length - sizeof entry) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: entry length %u of a Wireshark custom block is larger than the payload length %u",
                                     entry_length, payload_length);
        return false;
    }
    ws_debug("Wireshark custom block entry type %u, entry length %u",
             entry_type, entry_length);

    switch (entry_type) {

    case WIRESHARK_CB_ENTRY_PROCESS_INFORMATION:
        return pcapng_read_process_info_entry(fh, section_info, wblock,
                                              entry_length,
                                              payload_length - (uint32_t)sizeof entry - entry_padded_length,
                                              err, err_info);

    default:
        /*
         * An entry type we don't know about, for example one from a
         * newer version; keep the whole payload as an opaque custom
         * block record, so that it can be copied to a new file as is.
         */
        ws_buffer_append(&wblock->rec->data, (const uint8_t *)&entry,
                         sizeof entry);
        return wtap_read_bytes_buffer(fh, &wblock->rec->data,
                                      payload_length - (uint32_t)sizeof entry,
                                      err, err_info);
    }
}

static uint32_t
compute_pib_option_size(wtap_block_t block _U_, unsigned option_id,
                        wtap_opttype_e option_type _U_, wtap_optval_t *optval)
{
    uint32_t size;

    switch (option_id) {
    case OPT_PIB_NAME:
    case OPT_PIB_PATH:
    case OPT_PIB_USER:
        size = (uint32_t)strlen(optval->stringval);
        break;
    case OPT_PIB_CMDLINE:
    case OPT_PIB_UUID:
        size = (uint32_t)g_bytes_get_size(optval->byteval);
        break;
    case OPT_PIB_PPID:
    case OPT_PIB_UID:
        size = 4;
        break;
    case OPT_PIB_STARTTIME:
        size = 8;
        break;
    default:
        /* Unknown options - don't write them. */
        size = 0;
        break;
    }

    /* Don't write it if it's too big to fit. */
    if (size > UINT16_MAX)
        size = 0;
    return size;
}

/*
 * Write an option of a process information block body in a Wireshark
 * custom block, which is little-endian.
 */
static bool
write_pib_option(wtap_dumper *wdh, wtap_block_t block _U_, unsigned option_id,
                 wtap_opttype_e option_type _U_, wtap_optval_t *optval,
                 int *err, char **err_info _U_)
{
    struct pcapng_option_header option_hdr;
    const void *data;
    size_t size;
    uint32_t uint32;
    uint64_t uint64;

    switch (option_id) {
    case OPT_PIB_NAME:
    case OPT_PIB_PATH:
    case OPT_PIB_USER:
        data = optval->stringval;
        size = strlen(optval->stringval);
        break;
    case OPT_PIB_CMDLINE:
    case OPT_PIB_UUID:
        data = g_bytes_get_data(optval->byteval, &size);
        break;
    case OPT_PIB_PPID:
    case OPT_PIB_UID:
        uint32 = GUINT32_TO_LE(optval->uint32val);
        data = &uint32;
        size = sizeof uint32;
        break;
    case OPT_PIB_STARTTIME:
        uint64 = GUINT64_TO_LE(optval->uint64val);
        data = &uint64;
        size = sizeof uint64;
        break;
    default:
        /* Unknown options - don't write them. */
        return true;
    }

    /*
     * Don't write it if it's empty or too big to fit; that's
     * consistent with compute_pib_option_size().
     */
    if (size == 0 || size > UINT16_MAX)
        return true;

    option_hdr.type         = GUINT16_TO_LE((uint16_t)option_id);
    option_hdr.value_length = GUINT16_TO_LE((uint16_t)size);
    if (!wtap_dump_file_write(wdh, &option_hdr, sizeof option_hdr, err))
        return false;
    if (!wtap_dump_file_write(wdh, data, size, err))
        return false;
    return pcapng_write_padding(wdh, WS_PADDING_TO_4(size), err);
}

bool
pcapng_write_wireshark_process_info_block(wtap_dumper *wdh, wtap_block_t pib,
                                          int *err, char **err_info)
{
    wtapng_process_info_mandatory_t *pib_mand;
    uint32_t options_size;
    uint32_t entry_length;
    uint32_t block_content_length;
    uint32_t pen;
    pcapng_wireshark_cb_entry_t entry;
    pcapng_process_info_block_t pib_body;

    pib_mand = (wtapng_process_info_mandatory_t *)wtap_block_get_mandatory_data(pib);

    /*
     * pcapng_compute_options_size() takes care of the 4 bytes for the
     * end-of-options, and of the padding of each option, so the entry
     * length is a multiple of 4 and needs no padding.
     */
    options_size = pcapng_compute_options_size(pib, compute_pib_option_size);
    entry_length = MIN_PIB_SIZE + options_size;
    block_content_length = (uint32_t)sizeof pen + (uint32_t)sizeof entry + entry_length;
    ws_debug("writing process information block for process %u, %u bytes",
             pib_mand->process_id, block_content_length);

    /* write block header */
    if (!pcapng_write_block_header(wdh, BLOCK_TYPE_CB_COPY,
                                   block_content_length, err))
        return false;

    /* write the PEN, in the byte order of the section */
    pen = PEN_WIRESHARK;
    if (!wtap_dump_file_write(wdh, &pen, sizeof pen, err))
        return false;

    /* write the entry type and length; these, and the rest of the entry, are little-endian */
    entry.entry_type = GUINT32_TO_LE(WIRESHARK_CB_ENTRY_PROCESS_INFORMATION);
    entry.entry_length = GUINT32_TO_LE(entry_length);
    if (!wtap_dump_file_write(wdh, &entry, sizeof entry, err))
        return false;

    /* write the process ID */
    pib_body.process_id = GUINT32_TO_LE(pib_mand->process_id);
    if (!wtap_dump_file_write(wdh, &pib_body, sizeof pib_body, err))
        return false;

    /* write options, if we have any */
    if (options_size != 0) {
        if (!pcapng_write_options(wdh, OPT_LITTLE_ENDIAN, pib,
                                  write_pib_option, err, err_info))
            return false;
    }

    /* write block footer */
    return pcapng_write_block_footer(wdh, block_content_length, err);
}

void register_wireshark_custom(void)
{
    /*
     * Custom binary options and custom block records with our PEN that
     * we don't handle are kept as they are, so there's no custom option
     * processor and no custom block writer.
     */
    static const pcapng_custom_block_enterprise_handler_t enterprise_wireshark =
    {
        pcapng_read_wireshark_custom_block,
        NULL,
        NULL
    };

    register_pcapng_custom_block_enterprise_handler(PEN_WIRESHARK, &enterprise_wireshark);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
