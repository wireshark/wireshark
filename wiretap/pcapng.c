/* pcapng.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * File format support for pcap-ng file format
 * Copyright (c) 2007 by Ulf Lamping <ulf.lamping@web.de>
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

/* File format specification:
 *   https://github.com/pcapng/pcapng
 * Related Wiki page:
 *   https://wiki.wireshark.org/Development/PcapNg
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>


#include "wtap-int.h"
#include "file_wrappers.h"
#include "pcap-common.h"
#include "pcap-encap.h"
#include "pcapng.h"
#include "pcapng_module.h"

#if 0
#define pcapng_debug(...) g_warning(__VA_ARGS__)
#else
#define pcapng_debug(...)
#endif

static gboolean
pcapng_read(wtap *wth, int *err, gchar **err_info,
            gint64 *data_offset);
static gboolean
pcapng_seek_read(wtap *wth, gint64 seek_off,
                 struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info);
static void
pcapng_close(wtap *wth);


/* pcapng: common block header file encoding for every block type */
typedef struct pcapng_block_header_s {
    guint32 block_type;
    guint32 block_total_length;
    /* x bytes block_body */
    /* guint32 block_total_length */
} pcapng_block_header_t;

/*
 * Minimum block size = size of block header + size of block trailer.
 */
#define MIN_BLOCK_SIZE  ((guint32)(sizeof(pcapng_block_header_t) + sizeof(guint32)))

/*
 * In order to keep from trying to allocate large chunks of memory,
 * which could either fail or, even if it succeeds, chew up so much
 * address space or memory+backing store as not to leave room for
 * anything else, we impose an upper limit on the size of blocks
 * we're willing to handle.
 *
 * For now, we pick an arbitrary limit of 16MB (OK, fine, 16MiB, but
 * don't try saying that on Wikipedia :-) :-) :-)).
 */
#define MAX_BLOCK_SIZE  (16*1024*1024)

/* pcapng: section header block file encoding */
typedef struct pcapng_section_header_block_s {
    /* pcapng_block_header_t */
    guint32 magic;
    guint16 version_major;
    guint16 version_minor;
    guint64 section_length; /* might be -1 for unknown */
    /* ... Options ... */
} pcapng_section_header_block_t;

/*
 * Minimum SHB size = minimum block size + size of fixed length portion of SHB.
 */
#define MIN_SHB_SIZE    ((guint32)(MIN_BLOCK_SIZE + sizeof(pcapng_section_header_block_t)))

/* pcapng: interface description block file encoding */
typedef struct pcapng_interface_description_block_s {
    guint16 linktype;
    guint16 reserved;
    guint32 snaplen;
    /* ... Options ... */
} pcapng_interface_description_block_t;

/*
 * Minimum IDB size = minimum block size + size of fixed length portion of IDB.
 */
#define MIN_IDB_SIZE    ((guint32)(MIN_BLOCK_SIZE + sizeof(pcapng_interface_description_block_t)))

/* pcapng: packet block file encoding (obsolete) */
typedef struct pcapng_packet_block_s {
    guint16 interface_id;
    guint16 drops_count;
    guint32 timestamp_high;
    guint32 timestamp_low;
    guint32 captured_len;
    guint32 packet_len;
    /* ... Packet Data ... */
    /* ... Padding ... */
    /* ... Options ... */
} pcapng_packet_block_t;

/*
 * Minimum PB size = minimum block size + size of fixed length portion of PB.
 */
#define MIN_PB_SIZE     ((guint32)(MIN_BLOCK_SIZE + sizeof(pcapng_packet_block_t)))

/* pcapng: enhanced packet block file encoding */
typedef struct pcapng_enhanced_packet_block_s {
    guint32 interface_id;
    guint32 timestamp_high;
    guint32 timestamp_low;
    guint32 captured_len;
    guint32 packet_len;
    /* ... Packet Data ... */
    /* ... Padding ... */
    /* ... Options ... */
} pcapng_enhanced_packet_block_t;

/*
 * Minimum EPB size = minimum block size + size of fixed length portion of EPB.
 */
#define MIN_EPB_SIZE    ((guint32)(MIN_BLOCK_SIZE + sizeof(pcapng_enhanced_packet_block_t)))

/* pcapng: simple packet block file encoding */
typedef struct pcapng_simple_packet_block_s {
    guint32 packet_len;
    /* ... Packet Data ... */
    /* ... Padding ... */
} pcapng_simple_packet_block_t;

/*
 * Minimum SPB size = minimum block size + size of fixed length portion of SPB.
 */
#define MIN_SPB_SIZE    ((guint32)(MIN_BLOCK_SIZE + sizeof(pcapng_simple_packet_block_t)))

/* pcapng: name resolution block file encoding */
typedef struct pcapng_name_resolution_block_s {
    guint16 record_type;
    guint16 record_len;
    /* ... Record ... */
} pcapng_name_resolution_block_t;

/*
 * Minimum NRB size = minimum block size + size of smallest NRB record
 * (there must at least be an "end of records" record).
 */
#define MIN_NRB_SIZE    ((guint32)(MIN_BLOCK_SIZE + sizeof(pcapng_name_resolution_block_t)))

/* pcapng: interface statistics block file encoding */
typedef struct pcapng_interface_statistics_block_s {
    guint32 interface_id;
    guint32 timestamp_high;
    guint32 timestamp_low;
    /* ... Options ... */
} pcapng_interface_statistics_block_t;

/*
 * Minimum ISB size = minimum block size + size of fixed length portion of ISB.
 */
#define MIN_ISB_SIZE    ((guint32)(MIN_BLOCK_SIZE + sizeof(pcapng_interface_statistics_block_t)))

/*
 * Minimum Sysdig size = minimum block size + packed size of sysdig_event_phdr.
 */
#define MIN_SYSDIG_EVENT_SIZE    ((guint32)(MIN_BLOCK_SIZE)) + ((16 + 64 + 64 + 32 + 16) / 8)

/* pcapng: common option header file encoding for every option type */
typedef struct pcapng_option_header_s {
    guint16 option_code;
    guint16 option_length;
    /* ... x bytes Option Body ... */
    /* ... Padding ... */
} pcapng_option_header_t;

struct option {
    guint16 type;
    guint16 value_length;
};

/* Option codes: 16-bit field */
#define OPT_EPB_FLAGS        0x0002
#define OPT_EPB_HASH         0x0003
#define OPT_EPB_DROPCOUNT    0x0004

#define OPT_NRB_DNSNAME      0x0002
#define OPT_NRB_DNSV4ADDR    0x0003
#define OPT_NRB_DNSV6ADDR    0x0004

/* MSBit of option code means "local type" */
#define OPT_LOCAL_FLAG       0x8000

/* Note: many of the defined structures for block data are defined in wtap.h */

/* Packet data - used for both Enhanced Packet Block and the obsolete Packet Block data */
typedef struct wtapng_packet_s {
    /* mandatory */
    guint32                         ts_high;        /* seconds since 1.1.1970 */
    guint32                         ts_low;         /* fraction of seconds, depends on if_tsresol */
    guint32                         cap_len;        /* data length in the file */
    guint32                         packet_len;     /* data length on the wire */
    guint32                         interface_id;   /* identifier of the interface. */
    guint16                         drops_count;    /* drops count, only valid for packet block */
    /* 0xffff if information no available */
    /* pack_hash */
    /* XXX - put the packet data / pseudo_header here as well? */
} wtapng_packet_t;

/* Simple Packet data */
typedef struct wtapng_simple_packet_s {
    /* mandatory */
    guint32                         cap_len;        /* data length in the file */
    guint32                         packet_len;     /* data length on the wire */
    /* XXX - put the packet data / pseudo_header here as well? */
} wtapng_simple_packet_t;

/* Block data to be passed between functions during reading */
typedef struct wtapng_block_s {
    guint32                     type;           /* block_type as defined by pcapng */
    wtap_optionblock_t          block;

    /*
     * XXX - currently don't know how to handle these!
     *
     * For one thing, when we're reading a block, they must be
     * writable, i.e. not const, so that we can read into them,
     * but, when we're writing a block, they can be const, and,
     * in fact, they sometimes point to const values.
     */
    struct wtap_pkthdr *packet_header;
    Buffer *frame_buffer;
} wtapng_block_t;

/* Interface data in private struct */
typedef struct interface_info_s {
    int wtap_encap;
    guint32 snap_len;
    guint64 time_units_per_second;
    int tsprecision;
} interface_info_t;

typedef struct {
    gboolean shb_read;           /**< Set when first SHB read, second read will fail */
    gboolean byte_swapped;
    guint16 version_major;
    guint16 version_minor;
    GArray *interfaces;          /**< Interfaces found in the capture file. */
    gint8 if_fcslen;
    wtap_new_ipv4_callback_t add_new_ipv4;
    wtap_new_ipv6_callback_t add_new_ipv6;
} pcapng_t;

#ifdef HAVE_PLUGINS
/*
 * Table for plugins to handle particular block types.
 *
 * A handler has a "read" routine and a "write" routine.
 *
 * A "read" routine returns a block as a libwiretap record, filling
 * in the wtap_pkthdr structure with the appropriate record type and
 * other information, and filling in the supplied Buffer with
 * data for which there's no place in the wtap_pkthdr structure.
 *
 * A "write" routine takes a libwiretap record and Buffer and writes
 * out a block.
 */
typedef struct {
    block_reader reader;
    block_writer writer;
} block_handler;

static GHashTable *block_handlers;

void
register_pcapng_block_type_handler(guint block_type, block_reader reader,
                                   block_writer writer)
{
    block_handler *handler;

    if (block_handlers == NULL) {
        /*
         * Create the table of block handlers.
         *
         * XXX - there's no "g_uint_hash()" or "g_uint_equal()",
         * so we use "g_direct_hash()" and "g_direct_equal()".
         */
        block_handlers = g_hash_table_new_full(g_direct_hash,
                                               g_direct_equal,
                                               NULL, g_free);
    }
    handler = g_new(block_handler, 1);
    handler->reader = reader;
    handler->writer = writer;
    g_hash_table_insert(block_handlers, GUINT_TO_POINTER(block_type),
                              handler);
}

/*
 * Tables for plugins to handle particular options for particular block
 * types.
 *
 * An option has a handler routine, which is passed an indication of
 * whether this section of the file is byte-swapped, the length of the
 * option, the data of the option, a pointer to an error code, and a
 * pointer to a pointer variable for an error string.
 *
 * It checks whether the length and option are valid, and, if they aren't,
 * returns FALSE, setting the error code to the appropriate error (normally
 * WTAP_ERR_BAD_FILE) and the error string to an appropriate string
 * indicating the problem.
 *
 * Otherwise, if this section of the file is byte-swapped, it byte-swaps
 * multi-byte numerical values, so that it's in the host byte order.
 */

/*
 * Block types indices in the table of tables of option handlers.
 *
 * Block types are not guaranteed to be sequential, so we map the
 * block types we support to a sequential set.  Furthermore, all
 * packet block types have the same set of options.
 */
#define BT_INDEX_SHB        0
#define BT_INDEX_IDB        1
#define BT_INDEX_PBS        2  /* all packet blocks */
#define BT_INDEX_NRB        3
#define BT_INDEX_ISB        4
#define BT_INDEX_EVT        5

#define NUM_BT_INDICES      6

typedef struct {
    option_handler_fn hfunc;
} option_handler;

static GHashTable *option_handlers[NUM_BT_INDICES];

static gboolean
get_block_type_index(guint block_type, guint *bt_index)
{
    g_assert(bt_index);

    switch (block_type) {

        case BLOCK_TYPE_SHB:
            *bt_index = BT_INDEX_SHB;
            break;

        case BLOCK_TYPE_IDB:
            *bt_index = BT_INDEX_IDB;
            break;

        case BLOCK_TYPE_PB:
        case BLOCK_TYPE_EPB:
        case BLOCK_TYPE_SPB:
            *bt_index = BT_INDEX_PBS;
            break;

        case BLOCK_TYPE_NRB:
            *bt_index = BT_INDEX_NRB;
            break;

        case BLOCK_TYPE_ISB:
            *bt_index = BT_INDEX_ISB;
            break;

        case BLOCK_TYPE_SYSDIG_EVENT:
        /* case BLOCK_TYPE_SYSDIG_EVF: */
            *bt_index = BT_INDEX_EVT;
            break;

        default:
            /*
             * This is a block type we don't process; either we ignore it,
             * in which case the options don't get processed, or there's
             * a plugin routine to handle it, in which case that routine
             * will do the option processing itself.
             *
             * XXX - report an error?
             */
            return FALSE;
    }

    return TRUE;
}

void
register_pcapng_option_handler(guint block_type, guint option_code,
                               option_handler_fn hfunc)
{
    guint bt_index;
    option_handler *handler;

    if (!get_block_type_index(block_type, &bt_index))
        return;

    if (option_handlers[bt_index] == NULL) {
        /*
         * Create the table of option handlers for this block type.
         *
         * XXX - there's no "g_uint_hash()" or "g_uint_equal()",
         * so we use "g_direct_hash()" and "g_direct_equal()".
         */
        option_handlers[bt_index] = g_hash_table_new_full(g_direct_hash,
                                                          g_direct_equal,
                                                          NULL, g_free);
    }
    handler = g_new(option_handler, 1);
    handler->hfunc = hfunc;
    g_hash_table_insert(option_handlers[bt_index],
                              GUINT_TO_POINTER(option_code), handler);
}
#endif /* HAVE_PLUGINS */

static int
pcapng_read_option(FILE_T fh, pcapng_t *pn, pcapng_option_header_t *oh,
                   guint8 *content, guint len, guint to_read,
                   int *err, gchar **err_info, gchar* block_name)
{
    int     block_read;

    /* sanity check: don't run past the end of the block */
    if (to_read < sizeof (*oh)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("pcapng_read_option: Not enough data to read header of the %s block",
                                    block_name);
        return -1;
    }

    /* read option header */
    if (!wtap_read_bytes(fh, oh, sizeof (*oh), err, err_info)) {
        pcapng_debug("pcapng_read_option: failed to read option");
        return -1;
    }
    block_read = sizeof (*oh);
    if (pn->byte_swapped) {
        oh->option_code      = GUINT16_SWAP_LE_BE(oh->option_code);
        oh->option_length    = GUINT16_SWAP_LE_BE(oh->option_length);
    }

    /* sanity check: don't run past the end of the block */
    if (to_read < sizeof (*oh) + oh->option_length) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("pcapng_read_option: Not enough data to handle option length (%d) of the %s block",
                                    oh->option_length, block_name);
        return -1;
    }

    /* sanity check: option length */
    if (len < oh->option_length) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("pcapng_read_option: option length (%d) to long for %s block",
                                    len, block_name);
        return -1;
    }

    /* read option content */
    if (!wtap_read_bytes(fh, content, oh->option_length, err, err_info)) {
        pcapng_debug("pcapng_read_option: failed to read content of option %u", oh->option_code);
        return -1;
    }
    block_read += oh->option_length;

    /* jump over potential padding bytes at end of option */
    if ( (oh->option_length % 4) != 0) {
        if (!file_skip(fh, 4 - (oh->option_length % 4), err))
            return -1;
        block_read += 4 - (oh->option_length % 4);
    }

    return block_read;
}

typedef enum {
    PCAPNG_BLOCK_OK,
    PCAPNG_BLOCK_NOT_SHB,
    PCAPNG_BLOCK_ERROR
} block_return_val;

static block_return_val
pcapng_read_section_header_block(FILE_T fh, pcapng_block_header_t *bh,
                                 pcapng_t *pn, wtapng_block_t *wblock,
                                 int *err, gchar **err_info)
{
    int     bytes_read;
    gboolean byte_swapped;
    guint16 version_major;
    guint16 version_minor;
    guint to_read, opt_cont_buf_len;
    pcapng_section_header_block_t shb;
    pcapng_option_header_t oh;
    wtapng_mandatory_section_t* section_data;
    gchar* tmp_content;

    guint8 *option_content = NULL; /* Allocate as large as the options block */

    /* read fixed-length part of the block */
    if (!wtap_read_bytes(fh, &shb, sizeof shb, err, err_info)) {
        if (*err == WTAP_ERR_SHORT_READ) {
            /*
             * This block is too short to be an SHB.
             *
             * If we're reading this as part of an open,
             * the file is too short to be a pcap-ng file.
             *
             * If we're not, we treat PCAPNG_BLOCK_NOT_SHB and
             * PCAPNG_BLOCK_ERROR the same, so we can just return
             * PCAPNG_BLOCK_NOT_SHB in both cases.
             */
            return PCAPNG_BLOCK_NOT_SHB;
        }
        return PCAPNG_BLOCK_ERROR;
    }

    /* is the magic number one we expect? */
    switch (shb.magic) {
        case(0x1A2B3C4D):
            /* this seems pcapng with correct byte order */
            byte_swapped                = FALSE;
            version_major               = shb.version_major;
            version_minor               = shb.version_minor;

            pcapng_debug("pcapng_read_section_header_block: SHB (our byte order) V%u.%u, len %u",
                          version_major, version_minor, bh->block_total_length);
            break;
        case(0x4D3C2B1A):
            /* this seems pcapng with swapped byte order */
            byte_swapped                = TRUE;
            version_major               = GUINT16_SWAP_LE_BE(shb.version_major);
            version_minor               = GUINT16_SWAP_LE_BE(shb.version_minor);

            /* tweak the block length to meet current swapping that we know now */
            bh->block_total_length  = GUINT32_SWAP_LE_BE(bh->block_total_length);

            pcapng_debug("pcapng_read_section_header_block: SHB (byte-swapped) V%u.%u, len %u",
                          version_major, version_minor, bh->block_total_length);
            break;
        default:
            /* Not a "pcapng" magic number we know about. */
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup_printf("pcapng_read_section_header_block: unknown byte-order magic number 0x%08x", shb.magic);

            /*
             * See above comment about PCAPNG_BLOCK_NOT_SHB.
             */
            return PCAPNG_BLOCK_NOT_SHB;
    }

    /*
     * Is this block long enough to be an SHB?
     */
    if (bh->block_total_length < MIN_SHB_SIZE) {
        /*
         * No.
         */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("pcapng_read_section_header_block: total block length %u of an SHB is less than the minimum SHB size %u",
                                    bh->block_total_length, MIN_SHB_SIZE);
        return PCAPNG_BLOCK_ERROR;
    }

    /* OK, at this point we assume it's a pcap-ng file.

       Don't try to allocate memory for a huge number of options, as
       that might fail and, even if it succeeds, it might not leave
       any address space or memory+backing store for anything else.

       We do that by imposing a maximum block size of MAX_BLOCK_SIZE.
       We check for this *after* checking the SHB for its byte
       order magic number, so that non-pcap-ng files are less
       likely to be treated as bad pcap-ng files. */
    if (bh->block_total_length > MAX_BLOCK_SIZE) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("pcapng_read_section_header_block: total block length %u is too large (> %u)",
                                    bh->block_total_length, MAX_BLOCK_SIZE);
        return PCAPNG_BLOCK_ERROR;
    }

    /* We currently only suport one SHB */
    if (pn->shb_read == TRUE) {
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = g_strdup_printf("pcapng_read_section_header_block: multiple section header blocks not supported");
        return PCAPNG_BLOCK_ERROR;
    }

    /* we currently only understand SHB V1.0 */
    if (version_major != 1 || version_minor > 0) {
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = g_strdup_printf("pcapng_read_section_header_block: unknown SHB version %u.%u",
                                    pn->version_major, pn->version_minor);
        return PCAPNG_BLOCK_ERROR;
    }

    pn->byte_swapped  = byte_swapped;
    pn->version_major = version_major;
    pn->version_minor = version_minor;

    wblock->block = wtap_optionblock_create(WTAP_OPTION_BLOCK_NG_SECTION);
    section_data = (wtapng_mandatory_section_t*)wtap_optionblock_get_mandatory_data(wblock->block);
    /* 64bit section_length (currently unused) */
    if (pn->byte_swapped) {
        section_data->section_length = GUINT64_SWAP_LE_BE(shb.section_length);
    } else {
        section_data->section_length = shb.section_length;
    }

    /* Options */
    to_read = bh->block_total_length - MIN_SHB_SIZE;

    /* Allocate enough memory to hold all options */
    opt_cont_buf_len = to_read;
    option_content = (guint8 *)g_try_malloc(opt_cont_buf_len);
    if (opt_cont_buf_len != 0 && option_content == NULL) {
        *err = ENOMEM;  /* we assume we're out of memory */
        return PCAPNG_BLOCK_ERROR;
    }
    pcapng_debug("pcapng_read_section_header_block: Options %u bytes", to_read);
    while (to_read != 0) {
        /* read option */
        pcapng_debug("pcapng_read_section_header_block: Options %u bytes remaining", to_read);
        bytes_read = pcapng_read_option(fh, pn, &oh, option_content, opt_cont_buf_len, to_read, err, err_info, "section_header");
        if (bytes_read <= 0) {
            pcapng_debug("pcapng_read_section_header_block: failed to read option");
            return PCAPNG_BLOCK_ERROR;
        }
        to_read -= bytes_read;

        /* handle option content */
        switch (oh.option_code) {
            case(OPT_EOFOPT):
                if (to_read != 0) {
                    pcapng_debug("pcapng_read_section_header_block: %u bytes after opt_endofopt", to_read);
                }
                /* padding should be ok here, just get out of this */
                to_read = 0;
                break;
            case(OPT_COMMENT):
                if (oh.option_length > 0 && oh.option_length < opt_cont_buf_len) {
                    tmp_content = g_strndup((char *)option_content, oh.option_length);
                    wtap_optionblock_set_option_string(wblock->block, OPT_COMMENT, tmp_content);
                    pcapng_debug("pcapng_read_section_header_block: opt_comment %s", tmp_content);
                    g_free(tmp_content);
                } else {
                    pcapng_debug("pcapng_read_section_header_block: opt_comment length %u seems strange", oh.option_length);
                }
                break;
            case(OPT_SHB_HARDWARE):
                if (oh.option_length > 0 && oh.option_length < opt_cont_buf_len) {
                    tmp_content = g_strndup((char *)option_content, oh.option_length);
                    wtap_optionblock_set_option_string(wblock->block, OPT_SHB_HARDWARE, tmp_content);
                    pcapng_debug("pcapng_read_section_header_block: shb_hardware %s", tmp_content);
                    g_free(tmp_content);
                } else {
                    pcapng_debug("pcapng_read_section_header_block: shb_hardware length %u seems strange", oh.option_length);
                }
                break;
            case(OPT_SHB_OS):
                if (oh.option_length > 0 && oh.option_length < opt_cont_buf_len) {
                    tmp_content = g_strndup((char *)option_content, oh.option_length);
                    wtap_optionblock_set_option_string(wblock->block, OPT_SHB_OS, tmp_content);
                    pcapng_debug("pcapng_read_section_header_block: shb_os %s", tmp_content);
                    g_free(tmp_content);
                } else {
                    pcapng_debug("pcapng_read_section_header_block: shb_os length %u seems strange, opt buffsize %u", oh.option_length,to_read);
                }
                break;
            case(OPT_SHB_USERAPPL):
                if (oh.option_length > 0 && oh.option_length < opt_cont_buf_len) {
                    tmp_content = g_strndup((char *)option_content, oh.option_length);
                    wtap_optionblock_set_option_string(wblock->block, OPT_SHB_USERAPPL, tmp_content);
                    pcapng_debug("pcapng_read_section_header_block: shb_user_appl %s", tmp_content);
                    g_free(tmp_content);
                } else {
                    pcapng_debug("pcapng_read_section_header_block: shb_user_appl length %u seems strange", oh.option_length);
                }
                break;
            default:
                pcapng_debug("pcapng_read_section_header_block: unknown option %u - ignoring %u bytes",
                              oh.option_code, oh.option_length);
        }
    }
    g_free(option_content);

    return PCAPNG_BLOCK_OK;
}


/* "Interface Description Block" */
static gboolean
pcapng_read_if_descr_block(wtap *wth, FILE_T fh, pcapng_block_header_t *bh,
                           pcapng_t *pn, wtapng_block_t *wblock, int *err,
                           gchar **err_info)
{
    guint64 time_units_per_second = 1000000; /* default = 10^6 */
    int     tsprecision = WTAP_TSPREC_USEC;
    int     bytes_read;
    guint to_read, opt_cont_buf_len;
    pcapng_interface_description_block_t idb;
    wtapng_if_descr_mandatory_t* if_descr_mand;
    pcapng_option_header_t oh;
    guint8 *option_content = NULL; /* Allocate as large as the options block */
    gchar* tmp_content;
    guint64 tmp64;

    /*
     * Is this block long enough to be an IDB?
     */
    if (bh->block_total_length < MIN_IDB_SIZE) {
        /*
         * No.
         */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("pcapng_read_if_descr_block: total block length %u of an IDB is less than the minimum IDB size %u",
                                    bh->block_total_length, MIN_IDB_SIZE);
        return FALSE;
    }

    /* Don't try to allocate memory for a huge number of options, as
       that might fail and, even if it succeeds, it might not leave
       any address space or memory+backing store for anything else.

       We do that by imposing a maximum block size of MAX_BLOCK_SIZE.
       We check for this *after* checking the SHB for its byte
       order magic number, so that non-pcap-ng files are less
       likely to be treated as bad pcap-ng files. */
    if (bh->block_total_length > MAX_BLOCK_SIZE) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("pcapng_read_if_descr_block: total block length %u is too large (> %u)",
                                    bh->block_total_length, MAX_BLOCK_SIZE);
        return FALSE;
    }

    /* read block content */
    if (!wtap_read_bytes(fh, &idb, sizeof idb, err, err_info)) {
        pcapng_debug("pcapng_read_if_descr_block: failed to read IDB");
        return FALSE;
    }

    /* mandatory values */
    wblock->block = wtap_optionblock_create(WTAP_OPTION_BLOCK_IF_DESCR);
    if_descr_mand = (wtapng_if_descr_mandatory_t*)wtap_optionblock_get_mandatory_data(wblock->block);
    if (pn->byte_swapped) {
        if_descr_mand->link_type = GUINT16_SWAP_LE_BE(idb.linktype);
        if_descr_mand->snap_len  = GUINT32_SWAP_LE_BE(idb.snaplen);
    } else {
        if_descr_mand->link_type = idb.linktype;
        if_descr_mand->snap_len  = idb.snaplen;
    }

    if_descr_mand->wtap_encap = wtap_pcap_encap_to_wtap_encap(if_descr_mand->link_type);
    if_descr_mand->time_units_per_second = time_units_per_second;
    if_descr_mand->tsprecision = tsprecision;

    pcapng_debug("pcapng_read_if_descr_block: IDB link_type %u (%s), snap %u",
                  if_descr_mand->link_type,
                  wtap_encap_string(if_descr_mand->wtap_encap),
                  if_descr_mand->snap_len);

    if (if_descr_mand->snap_len > WTAP_MAX_PACKET_SIZE) {
        /* This is unrealistic, but text2pcap currently uses 102400.
         * We do not use this value, maybe we should check the
         * snap_len of the packets against it. For now, only warn.
         */
        pcapng_debug("pcapng_read_if_descr_block: snapshot length %u unrealistic.",
                      if_descr_mand->snap_len);
        /*if_descr_mand->snap_len = WTAP_MAX_PACKET_SIZE;*/
    }

    /* Options */
    to_read = bh->block_total_length - MIN_IDB_SIZE;

    /* Allocate enough memory to hold all options */
    opt_cont_buf_len = to_read;
    option_content = (guint8 *)g_try_malloc(opt_cont_buf_len);
    if (opt_cont_buf_len != 0 && option_content == NULL) {
        *err = ENOMEM;  /* we assume we're out of memory */
        return FALSE;
    }

    while (to_read != 0) {
        /* read option */
        bytes_read = pcapng_read_option(fh, pn, &oh, option_content, opt_cont_buf_len, to_read, err, err_info, "if_descr");
        if (bytes_read <= 0) {
            pcapng_debug("pcapng_read_if_descr_block: failed to read option");
            return FALSE;
        }
        to_read -= bytes_read;

        /* handle option content */
        switch (oh.option_code) {
            case(OPT_EOFOPT): /* opt_endofopt */
                if (to_read != 0) {
                    pcapng_debug("pcapng_read_if_descr_block: %u bytes after opt_endofopt", to_read);
                }
                /* padding should be ok here, just get out of this */
                to_read = 0;
                break;
            case(OPT_COMMENT): /* opt_comment */
                if (oh.option_length > 0 && oh.option_length < opt_cont_buf_len) {
                    tmp_content = g_strndup((char *)option_content, oh.option_length);
                    wtap_optionblock_set_option_string(wblock->block, OPT_COMMENT, tmp_content);
                    pcapng_debug("pcapng_read_if_descr_block: opt_comment %s", tmp_content);
                    g_free(tmp_content);
                } else {
                    pcapng_debug("pcapng_read_if_descr_block: opt_comment length %u seems strange", oh.option_length);
                }
                break;
            case(OPT_IDB_NAME): /* if_name */
                if (oh.option_length > 0 && oh.option_length < opt_cont_buf_len) {
                    tmp_content = g_strndup((char *)option_content, oh.option_length);
                    wtap_optionblock_set_option_string(wblock->block, OPT_IDB_NAME, tmp_content);
                    pcapng_debug("pcapng_read_if_descr_block: if_name %s", tmp_content);
                    g_free(tmp_content);
                } else {
                    pcapng_debug("pcapng_read_if_descr_block: if_name length %u seems strange", oh.option_length);
                }
                break;
            case(OPT_IDB_DESCR): /* if_description */
                if (oh.option_length > 0 && oh.option_length < opt_cont_buf_len) {
                    tmp_content = g_strndup((char *)option_content, oh.option_length);
                    wtap_optionblock_set_option_string(wblock->block, OPT_IDB_DESCR, tmp_content);
                    pcapng_debug("pcapng_read_if_descr_block: if_description %s", tmp_content);
                    g_free(tmp_content);
                } else {
                    pcapng_debug("pcapng_read_if_descr_block: if_description length %u seems strange", oh.option_length);
                }
                break;
            case(OPT_IDB_SPEED): /* if_speed */
                if (oh.option_length == 8) {
                    /*  Don't cast a guint8 * into a guint64 *--the
                     *  guint8 * may not point to something that's
                     *  aligned correctly.
                     */
                    memcpy(&tmp64, option_content, sizeof(guint64));
                    if (pn->byte_swapped)
                        tmp64 = GUINT64_SWAP_LE_BE(tmp64);
                    wtap_optionblock_set_option_uint64(wblock->block, OPT_IDB_SPEED, tmp64);
                    pcapng_debug("pcapng_read_if_descr_block: if_speed %" G_GINT64_MODIFIER "u (bps)", tmp64);
                } else {
                    pcapng_debug("pcapng_read_if_descr_block: if_speed length %u not 8 as expected", oh.option_length);
                }
                break;
            case(OPT_IDB_TSRESOL): /* if_tsresol */
                if (oh.option_length == 1) {
                    guint64 base;
                    guint64 result;
                    guint8 i, exponent, if_tsresol;

                    if_tsresol = option_content[0];
                    if (if_tsresol & 0x80) {
                        base = 2;
                    } else {
                        base = 10;
                    }
                    exponent = (guint8)(if_tsresol & 0x7f);
                    if (((base == 2) && (exponent < 64)) || ((base == 10) && (exponent < 20))) {
                        result = 1;
                        for (i = 0; i < exponent; i++) {
                            result *= base;
                        }
                        time_units_per_second = result;
                    } else {
                        time_units_per_second = G_MAXUINT64;
                    }
                    if (time_units_per_second > (((guint64)1) << 32)) {
                        pcapng_debug("pcapng_open: time conversion might be inaccurate");
                    }
                    if_descr_mand->time_units_per_second = time_units_per_second;
                    wtap_optionblock_set_option_uint8(wblock->block, OPT_IDB_TSRESOL, if_tsresol);
                    if (time_units_per_second >= 1000000000)
                        tsprecision = WTAP_TSPREC_NSEC;
                    else if (time_units_per_second >= 1000000)
                        tsprecision = WTAP_TSPREC_USEC;
                    else if (time_units_per_second >= 1000)
                        tsprecision = WTAP_TSPREC_MSEC;
                    else if (time_units_per_second >= 100)
                        tsprecision = WTAP_TSPREC_CSEC;
                    else if (time_units_per_second >= 10)
                        tsprecision = WTAP_TSPREC_DSEC;
                    else
                        tsprecision = WTAP_TSPREC_SEC;
                    if_descr_mand->tsprecision = tsprecision;
                    pcapng_debug("pcapng_read_if_descr_block: if_tsresol %u, units/s %" G_GINT64_MODIFIER "u, tsprecision %d", if_tsresol, if_descr_mand->time_units_per_second, tsprecision);
                } else {
                    pcapng_debug("pcapng_read_if_descr_block: if_tsresol length %u not 1 as expected", oh.option_length);
                }
                break;
                /*
                 * if_tzone      10  Time zone for GMT support (TODO: specify better). TODO: give a good example
                 */
            case(OPT_IDB_FILTER): /* if_filter */
                if (oh.option_length > 0 && oh.option_length < opt_cont_buf_len) {
                    wtapng_if_descr_filter_t if_filter;
                    memset(&if_filter, 0, sizeof(if_filter));

                    /* The first byte of the Option Data keeps a code of the filter used (e.g. if this is a libpcap string,
                     * or BPF bytecode.
                     */
                    if (option_content[0] == 0) {
                        if_filter.if_filter_str = g_strndup((char *)option_content+1, oh.option_length-1);
                        pcapng_debug("pcapng_read_if_descr_block: if_filter_str %s oh.option_length %u", if_filter.if_filter_str, oh.option_length);
                    } else if (option_content[0] == 1) {
                        if_filter.bpf_filter_len = oh.option_length-1;
                        if_filter.if_filter_bpf_bytes = (gchar *)g_malloc(oh.option_length-1);
                        memcpy(if_filter.if_filter_bpf_bytes, (char *)option_content+1, oh.option_length-1);
                    }
                    wtap_optionblock_set_option_custom(wblock->block, OPT_IDB_FILTER, &if_filter);
                } else {
                    pcapng_debug("pcapng_read_if_descr_block: if_filter length %u seems strange", oh.option_length);
                }
                break;
            case(OPT_IDB_OS): /* if_os */
                /*
                 * if_os         12  A UTF-8 string containing the name of the operating system of the machine in which this interface is installed.
                 * This can be different from the same information that can be contained by the Section Header Block (Section 3.1 (Section Header Block (mandatory)))
                 * because the capture can have been done on a remote machine. "Windows XP SP2" / "openSUSE 10.2" / ...
                 */
                if (oh.option_length > 0 && oh.option_length < opt_cont_buf_len) {
                    tmp_content = g_strndup((char *)option_content, oh.option_length);
                    wtap_optionblock_set_option_string(wblock->block, OPT_IDB_OS, tmp_content);
                    pcapng_debug("pcapng_read_if_descr_block: if_os %s", tmp_content);
                    g_free(tmp_content);
                } else {
                    pcapng_debug("pcapng_read_if_descr_block: if_os length %u seems strange", oh.option_length);
                }
                break;
            case(OPT_IDB_FCSLEN): /* if_fcslen */
                if (oh.option_length == 1) {
                    wtap_optionblock_set_option_uint8(wblock->block, OPT_IDB_TSRESOL, option_content[0]);
                    pn->if_fcslen = option_content[0];
                    pcapng_debug("pcapng_read_if_descr_block: if_fcslen %u", pn->if_fcslen);
                    /* XXX - add sanity check */
                } else {
                    pcapng_debug("pcapng_read_if_descr_block: if_fcslen length %u not 1 as expected", oh.option_length);
                }
                break;

            /* TODO: process these! */
            case(OPT_IDB_IP4ADDR):
                /*
                 * Interface network address and netmask. This option can be
                 * repeated multiple times within the same Interface
                 * Description Block when multiple IPv4 addresses are assigned
                 * to the interface. 192 168 1 1 255 255 255 0
                 */
            case(OPT_IDB_IP6ADDR):
                /*
                 * Interface network address and prefix length (stored in the
                 * last byte). This option can be repeated multiple times
                 * within the same Interface Description Block when multiple
                 * IPv6 addresses are assigned to the interface.
                 * 2001:0db8:85a3:08d3:1319:8a2e:0370:7344/64 is written (in
                 * hex) as "20 01 0d b8 85 a3 08 d3 13 19 8a 2e 03 70 73 44
                 * 40"
                 */
            case(OPT_IDB_MACADDR):
                /*
                 * Interface Hardware MAC address (48 bits). 00 01 02 03 04 05
                 */
            case(OPT_IDB_EUIADDR):
                /*
                 * Interface Hardware EUI address (64 bits), if available.
                 * TODO: give a good example
                 */
            case(OPT_IDB_TZONE):
                /*
                 * Time zone for GMT support. TODO: specify better.
                 * TODO: give a good example.
                 */
            case(OPT_IDB_TSOFFSET):
                /*
                 * A 64 bits integer value that specifies an offset (in
                 * seconds) that must be added to the timestamp of each packet
                 * to obtain the absolute timestamp of a packet. If the option
                 * is missing, the timestamps stored in the packet must be
                 * considered absolute timestamps. The time zone of the offset
                 * can be specified with the option if_tzone.
                 *
                 * TODO: won't a if_tsoffset_low for fractional second offsets
                 * be useful for highly synchronized capture systems? 1234
                 */
            default:
                pcapng_debug("pcapng_read_if_descr_block: unknown option %u - ignoring %u bytes",
                              oh.option_code, oh.option_length);
        }
    }

    g_free(option_content);

    /*
     * If the per-file encapsulation isn't known, set it to this
     * interface's encapsulation.
     *
     * If it *is* known, and it isn't this interface's encapsulation,
     * set it to WTAP_ENCAP_PER_PACKET, as this file doesn't
     * have a single encapsulation for all interfaces in the file,
     * so it probably doesn't have a single encapsulation for all
     * packets in the file.
     */
    if (wth->file_encap == WTAP_ENCAP_UNKNOWN) {
        wth->file_encap = if_descr_mand->wtap_encap;
    } else {
        if (wth->file_encap != if_descr_mand->wtap_encap) {
            wth->file_encap = WTAP_ENCAP_PER_PACKET;
        }
    }

    /*
     * The same applies to the per-file time stamp resolution.
     */
    if (wth->file_tsprec == WTAP_TSPREC_UNKNOWN) {
        wth->file_tsprec = if_descr_mand->tsprecision;
    } else {
        if (wth->file_tsprec != if_descr_mand->tsprecision) {
            wth->file_tsprec = WTAP_TSPREC_PER_PACKET;
        }
    }

    return TRUE;
}


static gboolean
pcapng_read_packet_block(FILE_T fh, pcapng_block_header_t *bh, pcapng_t *pn, wtapng_block_t *wblock, int *err, gchar **err_info, gboolean enhanced)
{
    int bytes_read;
    guint block_read;
    guint to_read, opt_cont_buf_len;
    pcapng_enhanced_packet_block_t epb;
    pcapng_packet_block_t pb;
    wtapng_packet_t packet;
    guint32 block_total_length;
    guint32 padding;
    interface_info_t iface_info;
    guint64 ts;
    guint8 *opt_ptr;
    pcapng_option_header_t *oh;
    guint8 *option_content;
    int pseudo_header_len;
    int fcslen;
#ifdef HAVE_PLUGINS
    option_handler *handler;
#endif

    /* Don't try to allocate memory for a huge number of options, as
       that might fail and, even if it succeeds, it might not leave
       any address space or memory+backing store for anything else.

       We do that by imposing a maximum block size of MAX_BLOCK_SIZE.
       We check for this *after* checking the SHB for its byte
       order magic number, so that non-pcap-ng files are less
       likely to be treated as bad pcap-ng files. */
    if (bh->block_total_length > MAX_BLOCK_SIZE) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("pcapng_read_packet_block: total block length %u is too large (> %u)",
                                    bh->block_total_length, MAX_BLOCK_SIZE);
        return FALSE;
    }

    /* "(Enhanced) Packet Block" read fixed part */
    if (enhanced) {
        /*
         * Is this block long enough to be an EPB?
         */
        if (bh->block_total_length < MIN_EPB_SIZE) {
            /*
             * No.
             */
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup_printf("pcapng_read_packet_block: total block length %u of an EPB is less than the minimum EPB size %u",
                                        bh->block_total_length, MIN_EPB_SIZE);
            return FALSE;
        }
        if (!wtap_read_bytes(fh, &epb, sizeof epb, err, err_info)) {
            pcapng_debug("pcapng_read_packet_block: failed to read packet data");
            return FALSE;
        }
        block_read = (guint)sizeof epb;

        if (pn->byte_swapped) {
            packet.interface_id        = GUINT32_SWAP_LE_BE(epb.interface_id);
            packet.drops_count         = -1; /* invalid */
            packet.ts_high             = GUINT32_SWAP_LE_BE(epb.timestamp_high);
            packet.ts_low              = GUINT32_SWAP_LE_BE(epb.timestamp_low);
            packet.cap_len             = GUINT32_SWAP_LE_BE(epb.captured_len);
            packet.packet_len          = GUINT32_SWAP_LE_BE(epb.packet_len);
        } else {
            packet.interface_id        = epb.interface_id;
            packet.drops_count         = -1; /* invalid */
            packet.ts_high             = epb.timestamp_high;
            packet.ts_low              = epb.timestamp_low;
            packet.cap_len             = epb.captured_len;
            packet.packet_len          = epb.packet_len;
        }
        pcapng_debug("pcapng_read_packet_block: EPB on interface_id %d, cap_len %d, packet_len %d",
                      packet.interface_id, packet.cap_len, packet.packet_len);
    } else {
        /*
         * Is this block long enough to be a PB?
         */
        if (bh->block_total_length < MIN_PB_SIZE) {
            /*
             * No.
             */
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup_printf("pcapng_read_packet_block: total block length %u of a PB is less than the minimum PB size %u",
                                        bh->block_total_length, MIN_PB_SIZE);
            return FALSE;
        }
        if (!wtap_read_bytes(fh, &pb, sizeof pb, err, err_info)) {
            pcapng_debug("pcapng_read_packet_block: failed to read packet data");
            return FALSE;
        }
        block_read = (guint)sizeof pb;

        if (pn->byte_swapped) {
            packet.interface_id        = GUINT16_SWAP_LE_BE(pb.interface_id);
            packet.drops_count         = GUINT16_SWAP_LE_BE(pb.drops_count);
            packet.ts_high             = GUINT32_SWAP_LE_BE(pb.timestamp_high);
            packet.ts_low              = GUINT32_SWAP_LE_BE(pb.timestamp_low);
            packet.cap_len             = GUINT32_SWAP_LE_BE(pb.captured_len);
            packet.packet_len          = GUINT32_SWAP_LE_BE(pb.packet_len);
        } else {
            packet.interface_id        = pb.interface_id;
            packet.drops_count         = pb.drops_count;
            packet.ts_high             = pb.timestamp_high;
            packet.ts_low              = pb.timestamp_low;
            packet.cap_len             = pb.captured_len;
            packet.packet_len          = pb.packet_len;
        }
        pcapng_debug("pcapng_read_packet_block: PB on interface_id %d, cap_len %d, packet_len %d",
                      packet.interface_id, packet.cap_len, packet.packet_len);
    }

    /*
     * How much padding is there at the end of the packet data?
     */
    if ((packet.cap_len % 4) != 0)
        padding = 4 - (packet.cap_len % 4);
    else
        padding = 0;

    /* add padding bytes to "block total length" */
    /* (the "block total length" of some example files don't contain the packet data padding bytes!) */
    if (bh->block_total_length % 4) {
        block_total_length = bh->block_total_length + 4 - (bh->block_total_length % 4);
    } else {
        block_total_length = bh->block_total_length;
    }
    pcapng_debug("pcapng_read_packet_block: block_total_length %d", block_total_length);

    /*
     * Is this block long enough to hold the packet data?
     */
    if (enhanced) {
        if (block_total_length <
            MIN_EPB_SIZE + packet.cap_len + padding) {
            /*
             * No.
             */
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup_printf("pcapng_read_packet_block: total block length %u of EPB is too small for %u bytes of packet data",
                                        block_total_length, packet.cap_len);
            return FALSE;
        }
    } else {
        if (block_total_length <
            MIN_PB_SIZE + packet.cap_len + padding) {
            /*
             * No.
             */
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup_printf("pcapng_read_packet_block: total block length %u of PB is too small for %u bytes of packet data",
                                        block_total_length, packet.cap_len);
            return FALSE;
        }
    }

    if (packet.cap_len > WTAP_MAX_PACKET_SIZE) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("pcapng_read_packet_block: cap_len %u is larger than WTAP_MAX_PACKET_SIZE %u",
                                    packet.cap_len, WTAP_MAX_PACKET_SIZE);
        return FALSE;
    }
    pcapng_debug("pcapng_read_packet_block: packet data: packet_len %u captured_len %u interface_id %u",
                  packet.packet_len,
                  packet.cap_len,
                  packet.interface_id);

    if (packet.interface_id >= pn->interfaces->len) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("pcapng_read_packet_block: interface index %u is not less than interface count %u",
                                    packet.interface_id, pn->interfaces->len);
        return FALSE;
    }
    iface_info = g_array_index(pn->interfaces, interface_info_t,
                               packet.interface_id);

    wblock->packet_header->rec_type = REC_TYPE_PACKET;
    wblock->packet_header->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN|WTAP_HAS_INTERFACE_ID;

    pcapng_debug("pcapng_read_packet_block: encapsulation = %d (%s), pseudo header size = %d.",
                  iface_info.wtap_encap,
                  wtap_encap_string(iface_info.wtap_encap),
                  pcap_get_phdr_size(iface_info.wtap_encap, &wblock->packet_header->pseudo_header));
    wblock->packet_header->interface_id = packet.interface_id;
    wblock->packet_header->pkt_encap = iface_info.wtap_encap;
    wblock->packet_header->pkt_tsprec = iface_info.tsprecision;

    memset((void *)&wblock->packet_header->pseudo_header, 0, sizeof(union wtap_pseudo_header));
    pseudo_header_len = pcap_process_pseudo_header(fh,
                                                   WTAP_FILE_TYPE_SUBTYPE_PCAPNG,
                                                   iface_info.wtap_encap,
                                                   packet.cap_len,
                                                   TRUE,
                                                   wblock->packet_header,
                                                   err,
                                                   err_info);
    if (pseudo_header_len < 0) {
        return FALSE;
    }
    block_read += pseudo_header_len;
    if (pseudo_header_len != pcap_get_phdr_size(iface_info.wtap_encap, &wblock->packet_header->pseudo_header)) {
        pcapng_debug("pcapng_read_packet_block: Could only read %d bytes for pseudo header.",
                      pseudo_header_len);
    }
    wblock->packet_header->caplen = packet.cap_len - pseudo_header_len;
    wblock->packet_header->len = packet.packet_len - pseudo_header_len;

    /* Combine the two 32-bit pieces of the timestamp into one 64-bit value */
    ts = (((guint64)packet.ts_high) << 32) | ((guint64)packet.ts_low);
    wblock->packet_header->ts.secs = (time_t)(ts / iface_info.time_units_per_second);
    wblock->packet_header->ts.nsecs = (int)(((ts % iface_info.time_units_per_second) * 1000000000) / iface_info.time_units_per_second);

    /* "(Enhanced) Packet Block" read capture data */
    if (!wtap_read_packet_bytes(fh, wblock->frame_buffer,
                                packet.cap_len - pseudo_header_len, err, err_info))
        return FALSE;
    block_read += packet.cap_len - pseudo_header_len;

    /* jump over potential padding bytes at end of the packet data */
    if (padding != 0) {
        if (!file_skip(fh, padding, err))
            return FALSE;
        block_read += padding;
    }

    /* Option defaults */
    wblock->packet_header->opt_comment = NULL;
    wblock->packet_header->drop_count  = -1;
    wblock->packet_header->pack_flags  = 0;

    /* FCS length default */
    fcslen = pn->if_fcslen;

    /* Options
     * opt_comment    1
     * epb_flags      2
     * epb_hash       3
     * epb_dropcount  4
     */
    to_read = block_total_length -
        (int)sizeof(pcapng_block_header_t) -
        block_read -    /* fixed and variable part, including padding */
        (int)sizeof(bh->block_total_length);

    /* Allocate enough memory to hold all options */
    opt_cont_buf_len = to_read;
    ws_buffer_assure_space(&wblock->packet_header->ft_specific_data, opt_cont_buf_len);
    opt_ptr = ws_buffer_start_ptr(&wblock->packet_header->ft_specific_data);

    while (to_read != 0) {
        /* read option */
        oh = (pcapng_option_header_t *)(void *)opt_ptr;
        option_content = opt_ptr + sizeof (pcapng_option_header_t);
        bytes_read = pcapng_read_option(fh, pn, oh, option_content, opt_cont_buf_len, to_read, err, err_info, "packet");
        if (bytes_read <= 0) {
            pcapng_debug("pcapng_read_packet_block: failed to read option");
            /* XXX - free anything? */
            return FALSE;
        }
        block_read += bytes_read;
        to_read -= bytes_read;

        /* handle option content */
        switch (oh->option_code) {
            case(OPT_EOFOPT):
                if (to_read != 0) {
                    pcapng_debug("pcapng_read_packet_block: %u bytes after opt_endofopt", to_read);
                }
                /* padding should be ok here, just get out of this */
                to_read = 0;
                break;
            case(OPT_COMMENT):
                if (oh->option_length > 0 && oh->option_length < opt_cont_buf_len) {
                    wblock->packet_header->presence_flags |= WTAP_HAS_COMMENTS;
                    wblock->packet_header->opt_comment = g_strndup((char *)option_content, oh->option_length);
                    pcapng_debug("pcapng_read_packet_block: length %u opt_comment '%s'", oh->option_length, wblock->packet_header->opt_comment);
                } else {
                    pcapng_debug("pcapng_read_packet_block: opt_comment length %u seems strange", oh->option_length);
                }
                break;
            case(OPT_EPB_FLAGS):
                if (oh->option_length != 4) {
                    *err = WTAP_ERR_BAD_FILE;
                    *err_info = g_strdup_printf("pcapng_read_packet_block: packet block flags option length %u is not 4",
                                                oh->option_length);
                    /* XXX - free anything? */
                    return FALSE;
                }
                /*  Don't cast a guint8 * into a guint32 *--the
                 *  guint8 * may not point to something that's
                 *  aligned correctly.
                 */
                wblock->packet_header->presence_flags |= WTAP_HAS_PACK_FLAGS;
                memcpy(&wblock->packet_header->pack_flags, option_content, sizeof(guint32));
                if (pn->byte_swapped) {
                    wblock->packet_header->pack_flags = GUINT32_SWAP_LE_BE(wblock->packet_header->pack_flags);
                    memcpy(option_content, &wblock->packet_header->pack_flags, sizeof(guint32));
                }
                if (wblock->packet_header->pack_flags & 0x000001E0) {
                    /* The FCS length is present */
                    fcslen = (wblock->packet_header->pack_flags & 0x000001E0) >> 5;
                }
                pcapng_debug("pcapng_read_packet_block: pack_flags %u (ignored)", wblock->packet_header->pack_flags);
                break;
            case(OPT_EPB_HASH):
                pcapng_debug("pcapng_read_packet_block: epb_hash %u currently not handled - ignoring %u bytes",
                              oh->option_code, oh->option_length);
                break;
            case(OPT_EPB_DROPCOUNT):
                if (oh->option_length != 8) {
                    *err = WTAP_ERR_BAD_FILE;
                    *err_info = g_strdup_printf("pcapng_read_packet_block: packet block drop count option length %u is not 8",
                                                oh->option_length);
                    /* XXX - free anything? */
                    return FALSE;
                }
                /*  Don't cast a guint8 * into a guint64 *--the
                 *  guint8 * may not point to something that's
                 *  aligned correctly.
                 */
                wblock->packet_header->presence_flags |= WTAP_HAS_DROP_COUNT;
                memcpy(&wblock->packet_header->drop_count, option_content, sizeof(guint64));
                if (pn->byte_swapped) {
                    wblock->packet_header->drop_count = GUINT64_SWAP_LE_BE(wblock->packet_header->drop_count);
                    memcpy(option_content, &wblock->packet_header->drop_count, sizeof(guint64));
                }

                pcapng_debug("pcapng_read_packet_block: drop_count %" G_GINT64_MODIFIER "u", wblock->packet_header->drop_count);
                break;
            default:
#ifdef HAVE_PLUGINS
                /*
                 * Do we have a handler for this packet block option code?
                 */
                if (option_handlers[BT_INDEX_PBS] != NULL &&
                    (handler = (option_handler *)g_hash_table_lookup(option_handlers[BT_INDEX_PBS],
                                                                   GUINT_TO_POINTER((guint)oh->option_code))) != NULL) {
                    /* Yes - call the handler. */
                    if (!handler->hfunc(pn->byte_swapped, oh->option_length,
                                 option_content, err, err_info))
                        /* XXX - free anything? */
                        return FALSE;
                } else
#endif
                {
                    pcapng_debug("pcapng_read_packet_block: unknown option %u - ignoring %u bytes",
                                  oh->option_code, oh->option_length);
                }
        }
    }

    pcap_read_post_process(WTAP_FILE_TYPE_SUBTYPE_PCAPNG, iface_info.wtap_encap,
                           wblock->packet_header, ws_buffer_start_ptr(wblock->frame_buffer),
                           pn->byte_swapped, fcslen);
    return TRUE;
}


static gboolean
pcapng_read_simple_packet_block(FILE_T fh, pcapng_block_header_t *bh, pcapng_t *pn, wtapng_block_t *wblock, int *err, gchar **err_info)
{
    interface_info_t iface_info;
    pcapng_simple_packet_block_t spb;
    wtapng_simple_packet_t simple_packet;
    guint32 block_total_length;
    guint32 padding;
    int pseudo_header_len;

    /*
     * Is this block long enough to be an SPB?
     */
    if (bh->block_total_length < MIN_SPB_SIZE) {
        /*
         * No.
         */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("pcapng_read_simple_packet_block: total block length %u of an SPB is less than the minimum SPB size %u",
                                    bh->block_total_length, MIN_SPB_SIZE);
        return FALSE;
    }

    /* Don't try to allocate memory for a huge number of options, as
       that might fail and, even if it succeeds, it might not leave
       any address space or memory+backing store for anything else.

       We do that by imposing a maximum block size of MAX_BLOCK_SIZE.
       We check for this *after* checking the SHB for its byte
       order magic number, so that non-pcap-ng files are less
       likely to be treated as bad pcap-ng files. */
    if (bh->block_total_length > MAX_BLOCK_SIZE) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("pcapng_read_simple_packet_block: total block length %u is too large (> %u)",
                                    bh->block_total_length, MAX_BLOCK_SIZE);
        return FALSE;
    }

    /* "Simple Packet Block" read fixed part */
    if (!wtap_read_bytes(fh, &spb, sizeof spb, err, err_info)) {
        pcapng_debug("pcapng_read_simple_packet_block: failed to read packet data");
        return FALSE;
    }

    if (0 >= pn->interfaces->len) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("pcapng_read_simple_packet_block: SPB appeared before any IDBs");
        return FALSE;
    }
    iface_info = g_array_index(pn->interfaces, interface_info_t, 0);

    if (pn->byte_swapped) {
        simple_packet.packet_len   = GUINT32_SWAP_LE_BE(spb.packet_len);
    } else {
        simple_packet.packet_len   = spb.packet_len;
    }

    /*
     * The captured length is not a field in the SPB; it can be
     * calculated as the minimum of the snapshot length from the
     * IDB and the packet length, as per the pcap-ng spec. An IDB
     * snapshot length of 0 means no limit.
     */
    simple_packet.cap_len = simple_packet.packet_len;
    if (simple_packet.cap_len > iface_info.snap_len && iface_info.snap_len != 0)
        simple_packet.cap_len = iface_info.snap_len;

    /*
     * How much padding is there at the end of the packet data?
     */
    if ((simple_packet.cap_len % 4) != 0)
        padding = 4 - (simple_packet.cap_len % 4);
    else
        padding = 0;

    /* add padding bytes to "block total length" */
    /* (the "block total length" of some example files don't contain the packet data padding bytes!) */
    if (bh->block_total_length % 4) {
        block_total_length = bh->block_total_length + 4 - (bh->block_total_length % 4);
    } else {
        block_total_length = bh->block_total_length;
    }
    pcapng_debug("pcapng_read_simple_packet_block: block_total_length %d", block_total_length);

    /*
     * Is this block long enough to hold the packet data?
     */
    if (block_total_length < MIN_SPB_SIZE + simple_packet.cap_len + padding) {
        /*
         * No.  That means that the problem is with the packet
         * length; the snapshot length can be bigger than the amount
         * of packet data in the block, as it's a *maximum* length,
         * not a *minimum* length.
         */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("pcapng_read_simple_packet_block: total block length %u of PB is too small for %u bytes of packet data",
                                    block_total_length, simple_packet.packet_len);
        return FALSE;
    }

    if (simple_packet.cap_len > WTAP_MAX_PACKET_SIZE) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("pcapng_read_simple_packet_block: cap_len %u is larger than WTAP_MAX_PACKET_SIZE %u",
                                    simple_packet.cap_len, WTAP_MAX_PACKET_SIZE);
        return FALSE;
    }
    pcapng_debug("pcapng_read_simple_packet_block: packet data: packet_len %u",
                  simple_packet.packet_len);

    pcapng_debug("pcapng_read_simple_packet_block: Need to read pseudo header of size %d",
                  pcap_get_phdr_size(iface_info.wtap_encap, &wblock->packet_header->pseudo_header));

    /* No time stamp in a simple packet block; no options, either */
    wblock->packet_header->rec_type = REC_TYPE_PACKET;
    wblock->packet_header->presence_flags = WTAP_HAS_CAP_LEN|WTAP_HAS_INTERFACE_ID;
    wblock->packet_header->interface_id = 0;
    wblock->packet_header->pkt_encap = iface_info.wtap_encap;
    wblock->packet_header->pkt_tsprec = iface_info.tsprecision;
    wblock->packet_header->ts.secs = 0;
    wblock->packet_header->ts.nsecs = 0;
    wblock->packet_header->interface_id = 0;
    wblock->packet_header->opt_comment = NULL;
    wblock->packet_header->drop_count = 0;
    wblock->packet_header->pack_flags = 0;

    memset((void *)&wblock->packet_header->pseudo_header, 0, sizeof(union wtap_pseudo_header));
    pseudo_header_len = pcap_process_pseudo_header(fh,
                                                   WTAP_FILE_TYPE_SUBTYPE_PCAPNG,
                                                   iface_info.wtap_encap,
                                                   simple_packet.cap_len,
                                                   TRUE,
                                                   wblock->packet_header,
                                                   err,
                                                   err_info);
    if (pseudo_header_len < 0) {
        return FALSE;
    }
    wblock->packet_header->caplen = simple_packet.cap_len - pseudo_header_len;
    wblock->packet_header->len = simple_packet.packet_len - pseudo_header_len;
    if (pseudo_header_len != pcap_get_phdr_size(iface_info.wtap_encap, &wblock->packet_header->pseudo_header)) {
        pcapng_debug("pcapng_read_simple_packet_block: Could only read %d bytes for pseudo header.",
                      pseudo_header_len);
    }

    memset((void *)&wblock->packet_header->pseudo_header, 0, sizeof(union wtap_pseudo_header));

    /* "Simple Packet Block" read capture data */
    if (!wtap_read_packet_bytes(fh, wblock->frame_buffer,
                                simple_packet.cap_len, err, err_info))
        return FALSE;

    /* jump over potential padding bytes at end of the packet data */
    if ((simple_packet.cap_len % 4) != 0) {
        if (!file_skip(fh, 4 - (simple_packet.cap_len % 4), err))
            return FALSE;
    }

    pcap_read_post_process(WTAP_FILE_TYPE_SUBTYPE_PCAPNG, iface_info.wtap_encap,
                           wblock->packet_header, ws_buffer_start_ptr(wblock->frame_buffer),
                           pn->byte_swapped, pn->if_fcslen);
    return TRUE;
}

#define NRES_ENDOFRECORD 0
#define NRES_IP4RECORD 1
#define NRES_IP6RECORD 2
#define PADDING4(x) ((((x + 3) >> 2) << 2) - x)
/* IPv6 + MAXNAMELEN */
#define INITIAL_NRB_REC_SIZE (16 + 64)

/*
 * Find the end of the NUL-terminated name the beginning of which is pointed
 * to by p; record_len is the number of bytes remaining in the record.
 *
 * Return the length of the name, including the terminating NUL.
 *
 * If we don't find a terminating NUL, return -1 and set *err and
 * *err_info appropriately.
 */
static int
name_resolution_block_find_name_end(const char *p, guint record_len, int *err,
                                    gchar **err_info)
{
    int namelen;

    namelen = 0;
    for (;;) {
        if (record_len == 0) {
            /*
             * We ran out of bytes in the record without
             * finding a NUL.
             */
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup("pcapng_read_name_resolution_block: NRB record has non-null-terminated host name");
            return -1;
        }
        if (*p == '\0')
            break;  /* that's the terminating NUL */
        p++;
        record_len--;
        namelen++;      /* count this byte */
    }

    /* Include the NUL in the name length. */
    return namelen + 1;
}

static gboolean
pcapng_read_name_resolution_block(FILE_T fh, pcapng_block_header_t *bh, pcapng_t *pn, wtapng_block_t *wblock, int *err, gchar **err_info)
{
    int block_read;
    int to_read;
    pcapng_name_resolution_block_t nrb;
    Buffer nrb_rec;
    guint32 v4_addr;
    guint record_len, opt_cont_buf_len;
    char *namep;
    int namelen;
    int bytes_read;
    pcapng_option_header_t oh;
    guint8 *option_content;
#ifdef HAVE_PLUGINS
    option_handler *handler;
#endif
    gchar* tmp_content;

    /*
     * Is this block long enough to be an NRB?
     */
    if (bh->block_total_length < MIN_NRB_SIZE) {
        /*
         * No.
         */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("pcapng_read_name_resolution_block: total block length %u of an NRB is less than the minimum NRB size %u",
                                    bh->block_total_length, MIN_NRB_SIZE);
        return FALSE;
    }

    /* Don't try to allocate memory for a huge number of options, as
       that might fail and, even if it succeeds, it might not leave
       any address space or memory+backing store for anything else.

       We do that by imposing a maximum block size of MAX_BLOCK_SIZE.
       We check for this *after* checking the SHB for its byte
       order magic number, so that non-pcap-ng files are less
       likely to be treated as bad pcap-ng files. */
    if (bh->block_total_length > MAX_BLOCK_SIZE) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("pcapng_read_name_resolution_block: total block length %u is too large (> %u)",
                                    bh->block_total_length, MAX_BLOCK_SIZE);
        return FALSE;
    }

    to_read = bh->block_total_length - 8 - 4; /* We have read the header and should not read the final block_total_length */

    pcapng_debug("pcapng_read_name_resolution_block, total %d bytes", bh->block_total_length);

    /* Ensure we have a name resolution block */
    if (wblock->block == NULL) {
        wblock->block = wtap_optionblock_create(WTAP_OPTION_BLOCK_NG_NRB);
    }

    /*
     * Start out with a buffer big enough for an IPv6 address and one
     * 64-byte name; we'll make the buffer bigger if necessary.
     */
    ws_buffer_init(&nrb_rec, INITIAL_NRB_REC_SIZE);
    block_read = 0;
    while (block_read < to_read) {
        /*
         * There must be at least one record's worth of data
         * here.
         */
        if ((size_t)(to_read - block_read) < sizeof nrb) {
            ws_buffer_free(&nrb_rec);
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup_printf("pcapng_read_name_resolution_block: %d bytes left in the block < NRB record header size %u",
                                        to_read - block_read,
                                        (guint)sizeof nrb);
            return FALSE;
        }
        if (!wtap_read_bytes(fh, &nrb, sizeof nrb, err, err_info)) {
            ws_buffer_free(&nrb_rec);
            pcapng_debug("pcapng_read_name_resolution_block: failed to read record header");
            return FALSE;
        }
        block_read += (int)sizeof nrb;

        if (pn->byte_swapped) {
            nrb.record_type = GUINT16_SWAP_LE_BE(nrb.record_type);
            nrb.record_len  = GUINT16_SWAP_LE_BE(nrb.record_len);
        }

        if (to_read - block_read < nrb.record_len + PADDING4(nrb.record_len)) {
            ws_buffer_free(&nrb_rec);
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup_printf("pcapng_read_name_resolution_block: %d bytes left in the block < NRB record length + padding %u",
                                        to_read - block_read,
                                        nrb.record_len + PADDING4(nrb.record_len));
            return FALSE;
        }
        switch (nrb.record_type) {
            case NRES_ENDOFRECORD:
                /* There shouldn't be any more data - but there MAY be options */
                goto read_options;
                break;
            case NRES_IP4RECORD:
                /*
                 * The smallest possible record must have
                 * a 4-byte IPv4 address, hence a minimum
                 * of 4 bytes.
                 *
                 * (The pcap-NG spec really indicates
                 * that it must be at least 5 bytes,
                 * as there must be at least one name,
                 * and it really must be at least 6
                 * bytes, as the name mustn't be null,
                 * but there's no need to fail if there
                 * aren't any names at all, and we
                 * should report a null name as such.)
                 */
                if (nrb.record_len < 4) {
                    ws_buffer_free(&nrb_rec);
                    *err = WTAP_ERR_BAD_FILE;
                    *err_info = g_strdup_printf("pcapng_read_name_resolution_block: NRB record length for IPv4 record %u < minimum length 4",
                                                nrb.record_len);
                    return FALSE;
                }
                ws_buffer_assure_space(&nrb_rec, nrb.record_len);
                if (!wtap_read_bytes(fh, ws_buffer_start_ptr(&nrb_rec),
                                     nrb.record_len, err, err_info)) {
                    ws_buffer_free(&nrb_rec);
                    pcapng_debug("pcapng_read_name_resolution_block: failed to read IPv4 record data");
                    return FALSE;
                }
                block_read += nrb.record_len;

                if (pn->add_new_ipv4) {
                    /*
                     * Scan through all the names in
                     * the record and add them.
                     */
                    memcpy(&v4_addr,
                           ws_buffer_start_ptr(&nrb_rec), 4);
                    /* IPv4 address is in big-endian order in the file always, which is how we store
                       it internally as well, so don't byte-swap it */
                    for (namep = (char *)ws_buffer_start_ptr(&nrb_rec) + 4, record_len = nrb.record_len - 4;
                         record_len != 0;
                         namep += namelen, record_len -= namelen) {
                        /*
                         * Scan forward for a null
                         * byte.
                         */
                        namelen = name_resolution_block_find_name_end(namep, record_len, err, err_info);
                        if (namelen == -1) {
                            ws_buffer_free(&nrb_rec);
                            return FALSE;      /* fail */
                        }
                        pn->add_new_ipv4(v4_addr, namep);
                    }
                }

                if (!file_skip(fh, PADDING4(nrb.record_len), err)) {
                    ws_buffer_free(&nrb_rec);
                    return FALSE;
                }
                block_read += PADDING4(nrb.record_len);
                break;
            case NRES_IP6RECORD:
                /*
                 * The smallest possible record must have
                 * a 16-byte IPv6 address, hence a minimum
                 * of 16 bytes.
                 *
                 * (The pcap-NG spec really indicates
                 * that it must be at least 17 bytes,
                 * as there must be at least one name,
                 * and it really must be at least 18
                 * bytes, as the name mustn't be null,
                 * but there's no need to fail if there
                 * aren't any names at all, and we
                 * should report a null name as such.)
                 */
                if (nrb.record_len < 16) {
                    ws_buffer_free(&nrb_rec);
                    *err = WTAP_ERR_BAD_FILE;
                    *err_info = g_strdup_printf("pcapng_read_name_resolution_block: NRB record length for IPv6 record %u < minimum length 16",
                                                nrb.record_len);
                    return FALSE;
                }
                if (to_read < nrb.record_len) {
                    ws_buffer_free(&nrb_rec);
                    *err = WTAP_ERR_BAD_FILE;
                    *err_info = g_strdup_printf("pcapng_read_name_resolution_block: NRB record length for IPv6 record %u > remaining data in NRB",
                                                nrb.record_len);
                    return FALSE;
                }
                ws_buffer_assure_space(&nrb_rec, nrb.record_len);
                if (!wtap_read_bytes(fh, ws_buffer_start_ptr(&nrb_rec),
                                     nrb.record_len, err, err_info)) {
                    ws_buffer_free(&nrb_rec);
                    return FALSE;
                }
                block_read += nrb.record_len;

                if (pn->add_new_ipv6) {
                    for (namep = (char *)ws_buffer_start_ptr(&nrb_rec) + 16, record_len = nrb.record_len - 16;
                         record_len != 0;
                         namep += namelen, record_len -= namelen) {
                        /*
                         * Scan forward for a null
                         * byte.
                         */
                        namelen = name_resolution_block_find_name_end(namep, record_len, err, err_info);
                        if (namelen == -1) {
                            ws_buffer_free(&nrb_rec);
                            return FALSE;      /* fail */
                        }
                        pn->add_new_ipv6(ws_buffer_start_ptr(&nrb_rec),
                                         namep);
                    }
                }

                if (!file_skip(fh, PADDING4(nrb.record_len), err)) {
                    ws_buffer_free(&nrb_rec);
                    return FALSE;
                }
                block_read += PADDING4(nrb.record_len);
                break;
            default:
                pcapng_debug("pcapng_read_name_resolution_block: unknown record type 0x%x", nrb.record_type);
                if (!file_skip(fh, nrb.record_len + PADDING4(nrb.record_len), err)) {
                    ws_buffer_free(&nrb_rec);
                    return FALSE;
                }
                block_read += nrb.record_len + PADDING4(nrb.record_len);
                break;
        }
    }


read_options:
    to_read -= block_read;

    /* Options
     * opt_comment    1
     *
     * TODO:
     * ns_dnsname     2
     * ns_dnsIP4addr  3
     * ns_dnsIP6addr  4
     */

    /* Allocate enough memory to hold all options */
    opt_cont_buf_len = to_read;
    option_content = (guint8 *)g_try_malloc(opt_cont_buf_len);
    if (opt_cont_buf_len != 0 && option_content == NULL) {
        *err = ENOMEM;  /* we assume we're out of memory */
        ws_buffer_free(&nrb_rec);
        return FALSE;
    }

    while (to_read != 0) {
        /* read option */
        bytes_read = pcapng_read_option(fh, pn, &oh, option_content, opt_cont_buf_len, to_read, err, err_info, "name_resolution");
        if (bytes_read <= 0) {
            pcapng_debug("pcapng_read_name_resolution_block: failed to read option");
            g_free(option_content);
            ws_buffer_free(&nrb_rec);
            return FALSE;
        }
        to_read -= bytes_read;

        /* handle option content */
        switch (oh.option_code) {
            case(OPT_EOFOPT):
                if (to_read != 0) {
                    pcapng_debug("pcapng_read_name_resolution_block: %u bytes after opt_endofopt", to_read);
                }
                /* padding should be ok here, just get out of this */
                to_read = 0;
                break;
            case(OPT_COMMENT):
                if (oh.option_length > 0 && oh.option_length < opt_cont_buf_len) {
                    tmp_content = g_strndup((char *)option_content, oh.option_length);
                    wtap_optionblock_set_option_string(wblock->block, OPT_COMMENT, tmp_content);
                    pcapng_debug("pcapng_read_name_resolution_block: length %u opt_comment '%s'", oh.option_length, tmp_content);
                    g_free(tmp_content);
                } else {
                    pcapng_debug("pcapng_read_name_resolution_block: opt_comment length %u seems strange", oh.option_length);
                }
                break;
            default:
#ifdef HAVE_PLUGINS
                /*
                 * Do we have a handler for this network resolution block option code?
                 */
                if (option_handlers[BT_INDEX_NRB] != NULL &&
                    (handler = (option_handler *)g_hash_table_lookup(option_handlers[BT_INDEX_NRB],
                                                                   GUINT_TO_POINTER((guint)oh.option_code))) != NULL) {
                    /* Yes - call the handler. */
                    if (!handler->hfunc(pn->byte_swapped, oh.option_length,
                                 option_content, err, err_info)) {

                        g_free(option_content);
                        ws_buffer_free(&nrb_rec);
                        return FALSE;
                    }
                } else
#endif
                {
                    pcapng_debug("pcapng_read_name_resolution_block: unknown option %u - ignoring %u bytes",
                                  oh.option_code, oh.option_length);
                }
        }
    }

    g_free(option_content);
    ws_buffer_free(&nrb_rec);
    return TRUE;
}

static gboolean
pcapng_read_interface_statistics_block(FILE_T fh, pcapng_block_header_t *bh, pcapng_t *pn, wtapng_block_t *wblock,int *err, gchar **err_info)
{
    int bytes_read;
    guint to_read, opt_cont_buf_len;
    pcapng_interface_statistics_block_t isb;
    pcapng_option_header_t oh;
    guint8 *option_content = NULL; /* Allocate as large as the options block */
    wtapng_if_stats_mandatory_t* if_stats_mand;
    char* tmp_content;

    /*
     * Is this block long enough to be an ISB?
     */
    if (bh->block_total_length < MIN_ISB_SIZE) {
        /*
         * No.
         */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("pcapng_read_interface_statistics_block: total block length %u is too small (< %u)",
                                    bh->block_total_length, MIN_ISB_SIZE);
        return FALSE;
    }

    /* Don't try to allocate memory for a huge number of options, as
       that might fail and, even if it succeeds, it might not leave
       any address space or memory+backing store for anything else.

       We do that by imposing a maximum block size of MAX_BLOCK_SIZE.
       We check for this *after* checking the SHB for its byte
       order magic number, so that non-pcap-ng files are less
       likely to be treated as bad pcap-ng files. */
    if (bh->block_total_length > MAX_BLOCK_SIZE) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("pcapng_read_interface_statistics_block: total block length %u is too large (> %u)",
                                    bh->block_total_length, MAX_BLOCK_SIZE);
        return FALSE;
    }

    /* "Interface Statistics Block" read fixed part */
    if (!wtap_read_bytes(fh, &isb, sizeof isb, err, err_info)) {
        pcapng_debug("pcapng_read_interface_statistics_block: failed to read packet data");
        return FALSE;
    }

    wblock->block = wtap_optionblock_create(WTAP_OPTION_BLOCK_IF_STATS);
    if_stats_mand = (wtapng_if_stats_mandatory_t*)wtap_optionblock_get_mandatory_data(wblock->block);
    if (pn->byte_swapped) {
        if_stats_mand->interface_id = GUINT32_SWAP_LE_BE(isb.interface_id);
        if_stats_mand->ts_high      = GUINT32_SWAP_LE_BE(isb.timestamp_high);
        if_stats_mand->ts_low       = GUINT32_SWAP_LE_BE(isb.timestamp_low);
    } else {
        if_stats_mand->interface_id = isb.interface_id;
        if_stats_mand->ts_high      = isb.timestamp_high;
        if_stats_mand->ts_low       = isb.timestamp_low;
    }
    pcapng_debug("pcapng_read_interface_statistics_block: interface_id %u", if_stats_mand->interface_id);

    /* Options */
    to_read = bh->block_total_length -
        (MIN_BLOCK_SIZE + (guint)sizeof isb);    /* fixed and variable part, including padding */

    /* Allocate enough memory to hold all options */
    opt_cont_buf_len = to_read;
    option_content = (guint8 *)g_try_malloc(opt_cont_buf_len);
    if (opt_cont_buf_len != 0 && option_content == NULL) {
        *err = ENOMEM;  /* we assume we're out of memory */
        return FALSE;
    }

    while (to_read != 0) {
        /* read option */
        bytes_read = pcapng_read_option(fh, pn, &oh, option_content, opt_cont_buf_len, to_read, err, err_info, "interface_statistics");
        if (bytes_read <= 0) {
            pcapng_debug("pcapng_read_interface_statistics_block: failed to read option");
            return FALSE;
        }
        to_read -= bytes_read;

        /* handle option content */
        switch (oh.option_code) {
            case(OPT_EOFOPT): /* opt_endofopt */
                if (to_read != 0) {
                    pcapng_debug("pcapng_read_interface_statistics_block: %u bytes after opt_endofopt", to_read);
                }
                /* padding should be ok here, just get out of this */
                to_read = 0;
                break;
            case(OPT_COMMENT): /* opt_comment */
                if (oh.option_length > 0 && oh.option_length < opt_cont_buf_len) {
                    tmp_content = g_strndup((char *)option_content, oh.option_length);
                    wtap_optionblock_set_option_string(wblock->block, OPT_COMMENT, tmp_content);
                    g_free(tmp_content);
                    pcapng_debug("pcapng_read_interface_statistics_block: opt_comment %s", tmp_content);
                } else {
                    pcapng_debug("pcapng_read_interface_statistics_block: opt_comment length %u seems strange", oh.option_length);
                }
                break;
            case(OPT_ISB_STARTTIME): /* isb_starttime */
                if (oh.option_length == 8) {
                    guint32 high, low;
                    guint64 starttime;

                    /*  Don't cast a guint8 * into a guint32 *--the
                     *  guint8 * may not point to something that's
                     *  aligned correctly.
                     */
                    memcpy(&high, option_content, sizeof(guint32));
                    memcpy(&low, option_content + sizeof(guint32), sizeof(guint32));
                    if (pn->byte_swapped) {
                        high = GUINT32_SWAP_LE_BE(high);
                        low = GUINT32_SWAP_LE_BE(low);
                    }
                    starttime = (guint64)high;
                    starttime <<= 32;
                    starttime += (guint64)low;
                    wtap_optionblock_set_option_uint64(wblock->block, OPT_ISB_STARTTIME, starttime);
                    pcapng_debug("pcapng_read_interface_statistics_block: isb_starttime %" G_GINT64_MODIFIER "u", starttime);
                } else {
                    pcapng_debug("pcapng_read_interface_statistics_block: isb_starttime length %u not 8 as expected", oh.option_length);
                }
                break;
            case(OPT_ISB_ENDTIME): /* isb_endtime */
                if (oh.option_length == 8) {
                    guint32 high, low;
                    guint64 endtime;

                    /*  Don't cast a guint8 * into a guint32 *--the
                     *  guint8 * may not point to something that's
                     *  aligned correctly.
                     */
                    memcpy(&high, option_content, sizeof(guint32));
                    memcpy(&low, option_content + sizeof(guint32), sizeof(guint32));
                    if (pn->byte_swapped) {
                        high = GUINT32_SWAP_LE_BE(high);
                        low = GUINT32_SWAP_LE_BE(low);
                    }
                    endtime = (guint64)high;
                    endtime <<= 32;
                    endtime += (guint64)low;
                    wtap_optionblock_set_option_uint64(wblock->block, OPT_ISB_ENDTIME, endtime);
                    pcapng_debug("pcapng_read_interface_statistics_block: isb_endtime %" G_GINT64_MODIFIER "u", endtime);
                } else {
                    pcapng_debug("pcapng_read_interface_statistics_block: isb_starttime length %u not 8 as expected", oh.option_length);
                }
                break;
            case(OPT_ISB_IFRECV): /* isb_ifrecv */
                if (oh.option_length == 8) {
                    guint64 ifrecv;
                    /*  Don't cast a guint8 * into a guint64 *--the
                     *  guint8 * may not point to something that's
                     *  aligned correctly.
                     */
                    memcpy(&ifrecv, option_content, sizeof(guint64));
                    if (pn->byte_swapped)
                        ifrecv = GUINT64_SWAP_LE_BE(ifrecv);
                    wtap_optionblock_set_option_uint64(wblock->block, OPT_ISB_IFRECV, ifrecv);
                    pcapng_debug("pcapng_read_interface_statistics_block: isb_ifrecv %" G_GINT64_MODIFIER "u", ifrecv);
                } else {
                    pcapng_debug("pcapng_read_interface_statistics_block: isb_ifrecv length %u not 8 as expected", oh.option_length);
                }
                break;
            case(OPT_ISB_IFDROP): /* isb_ifdrop */
                if (oh.option_length == 8) {
                    guint64 ifdrop;
                    /*  Don't cast a guint8 * into a guint64 *--the
                     *  guint8 * may not point to something that's
                     *  aligned correctly.
                     */
                    memcpy(&ifdrop, option_content, sizeof(guint64));
                    if (pn->byte_swapped)
                        ifdrop = GUINT64_SWAP_LE_BE(ifdrop);
                    wtap_optionblock_set_option_uint64(wblock->block, OPT_ISB_IFDROP, ifdrop);
                    pcapng_debug("pcapng_read_interface_statistics_block: isb_ifdrop %" G_GINT64_MODIFIER "u", ifdrop);
                } else {
                    pcapng_debug("pcapng_read_interface_statistics_block: isb_ifdrop length %u not 8 as expected", oh.option_length);
                }
                break;
            case(OPT_ISB_FILTERACCEPT): /* isb_filteraccept 6 */
                if (oh.option_length == 8) {
                    guint64 filteraccept;
                    /*  Don't cast a guint8 * into a guint64 *--the
                     *  guint8 * may not point to something that's
                     *  aligned correctly.
                     */
                    memcpy(&filteraccept, option_content, sizeof(guint64));
                    if (pn->byte_swapped)
                        filteraccept = GUINT64_SWAP_LE_BE(filteraccept);
                    wtap_optionblock_set_option_uint64(wblock->block, OPT_ISB_FILTERACCEPT, filteraccept);
                    pcapng_debug("pcapng_read_interface_statistics_block: isb_filteraccept %" G_GINT64_MODIFIER "u", filteraccept);
                } else {
                    pcapng_debug("pcapng_read_interface_statistics_block: isb_filteraccept length %u not 8 as expected", oh.option_length);
                }
                break;
            case(OPT_ISB_OSDROP): /* isb_osdrop 7 */
                if (oh.option_length == 8) {
                    guint64 osdrop;
                    /*  Don't cast a guint8 * into a guint64 *--the
                     *  guint8 * may not point to something that's
                     *  aligned correctly.
                     */
                    memcpy(&osdrop, option_content, sizeof(guint64));
                    if (pn->byte_swapped)
                        osdrop = GUINT64_SWAP_LE_BE(osdrop);
                    wtap_optionblock_set_option_uint64(wblock->block, OPT_ISB_OSDROP, osdrop);
                    pcapng_debug("pcapng_read_interface_statistics_block: isb_osdrop %" G_GINT64_MODIFIER "u", osdrop);
                } else {
                    pcapng_debug("pcapng_read_interface_statistics_block: isb_osdrop length %u not 8 as expected", oh.option_length);
                }
                break;
            case(OPT_ISB_USRDELIV): /* isb_usrdeliv 8  */
                if (oh.option_length == 8) {
                    guint64 usrdeliv;
                    /*  Don't cast a guint8 * into a guint64 *--the
                     *  guint8 * may not point to something that's
                     *  aligned correctly.
                     */
                    memcpy(&usrdeliv, option_content, sizeof(guint64));
                    if (pn->byte_swapped)
                        usrdeliv = GUINT64_SWAP_LE_BE(usrdeliv);
                    wtap_optionblock_set_option_uint64(wblock->block, OPT_ISB_USRDELIV, usrdeliv);
                    pcapng_debug("pcapng_read_interface_statistics_block: isb_usrdeliv %" G_GINT64_MODIFIER "u", usrdeliv);
                } else {
                    pcapng_debug("pcapng_read_interface_statistics_block: isb_usrdeliv length %u not 8 as expected", oh.option_length);
                }
                break;
            default:
                pcapng_debug("pcapng_read_interface_statistics_block: unknown option %u - ignoring %u bytes",
                              oh.option_code, oh.option_length);
        }
    }

    g_free(option_content);

    return TRUE;
}

static gboolean
pcapng_read_sysdig_event_block(FILE_T fh, pcapng_block_header_t *bh, pcapng_t *pn _U_, wtapng_block_t *wblock, int *err, gchar **err_info)
{
    unsigned block_read;
    guint32 block_total_length;
    guint16 cpu_id;
    guint64 wire_ts;
    guint64 ts;
    guint64 thread_id;
    guint32 event_len;
    guint16 event_type;

    if (bh->block_total_length < MIN_SYSDIG_EVENT_SIZE) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("%s: total block length %u is too small (< %u)", G_STRFUNC,
                                    bh->block_total_length, MIN_SYSDIG_EVENT_SIZE);
        return FALSE;
    }

    /* add padding bytes to "block total length" */
    /* (the "block total length" of some example files don't contain any padding bytes!) */
    if (bh->block_total_length % 4) {
        block_total_length = bh->block_total_length + 4 - (bh->block_total_length % 4);
    } else {
        block_total_length = bh->block_total_length;
    }

    pcapng_debug("pcapng_read_sysdig_event_block: block_total_length %u",
                  bh->block_total_length);

    wblock->packet_header->rec_type = REC_TYPE_FT_SPECIFIC_EVENT;
    wblock->packet_header->pseudo_header.sysdig_event.record_type = BLOCK_TYPE_SYSDIG_EVENT;
    wblock->packet_header->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN /*|WTAP_HAS_INTERFACE_ID */;
    wblock->packet_header->pkt_tsprec = WTAP_TSPREC_NSEC;

    block_read = block_total_length;

    if (!wtap_read_bytes(fh, &cpu_id, sizeof cpu_id, err, err_info)) {
        pcapng_debug("pcapng_read_packet_block: failed to read sysdig event cpu id");
        return FALSE;
    }
    if (!wtap_read_bytes(fh, &wire_ts, sizeof wire_ts, err, err_info)) {
        pcapng_debug("pcapng_read_packet_block: failed to read sysdig event timestamp");
        return FALSE;
    }
    if (!wtap_read_bytes(fh, &thread_id, sizeof thread_id, err, err_info)) {
        pcapng_debug("pcapng_read_packet_block: failed to read sysdig event thread id");
        return FALSE;
    }
    if (!wtap_read_bytes(fh, &event_len, sizeof event_len, err, err_info)) {
        pcapng_debug("pcapng_read_packet_block: failed to read sysdig event length");
        return FALSE;
    }
    if (!wtap_read_bytes(fh, &event_type, sizeof event_type, err, err_info)) {
        pcapng_debug("pcapng_read_packet_block: failed to read sysdig event type");
        return FALSE;
    }

    block_read -= MIN_SYSDIG_EVENT_SIZE;
    wblock->packet_header->pseudo_header.sysdig_event.byte_order = G_BYTE_ORDER;

    if (pn->byte_swapped) {
        wblock->packet_header->pseudo_header.sysdig_event.byte_order =
                G_BYTE_ORDER == G_LITTLE_ENDIAN ? G_BIG_ENDIAN : G_LITTLE_ENDIAN;
        wblock->packet_header->pseudo_header.sysdig_event.cpu_id = GUINT16_SWAP_LE_BE(cpu_id);
        ts = GUINT64_SWAP_LE_BE(wire_ts);
        wblock->packet_header->pseudo_header.sysdig_event.thread_id = GUINT64_SWAP_LE_BE(thread_id);
        wblock->packet_header->pseudo_header.sysdig_event.event_len = GUINT32_SWAP_LE_BE(event_len);
        wblock->packet_header->pseudo_header.sysdig_event.event_type = GUINT16_SWAP_LE_BE(event_type);
    } else {
        wblock->packet_header->pseudo_header.sysdig_event.cpu_id = cpu_id;
        ts = wire_ts;
        wblock->packet_header->pseudo_header.sysdig_event.thread_id = thread_id;
        wblock->packet_header->pseudo_header.sysdig_event.event_len = event_len;
        wblock->packet_header->pseudo_header.sysdig_event.event_type = event_type;
    }

    wblock->packet_header->ts.secs = (time_t) (ts / 1000000000);
    wblock->packet_header->ts.nsecs = (int) (ts % 1000000000);

    wblock->packet_header->caplen = block_read;
    wblock->packet_header->len = wblock->packet_header->pseudo_header.sysdig_event.event_len;

    /* "Sysdig Event Block" read event data */
    if (!wtap_read_packet_bytes(fh, wblock->frame_buffer,
                                block_read, err, err_info))
        return FALSE;

    return TRUE;
}

static gboolean
pcapng_read_unknown_block(FILE_T fh, pcapng_block_header_t *bh, pcapng_t *pn _U_, wtapng_block_t *wblock _U_, int *err, gchar **err_info)
{
    guint32 block_read;
    guint32 block_total_length;
#ifdef HAVE_PLUGINS
    block_handler *handler;
#endif

    if (bh->block_total_length < MIN_BLOCK_SIZE) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("pcapng_read_unknown_block: total block length %u of an unknown block type is less than the minimum block size %u",
                                    bh->block_total_length, MIN_BLOCK_SIZE);
        return FALSE;
    }

    /* add padding bytes to "block total length" */
    /* (the "block total length" of some example files don't contain any padding bytes!) */
    if (bh->block_total_length % 4) {
        block_total_length = bh->block_total_length + 4 - (bh->block_total_length % 4);
    } else {
        block_total_length = bh->block_total_length;
    }

    block_read = block_total_length - MIN_BLOCK_SIZE;

#ifdef HAVE_PLUGINS
    /*
     * Do we have a handler for this block type?
     */
    if (block_handlers != NULL &&
        (handler = (block_handler *)g_hash_table_lookup(block_handlers,
                                                        GUINT_TO_POINTER(bh->block_type))) != NULL) {
        /* Yes - call it to read this block type. */
        if (!handler->reader(fh, block_read, pn->byte_swapped,
                             wblock->packet_header, wblock->frame_buffer,
                             err, err_info))
            return FALSE;
    } else
#endif
    {
        /* No.  Skip over this unknown block. */
        if (!file_skip(fh, block_read, err)) {
            return FALSE;
        }
    }

    return TRUE;
}


static block_return_val
pcapng_read_block(wtap *wth, FILE_T fh, pcapng_t *pn, wtapng_block_t *wblock, int *err, gchar **err_info)
{
    block_return_val ret;
    pcapng_block_header_t bh;
    guint32 block_total_length;

    wblock->block = NULL;

    /* Try to read the (next) block header */
    if (!wtap_read_bytes_or_eof(fh, &bh, sizeof bh, err, err_info)) {
        pcapng_debug("pcapng_read_block: wtap_read_bytes_or_eof() failed, err = %d.", *err);
        if (*err == 0 || *err == WTAP_ERR_SHORT_READ) {
            /*
             * Short read or EOF.
             *
             * If we're reading this as part of an open,
             * the file is too short to be a pcap-ng file.
             *
             * If we're not, we treat PCAPNG_BLOCK_NOT_SHB and
             * PCAPNG_BLOCK_ERROR the same, so we can just return
             * PCAPNG_BLOCK_NOT_SHB in both cases.
             */
            return PCAPNG_BLOCK_NOT_SHB;
        }
        return PCAPNG_BLOCK_ERROR;
    }

    /*
     * SHBs have to be treated differently from other blocks, as we
     * might be doing an open and attempting to read a block at the
     * beginning of the file to see if it's a pcap-ng file or not,
     * and as they do not necessarily have the same byte order as
     * previous blocks.
     */
    if (bh.block_type == BLOCK_TYPE_SHB) {
        /*
         * BLOCK_TYPE_SHB has the same value regardless of byte order,
         * so we don't need to byte-swap it.
         */
        wblock->type = bh.block_type;

        pcapng_debug("pcapng_read_block: block_type 0x%x", bh.block_type);

        ret = pcapng_read_section_header_block(fh, &bh, pn, wblock, err, err_info);
        if (ret != PCAPNG_BLOCK_OK) {
            return ret;
        }
    } else {
        if (pn->byte_swapped) {
            bh.block_type         = GUINT32_SWAP_LE_BE(bh.block_type);
            bh.block_total_length = GUINT32_SWAP_LE_BE(bh.block_total_length);
        }

        wblock->type = bh.block_type;

        pcapng_debug("pcapng_read_block: block_type 0x%x", bh.block_type);

        if (!pn->shb_read) {
            /*
             * No SHB seen yet, so we're trying to read the first block
             * during an open, to see whether it's an SHB; if what we
             * read doesn't look like an SHB, this isn't a pcap-ng file.
             */
            *err = 0;
            *err_info = NULL;
            return PCAPNG_BLOCK_NOT_SHB;
        }
        switch (bh.block_type) {
            case(BLOCK_TYPE_IDB):
                if (!pcapng_read_if_descr_block(wth, fh, &bh, pn, wblock, err, err_info))
                    return PCAPNG_BLOCK_ERROR;
                break;
            case(BLOCK_TYPE_PB):
                if (!pcapng_read_packet_block(fh, &bh, pn, wblock, err, err_info, FALSE))
                    return PCAPNG_BLOCK_ERROR;
                break;
            case(BLOCK_TYPE_SPB):
                if (!pcapng_read_simple_packet_block(fh, &bh, pn, wblock, err, err_info))
                    return PCAPNG_BLOCK_ERROR;
                break;
            case(BLOCK_TYPE_EPB):
                if (!pcapng_read_packet_block(fh, &bh, pn, wblock, err, err_info, TRUE))
                    return PCAPNG_BLOCK_ERROR;
                break;
            case(BLOCK_TYPE_NRB):
                if (!pcapng_read_name_resolution_block(fh, &bh, pn, wblock, err, err_info))
                    return PCAPNG_BLOCK_ERROR;
                break;
            case(BLOCK_TYPE_ISB):
                if (!pcapng_read_interface_statistics_block(fh, &bh, pn, wblock, err, err_info))
                    return PCAPNG_BLOCK_ERROR;
                break;
            case(BLOCK_TYPE_SYSDIG_EVENT):
            /* case(BLOCK_TYPE_SYSDIG_EVF): */
                if (!pcapng_read_sysdig_event_block(fh, &bh, pn, wblock, err, err_info))
                    return PCAPNG_BLOCK_ERROR;
                break;
            default:
                pcapng_debug("pcapng_read_block: Unknown block_type: 0x%x (block ignored), block total length %d", bh.block_type, bh.block_total_length);
                if (!pcapng_read_unknown_block(fh, &bh, pn, wblock, err, err_info))
                    return PCAPNG_BLOCK_ERROR;
                break;
        }
    }

    /* sanity check: first and second block lengths must match */
    if (!wtap_read_bytes(fh, &block_total_length, sizeof block_total_length,
                         err, err_info)) {
        pcapng_debug("pcapng_check_block_trailer: couldn't read second block length");
        return PCAPNG_BLOCK_ERROR;
    }

    if (pn->byte_swapped)
        block_total_length = GUINT32_SWAP_LE_BE(block_total_length);

    if (block_total_length != bh.block_total_length) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("pcapng_check_block_trailer: total block lengths (first %u and second %u) don't match",
                                    bh.block_total_length, block_total_length);
        return PCAPNG_BLOCK_ERROR;
    }
    return PCAPNG_BLOCK_OK;
}

/* Process an IDB that we've just read. */
static void
pcapng_process_idb(wtap *wth, pcapng_t *pcapng, wtapng_block_t *wblock)
{
    wtap_optionblock_t int_data = wtap_optionblock_create(WTAP_OPTION_BLOCK_IF_DESCR);
    interface_info_t iface_info;
    wtapng_if_descr_mandatory_t *if_descr_mand = (wtapng_if_descr_mandatory_t*)wtap_optionblock_get_mandatory_data(int_data),
                                *wblock_if_descr_mand = (wtapng_if_descr_mandatory_t*)wtap_optionblock_get_mandatory_data(wblock->block);

    wtap_optionblock_copy_options(int_data, wblock->block);

    /* XXX if_tsoffset; opt 14  A 64 bits integer value that specifies an offset (in seconds)...*/
    /* Interface statistics */
    if_descr_mand->num_stat_entries = 0;
    if_descr_mand->interface_statistics = NULL;

    g_array_append_val(wth->interface_data, int_data);

    iface_info.wtap_encap = wblock_if_descr_mand->wtap_encap;
    iface_info.snap_len = wblock_if_descr_mand->snap_len;
    iface_info.time_units_per_second = wblock_if_descr_mand->time_units_per_second;
    iface_info.tsprecision = wblock_if_descr_mand->tsprecision;

    g_array_append_val(pcapng->interfaces, iface_info);
}

/* classic wtap: open capture file */
wtap_open_return_val
pcapng_open(wtap *wth, int *err, gchar **err_info)
{
    pcapng_t pn;
    wtapng_block_t wblock;
    pcapng_t *pcapng;
    pcapng_block_header_t bh;
    gint64 saved_offset;

    pn.shb_read = FALSE;
    /* we don't know the byte swapping of the file yet */
    pn.byte_swapped = FALSE;
    pn.if_fcslen = -1;
    pn.version_major = -1;
    pn.version_minor = -1;
    pn.interfaces = NULL;

    /* we don't expect any packet blocks yet */
    wblock.frame_buffer = NULL;
    wblock.packet_header = NULL;

    pcapng_debug("pcapng_open: opening file");
    /* read first block */
    switch (pcapng_read_block(wth, wth->fh, &pn, &wblock, err, err_info)) {

    case PCAPNG_BLOCK_OK:
        /* No problem */
        break;

    case PCAPNG_BLOCK_NOT_SHB:
        /* An error indicating that this isn't a pcap-ng file. */
        wtap_optionblock_free(wblock.block);
        *err = 0;
        *err_info = NULL;
        return WTAP_OPEN_NOT_MINE;

    case PCAPNG_BLOCK_ERROR:
        /* An I/O error, or this probably *is* a pcap-ng file but not a valid one. */
        wtap_optionblock_free(wblock.block);
        return WTAP_OPEN_ERROR;
    }

    /* first block must be a "Section Header Block" */
    if (wblock.type != BLOCK_TYPE_SHB) {
        /*
         * XXX - check for damage from transferring a file
         * between Windows and UN*X as text rather than
         * binary data?
         */
        pcapng_debug("pcapng_open: first block type %u not SHB", wblock.type);
        wtap_optionblock_free(wblock.block);
        return WTAP_OPEN_NOT_MINE;
    }
    pn.shb_read = TRUE;

    /*
     * At this point, we've decided this is a pcap-NG file, not
     * some other type of file, so we can't return WTAP_OPEN_NOT_MINE
     * past this point.
     */
    wtap_optionblock_copy_options(wth->shb_hdr, wblock.block);

    wth->file_encap = WTAP_ENCAP_UNKNOWN;
    wth->snapshot_length = 0;
    wth->file_tsprec = WTAP_TSPREC_UNKNOWN;
    pcapng = (pcapng_t *)g_malloc(sizeof(pcapng_t));
    wth->priv = (void *)pcapng;
    *pcapng = pn;
    pcapng->interfaces = g_array_new(FALSE, FALSE, sizeof(interface_info_t));

    wth->subtype_read = pcapng_read;
    wth->subtype_seek_read = pcapng_seek_read;
    wth->subtype_close = pcapng_close;
    wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_PCAPNG;

    /* Loop over all IDB:s that appear before any packets */
    while (1) {
        /* peek at next block */
        /* Try to read the (next) block header */
        saved_offset = file_tell(wth->fh);
        if (!wtap_read_bytes_or_eof(wth->fh, &bh, sizeof bh, err, err_info)) {
            if (*err == 0) {
                /* EOF */
                pcapng_debug("No more IDBs available...");
                break;
            }
            pcapng_debug("pcapng_open:  Check for more IDB:s, wtap_read_bytes_or_eof() failed, err = %d.", *err);
            return WTAP_OPEN_ERROR;
        }

        /* go back to where we were */
        file_seek(wth->fh, saved_offset, SEEK_SET, err);

        if (pn.byte_swapped) {
            bh.block_type         = GUINT32_SWAP_LE_BE(bh.block_type);
        }

        pcapng_debug("pcapng_open: Check for more IDB:s block_type 0x%x", bh.block_type);

        if (bh.block_type != BLOCK_TYPE_IDB) {
            break;  /* No more IDB:s */
        }
        if (pcapng_read_block(wth, wth->fh, &pn, &wblock, err, err_info) != PCAPNG_BLOCK_OK) {
            if (*err == 0) {
                pcapng_debug("No more IDBs available...");
                wtap_optionblock_free(wblock.block);
                break;
            } else {
                pcapng_debug("pcapng_open: couldn't read IDB");
                wtap_optionblock_free(wblock.block);
                return WTAP_OPEN_ERROR;
            }
        }
        pcapng_process_idb(wth, pcapng, &wblock);
        pcapng_debug("pcapng_open: Read IDB number_of_interfaces %u, wtap_encap %i",
                      wth->interface_data->len, wth->file_encap);
    }
    return WTAP_OPEN_MINE;
}


/* classic wtap: read packet */
static gboolean
pcapng_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
    pcapng_t *pcapng = (pcapng_t *)wth->priv;
    wtapng_block_t wblock;
    wtap_optionblock_t wtapng_if_descr;
    wtap_optionblock_t if_stats;
    wtapng_if_stats_mandatory_t *if_stats_mand_block, *if_stats_mand;
    wtapng_if_descr_mandatory_t *wtapng_if_descr_mand;

    wblock.frame_buffer  = wth->frame_buffer;
    wblock.packet_header = &wth->phdr;

    pcapng->add_new_ipv4 = wth->add_new_ipv4;
    pcapng->add_new_ipv6 = wth->add_new_ipv6;

    /* read next block */
    while (1) {
        *data_offset = file_tell(wth->fh);
        pcapng_debug("pcapng_read: data_offset is %" G_GINT64_MODIFIER "d", *data_offset);
        if (pcapng_read_block(wth, wth->fh, pcapng, &wblock, err, err_info) != PCAPNG_BLOCK_OK) {
            pcapng_debug("pcapng_read: data_offset is finally %" G_GINT64_MODIFIER "d", *data_offset);
            pcapng_debug("pcapng_read: couldn't read packet block");
            return FALSE;
        }

        switch (wblock.type) {

            case(BLOCK_TYPE_SHB):
                /* We don't currently support multi-section files. */
                wth->phdr.pkt_encap = WTAP_ENCAP_UNKNOWN;
                wth->phdr.pkt_tsprec = WTAP_TSPREC_UNKNOWN;
                *err = WTAP_ERR_UNSUPPORTED;
                *err_info = g_strdup_printf("pcapng: multi-section files not currently supported");
                return FALSE;

            case(BLOCK_TYPE_PB):
            case(BLOCK_TYPE_SPB):
            case(BLOCK_TYPE_EPB):
            case(BLOCK_TYPE_SYSDIG_EVENT):
            case(BLOCK_TYPE_SYSDIG_EVF):
                /* packet block - we've found a packet */
                goto got_packet;

            case(BLOCK_TYPE_IDB):
                /* A new interface */
                pcapng_debug("pcapng_read: block type BLOCK_TYPE_IDB");
                pcapng_process_idb(wth, pcapng, &wblock);
                break;

            case(BLOCK_TYPE_NRB):
                /* More name resolution entries */
                pcapng_debug("pcapng_read: block type BLOCK_TYPE_NRB");
                break;

            case(BLOCK_TYPE_ISB):
                /* Another interface statistics report */
                pcapng_debug("pcapng_read: block type BLOCK_TYPE_ISB");
                if_stats_mand_block = (wtapng_if_stats_mandatory_t*)wtap_optionblock_get_mandatory_data(wblock.block);
                if (wth->interface_data->len <= if_stats_mand_block->interface_id) {
                    pcapng_debug("pcapng_read: BLOCK_TYPE_ISB wblock.if_stats.interface_id %u >= number_of_interfaces", if_stats_mand_block->interface_id);
                } else {
                    /* Get the interface description */
                    wtapng_if_descr = g_array_index(wth->interface_data, wtap_optionblock_t, if_stats_mand_block->interface_id);
                    wtapng_if_descr_mand = (wtapng_if_descr_mandatory_t*)wtap_optionblock_get_mandatory_data(wtapng_if_descr);
                    if (wtapng_if_descr_mand->num_stat_entries == 0) {
                        /* First ISB found, no previous entry */
                        pcapng_debug("pcapng_read: block type BLOCK_TYPE_ISB. First ISB found, no previous entry");
                        wtapng_if_descr_mand->interface_statistics = g_array_new(FALSE, FALSE, sizeof(wtap_optionblock_t));
                    }

                    if_stats = wtap_optionblock_create(WTAP_OPTION_BLOCK_IF_STATS);
                    if_stats_mand = (wtapng_if_stats_mandatory_t*)wtap_optionblock_get_mandatory_data(if_stats);
                    if_stats_mand->interface_id  = if_stats_mand_block->interface_id;
                    if_stats_mand->ts_high       = if_stats_mand_block->ts_high;
                    if_stats_mand->ts_low        = if_stats_mand_block->ts_low;

                    wtap_optionblock_copy_options(if_stats, wblock.block);
                    g_array_append_val(wtapng_if_descr_mand->interface_statistics, if_stats);
                    wtapng_if_descr_mand->num_stat_entries++;
                }
                break;

            default:
                /* XXX - improve handling of "unknown" blocks */
                pcapng_debug("pcapng_read: Unknown block type 0x%08x", wblock.type);
                break;
        }
    }

got_packet:

    /*pcapng_debug("Read length: %u Packet length: %u", bytes_read, wth->phdr.caplen);*/
    pcapng_debug("pcapng_read: data_offset is finally %" G_GINT64_MODIFIER "d", *data_offset);

    return TRUE;
}


/* classic wtap: seek to file position and read packet */
static gboolean
pcapng_seek_read(wtap *wth, gint64 seek_off,
                 struct wtap_pkthdr *phdr, Buffer *buf,
                 int *err, gchar **err_info)
{
    pcapng_t *pcapng = (pcapng_t *)wth->priv;
    block_return_val ret;
    wtapng_block_t wblock;


    /* seek to the right file position */
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) < 0) {
        return FALSE;   /* Seek error */
    }
    pcapng_debug("pcapng_seek_read: reading at offset %" G_GINT64_MODIFIER "u", seek_off);

    wblock.frame_buffer = buf;
    wblock.packet_header = phdr;

    /* read the block */
    ret = pcapng_read_block(wth, wth->random_fh, pcapng, &wblock, err, err_info);
    wtap_optionblock_free(wblock.block);
    if (ret != PCAPNG_BLOCK_OK) {
        pcapng_debug("pcapng_seek_read: couldn't read packet block (err=%d).",
                      *err);
        return FALSE;
    }

    /* block must be a "Packet Block", an "Enhanced Packet Block",
       a "Simple Packet Block", or an event */
    if (wblock.type != BLOCK_TYPE_PB && wblock.type != BLOCK_TYPE_EPB &&
        wblock.type != BLOCK_TYPE_SPB &&
        wblock.type != BLOCK_TYPE_SYSDIG_EVENT && wblock.type != BLOCK_TYPE_SYSDIG_EVF) {
            pcapng_debug("pcapng_seek_read: block type %u not PB/EPB/SPB", wblock.type);
        return FALSE;
    }

    return TRUE;
}


/* classic wtap: close capture file */
static void
pcapng_close(wtap *wth)
{
    pcapng_t *pcapng = (pcapng_t *)wth->priv;

    pcapng_debug("pcapng_close: closing file");
    g_array_free(pcapng->interfaces, TRUE);
}


static gboolean
pcapng_write_section_header_block(wtap_dumper *wdh, int *err)
{
    pcapng_block_header_t bh;
    pcapng_section_header_block_t shb;
    const guint32 zero_pad = 0;
    gboolean have_options = FALSE;
    struct option option_hdr;                   /* guint16 type, guint16 value_length; */
    guint32 options_total_length = 0;
    guint32 comment_len = 0, shb_hardware_len = 0, shb_os_len = 0, shb_user_appl_len = 0;
    guint32 comment_pad_len = 0, shb_hardware_pad_len = 0, shb_os_pad_len = 0, shb_user_appl_pad_len = 0;
    char *opt_comment, *shb_hardware, *shb_os, *shb_user_appl;

    if (wdh->shb_hdr) {
        pcapng_debug("pcapng_write_section_header_block: Have shb_hdr");
        /* Check if we should write comment option */
        wtap_optionblock_get_option_string(wdh->shb_hdr, OPT_COMMENT, &opt_comment);
        if (opt_comment) {
            have_options = TRUE;
            comment_len = (guint32)strlen(opt_comment) & 0xffff;
            if ((comment_len % 4)) {
                comment_pad_len = 4 - (comment_len % 4);
            } else {
                comment_pad_len = 0;
            }
            options_total_length = options_total_length + comment_len + comment_pad_len + 4 /* comment options tag */ ;
        }

        /* Check if we should write shb_hardware option */
        wtap_optionblock_get_option_string(wdh->shb_hdr, OPT_SHB_HARDWARE, &shb_hardware);
        if (shb_hardware) {
            have_options = TRUE;
            shb_hardware_len = (guint32)strlen(shb_hardware) & 0xffff;
            if ((shb_hardware_len % 4)) {
                shb_hardware_pad_len = 4 - (shb_hardware_len % 4);
            } else {
                shb_hardware_pad_len = 0;
            }
            options_total_length = options_total_length + shb_hardware_len + shb_hardware_pad_len + 4 /* options tag */ ;
        }

        /* Check if we should write shb_os option */
        wtap_optionblock_get_option_string(wdh->shb_hdr, OPT_SHB_OS, &shb_os);
        if (shb_os) {
            have_options = TRUE;
            shb_os_len = (guint32)strlen(shb_os) & 0xffff;
            if ((shb_os_len % 4)) {
                shb_os_pad_len = 4 - (shb_os_len % 4);
            } else {
                shb_os_pad_len = 0;
            }
            options_total_length = options_total_length + shb_os_len + shb_os_pad_len + 4 /* options tag */ ;
        }

        /* Check if we should write shb_user_appl option */
        wtap_optionblock_get_option_string(wdh->shb_hdr, OPT_SHB_USERAPPL, &shb_user_appl);
        if (shb_user_appl) {
            have_options = TRUE;
            shb_user_appl_len = (guint32)strlen(shb_user_appl) & 0xffff;
            if ((shb_user_appl_len % 4)) {
                shb_user_appl_pad_len = 4 - (shb_user_appl_len % 4);
            } else {
                shb_user_appl_pad_len = 0;
            }
            options_total_length = options_total_length + shb_user_appl_len + shb_user_appl_pad_len + 4 /* options tag */ ;
        }

        if (have_options) {
            /* End-of-options tag */
            options_total_length += 4;
        }
    }

    /* write block header */
    bh.block_type = BLOCK_TYPE_SHB;
    bh.block_total_length = (guint32)(sizeof(bh) + sizeof(shb) + options_total_length + 4);
    pcapng_debug("pcapng_write_section_header_block: Total len %u, Options total len %u",bh.block_total_length, options_total_length);

    if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err))
        return FALSE;
    wdh->bytes_dumped += sizeof bh;

    /* write block fixed content */
    /* XXX - get these values from wblock? */
    shb.magic = 0x1A2B3C4D;
    shb.version_major = 1;
    shb.version_minor = 0;
    shb.section_length = -1;

    if (!wtap_dump_file_write(wdh, &shb, sizeof shb, err))
        return FALSE;
    wdh->bytes_dumped += sizeof shb;

    /* XXX - write (optional) block options
     * opt_comment  1
     * shb_hardware 2
     * shb_os       3
     * shb_user_appl 4
     */

    if (comment_len) {
        option_hdr.type          = OPT_COMMENT;
        option_hdr.value_length = comment_len;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;

        /* Write the comments string */
        pcapng_debug("pcapng_write_section_header_block, comment:'%s' comment_len %u comment_pad_len %u" , opt_comment, comment_len, comment_pad_len);
        if (!wtap_dump_file_write(wdh, opt_comment, comment_len, err))
            return FALSE;
        wdh->bytes_dumped += comment_len;

        /* write padding (if any) */
        if (comment_pad_len != 0) {
            if (!wtap_dump_file_write(wdh, &zero_pad, comment_pad_len, err))
                return FALSE;
            wdh->bytes_dumped += comment_pad_len;
        }
    }

    if (shb_hardware_len) {
        option_hdr.type          = OPT_SHB_HARDWARE;
        option_hdr.value_length = shb_hardware_len;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;

        /* Write the string */
        pcapng_debug("pcapng_write_section_header_block, shb_hardware:'%s' shb_hardware_len %u shb_hardware_pad_len %u" , shb_hardware, shb_hardware_len, shb_hardware_pad_len);
        if (!wtap_dump_file_write(wdh, shb_hardware, shb_hardware_len, err))
            return FALSE;
        wdh->bytes_dumped += shb_hardware_len;

        /* write padding (if any) */
        if (shb_hardware_pad_len != 0) {
            if (!wtap_dump_file_write(wdh, &zero_pad, shb_hardware_pad_len, err))
                return FALSE;
            wdh->bytes_dumped += shb_hardware_pad_len;
        }
    }

    if (shb_os_len) {
        option_hdr.type          = OPT_SHB_OS;
        option_hdr.value_length = shb_os_len;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;

        /* Write the string */
        pcapng_debug("pcapng_write_section_header_block, shb_os:'%s' shb_os_len %u shb_os_pad_len %u" , shb_os, shb_os_len, shb_os_pad_len);
        if (!wtap_dump_file_write(wdh, shb_os, shb_os_len, err))
            return FALSE;
        wdh->bytes_dumped += shb_os_len;

        /* write padding (if any) */
        if (shb_os_pad_len != 0) {
            if (!wtap_dump_file_write(wdh, &zero_pad, shb_os_pad_len, err))
                return FALSE;
            wdh->bytes_dumped += shb_os_pad_len;
        }
    }

    if (shb_user_appl_len) {
        option_hdr.type          = OPT_SHB_USERAPPL;
        option_hdr.value_length = shb_user_appl_len;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;

        /* Write the comments string */
        pcapng_debug("pcapng_write_section_header_block, shb_user_appl:'%s' shb_user_appl_len %u shb_user_appl_pad_len %u" , shb_user_appl, shb_user_appl_len, shb_user_appl_pad_len);
        if (!wtap_dump_file_write(wdh, shb_user_appl, shb_user_appl_len, err))
            return FALSE;
        wdh->bytes_dumped += shb_user_appl_len;

        /* write padding (if any) */
        if (shb_user_appl_pad_len != 0) {
            if (!wtap_dump_file_write(wdh, &zero_pad, shb_user_appl_pad_len, err))
                return FALSE;
            wdh->bytes_dumped += shb_user_appl_pad_len;
        }
    }

    /* Write end of options if we have otions */
    if (have_options) {
        option_hdr.type = OPT_EOFOPT;
        option_hdr.value_length = 0;
        if (!wtap_dump_file_write(wdh, &zero_pad, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;
    }

    /* write block footer */
    if (!wtap_dump_file_write(wdh, &bh.block_total_length,
                              sizeof bh.block_total_length, err))
        return FALSE;
    wdh->bytes_dumped += sizeof bh.block_total_length;

    return TRUE;
}


static gboolean
pcapng_write_if_descr_block(wtap_dumper *wdh, wtap_optionblock_t int_data, int *err)
{
    pcapng_block_header_t bh;
    pcapng_interface_description_block_t idb;
    const guint32 zero_pad = 0;
    gboolean have_options = FALSE;
    struct option option_hdr;                   /* guint16 type, guint16 value_length; */
    guint32 options_total_length = 0;
    guint32 comment_len = 0, if_name_len = 0, if_description_len = 0 , if_os_len = 0, if_filter_str_len = 0;
    guint32 comment_pad_len = 0, if_name_pad_len = 0, if_description_pad_len = 0, if_os_pad_len = 0, if_filter_str_pad_len = 0;
    wtapng_if_descr_mandatory_t* int_data_mand = (wtapng_if_descr_mandatory_t*)wtap_optionblock_get_mandatory_data(int_data);
    char *opt_comment, *if_name, *if_description, *if_os;
    guint64 if_speed;
    guint8 if_tsresol, if_fcslen;
    wtapng_if_descr_filter_t* if_filter;

    pcapng_debug("pcapng_write_if_descr_block: encap = %d (%s), snaplen = %d",
                  int_data_mand->link_type,
                  wtap_encap_string(wtap_pcap_encap_to_wtap_encap(int_data_mand->link_type)),
                  int_data_mand->snap_len);

    if (int_data_mand->link_type == (guint16)-1) {
        *err = WTAP_ERR_UNWRITABLE_ENCAP;
        return FALSE;
    }

    /* Calculate options length */
    wtap_optionblock_get_option_string(int_data, OPT_COMMENT, &opt_comment);
    if (opt_comment) {
        have_options = TRUE;
        comment_len = (guint32)strlen(opt_comment) & 0xffff;
        if ((comment_len % 4)) {
            comment_pad_len = 4 - (comment_len % 4);
        } else {
            comment_pad_len = 0;
        }
        options_total_length = options_total_length + comment_len + comment_pad_len + 4 /* comment options tag */ ;
    }

    /*
     * if_name        2  A UTF-8 string containing the name of the device used to capture data.
     */
    wtap_optionblock_get_option_string(int_data, OPT_IDB_NAME, &if_name);
    if (if_name) {
        have_options = TRUE;
        if_name_len = (guint32)strlen(if_name) & 0xffff;
        if ((if_name_len % 4)) {
            if_name_pad_len = 4 - (if_name_len % 4);
        } else {
            if_name_pad_len = 0;
        }
        options_total_length = options_total_length + if_name_len + if_name_pad_len + 4 /* comment options tag */ ;
    }

    /*
     * if_description 3  A UTF-8 string containing the description of the device used to capture data.
     */
    wtap_optionblock_get_option_string(int_data, OPT_IDB_DESCR, &if_description);
    if (if_description) {
        have_options = TRUE;
        if_description_len = (guint32)strlen(if_description) & 0xffff;
        if ((if_description_len % 4)) {
            if_description_pad_len = 4 - (if_description_len % 4);
        } else {
            if_description_pad_len = 0;
        }
        options_total_length = options_total_length + if_description_len + if_description_pad_len + 4 /* comment options tag */ ;
    }
    /* Currently not handled
     * if_IPv4addr    4  Interface network address and netmask.
     * if_IPv6addr    5  Interface network address and prefix length (stored in the last byte).
     * if_MACaddr     6  Interface Hardware MAC address (48 bits). 00 01 02 03 04 05
     * if_EUIaddr     7  Interface Hardware EUI address (64 bits), if available. TODO: give a good example
     */
    /*
     * if_speed       8  Interface speed (in bps). 100000000 for 100Mbps
     */
    wtap_optionblock_get_option_uint64(int_data, OPT_IDB_SPEED, &if_speed);
    if (if_speed != 0) {
        have_options = TRUE;
        options_total_length = options_total_length + 8 + 4;
    }
    /*
     * if_tsresol     9  Resolution of timestamps.
     */
    wtap_optionblock_get_option_uint8(int_data, OPT_IDB_TSRESOL, &if_tsresol);
    if (if_tsresol != 0) {
        have_options = TRUE;
        options_total_length = options_total_length + 4 + 4;
    }
    /* Not used
     * if_tzone      10  Time zone for GMT support (TODO: specify better). TODO: give a good example
     */
    /*
     * if_filter     11  The filter (e.g. "capture only TCP traffic") used to capture traffic.
     * The first byte of the Option Data keeps a code of the filter used (e.g. if this is a libpcap string, or BPF bytecode, and more).
     */
    wtap_optionblock_get_option_custom(int_data, OPT_IDB_FILTER, (void**)&if_filter);
    if (if_filter->if_filter_str) {
        have_options = TRUE;
        if_filter_str_len = (guint32)(strlen(if_filter->if_filter_str) + 1) & 0xffff;
        if ((if_filter_str_len % 4)) {
            if_filter_str_pad_len = 4 - (if_filter_str_len % 4);
        } else {
            if_filter_str_pad_len = 0;
        }
        options_total_length = options_total_length + if_filter_str_len + if_filter_str_pad_len + 4 /* comment options tag */ ;
    }
    /*
     * if_os         12  A UTF-8 string containing the name of the operating system of the machine in which this interface is installed.
     */
    wtap_optionblock_get_option_string(int_data, OPT_IDB_OS, &if_os);
    if (if_os) {
        have_options = TRUE;
        if_os_len = (guint32)strlen(if_os) & 0xffff;
        if ((if_os_len % 4)) {
            if_os_pad_len = 4 - (if_os_len % 4);
        } else {
            if_os_pad_len = 0;
        }
        options_total_length = options_total_length + if_os_len + if_os_pad_len + 4 /* comment options tag */ ;
    }
    /*
     * if_fcslen     13  An integer value that specified the length of the Frame Check Sequence (in bits) for this interface.
     * -1 if unknown or changes between packets, opt 13  An integer value that specified the length of the Frame Check Sequence (in bits) for this interface.
     */
    wtap_optionblock_get_option_uint8(int_data, OPT_IDB_FCSLEN, &if_fcslen);
    if (if_fcslen != 0) {
    }
    /* Not used
     * if_tsoffset   14  A 64 bits integer value that specifies an offset (in seconds) that must be added to the timestamp of each packet
     * to obtain the absolute timestamp of a packet. If the option is missing, the timestamps stored in the packet must be considered absolute timestamps.
     */

    if (have_options) {
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
    idb.linktype    = int_data_mand->link_type;
    idb.reserved    = 0;
    idb.snaplen     = int_data_mand->snap_len;

    if (!wtap_dump_file_write(wdh, &idb, sizeof idb, err))
        return FALSE;
    wdh->bytes_dumped += sizeof idb;

    /* XXX - write (optional) block options */
    if (comment_len != 0) {
        option_hdr.type         = OPT_COMMENT;
        option_hdr.value_length = comment_len;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;

        /* Write the comments string */
        pcapng_debug("pcapng_write_if_descr_block, comment:'%s' comment_len %u comment_pad_len %u" , opt_comment, comment_len, comment_pad_len);
        if (!wtap_dump_file_write(wdh, opt_comment, comment_len, err))
            return FALSE;
        wdh->bytes_dumped += comment_len;

        /* write padding (if any) */
        if (comment_pad_len != 0) {
            if (!wtap_dump_file_write(wdh, &zero_pad, comment_pad_len, err))
                return FALSE;
            wdh->bytes_dumped += comment_pad_len;
        }
    }
    /*
     * if_name        2  A UTF-8 string containing the name of the device used to capture data.
     */
    if (if_name_len !=0) {
        option_hdr.type = OPT_IDB_NAME;
        option_hdr.value_length = if_name_len;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;

        /* Write the comments string */
        pcapng_debug("pcapng_write_if_descr_block, if_name:'%s' if_name_len %u if_name_pad_len %u" , if_name, if_name_len, if_name_pad_len);
        if (!wtap_dump_file_write(wdh, if_name, if_name_len, err))
            return FALSE;
        wdh->bytes_dumped += if_name_len;

        /* write padding (if any) */
        if (if_name_pad_len != 0) {
            if (!wtap_dump_file_write(wdh, &zero_pad, if_name_pad_len, err))
                return FALSE;
            wdh->bytes_dumped += if_name_pad_len;
        }
    }
    /*
     * if_description 3  A UTF-8 string containing the description of the device used to capture data.
     */
    if (if_description_len != 0) {
        option_hdr.type          = OPT_IDB_NAME;
        option_hdr.value_length = if_description_len;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;

        /* Write the comments string */
        pcapng_debug("pcapng_write_if_descr_block, if_description:'%s' if_description_len %u if_description_pad_len %u" , if_description, if_description_len, if_description_pad_len);
        if (!wtap_dump_file_write(wdh, if_description, if_description_len, err))
            return FALSE;
        wdh->bytes_dumped += if_description_len;

        /* write padding (if any) */
        if (if_description_pad_len != 0) {
            if (!wtap_dump_file_write(wdh, &zero_pad, if_description_pad_len, err))
                return FALSE;
            wdh->bytes_dumped += if_description_pad_len;
        }
    }
    /* Currently not handled
     * if_IPv4addr    4  Interface network address and netmask.
     * if_IPv6addr    5  Interface network address and prefix length (stored in the last byte).
     * if_MACaddr     6  Interface Hardware MAC address (48 bits). 00 01 02 03 04 05
     * if_EUIaddr     7  Interface Hardware EUI address (64 bits), if available. TODO: give a good example
     */
    /*
     * if_speed       8  Interface speed (in bps). 100000000 for 100Mbps
     */
    if (if_speed != 0) {
        option_hdr.type          = OPT_IDB_SPEED;
        option_hdr.value_length = 8;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;

        /* Write the comments string */
        pcapng_debug("pcapng_write_if_descr_block: if_speed %" G_GINT64_MODIFIER "u (bps)", if_speed);
        if (!wtap_dump_file_write(wdh, &if_speed, sizeof(guint64), err))
            return FALSE;
        wdh->bytes_dumped += 8;
    }
    /*
     * if_tsresol     9  Resolution of timestamps.
     * default is 6 for microsecond resolution, opt 9  Resolution of timestamps.
     * If the Most Significant Bit is equal to zero, the remaining bits indicates
     * the resolution of the timestamp as as a negative power of 10
     */
    if (if_tsresol != 0) {
        option_hdr.type          = OPT_IDB_TSRESOL;
        option_hdr.value_length = 1;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;

        /* Write the time stamp resolution */
        pcapng_debug("pcapng_write_if_descr_block: if_tsresol %u", if_tsresol);
        if (!wtap_dump_file_write(wdh, &if_tsresol, 1, err))
            return FALSE;
        wdh->bytes_dumped += 1;
        if (!wtap_dump_file_write(wdh, &zero_pad, 3, err))
            return FALSE;
        wdh->bytes_dumped += 3;
    }
    /* not used
     * if_tzone      10  Time zone for GMT support (TODO: specify better). TODO: give a good example
     */
    /*
     * if_filter     11  The filter (e.g. "capture only TCP traffic") used to capture traffic.
     */
    /* Libpcap string variant */
    if (if_filter_str_len !=0) {
        option_hdr.type          = OPT_IDB_FILTER;
        option_hdr.value_length = if_filter_str_len;
        /* if_filter_str_len includes the leading byte indicating filter type (libpcap str or BPF code) */
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;

        /* Write the zero indicating libpcap filter variant */
        if (!wtap_dump_file_write(wdh, &zero_pad, 1, err))
            return FALSE;
        wdh->bytes_dumped += 1;

        /* Write the comments string */
        pcapng_debug("pcapng_write_if_descr_block, if_filter_str:'%s' if_filter_str_len %u if_filter_str_pad_len %u" , if_filter->if_filter_str, if_filter_str_len, if_filter_str_pad_len);
        /* if_filter_str_len includes the leading byte indicating filter type (libpcap str or BPF code) */
        if (!wtap_dump_file_write(wdh, if_filter->if_filter_str, if_filter_str_len-1, err))
            return FALSE;
        wdh->bytes_dumped += if_filter_str_len - 1;

        /* write padding (if any) */
        if (if_filter_str_pad_len != 0) {
            if (!wtap_dump_file_write(wdh, &zero_pad, if_filter_str_pad_len, err))
                return FALSE;
            wdh->bytes_dumped += if_filter_str_pad_len;
        }
    }
    /*
     * if_os         12  A UTF-8 string containing the name of the operating system of the machine in which this interface is installed.
     */
    if (if_os_len != 0) {
        option_hdr.type          = OPT_IDB_OS;
        option_hdr.value_length = if_os_len;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;

        /* Write the comments string */
        pcapng_debug("pcapng_write_if_descr_block, if_os:'%s' if_os_len %u if_os_pad_len %u" , if_os, if_os_len, if_os_pad_len);
        if (!wtap_dump_file_write(wdh, if_os, if_os_len, err))
            return FALSE;
        wdh->bytes_dumped += if_os_len;

        /* write padding (if any) */
        if (if_os_pad_len != 0) {
            if (!wtap_dump_file_write(wdh, &zero_pad, if_os_pad_len, err))
                return FALSE;
            wdh->bytes_dumped += if_os_pad_len;
        }
    }

    if (have_options) {
        option_hdr.type = OPT_EOFOPT;
        option_hdr.value_length = 0;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;
    }

    /*
     * if_fcslen     13  An integer value that specified the length of the Frame Check Sequence (in bits) for this interface.
     */
    /*
     * if_tsoffset   14  A 64 bits integer value that specifies an offset (in seconds) that must be added to the timestamp of each packet
     * to obtain the absolute timestamp of a packet. If the option is missing, the timestamps stored in the packet must be considered absolute timestamps.
     */

    /* write block footer */
    if (!wtap_dump_file_write(wdh, &bh.block_total_length,
                              sizeof bh.block_total_length, err))
        return FALSE;
    wdh->bytes_dumped += sizeof bh.block_total_length;

    return TRUE;
}

static gboolean
pcapng_write_interface_statistics_block(wtap_dumper *wdh, wtap_optionblock_t if_stats, int *err)
{

    pcapng_block_header_t bh;
    pcapng_interface_statistics_block_t isb;
    const guint32 zero_pad = 0;
    gboolean have_options = FALSE;
    struct option option_hdr;                   /* guint16 type, guint16 value_length; */
    guint32 options_total_length = 0;
    guint32 comment_len = 0;
    guint32 comment_pad_len = 0;
    char *opt_comment;
    guint64 isb_starttime, isb_endtime, isb_ifrecv, isb_ifdrop, isb_filteraccept, isb_osdrop, isb_usrdeliv;
    wtapng_if_stats_mandatory_t* if_stats_mand;

    pcapng_debug("pcapng_write_interface_statistics_block");

    wtap_optionblock_get_option_string(if_stats, OPT_COMMENT, &opt_comment);
    /* Calculate options length */
    if (opt_comment) {
        have_options = TRUE;
        comment_len = (guint32)strlen(opt_comment) & 0xffff;
        if ((comment_len % 4)) {
            comment_pad_len = 4 - (comment_len % 4);
        } else {
            comment_pad_len = 0;
        }
        options_total_length = options_total_length + comment_len + comment_pad_len + 4 /* comment options tag */ ;
    }

    wtap_optionblock_get_option_uint64(if_stats, OPT_ISB_STARTTIME, &isb_starttime);
    if (isb_starttime != 0) {
        have_options = TRUE;
        options_total_length = options_total_length + 8 + 4 /* options tag */ ;
    }
    wtap_optionblock_get_option_uint64(if_stats, OPT_ISB_ENDTIME, &isb_endtime);
    if (isb_endtime != 0) {
        have_options = TRUE;
        options_total_length = options_total_length + 8 + 4 /* options tag */ ;
    }
    wtap_optionblock_get_option_uint64(if_stats, OPT_ISB_IFRECV, &isb_ifrecv);
    if (isb_ifrecv != G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) {
        have_options = TRUE;
        options_total_length = options_total_length + 8 + 4 /* options tag */ ;
    }
    wtap_optionblock_get_option_uint64(if_stats, OPT_ISB_IFDROP, &isb_ifdrop);
    if (isb_ifdrop != G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) {
        have_options = TRUE;
        options_total_length = options_total_length + 8 + 4 /* options tag */ ;
    }
    wtap_optionblock_get_option_uint64(if_stats, OPT_ISB_FILTERACCEPT, &isb_filteraccept);
    if (isb_filteraccept != G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) {
        have_options = TRUE;
        options_total_length = options_total_length + 8 + 4 /* options tag */ ;
    }
    wtap_optionblock_get_option_uint64(if_stats, OPT_ISB_OSDROP, &isb_osdrop);
    if (isb_osdrop != G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) {
        have_options = TRUE;
        options_total_length = options_total_length + 8 + 4 /* options tag */ ;
    }
    wtap_optionblock_get_option_uint64(if_stats, OPT_ISB_USRDELIV, &isb_usrdeliv);
    if (isb_usrdeliv != G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) {
        have_options = TRUE;
        options_total_length = options_total_length + 8 + 4 /* options tag */ ;
    }

    /* write block header */
    if (have_options) {
        /* End-of-optios tag */
        options_total_length += 4;
    }

    /* write block header */
    bh.block_type = BLOCK_TYPE_ISB;
    bh.block_total_length = (guint32)(sizeof(bh) + sizeof(isb) + options_total_length + 4);

    if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err))
        return FALSE;
    wdh->bytes_dumped += sizeof bh;

    /* write block fixed content */
    if_stats_mand = (wtapng_if_stats_mandatory_t*)wtap_optionblock_get_mandatory_data(if_stats);

    isb.interface_id                = if_stats_mand->interface_id;
    isb.timestamp_high              = if_stats_mand->ts_high;
    isb.timestamp_low               = if_stats_mand->ts_low;

    if (!wtap_dump_file_write(wdh, &isb, sizeof isb, err))
        return FALSE;
    wdh->bytes_dumped += sizeof isb;

    /* write (optional) block options */
    if (comment_len) {
        option_hdr.type          = OPT_COMMENT;
        option_hdr.value_length  = comment_len;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;

        /* Write the comments string */
        pcapng_debug("pcapng_write_interface_statistics_block, comment:'%s' comment_len %u comment_pad_len %u" , opt_comment, comment_len, comment_pad_len);
        if (!wtap_dump_file_write(wdh, opt_comment, comment_len, err))
            return FALSE;
        wdh->bytes_dumped += comment_len;

        /* write padding (if any) */
        if (comment_pad_len != 0) {
            if (!wtap_dump_file_write(wdh, &zero_pad, comment_pad_len, err))
                return FALSE;
            wdh->bytes_dumped += comment_pad_len;
        }
    }
    /*guint64               isb_starttime */
    if (isb_starttime != 0) {
        guint32 high, low;

        option_hdr.type = OPT_ISB_STARTTIME;
        option_hdr.value_length = 8;
        high = (guint32)((isb_starttime>>32) & 0xffffffff);
        low = (guint32)(isb_starttime & 0xffffffff);
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;

        /* Write isb_starttime */
        pcapng_debug("pcapng_write_interface_statistics_block, isb_starttime: %" G_GINT64_MODIFIER "u" , isb_starttime);
        if (!wtap_dump_file_write(wdh, &high, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;
        if (!wtap_dump_file_write(wdh, &low, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;
    }
    /*guint64               isb_endtime */
    if (isb_endtime != 0) {
        guint32 high, low;

        option_hdr.type = OPT_ISB_ENDTIME;
        option_hdr.value_length = 8;
        high = (guint32)((isb_endtime>>32) & 0xffffffff);
        low = (guint32)(isb_endtime & 0xffffffff);
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;

        /* Write isb_endtime */
        pcapng_debug("pcapng_write_interface_statistics_block, isb_starttime: %" G_GINT64_MODIFIER "u" , isb_endtime);
        if (!wtap_dump_file_write(wdh, &high, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;
        if (!wtap_dump_file_write(wdh, &low, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;
    }
    /*guint64               isb_ifrecv;*/
    if (isb_ifrecv != G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) {
        option_hdr.type          = OPT_ISB_IFRECV;
        option_hdr.value_length  = 8;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;

        /* Write isb_ifrecv */
        pcapng_debug("pcapng_write_interface_statistics_block, isb_ifrecv: %" G_GINT64_MODIFIER "u" , isb_ifrecv);
        if (!wtap_dump_file_write(wdh, &isb_ifrecv, 8, err))
            return FALSE;
        wdh->bytes_dumped += 8;
    }
    /*guint64               isb_ifdrop;*/
    if (isb_ifdrop != G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) {
        option_hdr.type          = OPT_ISB_IFDROP;
        option_hdr.value_length  = 8;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;

        /* Write isb_ifdrop */
        pcapng_debug("pcapng_write_interface_statistics_block, isb_ifdrop: %" G_GINT64_MODIFIER "u" , isb_ifdrop);
        if (!wtap_dump_file_write(wdh, &isb_ifdrop, 8, err))
            return FALSE;
        wdh->bytes_dumped += 8;
    }
    /*guint64               isb_filteraccept;*/
    if (isb_filteraccept != G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) {
        option_hdr.type          = OPT_ISB_FILTERACCEPT;
        option_hdr.value_length  = 8;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;

        /* Write isb_filteraccept */
        pcapng_debug("pcapng_write_interface_statistics_block, isb_filteraccept: %" G_GINT64_MODIFIER "u" , isb_filteraccept);
        if (!wtap_dump_file_write(wdh, &isb_filteraccept, 8, err))
            return FALSE;
        wdh->bytes_dumped += 8;
    }
    /*guint64               isb_osdrop;*/
    if (isb_osdrop != G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) {
        option_hdr.type          = OPT_ISB_OSDROP;
        option_hdr.value_length  = 8;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;

        /* Write isb_osdrop */
        pcapng_debug("pcapng_write_interface_statistics_block, isb_osdrop: %" G_GINT64_MODIFIER "u" , isb_osdrop);
        if (!wtap_dump_file_write(wdh, &isb_osdrop, 8, err))
            return FALSE;
        wdh->bytes_dumped += 8;
    }
    /*guint64               isb_usrdeliv;*/
    if (isb_usrdeliv != G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF)) {
        option_hdr.type          = OPT_ISB_USRDELIV;
        option_hdr.value_length  = 8;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;

        /* Write isb_usrdeliv */
        pcapng_debug("pcapng_write_interface_statistics_block, isb_usrdeliv: %" G_GINT64_MODIFIER "u" , isb_usrdeliv);
        if (!wtap_dump_file_write(wdh, &isb_usrdeliv, 8, err))
            return FALSE;
        wdh->bytes_dumped += 8;
    }

    if (have_options) {
        option_hdr.type = OPT_EOFOPT;
        option_hdr.value_length = 0;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;
    }

    /* write block footer */
    if (!wtap_dump_file_write(wdh, &bh.block_total_length,
                              sizeof bh.block_total_length, err))
        return FALSE;
    wdh->bytes_dumped += sizeof bh.block_total_length;

    return TRUE;

}


static gboolean
pcapng_write_enhanced_packet_block(wtap_dumper *wdh,
                                   const struct wtap_pkthdr *phdr,
                                   const union wtap_pseudo_header *pseudo_header, const guint8 *pd, int *err)
{
    pcapng_block_header_t bh;
    pcapng_enhanced_packet_block_t epb;
    guint64 ts;
    const guint32 zero_pad = 0;
    guint32 pad_len;
    guint32 phdr_len;
    gboolean have_options = FALSE;
    guint32 options_total_length = 0;
    struct option option_hdr;
    guint32 comment_len = 0, comment_pad_len = 0;
    wtap_optionblock_t int_data;
    wtapng_if_descr_mandatory_t *int_data_mand;

    /* Don't write anything we're not willing to read. */
    if (phdr->caplen > WTAP_MAX_PACKET_SIZE) {
        *err = WTAP_ERR_PACKET_TOO_LARGE;
        return FALSE;
    }

    phdr_len = (guint32)pcap_get_phdr_size(phdr->pkt_encap, pseudo_header);
    if ((phdr_len + phdr->caplen) % 4) {
        pad_len = 4 - ((phdr_len + phdr->caplen) % 4);
    } else {
        pad_len = 0;
    }

    /* Check if we should write comment option */
    if (phdr->opt_comment) {
        have_options = TRUE;
        comment_len = (guint32)strlen(phdr->opt_comment) & 0xffff;
        if ((comment_len % 4)) {
            comment_pad_len = 4 - (comment_len % 4);
        } else {
            comment_pad_len = 0;
        }
        options_total_length = options_total_length + comment_len + comment_pad_len + 4 /* comment options tag */ ;
    }
    if (phdr->presence_flags & WTAP_HAS_PACK_FLAGS) {
        have_options = TRUE;
        options_total_length = options_total_length + 8;
    }
    if (have_options) {
        /* End-of options tag */
        options_total_length += 4;
    }

    /* write (enhanced) packet block header */
    bh.block_type = BLOCK_TYPE_EPB;
    bh.block_total_length = (guint32)sizeof(bh) + (guint32)sizeof(epb) + phdr_len + phdr->caplen + pad_len + options_total_length + 4;

    if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err))
        return FALSE;
    wdh->bytes_dumped += sizeof bh;

    /* write block fixed content */
    if (phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
        epb.interface_id        = phdr->interface_id;
    else {
        /*
         * XXX - we should support writing WTAP_ENCAP_PER_PACKET
         * data to pcap-NG files even if we *don't* have interface
         * IDs.
         */
        epb.interface_id        = 0;
    }
    /*
     * Split the 64-bit timestamp into two 32-bit pieces, using
     * the time stamp resolution for the interface.
     */
    if (epb.interface_id >= wdh->interface_data->len) {
        /*
         * Our caller is doing something bad.
         */
        *err = WTAP_ERR_INTERNAL;
        return FALSE;
    }
    int_data = g_array_index(wdh->interface_data, wtap_optionblock_t,
                             epb.interface_id);
    int_data_mand = (wtapng_if_descr_mandatory_t*)wtap_optionblock_get_mandatory_data(int_data);
    ts = ((guint64)phdr->ts.secs) * int_data_mand->time_units_per_second +
        (((guint64)phdr->ts.nsecs) * int_data_mand->time_units_per_second) / 1000000000;
    epb.timestamp_high      = (guint32)(ts >> 32);
    epb.timestamp_low       = (guint32)ts;
    epb.captured_len        = phdr->caplen + phdr_len;
    epb.packet_len          = phdr->len + phdr_len;

    if (!wtap_dump_file_write(wdh, &epb, sizeof epb, err))
        return FALSE;
    wdh->bytes_dumped += sizeof epb;

    /* write pseudo header */
    if (!pcap_write_phdr(wdh, phdr->pkt_encap, pseudo_header, err)) {
        return FALSE;
    }
    wdh->bytes_dumped += phdr_len;

    /* write packet data */
    if (!wtap_dump_file_write(wdh, pd, phdr->caplen, err))
        return FALSE;
    wdh->bytes_dumped += phdr->caplen;

    /* write padding (if any) */
    if (pad_len != 0) {
        if (!wtap_dump_file_write(wdh, &zero_pad, pad_len, err))
            return FALSE;
        wdh->bytes_dumped += pad_len;
    }

    /* XXX - write (optional) block options */
    /* options defined in Section 2.5 (Options)
     * Name           Code Length     Description
     * opt_comment    1    variable   A UTF-8 string containing a comment that is associated to the current block.
     *
     * Enhanced Packet Block options
     * epb_flags      2    4          A flags word containing link-layer information. A complete specification of
     *                                the allowed flags can be found in Appendix A (Packet Block Flags Word).
     * epb_hash       3    variable   This option contains a hash of the packet. The first byte specifies the hashing algorithm,
     *                                while the following bytes contain the actual hash, whose size depends on the hashing algorithm,
     *                                                                and hence from the value in the first bit. The hashing algorithm can be: 2s complement
     *                                                                (algorithm byte = 0, size=XXX), XOR (algorithm byte = 1, size=XXX), CRC32 (algorithm byte = 2, size = 4),
     *                                                                MD-5 (algorithm byte = 3, size=XXX), SHA-1 (algorithm byte = 4, size=XXX).
     *                                                                The hash covers only the packet, not the header added by the capture driver:
     *                                                                this gives the possibility to calculate it inside the network card.
     *                                                                The hash allows easier comparison/merging of different capture files, and reliable data transfer between the
     *                                                                data acquisition system and the capture library.
     * epb_dropcount   4   8          A 64bit integer value specifying the number of packets lost (by the interface and the operating system)
     *                                between this packet and the preceding one.
     * opt_endofopt    0   0          It delimits the end of the optional fields. This block cannot be repeated within a given list of options.
     */
    if (phdr->opt_comment) {
        option_hdr.type         = OPT_COMMENT;
        option_hdr.value_length = comment_len;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;

        /* Write the comments string */
        pcapng_debug("pcapng_write_enhanced_packet_block, comment:'%s' comment_len %u comment_pad_len %u" , phdr->opt_comment, comment_len, comment_pad_len);
        if (!wtap_dump_file_write(wdh, phdr->opt_comment, comment_len, err))
            return FALSE;
        wdh->bytes_dumped += comment_len;

        /* write padding (if any) */
        if (comment_pad_len != 0) {
            if (!wtap_dump_file_write(wdh, &zero_pad, comment_pad_len, err))
                return FALSE;
            wdh->bytes_dumped += comment_pad_len;
        }

        pcapng_debug("pcapng_write_enhanced_packet_block: Wrote Options comments: comment_len %u, comment_pad_len %u",
                      comment_len,
                      comment_pad_len);
    }
    if (phdr->presence_flags & WTAP_HAS_PACK_FLAGS) {
        option_hdr.type         = OPT_EPB_FLAGS;
        option_hdr.value_length = 4;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;
        if (!wtap_dump_file_write(wdh, &phdr->pack_flags, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;
        pcapng_debug("pcapng_write_enhanced_packet_block: Wrote Options packet flags: %x", phdr->pack_flags);
    }
    /* Write end of options if we have options */
    if (have_options) {
        if (!wtap_dump_file_write(wdh, &zero_pad, 4, err))
            return FALSE;
        wdh->bytes_dumped += 4;
    }

    /* write block footer */
    if (!wtap_dump_file_write(wdh, &bh.block_total_length,
                              sizeof bh.block_total_length, err))
        return FALSE;
    wdh->bytes_dumped += sizeof bh.block_total_length;

    return TRUE;
}

/* Arbitrary. */
#define NRES_REC_MAX_SIZE ((WTAP_MAX_PACKET_SIZE * 4) + 16)
static gboolean
pcapng_write_name_resolution_block(wtap_dumper *wdh, int *err)
{
    pcapng_block_header_t bh;
    pcapng_name_resolution_block_t nrb;
    guint8 *rec_data;
    guint32 rec_off;
    size_t hostnamelen;
    guint16 namelen;
    guint32 tot_rec_len;
    hashipv4_t *ipv4_hash_list_entry;
    hashipv6_t *ipv6_hash_list_entry;
    int i;

    if ((!wdh->addrinfo_lists) || ((!wdh->addrinfo_lists->ipv4_addr_list)&&(!wdh->addrinfo_lists->ipv6_addr_list))) {
        return TRUE;
    }

    rec_off = 8; /* block type + block total length */
    bh.block_type = BLOCK_TYPE_NRB;
    bh.block_total_length = rec_off + 8; /* end-of-record + block total length */
    rec_data = (guint8 *)g_malloc(NRES_REC_MAX_SIZE);

    if (wdh->addrinfo_lists->ipv4_addr_list){
        i = 0;
        ipv4_hash_list_entry = (hashipv4_t *)g_list_nth_data(wdh->addrinfo_lists->ipv4_addr_list, i);
        while(ipv4_hash_list_entry != NULL){

            nrb.record_type = NRES_IP4RECORD;
            hostnamelen = strlen(ipv4_hash_list_entry->name);
            if (hostnamelen > (G_MAXUINT16 - 4) - 1) {
                /*
                 * This won't fit in a maximum-sized record; discard it.
                 */
                i++;
                ipv4_hash_list_entry = (hashipv4_t *)g_list_nth_data(wdh->addrinfo_lists->ipv4_addr_list, i);
                continue;
            }
            namelen = (guint16)(hostnamelen + 1);
            nrb.record_len = 4 + namelen;
            tot_rec_len = 4 + nrb.record_len + PADDING4(nrb.record_len);

            if (rec_off + tot_rec_len > NRES_REC_MAX_SIZE){
                /* We know the total length now; copy the block header. */
                memcpy(rec_data, &bh, sizeof(bh));

                /* End of record */
                memset(rec_data + rec_off, 0, 4);
                rec_off += 4;

                memcpy(rec_data + rec_off, &bh.block_total_length, sizeof(bh.block_total_length));

                pcapng_debug("pcapng_write_name_resolution_block: Write bh.block_total_length bytes %d, rec_off %u", bh.block_total_length, rec_off);

                if (!wtap_dump_file_write(wdh, rec_data, bh.block_total_length, err)) {
                    g_free(rec_data);
                    return FALSE;
                }
                wdh->bytes_dumped += bh.block_total_length;

                /*Start a new NRB */
                rec_off = 8; /* block type + block total length */
                bh.block_type = BLOCK_TYPE_NRB;
                bh.block_total_length = rec_off + 8; /* end-of-record + block total length */

            }

            bh.block_total_length += tot_rec_len;
            memcpy(rec_data + rec_off, &nrb, sizeof(nrb));
            rec_off += 4;
            memcpy(rec_data + rec_off, &(ipv4_hash_list_entry->addr), 4);
            rec_off += 4;
            memcpy(rec_data + rec_off, ipv4_hash_list_entry->name, namelen);
            rec_off += namelen;
            memset(rec_data + rec_off, 0, PADDING4(namelen));
            rec_off += PADDING4(namelen);
            pcapng_debug("NRB: added IPv4 record for %s", ipv4_hash_list_entry->name);

            i++;
            ipv4_hash_list_entry = (hashipv4_t *)g_list_nth_data(wdh->addrinfo_lists->ipv4_addr_list, i);
        }
        g_list_free(wdh->addrinfo_lists->ipv4_addr_list);
        wdh->addrinfo_lists->ipv4_addr_list = NULL;
    }

    if (wdh->addrinfo_lists->ipv6_addr_list){
        i = 0;
        ipv6_hash_list_entry = (hashipv6_t *)g_list_nth_data(wdh->addrinfo_lists->ipv6_addr_list, i);
        while(ipv6_hash_list_entry != NULL){

            nrb.record_type = NRES_IP6RECORD;
            hostnamelen = strlen(ipv6_hash_list_entry->name);
            if (hostnamelen > (G_MAXUINT16 - 16) - 1) {
                /*
                 * This won't fit in a maximum-sized record; discard it.
                 */
                i++;
                ipv6_hash_list_entry = (hashipv6_t *)g_list_nth_data(wdh->addrinfo_lists->ipv6_addr_list, i);
                continue;
            }
            namelen = (guint16)(hostnamelen + 1);
            nrb.record_len = 16 + namelen;  /* 16 bytes IPv6 address length */
            /* 2 bytes record type, 2 bytes length field */
            tot_rec_len = 4 + nrb.record_len + PADDING4(nrb.record_len);

            if (rec_off + tot_rec_len > NRES_REC_MAX_SIZE){
                /*
                 * This record would overflow our maximum size for Name
                 * Resolution Blocks; write out all the records we created
                 * before it, and start a new NRB.
                 */

                /* First, copy the block header. */
                memcpy(rec_data, &bh, sizeof(bh));

                /* End of record */
                memset(rec_data + rec_off, 0, 4);
                rec_off += 4;

                memcpy(rec_data + rec_off, &bh.block_total_length, sizeof(bh.block_total_length));

                pcapng_debug("pcapng_write_name_resolution_block: Write bh.block_total_length bytes %d, rec_off %u", bh.block_total_length, rec_off);

                if (!wtap_dump_file_write(wdh, rec_data, bh.block_total_length, err)) {
                    g_free(rec_data);
                    return FALSE;
                }
                wdh->bytes_dumped += bh.block_total_length;

                /*Start a new NRB */
                rec_off = 8; /* block type + block total length */
                bh.block_type = BLOCK_TYPE_NRB;
                bh.block_total_length = rec_off + 8; /* end-of-record + block total length */

            }

            bh.block_total_length += tot_rec_len;
            memcpy(rec_data + rec_off, &nrb, sizeof(nrb));
            rec_off += 4;
            memcpy(rec_data + rec_off, &(ipv6_hash_list_entry->addr), 16);
            rec_off += 16;
            memcpy(rec_data + rec_off, ipv6_hash_list_entry->name, namelen);
            rec_off += namelen;
            memset(rec_data + rec_off, 0, PADDING4(namelen));
            rec_off += PADDING4(namelen);
            pcapng_debug("NRB: added IPv6 record for %s", ipv6_hash_list_entry->name);

            i++;
            ipv6_hash_list_entry = (hashipv6_t *)g_list_nth_data(wdh->addrinfo_lists->ipv6_addr_list, i);
        }
        g_list_free(wdh->addrinfo_lists->ipv6_addr_list);
        wdh->addrinfo_lists->ipv6_addr_list = NULL;
    }

    /* add options, if any */
    if (wdh->nrb_hdr) {
        gboolean have_options = FALSE;
        guint32 options_total_length = 0;
        struct option option_hdr;
        guint32 comment_len = 0, comment_pad_len = 0;
        wtap_optionblock_t nrb_hdr = wdh->nrb_hdr;
        guint32 prev_rec_off = rec_off;
        char* opt_comment;

        /* get lengths first to make sure we can fit this into the block */
        wtap_optionblock_get_option_string(nrb_hdr, OPT_COMMENT, &opt_comment);
        if (opt_comment) {
            have_options = TRUE;
            comment_len = (guint32)strlen(opt_comment) & 0xffff;
            if ((comment_len % 4)) {
                comment_pad_len = 4 - (comment_len % 4);
            } else {
                comment_pad_len = 0;
            }
            options_total_length = options_total_length + comment_len + comment_pad_len + 4 /* comment options tag */ ;
        }

        if (have_options) {
            /* End-of options tag */
            options_total_length += 4;

            if (rec_off + options_total_length > NRES_REC_MAX_SIZE) {
                /*
                 * This record would overflow our maximum size for Name
                 * Resolution Blocks; write out all the records we created
                 * before it, and start a new NRB.
                 */

                /* First, copy the block header. */
                memcpy(rec_data, &bh, sizeof(bh));

                /* End of record */
                memset(rec_data + rec_off, 0, 4);
                rec_off += 4;

                memcpy(rec_data + rec_off, &bh.block_total_length, sizeof(bh.block_total_length));

                pcapng_debug("pcapng_write_name_resolution_block: Write bh.block_total_length bytes %d, rec_off %u", bh.block_total_length, rec_off);

                if (!wtap_dump_file_write(wdh, rec_data, bh.block_total_length, err)) {
                    g_free(rec_data);
                    return FALSE;
                }
                wdh->bytes_dumped += bh.block_total_length;

                /*Start a new NRB */
                prev_rec_off = rec_off = 8; /* block type + block total length */
                bh.block_type = BLOCK_TYPE_NRB;
                bh.block_total_length = rec_off + 8; /* end-of-record + block total length */
            }

            bh.block_total_length += options_total_length;

            if (comment_len > 0) {
                option_hdr.type         = OPT_COMMENT;
                option_hdr.value_length = comment_len;

                memcpy(rec_data + rec_off, &option_hdr, sizeof(option_hdr));
                rec_off += (guint32)sizeof(option_hdr);

                /* Write the comments string */
                memcpy(rec_data + rec_off, opt_comment, comment_len);
                rec_off += comment_len;
                memset(rec_data + rec_off, 0, comment_pad_len);
                rec_off += comment_pad_len;

                pcapng_debug("pcapng_write_name_resolution_block: Wrote Options comments: comment_len %u, comment_pad_len %u",
                              comment_len,
                              comment_pad_len);
            }

            /* Write end of options */
            memset(rec_data + rec_off, 0, 4);
            rec_off += 4;

            /* sanity check */
            g_assert(options_total_length == rec_off - prev_rec_off);
        }
    }

    /* We know the total length now; copy the block header. */
    memcpy(rec_data, &bh, sizeof(bh));

    /* End of record */
    memset(rec_data + rec_off, 0, 4);
    rec_off += 4;

    memcpy(rec_data + rec_off, &bh.block_total_length, sizeof(bh.block_total_length));

    pcapng_debug("pcapng_write_name_resolution_block: Write bh.block_total_length bytes %d, rec_off %u", bh.block_total_length, rec_off);

    if (!wtap_dump_file_write(wdh, rec_data, bh.block_total_length, err)) {
        g_free(rec_data);
        return FALSE;
    }

    g_free(rec_data);
    wdh->bytes_dumped += bh.block_total_length;
    return TRUE;
}

static gboolean pcapng_dump(wtap_dumper *wdh,
                            const struct wtap_pkthdr *phdr,
                            const guint8 *pd, int *err, gchar **err_info _U_)
{
    const union wtap_pseudo_header *pseudo_header = &phdr->pseudo_header;
#ifdef HAVE_PLUGINS
    block_handler *handler;
#endif

    pcapng_debug("pcapng_dump: encap = %d (%s)",
                  phdr->pkt_encap,
                  wtap_encap_string(phdr->pkt_encap));

    switch (phdr->rec_type) {

        case REC_TYPE_PACKET:
            if (!pcapng_write_enhanced_packet_block(wdh, phdr, pseudo_header, pd, err)) {
                return FALSE;
            }
            break;

        case REC_TYPE_FT_SPECIFIC_EVENT:
        case REC_TYPE_FT_SPECIFIC_REPORT:
#ifdef HAVE_PLUGINS
            /*
             * Do we have a handler for this block type?
             */
            if (block_handlers != NULL &&
                (handler = (block_handler *)g_hash_table_lookup(block_handlers,
                                                                GUINT_TO_POINTER(pseudo_header->ftsrec.record_type))) != NULL) {
                /* Yes. Call it to write out this record. */
                if (!handler->writer(wdh, phdr, pd, err))
                    return FALSE;
            } else
#endif
            {
                /* No. */
                *err = WTAP_ERR_UNWRITABLE_REC_TYPE;
                return FALSE;
            }
            break;

        default:
            /* We don't support writing this record type. */
            *err = WTAP_ERR_UNWRITABLE_REC_TYPE;
            return FALSE;
    }

    return TRUE;
}


/* Finish writing to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean pcapng_dump_finish(wtap_dumper *wdh, int *err)
{
    guint i, j;

    /* Flush any hostname resolution info we may have */
    pcapng_write_name_resolution_block(wdh, err);

    for (i = 0; i < wdh->interface_data->len; i++) {

        /* Get the interface description */
        wtap_optionblock_t int_data;
        wtapng_if_descr_mandatory_t *int_data_mand;

        int_data = g_array_index(wdh->interface_data, wtap_optionblock_t, i);
        int_data_mand = (wtapng_if_descr_mandatory_t*)wtap_optionblock_get_mandatory_data(int_data);

        for (j = 0; j < int_data_mand->num_stat_entries; j++) {
            wtap_optionblock_t if_stats;

            if_stats = g_array_index(int_data_mand->interface_statistics, wtap_optionblock_t, j);
            pcapng_debug("pcapng_dump_finish: write ISB for interface %u", ((wtapng_if_stats_mandatory_t*)wtap_optionblock_get_mandatory_data(if_stats))->interface_id);
            if (!pcapng_write_interface_statistics_block(wdh, if_stats, err)) {
                return FALSE;
            }
        }
    }

    pcapng_debug("pcapng_dump_finish");
    return TRUE;
}


/* Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
gboolean
pcapng_dump_open(wtap_dumper *wdh, int *err)
{
    guint i;

    pcapng_debug("pcapng_dump_open");
    /* This is a pcapng file */
    wdh->subtype_write = pcapng_dump;
    wdh->subtype_finish = pcapng_dump_finish;

    if (wdh->interface_data->len == 0) {
        pcapng_debug("There are no interfaces. Can't handle that...");
        *err = WTAP_ERR_INTERNAL;
        return FALSE;
    }

    /* write the section header block */
    if (!pcapng_write_section_header_block(wdh, err)) {
        return FALSE;
    }
    pcapng_debug("pcapng_dump_open: wrote section header block.");

    /* Write the Interface description blocks */
    pcapng_debug("pcapng_dump_open: Number of IDB:s to write (number of interfaces) %u",
                  wdh->interface_data->len);

    for (i = 0; i < wdh->interface_data->len; i++) {

        /* Get the interface description */
        wtap_optionblock_t int_data;

        int_data = g_array_index(wdh->interface_data, wtap_optionblock_t, i);

        if (!pcapng_write_if_descr_block(wdh, int_data, err)) {
            return FALSE;
        }

    }

    return TRUE;
}


/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
int pcapng_dump_can_write_encap(int wtap_encap)
{
    pcapng_debug("pcapng_dump_can_write_encap: encap = %d (%s)",
                  wtap_encap,
                  wtap_encap_string(wtap_encap));

    /* Per-packet encapsulation is supported. */
    if (wtap_encap == WTAP_ENCAP_PER_PACKET)
        return 0;

    /* Make sure we can figure out this DLT type */
    if (wtap_wtap_encap_to_pcap_encap(wtap_encap) == -1)
        return WTAP_ERR_UNWRITABLE_ENCAP;

    return 0;
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
