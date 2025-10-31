/* ttl.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * TTX Logger (TTL) file format from TTTech Computertechnik AG decoder
 * for the Wiretap library.
 * You can find the PDF with the documentation of the format at
 * https://servicearea.tttech-auto.com/ (registration and approval required).
 *
 * Copyright (c) 2024 by Giovanni Musto <giovanni.musto@partner.italdesign.it>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#define WS_LOG_DOMAIN LOG_DOMAIN_WIRETAP

#include "ttl.h"

#include <string.h>
#include <epan/dissectors/packet-socketcan.h>
#include <wsutil/wslog.h>
#include <wsutil/report_message.h>
#include <wsutil/filesystem.h>
#include <wsutil/strtoi.h>
#include <wsutil/pint.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include "file_wrappers.h"
#include "wtap_module.h"

static const uint8_t ttl_magic[] = { 'T', 'T', 'L', ' ' };

static int ttl_file_type_subtype = -1;

#define TTL_ADDRESS_NAME_PREFS      "file_format_ttl_names"
#define TTL_ADDRESS_MASTER_PREFS    "file_format_ttl_masters"

void register_ttl(void);
static bool ttl_read(wtap* wth, wtap_rec* rec, int* err, char** err_info, int64_t* data_offset);
static bool ttl_seek_read(wtap* wth, int64_t seek_off, wtap_rec* rec, int* err, char** err_info);
static void ttl_close(wtap* wth);

typedef struct ttl_data {
    uint32_t    block_size;
    uint32_t    header_size;
    uint32_t    next_interface_id;

    GHashTable* address_to_iface_ht;
    GHashTable* address_to_master_ht;
    GHashTable* address_to_name_ht;
    GHashTable* segmented_frames_ht;
    GHashTable* reassembled_frames_ht;
} ttl_t;

typedef enum ttl_read_validity {
    VALIDITY_FH = 1,
    VALIDITY_BUF = 2
} ttl_read_validity_t;

/*
 * Usually, 'fh' is valid and is used by ttl_read_bytes, but in case of
 * segmented entries, 'buf' will be set to the reassembled nested entry.
 */
typedef struct ttl_read {
    union {
        FILE_T  fh;
        struct {
            uint8_t*    buf;
            uint32_t    size;
            uint32_t    cur_pos;
        };
    };
    ttl_read_validity_t validity;
} ttl_read_t;

/*
 * Values smaller than 0 indicate errors, 0 means OK, 1 means everything is
 * good, but the entry is unsupported. 2 means that the file looks corrupted
 * or unaligned and our caller should try to fix the situation.
 */
typedef enum {
    TTL_ERROR = -1,
    TTL_NO_ERROR = 0,
    TTL_UNSUPPORTED = 1,
    TTL_CORRUPTED = 2
} ttl_result_t;

static ttl_result_t ttl_read_entry(wtap* wth, wtap_rec* rec, int* err, char** err_info, ttl_read_t* in, int64_t offset, int64_t end);

/*
 * This struct is used to map the source address of an entry to an actual
 * interface.
 *
 * The field 'channelB' has meaning only for FlexRay and it means that the
 * packet belongs to FlexRay's Channel B.
 */
typedef struct ttl_addr_to_iface_entry {
    int         pkt_encap;
    bool        channelB;

    uint32_t    interface_id;
} ttl_addr_to_iface_entry_t;

typedef struct ttl_segmented_entry {
    uint64_t        timestamp;
    uint32_t        size;   /* Full size of the reassembled entry */
    uint32_t        type;   /* Type of the entry */

    uint32_t        size_so_far;
    uint8_t         next_segment;
    unsigned char*  buf;
} ttl_segmented_entry_t;

typedef struct ttl_reassembled_entry {
    uint64_t        timestamp;
    uint32_t        size;
    unsigned char*  buf;
} ttl_reassembled_entry_t;

void
ttl_free_segmented_entry(void* data) {
    ttl_segmented_entry_t* item;
    if (data != NULL) {
        item = (ttl_segmented_entry_t*)data;
        if (item->buf != NULL) {
            g_free(item->buf);
        }
        g_free(data);
    }
}

void
ttl_free_reassembled_entry(void* data) {
    ttl_reassembled_entry_t* item;
    if (data != NULL) {
        item = (ttl_reassembled_entry_t*)data;
        if (item->buf != NULL) {
            g_free(item->buf);
        }
        g_free(data);
    }
}

#ifndef OPT_EPB_FLAGS
    #define OPT_EPB_FLAGS   0x0002  /* Copied from pcapng.c */
#endif

#ifndef FLEXRAY_FRAME
    #define FLEXRAY_FRAME   0x01    /* Copied from packet-flexray.c */
#endif

#ifndef FLEXRAY_SYMBOL
    #define FLEXRAY_SYMBOL  0x02    /* Copied from packet-flexray.c */
#endif

static void
fix_endianness_ttl_fileheader(ttl_fileheader_t* header) {
    header->version = GUINT32_FROM_LE(header->version);
    header->block_size = GUINT32_FROM_LE(header->block_size);
    header->header_size = GUINT32_FROM_LE(header->header_size);
}

static void
fix_endianness_ttl_entryheader(ttl_entryheader_t* header) {
    header->size_type = GUINT16_FROM_LE(header->size_type);
    header->dest_addr = GUINT16_FROM_LE(header->dest_addr);
    header->src_addr = GUINT16_FROM_LE(header->src_addr);
    header->status_info = GUINT16_FROM_LE(header->status_info);
}

/*
 * This function returns the "master" address of coupled addresses.
 *
 * The output is different from the input in two cases:
 * 1. Coupled Ethernet channel, such as the slave side of a tap
 * 2. FlexRay Channel B, in order to couple it to Channel A
 *
 * In both cases, the returned address is the one of the "main" channel, so
 * that both addresses can be mapped to the same interface.
 *
 * If a hash table is passed as input, and an entry is present for addr,
 * then the stored result is returned. If there's no match, or no hash table
 * is passed as input, then the default behaviour applies:
 * - For FlexRay, always return corresponding Channel A if addr is Channel B.
 * - For Ethernet:
 *   - Return the same address if cascade is 0 (i.e. the channel belongs to
 *     the logger).
 *   - Return the address of the master if addr belongs to a tap (cascade != 0)
 */
uint16_t ttl_get_master_address(GHashTable* ht, uint16_t addr) {
    uint8_t function = ttl_addr_get_function(addr);

    if (ht != NULL) {
        void* master;
        if (g_hash_table_lookup_extended(ht, GUINT_TO_POINTER(addr), NULL, &master)) {
            return (uint16_t)GPOINTER_TO_UINT(master);
        }
    }

    if (ttl_addr_get_cascade(addr) == 0) {  /* The address refers to the logger itself */
        switch (ttl_addr_get_device(addr))
        {
        case TTL_LOGGER_DEVICE_FPGA:
            switch (function) {
            case TTL_LOGGER_FPGA_FUNCTION_ETHA_CH2:
            case TTL_LOGGER_FPGA_FUNCTION_ETHB_CH2:
                return (addr - 45);
            case TTL_LOGGER_FPGA_FUNCTION_ETHA_CH3:
            case TTL_LOGGER_FPGA_FUNCTION_ETHB_CH3:
                return (addr - 47);
            case TTL_LOGGER_FPGA_FUNCTION_FLEXRAY1B:
            case TTL_LOGGER_FPGA_FUNCTION_FLEXRAY2B:
            case TTL_LOGGER_FPGA_FUNCTION_FLEXRAY3B:
                return (addr - 1);
            default:
                break;
            }
            break;
        case TTL_LOGGER_DEVICE_TRICORE1:
        case TTL_LOGGER_DEVICE_TRICORE2:
        case TTL_LOGGER_DEVICE_TRICORE3:
            if (function == TTL_LOGGER_TRICORE_FUNCTION_FLEXRAYB) {
                return (addr - 1);
            }
            break;
        case TTL_LOGGER_DEVICE_TDA4x:
            if (function == TTL_LOGGER_TDA4x_FUNCTION_FLEXRAY1B) {
                return (addr - 1);
            }
            break;
        case TTL_LOGGER_DEVICE_FPGAA:
            if (function == TTL_LOGGER_FPGAA_FUNCTION_FLEXRAY1B) {
                return (addr - 1);
            }
            break;
        case TTL_LOGGER_DEVICE_FPGAB:
            switch (function) {
            case TTL_LOGGER_FPGAB_FUNCTION_ETHA_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_ETHB_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH1a_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH1b_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH2a_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH2b_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH3a_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH3b_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH4a_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH4b_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH5a_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH5b_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH6a_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH6b_CH2:
                return (addr - 14);
            default:
                break;
            }
            break;
        default:
            break;
        }
    }
    else {  /* The address refers to a TAP */
        switch (ttl_addr_get_device(addr)) {
        case TTL_TAP_DEVICE_PT15_FPGA:
            switch (function) {
            case TTL_PT15_FPGA_FUNCTION_BrdR1b:
            case TTL_PT15_FPGA_FUNCTION_BrdR2b:
            case TTL_PT15_FPGA_FUNCTION_BrdR3b:
            case TTL_PT15_FPGA_FUNCTION_BrdR4b:
            case TTL_PT15_FPGA_FUNCTION_BrdR5b:
            case TTL_PT15_FPGA_FUNCTION_BrdR6b:
                return (addr - 1);
            default:
                break;
            }
            break;
        case TTL_TAP_DEVICE_PT20_FPGA:
            switch (function) {
            case TTL_PT20_FPGA_FUNCTION_GbEth1b:
            case TTL_PT20_FPGA_FUNCTION_GbEth2b:
            case TTL_PT20_FPGA_FUNCTION_GbEth3b:
                return (addr - 1);
            default:
                break;
            }
            break;
        case TTL_TAP_DEVICE_PC3_FPGA:
            if (function == TTL_PC3_FPGA_FUNCTION_BrdR1b) {
                return (addr - 1);
            }
            break;
        case TTL_TAP_DEVICE_PC3_AURIX:
            switch (function) {
            case TTL_PC3_AURIX_FUNCTION_FLEXRAY1B:
            case TTL_PC3_AURIX_FUNCTION_FLEXRAY2B:
                return (addr - 1);
            default:
                break;
            }
            break;
        default:
            break;
        }
    }

    return addr;
}

bool ttl_is_chb_addr(uint16_t addr) {
    uint8_t function = ttl_addr_get_function(addr);

    if (ttl_addr_get_cascade(addr) == 0) {  /* The address refers to the logger itself */
        switch (ttl_addr_get_device(addr))
        {
        case TTL_LOGGER_DEVICE_FPGA:
            switch (function) {
            case TTL_LOGGER_FPGA_FUNCTION_FLEXRAY1B:
            case TTL_LOGGER_FPGA_FUNCTION_FLEXRAY2B:
            case TTL_LOGGER_FPGA_FUNCTION_FLEXRAY3B:
                return true;
            default:
                break;
            }
            break;
        case TTL_LOGGER_DEVICE_TRICORE1:
        case TTL_LOGGER_DEVICE_TRICORE2:
        case TTL_LOGGER_DEVICE_TRICORE3:
            if (function == TTL_LOGGER_TRICORE_FUNCTION_FLEXRAYB) {
                return true;
            }
            break;
        case TTL_LOGGER_DEVICE_FPGAA:
            if (function == TTL_LOGGER_FPGAA_FUNCTION_FLEXRAY1B) {
                return true;
            }
            break;
        default:
            break;
        }
    }
    else {  /* The address refers to a TAP */
        switch (ttl_addr_get_device(addr)) {
        case TTL_TAP_DEVICE_PC3_AURIX:
            switch (function) {
            case TTL_PC3_AURIX_FUNCTION_FLEXRAY1B:
            case TTL_PC3_AURIX_FUNCTION_FLEXRAY2B:
                return true;
            default:
                break;
            }
            break;
        default:
            break;
        }
    }

    return false;
}

int ttl_get_address_iface_type(uint16_t addr) {
    uint8_t function = ttl_addr_get_function(addr);

    if (ttl_addr_get_cascade(addr) == 0) { /* The address refers to the logger itself */
        switch (ttl_addr_get_device(addr))
        {
        case TTL_LOGGER_DEVICE_FPGA:
            switch (function) {
            case TTL_LOGGER_FPGA_FUNCTION_EXT0_MOST25:
            case TTL_LOGGER_FPGA_FUNCTION_EXT0_MOST150:
            case TTL_LOGGER_FPGA_FUNCTION_EXT1_MOST25:
                return WTAP_ENCAP_MOST;
            case TTL_LOGGER_FPGA_FUNCTION_ETHA_CH1:
            case TTL_LOGGER_FPGA_FUNCTION_ETHB_CH1:
            case TTL_LOGGER_FPGA_FUNCTION_ETHA_CH2:
            case TTL_LOGGER_FPGA_FUNCTION_ETHB_CH2:
            case TTL_LOGGER_FPGA_FUNCTION_ETHA_CH3:
            case TTL_LOGGER_FPGA_FUNCTION_ETHB_CH3:
                return WTAP_ENCAP_ETHERNET;
            case TTL_LOGGER_FPGA_FUNCTION_FLEXRAY1A:
            case TTL_LOGGER_FPGA_FUNCTION_FLEXRAY1B:
            case TTL_LOGGER_FPGA_FUNCTION_FLEXRAY2A:
            case TTL_LOGGER_FPGA_FUNCTION_FLEXRAY2B:
            case TTL_LOGGER_FPGA_FUNCTION_FLEXRAY3A:
            case TTL_LOGGER_FPGA_FUNCTION_FLEXRAY3B:
                return WTAP_ENCAP_FLEXRAY;
            case TTL_LOGGER_FPGA_FUNCTION_CAN1:
            case TTL_LOGGER_FPGA_FUNCTION_CAN2:
            case TTL_LOGGER_FPGA_FUNCTION_CAN3:
            case TTL_LOGGER_FPGA_FUNCTION_CAN4:
            case TTL_LOGGER_FPGA_FUNCTION_CAN5:
            case TTL_LOGGER_FPGA_FUNCTION_CAN6:
            case TTL_LOGGER_FPGA_FUNCTION_CAN7:
            case TTL_LOGGER_FPGA_FUNCTION_CAN8:
            case TTL_LOGGER_FPGA_FUNCTION_CAN9:
            case TTL_LOGGER_FPGA_FUNCTION_CAN10:
            case TTL_LOGGER_FPGA_FUNCTION_CAN11:
            case TTL_LOGGER_FPGA_FUNCTION_CAN12:
            case TTL_LOGGER_FPGA_FUNCTION_CAN13:
            case TTL_LOGGER_FPGA_FUNCTION_CAN14:
            case TTL_LOGGER_FPGA_FUNCTION_CAN15:
            case TTL_LOGGER_FPGA_FUNCTION_CAN16:
            case TTL_LOGGER_FPGA_FUNCTION_CAN17:
            case TTL_LOGGER_FPGA_FUNCTION_CAN18:
            case TTL_LOGGER_FPGA_FUNCTION_CAN19:
            case TTL_LOGGER_FPGA_FUNCTION_CAN20:
            case TTL_LOGGER_FPGA_FUNCTION_CAN21:
            case TTL_LOGGER_FPGA_FUNCTION_CAN22:
            case TTL_LOGGER_FPGA_FUNCTION_CAN23:
            case TTL_LOGGER_FPGA_FUNCTION_CAN24:
                return WTAP_ENCAP_SOCKETCAN;
            case TTL_LOGGER_FPGA_FUNCTION_LIN1:
            case TTL_LOGGER_FPGA_FUNCTION_LIN2:
            case TTL_LOGGER_FPGA_FUNCTION_LIN3:
            case TTL_LOGGER_FPGA_FUNCTION_LIN4:
            case TTL_LOGGER_FPGA_FUNCTION_LIN5:
            case TTL_LOGGER_FPGA_FUNCTION_LIN6:
            case TTL_LOGGER_FPGA_FUNCTION_LIN7:
            case TTL_LOGGER_FPGA_FUNCTION_LIN8:
            case TTL_LOGGER_FPGA_FUNCTION_LIN9:
            case TTL_LOGGER_FPGA_FUNCTION_LIN10:
            case TTL_LOGGER_FPGA_FUNCTION_LIN11:
            case TTL_LOGGER_FPGA_FUNCTION_LIN12:
                return WTAP_ENCAP_LIN;
            default:
                break;
            }

            break;
        case TTL_LOGGER_DEVICE_ATOM:
            switch (function) {
            case TTL_LOGGER_ATOM_FUNCTION_ETHA:
            case TTL_LOGGER_ATOM_FUNCTION_ETHB:
                return WTAP_ENCAP_ETHERNET;
            default:
                break;
            }

            break;
        case TTL_LOGGER_DEVICE_TRICORE1:
            switch (function) {
            case TTL_LOGGER_TRICORE1_FUNCTION_FLEXRAY1A:
            case TTL_LOGGER_TRICORE1_FUNCTION_FLEXRAY1B:
            case TTL_LOGGER_TRICORE1_FUNCTION_FLEXRAY1:
            case TTL_LOGGER_TRICORE1_FUNCTION_FLEXRAY1AB:
                return WTAP_ENCAP_FLEXRAY;
            case TTL_LOGGER_TRICORE1_FUNCTION_CAN1:
            case TTL_LOGGER_TRICORE1_FUNCTION_CAN2:
            case TTL_LOGGER_TRICORE1_FUNCTION_CAN3:
            case TTL_LOGGER_TRICORE1_FUNCTION_CAN4:
                return WTAP_ENCAP_SOCKETCAN;
            default:
                break;
            }

            break;
        case TTL_LOGGER_DEVICE_TRICORE2:
            switch (function) {
            case TTL_LOGGER_TRICORE2_FUNCTION_FLEXRAY2A:
            case TTL_LOGGER_TRICORE2_FUNCTION_FLEXRAY2B:
            case TTL_LOGGER_TRICORE2_FUNCTION_FLEXRAY2:
            case TTL_LOGGER_TRICORE2_FUNCTION_FLEXRAY2AB:
                return WTAP_ENCAP_FLEXRAY;
            case TTL_LOGGER_TRICORE2_FUNCTION_CAN6:
            case TTL_LOGGER_TRICORE2_FUNCTION_CAN7:
            case TTL_LOGGER_TRICORE2_FUNCTION_CAN10:
            case TTL_LOGGER_TRICORE2_FUNCTION_CAN12:
                return WTAP_ENCAP_SOCKETCAN;
            default:
                break;
            }

            break;
        case TTL_LOGGER_DEVICE_TRICORE3:
            switch (function) {
            case TTL_LOGGER_TRICORE3_FUNCTION_FLEXRAY3A:
            case TTL_LOGGER_TRICORE3_FUNCTION_FLEXRAY3B:
            case TTL_LOGGER_TRICORE3_FUNCTION_FLEXRAY3:
            case TTL_LOGGER_TRICORE3_FUNCTION_FLEXRAY3AB:
                return WTAP_ENCAP_FLEXRAY;
            case TTL_LOGGER_TRICORE3_FUNCTION_CAN5:
            case TTL_LOGGER_TRICORE3_FUNCTION_CAN8:
            case TTL_LOGGER_TRICORE3_FUNCTION_CAN9:
            case TTL_LOGGER_TRICORE3_FUNCTION_CAN11:
                return WTAP_ENCAP_SOCKETCAN;
            default:
                break;
            }

            break;
        case TTL_LOGGER_DEVICE_TDA4x:
            switch (function) {
            case TTL_LOGGER_TDA4x_FUNCTION_CAN1:
            case TTL_LOGGER_TDA4x_FUNCTION_CAN2:
            case TTL_LOGGER_TDA4x_FUNCTION_CAN3:
            case TTL_LOGGER_TDA4x_FUNCTION_CAN4:
            case TTL_LOGGER_TDA4x_FUNCTION_CAN5:
            case TTL_LOGGER_TDA4x_FUNCTION_CAN6:
            case TTL_LOGGER_TDA4x_FUNCTION_CAN7:
            case TTL_LOGGER_TDA4x_FUNCTION_CAN8:
            case TTL_LOGGER_TDA4x_FUNCTION_CAN9:
            case TTL_LOGGER_TDA4x_FUNCTION_CAN10:
            case TTL_LOGGER_TDA4x_FUNCTION_CAN11:
            case TTL_LOGGER_TDA4x_FUNCTION_CAN12:
            case TTL_LOGGER_TDA4x_FUNCTION_CAN13:
            case TTL_LOGGER_TDA4x_FUNCTION_CAN14:
                return WTAP_ENCAP_SOCKETCAN;
            default:
                break;
            }

            break;
        case TTL_LOGGER_DEVICE_FPGAA:
            switch (function) {
            case TTL_LOGGER_FPGAA_FUNCTION_CAN1:
            case TTL_LOGGER_FPGAA_FUNCTION_CAN2:
            case TTL_LOGGER_FPGAA_FUNCTION_CAN3:
            case TTL_LOGGER_FPGAA_FUNCTION_CAN4:
            case TTL_LOGGER_FPGAA_FUNCTION_CAN5:
            case TTL_LOGGER_FPGAA_FUNCTION_CAN6:
            case TTL_LOGGER_FPGAA_FUNCTION_CAN7:
            case TTL_LOGGER_FPGAA_FUNCTION_CAN8:
            case TTL_LOGGER_FPGAA_FUNCTION_CAN9:
            case TTL_LOGGER_FPGAA_FUNCTION_CAN10:
            case TTL_LOGGER_FPGAA_FUNCTION_CAN11:
            case TTL_LOGGER_FPGAA_FUNCTION_CAN12:
            case TTL_LOGGER_FPGAA_FUNCTION_CAN13:
            case TTL_LOGGER_FPGAA_FUNCTION_CAN14:
                return WTAP_ENCAP_SOCKETCAN;
            case TTL_LOGGER_FPGAA_FUNCTION_LIN1:
            case TTL_LOGGER_FPGAA_FUNCTION_LIN2:
            case TTL_LOGGER_FPGAA_FUNCTION_LIN3:
            case TTL_LOGGER_FPGAA_FUNCTION_LIN4:
            case TTL_LOGGER_FPGAA_FUNCTION_LIN5:
            case TTL_LOGGER_FPGAA_FUNCTION_LIN6:
            case TTL_LOGGER_FPGAA_FUNCTION_LIN7:
            case TTL_LOGGER_FPGAA_FUNCTION_LIN8:
            case TTL_LOGGER_FPGAA_FUNCTION_LIN9:
            case TTL_LOGGER_FPGAA_FUNCTION_LIN10:
            case TTL_LOGGER_FPGAA_FUNCTION_LIN11:
            case TTL_LOGGER_FPGAA_FUNCTION_LIN12:
            case TTL_LOGGER_FPGAA_FUNCTION_LIN13:
            case TTL_LOGGER_FPGAA_FUNCTION_LIN14:
            case TTL_LOGGER_FPGAA_FUNCTION_LIN15:
            case TTL_LOGGER_FPGAA_FUNCTION_LIN16:
                return WTAP_ENCAP_LIN;
            case TTL_LOGGER_FPGAA_FUNCTION_FLEXRAY1A:
            case TTL_LOGGER_FPGAA_FUNCTION_FLEXRAY1B:
                return WTAP_ENCAP_FLEXRAY;
            default:
                break;
            }

            break;
        case TTL_LOGGER_DEVICE_FPGAB:
            switch (function) {
            case TTL_LOGGER_FPGAB_FUNCTION_ETHA_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_ETHB_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH1a_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH1b_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH2a_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH2b_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH3a_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH3b_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH4a_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH4b_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH5a_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH5b_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH6a_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH6b_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_ETHA_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_ETHB_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH1a_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH1b_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH2a_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH2b_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH3a_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH3b_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH4a_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH4b_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH5a_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH5b_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH6a_CH2:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH6b_CH2:
                return WTAP_ENCAP_ETHERNET;
            default:
                break;
            }

            break;
        default:
            break;
        }
    }
    else {  /* The address refers to a TAP */
        switch (ttl_addr_get_device(addr)) {
        case TTL_TAP_DEVICE_PT15_FPGA:
            switch (function) {
            case TTL_PT15_FPGA_FUNCTION_CAN1:
            case TTL_PT15_FPGA_FUNCTION_CAN2:
                return WTAP_ENCAP_SOCKETCAN;
            case TTL_PT15_FPGA_FUNCTION_BrdR1a:
            case TTL_PT15_FPGA_FUNCTION_BrdR1b:
            case TTL_PT15_FPGA_FUNCTION_BrdR2a:
            case TTL_PT15_FPGA_FUNCTION_BrdR2b:
            case TTL_PT15_FPGA_FUNCTION_BrdR3a:
            case TTL_PT15_FPGA_FUNCTION_BrdR3b:
            case TTL_PT15_FPGA_FUNCTION_BrdR4a:
            case TTL_PT15_FPGA_FUNCTION_BrdR4b:
            case TTL_PT15_FPGA_FUNCTION_BrdR5a:
            case TTL_PT15_FPGA_FUNCTION_BrdR5b:
            case TTL_PT15_FPGA_FUNCTION_BrdR6a:
            case TTL_PT15_FPGA_FUNCTION_BrdR6b:
                return WTAP_ENCAP_ETHERNET;
            case TTL_PT15_FPGA_FUNCTION_MDIO:   /* TODO: Support this */
            default:
                break;
            }

            break;
        case TTL_TAP_DEVICE_PT20_FPGA:
            switch (function) {
            case TTL_PT20_FPGA_FUNCTION_CAN1:
            case TTL_PT20_FPGA_FUNCTION_CAN2:
            case TTL_PT20_FPGA_FUNCTION_CAN3:
            case TTL_PT20_FPGA_FUNCTION_CAN4:
            case TTL_PT20_FPGA_FUNCTION_CAN5:
                return WTAP_ENCAP_SOCKETCAN;
            case TTL_PT20_FPGA_FUNCTION_GbEth1a:
            case TTL_PT20_FPGA_FUNCTION_GbEth1b:
            case TTL_PT20_FPGA_FUNCTION_GbEth2a:
            case TTL_PT20_FPGA_FUNCTION_GbEth2b:
            case TTL_PT20_FPGA_FUNCTION_GbEth3a:
            case TTL_PT20_FPGA_FUNCTION_GbEth3b:
                return WTAP_ENCAP_ETHERNET;
            case TTL_PT20_FPGA_FUNCTION_MDIO:   /* TODO: Support this */
            default:
                break;
            }

            break;
        case TTL_TAP_DEVICE_PC3_FPGA:
            switch (function) {
            case TTL_PC3_FPGA_FUNCTION_BrdR1a:
            case TTL_PC3_FPGA_FUNCTION_BrdR1b:
                return WTAP_ENCAP_ETHERNET;
            default:
                break;
            }

            break;
        case TTL_TAP_DEVICE_PC3_AURIX:
            switch (function) {
            case TTL_PC3_AURIX_FUNCTION_CAN1:
            case TTL_PC3_AURIX_FUNCTION_CAN2:
            case TTL_PC3_AURIX_FUNCTION_CAN3:
            case TTL_PC3_AURIX_FUNCTION_CAN4:
                return WTAP_ENCAP_SOCKETCAN;
            case TTL_PC3_AURIX_FUNCTION_FLEXRAY1A:
            case TTL_PC3_AURIX_FUNCTION_FLEXRAY1B:
            case TTL_PC3_AURIX_FUNCTION_FLEXRAY2A:
            case TTL_PC3_AURIX_FUNCTION_FLEXRAY2B:
                return WTAP_ENCAP_FLEXRAY;
            default:
                break;
            }

            break;
        case TTL_TAP_DEVICE_ZELDA_CANFD:
            switch (function) {
            case TTL_TAP_DEVICE_ZELDA_CANFD1:
            case TTL_TAP_DEVICE_ZELDA_CANFD2:
            case TTL_TAP_DEVICE_ZELDA_CANFD3:
            case TTL_TAP_DEVICE_ZELDA_CANFD4:
            case TTL_TAP_DEVICE_ZELDA_CANFD5:
            case TTL_TAP_DEVICE_ZELDA_CANFD6:
            case TTL_TAP_DEVICE_ZELDA_CANFD7:
            case TTL_TAP_DEVICE_ZELDA_CANFD8:
            case TTL_TAP_DEVICE_ZELDA_CANFD9:
            case TTL_TAP_DEVICE_ZELDA_CANFD10:
            case TTL_TAP_DEVICE_ZELDA_CANFD11:
            case TTL_TAP_DEVICE_ZELDA_CANFD12:
            case TTL_TAP_DEVICE_ZELDA_CANFD13:
            case TTL_TAP_DEVICE_ZELDA_CANFD14:
            case TTL_TAP_DEVICE_ZELDA_CANFD15:
                return WTAP_ENCAP_SOCKETCAN;
            default:
                break;
            }

            break;
        case TTL_TAP_DEVICE_ZELDA_LIN:
            switch (function) {
            case TTL_TAP_DEVICE_ZELDA_LIN1:
            case TTL_TAP_DEVICE_ZELDA_LIN2:
            case TTL_TAP_DEVICE_ZELDA_LIN3:
            case TTL_TAP_DEVICE_ZELDA_LIN4:
            case TTL_TAP_DEVICE_ZELDA_LIN5:
            case TTL_TAP_DEVICE_ZELDA_LIN6:
            case TTL_TAP_DEVICE_ZELDA_LIN7:
            case TTL_TAP_DEVICE_ZELDA_LIN8:
            case TTL_TAP_DEVICE_ZELDA_LIN9:
            case TTL_TAP_DEVICE_ZELDA_LIN10:
            case TTL_TAP_DEVICE_ZELDA_LIN11:
            case TTL_TAP_DEVICE_ZELDA_LIN12:
            case TTL_TAP_DEVICE_ZELDA_LIN13:
            case TTL_TAP_DEVICE_ZELDA_LIN14:
            case TTL_TAP_DEVICE_ZELDA_LIN15:
            case TTL_TAP_DEVICE_ZELDA_LIN16:
            case TTL_TAP_DEVICE_ZELDA_LIN17:
            case TTL_TAP_DEVICE_ZELDA_LIN18:
            case TTL_TAP_DEVICE_ZELDA_LIN19:
            case TTL_TAP_DEVICE_ZELDA_LIN20:
            case TTL_TAP_DEVICE_ZELDA_LIN21:
            case TTL_TAP_DEVICE_ZELDA_LIN22:
            case TTL_TAP_DEVICE_ZELDA_LIN23:
            case TTL_TAP_DEVICE_ZELDA_LIN24:
                return WTAP_ENCAP_LIN;
            default:
                break;
            }

            break;
        default:
            break;
        }
    }

    return WTAP_ENCAP_UNKNOWN;
}

static const char* const ttl_cascade_names[] = { "Logger", "Tap1", "Tap2", "Tap3", "Tap4", "Tap5", "Tap6", "Tap7" };

const char* ttl_get_cascade_name(uint16_t addr) {
    return ttl_cascade_names[ttl_addr_get_cascade(addr)];
}

const char* ttl_get_device_name(uint16_t addr) {
    if (ttl_addr_get_cascade(addr) == 0) {
        switch (ttl_addr_get_device(addr)) {
        case TTL_LOGGER_DEVICE_FPGA:
        case TTL_LOGGER_DEVICE_FPGAA:
        case TTL_LOGGER_DEVICE_FPGAB:
            return "FPGA";
        case TTL_LOGGER_DEVICE_ATOM:
            return "Atom";
        case TTL_LOGGER_DEVICE_TRICORE1:
        case TTL_LOGGER_DEVICE_TRICORE2:
        case TTL_LOGGER_DEVICE_TRICORE3:
            return "Tricore";
        case TTL_LOGGER_DEVICE_TDA4x:
            return "TDA4x";
        default:
            break;
        }
    }
    else {
        switch (ttl_addr_get_device(addr)) {
        case TTL_TAP_DEVICE_PT15_FPGA:
        case TTL_TAP_DEVICE_PT15_HPS_LINUX:
            return "PT15";
        case TTL_TAP_DEVICE_PT20_FPGA:
        case TTL_TAP_DEVICE_PT20_HPS_LINUX:
            return "PT20";
        case TTL_TAP_DEVICE_PC3_FPGA:
        case TTL_TAP_DEVICE_PC3_HPS_LINUX:
        case TTL_TAP_DEVICE_PC3_AURIX:
            return "PC3";
        case TTL_TAP_DEVICE_ZELDA_CANFD:
        case TTL_TAP_DEVICE_ZELDA_LIN:
            return "Zelda";
        default:
            break;
        }
    }

    return "Unknown";
}

const char* ttl_get_function_name(uint16_t addr) {
    uint8_t function = ttl_addr_get_function(addr);

    if (ttl_addr_get_cascade(addr) == 0) {
        switch (ttl_addr_get_device(addr)) {
        case TTL_LOGGER_DEVICE_FPGA:
            switch (function) {
            case TTL_LOGGER_FPGA_FUNCTION_CORE:
                return "Core";
            case TTL_LOGGER_FPGA_FUNCTION_EXT0_MOST25:
                return "Ext0_MOST25";
            case TTL_LOGGER_FPGA_FUNCTION_EXT0_MOST150:
                return "MOST150";
            case TTL_LOGGER_FPGA_FUNCTION_ETHA_CH1:
            case TTL_LOGGER_FPGA_FUNCTION_ETHA_CH2:
            case TTL_LOGGER_FPGA_FUNCTION_ETHA_CH3:
                return "EthernetA";
            case TTL_LOGGER_FPGA_FUNCTION_ETHB_CH1:
            case TTL_LOGGER_FPGA_FUNCTION_ETHB_CH2:
            case TTL_LOGGER_FPGA_FUNCTION_ETHB_CH3:
                return "EthernetB";
            case TTL_LOGGER_FPGA_FUNCTION_FLEXRAY1A:
            case TTL_LOGGER_FPGA_FUNCTION_FLEXRAY1B:
                return "FlexRay1";
            case TTL_LOGGER_FPGA_FUNCTION_FLEXRAY2A:
            case TTL_LOGGER_FPGA_FUNCTION_FLEXRAY2B:
                return "FlexRay2";
            case TTL_LOGGER_FPGA_FUNCTION_FLEXRAY3A:
            case TTL_LOGGER_FPGA_FUNCTION_FLEXRAY3B:
                return "FlexRay3";
            case TTL_LOGGER_FPGA_FUNCTION_CAN1:
                return "CAN1";
            case TTL_LOGGER_FPGA_FUNCTION_CAN2:
                return "CAN2";
            case TTL_LOGGER_FPGA_FUNCTION_CAN3:
                return "CAN3";
            case TTL_LOGGER_FPGA_FUNCTION_CAN4:
                return "CAN4";
            case TTL_LOGGER_FPGA_FUNCTION_CAN5:
                return "CAN5";
            case TTL_LOGGER_FPGA_FUNCTION_CAN6:
                return "CAN6";
            case TTL_LOGGER_FPGA_FUNCTION_CAN7:
                return "CAN7";
            case TTL_LOGGER_FPGA_FUNCTION_CAN8:
                return "CAN8";
            case TTL_LOGGER_FPGA_FUNCTION_CAN9:
                return "CAN9";
            case TTL_LOGGER_FPGA_FUNCTION_CAN10:
                return "CAN10";
            case TTL_LOGGER_FPGA_FUNCTION_CAN11:
                return "CAN11";
            case TTL_LOGGER_FPGA_FUNCTION_CAN12:
                return "CAN12";
            case TTL_LOGGER_FPGA_FUNCTION_CAN13:
                return "CAN13";
            case TTL_LOGGER_FPGA_FUNCTION_CAN14:
                return "CAN14";
            case TTL_LOGGER_FPGA_FUNCTION_CAN15:
                return "CAN15";
            case TTL_LOGGER_FPGA_FUNCTION_CAN16:
                return "CAN16";
            case TTL_LOGGER_FPGA_FUNCTION_CAN17:
                return "CAN17";
            case TTL_LOGGER_FPGA_FUNCTION_CAN18:
                return "CAN18";
            case TTL_LOGGER_FPGA_FUNCTION_CAN19:
                return "CAN19";
            case TTL_LOGGER_FPGA_FUNCTION_CAN20:
                return "CAN20";
            case TTL_LOGGER_FPGA_FUNCTION_CAN21:
                return "CAN21";
            case TTL_LOGGER_FPGA_FUNCTION_CAN22:
                return "CAN22";
            case TTL_LOGGER_FPGA_FUNCTION_CAN23:
                return "CAN23";
            case TTL_LOGGER_FPGA_FUNCTION_CAN24:
                return "CAN24";
            case TTL_LOGGER_FPGA_FUNCTION_EXT1_MOST25:
                return "MOST25";
            case TTL_LOGGER_FPGA_FUNCTION_LIN1:
                return "LIN1";
            case TTL_LOGGER_FPGA_FUNCTION_LIN2:
                return "LIN2";
            case TTL_LOGGER_FPGA_FUNCTION_LIN3:
                return "LIN3";
            case TTL_LOGGER_FPGA_FUNCTION_LIN4:
                return "LIN4";
            case TTL_LOGGER_FPGA_FUNCTION_LIN5:
                return "LIN5";
            case TTL_LOGGER_FPGA_FUNCTION_LIN6:
                return "LIN6";
            case TTL_LOGGER_FPGA_FUNCTION_LIN7:
                return "LIN7";
            case TTL_LOGGER_FPGA_FUNCTION_LIN8:
                return "LIN8";
            case TTL_LOGGER_FPGA_FUNCTION_LIN9:
                return "LIN9";
            case TTL_LOGGER_FPGA_FUNCTION_LIN10:
                return "LIN10";
            case TTL_LOGGER_FPGA_FUNCTION_LIN11:
                return "LIN11";
            case TTL_LOGGER_FPGA_FUNCTION_LIN12:
                return "LIN12";
            default:
                break;
            }
            break;
        case TTL_LOGGER_DEVICE_ATOM:
            switch (function) {
            case TTL_LOGGER_ATOM_FUNCTION_ETHA:
                return "EthernetA";
            case TTL_LOGGER_ATOM_FUNCTION_ETHB:
                return "EthernetB";
            default:
                break;
            }
            break;
        case TTL_LOGGER_DEVICE_TRICORE1:
            switch (function) {
            case TTL_LOGGER_TRICORE1_FUNCTION_CORE:
                return "Core1";
            case TTL_LOGGER_TRICORE1_FUNCTION_FLEXRAY1A:
            case TTL_LOGGER_TRICORE1_FUNCTION_FLEXRAY1B:
            case TTL_LOGGER_TRICORE1_FUNCTION_FLEXRAY1:
            case TTL_LOGGER_TRICORE1_FUNCTION_FLEXRAY1AB:
                return "FlexRay1";
            case TTL_LOGGER_TRICORE1_FUNCTION_CAN1:
                return "CAN1";
            case TTL_LOGGER_TRICORE1_FUNCTION_CAN2:
                return "CAN2";
            case TTL_LOGGER_TRICORE1_FUNCTION_CAN3:
                return "CAN3";
            case TTL_LOGGER_TRICORE1_FUNCTION_CAN4:
                return "CAN4";
            case TTL_LOGGER_TRICORE1_FUNCTION_ANALOGOUT1:
                return "AnalogOut1";
            case TTL_LOGGER_TRICORE1_FUNCTION_DIGITALOUT5:
                return "DigitalOut5";
            case TTL_LOGGER_TRICORE1_FUNCTION_DIGITALOUT6:
                return "DigitalOut6";
            case TTL_LOGGER_TRICORE1_FUNCTION_SERIAL1:
                return "Serial1";
            case TTL_LOGGER_TRICORE1_FUNCTION_SERIAL2:
                return "Serial2";
            case TTL_LOGGER_TRICORE1_FUNCTION_ANALOGIN6:
                return "AnalogIn6";
            case TTL_LOGGER_TRICORE1_FUNCTION_ANALOGIN8:
                return "AnalogIn8";
            case TTL_LOGGER_TRICORE1_FUNCTION_ANALOGIN11:
                return "AnalogIn11";
            case TTL_LOGGER_TRICORE1_FUNCTION_ANALOGIN14:
                return "AnalogIn14";
            case TTL_LOGGER_TRICORE1_FUNCTION_ANALOGIN15:
                return "AnalogIn15";
            case TTL_LOGGER_TRICORE1_FUNCTION_DIGITALIN8:
                return "DigitalIn8";
            case TTL_LOGGER_TRICORE1_FUNCTION_DIGITALIN10:
                return "DigitalIn10";
            case TTL_LOGGER_TRICORE1_FUNCTION_DIGITALIN11:
                return "DigitalIn11";
            case TTL_LOGGER_TRICORE1_FUNCTION_DIGITALIN12:
                return "DigitalIn12";
            case TTL_LOGGER_TRICORE1_FUNCTION_DIGITALIN13:
                return "DigitalIn13";
            case TTL_LOGGER_TRICORE1_FUNCTION_KL15IN:
                return "KL15";
            case TTL_LOGGER_TRICORE1_FUNCTION_KL30IN:
                return "KL30";
            default:
                break;
            }
            break;
        case TTL_LOGGER_DEVICE_TRICORE2:
            switch (function) {
            case TTL_LOGGER_TRICORE2_FUNCTION_CORE:
                return "Core2";
            case TTL_LOGGER_TRICORE2_FUNCTION_FLEXRAY2A:
            case TTL_LOGGER_TRICORE2_FUNCTION_FLEXRAY2B:
            case TTL_LOGGER_TRICORE2_FUNCTION_FLEXRAY2:
            case TTL_LOGGER_TRICORE2_FUNCTION_FLEXRAY2AB:
                return "FlexRay2";
            case TTL_LOGGER_TRICORE2_FUNCTION_CAN6:
                return "CAN6";
            case TTL_LOGGER_TRICORE2_FUNCTION_CAN7:
                return "CAN7";
            case TTL_LOGGER_TRICORE2_FUNCTION_CAN10:
                return "CAN10";
            case TTL_LOGGER_TRICORE2_FUNCTION_CAN12:
                return "CAN12";
            case TTL_LOGGER_TRICORE2_FUNCTION_ANALOGOUT2:
                return "AnalogOut2";
            case TTL_LOGGER_TRICORE2_FUNCTION_DIGITALOUT3:
                return "DigitalOut3";
            case TTL_LOGGER_TRICORE2_FUNCTION_DIGITALOUT4:
                return "DigitalOut4";
            case TTL_LOGGER_TRICORE2_FUNCTION_SERIAL3:
                return "Serial3";
            case TTL_LOGGER_TRICORE2_FUNCTION_SERIAL4:
                return "Serial4";
            case TTL_LOGGER_TRICORE2_FUNCTION_ANALOGIN3:
                return "AnalogIn3";
            case TTL_LOGGER_TRICORE2_FUNCTION_ANALOGIN4:
                return "AnalogIn4";
            case TTL_LOGGER_TRICORE2_FUNCTION_ANALOGIN5:
                return "AnalogIn5";
            case TTL_LOGGER_TRICORE2_FUNCTION_ANALOGIN7:
                return "AnalogIn7";
            case TTL_LOGGER_TRICORE2_FUNCTION_ANALOGIN9:
                return "AnalogIn9";
            case TTL_LOGGER_TRICORE2_FUNCTION_DIGITALIN6:
                return "DigitalIn6";
            case TTL_LOGGER_TRICORE2_FUNCTION_DIGITALIN7:
                return "DigitalIn7";
            case TTL_LOGGER_TRICORE2_FUNCTION_DIGITALIN9:
                return "DigitalIn9";
            case TTL_LOGGER_TRICORE2_FUNCTION_DIGITALIN14:
                return "DigitalIn14";
            case TTL_LOGGER_TRICORE2_FUNCTION_DIGITALIN15:
                return "DigitalIn15";
            default:
                break;
            }
            break;
        case TTL_LOGGER_DEVICE_TRICORE3:
            switch (function) {
            case TTL_LOGGER_TRICORE3_FUNCTION_CORE:
                return "Core3";
            case TTL_LOGGER_TRICORE3_FUNCTION_FLEXRAY3A:
            case TTL_LOGGER_TRICORE3_FUNCTION_FLEXRAY3B:
            case TTL_LOGGER_TRICORE3_FUNCTION_FLEXRAY3:
            case TTL_LOGGER_TRICORE3_FUNCTION_FLEXRAY3AB:
                return "FlexRay3";
            case TTL_LOGGER_TRICORE3_FUNCTION_CAN5:
                return "CAN5";
            case TTL_LOGGER_TRICORE3_FUNCTION_CAN8:
                return "CAN8";
            case TTL_LOGGER_TRICORE3_FUNCTION_CAN9:
                return "CAN9";
            case TTL_LOGGER_TRICORE3_FUNCTION_CAN11:
                return "CAN11";
            case TTL_LOGGER_TRICORE3_FUNCTION_ANALOGOUT3:
                return "AnalogOut3";
            case TTL_LOGGER_TRICORE3_FUNCTION_DIGITALOUT1:
                return "DigitalOut1";
            case TTL_LOGGER_TRICORE3_FUNCTION_DIGITALOUT2:
                return "DigitalOut2";
            case TTL_LOGGER_TRICORE3_FUNCTION_SERIAL5:
                return "Serial5";
            case TTL_LOGGER_TRICORE3_FUNCTION_SERIAL6:
                return "Serial6";
            case TTL_LOGGER_TRICORE3_FUNCTION_ANALOGIN1:
                return "AnalogIn1";
            case TTL_LOGGER_TRICORE3_FUNCTION_ANALOGIN2:
                return "AnalogIn2";
            case TTL_LOGGER_TRICORE3_FUNCTION_ANALOGIN10:
                return "AnalogIn10";
            case TTL_LOGGER_TRICORE3_FUNCTION_ANALOGIN12:
                return "AnalogIn12";
            case TTL_LOGGER_TRICORE3_FUNCTION_ANALOGIN13:
                return "AnalogIn13";
            case TTL_LOGGER_TRICORE3_FUNCTION_DIGITALIN1:
                return "DigitalIn1";
            case TTL_LOGGER_TRICORE3_FUNCTION_DIGITALIN2:
                return "DigitalIn2";
            case TTL_LOGGER_TRICORE3_FUNCTION_DIGITALIN3:
                return "DigitalIn3";
            case TTL_LOGGER_TRICORE3_FUNCTION_DIGITALIN4:
                return "DigitalIn4";
            case TTL_LOGGER_TRICORE3_FUNCTION_DIGITALIN5:
                return "DigitalIn5";
            default:
                break;
            }
            break;
        case TTL_LOGGER_DEVICE_TDA4x:
            switch (function) {
            case TTL_LOGGER_TDA4x_FUNCTION_CORE:
                return "Core";
            case TTL_LOGGER_TDA4x_FUNCTION_CAN1:
                return "CAN1";
            case TTL_LOGGER_TDA4x_FUNCTION_CAN2:
                return "CAN2";
            case TTL_LOGGER_TDA4x_FUNCTION_CAN3:
                return "CAN3";
            case TTL_LOGGER_TDA4x_FUNCTION_CAN4:
                return "CAN4";
            case TTL_LOGGER_TDA4x_FUNCTION_CAN5:
                return "CAN5";
            case TTL_LOGGER_TDA4x_FUNCTION_CAN6:
                return "CAN6";
            case TTL_LOGGER_TDA4x_FUNCTION_CAN7:
                return "CAN7";
            case TTL_LOGGER_TDA4x_FUNCTION_CAN8:
                return "CAN8";
            case TTL_LOGGER_TDA4x_FUNCTION_CAN9:
                return "CAN9";
            case TTL_LOGGER_TDA4x_FUNCTION_CAN10:
                return "CAN10";
            case TTL_LOGGER_TDA4x_FUNCTION_CAN11:
                return "CAN11";
            case TTL_LOGGER_TDA4x_FUNCTION_SERIAL1:
                return "Serial1";
            case TTL_LOGGER_TDA4x_FUNCTION_SERIAL2:
                return "Serial2";
            case TTL_LOGGER_TDA4x_FUNCTION_SERIAL3:
                return "Serial3";
            case TTL_LOGGER_TDA4x_FUNCTION_SERIAL4:
                return "Serial4";
            case TTL_LOGGER_TDA4x_FUNCTION_SERIAL5:
                return "Serial5";
            case TTL_LOGGER_TDA4x_FUNCTION_SERIAL6:
                return "Serial6";
            case TTL_LOGGER_TDA4x_FUNCTION_SERIAL7:
                return "Serial7";
            case TTL_LOGGER_TDA4x_FUNCTION_SERIAL8:
                return "Serial8";
            case TTL_LOGGER_TDA4x_FUNCTION_SERIAL9:
                return "Serial9";
            case TTL_LOGGER_TDA4x_FUNCTION_SERIAL10:
                return "Serial10";
            case TTL_LOGGER_TDA4x_FUNCTION_ANALOGIN1:
                return "AnalogIn1";
            case TTL_LOGGER_TDA4x_FUNCTION_ANALOGIN2:
                return "AnalogIn2";
            case TTL_LOGGER_TDA4x_FUNCTION_ANALOGIN3:
                return "AnalogIn3";
            case TTL_LOGGER_TDA4x_FUNCTION_ANALOGIN4:
                return "AnalogIn4";
            case TTL_LOGGER_TDA4x_FUNCTION_ANALOGIN5:
                return "AnalogIn5";
            case TTL_LOGGER_TDA4x_FUNCTION_ANALOGIN6:
                return "AnalogIn6";
            case TTL_LOGGER_TDA4x_FUNCTION_ANALOGOUT1:
                return "AnalogOut1";
            case TTL_LOGGER_TDA4x_FUNCTION_ANALOGOUT2:
                return "AnalogOut2";
            case TTL_LOGGER_TDA4x_FUNCTION_KL15IN:
                return "KL15";
            case TTL_LOGGER_TDA4x_FUNCTION_KL30IN:
                return "KL30";
            case TTL_LOGGER_TDA4x_FUNCTION_FLEXRAY1A:
            case TTL_LOGGER_TDA4x_FUNCTION_FLEXRAY1B:
            case TTL_LOGGER_TDA4x_FUNCTION_FLEXRAY1AB:
                return "FlexRay1";
            case TTL_LOGGER_TDA4x_FUNCTION_CAN12:
                return "CAN12";
            case TTL_LOGGER_TDA4x_FUNCTION_CAN13:
                return "CAN13";
            case TTL_LOGGER_TDA4x_FUNCTION_CAN14:
                return "CAN14";

            default:
                break;
            }
            break;
        case TTL_LOGGER_DEVICE_FPGAA:
            switch (function) {
            case TTL_LOGGER_FPGAA_FUNCTION_CORE:
                return "Core";
            case TTL_LOGGER_FPGAA_FUNCTION_CAN1:
                return "CAN1";
            case TTL_LOGGER_FPGAA_FUNCTION_CAN2:
                return "CAN2";
            case TTL_LOGGER_FPGAA_FUNCTION_CAN3:
                return "CAN3";
            case TTL_LOGGER_FPGAA_FUNCTION_CAN4:
                return "CAN4";
            case TTL_LOGGER_FPGAA_FUNCTION_CAN5:
                return "CAN5";
            case TTL_LOGGER_FPGAA_FUNCTION_CAN6:
                return "CAN6";
            case TTL_LOGGER_FPGAA_FUNCTION_CAN7:
                return "CAN7";
            case TTL_LOGGER_FPGAA_FUNCTION_CAN8:
                return "CAN8";
            case TTL_LOGGER_FPGAA_FUNCTION_CAN9:
                return "CAN9";
            case TTL_LOGGER_FPGAA_FUNCTION_CAN10:
                return "CAN10";
            case TTL_LOGGER_FPGAA_FUNCTION_CAN11:
                return "CAN11";
            case TTL_LOGGER_FPGAA_FUNCTION_LIN1:
                return "LIN1";
            case TTL_LOGGER_FPGAA_FUNCTION_LIN2:
                return "LIN2";
            case TTL_LOGGER_FPGAA_FUNCTION_LIN3:
                return "LIN3";
            case TTL_LOGGER_FPGAA_FUNCTION_LIN4:
                return "LIN4";
            case TTL_LOGGER_FPGAA_FUNCTION_LIN5:
                return "LIN5";
            case TTL_LOGGER_FPGAA_FUNCTION_LIN6:
                return "LIN6";
            case TTL_LOGGER_FPGAA_FUNCTION_LIN7:
                return "LIN7";
            case TTL_LOGGER_FPGAA_FUNCTION_LIN8:
                return "LIN8";
            case TTL_LOGGER_FPGAA_FUNCTION_LIN9:
                return "LIN9";
            case TTL_LOGGER_FPGAA_FUNCTION_LIN10:
                return "LIN10";
            case TTL_LOGGER_FPGAA_FUNCTION_LIN11:
                return "LIN11";
            case TTL_LOGGER_FPGAA_FUNCTION_LIN12:
                return "LIN12";
            case TTL_LOGGER_FPGAA_FUNCTION_LIN13:
                return "LIN13";
            case TTL_LOGGER_FPGAA_FUNCTION_LIN14:
                return "LIN14";
            case TTL_LOGGER_FPGAA_FUNCTION_LIN15:
                return "LIN15";
            case TTL_LOGGER_FPGAA_FUNCTION_LIN16:
                return "LIN16";
            case TTL_LOGGER_FPGAA_FUNCTION_FLEXRAY1A:
            case TTL_LOGGER_FPGAA_FUNCTION_FLEXRAY1B:
                return "FlexRay1";
            case TTL_LOGGER_FPGAA_FUNCTION_SERIAL1:
                return "Serial1";
            case TTL_LOGGER_FPGAA_FUNCTION_SERIAL2:
                return "Serial2";
            case TTL_LOGGER_FPGAA_FUNCTION_SERIAL3:
                return "Serial3";
            case TTL_LOGGER_FPGAA_FUNCTION_SERIAL4:
                return "Serial4";
            case TTL_LOGGER_FPGAA_FUNCTION_SERIAL5:
                return "Serial5";
            case TTL_LOGGER_FPGAA_FUNCTION_SERIAL6:
                return "Serial6";
            case TTL_LOGGER_FPGAA_FUNCTION_SERIAL7:
                return "Serial7";
            case TTL_LOGGER_FPGAA_FUNCTION_SERIAL8:
                return "Serial8";
            case TTL_LOGGER_FPGAA_FUNCTION_SERIAL9:
                return "Serial9";
            case TTL_LOGGER_FPGAA_FUNCTION_SERIAL10:
                return "Serial10";
            case TTL_LOGGER_FPGAA_FUNCTION_CAN12:
                return "CAN12";
            case TTL_LOGGER_FPGAA_FUNCTION_CAN13:
                return "CAN13";
            case TTL_LOGGER_FPGAA_FUNCTION_CAN14:
                return "CAN14";
            default:
                break;
            }
            break;
        case TTL_LOGGER_DEVICE_FPGAB:
            switch (function) {
            case TTL_LOGGER_FPGAB_FUNCTION_ETHA_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_ETHA_CH2:
                return "EthernetA";
            case TTL_LOGGER_FPGAB_FUNCTION_ETHB_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_ETHB_CH2:
                return "EthernetB";
            case TTL_LOGGER_FPGAB_FUNCTION_AETH1a_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH1a_CH2:
                return "AutomotiveEthernet1a";
            case TTL_LOGGER_FPGAB_FUNCTION_AETH1b_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH1b_CH2:
                return "AutomotiveEthernet1b";
            case TTL_LOGGER_FPGAB_FUNCTION_AETH2a_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH2a_CH2:
                return "AutomotiveEthernet2a";
            case TTL_LOGGER_FPGAB_FUNCTION_AETH2b_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH2b_CH2:
                return "AutomotiveEthernet2b";
            case TTL_LOGGER_FPGAB_FUNCTION_AETH3a_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH3a_CH2:
                return "AutomotiveEthernet3a";
            case TTL_LOGGER_FPGAB_FUNCTION_AETH3b_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH3b_CH2:
                return "AutomotiveEthernet3b";
            case TTL_LOGGER_FPGAB_FUNCTION_AETH4a_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH4a_CH2:
                return "AutomotiveEthernet4a";
            case TTL_LOGGER_FPGAB_FUNCTION_AETH4b_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH4b_CH2:
                return "AutomotiveEthernet4b";
            case TTL_LOGGER_FPGAB_FUNCTION_AETH5a_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH5a_CH2:
                return "AutomotiveEthernet5a";
            case TTL_LOGGER_FPGAB_FUNCTION_AETH5b_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH5b_CH2:
                return "AutomotiveEthernet5b";
            case TTL_LOGGER_FPGAB_FUNCTION_AETH6a_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH6a_CH2:
                return "AutomotiveEthernet6a";
            case TTL_LOGGER_FPGAB_FUNCTION_AETH6b_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH6b_CH2:
                return "AutomotiveEthernet6b";
            default:
                break;
            }
            break;
        default:
            break;
        }
    }
    else {
        switch (ttl_addr_get_device(addr)) {
        case TTL_TAP_DEVICE_PT15_FPGA:
            switch (function) {
            case TTL_PT15_FPGA_FUNCTION_CORE:
                return "Core";
            case TTL_PT15_FPGA_FUNCTION_CAN1:
                return "CAN1";
            case TTL_PT15_FPGA_FUNCTION_CAN2:
                return "CAN2";
            case TTL_PT15_FPGA_FUNCTION_BrdR1a:
                return "BR1a";
            case TTL_PT15_FPGA_FUNCTION_BrdR1b:
                return "BR1b";
            case TTL_PT15_FPGA_FUNCTION_BrdR2a:
                return "BR2a";
            case TTL_PT15_FPGA_FUNCTION_BrdR2b:
                return "BR2b";
            case TTL_PT15_FPGA_FUNCTION_BrdR3a:
                return "BR3a";
            case TTL_PT15_FPGA_FUNCTION_BrdR3b:
                return "BR3b";
            case TTL_PT15_FPGA_FUNCTION_BrdR4a:
                return "BR4a";
            case TTL_PT15_FPGA_FUNCTION_BrdR4b:
                return "BR4b";
            case TTL_PT15_FPGA_FUNCTION_BrdR5a:
                return "BR5a";
            case TTL_PT15_FPGA_FUNCTION_BrdR5b:
                return "BR5b";
            case TTL_PT15_FPGA_FUNCTION_BrdR6a:
                return "BR6a";
            case TTL_PT15_FPGA_FUNCTION_BrdR6b:
                return "BR6b";
            case TTL_PT15_FPGA_FUNCTION_MDIO:
                return "MDIO";
            default:
                break;
            }
            break;
        case TTL_TAP_DEVICE_PT20_FPGA:
            switch (function) {
            case TTL_PT20_FPGA_FUNCTION_CORE:
                return "Core";
            case TTL_PT20_FPGA_FUNCTION_CAN1:
                return "CAN1";
            case TTL_PT20_FPGA_FUNCTION_CAN2:
                return "CAN2";
            case TTL_PT20_FPGA_FUNCTION_CAN3:
                return "CAN3";
            case TTL_PT20_FPGA_FUNCTION_CAN4:
                return "CAN4";
            case TTL_PT20_FPGA_FUNCTION_CAN5:
                return "CAN5";
            case TTL_PT20_FPGA_FUNCTION_GbEth1a:
                return "GbEth1a";
            case TTL_PT20_FPGA_FUNCTION_GbEth1b:
                return "GbEth1b";
            case TTL_PT20_FPGA_FUNCTION_GbEth2a:
                return "GbEth2a";
            case TTL_PT20_FPGA_FUNCTION_GbEth2b:
                return "GbEth2b";
            case TTL_PT20_FPGA_FUNCTION_GbEth3a:
                return "GbEth3a";
            case TTL_PT20_FPGA_FUNCTION_GbEth3b:
                return "GbEth3b";
            case TTL_PT20_FPGA_FUNCTION_MDIO:
                return "MDIO";
            default:
                break;
            }
            break;
        case TTL_TAP_DEVICE_PC3_FPGA:
            switch (function) {
            case TTL_PC3_FPGA_FUNCTION_CORE:
                return "FPGA_Core";
            case TTL_PC3_FPGA_FUNCTION_BrdR1a:
                return "BR1a";
            case TTL_PC3_FPGA_FUNCTION_BrdR1b:
                return "BR1b";
            default:
                break;
            }
            break;
        case TTL_TAP_DEVICE_PC3_AURIX:
            switch (function) {
            case TTL_PC3_AURIX_FUNCTION_CORE:
                return "Aurix_Core";
            case TTL_PC3_AURIX_FUNCTION_CAN1:
                return "CAN1";
            case TTL_PC3_AURIX_FUNCTION_CAN2:
                return "CAN2";
            case TTL_PC3_AURIX_FUNCTION_CAN3:
                return "CAN3";
            case TTL_PC3_AURIX_FUNCTION_CAN4:
                return "CAN4";
            case TTL_PC3_AURIX_FUNCTION_FLEXRAY1A:
            case TTL_PC3_AURIX_FUNCTION_FLEXRAY1B:
                return "FlexRay1";
            case TTL_PC3_AURIX_FUNCTION_FLEXRAY2A:
            case TTL_PC3_AURIX_FUNCTION_FLEXRAY2B:
                return "FlexRay2";
            case TTL_PC3_AURIX_FUNCTION_DIGITALIN1:
                return "DigitalIn1";
            case TTL_PC3_AURIX_FUNCTION_DIGITALIN2:
                return "DigitalIn2";
            case TTL_PC3_AURIX_FUNCTION_DIGITALOUT1:
                return "DigitalOut1";
            case TTL_PC3_AURIX_FUNCTION_DIGITALOUT2:
                return "DigitalOut2";
            default:
                break;
            }
            break;
        case TTL_TAP_DEVICE_ZELDA_CANFD:
            switch (function) {
            case TTL_TAP_DEVICE_ZELDA_CORE:
                return "CANFD_Core";
            case TTL_TAP_DEVICE_ZELDA_CANFD1:
                return "CANFD1";
            case TTL_TAP_DEVICE_ZELDA_CANFD2:
                return "CANFD2";
            case TTL_TAP_DEVICE_ZELDA_CANFD3:
                return "CANFD3";
            case TTL_TAP_DEVICE_ZELDA_CANFD4:
                return "CANFD4";
            case TTL_TAP_DEVICE_ZELDA_CANFD5:
                return "CANFD5";
            case TTL_TAP_DEVICE_ZELDA_CANFD6:
                return "CANFD6";
            case TTL_TAP_DEVICE_ZELDA_CANFD7:
                return "CANFD7";
            case TTL_TAP_DEVICE_ZELDA_CANFD8:
                return "CANFD8";
            case TTL_TAP_DEVICE_ZELDA_CANFD9:
                return "CANFD9";
            case TTL_TAP_DEVICE_ZELDA_CANFD10:
                return "CANFD10";
            case TTL_TAP_DEVICE_ZELDA_CANFD11:
                return "CANFD11";
            case TTL_TAP_DEVICE_ZELDA_CANFD12:
                return "CANFD12";
            case TTL_TAP_DEVICE_ZELDA_CANFD13:
                return "CANFD13";
            case TTL_TAP_DEVICE_ZELDA_CANFD14:
                return "CANFD14";
            case TTL_TAP_DEVICE_ZELDA_CANFD15:
                return "CANFD15";
            default:
                break;
            }
            break;
        case TTL_TAP_DEVICE_ZELDA_LIN:
            switch (function) {
            case TTL_TAP_DEVICE_ZELDA_CORE:
                return "LIN_Core";
            case TTL_TAP_DEVICE_ZELDA_LIN1:
                return "LIN1";
            case TTL_TAP_DEVICE_ZELDA_LIN2:
                return "LIN2";
            case TTL_TAP_DEVICE_ZELDA_LIN3:
                return "LIN3";
            case TTL_TAP_DEVICE_ZELDA_LIN4:
                return "LIN4";
            case TTL_TAP_DEVICE_ZELDA_LIN5:
                return "LIN5";
            case TTL_TAP_DEVICE_ZELDA_LIN6:
                return "LIN6";
            case TTL_TAP_DEVICE_ZELDA_LIN7:
                return "LIN7";
            case TTL_TAP_DEVICE_ZELDA_LIN8:
                return "LIN8";
            case TTL_TAP_DEVICE_ZELDA_LIN9:
                return "LIN9";
            case TTL_TAP_DEVICE_ZELDA_LIN10:
                return "LIN10";
            case TTL_TAP_DEVICE_ZELDA_LIN11:
                return "LIN11";
            case TTL_TAP_DEVICE_ZELDA_LIN12:
                return "LIN12";
            case TTL_TAP_DEVICE_ZELDA_LIN13:
                return "LIN13";
            case TTL_TAP_DEVICE_ZELDA_LIN14:
                return "LIN14";
            case TTL_TAP_DEVICE_ZELDA_LIN15:
                return "LIN15";
            case TTL_TAP_DEVICE_ZELDA_LIN16:
                return "LIN16";
            case TTL_TAP_DEVICE_ZELDA_LIN17:
                return "LIN17";
            case TTL_TAP_DEVICE_ZELDA_LIN18:
                return "LIN18";
            case TTL_TAP_DEVICE_ZELDA_LIN19:
                return "LIN19";
            case TTL_TAP_DEVICE_ZELDA_LIN20:
                return "LIN20";
            case TTL_TAP_DEVICE_ZELDA_LIN21:
                return "LIN21";
            case TTL_TAP_DEVICE_ZELDA_LIN22:
                return "LIN22";
            case TTL_TAP_DEVICE_ZELDA_LIN23:
                return "LIN23";
            case TTL_TAP_DEVICE_ZELDA_LIN24:
                return "LIN24";
            default:
                break;
            }
            break;
        default:
            break;
        }
    }

    return "Unknown";
}

static wtap_opttype_return_val
ttl_add_interface_name(wtap_block_t int_data, uint16_t addr, const char* name) {
    if (name != NULL) {
        return wtap_block_add_string_option(int_data, OPT_IDB_NAME, name, strlen(name));
    }

    return wtap_block_add_string_option_format(int_data, OPT_IDB_NAME, "%s::%s::%s",
                                               ttl_get_cascade_name(addr),
                                               ttl_get_device_name(addr),
                                               ttl_get_function_name(addr));
}

/*
 * This function will create the interface and populate the
 * 'address_to_iface_ht' hash table.
 */
static bool
ttl_create_interface(wtap* wth, int pkt_encap, uint16_t addr, const char* name) {
    wtap_block_t int_data;
    wtapng_if_descr_mandatory_t* if_descr_mand;

    if (wth == NULL) {
        return false;
    }

    int_data = wtap_block_create(WTAP_BLOCK_IF_ID_AND_INFO);
    if_descr_mand = wtap_block_get_mandatory_data(int_data);

    if_descr_mand->wtap_encap = pkt_encap;
    ttl_add_interface_name(int_data, addr, name);

    if_descr_mand->time_units_per_second = 1000 * 1000;
    if_descr_mand->tsprecision = WTAP_TSPREC_USEC;
    wtap_block_add_uint8_option(int_data, OPT_IDB_TSRESOL, 6);
    if_descr_mand->snap_len = WTAP_MAX_PACKET_SIZE_STANDARD;
    if_descr_mand->num_stat_entries = 0;
    if_descr_mand->interface_statistics = NULL;
    wtap_add_idb(wth, int_data);

    if (wth->file_encap == WTAP_ENCAP_NONE) {
        wth->file_encap = if_descr_mand->wtap_encap;
    }
    else if (wth->file_encap != if_descr_mand->wtap_encap) {
        wth->file_encap = WTAP_ENCAP_PER_PACKET;
    }

    return true;
}

#define TTL_LOOKUP_INTERFACE_MAX_ITERATIONS 2
#define ttl_lookup_interface(...)   ttl_lookup_interface_int(__VA_ARGS__, 0)

// NOLINTNEXTLINE(misc-no-recursion)
static const ttl_addr_to_iface_entry_t* ttl_lookup_interface_int(wtap* wth, uint16_t addr, int* err, char** err_info, int iteration) {
    ttl_addr_to_iface_entry_t* item;
    ttl_t*      ttl;
    uint32_t    iface_id;
    uint16_t    master_addr;
    int         pkt_encap;

    if (wth == NULL) {
        return NULL;
    }

    ttl = (ttl_t*)wth->priv;
    if (ttl == NULL || ttl->address_to_iface_ht == NULL) {
        return NULL;
    }

    /* Recursion limit to avoid coding errors. */
    if (iteration > TTL_LOOKUP_INTERFACE_MAX_ITERATIONS) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("ttl_lookup_interface(): more iterations than allowed: %d (max. %d)", iteration, TTL_LOOKUP_INTERFACE_MAX_ITERATIONS);
        return NULL;
    }

    item = g_hash_table_lookup(ttl->address_to_iface_ht, GUINT_TO_POINTER(addr));
    if (item != NULL) {
        return item;
    }

    pkt_encap = ttl_get_address_iface_type(addr);
    if (pkt_encap <= WTAP_ENCAP_UNKNOWN) {
        return NULL;
    }

    master_addr = ttl_get_master_address(ttl->address_to_master_ht, addr);
    if (addr != master_addr) {   /* The interface ID is the "slave" one */
        const ttl_addr_to_iface_entry_t* master_item = ttl_lookup_interface_int(wth, master_addr, err, err_info, iteration + 1);
        if (master_item == NULL) {
            return NULL;
        }

        iface_id = master_item->interface_id;
    }
    else {  /* Create a new interface */
        const char* saved_name = g_hash_table_lookup(ttl->address_to_name_ht, GUINT_TO_POINTER(addr));
        bool ret = ttl_create_interface(wth, pkt_encap, addr, saved_name);

        if (saved_name != NULL) {
            g_hash_table_remove(ttl->address_to_name_ht, GUINT_TO_POINTER(addr));
        }

        if (!ret) {
            return NULL;
        }

        iface_id = ttl->next_interface_id++;
    }

    /* Create the entry */
    item = g_new(ttl_addr_to_iface_entry_t, 1);
    item->interface_id = iface_id;
    item->pkt_encap = pkt_encap;
    item->channelB = ttl_is_chb_addr(addr);
    g_hash_table_insert(ttl->address_to_iface_ht, GUINT_TO_POINTER(addr), item);

    return item;
}

static void
ttl_init_rec(wtap_rec* rec, uint64_t timestamp, uint16_t addr, int pkt_encap, uint32_t iface_id, uint32_t caplen, uint32_t len) {
    wtap_setup_packet_rec(rec, pkt_encap);
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->presence_flags = WTAP_HAS_CAP_LEN | WTAP_HAS_INTERFACE_ID | WTAP_HAS_TS;
    rec->tsprec = WTAP_TSPREC_USEC;
    rec->ts.secs = timestamp / (1000 * 1000);
    rec->ts.nsecs = 1000 * (timestamp % (1000 * 1000));
    rec->rec_header.packet_header.caplen = caplen;
    rec->rec_header.packet_header.len = len;

    rec->rec_header.packet_header.interface_id = iface_id;

    wtap_block_add_uint32_option(rec->block, OPT_PKT_QUEUE, addr);
}

static bool
ttl_read_bytes(ttl_read_t* in, void* out, uint16_t size, int* err, char** err_info) {
    switch (in->validity) {
    case VALIDITY_FH:
        if (!wtap_read_bytes_or_eof(in->fh, out, size, err, err_info)) {
            ws_debug("wtap_read_bytes_or_eof() failed, err = %d.", *err);
            return false;
        }
        break;
    case VALIDITY_BUF:
        if (size != 0) {
            if ((in->cur_pos + size) > in->size) {
                *err = WTAP_ERR_SHORT_READ;
                *err_info = ws_strdup("ttl_read_bytes(): Attempt to read beyond buffer end");
                return false;
            }
            if (out != NULL) {
                memcpy(out, in->buf + in->cur_pos, size);
            }
            in->cur_pos += size;
        }
        break;
    default:
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("ttl_read_bytes(): ttl_read_t unknown validity flags: %d", in->validity);
        return false;
    }

    return true;
}

static bool
ttl_read_bytes_buffer(ttl_read_t* in, Buffer* buf, uint16_t size, int* err, char** err_info) {
    ws_buffer_assure_space(buf, size);
    if (!ttl_read_bytes(in, ws_buffer_end_ptr(buf), size, err, err_info)) {
        return false;
    }
    ws_buffer_increase_length(buf, size);
    return true;
}

static bool
ttl_skip_bytes(ttl_read_t* in, uint16_t size, int* err, char** err_info) {
    return ttl_read_bytes(in, NULL, size, err, err_info);
}

static void
ttl_add_eth_dir_option(wtap_rec* rec, uint16_t status) {
    uint32_t opt = PACK_FLAGS_DIRECTION_UNKNOWN;

    switch (status) {
    case TTL_ETH_STATUS_VALID_FRAME:
    case TTL_ETH_STATUS_CRC_ERROR_FRAME:
    case TTL_ETH_STATUS_LENGTH_ERROR_FRAME:
    case TTL_ETH_STATUS_PHY_ERROR_FRAME:
        opt = PACK_FLAGS_DIRECTION_INBOUND;
        break;
    case TTL_ETH_STATUS_TX_ERROR_FRAME:
    case TTL_ETH_STATUS_TX_FREEMEM_INFO_FRAME:
    case TTL_ETH_STATUS_TX_FRAME:
        opt = PACK_FLAGS_DIRECTION_OUTBOUND;
        break;
    default:
        break;
    }

    wtap_block_add_uint32_option(rec->block, OPT_EPB_FLAGS, opt);
}

static ttl_result_t
ttl_read_eth_data_entry(wtap_rec* rec, int* err, char** err_info, ttl_read_t* in, uint16_t size, uint16_t addr,
                        const ttl_addr_to_iface_entry_t* item, uint16_t status, uint64_t timestamp) {
    if (item == NULL) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup("ttl_read_eth_data_entry called with NULL item");
        return TTL_ERROR;
    }

    if (status == TTL_ETH_STATUS_PHY_STATUS) {  /* TODO */
        if (!ttl_skip_bytes(in, size, err, err_info)) {
            return TTL_ERROR;
        }
        return TTL_UNSUPPORTED;
    }

    if (size < 2) { /* 2 unused bytes */
        return TTL_CORRUPTED;
    }
    if (!ttl_skip_bytes(in, 2, err, err_info)) {
        return TTL_ERROR;
    }
    size -= 2;

    if (size != 0 && !ttl_read_bytes_buffer(in, &rec->data, size, err, err_info)) {
        return TTL_ERROR;
    }

    ttl_init_rec(rec, timestamp, addr, item->pkt_encap, item->interface_id, size, size);
    ttl_add_eth_dir_option(rec, status);

    return TTL_NO_ERROR;
}

static void
ttl_add_can_dir_option(wtap_rec* rec) {
    uint32_t opt = PACK_FLAGS_DIRECTION_INBOUND;    /* For the moment, we only support this */

    wtap_block_add_uint32_option(rec->block, OPT_EPB_FLAGS, opt);
}

static const uint8_t canfd_dlc_to_length[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64 };

static ttl_result_t
ttl_read_can_data_entry(wtap_rec* rec, int* err, char** err_info, ttl_read_t* in, uint16_t size, uint16_t addr,
                        const ttl_addr_to_iface_entry_t* item, uint16_t status, uint64_t timestamp) {
    uint32_t    can_id = 0;
    uint8_t     dlc, error_code, len, canfd_flags = 0;
    uint8_t     can_header[8], can_error_payload[CAN_ERR_DLC] = {0};

    if (item == NULL) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup("ttl_read_can_data_entry called with NULL item");
        return TTL_ERROR;
    }

    dlc = (status & TTL_CAN_STATUS_DLC_MASK) >> TTL_CAN_STATUS_DLC_POS;
    error_code = (status & TTL_CAN_STATUS_ERROR_CODE_MASK) >> TTL_CAN_STATUS_ERROR_CODE_POS;

    if (status & TTL_CAN_STATUS_VALID_BIT_MASK) {   /* DLC, ID and Payload are valid */
        if (size < sizeof(uint32_t)) {    /* No more data */
            return TTL_CORRUPTED;
        }

        if (!ttl_read_bytes(in, &can_id, sizeof(uint32_t), err, err_info)) {
            return TTL_ERROR;
        }
        can_id = GUINT32_FROM_LE(can_id);
        size -= sizeof(uint32_t);

        if (size == 0 && !(status & TTL_CAN_STATUS_RTR_BIT_MASK)) {
            /* No more data, and it's not a remote transmission frame */
            return TTL_CORRUPTED;
        }
    }

    if (error_code) {
        can_id = CAN_ERR_FLAG;
        if (status & TTL_CAN_STATUS_BUSOFF_MASK) can_id |= CAN_ERR_BUSOFF;
        len = CAN_ERR_DLC;

        switch (error_code) {
        case TTL_CAN_ERROR_STUFF_ERROR:
            can_id |= CAN_ERR_PROT;
            can_error_payload[2] = CAN_ERR_PROT_STUFF;
            break;
        case TTL_CAN_ERROR_FORM_ERROR:
            can_id |= CAN_ERR_PROT;
            can_error_payload[2] = CAN_ERR_PROT_FORM;
            break;
        case TTL_CAN_ERROR_ACK_ERROR:
            can_id |= CAN_ERR_ACK;
            break;
        case TTL_CAN_ERROR_BIT1_ERROR:
            can_id |= CAN_ERR_PROT;
            can_error_payload[2] = CAN_ERR_PROT_BIT1;
            break;
        case TTL_CAN_ERROR_BIT0_ERROR:
            can_id |= CAN_ERR_PROT;
            can_error_payload[2] = CAN_ERR_PROT_BIT0;
            break;
        case TTL_CAN_ERROR_CRC_ERROR:
            can_id |= CAN_ERR_PROT;
            can_error_payload[3] = CAN_ERR_PROT_LOC_CRC_SEQ;
            break;
        case TTL_CAN_ERROR_INVALID_DLC:
            can_id |= CAN_ERR_PROT;
            can_error_payload[3] = CAN_ERR_PROT_LOC_DLC;
            break;
        }
    }
    else {
        if (status & TTL_CAN_STATUS_RTR_BIT_MASK) can_id |= CAN_RTR_FLAG;
        if (status & TTL_CAN_STATUS_IDE_BIT_MASK) can_id |= CAN_EFF_FLAG;
        if (status & TTL_CAN_STATUS_EDL_BIT_MASK) {
            canfd_flags |= CANFD_FDF;
            len = canfd_dlc_to_length[dlc];
        }
        else {
            len = MIN(dlc, 8);
        }
        if (status & TTL_CAN_STATUS_BRS_BIT_MASK) canfd_flags |= CANFD_BRS;
        if (status & TTL_CAN_STATUS_ESI_BIT_MASK) canfd_flags |= CANFD_ESI;
    }

    phtonu32(&can_header[0], can_id);
    phtonu8(&can_header[4], len);
    phtonu8(&can_header[5], canfd_flags);
    phtonu8(&can_header[6], 0);
    phtonu8(&can_header[7], 0);

    ws_buffer_append(&rec->data, can_header, sizeof(can_header));

    if (error_code) {
        ws_buffer_append(&rec->data, can_error_payload, sizeof(can_error_payload));
        if (size != 0 && !ttl_skip_bytes(in, size, err, err_info)) {
            return TTL_ERROR;
        }
        ttl_init_rec(rec, timestamp, addr, item->pkt_encap, item->interface_id,
                     sizeof(can_header) + sizeof(can_error_payload), sizeof(can_header) + sizeof(can_error_payload));
    }
    else {
        if (size != 0 && !ttl_read_bytes_buffer(in, &rec->data, size, err, err_info)) {
            return TTL_ERROR;
        }
        ttl_init_rec(rec, timestamp, addr, item->pkt_encap, item->interface_id, size + sizeof(can_header), len + sizeof(can_header));
    }

    ttl_add_can_dir_option(rec);

    return TTL_NO_ERROR;
}

static void
ttl_add_lin_dir_option(wtap_rec* rec) {
    uint32_t opt = PACK_FLAGS_DIRECTION_INBOUND;    /* For the moment, we only support this */

    wtap_block_add_uint32_option(rec->block, OPT_EPB_FLAGS, opt);
}

static ttl_result_t
ttl_read_lin_data_entry(wtap_rec* rec, int* err, char** err_info, ttl_read_t* in, uint16_t size, uint16_t addr,
                        const ttl_addr_to_iface_entry_t* item, uint16_t status, uint64_t timestamp) {
    uint8_t     lin_header[8], lin_payload[8];
    uint8_t     dlc;

    if (item == NULL) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup("ttl_read_lin_data_entry called with NULL item");
        return TTL_ERROR;
    }

    dlc = size != 0 ? MIN((size - 1), 8) : 0;

    lin_header[0] = 1; /* message format rev = 1 */
    lin_header[1] = 0; /* reserved */
    lin_header[2] = 0; /* reserved */
    lin_header[3] = 0; /* reserved */
    lin_header[4] = dlc << 4;   /* dlc (4bit) | type (2bit) | checksum type (2bit) */
    lin_header[5] = status & TTL_LIN_STATUS_PID_MASK;  /* parity (2bit) | id (6bit) */
    lin_header[6] = 0; /* checksum */
    lin_header[7] = 0; /* errors */

    if (status & TTL_LIN_ERROR_PARITY_ERROR) lin_header[7] |= 0x04;
    if (status & TTL_LIN_ERROR_SYNC_ERROR) lin_header[7] |= 0x02;  /* Is this correct? */
    if (status & TTL_LIN_ERROR_NO_DATA_ERROR) lin_header[7] |= 0x01;
    if (status & TTL_LIN_ERROR_ABORT_ERROR) lin_header[7] |= 0x02; /* Is this correct? */
    /* Set the checksum error if the checksum is wrong with respect to both types */
    if ((status & TTL_LIN_ERROR_ANY_CHECKSUM) == TTL_LIN_ERROR_ANY_CHECKSUM) lin_header[7] |= 0x08;

    if (dlc != 0) {
        if (!ttl_read_bytes(in, &lin_payload[0], dlc, err, err_info)) {
            return TTL_ERROR;
        }
        size -= dlc;
    }

    if (size != 0) {
        if (!ttl_read_bytes(in, &lin_header[6], 1, err, err_info)) {
            return TTL_ERROR;
        }
        size -= 1;
    }

    if (size != 0) {    /* Skip any extra byte */
        if (!ttl_skip_bytes(in, size, err, err_info)) {
            return TTL_ERROR;
        }
    }

    ws_buffer_append(&rec->data, lin_header, sizeof(lin_header));

    if (dlc != 0) {
        ws_buffer_append(&rec->data, lin_payload, dlc);
    }

    ttl_init_rec(rec, timestamp, addr, item->pkt_encap, item->interface_id, dlc + sizeof(lin_header), dlc + sizeof(lin_header));
    ttl_add_lin_dir_option(rec);

    return TTL_NO_ERROR;
}

static void
ttl_add_flexray_dir_option(wtap_rec* rec) {
    uint32_t opt = PACK_FLAGS_DIRECTION_INBOUND;    /* For the moment, we only support this */

    wtap_block_add_uint32_option(rec->block, OPT_EPB_FLAGS, opt);
}

static ttl_result_t
ttl_read_flexray_data_entry(wtap_rec* rec, int* err, char** err_info, ttl_read_t* in, uint16_t size, uint16_t addr,
                            const ttl_addr_to_iface_entry_t* item, uint16_t status, uint64_t timestamp) {
    uint8_t     fr_item;
    uint8_t     fr_header[2];

    if (item == NULL) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup("ttl_read_flexray_data_entry called with NULL item");
        return TTL_ERROR;
    }

    fr_item = status & TTL_FLEXRAY_ITEM_MASK;

    if (fr_item != TTL_FLEXRAY_ITEM_REGULAR_FRAME && fr_item != TTL_FLEXRAY_ITEM_ABORTED_FRAME) {   /* TODO */
        if (!ttl_skip_bytes(in, size, err, err_info)) {
            return TTL_ERROR;
        }
        return TTL_UNSUPPORTED;
    }

    fr_header[0] = FLEXRAY_FRAME;
    fr_header[1] = 0;   /* Errors */

    if (item->channelB) fr_header[0] |= 0x80;

    if (status & (TTL_FLEXRAY_FSS_ERROR_MASK | TTL_FLEXRAY_BSS_ERROR_MASK)) fr_header[1] |= 0x02;
    if (status & TTL_FLEXRAY_FES_ERROR_MASK) fr_header[1] |= 0x04;
    if (status & TTL_FLEXRAY_FRAME_CRC_ERROR_MASK) fr_header[1] |= 0x10;
    if (status & TTL_FLEXRAY_HEADER_CRC_ERROR_MASK) fr_header[1] |= 0x08;

    ws_buffer_append(&rec->data, fr_header, sizeof(fr_header));

    if (size != 0 && !ttl_read_bytes_buffer(in, &rec->data, size, err, err_info)) {
        return TTL_ERROR;
    }

    ttl_init_rec(rec, timestamp, addr, item->pkt_encap, item->interface_id, size + sizeof(fr_header), size + sizeof(fr_header));
    ttl_add_flexray_dir_option(rec);

    return TTL_NO_ERROR;
}

static ttl_result_t
ttl_read_data_entry(wtap* wth, wtap_rec* rec, int* err, char** err_info, ttl_read_t* in, uint16_t size, uint16_t src, uint16_t status) {
    const ttl_addr_to_iface_entry_t* item;
    int         pkt_encap = ttl_get_address_iface_type(src);
    uint64_t    timestamp;

    if (pkt_encap <= WTAP_ENCAP_UNKNOWN) {
        ws_debug("ttl_read_data_entry: Unsupported source address found in TTL_BUS_DATA_ENTRY: 0x%X", src);
        if (!ttl_skip_bytes(in, size, err, err_info)) {
            return TTL_ERROR;
        }
        return TTL_UNSUPPORTED;
    }

    *err = 0;
    item = ttl_lookup_interface(wth, src, err, err_info);
    if (*err) {
        return TTL_ERROR;
    }

    if (size < sizeof(uint64_t)) {
        return TTL_CORRUPTED;
    }
    if (!ttl_read_bytes(in, &timestamp, sizeof(uint64_t), err, err_info)) {
        return TTL_ERROR;
    }
    timestamp = GUINT64_FROM_LE(timestamp);
    size -= sizeof(uint64_t);

    switch (pkt_encap) {
    case WTAP_ENCAP_ETHERNET:
        return ttl_read_eth_data_entry(rec, err, err_info, in, size, src, item, status, timestamp);
    case WTAP_ENCAP_SOCKETCAN:
        return ttl_read_can_data_entry(rec, err, err_info, in, size, src, item, status, timestamp);
    case WTAP_ENCAP_LIN:
        return ttl_read_lin_data_entry(rec, err, err_info, in, size, src, item, status, timestamp);
    case WTAP_ENCAP_FLEXRAY:
        return ttl_read_flexray_data_entry(rec, err, err_info, in, size, src, item, status, timestamp);
    default:
        ws_debug("ttl_read_data_entry: Unsupported packet type found in TTL_BUS_DATA_ENTRY: %d", pkt_encap);
        if (!ttl_skip_bytes(in, size, err, err_info)) {
            return TTL_ERROR;
        }
        return TTL_UNSUPPORTED;
    }

}

static bool
ttl_check_segmented_message_recursion(const ttl_read_t* in, int* err, char** err_info) {
    ttl_entryheader_t header;

    if (in->validity != VALIDITY_BUF) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup("tt_fix_segmented_message_entry_payload: input buffer is not valid");
        return false;
    }

    memcpy(&header, in->buf + in->cur_pos, sizeof(ttl_entryheader_t));
    fix_endianness_ttl_entryheader(&header);

    if ((header.size_type >> 12) == TTL_SEGMENTED_MESSAGE_ENTRY) {
        return false;
    }

    return true;
}

/*
 * For some reason, the timestamp of the nested frame is garbage.
 * Copy the timestamp of the first segment in its place.
 */
static bool
ttl_fix_segmented_message_entry_timestamp(const ttl_read_t* in, uint64_t timestamp, int* err, char** err_info) {
    ttl_entryheader_t header;

    if (in->validity != VALIDITY_BUF) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup("tt_fix_segmented_message_entry_payload: input buffer is not valid");
        return false;
    }

    memcpy(&header, in->buf + in->cur_pos, sizeof(ttl_entryheader_t));
    fix_endianness_ttl_entryheader(&header);

    if ((header.size_type >> 12) == TTL_BUS_DATA_ENTRY) {
        timestamp = GUINT64_TO_LE(timestamp);
        memcpy(in->buf + in->cur_pos + sizeof(ttl_entryheader_t), &timestamp, sizeof(uint64_t));
    }

    return true;
}

// NOLINTNEXTLINE(misc-no-recursion)
static ttl_result_t ttl_read_segmented_message_entry(wtap* wth, wtap_rec* rec, int* err, char** err_info, ttl_read_t* in,
                                                     uint16_t size, uint16_t src, uint16_t status, int64_t offset) {
    ttl_segmented_entry_t* item;
    ttl_reassembled_entry_t* reassembled_item;
    ttl_t*      ttl = (ttl_t*)wth->priv;
    uint64_t    timestamp;
    uint8_t     frame_num = status & 0x000f;
    uint8_t     seg_frame_id = (status >> 4) & 0x000f;
    uint32_t    key = ((uint32_t)seg_frame_id << 16) | src;
    ttl_read_t  new_in;

    if (status == 0xFFFF) { /* Reserved for future use */
        if (!ttl_skip_bytes(in, size, err, err_info)) {
            return TTL_ERROR;
        }
        return TTL_UNSUPPORTED;
    }

    reassembled_item = g_hash_table_lookup(ttl->reassembled_frames_ht, &offset);

    if (reassembled_item == NULL) {
        if (size < sizeof(uint64_t)) {
            return TTL_CORRUPTED;
        }
        if (!ttl_read_bytes(in, &timestamp, sizeof(uint64_t), err, err_info)) {
            return TTL_ERROR;
        }
        timestamp = GUINT64_FROM_LE(timestamp);
        size -= sizeof(uint64_t);

        item = g_hash_table_lookup(ttl->segmented_frames_ht, GUINT_TO_POINTER(key));

        if (frame_num == 0) {   /* This is the first segment */
            if (item != NULL) { /* New header with reassemble in progress */
                ws_debug("ttl_read_segmented_message_entry: Found new header while reassembly was in progress for SRC %d, FRAME ID %d", src, seg_frame_id);
                g_hash_table_remove(ttl->segmented_frames_ht, GUINT_TO_POINTER(key));
            }

            if (size < (2 * sizeof(uint32_t))) {    /* Size and type below */
                return TTL_CORRUPTED;
            }

            item = (ttl_segmented_entry_t*)g_new0(ttl_segmented_entry_t, 1);
            item->timestamp = timestamp;

            if (!ttl_read_bytes(in, &item->size, sizeof(uint32_t), err, err_info)) {
                g_free(item);
                return TTL_ERROR;
            }
            item->size = GUINT32_FROM_LE(item->size);
            size -= sizeof(uint32_t);

            if (!ttl_read_bytes(in, &item->type, sizeof(uint32_t), err, err_info)) {
                g_free(item);
                return TTL_ERROR;
            }
            item->type = GUINT32_FROM_LE(item->type);
            size -= sizeof(uint32_t);

            /* If the reassembled size is too big, we go on as usual, but without a buffer.
             * This way we avoid problems with segments later.
             */
            if (item->size <= WTAP_MAX_PACKET_SIZE_STANDARD) {
                item->buf = g_try_malloc(item->size);
                if (item->buf == NULL) {
                    g_free(item);
                    *err = WTAP_ERR_INTERNAL;
                    *err_info = ws_strdup("ttl_read_segmented_message_entry: cannot allocate memory");
                    return TTL_ERROR;
                }
            }

            g_hash_table_insert(ttl->segmented_frames_ht, GUINT_TO_POINTER(key), item);
        }
        else {
            if (item == NULL) {
                ws_debug("ttl_read_segmented_message_entry: Found frame number %d without header for SRC %d, FRAME ID %d", frame_num, src, seg_frame_id);
                if (!ttl_skip_bytes(in, size, err, err_info)) {
                    return TTL_ERROR;
                }
                return TTL_UNSUPPORTED;
            }

            if (item->next_segment != frame_num) {
                ws_debug("ttl_read_segmented_message_entry: Found out of order segment (expected %d, found %d) for SRC %d, FRAME ID %d",
                    item->next_segment, frame_num, src, seg_frame_id);
                if (!ttl_skip_bytes(in, size, err, err_info)) {
                    return TTL_ERROR;
                }
                return TTL_UNSUPPORTED;
            }
        }

        if ((item->size_so_far + size) > item->size) {
            g_hash_table_remove(ttl->segmented_frames_ht, GUINT_TO_POINTER(key));
            return TTL_CORRUPTED;
        }

        void* dest_buf = item->buf != NULL ? item->buf + item->size_so_far : NULL;
        if (!ttl_read_bytes(in, dest_buf, size, err, err_info)) {
            g_hash_table_remove(ttl->segmented_frames_ht, GUINT_TO_POINTER(key));
            return TTL_ERROR;
        }
        item->size_so_far += size;
        item->next_segment++;

        if (item->size_so_far >= item->size) {  /* Reassemble complete */
            if (item->buf == NULL) {
                /* Silently discard packets we reassembled without data */
                g_hash_table_remove(ttl->segmented_frames_ht, GUINT_TO_POINTER(key));
                return TTL_UNSUPPORTED;
            }

            if (item->type != TTL_SEGMENTED_MESSAGE_ENTRY_TYPE_NESTED_FRAME) {
                ws_debug("ttl_read_segmented_message_entry: Unsupported type found: %d", item->type);
                g_hash_table_remove(ttl->segmented_frames_ht, GUINT_TO_POINTER(key));
                return TTL_UNSUPPORTED;
            }

            reassembled_item = (ttl_reassembled_entry_t*)g_new(ttl_reassembled_entry_t, 1);
            reassembled_item->timestamp = item->timestamp;
            reassembled_item->size = item->size;
            reassembled_item->buf = item->buf;

            item->buf = NULL;   /* Dereference it so that it doesn't get destroyed */
            g_hash_table_remove(ttl->segmented_frames_ht, GUINT_TO_POINTER(key));
            int64_t* new_off = g_new(int64_t, 1);
            *new_off = offset;
            g_hash_table_insert(ttl->reassembled_frames_ht, new_off, reassembled_item);
        }
        else {  /* Reassemble not complete, wait for the rest */
            return TTL_UNSUPPORTED;
        }
    }
    else {
        /* We already have the reassembled item, maybe we're re-visiting this entry. Simply skip to the end. */
        if (!ttl_skip_bytes(in, size, err, err_info)) {
            return TTL_ERROR;
        }
    }

    /* If we're here, we have our reassembled entry */
    new_in.buf = reassembled_item->buf;
    new_in.size = reassembled_item->size;
    new_in.cur_pos = 0;
    new_in.validity = VALIDITY_BUF;

    /* Avoid recursion by not supporting nested segmented entries */
    *err = 0;
    if (!ttl_check_segmented_message_recursion(&new_in, err, err_info)) {
        g_hash_table_remove(ttl->reassembled_frames_ht, &offset);

        if (*err) {
            return TTL_ERROR;
        }
        return TTL_UNSUPPORTED;
    }

    if (!ttl_fix_segmented_message_entry_timestamp(&new_in, reassembled_item->timestamp, err, err_info)) {
        g_hash_table_remove(ttl->reassembled_frames_ht, &offset);
        return TTL_ERROR;
    }

    /* Read it as if it was a normal entry, but passing the buffer
     * as input instead of the file handler.
     */
    return ttl_read_entry(wth, rec, err, err_info, &new_in, 0, new_in.size);
}

static ttl_result_t
ttl_read_padding_entry(int* err, char** err_info, ttl_read_t* in, uint16_t size) {
    if (!ttl_skip_bytes(in, size, err, err_info)) {
        return TTL_ERROR;
    }
    return TTL_UNSUPPORTED;
}

// NOLINTNEXTLINE(misc-no-recursion)
static ttl_result_t ttl_read_entry(wtap* wth, wtap_rec* rec, int* err, char** err_info, ttl_read_t* in, int64_t offset, int64_t end) {
    ttl_entryheader_t header;
    uint16_t    size;
    uint16_t    src_addr;
    uint8_t     type;

    if ((end - offset) < (int64_t)sizeof(ttl_entryheader_t)) {
        /*
         * We probably have a corrupted file, try to recover our alignment
         * by skipping to the next block.
         */
        return TTL_CORRUPTED;
    }

    /* Try to read the (next) entry header */
    if (!ttl_read_bytes(in, &header, sizeof(ttl_entryheader_t), err, err_info)) {
        return TTL_ERROR;
    }
    fix_endianness_ttl_entryheader(&header);

    type = header.size_type >> 12;
    size = header.size_type & TTL_SIZE_MASK;
    src_addr = header.src_addr & TTL_ADDRESS_MASK;

    if (size < sizeof(ttl_entryheader_t) || size > (end - offset)) {
        /*
         * Hope the file is simply unaligned and skipping to the next block
         * will fix everything. This could also be the sign of a malformed
         * file; in that case, this error will repeat itself many times.
         */
        return TTL_CORRUPTED;
    }

    size -= sizeof(ttl_entryheader_t);

    if (header.dest_addr & TTL_META1_COMPRESSED_FORMAT_MASK) {
        /* We do not support this kind of entries yet. */
        ws_debug("ttl_read_entry: Skipping entry with compressed timestamp");
        if (!ttl_skip_bytes(in, size, err, err_info)) {
            return TTL_ERROR;
        }
        return TTL_UNSUPPORTED;
    }

    switch (type) {
    case TTL_BUS_DATA_ENTRY:
        return ttl_read_data_entry(wth, rec, err, err_info, in, size, src_addr, header.status_info);
    case TTL_SEGMENTED_MESSAGE_ENTRY:
        /* Recursion is avoided inside ttl_read_segmented_message_entry() */
        return ttl_read_segmented_message_entry(wth, rec, err, err_info, in, size, src_addr, header.status_info, offset);
    case TTL_PADDING_ENTRY:
        return ttl_read_padding_entry(err, err_info, in, size);
    default:
        ws_debug("ttl_read_entry: Unknown Entry type: %u", type);
        if (!ttl_skip_bytes(in, size, err, err_info)) {
            return TTL_ERROR;
        }
        return TTL_UNSUPPORTED;
    }

}

static bool
ttl_xml_node_get_number(xmlNodePtr node, xmlXPathContextPtr ctx, double *ret) {
    xmlXPathObjectPtr result;
    double val;

    if (ret == NULL) {
        return false;
    }

    result = xmlXPathNodeEval(node, "./Number[1]/text()", ctx);
    if (result && result->type == XPATH_NODESET && !xmlXPathNodeSetIsEmpty(result->nodesetval)) {
        val = xmlXPathCastToNumber(result);
        if (!xmlXPathIsNaN(val)) {
            *ret = val;
            xmlXPathFreeObject(result);
            return true;
        }
    }

    return false;
}

static bool
ttl_xml_node_get_string(xmlNodePtr node, xmlXPathContextPtr ctx, const char* name, char** ret) {
    xmlXPathObjectPtr result;
    char* str;

    if (name == NULL || ret == NULL) {
        return false;
    }

    str = ws_strdup_printf("./%s[1]/text()", name);

    result = xmlXPathNodeEval(node, str, ctx);
    g_free(str);
    if (result && result->type == XPATH_NODESET && !xmlXPathNodeSetIsEmpty(result->nodesetval)) {
        str = xmlXPathCastToString(result);
        *ret = ws_strdup(str);
        xmlFree(str);
        return true;
    }

    return false;
}

static bool
ttl_process_xml_config(ttl_t* ttl, const char* text, int size) {
    xmlDocPtr           doc;
    xmlXPathContextPtr  ctx;
    xmlXPathObjectPtr   cascades, devices, functions;
    int         i, j, k;
    double      val;
    uint16_t    cascade, device, function, addr;
    char*       user_defined_name = NULL;

    doc = xmlParseMemory(text, size);
    if (doc == NULL) {
        return false;
    }

    if (xmlDocGetRootElement(doc) == NULL) {
        xmlFreeDoc(doc);
        return false;   /* Empty XML */
    }

    ctx = xmlXPathNewContext(doc);
    cascades = xmlXPathEvalExpression("/LoggerConfiguration/HWList/Cascades/Cascade", ctx);
    if (cascades && cascades->type == XPATH_NODESET && !xmlXPathNodeSetIsEmpty(cascades->nodesetval)) {
        for (i = 0; i < cascades->nodesetval->nodeNr; i++) {
            if (ttl_xml_node_get_number(cascades->nodesetval->nodeTab[i], ctx, &val) && val >= 0 && val <= 7) {
                cascade = (uint16_t)val;
                if (val == 0) { /* Only the configuration of the logger is inside the TTL file. The TAPs have their own configuration */

                    devices = xmlXPathNodeEval(cascades->nodesetval->nodeTab[i], "./Devices/Device", ctx);
                    if (devices && devices->type == XPATH_NODESET && !xmlXPathNodeSetIsEmpty(devices->nodesetval)) {
                        for (j = 0; j < devices->nodesetval->nodeNr; j++) {
                            if (ttl_xml_node_get_number(devices->nodesetval->nodeTab[j], ctx, &val) && val >= 0 && val <= 15) {
                                device = (uint16_t)val;

                                functions = xmlXPathNodeEval(devices->nodesetval->nodeTab[j], "./Functions/Function", ctx);
                                if (functions && functions->type == XPATH_NODESET && !xmlXPathNodeSetIsEmpty(functions->nodesetval)) {
                                    for (k = 0; k < functions->nodesetval->nodeNr; k++) {
                                        if (ttl_xml_node_get_number(functions->nodesetval->nodeTab[k], ctx, &val) && val >= 0 && val <= 63) {
                                            function = (uint16_t)val;
                                            addr = cascade << 10 | device << 6 | function;

                                            if (g_hash_table_lookup(ttl->address_to_name_ht, GUINT_TO_POINTER(addr)) == NULL) {
                                                /* Get the name only if we don't already have it */
                                                if (ttl_xml_node_get_string(functions->nodesetval->nodeTab[k], ctx, "UserDefinedName", &user_defined_name)) {
                                                    g_hash_table_insert(ttl->address_to_name_ht, GUINT_TO_POINTER(addr), user_defined_name);
                                                    /* XXX - At this point, we should check if the interface (in case of Ethernet)
                                                     * is a standalone interface or it's a coupled interface. Since getting this
                                                     * information from the XML is a pain, and the configuration will never be
                                                     * exhaustive, give up and rely on the user setting the mapping themself.
                                                     */
                                                }
                                            }

                                        }
                                    }
                                }
                                xmlXPathFreeObject(functions);
                            }
                        }
                    }
                    xmlXPathFreeObject(devices);
                }
            }
        }
    }
    xmlXPathFreeObject(cascades);

    xmlXPathFreeContext(ctx);
    xmlFreeDoc(doc);
    return true;
}

/* Maximum supported line length of preference files */
#define MAX_LINELEN     1024

/** Read a line without trailing (CR)LF. Returns -1 on failure.  */
static int
fgetline(char* buf, int size, FILE* fp)
{
    if (fgets(buf, size, fp)) {
        int len = (int)strcspn(buf, "\r\n");
        buf[len] = '\0';
        return len;
    }
    return -1;

} /* fgetline */

static bool
ttl_is_master_slave_relation_correct(uint16_t master, uint16_t slave) {
    uint8_t function = ttl_addr_get_function(master);

    if (ttl_addr_get_cascade(master) == 0) {
        switch (ttl_addr_get_device(master)) {
        case TTL_LOGGER_DEVICE_FPGA:
            if (function == TTL_LOGGER_FPGA_FUNCTION_ETHA_CH1) {
                return (slave == (master + 1));
            }
            break;
        case TTL_LOGGER_DEVICE_ATOM:
            if (function == TTL_LOGGER_ATOM_FUNCTION_ETHA) {
                return (slave == (master + 1));
            }
            break;
        case TTL_LOGGER_DEVICE_FPGAB:
            switch (function) {
            case TTL_LOGGER_FPGAB_FUNCTION_ETHA_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH1a_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH2a_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH3a_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH4a_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH5a_CH1:
            case TTL_LOGGER_FPGAB_FUNCTION_AETH6a_CH1:
                return (slave == (master + 1));
            default:
                break;
            }
            break;
        default:
            break;
        }
    }
    else {
        switch (ttl_addr_get_device(master)) {
        case TTL_TAP_DEVICE_PT15_FPGA:
            switch (function) {
            case TTL_PT15_FPGA_FUNCTION_BrdR1a:
            case TTL_PT15_FPGA_FUNCTION_BrdR2a:
            case TTL_PT15_FPGA_FUNCTION_BrdR3a:
            case TTL_PT15_FPGA_FUNCTION_BrdR4a:
            case TTL_PT15_FPGA_FUNCTION_BrdR5a:
            case TTL_PT15_FPGA_FUNCTION_BrdR6a:
                return (slave == (master + 1));
            default:
                break;
            }
            break;
        case TTL_TAP_DEVICE_PT20_FPGA:
            switch (function) {
            case TTL_PT20_FPGA_FUNCTION_GbEth1a:
            case TTL_PT20_FPGA_FUNCTION_GbEth2a:
            case TTL_PT20_FPGA_FUNCTION_GbEth3a:
                return (slave == (master + 1));
            default:
                break;
            }
            break;
        case TTL_TAP_DEVICE_PC3_FPGA:
            if (function == TTL_PC3_FPGA_FUNCTION_BrdR1a) {
                return (slave == (master + 1));
            }
            break;
        default:
            break;
        }
    }

    return false;
}

static bool
ttl_parse_masters_pref_file(ttl_t* ttl, const char* path) {
    FILE*       fp;
    char        line[MAX_LINELEN];
    char*       cp;
    uint16_t    addr, tmp;

    if (path == NULL) {
        return false;
    }

    fp = ws_fopen(path, "r");
    if (fp == NULL) {
        return false;
    }

    while (fgetline(line, sizeof(line), fp) >= 0) {
        if ((cp = strchr(line, '#')))
            *cp = '\0';

        cp = strtok(line, " \t");
        if (cp == NULL || !ws_strtou16(cp, NULL, &tmp) || tmp > 7) {
            continue;   /* Invalid cascade */
        }
        addr = tmp << 10;

        cp = strtok(NULL, " \t");
        if (cp == NULL || !ws_strtou16(cp, NULL, &tmp) || tmp > 15) {
            continue;   /* Invalid device */
        }
        addr |= tmp << 6;

        cp = strtok(NULL, " \t");
        if (cp == NULL || !ws_strtou16(cp, NULL, &tmp) || tmp > 63) {
            continue;   /* Invalid function */
        }
        addr |= tmp;

        cp = strtok(NULL, " \t");
        if (cp == NULL || !ws_strtou16(cp, NULL, &tmp) || tmp > 1) {
            continue;   /* Invalid flag */
        }

        if (tmp) {  /* The address is coupled to the master */
            if (addr != 0 && ttl_is_master_slave_relation_correct(addr - 1, addr)) {
                g_hash_table_insert(ttl->address_to_master_ht, GUINT_TO_POINTER(addr), GUINT_TO_POINTER(addr - 1));
            }
        }
        else {  /* The address is independent from the master */
            g_hash_table_insert(ttl->address_to_master_ht, GUINT_TO_POINTER(addr), GUINT_TO_POINTER(addr));
        }
    }

    fclose(fp);
    return true;
}

/*
 * This function gets the working mode of the Ethernet interfaces from a
 * configuration file. This only applies to the interfaces that can be
 * configured both as the second side of a tap and independent interfaces.
 * The entry format is the following:   Cascade  Device  Function    Flag
 * A flag value of 0 means independent interface, while 1 means coupled with
 * its master. If an entry is not present, the interface will be treated
 * by ttl_lookup_interface() according to the default behaviour (currently,
 * independent interface for the logger and coupled interface for the taps).
 */
static bool
ttl_init_masters_from_pref_file(ttl_t* ttl) {
    char*   pref_file;
    bool    ret;

    pref_file = get_persconffile_path(TTL_ADDRESS_MASTER_PREFS, true);
    ret = ttl_parse_masters_pref_file(ttl, pref_file);
    g_free(pref_file);
    if (!ret) {
        pref_file = get_persconffile_path(TTL_ADDRESS_MASTER_PREFS, false);
        ret = ttl_parse_masters_pref_file(ttl, pref_file);
        g_free(pref_file);
    }

    return ret;
}

static bool
ttl_parse_names_pref_file(ttl_t* ttl, const char* path) {
    FILE*       fp;
    char        line[MAX_LINELEN];
    char*       cp;
    uint16_t    addr, tmp;
    char*       name;

    if (path == NULL) {
        return false;
    }

    fp = ws_fopen(path, "r");
    if (fp == NULL) {
        return false;
    }

    while (fgetline(line, sizeof(line), fp) >= 0) {
        if ((cp = strchr(line, '#')))
            *cp = '\0';

        cp = strtok(line, " \t");
        if (cp == NULL || !ws_strtou16(cp, NULL, &tmp) || tmp > 7) {
            continue;   /* Invalid cascade */
        }
        addr = tmp << 10;

        cp = strtok(NULL, " \t");
        if (cp == NULL || !ws_strtou16(cp, NULL, &tmp) || tmp > 15) {
            continue;   /* Invalid device */
        }
        addr |= tmp << 6;

        cp = strtok(NULL, " \t");
        if (cp == NULL || !ws_strtou16(cp, NULL, &tmp) || tmp > 63) {
            continue;   /* Invalid function */
        }
        addr |= tmp;

        cp = strtok(NULL, " \t");
        if (cp != NULL && strlen(cp) != 0) {
            name = ws_strdup(cp);
            g_hash_table_insert(ttl->address_to_name_ht, GUINT_TO_POINTER(addr), name);
        }
    }

    fclose(fp);
    return true;
}

/*
 * This function gets the names of the interfaces from a configuration file.
 * The entry format is the following:   Cascade  Device  Function    Name
 * If an entry is not present, the value from the configuration XML in the file
 * is used. If also that is not present, a meaningful name is generated in
 * ttl_add_interface_name() starting from the interface address.
 */
static bool
ttl_init_names_from_pref_file(ttl_t* ttl) {
    char*   pref_file;
    bool    ret;

    pref_file = get_persconffile_path(TTL_ADDRESS_NAME_PREFS, true);
    ret = ttl_parse_names_pref_file(ttl, pref_file);
    g_free(pref_file);
    if (!ret) {
        pref_file = get_persconffile_path(TTL_ADDRESS_NAME_PREFS, false);
        ret = ttl_parse_names_pref_file(ttl, pref_file);
        g_free(pref_file);
    }

    return ret;
}

static void
ttl_cleanup(ttl_t* ttl) {
    if (ttl != NULL) {
        if (ttl->address_to_iface_ht != NULL) {
            g_hash_table_destroy(ttl->address_to_iface_ht);
        }
        if (ttl->address_to_master_ht != NULL) {
            g_hash_table_destroy(ttl->address_to_master_ht);
        }
        if (ttl->address_to_name_ht != NULL) {
            g_hash_table_destroy(ttl->address_to_name_ht);
        }
        if (ttl->segmented_frames_ht != NULL) {
            g_hash_table_destroy(ttl->segmented_frames_ht);
        }
        if (ttl->reassembled_frames_ht != NULL) {
            g_hash_table_destroy(ttl->reassembled_frames_ht);
        }
        g_free(ttl);
    }
}

wtap_open_return_val
ttl_open(wtap* wth, int* err, char** err_info) {
    ttl_fileheader_t    header;
    ttl_t*              ttl;
    unsigned int        offset;

    ws_debug("opening file");

    if (!wtap_read_bytes_or_eof(wth->fh, &header, sizeof(ttl_fileheader_t), err, err_info)) {

        ws_debug("wtap_read_bytes_or_eof() failed, err = %d.", *err);
        if (*err == 0 || *err == WTAP_ERR_SHORT_READ) {
            /*
             * Short read or EOF.
             *
             * We're reading this as part of an open, so
             * the file is too short to be a ttl file.
             */
            *err = 0;
            g_free(*err_info);
            *err_info = NULL;
            return WTAP_OPEN_NOT_MINE;
        }
        return WTAP_OPEN_ERROR;
    }

    fix_endianness_ttl_fileheader(&header);

    if (memcmp(header.magic, ttl_magic, sizeof(ttl_magic))) {
        return WTAP_OPEN_NOT_MINE;
    }
    /* This seems to be a TLL! */

    /* Check for valid block size */
    if (header.block_size == 0) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("ttl: block size cannot be 0");
        return WTAP_OPEN_ERROR;
    }
    /* Check for a valid header length */
    if (header.header_size < sizeof(ttl_fileheader_t)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("ttl: file header length too short");
        return WTAP_OPEN_ERROR;
    }

    offset = (unsigned int)sizeof(ttl_fileheader_t);

    /* Prepare our private context. */
    ttl = g_new(ttl_t, 1);
    ttl->next_interface_id = 0;
    ttl->block_size = header.block_size;
    ttl->header_size = header.header_size;
    ttl->address_to_iface_ht = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    ttl->address_to_master_ht = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    ttl->address_to_name_ht = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    ttl->segmented_frames_ht = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, ttl_free_segmented_entry);
    ttl->reassembled_frames_ht = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, ttl_free_reassembled_entry);

    if (header.version >= 10) {
        if (header.header_size < (offset + TTL_LOGFILE_INFO_SIZE)) {
            report_warning("Found TTL file version %u with shorter header length than expected.", header.version);
        }
        else {
            /* TODO: Extract needed info from the rest of the header. */
            if (!wtap_read_bytes(wth->fh, NULL, TTL_LOGFILE_INFO_SIZE, err, err_info)) {
                ttl_cleanup(ttl);
                return WTAP_OPEN_ERROR;
            }
            offset += TTL_LOGFILE_INFO_SIZE;
            unsigned int xml_len = header.header_size - offset;
            if (xml_len != 0) {
                unsigned char* xml = g_try_malloc(xml_len);
                if (xml == NULL) {
                    *err = WTAP_ERR_INTERNAL;
                    *err_info = ws_strdup("ttl: cannot allocate memory");
                    ttl_cleanup(ttl);
                    return false;
                }
                if (!wtap_read_bytes(wth->fh, xml, xml_len, err, err_info)) {
                    g_free(xml);
                    ttl_cleanup(ttl);
                    return WTAP_OPEN_ERROR;
                }
                if (!ttl_process_xml_config(ttl, xml, xml_len)) {
                    report_warning("Cannot extract information from TTL XML.");
                }
                g_free(xml);
                offset += xml_len;
            }
        }
    }

    if ((header.header_size - offset) != 0) {
        if (!wtap_read_bytes(wth->fh, NULL, header.header_size - offset, err, err_info)) {
            ttl_cleanup(ttl);
            return WTAP_OPEN_ERROR;
        }
    }

    ttl_init_masters_from_pref_file(ttl);
    ttl_init_names_from_pref_file(ttl);

    wth->priv = (void*)ttl;
    wth->file_encap = WTAP_ENCAP_NONE;
    wth->snapshot_length = 0;
    wth->file_tsprec = WTAP_TSPREC_UNKNOWN;
    wth->subtype_read = ttl_read;
    wth->subtype_seek_read = ttl_seek_read;
    wth->subtype_close = ttl_close;
    wth->file_type_subtype = ttl_file_type_subtype;

    return WTAP_OPEN_MINE;
}

static inline int64_t
ttl_next_block(const ttl_t* ttl, int64_t pos) {
    if (ttl == NULL || pos < 0 || pos < ttl->header_size) {
        return pos;
    }

    return pos + ttl->block_size - ((pos - ttl->header_size) % ttl->block_size);
}

static bool ttl_read(wtap* wth, wtap_rec* rec, int* err, char** err_info, int64_t* data_offset) {
    ttl_read_t      input;
    int64_t         pos, end;
    ttl_result_t    res;

    input.fh = wth->fh;
    input.validity = VALIDITY_FH;

    do {
        pos = file_tell(wth->fh);
        end = ttl_next_block((ttl_t*)wth->priv, pos);

        res = ttl_read_entry(wth, rec, err, err_info, &input, pos, end);
        if (G_UNLIKELY(res == TTL_CORRUPTED)) {
            ws_warning("ttl_read(): Unaligned block found, skipping to next block offset: 0x%" PRIx64, end);
            report_warning("Found unaligned TTL block. Skipping to the next one.");
            if (file_seek(wth->fh, end, SEEK_SET, err) < 0) {
                return false;   /* Seek error */
            }
        }
        /*
         * XXX - For now we simply skip over any entry we don't understand,
         * but in the future we might want an easy way to report warnings
         * without spamming the user with dialog boxes.
         */
    } while (res > TTL_NO_ERROR);

    if (G_LIKELY(res == TTL_NO_ERROR)) {
        *data_offset = pos;
        return true;
    }

    return false;
}

static bool ttl_seek_read(wtap* wth, int64_t seek_off, wtap_rec* rec, int* err, char** err_info) {
    ttl_read_t      input;
    ttl_result_t    res;

    input.fh = wth->random_fh;
    input.validity = VALIDITY_FH;

    /* seek to the right file position */
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) < 0) {
        return false;   /* Seek error */
    }

    res = ttl_read_entry(wth, rec, err, err_info, &input, seek_off, ttl_next_block((ttl_t*)wth->priv, seek_off));
    if (G_LIKELY(res == TTL_NO_ERROR)) {
        return true;
    }

    if (res > TTL_NO_ERROR) {
        /*
         * If we're here, there has been an error during the first pass and we
         * returned true on an unsupported or unaligned entry.
         */
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("ttl_seek_read called with invalid offset: 0x%" PRIx64, seek_off);
    }

    return false;
}

static void ttl_close(wtap* wth) {
    if (wth != NULL) {
        ttl_cleanup((ttl_t*)wth->priv);
        wth->priv = NULL;
    }
}

 /* Options for interface blocks. */
static const struct supported_option_type interface_block_options_supported[] = {
    /* No comments, just an interface name. */
    { OPT_IDB_NAME, ONE_OPTION_SUPPORTED }
};

static const struct supported_block_type ttl_blocks_supported[] = {
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED },
    { WTAP_BLOCK_IF_ID_AND_INFO, MULTIPLE_BLOCKS_SUPPORTED, OPTION_TYPES_SUPPORTED(interface_block_options_supported) },
};

static const struct file_type_subtype_info ttl_info = {
        "TTTech Computertechnik TTX Logger (TTL) logfile", "ttl", "ttl", NULL,
        false, BLOCKS_SUPPORTED(ttl_blocks_supported),
        NULL, NULL, NULL
};

void register_ttl(void)
{
    ttl_file_type_subtype = wtap_register_file_type_subtype(&ttl_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("TTL", ttl_file_type_subtype);
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
