/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_PCAPNG_H__
#define __W_PCAPNG_H__

#include <stdint.h>

#include "wtap.h"
#include "ws_symbol_export.h"

#define PCAPNG_MAGIC         0x1A2B3C4D
#define PCAPNG_SWAPPED_MAGIC 0x4D3C2B1A

#define PCAPNG_MAJOR_VERSION 1
#define PCAPNG_MINOR_VERSION 0

/**
 * @brief Common block header shared by every block type in a pcapng capture file.
 */
typedef struct pcapng_block_header_s {
    uint32_t block_type;         /**< Block type identifier indicating the format of the block body. */
    uint32_t block_total_length; /**< Total length in bytes of this block, including this header and the trailing length field. */
    /* x bytes of block body follow. */
    /* uint32_t block_total_length repeated at the end of every block for reverse traversal. */
} pcapng_block_header_t;

/**
 * @brief Section Header Block (SHB) body encoding in a pcapng file, marking the start of a capture section.
 */
typedef struct pcapng_section_header_block_s {
    /* Preceded by pcapng_block_header_t */
    uint32_t magic;           /**< Byte-order magic number (0x1A2B3C4D); used to detect file endianness. */
    uint16_t version_major;   /**< Major version of the pcapng format used in this section. */
    uint16_t version_minor;   /**< Minor version of the pcapng format used in this section. */
    uint64_t section_length;  /**< Length in bytes of this section excluding the SHB itself; -1 if unknown. */
    /* ... Options ... */
} pcapng_section_header_block_t;

/**
 * @brief Interface Description Block (IDB) body encoding in a pcapng file, describing a capture interface.
 */
typedef struct pcapng_interface_description_block_s {
    uint16_t linktype; /**< Data link type of packets captured on this interface, as a LINKTYPE_* value. */
    uint16_t reserved; /**< Reserved; must be zero. */
    uint32_t snaplen;  /**< Maximum number of octets captured per packet on this interface; 0 means no limit. */
    /* ... Options ... */
} pcapng_interface_description_block_t;

/**
 * @brief Interface Statistics Block (ISB) body encoding in a pcapng file, reporting per-interface capture statistics.
 */
typedef struct pcapng_interface_statistics_block_s {
    uint32_t interface_id;    /**< Zero-based index of the interface (referencing a prior IDB) to which these statistics apply. */
    uint32_t timestamp_high;  /**< High 32 bits of the 64-bit timestamp of this statistics record. */
    uint32_t timestamp_low;   /**< Low 32 bits of the 64-bit timestamp of this statistics record. */
    /* ... Options ... */
} pcapng_interface_statistics_block_t;

/**
 * @brief Decryption Secrets Block (DSB) body encoding in a pcapng file, embedding key material for decrypting captured traffic.
 */
typedef struct pcapng_decryption_secrets_block_s {
    uint32_t secrets_type; /**< Secrets type identifier indicating the format of the embedded key material; see secrets-types.h. */
    uint32_t secrets_len;  /**< Length in bytes of the variable-length secrets data that follows this header. */
    /* x bytes of Secrets Data follow. */
    /* ... Options ... */
} pcapng_decryption_secrets_block_t;

/**
 * @brief Option header used to encode a single TLV option appended to a pcapng block.
 */
struct pcapng_option_header {
    uint16_t type;         /**< Option type code identifying the meaning of this option's value. */
    uint16_t value_length; /**< Length in bytes of the option value that follows this header; padded to a 4-byte boundary in the file. */
};

/**
 * @brief Opens a pcapng file.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Pointer to an integer that will be set to an error code if an error occurs.
 * @param err_info Pointer to a string that will be set to an error message if an error occurs.
 * @return wtap_open_return_val The result of opening the file.
 */
wtap_open_return_val pcapng_open(wtap *wth, int *err, char **err_info);

#endif
