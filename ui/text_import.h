/** @file
 *
 * text_import.h
 * State machine for text import
 * November 2010, Jaap Keuter <jaap.keuter@xs4all.nl>
 * Modified February 2021, Paul Weiß
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Based on text2pcap.h by Ashok Narayanan <ashokn@cisco.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later*
 *******************************************************************************/


#ifndef __TEXT_IMPORT_H__
#define __TEXT_IMPORT_H__

#include <stdio.h>
#include <wireshark.h>

#include <wiretap/wtap.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* The parameter interface */

/**
 * @brief Numeric base used to render byte offsets in a hex dump import.
 */
enum offset_type
{
    OFFSET_NONE = 0, /**< No offset column present in the input */
    OFFSET_HEX,      /**< Offsets are written in hexadecimal */
    OFFSET_OCT,      /**< Offsets are written in octal */
    OFFSET_DEC       /**< Offsets are written in decimal */
};


/**
 * @brief Encoding used to represent raw byte data in a regex-mode text import.
 */
enum data_encoding {
    ENCODING_PLAIN_HEX, /**< Bytes encoded as plain hexadecimal digit pairs */
    ENCODING_PLAIN_OCT, /**< Bytes encoded as plain octal digit groups */
    ENCODING_PLAIN_BIN, /**< Bytes encoded as plain binary digit groups */
    ENCODING_BASE64     /**< Bytes encoded as Base64 */
};


/**
 * @brief Selects the synthetic protocol header prepended to each imported frame.
 */
enum dummy_header_type
{
    HEADER_NONE,        /**< No dummy header; raw payload only */
    HEADER_ETH,         /**< Prepend a dummy Ethernet II header */
    HEADER_IPV4,        /**< Prepend a dummy IPv4 header */
    HEADER_UDP,         /**< Prepend dummy IPv4 and UDP headers */
    HEADER_TCP,         /**< Prepend dummy IPv4 and TCP headers */
    HEADER_SCTP,        /**< Prepend dummy IPv4 and SCTP headers */
    HEADER_SCTP_DATA,   /**< Prepend dummy IPv4, SCTP, and SCTP DATA chunk headers */
    HEADER_EXPORT_PDU   /**< Prepend a Wireshark Export PDU header */
};


/**
 * @brief Selects the parsing mode used to extract packet data from the input text file.
 */
enum text_import_mode {
    TEXT_IMPORT_HEXDUMP, /**< Parse input as a hex dump with optional offset and ASCII columns */
    TEXT_IMPORT_REGEX    /**< Parse input by matching lines against a user-supplied regular expression */
};


/**
 * @brief Complete configuration and runtime state for a text-to-pcap import operation.
 */
typedef struct
{
    /* --- Input / output paths --- */
    char *import_text_filename; /**< Path to the input text file to be imported */
    char *output_filename;      /**< Path to the output capture file to be written */
    enum text_import_mode mode; /**< Parsing mode: hex dump or regex (see ::text_import_mode) */

    /** @brief Parameters used when @p mode is ::TEXT_IMPORT_HEXDUMP. */
    struct {
        FILE               *import_text_FILE; /**< Open file handle for the hex dump input file */
        enum offset_type    offset_type;      /**< Numeric base of the offset column in the hex dump */
        bool                has_direction;    /**< True if the hex dump includes an inbound/outbound direction indicator */
        bool                identify_ascii;   /**< True if printable ASCII runs should be detected and tagged */
        bool                little_endian;    /**< True if multi-byte values in the hex dump are little-endian */
    } hexdump;

    /** @brief Parameters used when @p mode is ::TEXT_IMPORT_REGEX. */
    struct {
        GMappedFile        *import_text_GMappedFile; /**< Memory-mapped view of the regex input file */
        GRegex             *format;                  /**< Compiled regular expression used to match packet records */
        enum data_encoding  encoding;                /**< Encoding of the byte data captured by the regex */
        char               *in_indication;           /**< String token in a match that marks the packet as inbound */
        char               *out_indication;          /**< String token in a match that marks the packet as outbound */
    } regex;

    const char *timestamp_format; /**< strptime-compatible format string used to parse timestamps in the input */

    /* --- Wiretap output --- */
    unsigned      encapsulation; /**< Wiretap encapsulation type for the output file (see wiretap/wtap.h) */
    wtap_dumper  *wdh;           /**< Wiretap dumper handle used to write the output capture file */

    /* --- Dummy header configuration (used when encapsulation == 1) --- */
    enum dummy_header_type dummy_header_type; /**< Type of synthetic header prepended to each frame */
    unsigned pid;    /**< Ethernet PID / EtherType inserted into the dummy Ethernet header */
    bool     ipv6;   /**< True if IPv6 addresses are used in the dummy IP header; false for IPv4 */

    /** @brief Source IP address inserted into the dummy IP header. */
    union {
        ws_in4_addr ipv4; /**< IPv4 source address (used when @p ipv6 is false) */
        ws_in6_addr ipv6; /**< IPv6 source address (used when @p ipv6 is true) */
    } ip_src_addr;

    /** @brief Destination IP address inserted into the dummy IP header. */
    union {
        ws_in4_addr ipv4; /**< IPv4 destination address (used when @p ipv6 is false) */
        ws_in6_addr ipv6; /**< IPv6 destination address (used when @p ipv6 is true) */
    } ip_dest_addr;

    unsigned protocol; /**< IP protocol number inserted into the dummy IP header */
    unsigned src_port; /**< Source port inserted into the dummy TCP/UDP/SCTP header */
    unsigned dst_port; /**< Destination port inserted into the dummy TCP/UDP/SCTP header */
    unsigned tag;      /**< SCTP verification tag inserted into the dummy SCTP header */
    unsigned ppi;      /**< Payload Protocol Identifier (PPI) inserted into the dummy SCTP DATA chunk */
    char    *payload;  /**< Wireshark dissector name embedded in the Export PDU header */

    unsigned max_frame_length; /**< Maximum number of bytes per imported frame; longer frames are truncated */

    /* --- Operation results --- */
    unsigned num_packets_read;    /**< Number of packet records successfully parsed from the input */
    unsigned num_packets_written; /**< Number of frames successfully written to the output capture file */
} text_import_info_t;

/**
 * @brief Import a text file.
 *
 * This function imports a text file and writes the SHB and IDB to the wtap_dump_params before opening the wtap dump file.
 * It initializes various parameters for packet processing, including timestamps and direction.
 *
 * @param info Pointer to the text import information structure.
 * @return Return status of the import operation.
 */
int text_import(text_import_info_t * const info);

/**
 * @brief Prepares the wtap_dump_params with necessary headers before opening the wtap dump file.
 *
 * Write the SHB and IDB to the wtap_dump_params before opening the wtap dump
 * file. While dummy headers can be written automatically, this writes out
 * some extra information including an optional interface name.
 *
 * NOTE: The caller will be responsible for freeing params->idb_inf after
 * finished with the wtap_dumper to avoid a memory leak. wtap_dump_close
 * does not free it.
 *
 * @param params Pointer to the wtap_dump_params structure.
 * @param file_type_subtype The type of the file to be opened.
 * @param input_filename The name of the input file.
 * @param interface_name The name of the interface.
 * @return Return status of the preparation operation.
 */
int
text_import_pre_open(wtap_dump_params * const params, int file_type_subtype, const char* const input_filename, const char* const interface_name);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TEXT_IMPORT_H__ */
