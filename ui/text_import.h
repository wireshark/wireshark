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

enum offset_type
{
    OFFSET_NONE = 0,
    OFFSET_HEX,
    OFFSET_OCT,
    OFFSET_DEC
};

enum data_encoding {
  ENCODING_PLAIN_HEX,
  ENCODING_PLAIN_OCT,
  ENCODING_PLAIN_BIN,
  ENCODING_BASE64
};

enum dummy_header_type
{
    HEADER_NONE,
    HEADER_ETH,
    HEADER_IPV4,
    HEADER_UDP,
    HEADER_TCP,
    HEADER_SCTP,
    HEADER_SCTP_DATA,
    HEADER_EXPORT_PDU
};

enum text_import_mode {
    TEXT_IMPORT_HEXDUMP,
    TEXT_IMPORT_REGEX
};

typedef struct
{
    /* Input info */
    // TODO: add const, as this way string constants can't be used
    // BUT: the other way clang-check complains when you free them
    /* const */ char *import_text_filename;
    char *output_filename;
    enum text_import_mode mode;

    struct {
        FILE *import_text_FILE;
        enum offset_type offset_type;
        bool has_direction;
        bool identify_ascii;
    } hexdump;
    struct {
        GMappedFile* import_text_GMappedFile;
        /* const */ GRegex* format;
        enum data_encoding encoding;
        /* const */ char* in_indication;
        /* const */ char* out_indication;
    } regex;
    const char* timestamp_format;

    /* Import info */
    /* Wiretap encapsulation type; see wiretap/wtap.h for details */
    unsigned encapsulation;
    wtap_dumper* wdh;

    /* Dummy header info (if encapsulation == 1) */
    enum dummy_header_type dummy_header_type;
    unsigned pid;
    bool ipv6;
    union {
        ws_in4_addr ipv4;
        ws_in6_addr ipv6;
    } ip_src_addr;
    union {
        ws_in4_addr ipv4;
        ws_in6_addr ipv6;
    } ip_dest_addr;
    unsigned protocol;
    unsigned src_port;
    unsigned dst_port;
    unsigned tag;
    unsigned ppi;
    /* const */ char* payload;

    unsigned max_frame_length;

    /* Output info */
    unsigned num_packets_read;
    unsigned num_packets_written;
} text_import_info_t;

int text_import(text_import_info_t * const info);

/* Write the SHB and IDB to the wtap_dump_params before opening the wtap dump
 * file. While dummy headers can be written automatically, this writes out
 * some extra information including an optional interface name.
 *
 * NOTE: The caller will be responsible for freeing params->idb_inf after
 * finished with the wtap_dumper to avoid a memory leak. wtap_dump_close
 * does not free it.
 */
int
text_import_pre_open(wtap_dump_params * const params, int file_type_subtype, const char* const input_filename, const char* const interface_name);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TEXT_IMPORT_H__ */
