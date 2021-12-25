/* text_import.c
 * State machine for text import
 * November 2010, Jaap Keuter <jaap.keuter@xs4all.nl>
 * Modified March 2021, Paul Weiß <paulniklasweiss@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Based on text2pcap.c by Ashok Narayanan <ashokn@cisco.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*******************************************************************************
 *
 * This code reads in an ASCII hexdump of this common format:
 *
 * 00000000  00 E0 1E A7 05 6F 00 10 5A A0 B9 12 08 00 46 00 .....o..Z.....F.
 * 00000010  03 68 00 00 00 00 0A 2E EE 33 0F 19 08 7F 0F 19 .h.......3......
 * 00000020  03 80 94 04 00 00 10 01 16 A2 0A 00 03 50 00 0C .............P..
 * 00000030  01 01 0F 19 03 80 11 01 1E 61 00 0C 03 01 0F 19 .........a......
 *
 * Each bytestring line consists of an offset, one or more bytes, and
 * text at the end. An offset is defined as a hex string of more than
 * two characters. A byte is defined as a hex string of exactly two
 * characters. The text at the end is ignored, as is any text before
 * the offset. Bytes read from a bytestring line are added to the
 * current packet only if all the following conditions are satisfied:
 *
 * - No text appears between the offset and the bytes (any bytes appearing after
 *   such text would be ignored)
 *
 * - The offset must be arithmetically correct, i.e. if the offset is 00000020,
 *   then exactly 32 bytes must have been read into this packet before this.
 *   If the offset is wrong, the packet is immediately terminated
 *
 * A packet start is signaled by a zero offset.
 *
 * Lines starting with #TEXT2PCAP are directives. These allow the user
 * to embed instructions into the capture file which allows text2pcap
 * to take some actions (e.g. specifying the encapsulation
 * etc.). Currently no directives are implemented.
 *
 * Lines beginning with # which are not directives are ignored as
 * comments. Currently all non-hexdump text is ignored by text2pcap;
 * in the future, text processing may be added, but lines prefixed
 * with '#' will still be ignored.
 *
 * The output is a libpcap packet containing Ethernet frames by
 * default. This program takes options which allow the user to add
 * dummy Ethernet, IP and UDP, TCP or SCTP headers to the packets in order
 * to allow dumps of L3 or higher protocols to be decoded.
 *
 * Considerable flexibility is built into this code to read hexdumps
 * of slightly different formats. For example, any text prefixing the
 * hexdump line is dropped (including mail forwarding '>'). The offset
 * can be any hex number of four digits or greater.
 *
 * This converter cannot read a single packet greater than
 * WTAP_MAX_PACKET_SIZE_STANDARD.  The snapshot length is automatically
 * set to WTAP_MAX_PACKET_SIZE_STANDARD.
 */

/*******************************************************************************
 * Alternatively this parses a Textfile based on a prel regex containing named
 * capturing groups like so:
 * (?<seqno>\d+)\s*(?<dir><|>)\s*(?<time>\d+:\d\d:\d\d.\d+)\s+(?<data>[0-9a-fA-F]+)\\s+
 *
 * Fields are decoded using a leanient parser, but only one attempt is made.
 * Except for in data invalid values will be replaced by default ones.
 * data currently only accepts plain HEX, OCT or BIN encoded data.
 * common field seperators are ignored. Note however that 0x or 0b prefixing is
 * not supported and no automatic format detection is attempted.
 */

#include "config.h"

/*
 * Just make sure we include the prototype for strptime as well
 * (needed for glibc 2.2) but make sure we do this only if not
 * yet defined.
 */
#ifndef __USE_XOPEN
#  define __USE_XOPEN
#endif
#ifndef _XOPEN_SOURCE
#  ifndef __sun
#    define _XOPEN_SOURCE 600
#  endif
#endif
#include "text_import.h"

/*
 * Defining _XOPEN_SOURCE is needed on some platforms, e.g. platforms
 * using glibc, to expand the set of things system header files define.
 *
 * Unfortunately, on other platforms, such as some versions of Solaris
 * (including Solaris 10), it *reduces* that set as well, causing
 * strptime() not to be declared, presumably because the version of the
 * X/Open spec that _XOPEN_SOURCE implies doesn't include strptime() and
 * blah blah blah namespace pollution blah blah blah.
 *
 * So we define __EXTENSIONS__ so that "strptime()" is declared.
 */
#ifndef __EXTENSIONS__
#  define __EXTENSIONS__
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wsutil/file_util.h>

#include <time.h>
#include <glib.h>

#include <errno.h>
#include <assert.h>

#include <epan/tvbuff.h>
#include <wsutil/crc32.h>
#include <epan/in_cksum.h>

#include <ui/exit_codes.h>
#include <wsutil/report_message.h>
#include <wsutil/exported_pdu_tlvs.h>

#include <wsutil/nstime.h>
#ifndef HAVE_STRPTIME
# include "wsutil/strptime.h"
#endif

#include "text_import_scanner.h"
#include "text_import_scanner_lex.h"
#include "text_import_regex.h"

/*--- Options --------------------------------------------------------------------*/

/* maximum time precision we can handle = 10^(-SUBSEC_PREC) */
#define SUBSEC_PREC 9

#define debug_printf(level,  ...) \
    if (info_p->debug >= (level)) { \
        printf(__VA_ARGS__); \
    }

static text_import_info_t *info_p;

/* Dummy Ethernet header */
static gboolean hdr_ethernet = FALSE;
static guint8 hdr_eth_dest_addr[6] = {0x20, 0x52, 0x45, 0x43, 0x56, 0x00};
static guint8 hdr_eth_src_addr[6]  = {0x20, 0x53, 0x45, 0x4E, 0x44, 0x00};
static guint32 hdr_ethernet_proto = 0;

/* Dummy IP header */
static gboolean hdr_ip = FALSE;
static gboolean hdr_ipv6 = FALSE;
static guint hdr_ip_proto = 0;

/* Destination and source addresses for IP header */
static ws_in6_addr NO_IPv6_ADDRESS    = {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};

/* Dummy UDP header */
static gboolean hdr_udp = FALSE;

/* Dummy TCP header */
static gboolean hdr_tcp = FALSE;

/* TCP sequence numbers when has_direction is true */
static guint32 tcp_in_seq_num = 0;
static guint32 tcp_out_seq_num = 0;

/* Dummy SCTP header */
static gboolean hdr_sctp = FALSE;

/* Dummy DATA chunk header */
static gboolean hdr_data_chunk = FALSE;
static guint8  hdr_data_chunk_type = 0;
static guint8  hdr_data_chunk_bits = 0;
static guint32 hdr_data_chunk_tsn  = 0;
static guint16 hdr_data_chunk_sid  = 0;
static guint16 hdr_data_chunk_ssn  = 0;

/* Dummy ExportPdu header */
static gboolean hdr_export_pdu = FALSE;

/* Hex+ASCII text dump identification, to handle an edge case where
 * the ASCII representation contains patterns that look like bytes. */
static guint8* pkt_lnstart;

static gboolean has_direction = FALSE;
static guint32 direction = PACK_FLAGS_RECEPTION_TYPE_UNSPECIFIED;
static gboolean has_seqno = FALSE;
static guint64 seqno = 0;
/*--- Local data -----------------------------------------------------------------*/

/* This is where we store the packet currently being built */
static guint8 *packet_buf;
static guint32 curr_offset = 0;
static guint32 packet_start = 0;
static import_status_t start_new_packet(gboolean);

/* This buffer contains strings present before the packet offset 0 */
#define PACKET_PREAMBLE_MAX_LEN    2048
static guint8 packet_preamble[PACKET_PREAMBLE_MAX_LEN+1];
static int packet_preamble_len = 0;

/* Time code of packet, derived from packet_preamble */
static time_t   ts_sec = 0;
static guint32  ts_nsec = 0;
static gboolean ts_fmt_iso = FALSE;
static struct tm timecode_default;
static gboolean timecode_warned = FALSE;
/* The time delta to add to packets without a valid time code.
 * This can be no smaller than the time resolution of the dump
 * file, so the default is 1000 nanoseconds, or 1 microsecond.
 * XXX: We should at least get this from the resolution of the file we're
 * writing to, and possibly allow the user to set a different value.
 */
static guint32 ts_tick = 1000;

/* HDR_ETH Offset base to parse */
static guint32 offset_base = 16;

/* ----- State machine -----------------------------------------------------------*/

/* Current state of parser */
typedef enum {
    INIT,             /* Waiting for start of new packet */
    START_OF_LINE,    /* Starting from beginning of line */
    READ_OFFSET,      /* Just read the offset */
    READ_BYTE,        /* Just read a byte */
    READ_TEXT         /* Just read text - ignore until EOL */
} parser_state_t;
static parser_state_t state = INIT;

static const char *state_str[] = {"Init",
                           "Start-of-line",
                           "Offset",
                           "Byte",
                           "Text"
};

static const char *token_str[] = {"",
                           "Byte",
                           "Offset",
                           "Directive",
                           "Text",
                           "End-of-line"
};

/* ----- Skeleton Packet Headers --------------------------------------------------*/

typedef struct {
    guint8  dest_addr[6];
    guint8  src_addr[6];
    guint16 l3pid;
} hdr_ethernet_t;

static hdr_ethernet_t HDR_ETHERNET;

typedef struct {
    guint8  ver_hdrlen;
    guint8  dscp;
    guint16 packet_length;
    guint16 identification;
    guint8  flags;
    guint8  fragment;
    guint8  ttl;
    guint8  protocol;
    guint16 hdr_checksum;
    guint32 src_addr;
    guint32 dest_addr;
} hdr_ip_t;

#if G_BYTE_ORDER == G_BIG_ENDIAN
#define IP_ID  0x1234
#define IP_SRC 0x01010101
#define IP_DST 0x02020202
#else
#define IP_ID  0x3412
#define IP_SRC 0x01010101
#define IP_DST 0x02020202
#endif

static hdr_ip_t HDR_IP =
  {0x45, 0, 0, IP_ID, 0, 0, 0xff, 0, 0, IP_SRC, IP_DST};

static struct {         /* pseudo header for checksum calculation */
    guint32 src_addr;
    guint32 dest_addr;
    guint8  zero;
    guint8  protocol;
    guint16 length;
} pseudoh;


/* headers taken from glibc */

typedef struct {
    union  {
        struct ip6_hdrctl {
            guint32 ip6_un1_flow;   /* 24 bits of flow-ID */
            guint16 ip6_un1_plen;   /* payload length */
            guint8  ip6_un1_nxt;    /* next header */
            guint8  ip6_un1_hlim;   /* hop limit */
        } ip6_un1;
        guint8 ip6_un2_vfc;       /* 4 bits version, 4 bits priority */
    } ip6_ctlun;
    ws_in6_addr ip6_src;      /* source address */
    ws_in6_addr ip6_dst;      /* destination address */
} hdr_ipv6_t;

static hdr_ipv6_t HDR_IPv6;

/* https://tools.ietf.org/html/rfc2460#section-8.1 */
static struct {                 /* pseudo header ipv6 for checksum calculation */
    struct  e_in6_addr src_addr6;
    struct  e_in6_addr dst_addr6;
    guint32 length;
    guint8 zero[3];
    guint8 next_header;
} pseudoh6;


typedef struct {
    guint16 source_port;
    guint16 dest_port;
    guint16 length;
    guint16 checksum;
} hdr_udp_t;

static hdr_udp_t HDR_UDP = {0, 0, 0, 0};

typedef struct {
    guint16 source_port;
    guint16 dest_port;
    guint32 seq_num;
    guint32 ack_num;
    guint8  hdr_length;
    guint8  flags;
    guint16 window;
    guint16 checksum;
    guint16 urg;
} hdr_tcp_t;

static hdr_tcp_t HDR_TCP = {0, 0, 0, 0, 0x50, 0, 0, 0, 0};

typedef struct {
    guint16 src_port;
    guint16 dest_port;
    guint32 tag;
    guint32 checksum;
} hdr_sctp_t;

static hdr_sctp_t HDR_SCTP = {0, 0, 0, 0};

typedef struct {
    guint8  type;
    guint8  bits;
    guint16 length;
    guint32 tsn;
    guint16 sid;
    guint16 ssn;
    guint32 ppid;
} hdr_data_chunk_t;

static hdr_data_chunk_t HDR_DATA_CHUNK = {0, 0, 0, 0, 0, 0, 0};

typedef struct {
    guint16 tag_type;
    guint16 payload_len;
} hdr_export_pdu_t;

static hdr_export_pdu_t HDR_EXPORT_PDU = {0, 0};

#define EXPORT_PDU_END_OF_OPTIONS_SIZE 4

/*----------------------------------------------------------------------
 * Parse a single hex number
 * Will abort the program if it can't parse the number
 * Pass in TRUE if this is an offset, FALSE if not
 */
static import_status_t
parse_num(const char *str, int offset, guint32* num)
{
    char *c;

    if (str == NULL) {
        report_failure("FATAL ERROR: str is NULL");
        return IMPORT_FAILURE;
    }

    errno = 0;
    unsigned long ulnum = strtoul(str, &c, offset ? offset_base : 16);
    if (errno != 0) {
        report_failure("Unable to convert %s to base %u: %s", str,
            offset ? offset_base : 16, g_strerror(errno));
        return IMPORT_FAILURE;
    }
    if (c == str) {
        report_failure("Unable to convert %s to base %u", str,
            offset ? offset_base : 16);
        return IMPORT_FAILURE;
    }
    if (ulnum > G_MAXUINT32) {
        report_failure("%s too large", str);
        return IMPORT_FAILURE;
    }
    *num = (guint32) ulnum;
    return IMPORT_SUCCESS;
}

/*----------------------------------------------------------------------
 * Write this byte into current packet
 */
static import_status_t
write_byte(const char *str)
{
    guint32 num;

    if (parse_num(str, FALSE, &num) != IMPORT_SUCCESS)
        return IMPORT_FAILURE;

    packet_buf[curr_offset] = (guint8) num;
    curr_offset++;
    if (curr_offset >= info_p->max_frame_length) /* packet full */
        if (start_new_packet(TRUE) != IMPORT_SUCCESS)
           return IMPORT_FAILURE;

    return IMPORT_SUCCESS;
}

/*----------------------------------------------------------------------
 * Remove bytes from the current packet
 */
static void
unwrite_bytes (guint32 nbytes)
{
    curr_offset -= nbytes;
}

/*----------------------------------------------------------------------
 * Determine SCTP chunk padding length
 */
static guint32
number_of_padding_bytes (guint32 length)
{
  guint32 remainder;

  remainder = length % 4;

  if (remainder == 0)
    return 0;
  else
    return 4 - remainder;
}

/*----------------------------------------------------------------------
 * Write current packet out
 *
 * @param cont [IN] TRUE if a packet is being written because the max frame
 * length was reached, and the original packet from the input file is
 * continued in a later frame. Used to set fragmentation fields in dummy
 * headers (currently only implemented for SCTP; IPv4 could be added later.)
 */
static import_status_t
write_current_packet(gboolean cont)
{
    int prefix_length = 0;
    int proto_length = 0;
    int ip_length = 0;
    int eth_trailer_length = 0;
    int prefix_index = 0;
    int i, padding_length;

    if (curr_offset > 0) {
        /* Write the packet */

        /* Is direction indication on with an inbound packet? */
        gboolean isOutbound = has_direction && (direction == PACK_FLAGS_DIRECTION_OUTBOUND);

        /* Compute packet length */
        prefix_length = 0;
        if (hdr_export_pdu) {
            prefix_length += (int)sizeof(HDR_EXPORT_PDU) + (int)strlen(info_p->payload) + EXPORT_PDU_END_OF_OPTIONS_SIZE;
            proto_length = prefix_length + curr_offset;
        }
        if (hdr_data_chunk) { prefix_length += (int)sizeof(HDR_DATA_CHUNK); }
        if (hdr_sctp) { prefix_length += (int)sizeof(HDR_SCTP); }
        if (hdr_udp) { prefix_length += (int)sizeof(HDR_UDP); proto_length = prefix_length + curr_offset; }
        if (hdr_tcp) { prefix_length += (int)sizeof(HDR_TCP); proto_length = prefix_length + curr_offset; }
        if (hdr_ip) {
            prefix_length += (int)sizeof(HDR_IP);
            ip_length = prefix_length + curr_offset + ((hdr_data_chunk) ? number_of_padding_bytes(curr_offset) : 0);
        } else if (hdr_ipv6) {
            ip_length = prefix_length + curr_offset + ((hdr_data_chunk) ? number_of_padding_bytes(curr_offset) : 0);
            /* IPv6 payload length field does not include the header itself.
             * It does include extension headers, but we don't put any
             * (if we later do fragments, that would change.)
             */
            prefix_length += (int)sizeof(HDR_IPv6);
        }
        if (hdr_ethernet) { prefix_length += (int)sizeof(HDR_ETHERNET); }

        /* Make room for dummy header */
        memmove(&packet_buf[prefix_length], packet_buf, curr_offset);

        if (hdr_ethernet) {
            /* Pad trailer */
            if (prefix_length + curr_offset < 60) {
                eth_trailer_length = 60 - (prefix_length + curr_offset);
            }
        }

        /* Write Ethernet header */
        if (hdr_ethernet) {
            if (isOutbound)
            {
                memcpy(HDR_ETHERNET.dest_addr, hdr_eth_src_addr, 6);
                memcpy(HDR_ETHERNET.src_addr, hdr_eth_dest_addr, 6);
            } else {
                memcpy(HDR_ETHERNET.dest_addr, hdr_eth_dest_addr, 6);
                memcpy(HDR_ETHERNET.src_addr, hdr_eth_src_addr, 6);
            }
            HDR_ETHERNET.l3pid = g_htons(hdr_ethernet_proto);
            memcpy(&packet_buf[prefix_index], &HDR_ETHERNET, sizeof(HDR_ETHERNET));
            prefix_index += (int)sizeof(HDR_ETHERNET);
        }

        /* Write IP header */
        if (hdr_ip) {
            vec_t cksum_vector[1];

            if (isOutbound) {
                HDR_IP.src_addr = info_p->ip_dest_addr.ipv4 ? info_p->ip_dest_addr.ipv4 : IP_DST;
                HDR_IP.dest_addr = info_p->ip_src_addr.ipv4 ? info_p->ip_src_addr.ipv4 : IP_SRC;
            }
            else {
                HDR_IP.src_addr = info_p->ip_src_addr.ipv4 ? info_p->ip_src_addr.ipv4 : IP_SRC;
                HDR_IP.dest_addr = info_p->ip_dest_addr.ipv4 ? info_p->ip_dest_addr.ipv4 : IP_DST;
            }
            HDR_IP.packet_length = g_htons(ip_length);
            HDR_IP.protocol = (guint8) hdr_ip_proto;
            HDR_IP.hdr_checksum = 0;
            cksum_vector[0].ptr = (guint8 *)&HDR_IP; cksum_vector[0].len = sizeof(HDR_IP);
            HDR_IP.hdr_checksum = in_cksum(cksum_vector, 1);

            memcpy(&packet_buf[prefix_index], &HDR_IP, sizeof(HDR_IP));
            prefix_index += (int)sizeof(HDR_IP);

            /* initialize pseudo header for checksum calculation */
            pseudoh.src_addr    = HDR_IP.src_addr;
            pseudoh.dest_addr   = HDR_IP.dest_addr;
            pseudoh.zero        = 0;
            pseudoh.protocol    = (guint8) hdr_ip_proto;
            pseudoh.length      = g_htons(proto_length);
        } else if (hdr_ipv6) {
            if (memcmp(isOutbound ? &info_p->ip_dest_addr.ipv6 : &info_p->ip_src_addr.ipv6, &NO_IPv6_ADDRESS, sizeof(ws_in6_addr)))
                memcpy(&HDR_IPv6.ip6_src, isOutbound ? &info_p->ip_dest_addr.ipv6 : &info_p->ip_src_addr.ipv6, sizeof(ws_in6_addr));
            if (memcmp(isOutbound ? &info_p->ip_src_addr.ipv6 : &info_p->ip_dest_addr.ipv6, &NO_IPv6_ADDRESS, sizeof(ws_in6_addr)))
                memcpy(&HDR_IPv6.ip6_dst, isOutbound ? &info_p->ip_src_addr.ipv6 : &info_p->ip_dest_addr.ipv6, sizeof(ws_in6_addr));

            HDR_IPv6.ip6_ctlun.ip6_un2_vfc &= 0x0F;
            HDR_IPv6.ip6_ctlun.ip6_un2_vfc |= (6<< 4);
            HDR_IPv6.ip6_ctlun.ip6_un1.ip6_un1_plen = g_htons(ip_length);
            HDR_IPv6.ip6_ctlun.ip6_un1.ip6_un1_nxt  = (guint8) hdr_ip_proto;
            HDR_IPv6.ip6_ctlun.ip6_un1.ip6_un1_hlim = 32;

            memcpy(&packet_buf[prefix_index], &HDR_IPv6, sizeof(HDR_IPv6));
            prefix_index += (int)sizeof(HDR_IPv6);

            /* initialize pseudo ipv6 header for checksum calculation */
            pseudoh6.src_addr6  = HDR_IPv6.ip6_src;
            pseudoh6.dst_addr6  = HDR_IPv6.ip6_dst;
            memset(pseudoh6.zero, 0, sizeof(pseudoh6.zero));
            pseudoh6.next_header   = (guint8) hdr_ip_proto;
            pseudoh6.length      = g_htons(proto_length);
        }

        /* Write UDP header */
        if (hdr_udp) {
            vec_t cksum_vector[3];

            HDR_UDP.source_port = isOutbound ? g_htons(info_p->dst_port): g_htons(info_p->src_port);
            HDR_UDP.dest_port = isOutbound ? g_htons(info_p->src_port) : g_htons(info_p->dst_port);
            HDR_UDP.length = g_htons(proto_length);

            HDR_UDP.checksum = 0;
            if (hdr_ipv6) {
                cksum_vector[0].ptr = (guint8 *)&pseudoh6; cksum_vector[0].len = sizeof(pseudoh6);
            } else {
                cksum_vector[0].ptr = (guint8 *)&pseudoh; cksum_vector[0].len = sizeof(pseudoh);
            }
            cksum_vector[1].ptr = (guint8 *)&HDR_UDP; cksum_vector[1].len = sizeof(HDR_UDP);
            cksum_vector[2].ptr = &packet_buf[prefix_length]; cksum_vector[2].len = curr_offset;
            HDR_UDP.checksum = in_cksum(cksum_vector, 3);

            memcpy(&packet_buf[prefix_index], &HDR_UDP, sizeof(HDR_UDP));
            prefix_index += (int)sizeof(HDR_UDP);
        }

        /* Write TCP header */
        if (hdr_tcp) {
            vec_t cksum_vector[3];

            HDR_TCP.source_port = isOutbound ? g_htons(info_p->dst_port): g_htons(info_p->src_port);
            HDR_TCP.dest_port = isOutbound ? g_htons(info_p->src_port) : g_htons(info_p->dst_port);
            /* set ack number if we have direction */
            if (has_direction) {
                HDR_TCP.flags = 0x10;
                HDR_TCP.ack_num = g_ntohl(isOutbound ? tcp_out_seq_num : tcp_in_seq_num);
                HDR_TCP.ack_num = g_htonl(HDR_TCP.ack_num);
            }
            else {
                HDR_TCP.flags = 0;
                HDR_TCP.ack_num = 0;
            }
            HDR_TCP.seq_num = isOutbound ? tcp_in_seq_num : tcp_out_seq_num;
            HDR_TCP.window = g_htons(0x2000);

            HDR_TCP.checksum = 0;
            if (hdr_ipv6) {
                cksum_vector[0].ptr = (guint8 *)&pseudoh6; cksum_vector[0].len = sizeof(pseudoh6);
            } else {
                cksum_vector[0].ptr = (guint8 *)&pseudoh; cksum_vector[0].len = sizeof(pseudoh);
            }
            cksum_vector[1].ptr = (guint8 *)&HDR_TCP; cksum_vector[1].len = sizeof(HDR_TCP);
            cksum_vector[2].ptr = &packet_buf[prefix_length]; cksum_vector[2].len = curr_offset;
            HDR_TCP.checksum = in_cksum(cksum_vector, 3);

            memcpy(&packet_buf[prefix_index], &HDR_TCP, sizeof(HDR_TCP));
            prefix_index += (int)sizeof(HDR_TCP);
            if (isOutbound) {
                tcp_in_seq_num = g_ntohl(tcp_in_seq_num) + curr_offset;
                tcp_in_seq_num = g_htonl(tcp_in_seq_num);
            }
            else {
                tcp_out_seq_num = g_ntohl(tcp_out_seq_num) + curr_offset;
                tcp_out_seq_num = g_htonl(tcp_out_seq_num);
            }
        }

        /* Compute DATA chunk header and append padding */
        if (hdr_data_chunk) {
            hdr_data_chunk_bits = 0;
            if (packet_start == 0) {
                hdr_data_chunk_bits |= 0x02;
            }
            if (!cont) {
                hdr_data_chunk_bits |= 0x01;
            }
            HDR_DATA_CHUNK.type   = hdr_data_chunk_type;
            HDR_DATA_CHUNK.bits   = hdr_data_chunk_bits;
            HDR_DATA_CHUNK.length = g_htons(curr_offset + sizeof(HDR_DATA_CHUNK));
            HDR_DATA_CHUNK.tsn    = g_htonl(hdr_data_chunk_tsn);
            HDR_DATA_CHUNK.sid    = g_htons(hdr_data_chunk_sid);
            HDR_DATA_CHUNK.ssn    = g_htons(hdr_data_chunk_ssn);
            HDR_DATA_CHUNK.ppid   = g_htonl(info_p->ppi);
            hdr_data_chunk_tsn++;
            if (!cont) {
                hdr_data_chunk_ssn++;
            }
            padding_length = number_of_padding_bytes(curr_offset);
            for (i=0; i<padding_length; i++)
                packet_buf[prefix_length+curr_offset+i] = 0;
            curr_offset += padding_length;
        }

        /* Write SCTP header */
        if (hdr_sctp) {
            HDR_SCTP.src_port  = isOutbound ? g_htons(info_p->dst_port): g_htons(info_p->src_port);
            HDR_SCTP.dest_port = isOutbound ? g_htons(info_p->src_port) : g_htons(info_p->dst_port);
            HDR_SCTP.tag       = g_htonl(info_p->tag);
            HDR_SCTP.checksum  = g_htonl(0);

            HDR_SCTP.checksum  = crc32c_calculate(&HDR_SCTP, sizeof(HDR_SCTP), CRC32C_PRELOAD);
            if (hdr_data_chunk)
                HDR_SCTP.checksum  = crc32c_calculate(&HDR_DATA_CHUNK, sizeof(HDR_DATA_CHUNK), HDR_SCTP.checksum);
            HDR_SCTP.checksum  = g_htonl(~crc32c_calculate(&packet_buf[prefix_length], curr_offset, HDR_SCTP.checksum));

            memcpy(&packet_buf[prefix_index], &HDR_SCTP, sizeof(HDR_SCTP));
            prefix_index += (int)sizeof(HDR_SCTP);
        }

        /* Write DATA chunk header */
        if (hdr_data_chunk) {
            memcpy(&packet_buf[prefix_index], &HDR_DATA_CHUNK, sizeof(HDR_DATA_CHUNK));
            /*prefix_index += (int)sizeof(HDR_DATA_CHUNK);*/
        }

        /* Write ExportPDU header */
        if (hdr_export_pdu) {
            guint payload_len = (guint)strlen(info_p->payload);
            HDR_EXPORT_PDU.tag_type = g_htons(EXP_PDU_TAG_PROTO_NAME);
            HDR_EXPORT_PDU.payload_len = g_htons(payload_len);
            memcpy(&packet_buf[prefix_index], &HDR_EXPORT_PDU, sizeof(HDR_EXPORT_PDU));
            prefix_index += sizeof(HDR_EXPORT_PDU);
            memcpy(&packet_buf[prefix_index], info_p->payload, payload_len);
            prefix_index += payload_len;
            /* Add end-of-options tag */
            memset(&packet_buf[prefix_index], 0x00, 4);
        }

        /* Write Ethernet trailer */
        if (hdr_ethernet && eth_trailer_length > 0) {
            memset(&packet_buf[prefix_length+curr_offset], 0, eth_trailer_length);
        }

        HDR_TCP.seq_num = g_ntohl(HDR_TCP.seq_num) + curr_offset;
        HDR_TCP.seq_num = g_htonl(HDR_TCP.seq_num);

        /* Write the packet */
        wtap_rec rec;
        int err;
        gchar *err_info;

        memset(&rec, 0, sizeof rec);

        rec.rec_type = REC_TYPE_PACKET;
        rec.block = wtap_block_create(WTAP_BLOCK_PACKET);
        rec.ts.secs = ts_sec;
        rec.ts.nsecs = ts_nsec;
        rec.rec_header.packet_header.caplen = rec.rec_header.packet_header.len = prefix_length + curr_offset + eth_trailer_length;
        rec.rec_header.packet_header.pkt_encap = info_p->encapsulation;
        rec.presence_flags = WTAP_HAS_CAP_LEN|WTAP_HAS_INTERFACE_ID|WTAP_HAS_TS;
        if (has_direction) {
            wtap_block_add_uint32_option(rec.block, OPT_PKT_FLAGS, direction);
        }
        if (has_seqno) {
            wtap_block_add_uint64_option(rec.block, OPT_PKT_PACKETID, seqno);
        }

        if (!wtap_dump(info_p->wdh, &rec, packet_buf, &err, &err_info)) {
            report_cfile_write_failure(info_p->import_text_filename,
                    info_p->output_filename, err, err_info,
                    info_p->num_packets_read,
                    wtap_dump_file_type_subtype(info_p->wdh));
            wtap_block_unref(rec.block);
            return IMPORT_FAILURE;
        }
        wtap_block_unref(rec.block);
        info_p->num_packets_written++;
    }

    packet_start += curr_offset;
    curr_offset = 0;
    return IMPORT_SUCCESS;
}


/*----------------------------------------------------------------------
 * Append a token to the packet preamble.
 */
static import_status_t
append_to_preamble(char *str)
{
    size_t toklen;

    if (packet_preamble_len != 0) {
        if (packet_preamble_len == PACKET_PREAMBLE_MAX_LEN)
            return IMPORT_SUCCESS;    /* no room to add more preamble */
            /* XXX: Just keep going? This is probably not a problem, unless
             * someone had >2000 bytes of whitespace before the timestamp... */
        /* Add a blank separator between the previous token and this token. */
        packet_preamble[packet_preamble_len++] = ' ';
    }
    if(str == NULL){
        report_failure("FATAL ERROR: str is NULL");
        return IMPORT_FAILURE;
    }
    toklen = strlen(str);
    if (toklen != 0) {
        if (packet_preamble_len + toklen > PACKET_PREAMBLE_MAX_LEN)
            return IMPORT_SUCCESS;    /* no room to add token to the preamble */
            /* XXX: Just keep going? This is probably not a problem, as above.*/
        (void) g_strlcpy(&packet_preamble[packet_preamble_len], str, PACKET_PREAMBLE_MAX_LEN);
        packet_preamble_len += (int) toklen;
        if (info_p->debug >= 2) {
            char *c;
            char xs[PACKET_PREAMBLE_MAX_LEN];
            (void) g_strlcpy(xs, packet_preamble, PACKET_PREAMBLE_MAX_LEN);
            while ((c = strchr(xs, '\r')) != NULL) *c=' ';
            fprintf (stderr, "[[append_to_preamble: \"%s\"]]", xs);
        }
    }

    return IMPORT_SUCCESS;
}

#define INVALID_VALUE (-1)

#define WHITESPACE_VALUE (-2)

/*
 * Information on how to parse any plainly encoded binary data
 *
 * one Unit is least_common_mmultiple(bits_per_char, 8) bits.
 */
struct plain_decoding_data {
    const gchar* name;
    guint chars_per_unit;
    guint bytes_per_unit : 3; /* Internally a guint64 is used to hold units */
    guint bits_per_char : 6;
    gint8 table[256];
};

#define _INVALID_INIT2 INVALID_VALUE, INVALID_VALUE
#define _INVALID_INIT4 _INVALID_INIT2, _INVALID_INIT2
#define _INVALID_INIT8 _INVALID_INIT4, _INVALID_INIT4
#define _INVALID_INIT16 _INVALID_INIT8, _INVALID_INIT8
#define _INVALID_INIT32 _INVALID_INIT16, _INVALID_INIT16
#define _INVALID_INIT64 _INVALID_INIT32, _INVALID_INIT32
#define _INVALID_INIT128 _INVALID_INIT64, _INVALID_INIT64
#define _INVALID_INIT256 _INVALID_INIT128, _INVALID_INIT128

#define INVALID_INIT _INVALID_INIT256
// this is a gcc/clang extension:
//    [0 ... 255] = INVALID_VALUE

#define WHITESPACE_INIT \
    [' '] = WHITESPACE_VALUE, \
    ['\t'] = WHITESPACE_VALUE, \
    ['\n'] = WHITESPACE_VALUE, \
    ['\v'] = WHITESPACE_VALUE, \
    ['\f'] = WHITESPACE_VALUE, \
    ['\r'] = WHITESPACE_VALUE


/*
 * Some compilers warn about initializing the same subobject
 * more than once with designated initializers.
 *
 * We're doing that - INVALID_INIT iniitalizes everything to
 * INVALID_VALUE, but then we override selected elements -
 * but we know what we're doing, so just suppress that
 * warning.
 */
DIAG_OFF_INIT_TWICE

const struct plain_decoding_data hex_decode_info = {
    .chars_per_unit = 2,
    .bytes_per_unit = 1,
    .bits_per_char = 4,
    .table = {
        INVALID_INIT,
        WHITESPACE_INIT,
        [':'] = WHITESPACE_VALUE,
        ['0'] = 0,1,2,3,4,5,6,7,8,9,
        ['A'] = 10,11,12,13,14,15,
        ['a'] = 10,11,12,13,14,15
    }
};

const struct plain_decoding_data bin_decode_info = {
    .chars_per_unit = 8,
    .bytes_per_unit = 1,
    .bits_per_char = 1,
    .table = {
        INVALID_INIT,
        WHITESPACE_INIT,
        ['0'] = 0, 1
    }
};

const struct plain_decoding_data oct_decode_info = {
    .chars_per_unit = 8,
    .bytes_per_unit = 3,
    .bits_per_char = 3,
    .table = {
        INVALID_INIT,
        WHITESPACE_INIT,
        ['0'] = 0,1,2,3,4,5,6,7
    }
};

const struct plain_decoding_data base64_decode_info = {
    .chars_per_unit = 4,
    .bytes_per_unit = 3,
    .bits_per_char = 6,
    .table = {
        INVALID_INIT,
        WHITESPACE_INIT,
        ['A'] = 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,
        ['a'] = 26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,
        ['0'] = 52,53,54,55,56,57,58,59,60,61,
        ['+'] = 62,
        ['/'] = 63,
        ['='] = WHITESPACE_VALUE /* padding at the end, the decoder doesn't need this, so just ignores it */
    }
};

DIAG_ON_INIT_TWICE

/*******************************************************************************
 * The modularized part of this mess, used by the wrapper around the regex
 * engine in text_import_regex.c to hook into this state-machine backend.
 *
 * Should the rest be modularized aswell? Maybe, but then start with pcap2text.c
 */

 /**
  * This function parses encoded data according to <encoding> into binary data.
  * It will continue until one of the following conditions is met:
  *    - src is depletetd
  *    - dest cannot hold another full unit of data
  *    - an invalid character is read
  * When this happens any complete bytes will be recovered from the remaining
  * possibly incomplete unit and stored to dest (there will be no incomplete unit
  * if dest is full). Any remaining bits will be discarded.
  * src and dest will be advanced to where parsing including this last incomplete
  * unit stopped.
  * If you want to continue parsing (meaning incomplete units were due to call
  * fragmentation and not actually due to EOT) you have to resume the parser at
  * *src_last_unit and dest - result % bytes_per_unit
  */
static int parse_plain_data(guchar** src, const guchar* src_end,
    guint8** dest, const guint8* dest_end, const struct plain_decoding_data* encoding,
    guchar** src_last_unit) {
    int status = 1;
    int units = 0;
    /* unit buffer */
    guint64 c_val = 0;
    guint c_chars = 0;
    /**
     * Src data   |- - -|- - -|- - -|- - -|- - -|- - -|- - -|- - -|
     * Bytes      |- - - - - - - -|- - - - - - - -|- - - - - - - -|
     * Units      |- - - - - - - - - - - - - - - - - - - - - - - -|
     */
    guint64 val;
    int j;
    debug_printf(3, "parsing data: ");
    while (*src < src_end && *dest + encoding->bytes_per_unit <= dest_end) {
        debug_printf(3, "%c", **src);
        val = encoding->table[**src];
        switch (val) {
          case INVALID_VALUE:
            status = -1;
            goto remainder;
          case WHITESPACE_VALUE:
            fprintf(stderr, "Unexpected char %d in data\n", **src);
            break;
          default:
            c_val = c_val << encoding->bits_per_char | val;
            ++c_chars;
            /* another full unit */
            if (c_chars == encoding->chars_per_unit) {
                ++units;
                if (src_last_unit)
                    *src_last_unit = *src;
                c_chars = 0;
                for (j = encoding->bytes_per_unit; j > 0; --j) {
                    **dest = (gchar) (c_val >> (j * 8 - 8));
                    *dest += 1;
                }
            }
        }
        *src += 1;
    }
remainder:
    for (j = c_chars * encoding->bits_per_char; j >= 8; j -= 8) {
        **dest = (gchar) (c_val >> (j - 8));
        *dest += 1;
    }
    debug_printf(3, "\n");
    return status * units;
}

void parse_data(guchar* start_field, guchar* end_field, enum data_encoding encoding) {
    guint8* dest = &packet_buf[curr_offset];
    guint8* dest_end = &packet_buf[info_p->max_frame_length];

    const struct plain_decoding_data* table; /* should be further down */
    switch (encoding) {
      case ENCODING_PLAIN_HEX:
      case ENCODING_PLAIN_OCT:
      case ENCODING_PLAIN_BIN:
      case ENCODING_BASE64:
        /* const struct plain_decoding_data* table; // This can't be here because gcc says no */
        switch (encoding) {
          case ENCODING_PLAIN_HEX:
            table = &hex_decode_info;
            break;
          case ENCODING_PLAIN_OCT:
            table = &oct_decode_info;
            break;
          case ENCODING_PLAIN_BIN:
            table = &bin_decode_info;
            break;
          case ENCODING_BASE64:
            table = &base64_decode_info;
            break;
          default:
            return;
        }
        info_p->num_packets_read++;
        while (1) {
            parse_plain_data(&start_field, end_field, &dest, dest_end, table, NULL);
            curr_offset = (int) (dest - packet_buf);
            if (curr_offset == info_p->max_frame_length) {
                write_current_packet(TRUE);
                dest = &packet_buf[curr_offset];
            } else
                break;
        }
        break;
      default:
          fprintf(stderr, "not implemented/invalid encoding type\n");
          return;
    }
}

#define setFlags(VAL, MASK, FLAGS) \
    ((VAL) & ~(MASK)) | ((FLAGS) & (MASK))

static void _parse_dir(const guchar* start_field, const guchar* end_field _U_, const gchar* in_indicator, const gchar* out_indicator, guint32* dir) {

    for (; *in_indicator && *start_field != *in_indicator; ++in_indicator);
    if (*in_indicator) {
        *dir = setFlags(*dir, PACK_FLAGS_DIRECTION_MASK << PACK_FLAGS_DIRECTION_SHIFT, PACK_FLAGS_DIRECTION_INBOUND);
        return;
    }
    for (; *out_indicator && *start_field != *out_indicator; ++out_indicator);
    if (*out_indicator) {
        *dir = setFlags(*dir, PACK_FLAGS_DIRECTION_MASK << PACK_FLAGS_DIRECTION_SHIFT, PACK_FLAGS_DIRECTION_OUTBOUND);
        return;
    }
    *dir = setFlags(*dir, PACK_FLAGS_DIRECTION_MASK << PACK_FLAGS_DIRECTION_SHIFT, PACK_FLAGS_DIRECTION_UNKNOWN);
}

void parse_dir(const guchar* start_field, const guchar* end_field, const gchar* in_indicator, const gchar* out_indicator) {
    _parse_dir(start_field, end_field, in_indicator, out_indicator, &direction);
}

#define PARSE_BUF 64

/* Attempt to parse a time according to the given format. If the conversion
 * succeeds, set sec and nsec appropriately and return TRUE. If it fails,
 * leave sec and nsec unchanged and return FALSE.
 */
static gboolean
_parse_time(const guchar* start_field, const guchar* end_field, const gchar* _format, time_t* sec, gint* nsec) {
    struct tm timecode;
    time_t sec_buf;
    gint nsec_buf = 0;

    char field[PARSE_BUF];
    char format[PARSE_BUF];

    char* subsecs_fmt;
    int  subseclen = -1;

    char *cursor;
    char *p;
    int  i;

    (void) g_strlcpy(field, start_field, MIN(end_field - start_field + 1, PARSE_BUF));
    if (ts_fmt_iso) {
        nstime_t ts_iso;
        if (!iso8601_to_nstime(&ts_iso, field, ISO8601_DATETIME_AUTO)) {
            return FALSE;
        }
        *sec = ts_iso.secs;
        *nsec = ts_iso.nsecs;
    } else {
        (void) g_strlcpy(format, _format, PARSE_BUF);

        /*
         * Initialize to today localtime, just in case not all fields
         * of the date and time are specified.
         */
        timecode = timecode_default;
        cursor = &field[0];

        /*
         * %f is for fractions of seconds not supported by strptime
         * BTW: what is this function name? is this some russian joke?
         */
        subsecs_fmt = g_strrstr(format, "%f");
        if (subsecs_fmt) {
            *subsecs_fmt = 0;
        }

        cursor = strptime(cursor, format, &timecode);

        if (cursor == NULL) {
            return FALSE;
        }

        if (subsecs_fmt != NULL) {
            /*
             * Parse subsecs and any following format
             */
            nsec_buf = (guint) strtol(cursor, &p, 10);
            if (p == cursor) {
                return FALSE;
            }

            subseclen = (int) (p - cursor);
            cursor = p;
            cursor = strptime(cursor, subsecs_fmt + 2, &timecode);
            if (cursor == NULL) {
                return FALSE;
            }
        }

        if (subseclen > 0) {
            /*
             * Convert that number to a number
             * of nanoseconds; if it's N digits
             * long, it's in units of 10^(-N) seconds,
             * so, to convert it to units of
             * 10^-9 seconds, we multiply by
             * 10^(9-N).
             */
            if (subseclen > SUBSEC_PREC) {
                /*
                 * *More* than 9 digits; 9-N is
                 * negative, so we divide by
                 * 10^(N-9).
                 */
                for (i = subseclen - SUBSEC_PREC; i != 0; i--)
                    nsec_buf /= 10;
            } else if (subseclen < SUBSEC_PREC) {
                for (i = SUBSEC_PREC - subseclen; i != 0; i--)
                    nsec_buf *= 10;
            }
        }

        if ( -1 == (sec_buf = mktime(&timecode)) ) {
            return FALSE;
        }

        *sec = sec_buf;
        *nsec = nsec_buf;
    }

    debug_printf(3, "parsed time %s Format(%s), time(%u), subsecs(%u)\n", field, _format, (guint32)*sec, (guint32)*nsec);

    return TRUE;
}

void parse_time(const guchar* start_field, const guchar* end_field, const gchar* format) {
    if (format == NULL || !_parse_time(start_field, end_field, format, &ts_sec, &ts_nsec)) {
        ts_nsec += ts_tick;
    }
}

void parse_seqno(const guchar* start_field, const guchar* end_field) {
    char* buf = (char*) g_alloca(end_field - start_field + 1);
    (void) g_strlcpy(buf, start_field, end_field - start_field + 1);
    seqno = g_ascii_strtoull(buf, NULL, 10);
}

void flush_packet(void) {
    write_current_packet(FALSE);
}

/*----------------------------------------------------------------------
 * Parse the preamble to get the timecode.
 */

static void
parse_preamble (void)
{
    int  i;
    gboolean got_time = FALSE;

    /*
     * Null-terminate the preamble.
     */
    packet_preamble[packet_preamble_len] = '\0';

    if (has_direction) {
        _parse_dir(&packet_preamble[0], &packet_preamble[1], "iI", "oO", &direction);
        i = (direction == PACK_FLAGS_DIRECTION_UNKNOWN) ? 0 : 1;
        while (packet_preamble[i] == ' ' ||
               packet_preamble[i] == '\r' ||
               packet_preamble[i] == '\t') {
            i++;
        }
        packet_preamble_len -= i;
        /* Also move the trailing '\0'. */
        memmove(packet_preamble, packet_preamble + i, packet_preamble_len + 1);
    }

    /*
     * If no time stamp format was specified, don't attempt to parse
     * the packet preamble to extract a time stamp.
     */

    /* Ensure preamble has more than two chars before attempting to parse.
     * This should cover line breaks etc that get counted.
     */
    if ( info_p->timestamp_format != NULL && strlen(packet_preamble) > 2 ) {
        got_time = _parse_time(packet_preamble, packet_preamble + strlen(packet_preamble), info_p->timestamp_format, &ts_sec, &ts_nsec);
        if (!got_time) {
            /* Let's only have a possible GUI popup once, other messages to log
             */
            if (!timecode_warned) {
                report_warning("Time conversions (%s) failed, advancing time by %d ns from previous packet on failure. First failure was for %s on input packet %d.", info_p->timestamp_format, ts_tick, packet_preamble, info_p->num_packets_read);
                timecode_warned = TRUE;
            }
            ws_warning("Time conversion (%s) failed for %s on input packet %d.", info_p->timestamp_format, packet_preamble, info_p->num_packets_read);
        }
    }
    if (info_p->debug >= 2) {
        char *c;
        while ((c = strchr(packet_preamble, '\r')) != NULL) *c=' ';
        fprintf(stderr, "[[parse_preamble: \"%s\"]]\n", packet_preamble);
        fprintf(stderr, "Format(%s), time(%u), subsecs(%u)\n", info_p->timestamp_format, (guint32)ts_sec, ts_nsec);
    }

    if (!got_time) {
        ts_nsec += ts_tick;
    }

    /* Clear Preamble */
    packet_preamble_len = 0;
}

/*----------------------------------------------------------------------
 * Start a new packet
 *
 * @param cont [IN] TRUE if a new packet is starting because the max frame
 * length was reached on the current packet, and the original packet from the
 * input file is continued in a later frame. Passed to write_current_packet,
 * where it is used to set fragmentation fields in dummy headers (currently
 * only implemented for SCTP; IPv4 could be added later.)
 */
static import_status_t
start_new_packet(gboolean cont)
{
    if (info_p->debug>=1)
        fprintf(stderr, "Start new packet (cont = %s).\n", cont ? "TRUE" : "FALSE");

    /* Write out the current packet, if required */
    if (write_current_packet(cont) != IMPORT_SUCCESS)
        return IMPORT_FAILURE;
    info_p->num_packets_read++;

    /* Ensure we parse the packet preamble as it may contain the time */
    /* THIS IMPLIES A STATE TRANSITION OUTSIDE THE STATE MACHINE */
    parse_preamble();

    return IMPORT_SUCCESS;
}

/*----------------------------------------------------------------------
 * Process a directive
 */
static void
process_directive (char *str)
{
    fprintf(stderr, "\n--- Directive [%s] currently unsupported ---\n", str+10);

}

/*----------------------------------------------------------------------
 * Parse a single token (called from the scanner)
 */
import_status_t
parse_token(token_t token, char *str)
{
    guint32 num;
    /* Variables for the hex+ASCII identification / lookback */
    int     by_eol;
    int	    rollback = 0;
    int     line_size;
    int     i;
    char   *s2;
    char    tmp_str[3];

    /*
     * This is implemented as a simple state machine of five states.
     * State transitions are caused by tokens being received from the
     * scanner. The code should be self_documenting.
     */

    if (info_p->debug>=2) {
        /* Sanitize - remove all '\r' */
        char *c;
        if (str!=NULL) { while ((c = strchr(str, '\r')) != NULL) *c=' '; }

        fprintf(stderr, "(%s, %s \"%s\") -> (",
                state_str[state], token_str[token], str ? str : "");
    }

    switch(state) {

    /* ----- Waiting for new packet -------------------------------------------*/
    case INIT:
        switch(token) {
        case T_TEXT:
            append_to_preamble(str);
            break;
        case T_DIRECTIVE:
            process_directive(str);
            break;
        case T_OFFSET:
            if (offset_base == 0) {
                append_to_preamble(str);
                /* If we're still in the INIT state, maybe there's something
                 * odd like a time format with no separators. That wouldn't
                 * work in a mode with an offset, but give it a try.
                 */
                report_warning("Running in no offset mode but read offset (%s) at start of file, treating as preamble", str);
                break;
            }
            if (parse_num(str, TRUE, &num) != IMPORT_SUCCESS)
                return IMPORT_FAILURE;
            if (num == 0) {
                /* New packet starts here */
                if (start_new_packet(FALSE) != IMPORT_SUCCESS)
                    return IMPORT_FAILURE;
                state = READ_OFFSET;
                pkt_lnstart = packet_buf + num;
            }
            break;
        case T_BYTE:
            if (offset_base == 0) {
                if (start_new_packet(FALSE) != IMPORT_SUCCESS)
                    return IMPORT_FAILURE;
                if (write_byte(str) != IMPORT_SUCCESS)
                    return IMPORT_FAILURE;
                state = READ_BYTE;
                pkt_lnstart = packet_buf;
            }
            break;
        case T_EOF:
            if (write_current_packet(FALSE) != IMPORT_SUCCESS)
                return IMPORT_FAILURE;
            break;
        default:
            break;
        }
        break;

    /* ----- Processing packet, start of new line -----------------------------*/
    case START_OF_LINE:
        switch(token) {
        case T_TEXT:
            append_to_preamble(str);
            break;
        case T_DIRECTIVE:
            process_directive(str);
            break;
        case T_OFFSET:
            if (offset_base == 0) {
                /* After starting the packet there's no point adding it to
                 * the preamble in this mode (we only do one packet.)
                 * Use a generic warning message to suppress the many
                 * expected duplicates. */
                report_warning("Running in no offset mode but read offset, ignoring");
                break;
            }
            if (parse_num(str, TRUE, &num) != IMPORT_SUCCESS)
                return IMPORT_FAILURE;
            if (num == 0) {
                /* New packet starts here */
                if (start_new_packet(FALSE) != IMPORT_SUCCESS)
                    return IMPORT_FAILURE;
                packet_start = 0;
                state = READ_OFFSET;
            } else if ((num - packet_start) != curr_offset) {
                /*
                 * The offset we read isn't the one we expected.
                 * This may only mean that we mistakenly interpreted
                 * some text as byte values (e.g., if the text dump
                 * of packet data included a number with spaces around
                 * it).  If the offset is less than what we expected,
                 * assume that's the problem, and throw away the putative
                 * extra byte values.
                 */
                if (num < curr_offset) {
                    unwrite_bytes(curr_offset - num);
                    state = READ_OFFSET;
                } else {
                    /* Bad offset; switch to INIT state */
                    if (info_p->debug>=1)
                        fprintf(stderr, "Inconsistent offset. Expecting %0X, got %0X. Ignoring rest of packet\n",
                                curr_offset, num);
                    if (write_current_packet(FALSE) != IMPORT_SUCCESS)
                        return IMPORT_FAILURE;
                    state = INIT;
                }
            } else {
                state = READ_OFFSET;
            }
            pkt_lnstart = packet_buf + num;
            break;
        case T_BYTE:
            if (offset_base == 0) {
                if (write_byte(str) != IMPORT_SUCCESS)
                    return IMPORT_FAILURE;
                state = READ_BYTE;
                pkt_lnstart = packet_buf;
            }
            break;
        case T_EOF:
            if (write_current_packet(FALSE) != IMPORT_SUCCESS)
                return IMPORT_FAILURE;
            break;
        default:
            break;
        }
        break;

    /* ----- Processing packet, read offset -----------------------------------*/
    case READ_OFFSET:
        switch(token) {
        case T_BYTE:
            /* Record the byte */
            state = READ_BYTE;
            if (write_byte(str) != IMPORT_SUCCESS)
                return IMPORT_FAILURE;
            break;
        case T_TEXT:
        case T_DIRECTIVE:
        case T_OFFSET:
            state = READ_TEXT;
            break;
        case T_EOL:
            state = START_OF_LINE;
            break;
        case T_EOF:
            if (write_current_packet(FALSE) != IMPORT_SUCCESS)
                return IMPORT_FAILURE;
            break;
        default:
            break;
        }
        break;

    /* ----- Processing packet, read byte -------------------------------------*/
    case READ_BYTE:
        switch(token) {
        case T_BYTE:
            /* Record the byte */
            if (write_byte(str) != IMPORT_SUCCESS)
                return IMPORT_FAILURE;
            break;
        case T_TEXT:
        case T_DIRECTIVE:
        case T_OFFSET:
        case T_EOL:
            by_eol = 0;
            state = READ_TEXT;
            if (token == T_EOL) {
                by_eol = 1;
                state = START_OF_LINE;
            }
            if (info_p->identify_ascii) {
                /* Here a line of pkt bytes reading is finished
                   compare the ascii and hex to avoid such situation:
                   "61 62 20 ab ", when ab is ascii dump then it should
                   not be treat as byte */
                rollback = 0;
                /* s2 is the ASCII string, s1 is the HEX string, e.g, when
                   s2 = "ab ", s1 = "616220"
                   we should find out the largest tail of s1 matches the head
                   of s2, it means the matched part in tail is the ASCII dump
                   of the head byte. These matched should be rollback */
                line_size = curr_offset-(int)(pkt_lnstart-packet_buf);
                s2 = (char*)g_malloc((line_size+1)/4+1);
                /* gather the possible pattern */
                for (i = 0; i < (line_size+1)/4; i++) {
                    tmp_str[0] = pkt_lnstart[i*3];
                    tmp_str[1] = pkt_lnstart[i*3+1];
                    tmp_str[2] = '\0';
                    /* it is a valid convertable string */
                    if (!g_ascii_isxdigit(tmp_str[0]) || !g_ascii_isxdigit(tmp_str[1])) {
                        break;
                    }
                    s2[i] = (char)strtoul(tmp_str, (char **)NULL, 16);
                    rollback++;
                    /* the 3rd entry is not a delimiter, so the possible byte pattern will not shown */
                    if (!(pkt_lnstart[i*3+2] == ' ')) {
                        if (by_eol != 1)
                            rollback--;
                        break;
                    }
                }
                /* If packet line start contains possible byte pattern, the line end
                   should contain the matched pattern if the user open the -a flag.
                   The packet will be possible invalid if the byte pattern cannot find
                   a matched one in the line of packet buffer.*/
                if (rollback > 0) {
                    if (strncmp(pkt_lnstart+line_size-rollback, s2, rollback) == 0) {
                        unwrite_bytes(rollback);
                    }
                    /* Not matched. This line contains invalid packet bytes, so
                       discard the whole line */
                    else {
                        unwrite_bytes(line_size);
                    }
                }
                g_free(s2);
            }
            break;
        case T_EOF:
            if (write_current_packet(FALSE) != IMPORT_SUCCESS)
                return IMPORT_FAILURE;
            break;
        default:
            break;
        }
        break;

    /* ----- Processing packet, read text -------------------------------------*/
    case READ_TEXT:
        switch(token) {
        case T_EOL:
            state = START_OF_LINE;
            break;
        case T_EOF:
            if (write_current_packet(FALSE) != IMPORT_SUCCESS)
                return IMPORT_FAILURE;
            break;
        default:
            break;
        }
        break;

    default:
        report_failure("FATAL ERROR: Bad state (%d)", state);
        return IMPORT_FAILURE;
    }

    if (info_p->debug>=2)
        fprintf(stderr, ", %s)\n", state_str[state]);

    return IMPORT_SUCCESS;
}

/*----------------------------------------------------------------------
 * Import a text file.
 */
int
text_import(text_import_info_t * const info)
{
    import_status_t status;
    int ret;
    struct tm *now_tm;

    packet_buf = (guint8 *)g_malloc(sizeof(HDR_ETHERNET) + sizeof(HDR_IP) +
                                    sizeof(HDR_SCTP) + sizeof(HDR_DATA_CHUNK) +
                                    sizeof(HDR_EXPORT_PDU) + WTAP_MAX_PACKET_SIZE_STANDARD);

    if (!packet_buf)
    {
        /* XXX: This doesn't happen, because g_malloc aborts the program on
         * error, unlike malloc or g_try_malloc.
         */
        report_failure("FATAL ERROR: no memory for packet buffer");
        return INIT_FAILED;
    }

    /* Lets start from the beginning */
    state = INIT;
    curr_offset = 0;
    packet_start = 0;
    packet_preamble_len = 0;
    direction = PACK_FLAGS_DIRECTION_UNKNOWN;
    ts_sec = time(0);            /* initialize to current time */
    now_tm = localtime(&ts_sec);
    if (now_tm == NULL) {
        /*
         * This shouldn't happen - on UN*X, this should Just Work, and
         * on 32 bit Windows built with 32 bit time_t, it won't work if ts_sec
         * is before the Epoch, but it's long after 1970 (and even 32 bit
         * Windows builds with 64 bit time_t by default now), so....
         */
        report_failure("localtime(right now) failed");
        return INIT_FAILED;
    }
    timecode_default = *now_tm;
    timecode_default.tm_isdst = -1;     /* Unknown for now, depends on time given to the strptime() function */
    ts_nsec = 0;

    /* Get input parameters. */
    info_p = info;

    /* Dummy headers */
    hdr_ethernet = FALSE;
    hdr_ip = FALSE;
    hdr_udp = FALSE;
    hdr_tcp = FALSE;
    hdr_sctp = FALSE;
    hdr_data_chunk = FALSE;
    hdr_export_pdu = FALSE;

    if (info->mode == TEXT_IMPORT_HEXDUMP) {
        switch (info->hexdump.offset_type)
        {
            case OFFSET_NONE:
                offset_base = 0;
                break;
            case OFFSET_HEX:
                offset_base = 16;
                break;
            case OFFSET_OCT:
                offset_base = 8;
                break;
            case OFFSET_DEC:
                offset_base = 10;
                break;
        }
        has_direction = info->hexdump.has_direction;

    } else if (info->mode == TEXT_IMPORT_REGEX) {
        has_direction = g_regex_get_string_number(info->regex.format, "dir") >= 0;
        has_seqno = g_regex_get_string_number(info->regex.format, "seqno") >= 0;
    }

    ts_fmt_iso = !(g_strcmp0(info->timestamp_format, "ISO"));
    timecode_warned = FALSE;

    /* XXX: It would be good to know the time precision of the file,
     * to use for the time delta for packets without timestamps. (ts_tick)
     * That could either be added to text_import_info_t or a method
     * added to get it from wtap_dumper (which is opaque.)
     */

    switch (info->dummy_header_type)
    {
        case HEADER_ETH:
            hdr_ethernet = TRUE;
            hdr_ethernet_proto = info->pid;
            break;

        case HEADER_IPV4:
            hdr_ip = TRUE;
            hdr_ip_proto = info->protocol;
            hdr_ethernet = TRUE;
            hdr_ethernet_proto = 0x800;
            break;

        case HEADER_UDP:
            hdr_udp = TRUE;
            hdr_tcp = FALSE;
            hdr_ip = TRUE;
            hdr_ip_proto = 17;
            hdr_ethernet = TRUE;
            hdr_ethernet_proto = 0x800;
            break;

        case HEADER_TCP:
            hdr_tcp = TRUE;
            hdr_udp = FALSE;
            hdr_ip = TRUE;
            hdr_ip_proto = 6;
            hdr_ethernet = TRUE;
            hdr_ethernet_proto = 0x800;
            break;

        case HEADER_SCTP:
            hdr_sctp = TRUE;
            hdr_ip = TRUE;
            hdr_ip_proto = 132;
            hdr_ethernet = TRUE;
            hdr_ethernet_proto = 0x800;
            break;

        case HEADER_SCTP_DATA:
            hdr_sctp = TRUE;
            hdr_data_chunk = TRUE;
            hdr_ip = TRUE;
            hdr_ip_proto = 132;
            hdr_ethernet = TRUE;
            hdr_ethernet_proto = 0x800;
            break;

        case HEADER_EXPORT_PDU:
            hdr_export_pdu = TRUE;
            break;

        default:
            break;
    }

    if (hdr_ip) {
        if (info->ipv6) {
            hdr_ipv6 = TRUE;
            hdr_ip = FALSE;
            hdr_ethernet_proto = 0x86DD;
        }
    }

    info->num_packets_read = 0;
    info->num_packets_written = 0;

    if (info->mode == TEXT_IMPORT_HEXDUMP) {
        status = text_import_scan(info->hexdump.import_text_FILE);
        switch(status) {
        case (IMPORT_SUCCESS):
            ret = 0;
            break;
        case (IMPORT_FAILURE):
            ret = INVALID_FILE;
            break;
        case (IMPORT_INIT_FAILED):
            report_failure("Can't initialize scanner: %s", g_strerror(errno));
            ret = INIT_FAILED;
            break;
        default:
            ret = 0;
        }
    } else if (info->mode == TEXT_IMPORT_REGEX) {
        ret = text_import_regex(info);
        if (ret > 0) {
            info->num_packets_read = ret;
            ret = 0;
        } else if (ret < 0) {
            ret = INVALID_FILE;
        }
    } else {
        ret = INVALID_OPTION;
    }
    g_free(packet_buf);
    return ret;
}
