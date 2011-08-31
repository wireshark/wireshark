/* text_import.c
 * State machine for text import
 * November 2010, Jaap Keuter <jaap.keuter@xs4all.nl>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Based on text2pcap.c by Ashok Narayanan <ashokn@cisco.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

/*******************************************************************************
 *
 * This utility reads in an ASCII hexdump of this common format:
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
 * - The offset must be arithmetically correct, i.e. if the offset is 00000020, then
 *   exactly 32 bytes must have been read into this packet before this. If the offset
 *   is wrong, the packet is immediately terminated
 *
 * A packet start is signalled by a zero offset.
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
 * dummy Ethernet, IP and UDP or TCP headers to the packets in order
 * to allow dumps of L3 or higher protocols to be decoded.
 *
 * Considerable flexibility is built into this code to read hexdumps
 * of slightly different formats. For example, any text prefixing the
 * hexdump line is dropped (including mail forwarding '>'). The offset
 * can be any hex number of four digits or greater.
 *
 * This converter cannot read a single packet greater than 64K. Packet
 * snaplength is automatically set to 64K.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

/*
 * Just make sure we include the prototype for strptime as well
 * (needed for glibc 2.2) but make sure we do this only if not
 * yet defined.
 */
#ifndef __USE_XOPEN
#  define __USE_XOPEN
#endif
#ifndef _XOPEN_SOURCE
#  define _XOPEN_SOURCE
#endif

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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wsutil/file_util.h>

#include <time.h>
#include <glib.h>

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <errno.h>
#include <assert.h>

#include <epan/tvbuff.h>
#include <wsutil/crc32.h>
#include <epan/in_cksum.h>

#ifdef NEED_STRPTIME_H
# include "wsutil/strptime.h"
#endif

#include "text_import.h"
#include "text_import_scanner.h"

/*--- Options --------------------------------------------------------------------*/

/* Debug level */
static int debug = 0;

/* Dummy Ethernet header */
static int hdr_ethernet = FALSE;
static unsigned long hdr_ethernet_proto = 0;

/* Dummy IP header */
static int hdr_ip = FALSE;
static long hdr_ip_proto = 0;

/* Dummy UDP header */
static int hdr_udp = FALSE;
static unsigned long hdr_dest_port = 0;
static unsigned long hdr_src_port = 0;

/* Dummy TCP header */
static int hdr_tcp = FALSE;

/* Dummy SCTP header */
static int hdr_sctp = FALSE;
static unsigned long hdr_sctp_src  = 0;
static unsigned long hdr_sctp_dest = 0;
static unsigned long hdr_sctp_tag  = 0;

/* Dummy DATA chunk header */
static int hdr_data_chunk = FALSE;
static unsigned char  hdr_data_chunk_type = 0;
static unsigned char  hdr_data_chunk_bits = 3;
static unsigned long  hdr_data_chunk_tsn  = 0;
static unsigned short hdr_data_chunk_sid  = 0;
static unsigned short hdr_data_chunk_ssn  = 0;
static unsigned long  hdr_data_chunk_ppid = 0;


/*--- Local data -----------------------------------------------------------------*/

/* This is where we store the packet currently being built */
static unsigned char *packet_buf;
static unsigned long curr_offset = 0;
static unsigned long max_offset = IMPORT_MAX_PACKET;
static unsigned long packet_start = 0;
static void start_new_packet (void);

/* This buffer contains strings present before the packet offset 0 */
#define PACKET_PREAMBLE_MAX_LEN	2048
static unsigned char packet_preamble[PACKET_PREAMBLE_MAX_LEN+1];
static int packet_preamble_len = 0;

/* Time code of packet, derived from packet_preamble */
static time_t ts_sec = 0;
static guint32 ts_usec = 0;
static char *ts_fmt = NULL;
static struct tm timecode_default;

static wtap_dumper* wdh;

/* HDR_ETH Offset base to parse */
static unsigned long offset_base = 16;

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

static hdr_ethernet_t HDR_ETHERNET = {
    {0x20, 0x52, 0x45, 0x43, 0x56, 0x00},
    {0x20, 0x53, 0x45, 0x4E, 0x44, 0x00},
    0};

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

static hdr_ip_t HDR_IP =
  {0x45, 0, 0, 0x3412, 0, 0, 0xff, 0, 0, 0x01010101, 0x02020202};

static struct {         /* pseudo header for checksum calculation */
    guint32 src_addr;
    guint32 dest_addr;
    guint8  zero;
    guint8  protocol;
    guint16 length;
} pseudoh;

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

/* Link-layer type; see net/bpf.h for details */
static unsigned long pcap_link_type = 1;   /* Default is DLT-EN10MB */

/*----------------------------------------------------------------------
 * Parse a single hex number
 * Will abort the program if it can't parse the number
 * Pass in TRUE if this is an offset, FALSE if not
 */
static unsigned long
parse_num (const char *str, int offset)
{
    unsigned long num;
    char *c;

    num = strtoul(str, &c, offset ? offset_base : 16);
    if (c==str) {
        fprintf(stderr, "FATAL ERROR: Bad hex number? [%s]\n", str);
    }
    return num;
}

/*----------------------------------------------------------------------
 * Write this byte into current packet
 */
static void
write_byte (const char *str)
{
    unsigned long num;

    num = parse_num(str, FALSE);
    packet_buf[curr_offset] = (unsigned char) num;
    curr_offset ++;
    if (curr_offset >= max_offset) /* packet full */
        start_new_packet();
}

/*----------------------------------------------------------------------
 * Remove bytes from the current packet
 */
static void
unwrite_bytes (unsigned long nbytes)
{
    curr_offset -= nbytes;
}

/*----------------------------------------------------------------------
 * Determin SCTP chunk padding length
 */
static unsigned long
number_of_padding_bytes (unsigned long length)
{
  unsigned long remainder;

  remainder = length % 4;

  if (remainder == 0)
    return 0;
  else
    return 4 - remainder;
}

/*----------------------------------------------------------------------
 * Write current packet out
 */
void
write_current_packet (void)
{
    int prefix_length = 0;
    int proto_length = 0;
    int ip_length = 0;
    int eth_trailer_length = 0;
    int prefix_index = 0;
    int i, padding_length;

    if (curr_offset > 0) {
        /* Write the packet */

        /* Compute packet length */
        prefix_length = 0;
        if (hdr_data_chunk) { prefix_length += sizeof(HDR_DATA_CHUNK); }
        if (hdr_sctp) { prefix_length += sizeof(HDR_SCTP); }
        if (hdr_udp) { prefix_length += sizeof(HDR_UDP); proto_length = prefix_length + curr_offset; }
        if (hdr_tcp) { prefix_length += sizeof(HDR_TCP); proto_length = prefix_length + curr_offset; }
        if (hdr_ip) {
            prefix_length += sizeof(HDR_IP);
            ip_length = prefix_length + curr_offset + ((hdr_data_chunk) ? number_of_padding_bytes(curr_offset) : 0);
        }
        if (hdr_ethernet) { prefix_length += sizeof(HDR_ETHERNET); }

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
            HDR_ETHERNET.l3pid = g_htons(hdr_ethernet_proto);
            memcpy(&packet_buf[prefix_index], &HDR_ETHERNET, sizeof(HDR_ETHERNET));
            prefix_index += sizeof(HDR_ETHERNET);
        }

        /* Write IP header */
        if (hdr_ip) {
            vec_t cksum_vector[1];

            HDR_IP.packet_length = g_htons(ip_length);
            HDR_IP.protocol = (guint8) hdr_ip_proto;
            HDR_IP.hdr_checksum = 0;
            cksum_vector[0].ptr = (guint8 *)&HDR_IP; cksum_vector[0].len = sizeof(HDR_IP);
            HDR_IP.hdr_checksum = in_cksum(cksum_vector, 1);

            memcpy(&packet_buf[prefix_index], &HDR_IP, sizeof(HDR_IP));
            prefix_index += sizeof(HDR_IP);
        }

        /* initialize pseudo header for checksum calculation */
        pseudoh.src_addr    = HDR_IP.src_addr;
        pseudoh.dest_addr   = HDR_IP.dest_addr;
        pseudoh.zero        = 0;
        pseudoh.protocol    = (guint8) hdr_ip_proto;
        pseudoh.length      = g_htons(proto_length);

        /* Write UDP header */
        if (hdr_udp) {
            vec_t cksum_vector[3];
            
            HDR_UDP.source_port = g_htons(hdr_src_port);
            HDR_UDP.dest_port = g_htons(hdr_dest_port);
            HDR_UDP.length = g_htons(proto_length);

            HDR_UDP.checksum = 0;
            cksum_vector[0].ptr = (guint8 *)&pseudoh; cksum_vector[0].len = sizeof(pseudoh);
            cksum_vector[1].ptr = (guint8 *)&HDR_UDP; cksum_vector[1].len = sizeof(HDR_UDP);
            cksum_vector[2].ptr = &packet_buf[prefix_length]; cksum_vector[2].len = curr_offset;
            HDR_UDP.checksum = in_cksum(cksum_vector, 3);

            memcpy(&packet_buf[prefix_index], &HDR_UDP, sizeof(HDR_UDP));
            prefix_index += sizeof(HDR_UDP);
        }

        /* Write TCP header */
        if (hdr_tcp) {
            vec_t cksum_vector[3];
            
            HDR_TCP.source_port = g_htons(hdr_src_port);
            HDR_TCP.dest_port = g_htons(hdr_dest_port);
            /* HDR_TCP.seq_num already correct */
            HDR_TCP.window = g_htons(0x2000);

            HDR_TCP.checksum = 0;
            cksum_vector[0].ptr = (guint8 *)&pseudoh; cksum_vector[0].len = sizeof(pseudoh);
            cksum_vector[1].ptr = (guint8 *)&HDR_TCP; cksum_vector[1].len = sizeof(HDR_TCP);
            cksum_vector[2].ptr = &packet_buf[prefix_length]; cksum_vector[2].len = curr_offset;
            HDR_TCP.checksum = in_cksum(cksum_vector, 3);

            memcpy(&packet_buf[prefix_index], &HDR_TCP, sizeof(HDR_TCP));
            prefix_index += sizeof(HDR_TCP);
        }

        /* Compute DATA chunk header and append padding */
        if (hdr_data_chunk) {
            HDR_DATA_CHUNK.type   = hdr_data_chunk_type;
            HDR_DATA_CHUNK.bits   = hdr_data_chunk_bits;
            HDR_DATA_CHUNK.length = g_htons(curr_offset + sizeof(HDR_DATA_CHUNK));
            HDR_DATA_CHUNK.tsn    = g_htonl(hdr_data_chunk_tsn);
            HDR_DATA_CHUNK.sid    = g_htons(hdr_data_chunk_sid);
            HDR_DATA_CHUNK.ssn    = g_htons(hdr_data_chunk_ssn);
            HDR_DATA_CHUNK.ppid   = g_htonl(hdr_data_chunk_ppid);

            padding_length = number_of_padding_bytes(curr_offset);
            for (i=0; i<padding_length; i++)
                packet_buf[prefix_length+curr_offset+i] = 0;
            curr_offset += padding_length;
        }

        /* Write SCTP header */
        if (hdr_sctp) {
            HDR_SCTP.src_port  = g_htons(hdr_sctp_src);
            HDR_SCTP.dest_port = g_htons(hdr_sctp_dest);
            HDR_SCTP.tag       = g_htonl(hdr_sctp_tag);
            HDR_SCTP.checksum  = g_htonl(0);

            HDR_SCTP.checksum  = crc32c_calculate(&HDR_SCTP, sizeof(HDR_SCTP), CRC32C_PRELOAD);
            if (hdr_data_chunk)
                HDR_SCTP.checksum  = crc32c_calculate(&HDR_DATA_CHUNK, sizeof(HDR_DATA_CHUNK), HDR_SCTP.checksum);
            HDR_SCTP.checksum  = g_htonl(~crc32c_calculate(&packet_buf[prefix_length], curr_offset, HDR_SCTP.checksum));

            memcpy(&packet_buf[prefix_index], &HDR_SCTP, sizeof(HDR_SCTP));
            prefix_index += sizeof(HDR_SCTP);
        }

        /* Write DATA chunk header */
        if (hdr_data_chunk) {
            memcpy(&packet_buf[prefix_index], &HDR_DATA_CHUNK, sizeof(HDR_DATA_CHUNK));
            prefix_index += sizeof(HDR_DATA_CHUNK);
        }

        /* Write Ethernet trailer */
        if (hdr_ethernet && eth_trailer_length > 0) {
            memset(&packet_buf[prefix_length+curr_offset], 0, eth_trailer_length);
        }

        HDR_TCP.seq_num = g_htonl(g_ntohl(HDR_TCP.seq_num) + curr_offset);

        {
            /* Write the packet */
            struct wtap_pkthdr pkthdr;
            int err;
       
            pkthdr.ts.secs = (guint32)ts_sec;
            pkthdr.ts.nsecs = ts_usec * 1000;
            if (ts_fmt == NULL) { ts_usec++; }  /* fake packet counter */
            pkthdr.caplen = pkthdr.len = prefix_length + curr_offset + eth_trailer_length;;
            pkthdr.pkt_encap = pcap_link_type;

            wtap_dump(wdh, &pkthdr, NULL, packet_buf, &err);
        }
    }

    packet_start += curr_offset;
    curr_offset = 0;
}


/*----------------------------------------------------------------------
 * Append a token to the packet preamble.
 */
static void
append_to_preamble(char *str)
{
    size_t toklen;

    if (packet_preamble_len != 0) {
        if (packet_preamble_len == PACKET_PREAMBLE_MAX_LEN)
            return;	/* no room to add more preamble */
        /* Add a blank separator between the previous token and this token. */
        packet_preamble[packet_preamble_len++] = ' ';
    }
    toklen = strlen(str);
    if (toklen != 0) {
        if (packet_preamble_len + toklen > PACKET_PREAMBLE_MAX_LEN)
            return;	/* no room to add the token to the preamble */
        g_strlcpy(&packet_preamble[packet_preamble_len], str, PACKET_PREAMBLE_MAX_LEN);
        packet_preamble_len += (int) toklen;
        if (debug >= 2) {
            char *c;
            char xs[PACKET_PREAMBLE_MAX_LEN];
            g_strlcpy(xs, packet_preamble, PACKET_PREAMBLE_MAX_LEN);
            while ((c = strchr(xs, '\r')) != NULL) *c=' ';
            fprintf (stderr, "[[append_to_preamble: \"%s\"]]", xs);
        }
    }
}

/*----------------------------------------------------------------------
 * Parse the preamble to get the timecode.
 */

static void
parse_preamble (void)
{
	struct tm timecode;
	char *subsecs;
	char *p;
	int  subseclen;
	int  i;

	/*
	 * If no "-t" flag was specified, don't attempt to parse a packet
	 * preamble to extract a time stamp.
	 */
	if (ts_fmt == NULL)
	    return;

	/*
	 * Initialize to today localtime, just in case not all fields
	 * of the date and time are specified.
	 */

	timecode = timecode_default;
	ts_usec = 0;

	/*
	 * Null-terminate the preamble.
	 */
	packet_preamble[packet_preamble_len] = '\0';

	/* Ensure preamble has more than two chars before atempting to parse.
	 * This should cover line breaks etc that get counted.
	 */
	if ( strlen(packet_preamble) > 2 ) {
		/* Get Time leaving subseconds */
		subsecs = strptime( packet_preamble, ts_fmt, &timecode );
		if (subsecs != NULL) {
			/* Get the long time from the tm structure */
                        /*  (will return -1 if failure)            */
			ts_sec  = mktime( &timecode );
		} else
			ts_sec = -1;	/* we failed to parse it */

		/* This will ensure incorrectly parsed dates get set to zero */
		if ( -1 == ts_sec )
		{
			/* Sanitize - remove all '\r' */
			char *c;
			while ((c = strchr(packet_preamble, '\r')) != NULL) *c=' ';
			fprintf (stderr, "Failure processing time \"%s\" using time format \"%s\"\n   (defaulting to Jan 1,1970 00:00:00 GMT)\n",
				 packet_preamble, ts_fmt);
			if (debug >= 2) {
				fprintf(stderr, "timecode: %02d/%02d/%d %02d:%02d:%02d %d\n",
					timecode.tm_mday, timecode.tm_mon, timecode.tm_year,
					timecode.tm_hour, timecode.tm_min, timecode.tm_sec, timecode.tm_isdst);
			}
			ts_sec  = 0;  /* Jan 1,1970: 00:00 GMT; tshark/wireshark will display date/time as adjusted by timezone */
			ts_usec = 0;
		}
		else
		{
			/* Parse subseconds */
			ts_usec = strtol(subsecs, &p, 10);
			if (subsecs == p) {
				/* Error */
				ts_usec = 0;
			} else {
				/*
				 * Convert that number to a number
				 * of microseconds; if it's N digits
				 * long, it's in units of 10^(-N) seconds,
				 * so, to convert it to units of
				 * 10^-6 seconds, we multiply by
				 * 10^(6-N).
				 */
				subseclen = (int) (p - subsecs);
				if (subseclen > 6) {
					/*
					 * *More* than 6 digits; 6-N is
					 * negative, so we divide by
					 * 10^(N-6).
					 */
					for (i = subseclen - 6; i != 0; i--)
						ts_usec /= 10;
				} else if (subseclen < 6) {
					for (i = 6 - subseclen; i != 0; i--)
						ts_usec *= 10;
				}
			}
		}
	}
	if (debug >= 2) {
		char *c;
		while ((c = strchr(packet_preamble, '\r')) != NULL) *c=' ';
		fprintf(stderr, "[[parse_preamble: \"%s\"]]\n", packet_preamble);
		fprintf(stderr, "Format(%s), time(%u), subsecs(%u)\n", ts_fmt, (guint32)ts_sec, ts_usec);
	}


	/* Clear Preamble */
	packet_preamble_len = 0;
}

/*----------------------------------------------------------------------
 * Start a new packet
 */
static void
start_new_packet (void)
{
    if (debug>=1)
        fprintf(stderr, "Start new packet\n");

    /* Write out the current packet, if required */
    write_current_packet();

    /* Ensure we parse the packet preamble as it may contain the time */
    parse_preamble();
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
void
parse_token (token_t token, char *str)
{
    unsigned long num;

    /*
     * This is implemented as a simple state machine of five states.
     * State transitions are caused by tokens being received from the
     * scanner. The code should be self_documenting.
     */

    if (debug>=2) {
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
            num = parse_num(str, TRUE);
            if (num==0) {
                /* New packet starts here */
                start_new_packet();
                state = READ_OFFSET;
            }
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
            num = parse_num(str, TRUE);
            if (num==0) {
                /* New packet starts here */
                start_new_packet();
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
                    if (debug>=1)
                        fprintf(stderr, "Inconsistent offset. Expecting %0lX, got %0lX. Ignoring rest of packet\n",
                                curr_offset, num);
                    write_current_packet();
                    state = INIT;
                }
            } else
                state = READ_OFFSET;
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
            write_byte(str);
            break;
        case T_TEXT:
        case T_DIRECTIVE:
        case T_OFFSET:
            state = READ_TEXT;
            break;
        case T_EOL:
            state = START_OF_LINE;
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
            write_byte(str);
            break;
        case T_TEXT:
        case T_DIRECTIVE:
        case T_OFFSET:
            state = READ_TEXT;
            break;
        case T_EOL:
            state = START_OF_LINE;
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
        default:
            break;
        }
        break;

    default:
        fprintf(stderr, "FATAL ERROR: Bad state (%d)", state);
        exit(-1);
    }

    if (debug>=2)
        fprintf(stderr, ", %s)\n", state_str[state]);

}

/*----------------------------------------------------------------------
 * take in the import config information
 */
void
text_import_setup(text_import_info_t *info)
{
    packet_buf = (unsigned char *)g_malloc(sizeof(HDR_ETHERNET) + sizeof(HDR_IP) +
                                           sizeof(HDR_SCTP) + sizeof(HDR_DATA_CHUNK) +
                                           IMPORT_MAX_PACKET);

    if (!packet_buf)
    {
        fprintf(stderr, "FATAL ERROR: no memory for packet buffer");
        exit(-1);
    }
    
    /* Lets start from the beginning */
    state = INIT;
    curr_offset = 0;
    packet_start = 0;
    packet_preamble_len = 0;
    ts_sec = time(0);            /* initialize to current time */
    timecode_default = *localtime(&ts_sec);
    timecode_default.tm_isdst = -1;     /* Unknown for now, depends on time given to the strptime() function */
    ts_usec = 0;

    /* Dummy headers */
    hdr_ethernet = FALSE;
    hdr_ip = FALSE;
    hdr_udp = FALSE;
    hdr_tcp = FALSE;
    hdr_sctp = FALSE;
    hdr_data_chunk = FALSE;

    offset_base = (info->offset_type == OFFSET_HEX) ? 16 :
                  (info->offset_type == OFFSET_OCT) ? 8 :
                  (info->offset_type == OFFSET_DEC) ? 10 :
                  16;

    if (info->date_timestamp)
    {
        ts_fmt = info->date_timestamp_format;
    }

    pcap_link_type = info->encapsulation;

    wdh = info->wdh;

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
            hdr_src_port = info->src_port;
            hdr_dest_port = info->dst_port;
            hdr_ip = TRUE;
            hdr_ip_proto = 17;
            hdr_ethernet = TRUE;
            hdr_ethernet_proto = 0x800;
            break;

        case HEADER_TCP:
            hdr_tcp = TRUE;
            hdr_udp = FALSE;
            hdr_src_port = info->src_port;
            hdr_dest_port = info->dst_port;
            hdr_ip = TRUE;
            hdr_ip_proto = 6;
            hdr_ethernet = TRUE;
            hdr_ethernet_proto = 0x800;
            break;

        case HEADER_SCTP:
            hdr_sctp = TRUE;
            hdr_sctp_src = info->src_port;
            hdr_sctp_dest = info->dst_port;
            hdr_sctp_tag = info->tag;
            hdr_ip = TRUE;
            hdr_ip_proto = 132;
            hdr_ethernet = TRUE;
            hdr_ethernet_proto = 0x800;
            break;

        case HEADER_SCTP_DATA:
            hdr_sctp = TRUE;
            hdr_data_chunk = TRUE;
            hdr_sctp_src = info->src_port;
            hdr_sctp_dest = info->dst_port;
            hdr_data_chunk_ppid = info->ppi;
            hdr_ip = TRUE;
            hdr_ip_proto = 132;
            hdr_ethernet = TRUE;
            hdr_ethernet_proto = 0x800;
            break;

        default:
            break;
    }

    max_offset = info->max_frame_length;
}

/*----------------------------------------------------------------------
 * Clean up after text import
 */
void
text_import_cleanup(void)
{
    g_free(packet_buf);
}
