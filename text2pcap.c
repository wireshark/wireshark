/**-*-C-*-**********************************************************************
 *
 * text2pcap.c
 *
 * Utility to convert an ASCII hexdump into a libpcap-format capture file
 *
 * (c) Copyright 2001 Ashok Narayanan <ashokn@cisco.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *******************************************************************************/

/*******************************************************************************
 *
 * This utility reads in an ASCII hexdump of this common format:
 *
 * 00000000  00 E0 1E A7 05 6F 00 10 5A A0 B9 12 08 00 46 00 .....o..Z.....F.
 * 00000010  03 68 00 00 00 00 0A 2E EE 33 0F 19 08 7F 0F 19 .h.......3.....
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Just make sure we include the prototype for strptime as well
 * (needed for glibc 2.2)
 */
#define __USE_XOPEN

#include <time.h>
#include <glib.h>

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <errno.h>
#include <assert.h>

#ifdef NEED_GETOPT_H
# include "getopt.h"
#endif

#ifdef NEED_STRPTIME_H
# include "strptime.h"
#endif

#include "text2pcap.h"

/*--- Options --------------------------------------------------------------------*/

/* Debug level */
static int debug = 0;
/* Be quiet */
static int quiet = FALSE;

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


/*--- Local date -----------------------------------------------------------------*/

/* This is where we store the packet currently being built */
#define MAX_PACKET 64000
static unsigned char packet_buf[MAX_PACKET];
static unsigned long curr_offset = 0;
static unsigned long max_offset = MAX_PACKET;
static unsigned long packet_start = 0;
static void start_new_packet (void);

/* This buffer contains strings present before the packet offset 0 */
#define PACKET_PREAMBLE_MAX_LEN	2048
static unsigned char packet_preamble[PACKET_PREAMBLE_MAX_LEN+1];
static int packet_preamble_len = 0;

/* Number of packets read and written */
static unsigned long num_packets_read = 0;
static unsigned long num_packets_written = 0;

/* Time code of packet, derived from packet_preamble */
static gint32 ts_sec  = 0;
static guint32 ts_usec = 0;
static char *ts_fmt = NULL;

/* Input file */
static const char *input_filename;
static FILE *input_file = NULL;
/* Output file */
static const char *output_filename;
static FILE *output_file = NULL;

/* Offset base to parse */
static unsigned long offset_base = 16;

extern FILE *yyin;

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
    {0x02, 0x02, 0x02, 0x02, 0x02, 0x02},
    {0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
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

static hdr_ip_t HDR_IP = {0x45, 0, 0, 0x3412, 0, 0, 0xff, 0, 0, 0x01010101, 0x02020202};

static struct {			/* pseudo header for checksum calculation */
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

static char tempbuf[64];

/*----------------------------------------------------------------------
 * Stuff for writing a PCap file
 */
#define	PCAP_MAGIC			0xa1b2c3d4

/* "libpcap" file header (minus magic number). */
struct pcap_hdr {
    guint32	magic;		/* magic */
    guint16	version_major;	/* major version number */
    guint16	version_minor;	/* minor version number */
    guint32	thiszone;	/* GMT to local correction */
    guint32	sigfigs;	/* accuracy of timestamps */
    guint32	snaplen;	/* max length of captured packets, in octets */
    guint32	network;	/* data link type */
};

/* "libpcap" record header. */
struct pcaprec_hdr {
    gint32	ts_sec;		/* timestamp seconds */
    guint32	ts_usec;	/* timestamp microseconds */
    guint32	incl_len;	/* number of octets of packet saved in file */
    guint32	orig_len;	/* actual length of packet */
};

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
        exit(-1);
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
 * Compute one's complement checksum (from RFC1071)
 */
static guint16
in_checksum (void *buf, unsigned long count)
{
    unsigned long sum = 0;
    guint16 *addr = buf;

    while( count > 1 )  {
        /*  This is the inner loop */
        sum += g_ntohs(* (guint16 *) addr);
	addr++;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if( count > 0 )
        sum += g_ntohs(* (guint8 *) addr);

    /*  Fold 32-bit sum to 16 bits */
    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    return g_htons(~sum);
}

/* The CRC32C code is taken from draft-ietf-tsvwg-sctpcsum-01.txt.
 * That code is copyrighted by D. Otis and has been modified.
 */

#define CRC32C(c,d) (c=(c>>8)^crc_c[(c^(d))&0xFF])
static guint32 crc_c[256] =
{
0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L,
0xC79A971FL, 0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL,
0x8AD958CFL, 0x78B2DBCCL, 0x6BE22838L, 0x9989AB3BL,
0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L, 0x5E133C24L,
0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,
0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L,
0x9A879FA0L, 0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L,
0x5D1D08BFL, 0xAF768BBCL, 0xBC267848L, 0x4E4DFB4BL,
0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L, 0x33ED7D2AL,
0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,
0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L,
0x6DFE410EL, 0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL,
0x30E349B1L, 0xC288CAB2L, 0xD1D83946L, 0x23B3BA45L,
0xF779DEAEL, 0x05125DADL, 0x1642AE59L, 0xE4292D5AL,
0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,
0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L,
0x417B1DBCL, 0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L,
0x86E18AA3L, 0x748A09A0L, 0x67DAFA54L, 0x95B17957L,
0xCBA24573L, 0x39C9C670L, 0x2A993584L, 0xD8F2B687L,
0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,
0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L,
0x96BF4DCCL, 0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L,
0xDBFC821CL, 0x2997011FL, 0x3AC7F2EBL, 0xC8AC71E8L,
0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L, 0x0F36E6F7L,
0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,
0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L,
0xEB1FCBADL, 0x197448AEL, 0x0A24BB5AL, 0xF84F3859L,
0x2C855CB2L, 0xDEEEDFB1L, 0xCDBE2C45L, 0x3FD5AF46L,
0x7198540DL, 0x83F3D70EL, 0x90A324FAL, 0x62C8A7F9L,
0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,
0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L,
0x3CDB9BDDL, 0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L,
0x82F63B78L, 0x709DB87BL, 0x63CD4B8FL, 0x91A6C88CL,
0x456CAC67L, 0xB7072F64L, 0xA457DC90L, 0x563C5F93L,
0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,
0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL,
0x92A8FC17L, 0x60C37F14L, 0x73938CE0L, 0x81F80FE3L,
0x55326B08L, 0xA759E80BL, 0xB4091BFFL, 0x466298FCL,
0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL, 0x0B21572CL,
0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,
0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L,
0x65D122B9L, 0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL,
0x2892ED69L, 0xDAF96E6AL, 0xC9A99D9EL, 0x3BC21E9DL,
0xEF087A76L, 0x1D63F975L, 0x0E330A81L, 0xFC588982L,
0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,
0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L,
0x38CC2A06L, 0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L,
0xFF56BD19L, 0x0D3D3E1AL, 0x1E6DCDEEL, 0xEC064EEDL,
0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L, 0xD0DDD530L,
0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,
0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL,
0x8ECEE914L, 0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L,
0xD3D3E1ABL, 0x21B862A8L, 0x32E8915CL, 0xC083125FL,
0x144976B4L, 0xE622F5B7L, 0xF5720643L, 0x07198540L,
0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,
0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL,
0xE330A81AL, 0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL,
0x24AA3F05L, 0xD6C1BC06L, 0xC5914FF2L, 0x37FACCF1L,
0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L, 0x7AB90321L,
0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,
0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L,
0x34F4F86AL, 0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL,
0x79B737BAL, 0x8BDCB4B9L, 0x988C474DL, 0x6AE7C44EL,
0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L, 0xAD7D5351L,
};

static guint32
crc32c(const guint8* buf, unsigned int len, guint32 crc32_init)
{
  unsigned int i;
  guint32 crc32;

  crc32 = crc32_init;
  for (i = 0; i < len; i++)
    CRC32C(crc32, buf[i]);

  return ( crc32 );
}

static guint32
finalize_crc32c(guint32 crc32)
{
  guint32 result;
  guint8 byte0,byte1,byte2,byte3;

  result = ~crc32;
  byte0 = result & 0xff;
  byte1 = (result>>8) & 0xff;
  byte2 = (result>>16) & 0xff;
  byte3 = (result>>24) & 0xff;
  result = ((byte0 << 24) | (byte1 << 16) | (byte2 << 8) | byte3);
  return ( result );
}

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
static void
write_current_packet (void)
{
    int length = 0;
    int proto_length = 0;
    int ip_length = 0;
    int eth_trailer_length = 0;
    int i, padding_length;
    guint32 u;
    struct pcaprec_hdr ph;

    if (curr_offset > 0) {
        /* Write the packet */

        /* Compute packet length */
        length = curr_offset;
        if (hdr_data_chunk) { length += sizeof(HDR_DATA_CHUNK) + number_of_padding_bytes(curr_offset); }
        if (hdr_sctp) { length += sizeof(HDR_SCTP); }
        if (hdr_udp) { length += sizeof(HDR_UDP); proto_length = length; }
        if (hdr_tcp) { length += sizeof(HDR_TCP); proto_length = length; }
        if (hdr_ip) { length += sizeof(HDR_IP); ip_length = length; }
        if (hdr_ethernet) {
            length += sizeof(HDR_ETHERNET);
            /* Pad trailer */
            if (length < 60) {
                eth_trailer_length = 60 - length;
                length = 60;
            }
        }

        /* Write PCap header */
        ph.ts_sec = ts_sec;
        ph.ts_usec = ts_usec;
        if (ts_fmt == NULL) { ts_usec++; }	/* fake packet counter */
        ph.incl_len = length;
        ph.orig_len = length;
        fwrite(&ph, sizeof(ph), 1, output_file);

        /* Write Ethernet header */
        if (hdr_ethernet) {
            HDR_ETHERNET.l3pid = g_htons(hdr_ethernet_proto);
            fwrite(&HDR_ETHERNET, sizeof(HDR_ETHERNET), 1, output_file);
        }

        /* Write IP header */
        if (hdr_ip) {
            HDR_IP.packet_length = g_htons(ip_length);
            HDR_IP.protocol = (guint8) hdr_ip_proto;
            HDR_IP.hdr_checksum = 0;
            HDR_IP.hdr_checksum = in_checksum(&HDR_IP, sizeof(HDR_IP));
            fwrite(&HDR_IP, sizeof(HDR_IP), 1, output_file);
        }

	/* initialize pseudo header for checksum calculation */
	pseudoh.src_addr    = HDR_IP.src_addr;
	pseudoh.dest_addr   = HDR_IP.dest_addr;
	pseudoh.zero        = 0;
	pseudoh.protocol    = (guint8) hdr_ip_proto;
	pseudoh.length      = g_htons(proto_length);

        /* Write UDP header */
        if (hdr_udp) {
            HDR_UDP.source_port = g_htons(hdr_src_port);
            HDR_UDP.dest_port = g_htons(hdr_dest_port);
            HDR_UDP.length = g_htons(proto_length);

	    HDR_UDP.checksum = 0;
	    u = g_ntohs(in_checksum(&pseudoh, sizeof(pseudoh))) + 
		    g_ntohs(in_checksum(&HDR_UDP, sizeof(HDR_UDP))) +
		    g_ntohs(in_checksum(packet_buf, curr_offset));
	    HDR_UDP.checksum = g_htons((u & 0xffff) + (u>>16));
	    if (HDR_UDP.checksum == 0) /* differenciate between 'none' and 0 */
	    	    HDR_UDP.checksum = g_htons(1);

            fwrite(&HDR_UDP, sizeof(HDR_UDP), 1, output_file);
        }

        /* Write TCP header */
        if (hdr_tcp) {
            HDR_TCP.source_port = g_htons(hdr_src_port);
            HDR_TCP.dest_port = g_htons(hdr_dest_port);
    	    /* HDR_TCP.seq_num already correct */
	    HDR_TCP.window = g_htons(0x2000);

	    HDR_TCP.checksum = 0;
	    u = g_ntohs(in_checksum(&pseudoh, sizeof(pseudoh))) + 
		    g_ntohs(in_checksum(&HDR_TCP, sizeof(HDR_TCP))) +
		    g_ntohs(in_checksum(packet_buf, curr_offset));
	    HDR_TCP.checksum = g_htons((u & 0xffff) + (u>>16));
	    if (HDR_TCP.checksum == 0) /* differenciate between 'none' and 0 */
	    	    HDR_TCP.checksum = g_htons(1);

            fwrite(&HDR_TCP, sizeof(HDR_TCP), 1, output_file);
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
              write_byte("0");
        }

        /* Write SCTP header */
        if (hdr_sctp) {
            HDR_SCTP.src_port  = g_htons(hdr_sctp_src);
            HDR_SCTP.dest_port = g_htons(hdr_sctp_dest);
            HDR_SCTP.tag       = g_htonl(hdr_sctp_tag);
            HDR_SCTP.checksum  = g_htonl(0);
            HDR_SCTP.checksum  = crc32c((guint8 *)&HDR_SCTP, sizeof(HDR_SCTP), ~0L);
            if (hdr_data_chunk)
              HDR_SCTP.checksum  = crc32c((guint8 *)&HDR_DATA_CHUNK, sizeof(HDR_DATA_CHUNK), HDR_SCTP.checksum);
            HDR_SCTP.checksum  = g_htonl(finalize_crc32c(crc32c(packet_buf, curr_offset, HDR_SCTP.checksum)));

            fwrite(&HDR_SCTP, sizeof(HDR_SCTP), 1, output_file);
        }

        /* Write DATA chunk header */
        if (hdr_data_chunk) {
            fwrite(&HDR_DATA_CHUNK, sizeof(HDR_DATA_CHUNK), 1, output_file);
        }
        /* Write packet */
        fwrite(packet_buf, curr_offset, 1, output_file);

        /* Write Ethernet trailer */
        if (hdr_ethernet && eth_trailer_length > 0) {
            memset(tempbuf, 0, eth_trailer_length);
            fwrite(tempbuf, eth_trailer_length, 1, output_file);
        }

        if (!quiet)
            fprintf(stderr, "Wrote packet of %lu bytes at %u\n", curr_offset, g_ntohl(HDR_TCP.seq_num));
        num_packets_written ++;
    }

    HDR_TCP.seq_num = g_htonl(g_ntohl(HDR_TCP.seq_num) + curr_offset);

    packet_start += curr_offset;
    curr_offset = 0;
}

/*----------------------------------------------------------------------
 * Write the PCap file header
 */
static void
write_file_header (void)
{
    struct pcap_hdr fh;

    fh.magic = PCAP_MAGIC;
    fh.version_major = 2;
    fh.version_minor = 4;
    fh.thiszone = 0;
    fh.sigfigs = 0;
    fh.snaplen = 102400;
    fh.network = pcap_link_type;

    fwrite(&fh, sizeof(fh), 1, output_file);
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
        strcpy(&packet_preamble[packet_preamble_len], str);
        packet_preamble_len += toklen;
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

	ts_sec  = 0;
	ts_usec = 0;

	/*
	 * Null-terminate the preamble.
	 */
	packet_preamble[packet_preamble_len] = '\0';

	/* Ensure preamble has more than two chars before atempting to parse.
	 * This should cover line breaks etc that get counted.
	 */
	if ( strlen(packet_preamble) > 2 ) {
		/*
		 * Initialize to the Epoch, just in case not all fields
		 * of the date and time are specified.
		 */
		timecode.tm_sec = 0;
		timecode.tm_min = 0;
		timecode.tm_hour = 0;
		timecode.tm_mday = 1;
		timecode.tm_mon = 0;
		timecode.tm_year = 70;
		timecode.tm_wday = 0;
		timecode.tm_yday = 0;
		timecode.tm_isdst = -1;

		/* Get Time leaving subseconds */
		subsecs = strptime( packet_preamble, ts_fmt, &timecode );
		if (subsecs != NULL) {
			/* Get the long time from the tm structure */
			ts_sec  = (gint32)mktime( &timecode );
		} else
			ts_sec = -1;	/* we failed to parse it */

		/* This will ensure incorrectly parsed dates get set to zero */
		if ( -1 == ts_sec )
		{
			ts_sec  = 0;
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
				subseclen = p - subsecs;
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


	/*printf("Format(%s), time(%u), subsecs(%u)\n\n", ts_fmt, ts_sec, ts_usec);*/

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
    num_packets_read ++;

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
 * Print helpstring and exit
 */
static void
help (char *progname)
{
    fprintf(stderr,
            "Text2pcap %s"
#ifdef SVNVERSION
            " (" SVNVERSION ")"
#endif
            "\n"
            "Generate a capture file from an ASCII hexdump of packets.\n"
            "See http://www.ethereal.com for more information.\n"
            "\n"
            "Usage: text2pcap [options] <input-filename> <output-filename>\n"
            "\n"
            "where  <input-filename> specifies input  filename (use - for standard input)\n"
            "      <output-filename> specifies output filename (use - for standard output)\n"
            "\n"
            "Input:\n"
            "  -o hex|oct             parse offsets as (h)ex or (o)ctal, default is hex\n"
            "  -t <timefmt>           treats the text before the packet as a date/time code;\n"
            "                         the specified argument is a format string of the sort \n"
            "                         supported by strptime.\n"
            "                         Example: The time \"10:15:14.5476\" has the format code\n"
            "                         \"%%H:%%M:%%S.\"\n"
            "                         NOTE: The subsecond component delimiter must be given\n"
            "                          (.) but no pattern is required; the remaining number\n"
            "                          is assumed to be fractions of a second.\n"
            "\n"
            "Output:\n"
            "  -l <typenum>           link-layer type number. Default is 1 (Ethernet). \n"
            "                         See the file net/bpf.h for list of numbers.\n"
            "  -m <max-packet>        max packet length in output, default is %d\n"
            "\n"
            "Prepend dummy header:\n"
            "  -e <l3pid>             prepend dummy Ethernet II header with specified L3PID\n"
            "                         (in HEX)\n"
            "                         Example: -e 0x800\n"
            "  -i <proto>             prepend dummy IP header with specified IP protocol\n"
            "                         (in DECIMAL). \n"
            "                         Automatically prepends Ethernet header as well.\n"
            "                         Example: -i 46\n"
            "  -u <srcp>,<destp>      prepend dummy UDP header with specified\n"
            "                         dest and source ports (in DECIMAL).\n"
            "                         Automatically prepends Ethernet & IP headers as well\n"
            "                         Example: -u 30,40\n"
            "  -T <srcp>,<destp>      prepend dummy TCP header with specified \n"
            "                         dest and source ports (in DECIMAL).\n"
            "                         Automatically prepends Ethernet & IP headers as well\n"
            "                         Example: -T 50,60\n"
            "  -s <srcp>,<dstp>,<tag> prepend dummy SCTP header with specified \n"
            "                         dest/source ports and verification tag (in DECIMAL).\n"
            "                         Automatically prepends Ethernet & IP headers as well\n"
            "                         Example: -s 30,40,34\n"
            "  -S <srcp>,<dstp>,<ppi> prepend dummy SCTP header with specified \n"
            "                         dest/source ports and verification tag 0. \n"
            "                         It also prepends a dummy SCTP DATA \n"
            "                         chunk header with payload protocol identifier ppi.\n"
            "                         Example: -S 30,40,34\n"
            "\n"
            "Miscellaneous:\n"
            "  -h                     display this help and exit\n"
            "  -d                     detailed debug of parser states \n"
            "  -q                     generate no output at all (automatically turns off -d)\n"
            "",
            VERSION, MAX_PACKET);

    exit(-1);
}

/*----------------------------------------------------------------------
 * Parse CLI options
 */
static void
parse_options (int argc, char *argv[])
{
    int c;
    char *p;

    /* Scan CLI parameters */
    while ((c = getopt(argc, argv, "dhqe:i:l:m:o:u:s:S:t:T:")) != -1) {
        switch(c) {
        case '?': help(argv[0]); break;
        case 'h': help(argv[0]); break;
        case 'd': if (!quiet) debug++; break;
        case 'q': quiet = TRUE; debug = FALSE; break;
        case 'l': pcap_link_type = strtol(optarg, NULL, 0); break;
        case 'm': max_offset = strtol(optarg, NULL, 0); break;
        case 'o':
            if (optarg[0]!='h' && optarg[0] != 'o') {
                fprintf(stderr, "Bad argument for '-e': %s\n", optarg);
                help(argv[0]);
            }
            offset_base = (optarg[0]=='o') ? 8 : 16;
            break;
        case 'e':
            hdr_ethernet = TRUE;
            if (sscanf(optarg, "%lx", &hdr_ethernet_proto) < 1) {
                fprintf(stderr, "Bad argument for '-e': %s\n", optarg);
                help(argv[0]);
            }
            break;

        case 'i':
            hdr_ip = TRUE;
            hdr_ip_proto = strtol(optarg, &p, 10);
            if (p == optarg || *p != '\0' || hdr_ip_proto < 0 ||
                  hdr_ip_proto > 255) {
                fprintf(stderr, "Bad argument for '-i': %s\n", optarg);
                help(argv[0]);
            }
            hdr_ethernet = TRUE;
            hdr_ethernet_proto = 0x800;
            break;

        case 's':
            hdr_sctp       = TRUE;
            hdr_sctp_src   = strtol(optarg, &p, 10);
            if (p == optarg || (*p != ',' && *p != '\0')) {
                fprintf(stderr, "Bad src port for '-%c'\n", c);
                help(argv[0]);
            }
            if (*p == '\0') {
                fprintf(stderr, "No dest port specified for '-%c'\n", c);
                help(argv[0]);
            }
            p++;
            optarg = p;
            hdr_sctp_dest = strtol(optarg, &p, 10);
            if (p == optarg || (*p != ',' && *p != '\0')) {
                fprintf(stderr, "Bad dest port for '-s'\n");
                help(argv[0]);
            }
            if (*p == '\0') {
                fprintf(stderr, "No tag specified for '-%c'\n", c);
                help(argv[0]);
            }
            p++;
            optarg = p;
            hdr_sctp_tag = strtol(optarg, &p, 10);
            if (p == optarg || *p != '\0') {
                fprintf(stderr, "Bad tag for '-%c'\n", c);
                help(argv[0]);
            }

            hdr_ip = TRUE;
            hdr_ip_proto = 132;
            hdr_ethernet = TRUE;
            hdr_ethernet_proto = 0x800;
            break;
        case 'S':
            hdr_sctp       = TRUE;
            hdr_data_chunk = TRUE;
            hdr_sctp_src   = strtol(optarg, &p, 10);
            if (p == optarg || (*p != ',' && *p != '\0')) {
                fprintf(stderr, "Bad src port for '-%c'\n", c);
                help(argv[0]);
            }
            if (*p == '\0') {
                fprintf(stderr, "No dest port specified for '-%c'\n", c);
                help(argv[0]);
            }
            p++;
            optarg = p;
            hdr_sctp_dest = strtol(optarg, &p, 10);
            if (p == optarg || (*p != ',' && *p != '\0')) {
                fprintf(stderr, "Bad dest port for '-s'\n");
                help(argv[0]);
            }            if (*p == '\0') {
                fprintf(stderr, "No ppi specified for '-%c'\n", c);
                help(argv[0]);
            }
            p++;
            optarg = p;
            hdr_data_chunk_ppid = strtoul(optarg, &p, 10);
            if (p == optarg || *p != '\0') {
                fprintf(stderr, "Bad ppi for '-%c'\n", c);
                help(argv[0]);
            }

            hdr_ip = TRUE;
            hdr_ip_proto = 132;
            hdr_ethernet = TRUE;
            hdr_ethernet_proto = 0x800;
            break;

        case 't':
            ts_fmt = optarg;
            break;

        case 'u':
            hdr_udp = TRUE;
            hdr_tcp = FALSE;
            hdr_src_port = strtol(optarg, &p, 10);
            if (p == optarg || (*p != ',' && *p != '\0')) {
                fprintf(stderr, "Bad src port for '-u'\n");
                help(argv[0]);
            }
            if (*p == '\0') {
                fprintf(stderr, "No dest port specified for '-u'\n");
                help(argv[0]);
            }
            p++;
            optarg = p;
            hdr_dest_port = strtol(optarg, &p, 10);
            if (p == optarg || *p != '\0') {
                fprintf(stderr, "Bad dest port for '-u'\n");
                help(argv[0]);
            }
            hdr_ip = TRUE;
            hdr_ip_proto = 17;
            hdr_ethernet = TRUE;
            hdr_ethernet_proto = 0x800;
            break;

        case 'T':
            hdr_tcp = TRUE;
            hdr_udp = FALSE;
            hdr_src_port = strtol(optarg, &p, 10);
            if (p == optarg || (*p != ',' && *p != '\0')) {
                fprintf(stderr, "Bad src port for '-T'\n");
                help(argv[0]);
            }
            if (*p == '\0') {
                fprintf(stderr, "No dest port specified for '-u'\n");
                help(argv[0]);
            }
            p++;
            optarg = p;
            hdr_dest_port = strtol(optarg, &p, 10);
            if (p == optarg || *p != '\0') {
                fprintf(stderr, "Bad dest port for '-T'\n");
                help(argv[0]);
            }
            hdr_ip = TRUE;
            hdr_ip_proto = 6;
            hdr_ethernet = TRUE;
            hdr_ethernet_proto = 0x800;
            break;

        default:
            help(argv[0]);
        }
    }

    if (optind >= argc || argc-optind < 2) {
        fprintf(stderr, "Must specify input and output filename\n");
        help(argv[0]);
    }

    if (strcmp(argv[optind], "-")) {
        input_filename = strdup(argv[optind]);
        input_file = fopen(input_filename, "rb");
        if (!input_file) {
            fprintf(stderr, "Cannot open file [%s] for reading: %s\n",
                    input_filename, strerror(errno));
            exit(-1);
        }
    } else {
        input_filename = "Standard input";
        input_file = stdin;
    }

    if (strcmp(argv[optind+1], "-")) {
        output_filename = strdup(argv[optind+1]);
        output_file = fopen(output_filename, "wb");
        if (!output_file) {
            fprintf(stderr, "Cannot open file [%s] for writing: %s\n",
                    output_filename, strerror(errno));
            exit(-1);
        }
    } else {
        output_filename = "Standard output";
        output_file = stdout;
    }

    /* Some validation */
    if (pcap_link_type != 1 && hdr_ethernet) {
        fprintf(stderr, "Dummy headers (-e, -i, -u, -s, -S -T) cannot be specified with link type override (-l)\n");
        exit(-1);
    }

    /* Set up our variables */
    if (!input_file) {
        input_file = stdin;
        input_filename = "Standard input";
    }
    if (!output_file) {
        output_file = stdout;
        output_filename = "Standard output";
    }

    ts_sec = time(0);		/* initialize to current time */

    /* Display summary of our state */
    if (!quiet) {
        fprintf(stderr, "Input from: %s\n", input_filename);
        fprintf(stderr, "Output to: %s\n", output_filename);

        if (hdr_ethernet) fprintf(stderr, "Generate dummy Ethernet header: Protocol: 0x%0lX\n",
                                  hdr_ethernet_proto);
        if (hdr_ip) fprintf(stderr, "Generate dummy IP header: Protocol: %ld\n",
                            hdr_ip_proto);
        if (hdr_udp) fprintf(stderr, "Generate dummy UDP header: Source port: %ld. Dest port: %ld\n",
                             hdr_src_port, hdr_dest_port);
        if (hdr_tcp) fprintf(stderr, "Generate dummy TCP header: Source port: %ld. Dest port: %ld\n",
                             hdr_src_port, hdr_dest_port);
        if (hdr_sctp) fprintf(stderr, "Generate dummy SCTP header: Source port: %ld. Dest port: %ld. Tag: %ld\n",
                              hdr_sctp_src, hdr_sctp_dest, hdr_sctp_tag);
        if (hdr_data_chunk) fprintf(stderr, "Generate dummy DATA chunk header: TSN: %lu. SID: %d. SSN: %d. PPID: %lu\n",
                                    hdr_data_chunk_tsn, hdr_data_chunk_sid, hdr_data_chunk_ssn, hdr_data_chunk_ppid);
    }
}

int main(int argc, char *argv[])
{
    parse_options(argc, argv);

    assert(input_file != NULL);
    assert(output_file != NULL);

    write_file_header();

    yyin = input_file;
    yylex();

    write_current_packet();
    if (debug)
        fprintf(stderr, "\n-------------------------\n");
    if (!quiet) {
    fprintf(stderr, "Read %ld potential packets, wrote %ld packets\n",
            num_packets_read, num_packets_written);
    }
    return 0;
}
