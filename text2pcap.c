/**-*-C-*-**********************************************************************
 *
 * text2pcap.c
 *
 * Utility to convert an ASCII hexdump into a libpcap-format capture file
 *
 * (c) Copyright 2001 Ashok Narayanan <ashokn@cisco.com>
 *
 * $Id: text2pcap.c,v 1.12 2002/01/29 22:57:30 gram Exp $
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
 * dummy Ethernet, IP and UDP headers to the packets in order to allow
 * dumps of L3 or higher protocols to be decoded.
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
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500
#endif
#define __USE_XOPEN

#include <time.h>

#include <sys/types.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_WINSOCK_H
# include <winsock.h>
#endif
#include <errno.h>
#include <assert.h>

#ifdef NEED_GETOPT_H
# include "getopt.h"
#endif

#ifdef NEED_STRPTIME_H
# include "strptime.h"
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#include "text2pcap.h"

/*--- Options --------------------------------------------------------------------*/

/* Debug level */
int debug = 0; 
/* Be quiet */
int quiet = FALSE;

/* Dummy Ethernet header */
int hdr_ethernet = FALSE;
unsigned long hdr_ethernet_proto = 0;

/* Dummy IP header */
int hdr_ip = FALSE;
unsigned long hdr_ip_proto = 0;

/* Dummy UDP header */
int hdr_udp = FALSE;
unsigned long hdr_udp_dest = 0;
unsigned long hdr_udp_src = 0;

/* Dummy SCTP header */
int hdr_sctp = FALSE;
unsigned long hdr_sctp_src  = 0;
unsigned long hdr_sctp_dest = 0;
unsigned long hdr_sctp_tag  = 0;

/* Dummy DATA chunk header */
int hdr_data_chunk = FALSE;
unsigned char  hdr_data_chunk_type = 0;
unsigned char  hdr_data_chunk_bits = 3;
unsigned long  hdr_data_chunk_tsn  = 0;
unsigned short hdr_data_chunk_sid  = 0;
unsigned short hdr_data_chunk_ssn  = 0;
unsigned long  hdr_data_chunk_ppid = 0;


/*--- Local date -----------------------------------------------------------------*/

/* This is where we store the packet currently being built */
#define MAX_PACKET 64000
unsigned char packet_buf[MAX_PACKET];
unsigned long curr_offset = 0;

/* This buffer contains strings present before the packet offset 0 */
#define PACKET_PREAMBLE_MAX_LEN	2048
static unsigned char packet_preamble[PACKET_PREAMBLE_MAX_LEN+1];
static int packet_preamble_len = 0;

/* Number of packets read and written */
unsigned long num_packets_read = 0;
unsigned long num_packets_written = 0;

/* Time code of packet, derived from packet_preamble */
static unsigned long ts_sec  = 0;
static unsigned long ts_usec = 0;
static char *ts_fmt = NULL;

/* Input file */
char *input_filename;
FILE *input_file = NULL;
/* Output file */
char *output_filename;
FILE *output_file = NULL;

/* Offset base to parse */
unsigned long offset_base = 16;

FILE *yyin;

/* ----- State machine -----------------------------------------------------------*/

/* Current state of parser */
typedef enum {
    INIT,             /* Waiting for start of new packet */
    START_OF_LINE,    /* Starting from beginning of line */
    READ_OFFSET,      /* Just read the offset */
    READ_BYTE,        /* Just read a byte */
    READ_TEXT,        /* Just read text - ignore until EOL */
} parser_state_t;
parser_state_t state = INIT;

const char *state_str[] = {"Init", 
                           "Start-of-line", 
                           "Offset",
                           "Byte",
                           "Text"
};

const char *token_str[] = {"",
                           "Byte", 
                           "Offset",
                           "Directive",
                           "Text",
                           "End-of-line"
};

/* ----- Skeleton Packet Headers --------------------------------------------------*/

typedef struct {
    unsigned char   src_addr[6];
    unsigned char   dest_addr[6];
    unsigned short l3pid;
} hdr_ethernet_t;

hdr_ethernet_t HDR_ETHERNET = {
    {0x01, 0x01, 0x01, 0x01, 0x01, 0x01}, 
    {0x02, 0x02, 0x02, 0x02, 0x02, 0x02},
    0};

typedef struct {
    unsigned char   ver_hdrlen;
    unsigned char   dscp;
    unsigned short packet_length;
    unsigned short identification;
    unsigned char   flags;
    unsigned char   fragment;
    unsigned char   ttl;
    unsigned char   protocol;
    unsigned short hdr_checksum;
    unsigned long src_addr;
    unsigned long dest_addr;
} hdr_ip_t;

hdr_ip_t HDR_IP = {0x45, 0, 0, 0x3412, 0, 0, 0xff, 0, 0, 0x01010101, 0x02020202};

typedef struct {
    unsigned short source_port;
    unsigned short dest_port;
    unsigned short length;
    unsigned short checksum;
} hdr_udp_t;

hdr_udp_t HDR_UDP = {0, 0, 0, 0};

typedef struct {
    unsigned short src_port;
    unsigned short dest_port;
    unsigned long  tag;
    unsigned long  checksum;
} hdr_sctp_t;

hdr_sctp_t HDR_SCTP = {0, 0, 0, 0};

typedef struct {
    unsigned char  type;
    unsigned char  bits;
    unsigned short length;
    unsigned long  tsn;
    unsigned short sid;
    unsigned short ssn;
    unsigned long  ppid;
} hdr_data_chunk_t;

hdr_data_chunk_t HDR_DATA_CHUNK = {0, 0, 0, 0, 0, 0, 0};

char tempbuf[64];

/*----------------------------------------------------------------------
 * Stuff for writing a PCap file
 */
#define	PCAP_MAGIC			0xa1b2c3d4

/* "libpcap" file header (minus magic number). */
struct pcap_hdr {
    unsigned long    magic;          /* magic */
    unsigned short	version_major;	/* major version number */
    unsigned short	version_minor;	/* minor version number */
    unsigned long	thiszone;	/* GMT to local correction */
    unsigned long	sigfigs;	/* accuracy of timestamps */
    unsigned long	snaplen;	/* max length of captured packets, in octets */
    unsigned long	network;	/* data link type */
};

/* "libpcap" record header. */
struct pcaprec_hdr {
    unsigned long	ts_sec;		/* timestamp seconds */
    unsigned long	ts_usec;	/* timestamp microseconds */
    unsigned long	incl_len;	/* number of octets of packet saved in file */
    unsigned long	orig_len;	/* actual length of packet */
};

/* Link-layer type; see net/bpf.h for details */
unsigned long pcap_link_type = 1;   /* Default is DLT-EN10MB */

/*----------------------------------------------------------------------
 * Parse a single hex number
 * Will abort the program if it can't parse the number
 * Pass in TRUE if this is an offset, FALSE if not
 */
static unsigned long
parse_num (char *str, int offset)
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
write_byte (char *str)
{
    unsigned long num;

    num = parse_num(str, FALSE);
    packet_buf[curr_offset] = num;
    curr_offset ++;
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
static unsigned short
in_checksum (void *buf, unsigned long count)
{
    unsigned long sum = 0;
    unsigned short *addr = buf;

    while( count > 1 )  {
        /*  This is the inner loop */
        sum += ntohs(* (unsigned short *) addr++);
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if( count > 0 ) 
        sum += * (unsigned char *) addr;

    /*  Fold 32-bit sum to 16 bits */
    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    return htons(~sum);
}

/* The CRC32C code is taken from draft-ietf-tsvwg-sctpcsum-01.txt.
 * That code is copyrighted by D. Otis and has been modified.
 */
  
#define CRC32C(c,d) (c=(c>>8)^crc_c[(c^(d))&0xFF]) 
static unsigned long crc_c[256] = 
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
     
static unsigned int
crc32c(const unsigned char* buf, unsigned int len, unsigned long crc32_init)
{
  unsigned int i; 
  unsigned long crc32; 
            
  crc32 = crc32_init;
  for (i = 0; i < len; i++)  
    CRC32C(crc32, buf[i]); 
  return crc32; 
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
    int udp_length = 0;
    int ip_length = 0;
    int eth_trailer_length = 0;
    int i, padding_length;
    struct pcaprec_hdr ph;

    if (curr_offset > 0) {
        /* Write the packet */

        /* Compute packet length */
        length = curr_offset;
        if (hdr_data_chunk) { length += sizeof(HDR_DATA_CHUNK) + number_of_padding_bytes(curr_offset); }
        if (hdr_sctp) { length += sizeof(HDR_SCTP); }
        if (hdr_udp) { length += sizeof(HDR_UDP); udp_length = length; }
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
        ph.incl_len = length;
        ph.orig_len = length;
        fwrite(&ph, sizeof(ph), 1, output_file);
        
        /* Write Ethernet header */
        if (hdr_ethernet) {
            HDR_ETHERNET.l3pid = htons(hdr_ethernet_proto);
            fwrite(&HDR_ETHERNET, sizeof(HDR_ETHERNET), 1, output_file);
        }

        /* Write IP header */
        if (hdr_ip) {
            HDR_IP.packet_length = htons(ip_length);
            HDR_IP.protocol = hdr_ip_proto;
            HDR_IP.hdr_checksum = 0;
            HDR_IP.hdr_checksum = in_checksum(&HDR_IP, sizeof(HDR_IP));
            fwrite(&HDR_IP, sizeof(HDR_IP), 1, output_file);
        }

        /* Write UDP header */
        if (hdr_udp) {
            HDR_UDP.source_port = htons(hdr_udp_src);
            HDR_UDP.dest_port = htons(hdr_udp_dest);
            HDR_UDP.length = htons(udp_length);
            
            fwrite(&HDR_UDP, sizeof(HDR_UDP), 1, output_file);
        }
        
        /* Compute DATA chunk header and append padding */
        if (hdr_data_chunk) {
            HDR_DATA_CHUNK.type   = hdr_data_chunk_type;
            HDR_DATA_CHUNK.bits   = hdr_data_chunk_bits;
            HDR_DATA_CHUNK.length = htons(curr_offset + sizeof(HDR_DATA_CHUNK));
            HDR_DATA_CHUNK.tsn    = htonl(hdr_data_chunk_tsn);
            HDR_DATA_CHUNK.sid    = htons(hdr_data_chunk_sid);
            HDR_DATA_CHUNK.ssn    = htons(hdr_data_chunk_ssn);
            HDR_DATA_CHUNK.ppid   = htonl(hdr_data_chunk_ppid);
            
            padding_length = number_of_padding_bytes(curr_offset);
            for (i=0; i<padding_length; i++)
              write_byte("0");
        }
        
        /* Write SCTP header */
        if (hdr_sctp) {
            HDR_SCTP.src_port  = htons(hdr_sctp_src);
            HDR_SCTP.dest_port = htons(hdr_sctp_dest);
            HDR_SCTP.tag       = htonl(hdr_sctp_tag);
            HDR_SCTP.checksum  = htonl(0);
            HDR_SCTP.checksum  = crc32c((unsigned char *)&HDR_SCTP, sizeof(HDR_SCTP), ~0L);
            if (hdr_data_chunk)
              HDR_SCTP.checksum  = crc32c((unsigned char *)&HDR_DATA_CHUNK, sizeof(HDR_DATA_CHUNK), HDR_SCTP.checksum);
            HDR_SCTP.checksum  = htonl(crc32c(packet_buf, curr_offset, HDR_SCTP.checksum));
            
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
            fprintf(stderr, "Wrote packet of %lu bytes\n", curr_offset);
        num_packets_written ++;
    }
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
			ts_sec  = (unsigned long)mktime( &timecode );
		} else
			ts_sec = -1;	/* we failed to parse it */

		/* This will ensure incorrectly parsed dates get set to zero */
		if ( -1L == (long)ts_sec ) 
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
    curr_offset = 0;
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
                state = READ_OFFSET;
            } else if (num != curr_offset) {
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
            "\n"
            "Usage: %s [-d] [-q] [-o h|o] [-l typenum] [-e l3pid] [-i proto] \n"
            "          [-u srcp,destp] [-s srcp,destp,tag] [-S srcp,destp,tag] [-t timefmt] <input-filename> <output-filename>\n"
            "\n"
            "where <input-filename> specifies input filename (use - for standard input)\n"
            "      <output-filename> specifies output filename (use - for standard output)\n"
            "\n"
            "[options] are one or more of the following \n"
            "\n"
            " -w filename     : Write capfile to <filename>. Default is standard output\n"
            " -h              : Display this help message \n"
            " -d              : Generate detailed debug of parser states \n"
            " -o hex|oct      : Parse offsets as (h)ex or (o)ctal. Default is hex\n"
            " -l typenum      : Specify link-layer type number. Default is 1 (Ethernet). \n"
            "                   See net/bpf.h for list of numbers.\n"
            " -q              : Generate no output at all (automatically turns off -d)\n"
            " -e l3pid        : Prepend dummy Ethernet II header with specified L3PID (in HEX)\n"
            "                   Example: -e 0x800\n"
            " -i proto        : Prepend dummy IP header with specified IP protocol (in DECIMAL). \n"
            "                   Automatically prepends Ethernet header as well. Example: -i 46\n"
            " -u srcp,destp   : Prepend dummy UDP header with specified dest and source ports (in DECIMAL).\n"
            "                   Automatically prepends Ethernet and IP headers as well\n"
            "                   Example: -u 30,40\n"
            " -s srcp,dstp,tag: Prepend dummy SCTP header with specified dest/source ports and\n"
            "                   verification tag (in DECIMAL).\n"
            "                   Automatically prepends Ethernet and IP headers as well\n"
            "                   Example: -s 30,40,34\n"
            " -S srcp,dstp,tag: Same as -s srcp,dstp,tag but also prepends a DATA chunk header.\n"
            "                   Example: -S 30,40,34\n"                               
            " -t timefmt      : Treats the text before the packet as a date/time code; the\n"
            "                   specified argument is a format string of the sort supported\n"
            "                   by strptime.\n"
            "                   Example: The time \"10:15:14.5476\" has the format code\n"
            "                   \"%%H:%%M:%%S.\"\n"
            "                   NOTE:    The subsecond component delimiter must be specified\n"
            "                            (.) but no pattern is required; the remaining number\n"
            "                            is assumed to be fractions of a second.\n"
            "",
            progname);

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
    while ((c = getopt(argc, argv, "dqr:w:e:i:l:o:u:s:S:t:")) != -1) {
        switch(c) {
        case '?': help(argv[0]); break;
        case 'h': help(argv[0]); break;
        case 'd': if (!quiet) debug++; break;
        case 'q': quiet = TRUE; debug = FALSE; break;
        case 'l': pcap_link_type = atoi(optarg); break;
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
            if (sscanf(optarg, "%ld", &hdr_ip_proto) < 1) {
                fprintf(stderr, "Bad argument for '-i': %s\n", optarg);
                help(argv[0]);
            }
            hdr_ethernet = TRUE;
            hdr_ethernet_proto = 0x800;
            break;
            
        case 'S':
            hdr_data_chunk = TRUE;
        case 's':
            hdr_sctp = TRUE;
            hdr_sctp_src = strtol(optarg, &p, 10);
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
                fprintf(stderr, "No dest port specified for '-%c'\n", c);
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

        case 't':
            ts_fmt = optarg;
            break;
            
        case 'u':
            hdr_udp = TRUE;
            hdr_udp_src = strtol(optarg, &p, 10);
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
            hdr_udp_dest = strtol(optarg, &p, 10);
            if (p == optarg || *p != '\0') {
                fprintf(stderr, "Bad dest port for '-u'\n");
                help(argv[0]);
            }
            hdr_ip = TRUE;
            hdr_ip_proto = 17;
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
        fprintf(stderr, "Dummy headers (-e, -i, -u, -s, -S) cannot be specified with link type override (-l)\n");
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
    
    /* Display summary of our state */
    if (!quiet) {
        fprintf(stderr, "Input from: %s\n", input_filename);
        fprintf(stderr, "Output to: %s\n", output_filename);

        if (hdr_ethernet) fprintf(stderr, "Generate dummy Ethernet header: Protocol: 0x%0lX\n", 
                                  hdr_ethernet_proto); 
        if (hdr_ip) fprintf(stderr, "Generate dummy IP header: Protocol: %ld\n", 
                            hdr_ip_proto); 
        if (hdr_udp) fprintf(stderr, "Generate dummy UDP header: Source port: %ld. Dest port: %ld\n", 
                             hdr_udp_src, hdr_udp_dest); 
        if (hdr_sctp) fprintf(stderr, "Generate dummy SCTP header: Source port: %ld. Dest port: %ld. Tag: %ld\n", 
                              hdr_sctp_src, hdr_sctp_dest, hdr_sctp_tag); 
        if (hdr_data_chunk) fprintf(stderr, "Generate dummy DATA chunk header: TSN: %ld. SID: %d. SSN: %d. PPID: %ld\n", 
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
