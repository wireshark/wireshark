/**-*-C-*-**********************************************************************
 *
 * text2pcap.c
 *
 * Utility to convert an ASCII hexdump into a libpcap-format capture file
 *
 * (c) Copyright 2001 Ashok Narayanan <ashokn@cisco.com>
 *
 * $Id: text2pcap.c,v 1.3 2001/07/13 00:55:52 guy Exp $
 * 
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 * 
 * 
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/*--- Local date -----------------------------------------------------------------*/

/* This is where we store the packet currently being built */
#define MAX_PACKET 64000
unsigned char   packet_buf[MAX_PACKET];
unsigned long curr_offset = 0;

/* Number of packets read and written */
unsigned long num_packets_read = 0;
unsigned long num_packets_written = 0;

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
    struct pcaprec_hdr ph;

    if (curr_offset > 0) {
        /* Write the packet */

        /* Compute packet length */
        length = curr_offset;
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
        ph.ts_sec = num_packets_written;
        ph.ts_usec = num_packets_written;
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
                /* Bad offset; switch to INIT state */
                if (debug>=1)
                    fprintf(stderr, "Inconsistent offset. Expecting %0lX, got %0lX. Ignoring rest of packet\n", 
                            curr_offset, num);
                write_current_packet();
                state = INIT;
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
            "          [-u srcp destp] <input-filename> <output-filename>\n"
            "\n"
            "where <input-filename> specifies input filename (use - for standard input)\n"
            "      <output-filename> specifies output filename (use - for standard output)\n"
            "\n"
            "[options] are one or more of the following \n"
            "\n"
            " -w filename  : Write capfile to <filename>. Default is standard output\n"
            " -h           : Display this help message \n"
            " -d           : Generate detailed debug of parser states \n"
            " -o hex|oct   : Parse offsets as (h)ex or (o)ctal. Default is hex\n"
            " -l typenum   : Specify link-layer type number. Default is 1 (Ethernet). \n"
            "                See net/bpf.h for list of numbers.\n"
            " -q           : Generate no output at all (automatically turns off -d)\n"
            " -e l3pid     : Prepend dummy Ethernet II header with specified L3PID (in HEX)\n"
            "                Example: -e 0x800\n"
            " -i proto     : Prepend dummy IP header with specified IP protocol (in DECIMAL). \n"
            "                Automatically prepends Ethernet header as well. Example: -i 46\n"
            " -u srcp destp: Prepend dummy UDP header with specified dest and source ports (in DECIMAL).\n"
            "                Automatically prepends Ethernet and IP headers as well\n"
            "                Example: -u 30 40"
            "\n", 
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

    /* Scan CLI parameters */
    while ((c = getopt(argc, argv, "dqr:w:e:i:l:o:u:")) != -1) {
        switch(c) {
        case '?': help(argv[0]); break;
        case 'h': help(argv[0]); break;
        case 'd': if (!quiet) debug++; break;
        case 'q': quiet = TRUE; debug = FALSE; break;
        case 'l': pcap_link_type = atoi(optarg); break;
        case 'o': 
            if (!optarg || (optarg[0]!='h' && optarg[0] != 'o')) {
                fprintf(stderr, "Bad argument for '-e': %s\n",
                        optarg ? optarg : "");
                help(argv[0]);
            }
            offset_base = (optarg[0]=='o') ? 8 : 16;
            break;
        case 'e':
            hdr_ethernet = TRUE;
            if (!optarg || sscanf(optarg, "%lx", &hdr_ethernet_proto) < 1) {
                fprintf(stderr, "Bad argument for '-e': %s\n",
                        optarg ? optarg : "");
                help(argv[0]);
            }
            break;
            
        case 'i':
            hdr_ip = TRUE;
            if (!optarg || sscanf(optarg, "%ld", &hdr_ip_proto) < 1) {
                fprintf(stderr, "Bad argument for '-i': %s\n",
                        optarg ? optarg : "");
                help(argv[0]);
            }
            hdr_ethernet = TRUE;
            hdr_ethernet_proto = 0x800;
            break;
            
        case 'u':
            hdr_udp = TRUE;
            if (!optarg || sscanf(optarg, "%ld", &hdr_udp_src) < 1) {
                fprintf(stderr, "Bad src port for '-u'\n");
                help(argv[0]);
            }
            if (optind >= argc || sscanf(argv[optind], "%ld", &hdr_udp_dest) < 1) {
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
        fprintf(stderr, "Dummy headers (-e, -i, -u) cannot be specified with link type override (-l)\n");
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
