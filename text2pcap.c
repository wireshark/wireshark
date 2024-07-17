/**-*-C-*-**********************************************************************
 *
 * text2pcap.c
 *
 * Utility to convert an ASCII hexdump into a libpcap-format capture file
 *
 * (c) Copyright 2001 Ashok Narayanan <ashokn@cisco.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 *******************************************************************************/

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

#include <config.h>
#define WS_LOG_DOMAIN  LOG_DOMAIN_MAIN

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wsutil/file_util.h>
#include <cli_main.h>
#include <wsutil/cmdarg_err.h>
#include <ui/text_import.h>
#include <wsutil/version_info.h>
#include <ui/failure_message.h>
#include <wsutil/report_message.h>
#include <wsutil/inet_addr.h>
#include <wsutil/cpu_info.h>
#include <wsutil/os_version_info.h>
#include <wsutil/privileges.h>
#include <wsutil/strtoi.h>

#include <glib.h>

#include <ws_exit_codes.h>
#include <wsutil/filesystem.h>
#include <wsutil/str_util.h>
#include <wsutil/strnatcmp.h>
#include <wsutil/wslog.h>
#include <wsutil/ws_getopt.h>

#include <errno.h>

#include "text2pcap.h"

#include "wiretap/wtap.h"
#include "wiretap/pcap-encap.h"

/*--- Options --------------------------------------------------------------------*/

/* Be quiet */
static bool quiet;

/* Dummy Ethernet header */
static bool hdr_ethernet;
#if 0
/* XXX: Maybe add custom Ethernet Address options? */
static uint8_t hdr_eth_dest_addr[6] = {0x0a, 0x02, 0x02, 0x02, 0x02, 0x02};
static uint8_t hdr_eth_src_addr[6]  = {0x0a, 0x02, 0x02, 0x02, 0x02, 0x01};
#endif
static uint32_t hdr_ethernet_proto;

/* Dummy IP header */
static bool hdr_ip;
static bool hdr_ipv6;
static bool have_hdr_ip_proto;
static uint8_t hdr_ip_proto;

/* Destination and source addresses for IP header */
static uint32_t hdr_ip_dest_addr;
static uint32_t hdr_ip_src_addr;
static ws_in6_addr hdr_ipv6_dest_addr = {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
static ws_in6_addr hdr_ipv6_src_addr  = {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};

/* Dummy UDP header */
static bool hdr_udp;
static uint32_t hdr_dest_port;
static uint32_t hdr_src_port;

/* Dummy TCP header */
static bool hdr_tcp;

/* Dummy SCTP header */
static bool hdr_sctp;
static uint32_t hdr_sctp_src;
static uint32_t hdr_sctp_dest;
static uint32_t hdr_sctp_tag;

/* Dummy DATA chunk header */
static bool hdr_data_chunk;
static uint32_t hdr_data_chunk_tsn;
static uint16_t hdr_data_chunk_sid;
static uint16_t hdr_data_chunk_ssn;
static uint32_t hdr_data_chunk_ppid;

/* Export PDU */
static bool hdr_export_pdu;

/*--- Local data -----------------------------------------------------------------*/

/* This is where we store the packet currently being built */
static uint32_t max_offset = WTAP_MAX_PACKET_SIZE_STANDARD;

/* Time code of packet, derived from packet_preamble */
static int      ts_fmt_iso;

/* Input file */
static char *input_filename;
static FILE       *input_file;
/* Output file */
static char *output_filename;

static wtap_dumper* wdh;

/*----------------------------------------------------------------------
 * Print usage string and exit
 */
static void
print_usage (FILE *output)
{
    fprintf(output,
            "\n"
            "Usage: text2pcap [options] <infile> <outfile>\n"
            "\n"
            "where  <infile> specifies input  filename (use - for standard input)\n"
            "      <outfile> specifies output filename (use - for standard output)\n"
            "\n"
            "Input:\n"
            "  -o hex|oct|dec|none    parse offsets as (h)ex, (o)ctal, (d)ecimal, or (n)one;\n"
            "                         default is hex.\n"
            "  -t <timefmt>           treat the text before the packet as a date/time code;\n"
            "                         <timefmt> is a format string supported by strptime,\n"
            "                         with an optional %%f descriptor for fractional seconds.\n"
            "                         Example: The time \"10:15:14.5476\" has the format code\n"
            "                         \"%%H:%%M:%%S.%%f\"\n"
            "                         The special format string ISO supports ISO-8601 times.\n"
            "                         NOTE: Date/time fields from the current date/time are\n"
            "                         used as the default for unspecified fields.\n"
            "  -D                     the text before the packet starts with an I or an O,\n"
            "                         indicating that the packet is inbound or outbound.\n"
            "                         This is used when generating dummy headers if the\n"
            "                         output format supports it (e.g. pcapng).\n"
            "  -a                     enable ASCII text dump identification.\n"
            "                         The start of the ASCII text dump can be identified\n"
            "                         and excluded from the packet data, even if it looks\n"
            "                         like a HEX dump.\n"
            "                         NOTE: Do not enable it if the input file does not\n"
            "                         contain the ASCII text dump.\n"
            "  -r <regex>             enable regex mode. Scan the input using <regex>, a Perl\n"
            "                         compatible regular expression matching a single packet.\n"
            "                         Named capturing subgroups are used to identify fields:\n"
            "                         <data> (mand.), and <time>, <dir>, and <seqno> (opt.)\n"
            "                         The time field format is taken from the -t option\n"
            "                         Example: -r '^(?<dir>[<>])\\s(?<time>\\d+:\\d\\d:\\d\\d.\\d+)\\s(?<data>[0-9a-fA-F]+)$'\n"
            "                         could match a file with lines like\n"
            "                         > 0:00:00.265620 a130368b000000080060\n"
            "                         < 0:00:00.295459 a2010800000000000000000800000000\n"
            "  -b 2|8|16|64           encoding base (radix) of the packet data in regex mode\n"
            "                         (def: 16: hexadecimal) No effect in hexdump mode.\n"
            "\n"
            "Output:\n"
            "  -F <capture type>      set the output file type; default is pcapng.\n"
            "                         an empty \"-F\" option will list the file types.\n"
            "  -E <encap type>        set the output file encapsulation type; default is\n"
            "                         ether (Ethernet). An empty \"-E\" option will list\n"
            "                         the encapsulation types.\n"
            "  -l <typenum>           set the output file encapsulation type via link-layer\n"
            "                         type number; default is 1 (Ethernet). See\n"
            "                         https://www.tcpdump.org/linktypes.html for a list of\n"
            "                         numbers.\n"
            "                         Example: -l 7 for ARCNet packets.\n"
            "  -m <max-packet>        max packet length in output; default is %u\n"
            "  -N <intf-name>         assign name to the interface in the pcapng file.\n"
            "\n"
            "Prepend dummy header:\n"
            "  -e <ethertype>         prepend dummy Ethernet II header with specified EtherType\n"
            "                         (in HEX).\n"
            "                         Example: -e 0x806 to specify an ARP packet.\n"
            "  -i <proto>             prepend dummy IP header with specified IP protocol\n"
            "                         (in DECIMAL).\n"
            "                         Automatically prepends Ethernet header as well if\n"
            "                         link-layer type is Ethernet.\n"
            "                         Example: -i 46\n"
            "  -4 <srcip>,<destip>    prepend dummy IPv4 header with specified\n"
            "                         source and destination addresses.\n"
            "                         Example: -4 10.0.0.1,10.0.0.2\n"
            "  -6 <srcip>,<destip>    prepend dummy IPv6 header with specified\n"
            "                         source and destination addresses.\n"
            "                         Example: -6 2001:db8::b3ff:fe1e:8329,2001:0db8:85a3::8a2e:0370:7334\n"
            "  -u <srcp>,<destp>      prepend dummy UDP header with specified\n"
            "                         source and destination ports (in DECIMAL).\n"
            "                         Automatically prepends Ethernet & IP headers as well.\n"
            "                         Example: -u 1000,69 to make the packets look like\n"
            "                         TFTP/UDP packets.\n"
            "  -T <srcp>,<destp>      prepend dummy TCP header with specified\n"
            "                         source and destination ports (in DECIMAL).\n"
            "                         Automatically prepends Ethernet & IP headers as well.\n"
            "                         Example: -T 50,60\n"
            "  -s <srcp>,<dstp>,<tag> prepend dummy SCTP header with specified\n"
            "                         source/destination ports and verification tag (in DECIMAL).\n"
            "                         Automatically prepends Ethernet & IP headers as well.\n"
            "                         Example: -s 30,40,34\n"
            "  -S <srcp>,<dstp>,<ppi> prepend dummy SCTP header with specified\n"
            "                         source/destination ports and verification tag 0.\n"
            "                         Automatically prepends a dummy SCTP DATA\n"
            "                         chunk header with payload protocol identifier ppi.\n"
            "                         Example: -S 30,40,34\n"
            "  -P <dissector>         prepend EXPORTED_PDU header with specified dissector\n"
            "                         as the payload DISSECTOR_NAME tag.\n"
            "                         Automatically sets link type to Upper PDU Export.\n"
            "                         EXPORTED_PDU payload defaults to \"data\" otherwise.\n"
            "\n",
            WTAP_MAX_PACKET_SIZE_STANDARD);

    ws_log_print_usage(output);

    fprintf(output, "\n"
            "Miscellaneous:\n"
            "  -h, --help             display this help and exit\n"
            "  -v, --version          print version information and exit\n"
            "  -q                     don't report processed packet counts\n"
            "");
}

/*
 * Set the hdr_ip_proto parameter, and set the flag indicate that the
 * parameter has been specified.
 *
 * XXX - catch the case where two different options set it differently?
 */
static void
set_hdr_ip_proto(uint8_t ip_proto)
{
    have_hdr_ip_proto = true;
    hdr_ip_proto = ip_proto;
}

static void
list_capture_types(void) {
    GArray *writable_type_subtypes;

    cmdarg_err("The available capture file types for the \"-F\" flag are:\n");
    writable_type_subtypes = wtap_get_writable_file_types_subtypes(FT_SORT_BY_NAME);
    for (unsigned i = 0; i < writable_type_subtypes->len; i++) {
        int ft = g_array_index(writable_type_subtypes, int, i);
        fprintf(stderr, "    %s - %s\n", wtap_file_type_subtype_name(ft),
            wtap_file_type_subtype_description(ft));
    }
    g_array_free(writable_type_subtypes, TRUE);
}

struct string_elem {
    const char *sstr;   /* The short string */
    const char *lstr;   /* The long string */
};

static int
string_nat_compare(const void *a, const void *b)
{
    return ws_ascii_strnatcmp(((const struct string_elem *)a)->sstr,
        ((const struct string_elem *)b)->sstr);
}

static void
string_elem_print(void *data, void *stream_ptr)
{
    fprintf((FILE *) stream_ptr, "    %s - %s\n",
        ((struct string_elem *)data)->sstr,
        ((struct string_elem *)data)->lstr);
}

static void
list_encap_types(void) {
    int i;
    struct string_elem *encaps;
    GSList *list = NULL;

    encaps = g_new(struct string_elem, wtap_get_num_encap_types());
    cmdarg_err("The available encapsulation types for the \"-E\" flag are:\n");
    for (i = 0; i < wtap_get_num_encap_types(); i++) {
        /* Exclude wtap encapsulations that require a pseudo header,
         * because we won't setup one from the text we import and
         * wiretap doesn't allow us to write 'raw' frames
         */
        if (!wtap_encap_requires_phdr(i)) {
            encaps[i].sstr = wtap_encap_name(i);
            if (encaps[i].sstr != NULL) {
                encaps[i].lstr = wtap_encap_description(i);
                list = g_slist_insert_sorted(list, &encaps[i], string_nat_compare);
            }
        }
    }
    g_slist_foreach(list, string_elem_print, stderr);
    g_slist_free(list);
    g_free(encaps);
}

static void
cleanup_dump_params(wtap_dump_params *params)
{
    wtap_free_idb_info(params->idb_inf);
    wtap_dump_params_cleanup(params);
}

/*----------------------------------------------------------------------
 * Parse CLI options
 */
static int
parse_options(int argc, char *argv[], text_import_info_t * const info, wtap_dump_params * const params)
{
    int   ret;
    int   c;
    char *p;
    static const struct ws_option long_options[] = {
        {"help", ws_no_argument, NULL, 'h'},
        {"version", ws_no_argument, NULL, 'v'},
        {0, 0, 0, 0 }
    };
    const char *interface_name = NULL;
    /* Link-layer type; see https://www.tcpdump.org/linktypes.html for details */
    uint32_t pcap_link_type = 1;   /* Default is LINKTYPE_ETHERNET */
    int file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_UNKNOWN;
    int wtap_encap_type = WTAP_ENCAP_ETHERNET;
    int err;
    char* err_info;
    GError* gerror = NULL;
    GRegex* regex = NULL;

    info->mode = TEXT_IMPORT_HEXDUMP;
    info->hexdump.offset_type = OFFSET_HEX;
    info->regex.encoding = ENCODING_PLAIN_HEX;
    info->payload = "data";

    /* Initialize the version information. */
    ws_init_version_info("Text2pcap", NULL, NULL);

    /* Scan CLI parameters */
    while ((c = ws_getopt_long(argc, argv, "hqab:De:E:F:i:l:m:nN:o:u:P:r:s:S:t:T:v4:6:", long_options, NULL)) != -1) {
        switch (c) {
        case 'h':
            show_help_header("Generate a capture file from an ASCII hexdump of packets.");
            print_usage(stdout);
            exit(0);
            break;
        case 'q': quiet = true; break;
        case 'a': info->hexdump.identify_ascii = true; break;
        case 'D': info->hexdump.has_direction = true; break;
        case 'l':
            pcap_link_type = (uint32_t)strtol(ws_optarg, NULL, 0);
            wtap_encap_type = wtap_pcap_encap_to_wtap_encap(pcap_link_type);
            break;
        case 'm': max_offset = (uint32_t)strtol(ws_optarg, NULL, 0); break;
        case 'n': cmdarg_err("'-n' is deprecated; the output format already defaults to pcapng."); break;
        case 'N': interface_name = ws_optarg; break;
        case 'b':
        {
            uint8_t radix;
            if (!ws_strtou8(ws_optarg, NULL, &radix)) {
                cmdarg_err("Bad argument for '-b': %s", ws_optarg);
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }
            switch (radix) {
            case  2: info->regex.encoding = ENCODING_PLAIN_BIN; break;
            case  8: info->regex.encoding = ENCODING_PLAIN_OCT; break;
            case 16: info->regex.encoding = ENCODING_PLAIN_HEX; break;
            case 64: info->regex.encoding = ENCODING_BASE64; break;
            default:
                cmdarg_err("Bad argument for '-b': %s", ws_optarg);
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }
            break;
        }

        case 'o':
            if (ws_optarg[0] != 'h' && ws_optarg[0] != 'o' && ws_optarg[0] != 'd' && ws_optarg[0] != 'n') {
                cmdarg_err("Bad argument for '-o': %s", ws_optarg);
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }
            switch (ws_optarg[0]) {
            case 'o': info->hexdump.offset_type = OFFSET_OCT; break;
            case 'h': info->hexdump.offset_type = OFFSET_HEX; break;
            case 'd': info->hexdump.offset_type = OFFSET_DEC; break;
            case 'n': info->hexdump.offset_type = OFFSET_NONE; break;
            }
            break;

        case 'e':
            hdr_ethernet = true;
            if (sscanf(ws_optarg, "%x", &hdr_ethernet_proto) < 1) {
                cmdarg_err("Bad argument for '-e': %s", ws_optarg);
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }
            break;

        case 'E':
            wtap_encap_type = wtap_name_to_encap(ws_optarg);
            if (wtap_encap_type < 0) {
                cmdarg_err("\"%s\" isn't a valid encapsulation type", ws_optarg);
                list_encap_types();
                return WS_EXIT_INVALID_OPTION;
            }
            break;

        case 'F':
            file_type_subtype = wtap_name_to_file_type_subtype(ws_optarg);
            if  (file_type_subtype < 0) {
                cmdarg_err("\"%s\" isn't a valid capture file type", ws_optarg);
                list_capture_types();
                return WS_EXIT_INVALID_OPTION;
            }
            break;

        case 'i':
        {
            uint8_t ip_proto;
            if (!ws_strtou8(ws_optarg, NULL, &ip_proto)) {
                cmdarg_err("Bad argument for '-i': %s", ws_optarg);
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }
            set_hdr_ip_proto(ip_proto);
            break;
        }

        case 'P':
            hdr_export_pdu = true;
            wtap_encap_type = WTAP_ENCAP_WIRESHARK_UPPER_PDU;
            info->payload = ws_optarg;
            break;

        case 'r':
            info->mode = TEXT_IMPORT_REGEX;
            if (regex != NULL) {
                /* XXX: Used the option twice. Should we warn? */
                g_regex_unref(regex);
            }
            regex = g_regex_new(ws_optarg, G_REGEX_DUPNAMES | G_REGEX_OPTIMIZE | G_REGEX_MULTILINE, G_REGEX_MATCH_NOTEMPTY, &gerror);
            if (gerror) {
                cmdarg_err("%s", gerror->message);
                g_error_free(gerror);
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            } else {
                if (g_regex_get_string_number(regex, "data") == -1) {
                    cmdarg_err("Regex missing capturing group data (use (?<data>(...)) )");
                    g_regex_unref(regex);
                    print_usage(stderr);
                    return WS_EXIT_INVALID_OPTION;
                }
            }
            break;

        case 's':
            hdr_sctp = true;
            hdr_data_chunk = false;
            hdr_tcp = false;
            hdr_udp = false;
            hdr_sctp_src   = (uint32_t)strtol(ws_optarg, &p, 10);
            if (p == ws_optarg || (*p != ',' && *p != '\0')) {
                cmdarg_err("Bad src port for '-%c'", c);
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }
            if (*p == '\0') {
                cmdarg_err("No dest port specified for '-%c'", c);
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }
            p++;
            ws_optarg = p;
            hdr_sctp_dest = (uint32_t)strtol(ws_optarg, &p, 10);
            if (p == ws_optarg || (*p != ',' && *p != '\0')) {
                cmdarg_err("Bad dest port for '-s'");
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }
            if (*p == '\0') {
                cmdarg_err("No tag specified for '-%c'", c);
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }
            p++;
            ws_optarg = p;
            hdr_sctp_tag = (uint32_t)strtol(ws_optarg, &p, 10);
            if (p == ws_optarg || *p != '\0') {
                cmdarg_err("Bad tag for '-%c'", c);
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }

            set_hdr_ip_proto(132);
            break;

        case 'S':
            hdr_sctp = true;
            hdr_data_chunk = true;
            hdr_tcp = false;
            hdr_udp = false;
            hdr_sctp_src   = (uint32_t)strtol(ws_optarg, &p, 10);
            if (p == ws_optarg || (*p != ',' && *p != '\0')) {
                cmdarg_err("Bad src port for '-%c'", c);
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }
            if (*p == '\0') {
                cmdarg_err("No dest port specified for '-%c'", c);
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }
            p++;
            ws_optarg = p;
            hdr_sctp_dest = (uint32_t)strtol(ws_optarg, &p, 10);
            if (p == ws_optarg || (*p != ',' && *p != '\0')) {
                cmdarg_err("Bad dest port for '-s'");
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }
            if (*p == '\0') {
                cmdarg_err("No ppi specified for '-%c'", c);
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }
            p++;
            ws_optarg = p;
            hdr_data_chunk_ppid = (uint32_t)strtoul(ws_optarg, &p, 10);
            if (p == ws_optarg || *p != '\0') {
                cmdarg_err("Bad ppi for '-%c'", c);
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }

            set_hdr_ip_proto(132);
            break;

        case 't':
            info->timestamp_format = ws_optarg;
            if (!strcmp(ws_optarg, "ISO"))
              ts_fmt_iso = 1;
            break;

        case 'u':
            hdr_udp = true;
            hdr_tcp = false;
            hdr_sctp = false;
            hdr_data_chunk = false;
            hdr_src_port = (uint32_t)strtol(ws_optarg, &p, 10);
            if (p == ws_optarg || (*p != ',' && *p != '\0')) {
                cmdarg_err("Bad src port for '-u'");
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }
            if (*p == '\0') {
                cmdarg_err("No dest port specified for '-u'");
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }
            p++;
            ws_optarg = p;
            hdr_dest_port = (uint32_t)strtol(ws_optarg, &p, 10);
            if (p == ws_optarg || *p != '\0') {
                cmdarg_err("Bad dest port for '-u'");
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }
            set_hdr_ip_proto(17);
            break;

        case 'T':
            hdr_tcp = true;
            hdr_udp = false;
            hdr_sctp = false;
            hdr_data_chunk = false;
            hdr_src_port = (uint32_t)strtol(ws_optarg, &p, 10);
            if (p == ws_optarg || (*p != ',' && *p != '\0')) {
                cmdarg_err("Bad src port for '-T'");
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }
            if (*p == '\0') {
                cmdarg_err("No dest port specified for '-u'");
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }
            p++;
            ws_optarg = p;
            hdr_dest_port = (uint32_t)strtol(ws_optarg, &p, 10);
            if (p == ws_optarg || *p != '\0') {
                cmdarg_err("Bad dest port for '-T'");
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }
            set_hdr_ip_proto(6);
            break;

        case 'v':
            show_version();
            exit(0);
            break;

        case '4':
        case '6':
            p = strchr(ws_optarg, ',');

            if (!p) {
                cmdarg_err("Bad source param addr for '-%c'", c);
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }

            *p = '\0';
            if (c == '6')
            {
                hdr_ipv6 = true;
                hdr_ip   = false;
            }
            else
            {
                hdr_ip   = true;
                hdr_ipv6 = false;
            }
            hdr_ethernet = true;

            if (hdr_ipv6 == true) {
                if (!ws_inet_pton6(ws_optarg, &hdr_ipv6_src_addr)) {
                        cmdarg_err("Bad src addr -%c '%s'", c, p);
                        print_usage(stderr);
                        return WS_EXIT_INVALID_OPTION;
                }
            } else {
                if (!ws_inet_pton4(ws_optarg, &hdr_ip_src_addr)) {
                        cmdarg_err("Bad src addr -%c '%s'", c, p);
                        print_usage(stderr);
                        return WS_EXIT_INVALID_OPTION;
                }
            }

            p++;
            if (*p == '\0') {
                cmdarg_err("No dest addr specified for '-%c'", c);
                print_usage(stderr);
                return WS_EXIT_INVALID_OPTION;
            }

            if (hdr_ipv6 == true) {
                if (!ws_inet_pton6(p, &hdr_ipv6_dest_addr)) {
                        cmdarg_err("Bad dest addr for -%c '%s'", c, p);
                        print_usage(stderr);
                        return WS_EXIT_INVALID_OPTION;
                }
            } else {
                if (!ws_inet_pton4(p, &hdr_ip_dest_addr)) {
                        cmdarg_err("Bad dest addr for -%c '%s'", c, p);
                        print_usage(stderr);
                        return WS_EXIT_INVALID_OPTION;
                }
            }
            break;


        case '?':
            switch(ws_optopt) {
            case 'E':
                list_encap_types();
                return WS_EXIT_INVALID_OPTION;
            case 'F':
                list_capture_types();
                return WS_EXIT_INVALID_OPTION;
            }
            /* FALLTHROUGH */

        default:
            print_usage(stderr);
            return WS_EXIT_INVALID_OPTION;
        }
    }

    if (ws_optind >= argc || argc-ws_optind < 2) {
        cmdarg_err("Must specify input and output filename");
        print_usage(stderr);
        return WS_EXIT_INVALID_OPTION;
    }

    if (max_offset > WTAP_MAX_PACKET_SIZE_STANDARD) {
        cmdarg_err("Maximum packet length cannot be more than %d bytes",
                WTAP_MAX_PACKET_SIZE_STANDARD);
        return WS_EXIT_INVALID_OPTION;
    }

    /* Some validation */

    if (info->mode == TEXT_IMPORT_REGEX) {
        info->regex.format = regex;
        /* need option for data encoding */
        if (g_regex_get_string_number(regex, "dir") > -1) {
            /* XXX: Add parameter(s?) to specify these? */
            info->regex.in_indication = "iI<";
            info->regex.out_indication = "oO>";
        }
        if (g_regex_get_string_number(regex, "time") > -1 && info->timestamp_format == NULL) {
            cmdarg_err("Regex with <time> capturing group requires time format (-t)");
            return WS_EXIT_INVALID_OPTION;
        }
    }

    if (have_hdr_ip_proto && !(hdr_ip || hdr_ipv6)) {
        /*
         * If we have an IP protocol to add to the header, but neither an
         * IPv4 nor an IPv6 header was specified,  add an IPv4 header.
         */
        hdr_ip = true;
    }

    if (!have_hdr_ip_proto && (hdr_ip || hdr_ipv6)) {
        /* if -4 or -6 option is specified without an IP protocol then fail */
        cmdarg_err("IP protocol requires a next layer protocol number");
        return WS_EXIT_INVALID_OPTION;
    }

    if ((hdr_tcp || hdr_udp || hdr_sctp) && !(hdr_ip || hdr_ipv6)) {
        /*
         * If TCP (-T), UDP (-u) or SCTP (-s/-S) header options are specified
         * but none of IPv4 (-4) or IPv6 (-6) options then add an IPv4 header
         */
        hdr_ip = true;
    }

    if (hdr_export_pdu && wtap_encap_type != WTAP_ENCAP_WIRESHARK_UPPER_PDU) {
        cmdarg_err("Export PDU (-P) requires WIRESHARK_UPPER_PDU link type (252)");
        return WS_EXIT_INVALID_OPTION;
    }

    /* The other dummy headers require a IPv4 or IPv6 header. Allow
     * encapsulation types of Ethernet (and add a Ethernet header in that
     * case if we haven't already), or the appropriate raw IP types.
     */
    if (hdr_ip) {
        switch (wtap_encap_type) {

        case (WTAP_ENCAP_ETHERNET):
            hdr_ethernet = true;
            hdr_ethernet_proto = 0x0800;
            break;

        case (WTAP_ENCAP_RAW_IP):
        case (WTAP_ENCAP_RAW_IP4):
            break;

        default:
            cmdarg_err("Dummy IPv4 header not supported with encapsulation %s (%s)", wtap_encap_description(wtap_encap_type), wtap_encap_name(wtap_encap_type));
            return WS_EXIT_INVALID_OPTION;
        }
    } else if (hdr_ipv6) {
        switch (wtap_encap_type) {

        case (WTAP_ENCAP_ETHERNET):
            hdr_ethernet = true;
            hdr_ethernet_proto = 0x86DD;
            break;

        case (WTAP_ENCAP_RAW_IP):
        case (WTAP_ENCAP_RAW_IP6):
            break;

        default:
            cmdarg_err("Dummy IPv6 header not supported with encapsulation %s (%s)", wtap_encap_description(wtap_encap_type), wtap_encap_name(wtap_encap_type));
            return WS_EXIT_INVALID_OPTION;
        }
    }

    if (strcmp(argv[ws_optind], "-") != 0) {
        input_filename = argv[ws_optind];
        if (info->mode == TEXT_IMPORT_REGEX) {
            info->regex.import_text_GMappedFile = g_mapped_file_new(input_filename, TRUE, &gerror);
            if (gerror) {
                cmdarg_err("%s", gerror->message);
                g_error_free(gerror);
                return WS_EXIT_OPEN_ERROR;
            }
        } else {
            input_file = ws_fopen(input_filename, "rb");
            if (!input_file) {
                open_failure_message(input_filename, errno, false);
                return WS_EXIT_OPEN_ERROR;
            }
        }
    } else {
        if (info->mode == TEXT_IMPORT_REGEX) {
            /* text_import_regex requires a memory mapped file, so this likely
             * won't work, unless the user has redirected a file (not a FIFO)
             * to stdin, though that's pretty silly and unnecessary.
             * XXX: We could read until EOF, write it to a temp file, and then
             * mmap that (ugh)?
             */
            info->regex.import_text_GMappedFile = g_mapped_file_new_from_fd(0, TRUE, &gerror);
            if (gerror) {
                cmdarg_err("%s", gerror->message);
                cmdarg_err("regex import requires memory-mapped I/O and cannot be used with terminals or pipes");
                g_error_free(gerror);
                return WS_EXIT_INVALID_OPTION;
            }
        }
        input_filename = "Standard input";
        input_file = stdin;
    }

    params->encap = wtap_encap_type;
    params->snaplen = max_offset;
    if (file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_UNKNOWN) {
        file_type_subtype = wtap_pcapng_file_type_subtype();
    }
    /* Request nanosecond precision. Most file formats only support one time
     * precision and ignore this parameter (and the related options in the
     * generated IDB), but it affects pcapng.
     */
    params->tsprec = WTAP_TSPREC_NSEC;
    if ((ret = text_import_pre_open(params, file_type_subtype, input_filename, interface_name)) != EXIT_SUCCESS) {
        cleanup_dump_params(params);
        return ret;
    }

    if (strcmp(argv[ws_optind+1], "-") != 0) {
        /* Write to a file.  Open the file. */
        output_filename = argv[ws_optind+1];
        wdh = wtap_dump_open(output_filename, file_type_subtype, WTAP_UNCOMPRESSED, params, &err, &err_info);
    } else {
        /* Write to the standard output. */
        output_filename = "Standard output";
        wdh = wtap_dump_open_stdout(file_type_subtype, WTAP_UNCOMPRESSED, params, &err, &err_info);
    }

    if (!wdh) {
        cfile_dump_open_failure_message(output_filename, err, err_info,
                                        file_type_subtype);
        cleanup_dump_params(params);
        return WS_EXIT_OPEN_ERROR;
    }

    info->import_text_filename = input_filename;
    info->output_filename = output_filename;
    info->hexdump.import_text_FILE = input_file;

    info->encapsulation = wtap_encap_type;
    info->wdh = wdh;

    if (hdr_export_pdu) {
        info->dummy_header_type = HEADER_EXPORT_PDU;
    } else if (hdr_data_chunk) {
        info->dummy_header_type = HEADER_SCTP_DATA;
    } else if (hdr_sctp) {
        info->dummy_header_type = HEADER_SCTP;
    } else if (hdr_tcp) {
        info->dummy_header_type = HEADER_TCP;
    } else if (hdr_udp) {
        info->dummy_header_type = HEADER_UDP;
    } else if (hdr_ip) {
        info->dummy_header_type = HEADER_IPV4;
    } else if (hdr_ipv6) {
        info->dummy_header_type = HEADER_IPV4;
    } else if (hdr_ethernet) {
        info->dummy_header_type = HEADER_ETH;
    } else {
        info->dummy_header_type = HEADER_NONE;
    }
    info->pid = hdr_ethernet_proto;
    if (hdr_ip) {
        info->ip_src_addr.ipv4 = hdr_ip_src_addr;
        info->ip_dest_addr.ipv4 = hdr_ip_dest_addr;
    } else if (hdr_ipv6) {
        info->ipv6 = true;
        info->ip_src_addr.ipv6 = hdr_ipv6_src_addr;
        info->ip_dest_addr.ipv6 = hdr_ipv6_dest_addr;
    }
    info->protocol = hdr_ip_proto;
    if (hdr_sctp) {
        info->src_port = hdr_sctp_src;
        info->dst_port = hdr_sctp_dest;
    } else {
        info->src_port = hdr_src_port;
        info->dst_port = hdr_dest_port;
    }
    info->tag = hdr_sctp_tag;
    info->ppi = hdr_data_chunk_ppid;

    info->max_frame_length = max_offset;

    /* Display summary of our state */
    if (!quiet) {
        fprintf(stderr, "Input from: %s\n", input_filename);
        fprintf(stderr, "Output to: %s\n",  output_filename);
        fprintf(stderr, "Output format: %s\n", wtap_file_type_subtype_name(file_type_subtype));
        if (hdr_ethernet) fprintf(stderr, "Generate dummy Ethernet header: Protocol: 0x%0X\n",
                                  hdr_ethernet_proto);
        if (hdr_ip) fprintf(stderr, "Generate dummy IP header: Protocol: %u\n",
                            hdr_ip_proto);
        if (hdr_ipv6) fprintf(stderr, "Generate dummy IPv6 header: Protocol: %u\n",
                            hdr_ip_proto);
        if (hdr_udp) fprintf(stderr, "Generate dummy UDP header: Source port: %u. Dest port: %u\n",
                             hdr_src_port, hdr_dest_port);
        if (hdr_tcp) fprintf(stderr, "Generate dummy TCP header: Source port: %u. Dest port: %u\n",
                             hdr_src_port, hdr_dest_port);
        if (hdr_sctp) fprintf(stderr, "Generate dummy SCTP header: Source port: %u. Dest port: %u. Tag: %u\n",
                              hdr_sctp_src, hdr_sctp_dest, hdr_sctp_tag);
        if (hdr_data_chunk) fprintf(stderr, "Generate dummy DATA chunk header: TSN: %u. SID: %u. SSN: %u. PPID: %u\n",
                                    hdr_data_chunk_tsn, hdr_data_chunk_sid, hdr_data_chunk_ssn, hdr_data_chunk_ppid);
    }

    return EXIT_SUCCESS;
}

/*
 * General errors and warnings are reported with an console message
 * in text2pcap.
 */
static void
text2pcap_cmdarg_err(const char *msg_format, va_list ap)
{
    fprintf(stderr, "text2pcap: ");
    vfprintf(stderr, msg_format, ap);
    fprintf(stderr, "\n");
}

/*
 * Report additional information for an error in command-line arguments.
 */
static void
text2pcap_cmdarg_err_cont(const char *msg_format, va_list ap)
{
    vfprintf(stderr, msg_format, ap);
    fprintf(stderr, "\n");
}

int
main(int argc, char *argv[])
{
    char  *configuration_init_error;
    static const struct report_message_routines text2pcap_report_routines = {
        failure_message,
        failure_message,
        open_failure_message,
        read_failure_message,
        write_failure_message,
        cfile_open_failure_message,
        cfile_dump_open_failure_message,
        cfile_read_failure_message,
        cfile_write_failure_message,
        cfile_close_failure_message
    };
    int ret = EXIT_SUCCESS;
    text_import_info_t info;
    wtap_dump_params params;
    uint64_t bytes_written;

    cmdarg_err_init(text2pcap_cmdarg_err, text2pcap_cmdarg_err_cont);

    /* Initialize log handler early so we can have proper logging during startup. */
    ws_log_init("text2pcap", vcmdarg_err);

    /* Early logging command-line initialization. */
    ws_log_parse_args(&argc, argv, vcmdarg_err, WS_EXIT_INVALID_OPTION);

    ws_noisy("Finished log init and parsing command line log arguments");

#ifdef _WIN32
    create_app_running_mutex();
#endif /* _WIN32 */

    init_process_policies();

    /*
     * Make sure our plugin path is initialized for wtap_init.
     */
    configuration_init_error = configuration_init(argv[0], NULL);
    if (configuration_init_error != NULL) {
        fprintf(stderr,
                "text2pcap: Can't get pathname of directory containing the text2pcap program: %s.\n",
                configuration_init_error);
        g_free(configuration_init_error);
    }

    init_report_message("text2pcap", &text2pcap_report_routines);
    wtap_init(true);

    memset(&info, 0, sizeof(info));
    wtap_dump_params_init(&params, NULL);
    if ((ret = parse_options(argc, argv, &info, &params)) != EXIT_SUCCESS) {
        goto clean_exit;
    }

    ws_assert(input_file != NULL || info.regex.import_text_GMappedFile != NULL);
    ws_assert(wdh != NULL);

    ret = text_import(&info);

    if (ws_log_get_level() >= LOG_LEVEL_DEBUG)
        fprintf(stderr, "\n-------------------------\n");
    if (!quiet) {
        bytes_written = wtap_get_bytes_dumped(wdh);
        fprintf(stderr, "Read %u potential packet%s, wrote %u packet%s (%" PRIu64 " byte%s including overhead).\n",
                info.num_packets_read, plurality(info.num_packets_read, "", "s"),
                info.num_packets_written, plurality(info.num_packets_written, "", "s"),
                bytes_written, plurality(bytes_written, "", "s"));
    }
clean_exit:
    if (input_file) {
        fclose(input_file);
    }
    if (info.regex.import_text_GMappedFile) {
        g_mapped_file_unref(info.regex.import_text_GMappedFile);
    }
    if (info.regex.format) {
        g_regex_unref(info.regex.format);
    }
    if (wdh) {
        int err;
        char *err_info;
        if (!wtap_dump_close(wdh, NULL, &err, &err_info)) {
            cfile_close_failure_message(output_filename, err, err_info);
            ret = 2;
        }
    }
    cleanup_dump_params(&params);
    return ret;
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
