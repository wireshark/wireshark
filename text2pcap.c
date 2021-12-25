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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wsutil/file_util.h>
#include <cli_main.h>
#include <ui/cmdarg_err.h>
#include <ui/exit_codes.h>
#include <ui/text_import.h>
#include <ui/version_info.h>
#include <ui/failure_message.h>
#include <wsutil/report_message.h>
#include <wsutil/inet_addr.h>
#include <wsutil/cpu_info.h>
#include <wsutil/os_version_info.h>
#include <wsutil/privileges.h>
#include <wsutil/strtoi.h>

#include <glib.h>

#include <wsutil/str_util.h>
#include <wsutil/wslog.h>
#include <wsutil/ws_getopt.h>

#include <errno.h>
#include <assert.h>

#include "text2pcap.h"

#include "wiretap/wtap.h"
#include "wiretap/pcap-encap.h"

/*--- Options --------------------------------------------------------------------*/

/* File format */
static gboolean use_pcapng = FALSE;

/* Debug level */
static int debug = 0;
/* Be quiet */
static gboolean quiet = FALSE;

/* Dummy Ethernet header */
static gboolean hdr_ethernet = FALSE;
#if 0
/* XXX: Maybe add custom Ethernet Address options? */
static guint8 hdr_eth_dest_addr[6] = {0x0a, 0x02, 0x02, 0x02, 0x02, 0x02};
static guint8 hdr_eth_src_addr[6]  = {0x0a, 0x02, 0x02, 0x02, 0x02, 0x01};
#endif
static guint32 hdr_ethernet_proto = 0;

/* Dummy IP header */
static gboolean hdr_ip = FALSE;
static gboolean hdr_ipv6 = FALSE;
static gboolean have_hdr_ip_proto = FALSE;
static guint8 hdr_ip_proto = 0;

/* Destination and source addresses for IP header */
static guint32 hdr_ip_dest_addr = 0;
static guint32 hdr_ip_src_addr = 0;
static ws_in6_addr hdr_ipv6_dest_addr = {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
static ws_in6_addr hdr_ipv6_src_addr  = {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};

/* Dummy UDP header */
static gboolean hdr_udp = FALSE;
static guint32 hdr_dest_port = 0;
static guint32 hdr_src_port  = 0;

/* Dummy TCP header */
static gboolean hdr_tcp = FALSE;

/* Dummy SCTP header */
static gboolean hdr_sctp = FALSE;
static guint32 hdr_sctp_src  = 0;
static guint32 hdr_sctp_dest = 0;
static guint32 hdr_sctp_tag  = 0;

/* Dummy DATA chunk header */
static gboolean hdr_data_chunk = FALSE;
static guint32 hdr_data_chunk_tsn  = 0;
static guint16 hdr_data_chunk_sid  = 0;
static guint16 hdr_data_chunk_ssn  = 0;
static guint32 hdr_data_chunk_ppid = 0;

/* ASCII text dump identification */
static gboolean identify_ascii = FALSE;

static gboolean has_direction = FALSE;

/*--- Local data -----------------------------------------------------------------*/

/* This is where we store the packet currently being built */
static guint32 max_offset = WTAP_MAX_PACKET_SIZE_STANDARD;

/* Time code of packet, derived from packet_preamble */
static char    *ts_fmt  = NULL;
static int      ts_fmt_iso = 0;

/* Input file */
static char *input_filename;
static FILE       *input_file  = NULL;
/* Output file */
static char *output_filename;

static wtap_dumper* wdh;

/* Offset base to parse */
static guint32 offset_base = 16;

/* Encapsulation type; see wiretap/wtap.h for details */
static guint32 wtap_encap_type = 1;   /* Default is WTAP_ENCAP_ETHERNET */

/*----------------------------------------------------------------------
 * Write file header and trailer
 */
static int
write_file_header(wtap_dump_params * const params, int file_type_subtype, const char* const interface_name)
{
    wtap_block_t shb_hdr;
    wtap_block_t int_data;
    wtapng_if_descr_mandatory_t *int_data_mand;
    char    *comment;
    GString *info_str;

    if (wtap_file_type_subtype_supports_block(file_type_subtype, WTAP_BLOCK_SECTION) != BLOCK_NOT_SUPPORTED &&
        wtap_file_type_subtype_supports_option(file_type_subtype, WTAP_BLOCK_SECTION, OPT_COMMENT) != OPTION_NOT_SUPPORTED) {

        shb_hdr = wtap_block_create(WTAP_BLOCK_SECTION);

        comment = ws_strdup_printf("Generated from input file %s.", input_filename);
        wtap_block_add_string_option(shb_hdr, OPT_COMMENT, comment, strlen(comment));
        g_free(comment);

        info_str = g_string_new("");
        get_cpu_info(info_str);
        if (info_str->str) {
            wtap_block_add_string_option(shb_hdr, OPT_SHB_HARDWARE, info_str->str, info_str->len);
        }
        g_string_free(info_str, TRUE);

        info_str = g_string_new("");
        get_os_version_info(info_str);
        if (info_str->str) {
            wtap_block_add_string_option(shb_hdr, OPT_SHB_OS, info_str->str, info_str->len);
        }
        g_string_free(info_str, TRUE);

        wtap_block_add_string_option_format(shb_hdr, OPT_SHB_USERAPPL, "%s", get_appname_and_version());

        params->shb_hdrs = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));
        g_array_append_val(params->shb_hdrs, shb_hdr);
    }

    /* wtap_dumper will create a dummy interface block if needed, but since
     * we have the option of including the interface name, create it ourself.
     */
    if (wtap_file_type_subtype_supports_block(file_type_subtype, WTAP_BLOCK_IF_ID_AND_INFO) != BLOCK_NOT_SUPPORTED) {
        int_data = wtap_block_create(WTAP_BLOCK_IF_ID_AND_INFO);
        int_data_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(int_data);

        int_data_mand->wtap_encap = params->encap;
        int_data_mand->time_units_per_second = 1000000000;
        int_data_mand->snap_len = params->snaplen;

        if (interface_name != NULL) {
            wtap_block_add_string_option(int_data, OPT_IDB_NAME, interface_name, strlen(interface_name));
        } else {
            wtap_block_add_string_option(int_data, OPT_IDB_NAME, "Fake IF, text2pcap", strlen("Fake IF, text2pcap"));
        }
        wtap_block_add_uint8_option(int_data, OPT_IDB_TSRESOL, params->tsprec);

        params->idb_inf = g_new(wtapng_iface_descriptions_t,1);
        params->idb_inf->interface_data = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));
        g_array_append_val(params->idb_inf->interface_data, int_data);

    }

    return EXIT_SUCCESS;
}

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
            "  -o hex|oct|dec         parse offsets as (h)ex, (o)ctal or (d)ecimal;\n"
            "                         default is hex.\n"
            "  -t <timefmt>           treat the text before the packet as a date/time code;\n"
            "                         the specified argument is a format string of the sort\n"
            "                         supported by strptime.\n"
            "                         Example: The time \"10:15:14.5476\" has the format code\n"
            "                         \"%%H:%%M:%%S.\"\n"
            "                         NOTE: The subsecond component delimiter, '.', must be\n"
            "                         given, but no pattern is required; the remaining\n"
            "                         number is assumed to be fractions of a second.\n"
            "                         NOTE: Date/time fields from the current date/time are\n"
            "                         used as the default for unspecified fields.\n"
            "  -D                     the text before the packet starts with an I or an O,\n"
            "                         indicating that the packet is inbound or outbound.\n"
            "                         This is used when generating dummy headers.\n"
            "                         The indication is only stored if the output format is pcapng.\n"
            "  -a                     enable ASCII text dump identification.\n"
            "                         The start of the ASCII text dump can be identified\n"
            "                         and excluded from the packet data, even if it looks\n"
            "                         like a HEX dump.\n"
            "                         NOTE: Do not enable it if the input file does not\n"
            "                         contain the ASCII text dump.\n"
            "\n"
            "Output:\n"
            "  -l <typenum>           link-layer type number; default is 1 (Ethernet).  See\n"
            "                         https://www.tcpdump.org/linktypes.html for a list of\n"
            "                         numbers.  Use this option if your dump is a complete\n"
            "                         hex dump of an encapsulated packet and you wish to\n"
            "                         specify the exact type of encapsulation.\n"
            "                         Example: -l 7 for ARCNet packets.\n"
            "  -m <max-packet>        max packet length in output; default is %d\n"
            "  -n                     use pcapng instead of pcap as output format.\n"
            "  -N <intf-name>         assign name to the interface in the pcapng file.\n"
            "\n"
            "Prepend dummy header:\n"
            "  -e <l3pid>             prepend dummy Ethernet II header with specified L3PID\n"
            "                         (in HEX).\n"
            "                         Example: -e 0x806 to specify an ARP packet.\n"
            "  -i <proto>             prepend dummy IP header with specified IP protocol\n"
            "                         (in DECIMAL).\n"
            "                         Automatically prepends Ethernet header as well.\n"
            "                         Example: -i 46\n"
            "  -4 <srcip>,<destip>    prepend dummy IPv4 header with specified\n"
            "                         dest and source address.\n"
            "                         Example: -4 10.0.0.1,10.0.0.2\n"
            "  -6 <srcip>,<destip>    prepend dummy IPv6 header with specified\n"
            "                         dest and source address.\n"
            "                         Example: -6 fe80::202:b3ff:fe1e:8329,2001:0db8:85a3::8a2e:0370:7334\n"
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
            "                         source/dest ports and verification tag (in DECIMAL).\n"
            "                         Automatically prepends Ethernet & IP headers as well.\n"
            "                         Example: -s 30,40,34\n"
            "  -S <srcp>,<dstp>,<ppi> prepend dummy SCTP header with specified\n"
            "                         source/dest ports and verification tag 0.\n"
            "                         Automatically prepends a dummy SCTP DATA\n"
            "                         chunk header with payload protocol identifier ppi.\n"
            "                         Example: -S 30,40,34\n"
            "\n"
            "Miscellaneous:\n"
            "  -h                     display this help and exit.\n"
            "  -v                     print version information and exit.\n"
            "  -d                     show detailed debug of parser states.\n"
            "  -q                     generate no output at all (automatically disables -d).\n"
            "",
            WTAP_MAX_PACKET_SIZE_STANDARD);
}

/*
 * Set the hdr_ip_proto parameter, and set the flag indicate that the
 * parameter has been specified.
 *
 * Also indicate that we should add an Ethernet link-layer header.
 * (That's not an *inherent* requirement, as we could write a file
 * with a "raw IP packet" link-layer type, meaning that there *is*
 * no link-layer header, but it's the way text2pcap currently works.)
 *
 * XXX - catch the case where two different options set it differently?
 */
static void
set_hdr_ip_proto(guint8 ip_proto)
{
    have_hdr_ip_proto = TRUE;
    hdr_ip_proto = ip_proto;
    hdr_ethernet = TRUE;
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
    guint32 pcap_link_type = 1;   /* Default is LINKTYPE_ETHERNET */
    int file_type_subtype;
    int err;
    char* err_info;

    /* Initialize the version information. */
    ws_init_version_info("Text2pcap (Wireshark)", NULL, NULL, NULL);

    /* Scan CLI parameters */
    while ((c = ws_getopt_long(argc, argv, "aDdhqe:i:l:m:nN:o:u:s:S:t:T:v4:6:", long_options, NULL)) != -1) {
        switch (c) {
        case 'h':
            show_help_header("Generate a capture file from an ASCII hexdump of packets.");
            print_usage(stdout);
            exit(0);
            break;
        case 'd': if (!quiet) debug++; break;
        case 'D': has_direction = TRUE; break;
        case 'q': quiet = TRUE; debug = 0; break;
        case 'l': pcap_link_type = (guint32)strtol(ws_optarg, NULL, 0); break;
        case 'm': max_offset = (guint32)strtol(ws_optarg, NULL, 0); break;
        case 'n': use_pcapng = TRUE; break;
        case 'N': interface_name = ws_optarg; break;
        case 'o':
            if (ws_optarg[0] != 'h' && ws_optarg[0] != 'o' && ws_optarg[0] != 'd') {
                cmdarg_err("Bad argument for '-o': %s", ws_optarg);
                print_usage(stderr);
                return INVALID_OPTION;
            }
            switch (ws_optarg[0]) {
            case 'o': offset_base =  8; break;
            case 'h': offset_base = 16; break;
            case 'd': offset_base = 10; break;
            }
            break;
        case 'e':
            hdr_ethernet = TRUE;
            if (sscanf(ws_optarg, "%x", &hdr_ethernet_proto) < 1) {
                cmdarg_err("Bad argument for '-e': %s", ws_optarg);
                print_usage(stderr);
                return INVALID_OPTION;
            }
            break;

        case 'i':
        {
            guint8 ip_proto;
            if (!ws_strtou8(ws_optarg, NULL, &ip_proto)) {
                cmdarg_err("Bad argument for '-i': %s", ws_optarg);
                print_usage(stderr);
                return INVALID_OPTION;
            }
            set_hdr_ip_proto(ip_proto);
            break;
        }

        case 's':
            hdr_sctp = TRUE;
            hdr_data_chunk = FALSE;
            hdr_tcp = FALSE;
            hdr_udp = FALSE;
            hdr_sctp_src   = (guint32)strtol(ws_optarg, &p, 10);
            if (p == ws_optarg || (*p != ',' && *p != '\0')) {
                cmdarg_err("Bad src port for '-%c'", c);
                print_usage(stderr);
                return INVALID_OPTION;
            }
            if (*p == '\0') {
                cmdarg_err("No dest port specified for '-%c'", c);
                print_usage(stderr);
                return INVALID_OPTION;
            }
            p++;
            ws_optarg = p;
            hdr_sctp_dest = (guint32)strtol(ws_optarg, &p, 10);
            if (p == ws_optarg || (*p != ',' && *p != '\0')) {
                cmdarg_err("Bad dest port for '-s'");
                print_usage(stderr);
                return INVALID_OPTION;
            }
            if (*p == '\0') {
                cmdarg_err("No tag specified for '-%c'", c);
                print_usage(stderr);
                return INVALID_OPTION;
            }
            p++;
            ws_optarg = p;
            hdr_sctp_tag = (guint32)strtol(ws_optarg, &p, 10);
            if (p == ws_optarg || *p != '\0') {
                cmdarg_err("Bad tag for '-%c'", c);
                print_usage(stderr);
                return INVALID_OPTION;
            }

            set_hdr_ip_proto(132);
            break;
        case 'S':
            hdr_sctp = TRUE;
            hdr_data_chunk = TRUE;
            hdr_tcp = FALSE;
            hdr_udp = FALSE;
            hdr_sctp_src   = (guint32)strtol(ws_optarg, &p, 10);
            if (p == ws_optarg || (*p != ',' && *p != '\0')) {
                cmdarg_err("Bad src port for '-%c'", c);
                print_usage(stderr);
                return INVALID_OPTION;
            }
            if (*p == '\0') {
                cmdarg_err("No dest port specified for '-%c'", c);
                print_usage(stderr);
                return INVALID_OPTION;
            }
            p++;
            ws_optarg = p;
            hdr_sctp_dest = (guint32)strtol(ws_optarg, &p, 10);
            if (p == ws_optarg || (*p != ',' && *p != '\0')) {
                cmdarg_err("Bad dest port for '-s'");
                print_usage(stderr);
                return INVALID_OPTION;
            }
            if (*p == '\0') {
                cmdarg_err("No ppi specified for '-%c'", c);
                print_usage(stderr);
                return INVALID_OPTION;
            }
            p++;
            ws_optarg = p;
            hdr_data_chunk_ppid = (guint32)strtoul(ws_optarg, &p, 10);
            if (p == ws_optarg || *p != '\0') {
                cmdarg_err("Bad ppi for '-%c'", c);
                print_usage(stderr);
                return INVALID_OPTION;
            }

            set_hdr_ip_proto(132);
            break;

        case 't':
            ts_fmt = ws_optarg;
            if (!strcmp(ws_optarg, "ISO"))
              ts_fmt_iso = 1;
            break;

        case 'u':
            hdr_udp = TRUE;
            hdr_tcp = FALSE;
            hdr_sctp = FALSE;
            hdr_data_chunk = FALSE;
            hdr_src_port = (guint32)strtol(ws_optarg, &p, 10);
            if (p == ws_optarg || (*p != ',' && *p != '\0')) {
                cmdarg_err("Bad src port for '-u'");
                print_usage(stderr);
                return INVALID_OPTION;
            }
            if (*p == '\0') {
                cmdarg_err("No dest port specified for '-u'");
                print_usage(stderr);
                return INVALID_OPTION;
            }
            p++;
            ws_optarg = p;
            hdr_dest_port = (guint32)strtol(ws_optarg, &p, 10);
            if (p == ws_optarg || *p != '\0') {
                cmdarg_err("Bad dest port for '-u'");
                print_usage(stderr);
                return INVALID_OPTION;
            }
            set_hdr_ip_proto(17);
            break;

        case 'T':
            hdr_tcp = TRUE;
            hdr_udp = FALSE;
            hdr_sctp = FALSE;
            hdr_data_chunk = FALSE;
            hdr_src_port = (guint32)strtol(ws_optarg, &p, 10);
            if (p == ws_optarg || (*p != ',' && *p != '\0')) {
                cmdarg_err("Bad src port for '-T'");
                print_usage(stderr);
                return INVALID_OPTION;
            }
            if (*p == '\0') {
                cmdarg_err("No dest port specified for '-u'");
                print_usage(stderr);
                return INVALID_OPTION;
            }
            p++;
            ws_optarg = p;
            hdr_dest_port = (guint32)strtol(ws_optarg, &p, 10);
            if (p == ws_optarg || *p != '\0') {
                cmdarg_err("Bad dest port for '-T'");
                print_usage(stderr);
                return INVALID_OPTION;
            }
            set_hdr_ip_proto(6);
            break;

        case 'a':
            identify_ascii = TRUE;
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
                return INVALID_OPTION;
            }

            *p = '\0';
            if (c == '6')
            {
                hdr_ipv6 = TRUE;
                hdr_ip   = FALSE;
            }
            else
            {
                hdr_ip   = TRUE;
                hdr_ipv6 = FALSE;
            }
            hdr_ethernet = TRUE;

            if (hdr_ipv6 == TRUE) {
                if (!ws_inet_pton6(ws_optarg, &hdr_ipv6_src_addr)) {
                        cmdarg_err("Bad src addr -%c '%s'", c, p);
                        print_usage(stderr);
                        return INVALID_OPTION;
                }
            } else {
                if (!ws_inet_pton4(ws_optarg, &hdr_ip_src_addr)) {
                        cmdarg_err("Bad src addr -%c '%s'", c, p);
                        print_usage(stderr);
                        return INVALID_OPTION;
                }
            }

            p++;
            if (*p == '\0') {
                cmdarg_err("No dest addr specified for '-%c'", c);
                print_usage(stderr);
                return INVALID_OPTION;
            }

            if (hdr_ipv6 == TRUE) {
                if (!ws_inet_pton6(p, &hdr_ipv6_dest_addr)) {
                        cmdarg_err("Bad dest addr for -%c '%s'", c, p);
                        print_usage(stderr);
                        return INVALID_OPTION;
                }
            } else {
                if (!ws_inet_pton4(p, &hdr_ip_dest_addr)) {
                        cmdarg_err("Bad dest addr for -%c '%s'", c, p);
                        print_usage(stderr);
                        return INVALID_OPTION;
                }
            }
            break;


        case '?':
        default:
            print_usage(stderr);
            return INVALID_OPTION;
        }
    }

    if (ws_optind >= argc || argc-ws_optind < 2) {
        cmdarg_err("Must specify input and output filename");
        print_usage(stderr);
        return INVALID_OPTION;
    }

    if (max_offset > WTAP_MAX_PACKET_SIZE_STANDARD) {
        cmdarg_err("Maximum packet length cannot be more than %d bytes",
                WTAP_MAX_PACKET_SIZE_STANDARD);
        return INVALID_OPTION;
    }

    /* Some validation */
    if (pcap_link_type != 1 && hdr_ethernet) {
        cmdarg_err("Dummy headers (-e, -i, -u, -s, -S -T) cannot be specified with link type override (-l)");
        return INVALID_OPTION;
    }

    if (have_hdr_ip_proto && !(hdr_ip || hdr_ipv6)) {
        /*
         * If we have an IP protocol to add to the header, but neither an
         * IPv4 nor an IPv6 header was specified,  add an IPv4 header.
         */
        hdr_ip = TRUE;
    }

    if (!have_hdr_ip_proto && (hdr_ip || hdr_ipv6)) {
        /* if -4 or -6 option is specified without an IP protocol then fail */
        cmdarg_err("IP protocol requires a next layer protocol number");
        return INVALID_OPTION;
    }

    if ((hdr_tcp || hdr_udp || hdr_sctp) && !(hdr_ip || hdr_ipv6)) {
        /*
         * If TCP (-T), UDP (-u) or SCTP (-s/-S) header options are specified
         * but none of IPv4 (-4) or IPv6 (-6) options then add an IPv4 header
         */
        hdr_ip = TRUE;
    }

    if (hdr_ip)
    {
        hdr_ethernet_proto = 0x0800;
    } else if (hdr_ipv6)
    {
        hdr_ethernet_proto = 0x86DD;
    }

    if (strcmp(argv[ws_optind], "-") != 0) {
        input_filename = argv[ws_optind];
        input_file = ws_fopen(input_filename, "rb");
        if (!input_file) {
            open_failure_message(input_filename, errno, FALSE);
            return OPEN_ERROR;
        }
    } else {
        input_filename = "Standard input";
        input_file = stdin;
    }

    wtap_dump_params_init(params, NULL);

    wtap_encap_type = wtap_pcap_encap_to_wtap_encap(pcap_link_type);
    params->encap = wtap_encap_type;
    params->snaplen = max_offset;
    if (use_pcapng) {
        params->tsprec = WTAP_TSPREC_NSEC;
        file_type_subtype = wtap_pcapng_file_type_subtype();
    } else {
        params->tsprec = WTAP_TSPREC_USEC;
        file_type_subtype = wtap_pcap_file_type_subtype();
    }
    if ((ret = write_file_header(params, file_type_subtype, interface_name)) != EXIT_SUCCESS) {
        g_free(params->idb_inf);
        wtap_dump_params_cleanup(params);
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
        g_free(params->idb_inf);
        wtap_dump_params_cleanup(params);
        return OPEN_ERROR;
    }

    info->mode = TEXT_IMPORT_HEXDUMP;
    info->import_text_filename = input_filename;
    info->output_filename = output_filename;
    info->hexdump.import_text_FILE = input_file;
    switch (offset_base) {
    case (16): info->hexdump.offset_type = OFFSET_HEX; break;
    case (10): info->hexdump.offset_type = OFFSET_DEC; break;
    case (8):  info->hexdump.offset_type = OFFSET_OCT; break;
    default:   info->hexdump.offset_type = OFFSET_HEX; break;
    }
    info->hexdump.has_direction = has_direction;
    info->timestamp_format = ts_fmt;

    info->encapsulation = wtap_encap_type;
    info->wdh = wdh;

    if (hdr_data_chunk) {
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
        info->ipv6 = TRUE;
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

#if 0
    info->payload = /* XXX Export PDU not supported by text2pcap yet */
#endif

    info->max_frame_length = max_offset;
    info->identify_ascii = identify_ascii;

    /* Display summary of our state */
    if (!quiet) {
        fprintf(stderr, "Input from: %s\n", input_filename);
        fprintf(stderr, "Output to: %s\n",  output_filename);
        fprintf(stderr, "Output format: %s\n", use_pcapng ? "pcapng" : "pcap");

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
    guint64 bytes_written;

    cmdarg_err_init(text2pcap_cmdarg_err, text2pcap_cmdarg_err_cont);

    /* Initialize log handler early so we can have proper logging during startup. */
    ws_log_init("text2pcap", vcmdarg_err);

    /* Early logging command-line initialization. */
    ws_log_parse_args(&argc, argv, vcmdarg_err, INVALID_OPTION);

#ifdef _WIN32
    create_app_running_mutex();
#endif /* _WIN32 */

    init_process_policies();
    init_report_message("text2pcap", &text2pcap_report_routines);
    wtap_init(TRUE);

    memset(&info, 0, sizeof(info));
    if ((ret = parse_options(argc, argv, &info, &params)) != EXIT_SUCCESS) {
        goto clean_exit;
    }

    assert(input_file != NULL);
    assert(wdh != NULL);

    ret = text_import(&info);

    if (debug)
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
    if (wdh) {
        int err;
        char *err_info;
        if (!wtap_dump_close(wdh, &err, &err_info)) {
            cfile_close_failure_message(output_filename, err, err_info);
            ret = 2;
        }
        g_free(params.idb_inf);
    }
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
