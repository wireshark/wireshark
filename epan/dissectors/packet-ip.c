/* packet-ip.c
 * Routines for IP and miscellaneous IP protocol packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Wednesday, January 17, 2006
 * Support for the CIPSO IPv4 option
 * (http://sourceforge.net/docman/display_doc.php?docid=34650&group_id=174379)
 * by   Paul Moore <paul.moore@hp.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/addr_resolv.h>
#include <epan/maxmind_db.h>
#include <epan/ipproto.h>
#include <epan/expert.h>
#include <epan/ip_opts.h>
#include <epan/prefs.h>
#include <epan/conversation_table.h>
#include <epan/conversation_filter.h>
#include <epan/reassemble.h>
#include <epan/etypes.h>
#include <epan/ppptypes.h>
#include <epan/llcsaps.h>
#include <epan/aftypes.h>
#include <epan/arcnet_pids.h>
#include <epan/in_cksum.h>
#include <epan/nlpid.h>
#include <epan/ax25_pids.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>
#include <epan/exported_pdu.h>

#include <wiretap/erf_record.h>
#include <wsutil/str_util.h>

#include "packet-ip.h"
#include "packet-juniper.h"
#include "packet-sflow.h"
#include "packet-gre.h"
#include "packet-l2tp.h"
#include "packet-vxlan.h"
#include "packet-mpls.h"
#include "packet-nsh.h"

void proto_register_ip(void);
void proto_reg_handoff_ip(void);

static int ip_tap = -1;

static int exported_pdu_tap = -1;

/* Decode the old IPv4 TOS field as the DiffServ DS Field (RFC2474/2475) */
static gboolean g_ip_dscp_actif = TRUE;

/* Defragment fragmented IP datagrams */
static gboolean ip_defragment = TRUE;

/* Place IP summary in proto tree */
static gboolean ip_summary_in_tree = TRUE;

/* Perform IP checksum */
static gboolean ip_check_checksum = FALSE;

/* Assume TSO and correct zero-length IP packets */
static gboolean ip_tso_supported = TRUE;

/* Use heuristics to determine subdissector */
static gboolean try_heuristic_first = FALSE;

/* Look up addresses via mmdbresolve */
static gboolean ip_use_geoip = TRUE;

/* Interpret the reserved flag as security flag (RFC 3514) */
static gboolean ip_security_flag = FALSE;

static int proto_ip = -1;

static int proto_ip_option_eol = -1;
static int proto_ip_option_nop = -1;
static int proto_ip_option_security = -1;
static int proto_ip_option_route = -1;
static int proto_ip_option_timestamp = -1;
static int proto_ip_option_ext_security = -1;
static int proto_ip_option_cipso = -1;
static int proto_ip_option_record_route = -1;
static int proto_ip_option_sid = -1;
static int proto_ip_option_source_route = -1;
static int proto_ip_option_mtu_probe = -1;
static int proto_ip_option_mtu_reply = -1;
static int proto_ip_option_traceroute = -1;
static int proto_ip_option_routeralert = -1;
static int proto_ip_option_sdb = -1;
static int proto_ip_option_qs = -1;
static int hf_ip_version = -1;
static int hf_ip_hdr_len = -1;
static int hf_ip_dsfield = -1;
static int hf_ip_dsfield_dscp = -1;
static int hf_ip_dsfield_ecn = -1;
static int hf_ip_tos = -1;
static int hf_ip_tos_precedence = -1;
static int hf_ip_tos_delay = -1;
static int hf_ip_tos_throughput = -1;
static int hf_ip_tos_reliability = -1;
static int hf_ip_tos_cost = -1;
static int hf_ip_len = -1;
static int hf_ip_id = -1;
static int hf_ip_dst = -1;
static int hf_ip_dst_host = -1;
static int hf_ip_src = -1;
static int hf_ip_src_host = -1;
static int hf_ip_addr = -1;
static int hf_ip_host = -1;
static int hf_ip_flags = -1;
static int hf_ip_flags_sf = -1;
static int hf_ip_flags_rf = -1;
static int hf_ip_flags_df = -1;
static int hf_ip_flags_mf = -1;
static int hf_ip_frag_offset = -1;
static int hf_ip_ttl = -1;
static int hf_ip_proto = -1;
static int hf_ip_checksum = -1;
static int hf_ip_checksum_calculated = -1;
static int hf_ip_checksum_status = -1;

/* IP option fields */
static int hf_ip_opt_type = -1;
static int hf_ip_opt_type_copy = -1;
static int hf_ip_opt_type_class = -1;
static int hf_ip_opt_type_number = -1;
static int hf_ip_opt_len = -1;
static int hf_ip_opt_ptr = -1;
static int hf_ip_opt_sid = -1;
static int hf_ip_opt_mtu = -1;
static int hf_ip_opt_id_number = -1;
static int hf_ip_opt_ohc = -1;
static int hf_ip_opt_rhc = -1;
static int hf_ip_opt_originator = -1;
static int hf_ip_opt_ra = -1;
static int hf_ip_opt_addr = -1;
static int hf_ip_opt_padding = -1;
static int hf_ip_opt_qs_func = -1;
static int hf_ip_opt_qs_rate = -1;
static int hf_ip_opt_qs_ttl = -1;
static int hf_ip_opt_qs_ttl_diff = -1;
static int hf_ip_opt_qs_unused = -1;
static int hf_ip_opt_qs_nonce = -1;
static int hf_ip_opt_qs_reserved = -1;
static int hf_ip_opt_sec_rfc791_sec = -1;
static int hf_ip_opt_sec_rfc791_comp = -1;
static int hf_ip_opt_sec_rfc791_hr = -1;
static int hf_ip_opt_sec_rfc791_tcc = -1;
static int hf_ip_opt_sec_cl = -1;
static int hf_ip_opt_sec_prot_auth_flags = -1;
static int hf_ip_opt_sec_prot_auth_genser = -1;
static int hf_ip_opt_sec_prot_auth_siop_esi = -1;
static int hf_ip_opt_sec_prot_auth_sci = -1;
static int hf_ip_opt_sec_prot_auth_nsa = -1;
static int hf_ip_opt_sec_prot_auth_doe = -1;
static int hf_ip_opt_sec_prot_auth_unassigned = -1;
static int hf_ip_opt_sec_prot_auth_unassigned2 = -1;
static int hf_ip_opt_sec_prot_auth_fti = -1;
static int hf_ip_opt_ext_sec_add_sec_info_format_code = -1;
static int hf_ip_opt_ext_sec_add_sec_info = -1;
static int hf_ip_rec_rt = -1;
static int hf_ip_rec_rt_host = -1;
static int hf_ip_cur_rt = -1;
static int hf_ip_cur_rt_host = -1;
static int hf_ip_src_rt = -1;
static int hf_ip_src_rt_host = -1;
static int hf_ip_empty_rt = -1;
static int hf_ip_empty_rt_host = -1;
static int hf_ip_cipso_tag_type = -1;

static int hf_ip_fragments = -1;
static int hf_ip_fragment = -1;
static int hf_ip_fragment_overlap = -1;
static int hf_ip_fragment_overlap_conflict = -1;
static int hf_ip_fragment_multiple_tails = -1;
static int hf_ip_fragment_too_long_fragment = -1;
static int hf_ip_fragment_error = -1;
static int hf_ip_fragment_count = -1;
static int hf_ip_reassembled_in = -1;
static int hf_ip_reassembled_length = -1;
static int hf_ip_reassembled_data = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_ip_opt_flag = -1;
static int hf_ip_opt_overflow = -1;
static int hf_ip_cipso_tag_data = -1;
static int hf_ip_cipso_sensitivity_level = -1;
static int hf_ip_cipso_categories = -1;
static int hf_ip_cipso_doi = -1;
static int hf_ip_opt_time_stamp = -1;
static int hf_ip_opt_time_stamp_addr = -1;

static int hf_geoip_country = -1;
static int hf_geoip_country_iso = -1;
static int hf_geoip_city = -1;
static int hf_geoip_as_number = -1;
static int hf_geoip_as_org = -1;
static int hf_geoip_latitude = -1;
static int hf_geoip_longitude = -1;
static int hf_geoip_src_summary = -1;
static int hf_geoip_src_country = -1;
static int hf_geoip_src_country_iso = -1;
static int hf_geoip_src_city = -1;
static int hf_geoip_src_as_number = -1;
static int hf_geoip_src_as_org = -1;
static int hf_geoip_src_latitude = -1;
static int hf_geoip_src_longitude = -1;
static int hf_geoip_dst_summary = -1;
static int hf_geoip_dst_country = -1;
static int hf_geoip_dst_country_iso = -1;
static int hf_geoip_dst_city = -1;
static int hf_geoip_dst_as_number = -1;
static int hf_geoip_dst_as_org = -1;
static int hf_geoip_dst_latitude = -1;
static int hf_geoip_dst_longitude = -1;

static gint ett_ip = -1;
static gint ett_ip_dsfield = -1;
static gint ett_ip_tos = -1;
static gint ett_ip_flags = -1;
static gint ett_ip_options = -1;
static gint ett_ip_option_eool = -1;
static gint ett_ip_option_nop = -1;
static gint ett_ip_option_sec = -1;
static gint ett_ip_option_route = -1;
static gint ett_ip_option_timestamp = -1;
static gint ett_ip_option_ext_security = -1;
static gint ett_ip_option_cipso = -1;
static gint ett_ip_option_sid = -1;
static gint ett_ip_option_mtu = -1;
static gint ett_ip_option_tr = -1;
static gint ett_ip_option_ra = -1;
static gint ett_ip_option_sdb = -1;
static gint ett_ip_option_qs = -1;
static gint ett_ip_option_other = -1;
static gint ett_ip_fragments = -1;
static gint ett_ip_fragment  = -1;
static gint ett_ip_opt_type = -1;
static gint ett_ip_opt_sec_prot_auth_flags = -1;
static gint ett_ip_unknown_opt = -1;

static expert_field ei_ip_opt_len_invalid = EI_INIT;
static expert_field ei_ip_opt_sec_prot_auth_fti = EI_INIT;
static expert_field ei_ip_extraneous_data = EI_INIT;
static expert_field ei_ip_opt_ptr_before_address = EI_INIT;
static expert_field ei_ip_opt_ptr_middle_address = EI_INIT;
static expert_field ei_ip_subopt_too_long = EI_INIT;
static expert_field ei_ip_nop = EI_INIT;
static expert_field ei_ip_bogus_ip_length = EI_INIT;
static expert_field ei_ip_evil_packet = EI_INIT;
static expert_field ei_ip_checksum_bad = EI_INIT;
static expert_field ei_ip_ttl_lncb = EI_INIT;
static expert_field ei_ip_ttl_too_small = EI_INIT;
static expert_field ei_ip_cipso_tag = EI_INIT;
static expert_field ei_ip_bogus_ip_version = EI_INIT;
static expert_field ei_ip_bogus_header_length = EI_INIT;

static dissector_handle_t ip_handle;
static dissector_table_t ip_option_table;

static gint ett_geoip_info = -1;

static const fragment_items ip_frag_items = {
  &ett_ip_fragment,
  &ett_ip_fragments,
  &hf_ip_fragments,
  &hf_ip_fragment,
  &hf_ip_fragment_overlap,
  &hf_ip_fragment_overlap_conflict,
  &hf_ip_fragment_multiple_tails,
  &hf_ip_fragment_too_long_fragment,
  &hf_ip_fragment_error,
  &hf_ip_fragment_count,
  &hf_ip_reassembled_in,
  &hf_ip_reassembled_length,
  &hf_ip_reassembled_data,
  "IPv4 fragments"
};

static heur_dissector_list_t heur_subdissector_list;

static dissector_table_t ip_dissector_table;

static dissector_handle_t ipv6_handle;
static capture_dissector_handle_t ip_cap_handle;


/* IP structs and definitions */

const value_string ip_version_vals[] = {
  { IP_VERSION_NUM_RESERVED,       "Reserved" },
  { IP_VERSION_NUM_INET,           "IPv4" },
  { IP_VERSION_NUM_ST,             "ST Datagram" },
  { IP_VERSION_NUM_INET6,          "IPv6" },
  { IP_VERSION_NUM_TPIX,           "TP/IX" },
  { IP_VERSION_NUM_PIP,            "PIP" },
  { IP_VERSION_NUM_TUBA,           "TUBA" },
  { 0, NULL },
};

/* Offsets of fields within an IP header. */
#define IPH_V_HL                0
#define IPH_TOS                 1
#define IPH_LEN                 2
#define IPH_ID                  4
#define IPH_TTL                 6
#define IPH_OFF                 8
#define IPH_P                   9
#define IPH_SUM                 10
#define IPH_SRC                 12
#define IPH_DST                 16

/* Minimum IP header length. */
#define IPH_MIN_LEN             20

/* IP flags. */
#define IP_RF                   0x8000      /* Flag: "Reserved bit"     */
#define IP_DF                   0x4000      /* Flag: "Don't Fragment"   */
#define IP_MF                   0x2000      /* Flag: "More Fragments"   */
#define IP_OFFSET               0x1FFF      /* "Fragment Offset" part   */

/* Differentiated Services Field. See RFCs 2474, 2597, 2598 and 3168. */
#define IPDSFIELD_DSCP_DEFAULT  0x00
#define IPDSFIELD_DSCP_LE       0x01
#define IPDSFIELD_DSCP_CS1      0x08
#define IPDSFIELD_DSCP_AF11     0x0A
#define IPDSFIELD_DSCP_AF12     0x0C
#define IPDSFIELD_DSCP_AF13     0x0E
#define IPDSFIELD_DSCP_CS2      0x10
#define IPDSFIELD_DSCP_AF21     0x12
#define IPDSFIELD_DSCP_AF22     0x14
#define IPDSFIELD_DSCP_AF23     0x16
#define IPDSFIELD_DSCP_CS3      0x18
#define IPDSFIELD_DSCP_AF31     0x1A
#define IPDSFIELD_DSCP_AF32     0x1C
#define IPDSFIELD_DSCP_AF33     0x1E
#define IPDSFIELD_DSCP_CS4      0x20
#define IPDSFIELD_DSCP_AF41     0x22
#define IPDSFIELD_DSCP_AF42     0x24
#define IPDSFIELD_DSCP_AF43     0x26
#define IPDSFIELD_DSCP_CS5      0x28
#define IPDSFIELD_DSCP_EF       0x2E
#define IPDSFIELD_DSCP_CS6      0x30
#define IPDSFIELD_DSCP_CS7      0x38

#define IPDSFIELD_ECT_NOT       0x00
#define IPDSFIELD_ECT_1         0x01
#define IPDSFIELD_ECT_0         0x02
#define IPDSFIELD_CE            0x03

/* IP TOS, superseded by the DS Field, RFC 2474. */
#define IPTOS_TOS_MASK          0x1E
#define IPTOS_TOS(tos)          ((tos) & IPTOS_TOS_MASK)
#define IPTOS_NONE              0x00
#define IPTOS_LOWCOST           0x02
#define IPTOS_RELIABILITY       0x04
#define IPTOS_THROUGHPUT        0x08
#define IPTOS_LOWDELAY          0x10
#define IPTOS_SECURITY          0x1E

#define IPTOS_PREC_MASK             0xE0
#define IPTOS_PREC_SHIFT            5
#define IPTOS_PREC(tos)             (((tos)&IPTOS_PREC_MASK)>>IPTOS_PREC_SHIFT)
#define IPTOS_PREC_NETCONTROL       7
#define IPTOS_PREC_INTERNETCONTROL  6
#define IPTOS_PREC_CRITIC_ECP       5
#define IPTOS_PREC_FLASHOVERRIDE    4
#define IPTOS_PREC_FLASH            3
#define IPTOS_PREC_IMMEDIATE        2
#define IPTOS_PREC_PRIORITY         1
#define IPTOS_PREC_ROUTINE          0

/* IP options */
#define IPOPT_COPY              0x80

#define IPOPT_CONTROL           0x00
#define IPOPT_RESERVED1         0x20
#define IPOPT_MEASUREMENT       0x40
#define IPOPT_RESERVED2         0x60

/* REF: http://www.iana.org/assignments/ip-parameters */
/* TODO: Not all of these are implemented. */
#define IPOPT_EOOL      (0 |IPOPT_CONTROL)
#define IPOPT_NOP       (1 |IPOPT_CONTROL)
#define IPOPT_SEC       (2 |IPOPT_COPY|IPOPT_CONTROL)       /* RFC 791/1108 */
#define IPOPT_LSR       (3 |IPOPT_COPY|IPOPT_CONTROL)
#define IPOPT_TS        (4 |IPOPT_MEASUREMENT)
#define IPOPT_ESEC      (5 |IPOPT_COPY|IPOPT_CONTROL)       /* RFC 1108 */
#define IPOPT_CIPSO     (6 |IPOPT_COPY|IPOPT_CONTROL)       /* draft-ietf-cipso-ipsecurity-01 */
#define IPOPT_RR        (7 |IPOPT_CONTROL)
#define IPOPT_SID       (8 |IPOPT_COPY|IPOPT_CONTROL)
#define IPOPT_SSR       (9 |IPOPT_COPY|IPOPT_CONTROL)
#define IPOPT_ZSU       (10|IPOPT_CONTROL)                  /* Zsu */
#define IPOPT_MTUP      (11|IPOPT_CONTROL)                  /* RFC 1063 */
#define IPOPT_MTUR      (12|IPOPT_CONTROL)                  /* RFC 1063 */
#define IPOPT_FINN      (13|IPOPT_COPY|IPOPT_MEASUREMENT)   /* Finn */
#define IPOPT_VISA      (14|IPOPT_COPY|IPOPT_CONTROL)       /* Estrin */
#define IPOPT_ENCODE    (15|IPOPT_CONTROL)                  /* VerSteeg */
#define IPOPT_IMITD     (16|IPOPT_COPY|IPOPT_CONTROL)       /* Lee */
#define IPOPT_EIP       (17|IPOPT_COPY|IPOPT_CONTROL)       /* RFC 1385 */
#define IPOPT_TR        (18|IPOPT_MEASUREMENT)              /* RFC 1393 */
#define IPOPT_ADDEXT    (19|IPOPT_COPY|IPOPT_CONTROL)       /* Ullmann IPv7 */
#define IPOPT_RTRALT    (20|IPOPT_COPY|IPOPT_CONTROL)       /* RFC 2113 */
#define IPOPT_SDB       (21|IPOPT_COPY|IPOPT_CONTROL)       /* RFC 1770 Graff */
#define IPOPT_UN        (22|IPOPT_COPY|IPOPT_CONTROL)       /* Released 18-Oct-2005 */
#define IPOPT_DPS       (23|IPOPT_COPY|IPOPT_CONTROL)       /* Malis */
#define IPOPT_UMP       (24|IPOPT_COPY|IPOPT_CONTROL)       /* Farinacci */
#define IPOPT_QS        (25|IPOPT_CONTROL)                  /* RFC 4782 */
#define IPOPT_EXP       (30|IPOPT_CONTROL)                  /* RFC 4727 */


/* IP option lengths */
#define IPOLEN_SEC_MIN          3
#define IPOLEN_LSR_MIN          3
#define IPOLEN_TS_MIN           4
#define IPOLEN_ESEC_MIN         3
#define IPOLEN_CIPSO_MIN        10
#define IPOLEN_RR_MIN           3
#define IPOLEN_SID              4
#define IPOLEN_SSR_MIN          3
#define IPOLEN_MTU              4
#define IPOLEN_TR               12
#define IPOLEN_RA               4
#define IPOLEN_SDB_MIN          6
#define IPOLEN_QS               8
#define IPOLEN_MAX              40

#define IPSEC_RFC791_UNCLASSIFIED 0x0000
#define IPSEC_RFC791_CONFIDENTIAL 0xF135
#define IPSEC_RFC791_EFTO         0x789A
#define IPSEC_RFC791_MMMM         0xBC4D
#define IPSEC_RFC791_PROG         0x5E26
#define IPSEC_RFC791_RESTRICTED   0xAF13
#define IPSEC_RFC791_SECRET       0xD788
#define IPSEC_RFC791_TOPSECRET    0x6BC5
#define IPSEC_RFC791_RESERVED1    0x35E2
#define IPSEC_RFC791_RESERVED2    0x9AF1
#define IPSEC_RFC791_RESERVED3    0x4D78
#define IPSEC_RFC791_RESERVED4    0x24BD
#define IPSEC_RFC791_RESERVED5    0x135E
#define IPSEC_RFC791_RESERVED6    0x89AF
#define IPSEC_RFC791_RESERVED7    0xC4D6
#define IPSEC_RFC791_RESERVED8    0xE26B

#define IPSEC_RESERVED4         0x01
#define IPSEC_TOPSECRET         0x3D
#define IPSEC_SECRET            0x5A
#define IPSEC_CONFIDENTIAL      0x96
#define IPSEC_RESERVED3         0x66
#define IPSEC_RESERVED2         0xCC
#define IPSEC_UNCLASSIFIED      0xAB
#define IPSEC_RESERVED1         0xF1

#define IPOPT_TS_TSONLY         0       /* timestamps only */
#define IPOPT_TS_TSANDADDR      1       /* timestamps and addresses */
#define IPOPT_TS_PRESPEC        3       /* specified modules only */

#define IPLOCAL_NETWRK_CTRL_BLK_VRRP_ADDR       0xE0000012
#define IPLOCAL_NETWRK_CTRL_BLK_VRRP_TTL        0xFF
#define IPLOCAL_NETWRK_CTRL_BLK_GLPB_ADDR       0xE0000066
#define IPLOCAL_NETWRK_CTRL_BLK_GLPB_TTL        0XFF
#define IPLOCAL_NETWRK_CTRL_BLK_MDNS_ADDR       0xE00000FB
#define IPLOCAL_NETWRK_CTRL_BLK_MDNS_TTL        0XFF
#define IPLOCAL_NETWRK_CTRL_BLK_LLMNR_ADDR      0xE00000FC

#define IPLOCAL_NETWRK_CTRL_BLK_ANY_TTL         0x1000 /* larger than max ttl */
#define IPLOCAL_NETWRK_CTRL_BLK_DEFAULT_TTL     0X01

static void ip_prompt(packet_info *pinfo, gchar* result)
{
    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "IP protocol %u as",
        GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_ip, pinfo->curr_layer_num)));
}

static gpointer ip_value(packet_info *pinfo)
{
    return p_get_proto_data(pinfo->pool, pinfo, proto_ip, pinfo->curr_layer_num);
}

static const char* ip_conv_get_filter_type(conv_item_t* conv, conv_filter_type_e filter)
{
    if ((filter == CONV_FT_SRC_ADDRESS) && (conv->src_address.type == AT_IPv4))
        return "ip.src";

    if ((filter == CONV_FT_DST_ADDRESS) && (conv->dst_address.type == AT_IPv4))
        return "ip.dst";

    if ((filter == CONV_FT_ANY_ADDRESS) && (conv->src_address.type == AT_IPv4))
        return "ip.addr";

    return CONV_FILTER_INVALID;
}

static ct_dissector_info_t ip_ct_dissector_info = {&ip_conv_get_filter_type};

static tap_packet_status
ip_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
    conv_hash_t *hash = (conv_hash_t*) pct;
    hash->flags = flags;
    const ws_ip4 *iph=(const ws_ip4 *)vip;

    add_conversation_table_data(hash, &iph->ip_src, &iph->ip_dst, 0, 0, 1, pinfo->fd->pkt_len, &pinfo->rel_ts, &pinfo->abs_ts, &ip_ct_dissector_info, CONVERSATION_NONE);

    return TAP_PACKET_REDRAW;
}

static const char* ip_endpoint_get_filter_type(endpoint_item_t* endpoint, conv_filter_type_e filter)
{
    if ((filter == CONV_FT_ANY_ADDRESS) && (endpoint->myaddress.type == AT_IPv4))
        return "ip.addr";

    return CONV_FILTER_INVALID;
}

static et_dissector_info_t ip_endpoint_dissector_info = {&ip_endpoint_get_filter_type};

static tap_packet_status
ip_endpoint_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
    conv_hash_t *hash = (conv_hash_t*) pit;
    hash->flags = flags;
    const ws_ip4 *iph=(const ws_ip4 *)vip;

    /* Take two "add" passes per packet, adding for each direction, ensures that all
    packets are counted properly (even if address is sending to itself)
    XXX - this could probably be done more efficiently inside endpoint_table */
    add_endpoint_table_data(hash, &iph->ip_src, 0, TRUE, 1, pinfo->fd->pkt_len, &ip_endpoint_dissector_info, ENDPOINT_NONE);
    add_endpoint_table_data(hash, &iph->ip_dst, 0, FALSE, 1, pinfo->fd->pkt_len, &ip_endpoint_dissector_info, ENDPOINT_NONE);
    return TAP_PACKET_REDRAW;
}

static gboolean
ip_filter_valid(packet_info *pinfo)
{
    return proto_is_frame_protocol(pinfo->layers, "ip");
}

static gchar*
ip_build_filter(packet_info *pinfo)
{
    return ws_strdup_printf("ip.addr eq %s and ip.addr eq %s",
                address_to_str(pinfo->pool, &pinfo->net_src),
                address_to_str(pinfo->pool, &pinfo->net_dst));
}

/*
 * defragmentation of IPv4
 */
static reassembly_table ip_reassembly_table;

static gboolean
capture_ip(const guchar *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_) {
  if (!BYTES_ARE_IN_FRAME(offset, len, IPH_MIN_LEN))
    return FALSE;

  capture_dissector_increment_count(cpinfo, proto_ip);
  return try_capture_dissector("ip.proto", pd[offset + 9], pd, offset+IPH_MIN_LEN, len, cpinfo, pseudo_header);
}

static void
add_geoip_info_entry(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, gint offset, ws_in4_addr ip, int isdst)
{
  const mmdb_lookup_t *lookup = maxmind_db_lookup_ipv4(&ip);
  if (!lookup->found) return;

  wmem_strbuf_t *summary = wmem_strbuf_new(pinfo->pool, "");
  if (lookup->city) {
    wmem_strbuf_append(summary, lookup->city);
  }
  if (lookup->country_iso) {
    if (wmem_strbuf_get_len(summary) > 0) wmem_strbuf_append(summary, ", ");
    wmem_strbuf_append(summary, lookup->country_iso);
  } else if (lookup->country) {
    if (wmem_strbuf_get_len(summary) > 0) wmem_strbuf_append(summary, ", ");
    wmem_strbuf_append(summary, lookup->country);
  }
  if (lookup->as_number > 0) {
    if (wmem_strbuf_get_len(summary) > 0) wmem_strbuf_append(summary, ", ");
    wmem_strbuf_append_printf(summary, "ASN %u", lookup->as_number);
  }
  if (lookup->as_org) {
    if (wmem_strbuf_get_len(summary) > 0) wmem_strbuf_append(summary, ", ");
    wmem_strbuf_append(summary, lookup->as_org);
  }

  int addr_offset = offset + isdst ? IPH_DST : IPH_SRC;
  int dir_hf = isdst ? hf_geoip_dst_summary : hf_geoip_src_summary;
  proto_item *geoip_info_item = proto_tree_add_string(tree, dir_hf, tvb, addr_offset, 4, wmem_strbuf_finalize(summary));
  proto_item_set_generated(geoip_info_item);
  proto_tree *geoip_info_tree = proto_item_add_subtree(geoip_info_item, ett_geoip_info);

  proto_item *item;

  if (lookup->city) {
    dir_hf = isdst ? hf_geoip_dst_city : hf_geoip_src_city;
    item = proto_tree_add_string(geoip_info_tree, dir_hf, tvb, addr_offset, 4, lookup->city);
    proto_item_set_generated(item);
    item = proto_tree_add_string(geoip_info_tree, hf_geoip_city, tvb, addr_offset, 4, lookup->city);
    proto_item_set_generated(item);
  }

  if (lookup->country) {
    dir_hf = isdst ? hf_geoip_dst_country : hf_geoip_src_country;
    item = proto_tree_add_string(geoip_info_tree, dir_hf, tvb, addr_offset, 4, lookup->country);
    proto_item_set_generated(item);
    item = proto_tree_add_string(geoip_info_tree, hf_geoip_country, tvb, addr_offset, 4, lookup->country);
    proto_item_set_generated(item);
  }

  if (lookup->country_iso) {
    dir_hf = isdst ? hf_geoip_dst_country_iso : hf_geoip_src_country_iso;
    item = proto_tree_add_string(geoip_info_tree, dir_hf, tvb, addr_offset, 4, lookup->country_iso);
    proto_item_set_generated(item);
    item = proto_tree_add_string(geoip_info_tree, hf_geoip_country_iso, tvb, addr_offset, 4, lookup->country_iso);
    proto_item_set_generated(item);
  }

  if (lookup->as_number > 0) {
    dir_hf = isdst ? hf_geoip_dst_as_number : hf_geoip_src_as_number;
    item = proto_tree_add_uint(geoip_info_tree, dir_hf, tvb, addr_offset, 4, lookup->as_number);
    proto_item_set_generated(item);
    item = proto_tree_add_uint(geoip_info_tree, hf_geoip_as_number, tvb, addr_offset, 4, lookup->as_number);
    proto_item_set_generated(item);
  }

  if (lookup->as_org) {
    dir_hf = isdst ? hf_geoip_dst_as_org : hf_geoip_src_as_org;
    item = proto_tree_add_string(geoip_info_tree, dir_hf, tvb, addr_offset, 4, lookup->as_org);
    proto_item_set_generated(item);
    item = proto_tree_add_string(geoip_info_tree, hf_geoip_as_org, tvb, addr_offset, 4, lookup->as_org);
    proto_item_set_generated(item);
  }

  if (lookup->latitude >= -90.0 && lookup->latitude <= 90.0) {
    dir_hf = isdst ? hf_geoip_dst_latitude : hf_geoip_src_latitude;
    item = proto_tree_add_double(geoip_info_tree, dir_hf, tvb, addr_offset, 4, lookup->latitude);
    proto_item_set_generated(item);
    item = proto_tree_add_double(geoip_info_tree, hf_geoip_latitude, tvb, addr_offset, 4, lookup->latitude);
    proto_item_set_generated(item);
  }

  if (lookup->longitude >= -180.0 && lookup->longitude <= 180.0) {
    dir_hf = isdst ? hf_geoip_dst_longitude : hf_geoip_src_longitude;
    item = proto_tree_add_double(geoip_info_tree, dir_hf, tvb, addr_offset, 4, lookup->longitude);
    proto_item_set_generated(item);
    item = proto_tree_add_double(geoip_info_tree, hf_geoip_longitude, tvb, addr_offset, 4, lookup->longitude);
    proto_item_set_generated(item);
  }
}

static void
add_geoip_info(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, gint offset, guint32 src32,
               guint32 dst32)
{
  add_geoip_info_entry(tree, pinfo, tvb, offset, g_htonl(src32), FALSE);
  add_geoip_info_entry(tree, pinfo, tvb, offset, g_htonl(dst32), TRUE);
}

const value_string ipopt_type_class_vals[] = {
  {(IPOPT_CONTROL & IPOPT_CLASS_MASK) >> 5, "Control"},
  {(IPOPT_RESERVED1 & IPOPT_CLASS_MASK) >> 5, "Reserved for future use"},
  {(IPOPT_MEASUREMENT & IPOPT_CLASS_MASK) >> 5, "Debugging and measurement"},
  {(IPOPT_RESERVED2 & IPOPT_CLASS_MASK) >> 5, "Reserved for future use"},
  {0, NULL}
};

const value_string ipopt_type_number_vals[] = {
  {IPOPT_EOOL & IPOPT_NUMBER_MASK, "End of Option List (EOL)"},
  {IPOPT_NOP & IPOPT_NUMBER_MASK, "No-Operation (NOP)"},
  {IPOPT_SEC & IPOPT_NUMBER_MASK, "Security"},
  {IPOPT_LSR & IPOPT_NUMBER_MASK, "Loose source route"},
  {IPOPT_TS & IPOPT_NUMBER_MASK, "Time stamp"},
  {IPOPT_ESEC & IPOPT_NUMBER_MASK, "Extended security"},
  {IPOPT_CIPSO & IPOPT_NUMBER_MASK, "Commercial IP security option"},
  {IPOPT_RR & IPOPT_NUMBER_MASK, "Record route"},
  {IPOPT_SID & IPOPT_NUMBER_MASK, "Stream identifier"},
  {IPOPT_SSR & IPOPT_NUMBER_MASK, "Strict source route"},
  {IPOPT_ZSU & IPOPT_NUMBER_MASK, "Experimental Measurement"},
  {IPOPT_MTUP & IPOPT_NUMBER_MASK, "MTU probe"},
  {IPOPT_MTUR & IPOPT_NUMBER_MASK, "MTU Reply"},
  {IPOPT_FINN & IPOPT_NUMBER_MASK, "Experimental Flow Control"},
  {IPOPT_VISA & IPOPT_NUMBER_MASK, "Experimental Access Control"},
  {IPOPT_ENCODE & IPOPT_NUMBER_MASK, "Ask Estrin"},
  {IPOPT_IMITD & IPOPT_NUMBER_MASK, "IMI Traffic Descriptor"},
  {IPOPT_EIP & IPOPT_NUMBER_MASK, "Extended Internet Protocol"},
  {IPOPT_TR & IPOPT_NUMBER_MASK, "Traceroute"},
  {IPOPT_ADDEXT & IPOPT_NUMBER_MASK, "Address Extension"},
  {IPOPT_RTRALT & IPOPT_NUMBER_MASK, "Router Alert"},
  {IPOPT_SDB & IPOPT_NUMBER_MASK, "Selective Directed Broadcast"},
  {IPOPT_UN & IPOPT_NUMBER_MASK, "Unassigned"},
  {IPOPT_DPS & IPOPT_NUMBER_MASK, "Dynamic Packet State"},
  {IPOPT_UMP & IPOPT_NUMBER_MASK, "Upstream Multicast Packet"},
  {IPOPT_QS & IPOPT_NUMBER_MASK, "Quick-Start"},
  {IPOPT_EXP & IPOPT_NUMBER_MASK, "RFC 3692-style experiment"},
  {0, NULL}
};

static void
dissect_ipopt_type(tvbuff_t *tvb, int offset, proto_tree *tree)
{
  proto_tree *type_tree;
  proto_item *ti;

  ti = proto_tree_add_item(tree, hf_ip_opt_type, tvb, offset, 1, ENC_NA);
  type_tree = proto_item_add_subtree(ti, ett_ip_opt_type);
  proto_tree_add_item(type_tree, hf_ip_opt_type_copy, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(type_tree, hf_ip_opt_type_class, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(type_tree, hf_ip_opt_type_number, tvb, offset, 1, ENC_NA);
}

static proto_tree*
ip_fixed_option_header(proto_tree* tree, packet_info *pinfo, tvbuff_t *tvb, int proto, int ett, proto_item** ti, guint len, guint optlen)
{
  proto_tree *field_tree;
  proto_item *tf;

  *ti = proto_tree_add_item(tree, proto, tvb, 0, optlen, ENC_NA);
  field_tree = proto_item_add_subtree(*ti, ett);
  proto_item_append_text(*ti, " (%u bytes)", len);

  dissect_ipopt_type(tvb, 0, field_tree);
  tf = proto_tree_add_item(field_tree, hf_ip_opt_len, tvb, 1, 1, ENC_NA);

  if (len != optlen) {
    /* Bogus - option length isn't what it's supposed to be for this option. */
    expert_add_info_format(pinfo, tf, &ei_ip_opt_len_invalid,
                            "%s (with option length = %u byte%s; should be %u)",
                            proto_get_protocol_short_name(find_protocol_by_id(proto)),
                            optlen, plurality(optlen, "", "s"), len);
  }

  return field_tree;
}

static proto_tree*
ip_var_option_header(proto_tree* tree, packet_info *pinfo, tvbuff_t *tvb, int proto, int ett, proto_item** ti, guint optlen)
{
  proto_tree *field_tree;
  proto_item *tf;

  *ti = proto_tree_add_item(tree, proto, tvb, 0, optlen, ENC_NA);
  field_tree = proto_item_add_subtree(*ti, ett);
  proto_item_append_text(*ti, " (%u bytes)", optlen);

  dissect_ipopt_type(tvb, 0, field_tree);
  tf = proto_tree_add_item(field_tree, hf_ip_opt_len, tvb, 1, 1, ENC_NA);
  if (optlen > IPOLEN_MAX)
    expert_add_info(pinfo, tf, &ei_ip_opt_len_invalid);

  return field_tree;
}

static const value_string secl_rfc791_vals[] = {
  {IPSEC_RFC791_UNCLASSIFIED, "Unclassified"},
  {IPSEC_RFC791_CONFIDENTIAL, "Confidential"},
  {IPSEC_RFC791_EFTO,         "EFTO"        },
  {IPSEC_RFC791_MMMM,         "MMMM"        },
  {IPSEC_RFC791_PROG,         "PROG"        },
  {IPSEC_RFC791_RESTRICTED,   "Restricted"  },
  {IPSEC_RFC791_SECRET,       "Secret"      },
  {IPSEC_RFC791_TOPSECRET,    "Top secret"  },
  {IPSEC_RFC791_RESERVED1,    "Reserved"    },
  {IPSEC_RFC791_RESERVED2,    "Reserved"    },
  {IPSEC_RFC791_RESERVED3,    "Reserved"    },
  {IPSEC_RFC791_RESERVED4,    "Reserved"    },
  {IPSEC_RFC791_RESERVED5,    "Reserved"    },
  {IPSEC_RFC791_RESERVED6,    "Reserved"    },
  {IPSEC_RFC791_RESERVED7,    "Reserved"    },
  {IPSEC_RFC791_RESERVED8,    "Reserved"    },
  {0,                  NULL          }
};

static const value_string sec_cl_vals[] = {
  {IPSEC_RESERVED4,    "Reserved 4"  },
  {IPSEC_TOPSECRET,    "Top secret"  },
  {IPSEC_SECRET,       "Secret"      },
  {IPSEC_CONFIDENTIAL, "Confidential"},
  {IPSEC_RESERVED3,    "Reserved 3"  },
  {IPSEC_RESERVED2,    "Reserved 2"  },
  {IPSEC_UNCLASSIFIED, "Unclassified"},
  {IPSEC_RESERVED1,    "Reserved 1"  },
  {0,                  NULL          }
};

static const true_false_string ip_opt_sec_prot_auth_flag_tfs = {
  "Datagram protected in accordance with its rules",
  "Datagram not protected in accordance with its rules"
};

static const true_false_string ip_opt_sec_prot_auth_fti_tfs = {
  "Additional octet present",
  "Final octet"
};

static int * const ip_opt_sec_prot_auth_fields_byte_1[] = {
  &hf_ip_opt_sec_prot_auth_genser,
  &hf_ip_opt_sec_prot_auth_siop_esi,
  &hf_ip_opt_sec_prot_auth_sci,
  &hf_ip_opt_sec_prot_auth_nsa,
  &hf_ip_opt_sec_prot_auth_doe,
  &hf_ip_opt_sec_prot_auth_unassigned,
  &hf_ip_opt_sec_prot_auth_fti,
  NULL
};

static int * const ip_opt_sec_prot_auth_fields_byte_n[] = {
  &hf_ip_opt_sec_prot_auth_unassigned2,
  &hf_ip_opt_sec_prot_auth_fti,
  NULL
};
static int
dissect_ipopt_security(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
  proto_tree *field_tree;
  proto_item *tf;
  guint      val;
  guint      curr_offset = 2;
  guint      optlen = tvb_reported_length(tvb);

  field_tree = ip_var_option_header(tree, pinfo, tvb, proto_ip_option_security, ett_ip_option_sec, &tf, optlen);

  if (optlen == 11) {
  /* Analyze payload start to decide whether it should be dissected
     according to RFC 791 or RFC 1108 */
    val = tvb_get_ntohs(tvb, curr_offset);
    if (try_val_to_str(val, secl_rfc791_vals)) {
      /* Dissect as RFC 791 */
      proto_tree_add_item(field_tree, hf_ip_opt_sec_rfc791_sec,
                          tvb, curr_offset, 2, ENC_BIG_ENDIAN);
      curr_offset += 2;
      proto_tree_add_item(field_tree, hf_ip_opt_sec_rfc791_comp,
                          tvb, curr_offset, 2, ENC_BIG_ENDIAN);
      curr_offset += 2;
      proto_tree_add_item(field_tree, hf_ip_opt_sec_rfc791_hr,
                          tvb, curr_offset, 2, ENC_ASCII);
      curr_offset += 2;
      proto_tree_add_item(field_tree, hf_ip_opt_sec_rfc791_tcc,
                          tvb, curr_offset, 3, ENC_ASCII);
      return curr_offset;
    }
  }

  /* Dissect as RFC 108 */
  proto_tree_add_item(field_tree, hf_ip_opt_sec_cl, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
  curr_offset++;
  if (curr_offset >= optlen) {
    return curr_offset;
  }
  val = tvb_get_guint8(tvb, curr_offset);
  proto_tree_add_bitmask(field_tree, tvb, curr_offset, hf_ip_opt_sec_prot_auth_flags,
                         ett_ip_opt_sec_prot_auth_flags, ip_opt_sec_prot_auth_fields_byte_1,
                         ENC_BIG_ENDIAN);
  curr_offset++;
  while (val & 0x01) {
    if ((val & 0x01) && (curr_offset == optlen)) {
      expert_add_info(pinfo, tf, &ei_ip_opt_sec_prot_auth_fti);
      break;
    }
    val = tvb_get_guint8(tvb, curr_offset);
    proto_tree_add_bitmask(field_tree, tvb, curr_offset, hf_ip_opt_sec_prot_auth_flags,
                           ett_ip_opt_sec_prot_auth_flags, ip_opt_sec_prot_auth_fields_byte_n,
                           ENC_BIG_ENDIAN);
    curr_offset++;
  }
  if (curr_offset < optlen) {
    expert_add_info(pinfo, tf, &ei_ip_extraneous_data);
  }

  return curr_offset;
}

static int
dissect_ipopt_ext_security(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
  proto_tree *field_tree;
  proto_item *tf;
  guint      curr_offset = 2;
  gint      remaining;
  gint      optlen = tvb_reported_length(tvb);

  field_tree = ip_var_option_header(tree, pinfo, tvb, proto_ip_option_ext_security, ett_ip_option_ext_security, &tf, optlen);

  proto_tree_add_item(field_tree, hf_ip_opt_ext_sec_add_sec_info_format_code, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
  curr_offset++;
  remaining = optlen - curr_offset;
  if (remaining > 0) {
    proto_tree_add_item(field_tree, hf_ip_opt_ext_sec_add_sec_info, tvb, curr_offset, remaining, ENC_NA);
  }

  return tvb_captured_length(tvb);
}

/* USHRT_MAX can hold at most 5 (base 10) digits (6 for the NULL byte) */
#define USHRT_MAX_STRLEN    6

/* Maximum CIPSO tag length:
 * (IP hdr max)60 - (IPv4 hdr std)20 - (CIPSO base)6 = 34 */
#define CIPSO_TAG_LEN_MAX   34

/* The Commercial IP Security Option (CIPSO) is defined in IETF draft
 * draft-ietf-cipso-ipsecurity-01.txt and FIPS 188, a copy of both documents
 * can be found at the NetLabel project page, http://netlabel.sf.net or at
 * https://tools.ietf.org/html/draft-ietf-cipso-ipsecurity-01 */
static const value_string cipso_tag_type_vals[] = {
   {0,   "Padding"},
   {1,   "Restrictive Category Bitmap"},
   {2,   "Enumerated Categories"},
   {5,   "Ranged Categories"},
   {6,   "Permissive Categories"},
   {7,   "Free Form"},

   { 0,                          NULL }
};

static int
dissect_ipopt_cipso(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
  proto_tree *field_tree;
  proto_item *tf, *tag_item;
  guint      tagtype, taglen;
  gint       offset = 2,
             optlen = tvb_reported_length(tvb);
  int        offset_max = optlen;

  field_tree = ip_var_option_header(tree, pinfo, tvb, proto_ip_option_cipso, ett_ip_option_cipso, &tf, optlen);

  proto_tree_add_item(field_tree, hf_ip_cipso_doi, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  /* loop through all of the tags in the CIPSO option */
  while (offset < offset_max) {
    tagtype = tvb_get_guint8(tvb, offset);
    tag_item = proto_tree_add_item(field_tree, hf_ip_cipso_tag_type, tvb, offset, 1, ENC_NA);

    if ((offset + 1) < offset_max)
      taglen = tvb_get_guint8(tvb, offset + 1);
    else
      taglen = 1;

    switch (tagtype) {
    case 0:
      /* padding - skip this tag */
      offset += 1;
      continue;
    case 1:
      /* restrictive bitmap, see CIPSO draft section 3.4.2 for tag format */
      if ((taglen < 4) || (taglen > CIPSO_TAG_LEN_MAX) ||
         ((offset + (int)taglen - 1) > offset_max)) {
        expert_add_info(pinfo, tag_item, &ei_ip_cipso_tag);
        return offset;
      }

      /* skip past alignment octet */
      offset += 3;

      proto_tree_add_item(field_tree, hf_ip_cipso_sensitivity_level, tvb, offset, 1, ENC_NA);
      offset += 1;

      if (taglen > 4) {
        guint bit_spot = 0;
        guint byte_spot = 0;
        unsigned char bitmask;
        char *cat_str;
        char *cat_str_tmp = (char *)wmem_alloc(pinfo->pool, USHRT_MAX_STRLEN);
        size_t cat_str_len;
        const guint8 *val_ptr = tvb_get_ptr(tvb, offset, taglen - 4);

        /* this is just a guess regarding string size, but we grow it below
         * if needed */
        cat_str_len = 256;
        cat_str = (char *)wmem_alloc0(pinfo->pool, cat_str_len);

        /* we checked the length above so the highest category value
         * possible here is 240 */
        while (byte_spot < (taglen - 4)) {
          bitmask = 0x80;
          bit_spot = 0;
          while (bit_spot < 8) {
            if (val_ptr[byte_spot] & bitmask) {
              snprintf(cat_str_tmp, USHRT_MAX_STRLEN, "%u",
                         byte_spot * 8 + bit_spot);
              if (cat_str_len < (strlen(cat_str) + 2 + USHRT_MAX_STRLEN)) {
                char *cat_str_new;

                while (cat_str_len < (strlen(cat_str) + 2 + USHRT_MAX_STRLEN))
                  cat_str_len += cat_str_len;
                cat_str_new = (char *)wmem_alloc(pinfo->pool, cat_str_len);
                (void) g_strlcpy(cat_str_new, cat_str, cat_str_len);
                cat_str_new[cat_str_len - 1] = '\0';
                cat_str = cat_str_new;
              }
              if (cat_str[0] != '\0')
                (void) g_strlcat(cat_str, ",", cat_str_len);
              (void) g_strlcat(cat_str, cat_str_tmp, cat_str_len);
            }
            bit_spot++;
            bitmask >>= 1;
          }
          byte_spot++;
        }

        if (cat_str)
          proto_tree_add_string(field_tree, hf_ip_cipso_categories, tvb, offset, taglen - 4, cat_str);
        else
          proto_tree_add_string(field_tree, hf_ip_cipso_categories, tvb, offset, taglen - 4, "ERROR PARSING CATEGORIES");
        offset += taglen - 4;
      }
      break;
    case 2:
      /* enumerated categories, see CIPSO draft section 3.4.3 for tag format */
      if ((taglen < 4) || (taglen > CIPSO_TAG_LEN_MAX) ||
         ((offset + (int)taglen - 1) > offset_max)) {
        expert_add_info(pinfo, tag_item, &ei_ip_cipso_tag);
        return offset;
      }

      /* skip past alignment octet */
      offset += 3;

      /* sensitivity level */
      proto_tree_add_item(field_tree, hf_ip_cipso_sensitivity_level, tvb, offset, 1, ENC_NA);
      offset += 1;

      if (taglen > 4) {
        int offset_max_cat = offset + taglen - 4;
        char *cat_str = (char *)wmem_alloc0(pinfo->pool, USHRT_MAX_STRLEN * 15);
        char *cat_str_tmp = (char *)wmem_alloc(pinfo->pool, USHRT_MAX_STRLEN);

        while ((offset + 2) <= offset_max_cat) {
          snprintf(cat_str_tmp, USHRT_MAX_STRLEN, "%u",
                     tvb_get_ntohs(tvb, offset));
          offset += 2;
          if (cat_str[0] != '\0')
            (void) g_strlcat(cat_str, ",", USHRT_MAX_STRLEN * 15);
          (void) g_strlcat(cat_str, cat_str_tmp, USHRT_MAX_STRLEN * 15);
        }

        proto_tree_add_string(field_tree, hf_ip_cipso_categories, tvb, offset - taglen + 4, taglen - 4, cat_str);
      }
      break;
    case 5:
      /* ranged categories, see CIPSO draft section 3.4.4 for tag format */
      if ((taglen < 4) || (taglen > CIPSO_TAG_LEN_MAX) ||
         ((offset + (int)taglen - 1) > offset_max)) {
        expert_add_info(pinfo, tag_item, &ei_ip_cipso_tag);
        return offset;
      }

      /* skip past alignment octet */
      offset += 3;

      /* sensitivity level */
      proto_tree_add_item(field_tree, hf_ip_cipso_sensitivity_level, tvb, offset, 1, ENC_NA);
      offset += 1;

      if (taglen > 4) {
        guint16 cat_low, cat_high;
        int offset_max_cat = offset + taglen - 4;
        char *cat_str = (char *)wmem_alloc0(pinfo->pool, USHRT_MAX_STRLEN * 16);
        char *cat_str_tmp = (char *)wmem_alloc(pinfo->pool, USHRT_MAX_STRLEN * 2);

        while ((offset + 2) <= offset_max_cat) {
          cat_high = tvb_get_ntohs(tvb, offset);
          if ((offset + 4) <= offset_max_cat) {
            cat_low = tvb_get_ntohs(tvb, offset + 2);
            offset += 4;
          } else {
            cat_low = 0;
            offset += 2;
          }
          if (cat_low != cat_high)
            snprintf(cat_str_tmp, USHRT_MAX_STRLEN * 2, "%u-%u",
                       cat_high, cat_low);
          else
            snprintf(cat_str_tmp, USHRT_MAX_STRLEN * 2, "%u", cat_high);

          if (cat_str[0] != '\0')
            (void) g_strlcat(cat_str, ",", USHRT_MAX_STRLEN * 16);
          (void) g_strlcat(cat_str, cat_str_tmp, USHRT_MAX_STRLEN * 16);
        }

        proto_tree_add_string(field_tree, hf_ip_cipso_categories, tvb, offset - taglen + 4, taglen - 4, cat_str);
      }
      break;
    case 6:
      /* permissive categories, see FIPS 188 section 6.9 for tag format */
      if ((taglen < 4) || (taglen > CIPSO_TAG_LEN_MAX) ||
         ((offset + (int)taglen - 1) > offset_max)) {
        expert_add_info(pinfo, tag_item, &ei_ip_cipso_tag);
        return offset;
      }

      proto_tree_add_item(field_tree, hf_ip_cipso_tag_data, tvb, offset + 2, taglen - 2, ENC_NA);
      offset += taglen;
      break;
    case 7:
      /* free form, see FIPS 188 section 6.10 for tag format */
      if ((taglen < 2) || (taglen > CIPSO_TAG_LEN_MAX) ||
         ((offset + (int)taglen - 1) > offset_max)) {
        expert_add_info(pinfo, tag_item, &ei_ip_cipso_tag);
        return offset;
      }

      proto_tree_add_item(field_tree, hf_ip_cipso_tag_data, tvb, offset + 2, taglen - 2, ENC_NA);
      offset += taglen;
      break;
    default:
      /* unknown tag - stop parsing this IPv4 option */
      if ((offset + 1) <= offset_max) {
        taglen = tvb_get_guint8(tvb, offset + 1);
        proto_item_append_text(tag_item, " (%u bytes)", taglen);
        return offset;
      }
      return offset;
    }
  }

  return offset;
}

static void
dissect_option_route(proto_tree *tree, tvbuff_t *tvb, int offset, int hf,
                     int hf_host, gboolean next)
{
  proto_item *ti;
  guint32 route;

  route = tvb_get_ipv4(tvb, offset);
  if (next)
    proto_tree_add_ipv4_format_value(tree, hf, tvb, offset, 4, route,
                                     "%s <- (next)",
                                     tvb_ip_to_str(wmem_packet_scope(), tvb, offset));
  else
    proto_tree_add_ipv4(tree, hf, tvb, offset, 4, route);
  ti = proto_tree_add_string(tree, hf_host, tvb, offset, 4, get_hostname(route));
  proto_item_set_generated(ti);
  proto_item_set_hidden(ti);
}

static int
dissect_ipopt_route(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int proto, int optlen_min)
{
  proto_tree *field_tree;
  proto_item *tf;
  guint8 len, ptr;
  int optoffset = 0;
  gint       offset = 0,
             optlen = tvb_reported_length(tvb);

  field_tree = ip_var_option_header(tree, pinfo, tvb, proto, ett_ip_option_route, &tf, optlen);

  ptr = tvb_get_guint8(tvb, offset + 2);
  tf = proto_tree_add_item(field_tree, hf_ip_opt_ptr, tvb, offset + 2, 1, ENC_NA);
  if ((ptr < (optlen_min + 1)) || (ptr & 3)) {
    if (ptr < (optlen_min + 1)) {
      expert_add_info(pinfo, tf, &ei_ip_opt_ptr_before_address);
    }
    else {
      expert_add_info(pinfo, tf, &ei_ip_opt_ptr_middle_address);
    }
    return optlen_min;
  }

  len = optlen;
  optoffset = 3;    /* skip past type, length and pointer */
  for (optlen -= 3; optlen > 0; optlen -= 4, optoffset += 4) {
    if (optlen < 4) {
      expert_add_info(pinfo, tf, &ei_ip_subopt_too_long);
      break;
    }

    if (ptr > len) {
      /* This is a recorded route */
      dissect_option_route(field_tree, tvb, offset + optoffset, hf_ip_rec_rt,
                           hf_ip_rec_rt_host, FALSE);
    } else if (optoffset == (len - 4)) {
      /* This is the destination */
      proto_item *item;
      guint32 addr;
      const char *dst_host;

      addr = tvb_get_ipv4(tvb, offset + optoffset);
      dst_host = get_hostname(addr);
      proto_tree_add_ipv4(field_tree, hf_ip_dst, tvb,
                          offset + optoffset, 4, addr);
      item = proto_tree_add_ipv4(field_tree, hf_ip_addr, tvb,
                                 offset + optoffset, 4, addr);
      proto_item_set_hidden(item);
      item = proto_tree_add_string(field_tree, hf_ip_dst_host, tvb,
                                   offset + optoffset, 4, dst_host);
      proto_item_set_generated(item);
      proto_item_set_hidden(item);
      item = proto_tree_add_string(field_tree, hf_ip_host, tvb,
                                   offset + optoffset, 4, dst_host);
      proto_item_set_generated(item);
      proto_item_set_hidden(item);
    } else if ((optoffset + 1) < ptr) {
      /* This is also a recorded route */
      dissect_option_route(field_tree, tvb, offset + optoffset, hf_ip_rec_rt,
                           hf_ip_rec_rt_host, FALSE);
    } else if ((optoffset + 1) == ptr) {
      /* This is the next source route.  TODO: Should we use separate hf's
       * for this, such as hf_ip_next_rt and hf_ip_next_rt_host and avoid
       * having to pass TRUE/FALSE to dissect_option_route()? */
      dissect_option_route(field_tree, tvb, offset + optoffset, hf_ip_src_rt,
                           hf_ip_src_rt_host, TRUE);
    } else {
      /* This must be a source route */
      dissect_option_route(field_tree, tvb, offset + optoffset, hf_ip_src_rt,
                           hf_ip_src_rt_host, FALSE);
    }
  }

  return tvb_captured_length(tvb);
}

static int
dissect_ipopt_loose_route(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
  return dissect_ipopt_route(tvb, pinfo, tree, proto_ip_option_route, IPOLEN_LSR_MIN);
}

static int
dissect_ipopt_source_route(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
  return dissect_ipopt_route(tvb, pinfo, tree, proto_ip_option_source_route, IPOLEN_SSR_MIN);

}

static int
dissect_ipopt_record_route(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
  proto_tree *field_tree;
  proto_item *tf;
  guint8 len, ptr;
  int optoffset = 0;
  gint       offset = 0,
             optlen = tvb_reported_length(tvb);

  field_tree = ip_var_option_header(tree, pinfo, tvb, proto_ip_option_record_route, ett_ip_option_route, &tf, optlen);

  ptr = tvb_get_guint8(tvb, offset + 2);
  tf = proto_tree_add_item(field_tree, hf_ip_opt_ptr, tvb, offset + 2, 1, ENC_NA);

  if ((ptr < (IPOLEN_RR_MIN + 1)) || (ptr & 3)) {
    if (ptr < (IPOLEN_RR_MIN + 1)) {
      expert_add_info(pinfo, tf, &ei_ip_opt_ptr_before_address);
    }
    else {
      expert_add_info(pinfo, tf, &ei_ip_opt_ptr_middle_address);
    }
    return IPOLEN_RR_MIN;
  }

  len = optlen;
  optoffset = 3;    /* skip past type, length and pointer */
  for (optlen -= 3; optlen > 0; optlen -= 4, optoffset += 4) {
    if (optlen < 4) {
      expert_add_info(pinfo, tf, &ei_ip_subopt_too_long);
      break;
    }

    if (ptr > len) {
      /* The recorded route data area is full. */
      dissect_option_route(field_tree, tvb, offset + optoffset, hf_ip_rec_rt,
                           hf_ip_rec_rt_host, FALSE);
    } else if ((optoffset + 1) < ptr) {
      /* This is a recorded route */
      dissect_option_route(field_tree, tvb, offset + optoffset, hf_ip_rec_rt,
                           hf_ip_rec_rt_host, FALSE);
    } else if ((optoffset + 1) == ptr) {
      /* This is the next available slot.  TODO: Should we use separate hf's
       * for this, such as hf_ip_next_rt and hf_ip_next_rt_host and avoid
       * having to pass TRUE/FALSE to dissect_option_route()? */
      dissect_option_route(field_tree, tvb, offset + optoffset, hf_ip_empty_rt,
                           hf_ip_empty_rt_host, TRUE);
    } else {
      /* This must be an available slot too. */
      dissect_option_route(field_tree, tvb, offset + optoffset, hf_ip_empty_rt,
                           hf_ip_empty_rt_host, FALSE);
    }
  }

  return tvb_captured_length(tvb);
}

/* Stream Identifier */
static int
dissect_ipopt_sid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
  proto_tree *field_tree;
  proto_item *tf;

  field_tree = ip_fixed_option_header(tree, pinfo, tvb, proto_ip_option_sid, ett_ip_option_sid, &tf, IPOLEN_SID, tvb_reported_length(tvb));

  proto_tree_add_item(field_tree, hf_ip_opt_sid, tvb, 2, 2, ENC_BIG_ENDIAN);
  return tvb_captured_length(tvb);
}

/* RFC 1063: MTU Probe and MTU Reply */
static int
dissect_ipopt_mtu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int proto)
{
  proto_tree *field_tree;
  proto_item *tf;

  field_tree = ip_fixed_option_header(tree, pinfo, tvb, proto, ett_ip_option_mtu, &tf, IPOLEN_MTU, tvb_reported_length(tvb));

  proto_tree_add_item(field_tree, hf_ip_opt_mtu, tvb, 2, 2, ENC_BIG_ENDIAN);
  return tvb_captured_length(tvb);
}

static int
dissect_ipopt_mtu_probe(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  return dissect_ipopt_mtu(tvb, pinfo, tree, proto_ip_option_mtu_probe);
}

static int
dissect_ipopt_mtu_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  return dissect_ipopt_mtu(tvb, pinfo, tree, proto_ip_option_mtu_reply);
}

/* RFC 1393: Traceroute */
static int
dissect_ipopt_tr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
  proto_tree *field_tree;
  proto_item *tf;
  gint       offset = 2;

  field_tree = ip_fixed_option_header(tree, pinfo, tvb, proto_ip_option_traceroute, ett_ip_option_tr, &tf, IPOLEN_TR, tvb_reported_length(tvb));

  proto_tree_add_item(field_tree, hf_ip_opt_id_number, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(field_tree, hf_ip_opt_ohc, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(field_tree, hf_ip_opt_rhc, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(field_tree, hf_ip_opt_originator, tvb, offset + 6, 4, ENC_BIG_ENDIAN);
  return tvb_captured_length(tvb);
}

static const value_string ipopt_timestamp_flag_vals[] = {
    {IPOPT_TS_TSONLY,    "Time stamps only"                      },
    {IPOPT_TS_TSANDADDR, "Time stamp and address"                },
    {IPOPT_TS_PRESPEC,   "Time stamps for prespecified addresses"},
    {0,                  NULL                                    }};

static int
dissect_ipopt_timestamp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
  proto_tree *field_tree;
  proto_item *tf;
  int        ptr;
  int        optoffset = 0;
  int        flg;
  guint32 addr;
  gint       offset = 0,
             optlen = tvb_reported_length(tvb);

  field_tree = ip_var_option_header(tree, pinfo, tvb, proto_ip_option_timestamp, ett_ip_option_timestamp, &tf, optlen);

  optoffset += 2;   /* skip past type and length */
  optlen -= 2;      /* subtract size of type and length */

  ptr = tvb_get_guint8(tvb, offset + optoffset);
  proto_tree_add_uint_format_value(field_tree, hf_ip_opt_ptr, tvb, offset + optoffset, 1, ptr, "%d%s",
                      ptr, ((ptr == 1) ? " (header is full)" :
                      (ptr < 5) ? " (points before first address)" :
                      (((ptr - 1) & 3) ? " (points to middle of field)" : "")));
  optoffset++;
  optlen--;
  ptr--;    /* ptr is 1-origin */

  flg = tvb_get_guint8(tvb, offset + optoffset);
  proto_tree_add_item(field_tree, hf_ip_opt_overflow, tvb, offset + optoffset, 1, ENC_NA);
  flg &= 0xF;
  proto_tree_add_item(field_tree, hf_ip_opt_flag, tvb, offset + optoffset, 1, ENC_NA);
  optoffset++;
  optlen--;

  while (optlen > 0) {
    if (flg == IPOPT_TS_TSANDADDR || flg == IPOPT_TS_PRESPEC) {
      if (optlen < 8) {
        proto_tree_add_expert(field_tree, pinfo, &ei_ip_subopt_too_long, tvb, offset + optoffset, optlen);
        break;
      }
      addr = tvb_get_ipv4(tvb, offset + optoffset);
      proto_tree_add_ipv4_format_value(field_tree, hf_ip_opt_time_stamp_addr, tvb, offset + optoffset, 4, addr,
            "%s", ((addr == 0) ? "-" : get_hostname(addr)));
      optoffset += 4;
      optlen -= 4;

      proto_tree_add_item(field_tree, hf_ip_opt_time_stamp, tvb, offset + optoffset, 4, ENC_BIG_ENDIAN);
      optoffset += 4;
      optlen -= 4;
    } else {
      if (optlen < 4) {
        proto_tree_add_expert(field_tree, pinfo, &ei_ip_subopt_too_long, tvb, offset + optoffset, optlen);
        break;
      }
      proto_tree_add_item(field_tree, hf_ip_opt_time_stamp, tvb, offset + optoffset, 4, ENC_BIG_ENDIAN);
      optoffset += 4;
      optlen -= 4;
    }
  }

  return tvb_captured_length(tvb);
}

/* Router Alert */
static const range_string ra_rvals[] = {
  {0, 0, "Router shall examine packet"},
  {1, 65535, "Reserved"},
  {0, 0, NULL}
};

static int
dissect_ipopt_ra(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
  /* Router-Alert, as defined by RFC2113 */
  proto_tree *field_tree;
  proto_item *tf;
  guint32 value;

  field_tree = ip_fixed_option_header(tree, pinfo, tvb, proto_ip_option_routeralert, ett_ip_option_ra, &tf, IPOLEN_RA, tvb_reported_length(tvb));

  proto_tree_add_item_ret_uint(field_tree, hf_ip_opt_ra, tvb, 2, 2, ENC_BIG_ENDIAN, &value);
  proto_item_append_text(tf, ": %s (%u)", rval_to_str(value, ra_rvals, "Unknown (%u)"), value);
  return tvb_captured_length(tvb);
}

/* RFC 1770: Selective Directed Broadcast */
static int
dissect_ipopt_sdb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
  proto_tree *field_tree;
  proto_item *tf;
  gint       offset = 0,
             optlen = tvb_reported_length(tvb);

  field_tree = ip_var_option_header(tree, pinfo, tvb, proto_ip_option_sdb, ett_ip_option_sdb, &tf, optlen);

  for (offset += 2, optlen -= 2; optlen >= 4; offset += 4, optlen -= 4)
    proto_tree_add_item(field_tree, hf_ip_opt_addr, tvb, offset, 4, ENC_BIG_ENDIAN);

  if (optlen > 0)
    proto_tree_add_item(field_tree, hf_ip_opt_padding, tvb, offset, optlen, ENC_NA);

  return tvb_captured_length(tvb);
}

const value_string qs_func_vals[] = {
  {QS_RATE_REQUEST, "Rate request"},
  {QS_RATE_REPORT,  "Rate report"},
  {0,               NULL}
};

static const value_string qs_rate_vals[] = {
  { 0, "0 bit/s"},
  { 1, "80 Kbit/s"},
  { 2, "160 Kbit/s"},
  { 3, "320 Kbit/s"},
  { 4, "640 Kbit/s"},
  { 5, "1.28 Mbit/s"},
  { 6, "2.56 Mbit/s"},
  { 7, "5.12 Mbit/s"},
  { 8, "10.24 Mbit/s"},
  { 9, "20.48 Mbit/s"},
  {10, "40.96 Mbit/s"},
  {11, "81.92 Mbit/s"},
  {12, "163.84 Mbit/s"},
  {13, "327.68 Mbit/s"},
  {14, "655.36 Mbit/s"},
  {15, "1.31072 Gbit/s"},
  {0, NULL}
};
value_string_ext qs_rate_vals_ext = VALUE_STRING_EXT_INIT(qs_rate_vals);

static int
dissect_ipopt_qs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data)
{
  proto_tree *field_tree;
  proto_item *tf;
  proto_item *ti;
  ws_ip4 *iph = (ws_ip4 *)data;
  gint       offset = 2;

  guint8 command = tvb_get_guint8(tvb, offset);
  guint8 function = command >> 4;
  guint8 rate = command & QS_RATE_MASK;
  guint8 ttl_diff;

  field_tree = ip_fixed_option_header(tree, pinfo, tvb, proto_ip_option_qs, ett_ip_option_qs, &tf, IPOLEN_QS, tvb_reported_length(tvb));
  proto_item_append_text(tf, ": %s (%u)", val_to_str(function, qs_func_vals, "Unknown (%u)"), function);

  proto_tree_add_item(field_tree, hf_ip_opt_qs_func, tvb, offset, 1, ENC_NA);

  if (function == QS_RATE_REQUEST) {
    proto_tree_add_item(field_tree, hf_ip_opt_qs_rate, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(field_tree, hf_ip_opt_qs_ttl, tvb, offset + 1, 1, ENC_NA);
    ttl_diff = (iph->ip_ttl - tvb_get_guint8(tvb, offset + 1) % 256);
    ti = proto_tree_add_uint(field_tree, hf_ip_opt_qs_ttl_diff,
                                          tvb, offset + 1, 1, ttl_diff);
    proto_item_set_generated(ti);
    proto_item_append_text(tf, ", %s, QS TTL %u, QS TTL diff %u",
                           val_to_str_ext(rate, &qs_rate_vals_ext, "Unknown (%u)"),
                           tvb_get_guint8(tvb, offset + 1), ttl_diff);
    proto_tree_add_item(field_tree, hf_ip_opt_qs_nonce, tvb, offset + 2, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_ip_opt_qs_reserved, tvb, offset + 2, 4, ENC_BIG_ENDIAN);
  } else if (function == QS_RATE_REPORT) {
    proto_tree_add_item(field_tree, hf_ip_opt_qs_rate, tvb, offset, 1, ENC_NA);
    proto_item_append_text(tf, ", %s",
                           val_to_str_ext(rate, &qs_rate_vals_ext, "Unknown (%u)"));
    proto_tree_add_item(field_tree, hf_ip_opt_qs_unused, tvb, offset + 1, 1, ENC_NA);
    proto_tree_add_item(field_tree, hf_ip_opt_qs_nonce, tvb, offset + 2, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_ip_opt_qs_reserved, tvb, offset + 2, 4, ENC_BIG_ENDIAN);
  }

  return tvb_captured_length(tvb);
}

static void
dissect_ip_options(tvbuff_t *tvb, int offset, guint length,
                       packet_info *pinfo, proto_tree *opt_tree,
                       proto_item *opt_item, void * data)
{
  guchar            opt;
  unsigned int      optlen;
  proto_tree       *field_tree;
  const char       *name;
  dissector_handle_t option_dissector;
  guint             nop_count = 0;
  tvbuff_t         *next_tvb;

  while (length > 0) {
    opt = tvb_get_guint8(tvb, offset);
    --length;      /* account for type byte */

    if ((opt == IPOPT_EOOL) || (opt == IPOPT_NOP)) {
      int local_proto;
      proto_item* field_item;
      /* We assume that the only options with no length are EOL and NOP options,
         so that we can treat unknown options as having a minimum length of 2,
         and at least be able to move on to the next option by using the length in the option. */

      if (opt == IPOPT_EOOL)
      {
        local_proto = proto_ip_option_eol;
      } else {
        /* i.e. opt is IPOPT_NOP */
        local_proto = proto_ip_option_nop;

        if (opt_item && (nop_count == 0 || offset % 4)) {
          /* Count number of NOP in a row within a uint32 */
          nop_count++;

          if (nop_count == 4) {
            expert_add_info(pinfo, opt_item, &ei_ip_nop);
          }
        } else {
          nop_count = 0;
        }
      }

      field_item = proto_tree_add_item(opt_tree, local_proto, tvb, offset, 1, ENC_NA);
      field_tree = proto_item_add_subtree(field_item, ett_ip_option_other);

      dissect_ipopt_type(tvb, offset, field_tree);
      offset++;

    } else {
      option_dissector = dissector_get_uint_handle(ip_option_table, opt);
      if (option_dissector == NULL) {
        name = wmem_strdup_printf(pinfo->pool, "Unknown (0x%02x)", opt);
      } else {
        name = dissector_handle_get_short_name(option_dissector);
      }

      /* Option has a length. Is it in the packet? */
      if (length == 0) {
        /* Bogus - packet must at least include option code byte and
           length byte! */
        proto_tree_add_expert_format(opt_tree, pinfo, &ei_ip_opt_len_invalid, tvb, offset, 1,
                                     "%s (length byte past end of options)", name);
        return;
      }

      optlen = tvb_get_guint8(tvb, offset + 1);  /* total including type, len */
      --length;    /* account for length byte */

      if (optlen < 2) {
        /* Bogus - option length is too short to include option code and option length. */
        proto_tree_add_expert_format(opt_tree, pinfo, &ei_ip_opt_len_invalid, tvb, offset, 2,
                                    "%s (with too-short option length = %u byte%s)",
                                    name, optlen, plurality(optlen, "", "s"));
        return;
      } else if (optlen - 2 > length) {
        /* Bogus - option goes past the end of the header. */
        proto_tree_add_expert_format(opt_tree, pinfo, &ei_ip_opt_len_invalid, tvb, offset, length,
                                    "%s (option length = %u byte%s says option goes past end of options)",
                                    name, optlen, plurality(optlen, "", "s"));
        return;
      }

      if (option_dissector == NULL) {
        proto_tree_add_subtree_format(opt_tree, tvb, offset, optlen, ett_ip_unknown_opt, NULL, "%s (%u byte%s)",
                                              name, optlen, plurality(optlen, "", "s"));
      } else {
        next_tvb = tvb_new_subset_length(tvb, offset, optlen);
        call_dissector_with_data(option_dissector, next_tvb, pinfo, opt_tree, data);
        proto_item_append_text(proto_tree_get_parent(opt_tree), ", %s", name);
      }

      offset += optlen;
      length -= (optlen-2); //already accounted for type and len bytes
    }

    if (opt == IPOPT_EOOL)
      break;
  }
}

/* This function searches the IP options for either a loose or strict source
 * route option, then returns the offset to the destination address if the
 * pointer is still valid or zero if the pointer is greater than the length.
 *
 * The guts of this function was taken from dissect_ip_tcp_options().
 */
static int
get_dst_offset(tvbuff_t *tvb, int offset, guint length)
{
  guchar            opt;
  guint             len;
  int               orig_offset = offset;

  while (length > 0) {
    opt = tvb_get_guint8(tvb, offset);
    --length;      /* account for type byte */

    if ((opt != IPOPT_EOOL) && (opt != IPOPT_NOP)) {
      /* Option has a length. Is it in the packet? */
      if (length == 0) {
        /* Bogus - packet must at least include option code byte and
           length byte! */
        return 0;
      }
      len = tvb_get_guint8(tvb, offset + 1);  /* total including type, len */
      --length;    /* account for length byte */
      if (len < 2) {
        /* Bogus - option length is too short to include option code and
           option length. */
        return 0;
      } else if (len - 2 > length) {
        /* Bogus - option goes past the end of the header. */
        return 0;
      }

      if (opt == IPOPT_SSR || opt == IPOPT_LSR) {
        /* Hmm, what if you have both options? */
        guint8 ptr;

        ptr = tvb_get_guint8(tvb, offset + 2);
        if (ptr < 4 || (ptr & 3) || (ptr > len)) {
          return 0;
        }
        return (offset - orig_offset) + 4 + (len - 4);
      }

      offset += len;
      length -= (len-2); /* subtract size of type and length */
    } else {
      offset += 1;
    }
    if (opt == IPOPT_EOOL)
      return 0;
  }

  return 0;
}

/* Returns the valid ttl for the group address */
static guint16
local_network_control_block_addr_valid_ttl(guint32 addr)
{
  /* An exception list, as some protocols seem to insist on
   * doing differently:
   */

  /* IETF's VRRP (rfc3768) */
  if (IPLOCAL_NETWRK_CTRL_BLK_VRRP_ADDR == addr)
    return IPLOCAL_NETWRK_CTRL_BLK_VRRP_TTL;
  /* Cisco's GLPB */
  if (IPLOCAL_NETWRK_CTRL_BLK_GLPB_ADDR == addr)
    return IPLOCAL_NETWRK_CTRL_BLK_GLPB_TTL;
  /* mDNS (draft-cheshire-dnsext-multicastdns-07) */
  if (IPLOCAL_NETWRK_CTRL_BLK_MDNS_ADDR == addr)
    return IPLOCAL_NETWRK_CTRL_BLK_MDNS_TTL;
  /* LLMNR (rfc4795) */
  if (IPLOCAL_NETWRK_CTRL_BLK_LLMNR_ADDR == addr)
    return IPLOCAL_NETWRK_CTRL_BLK_ANY_TTL;
  return IPLOCAL_NETWRK_CTRL_BLK_DEFAULT_TTL;
}

static const value_string dscp_short_vals[] = {
  { IPDSFIELD_DSCP_DEFAULT, "CS0"    },
  { IPDSFIELD_DSCP_LE,      "LE"     },
  { IPDSFIELD_DSCP_CS1,     "CS1"    },
  { IPDSFIELD_DSCP_AF11,    "AF11"   },
  { IPDSFIELD_DSCP_AF12,    "AF12"   },
  { IPDSFIELD_DSCP_AF13,    "AF13"   },
  { IPDSFIELD_DSCP_CS2,     "CS2"    },
  { IPDSFIELD_DSCP_AF21,    "AF21"   },
  { IPDSFIELD_DSCP_AF22,    "AF22"   },
  { IPDSFIELD_DSCP_AF23,    "AF23"   },
  { IPDSFIELD_DSCP_CS3,     "CS3"    },
  { IPDSFIELD_DSCP_AF31,    "AF31"   },
  { IPDSFIELD_DSCP_AF32,    "AF32"   },
  { IPDSFIELD_DSCP_AF33,    "AF33"   },
  { IPDSFIELD_DSCP_CS4,     "CS4"    },
  { IPDSFIELD_DSCP_AF41,    "AF41"   },
  { IPDSFIELD_DSCP_AF42,    "AF42"   },
  { IPDSFIELD_DSCP_AF43,    "AF43"   },
  { IPDSFIELD_DSCP_CS5,     "CS5"    },
  { IPDSFIELD_DSCP_EF,      "EF PHB" },
  { IPDSFIELD_DSCP_CS6,     "CS6"    },
  { IPDSFIELD_DSCP_CS7,     "CS7"    },
  { 0,                      NULL     }};
value_string_ext dscp_short_vals_ext = VALUE_STRING_EXT_INIT(dscp_short_vals);


static const value_string dscp_vals[] = {
  { IPDSFIELD_DSCP_DEFAULT, "Default"               },
  { IPDSFIELD_DSCP_LE,      "Lower Effort"          },
  { IPDSFIELD_DSCP_CS1,     "Class Selector 1"      },
  { IPDSFIELD_DSCP_AF11,    "Assured Forwarding 11" },
  { IPDSFIELD_DSCP_AF12,    "Assured Forwarding 12" },
  { IPDSFIELD_DSCP_AF13,    "Assured Forwarding 13" },
  { IPDSFIELD_DSCP_CS2,     "Class Selector 2"      },
  { IPDSFIELD_DSCP_AF21,    "Assured Forwarding 21" },
  { IPDSFIELD_DSCP_AF22,    "Assured Forwarding 22" },
  { IPDSFIELD_DSCP_AF23,    "Assured Forwarding 23" },
  { IPDSFIELD_DSCP_CS3,     "Class Selector 3"      },
  { IPDSFIELD_DSCP_AF31,    "Assured Forwarding 31" },
  { IPDSFIELD_DSCP_AF32,    "Assured Forwarding 32" },
  { IPDSFIELD_DSCP_AF33,    "Assured Forwarding 33" },
  { IPDSFIELD_DSCP_CS4,     "Class Selector 4"      },
  { IPDSFIELD_DSCP_AF41,    "Assured Forwarding 41" },
  { IPDSFIELD_DSCP_AF42,    "Assured Forwarding 42" },
  { IPDSFIELD_DSCP_AF43,    "Assured Forwarding 43" },
  { IPDSFIELD_DSCP_CS5,     "Class Selector 5"      },
  { IPDSFIELD_DSCP_EF,      "Expedited Forwarding"  },
  { IPDSFIELD_DSCP_CS6,     "Class Selector 6"      },
  { IPDSFIELD_DSCP_CS7,     "Class Selector 7"      },
  { 0,                      NULL                    }};
value_string_ext dscp_vals_ext = VALUE_STRING_EXT_INIT(dscp_vals);

static const value_string ecn_short_vals[] = {
  { IPDSFIELD_ECT_NOT, "Not-ECT" },
  { IPDSFIELD_ECT_1,   "ECT(1)"  },
  { IPDSFIELD_ECT_0,   "ECT(0)"  },
  { IPDSFIELD_CE,      "CE"      },
  { 0,                 NULL      }};
value_string_ext ecn_short_vals_ext = VALUE_STRING_EXT_INIT(ecn_short_vals);

static const value_string ecn_vals[] = {
  { IPDSFIELD_ECT_NOT, "Not ECN-Capable Transport"            },
  { IPDSFIELD_ECT_1,   "ECN-Capable Transport codepoint '01'" },
  { IPDSFIELD_ECT_0,   "ECN-Capable Transport codepoint '10'" },
  { IPDSFIELD_CE,      "Congestion Experienced"               },
  { 0,                 NULL                                   }};
value_string_ext ecn_vals_ext = VALUE_STRING_EXT_INIT(ecn_vals);

static const value_string precedence_vals[] = {
  { IPTOS_PREC_ROUTINE,         "routine"              },
  { IPTOS_PREC_PRIORITY,        "priority"             },
  { IPTOS_PREC_IMMEDIATE,       "immediate"            },
  { IPTOS_PREC_FLASH,           "flash"                },
  { IPTOS_PREC_FLASHOVERRIDE,   "flash override"       },
  { IPTOS_PREC_CRITIC_ECP,      "CRITIC/ECP"           },
  { IPTOS_PREC_INTERNETCONTROL, "internetwork control" },
  { IPTOS_PREC_NETCONTROL,      "network control"      },
  { 0,                          NULL                   }};

static const value_string iptos_vals[] = {
  { IPTOS_NONE,        "None" },
  { IPTOS_LOWCOST,     "Minimize cost" },
  { IPTOS_RELIABILITY, "Maximize reliability" },
  { IPTOS_THROUGHPUT,  "Maximize throughput" },
  { IPTOS_LOWDELAY,    "Minimize delay" },
  { IPTOS_SECURITY,    "Maximize security" },
  { 0,                 NULL }
};

static const true_false_string flags_sf_set_evil = {
  "Evil",
  "Not evil"
};

gboolean
ip_try_dissect(gboolean heur_first, guint nxt, tvbuff_t *tvb, packet_info *pinfo,
               proto_tree *tree, void *iph)
{
  heur_dtbl_entry_t *hdtbl_entry;

  if ((heur_first) && (dissector_try_heuristic(heur_subdissector_list, tvb,
                       pinfo, tree, &hdtbl_entry, iph))) {
    return TRUE;
  }

  if (dissector_try_uint_new(ip_dissector_table, nxt, tvb, pinfo,
                             tree, TRUE, iph)) {
    return TRUE;
  }

  if ((!heur_first) && (dissector_try_heuristic(heur_subdissector_list, tvb,
                                                 pinfo, tree, &hdtbl_entry,
                                                 iph))) {
    return TRUE;
  }

  return FALSE;
}

static void
export_pdu(tvbuff_t *tvb, packet_info *pinfo)
{
  if (have_tap_listener(exported_pdu_tap)) {
    exp_pdu_data_t *exp_pdu_data = wmem_new0(pinfo->pool, exp_pdu_data_t);

    exp_pdu_data->tvb_captured_length = tvb_captured_length(tvb);
    exp_pdu_data->tvb_reported_length = tvb_reported_length(tvb);
    exp_pdu_data->pdu_tvb = tvb;
    tap_queue_packet(exported_pdu_tap, pinfo, exp_pdu_data);
  }
}

static int
dissect_ip_v4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
  proto_tree *ip_tree, *field_tree = NULL;
  proto_item *ti, *tf;
  guint32    addr;
  int        offset = 0, dst_off;
  guint      hlen, optlen;
  guint16    ipsum;
  fragment_head *ipfd_head = NULL;
  tvbuff_t   *next_tvb;
  gboolean   update_col_info = TRUE;
  gboolean   save_fragmented;
  ws_ip4 *iph;
  guint32    src32, dst32;
  proto_tree *tree;
  proto_item *item = NULL, *ttl_item;
  guint16 ttl_valid;

  tree = parent_tree;
  iph = wmem_new0(pinfo->pool, ws_ip4);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPv4");
  col_clear(pinfo->cinfo, COL_INFO);

  iph->ip_ver = tvb_get_bits8(tvb, 0, 4);

  hlen = tvb_get_bits8(tvb, 4, 4) * 4;  /* IP header length, in bytes */

  ti = proto_tree_add_item(tree, proto_ip, tvb, offset, hlen, ENC_NA);
  ip_tree = proto_item_add_subtree(ti, ett_ip);

  tf = proto_tree_add_bits_item(ip_tree, hf_ip_version, tvb, 0, 4, ENC_NA);
  if (iph->ip_ver != 4) {
    col_add_fstr(pinfo->cinfo, COL_INFO,
                 "Bogus IPv4 version (%u, must be 4)", iph->ip_ver);
    expert_add_info_format(pinfo, tf, &ei_ip_bogus_ip_version, "Bogus IPv4 version");
    /* I have a Linux cooked capture with ethertype IPv4 containing an IPv6 packet, continnue dissection in that case*/
    if (iph->ip_ver == 6) {
        call_dissector(ipv6_handle, tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
  }

  /* if IP is not referenced from any filters we don't need to worry about
     generating any tree items.  We must do this after we created the actual
     protocol above so that proto hier stat still works though.
     XXX: Note that because of the following optimization expert items must
          not be generated inside of an 'if (tree) ...'
          so that Analyze ! Expert ...  will work.
  */
  if (!proto_field_is_referenced(parent_tree, proto_ip)) {
    tree = NULL;
  }

  if (hlen < IPH_MIN_LEN) {
    col_add_fstr(pinfo->cinfo, COL_INFO,
                 "Bogus IP header length (%u, must be at least %u)",
                 hlen, IPH_MIN_LEN);
    tf = proto_tree_add_uint_bits_format_value(ip_tree, hf_ip_hdr_len, tvb, (offset<<3)+4, 4, hlen,
                                               ENC_BIG_ENDIAN, "%u bytes (%u)", hlen, hlen>>2);
    expert_add_info_format(pinfo, tf, &ei_ip_bogus_header_length,
                           "Bogus IP header length (%u, must be at least %u)", hlen, IPH_MIN_LEN);
    return tvb_captured_length(tvb);
  }

  // This should be consistent with tcp.hdr_len.
  proto_tree_add_uint_bits_format_value(ip_tree, hf_ip_hdr_len, tvb, (offset<<3)+4, 4, hlen,
                               ENC_BIG_ENDIAN, "%u bytes (%u)", hlen, hlen>>2);

  iph->ip_tos = tvb_get_guint8(tvb, offset + 1);
  if (g_ip_dscp_actif) {
    col_add_str(pinfo->cinfo, COL_DSCP_VALUE,
                val_to_str_ext(IPDSFIELD_DSCP(iph->ip_tos), &dscp_short_vals_ext, "%u"));
  }

  if (tree) {
    if (g_ip_dscp_actif) {
      tf = proto_tree_add_item(ip_tree, hf_ip_dsfield, tvb, offset + 1, 1, ENC_NA);
      proto_item_append_text(tf, " (DSCP: %s, ECN: %s)",
            val_to_str_ext_const(IPDSFIELD_DSCP(iph->ip_tos), &dscp_short_vals_ext, "Unknown"),
            val_to_str_ext_const(IPDSFIELD_ECN(iph->ip_tos), &ecn_short_vals_ext, "Unknown"));

      field_tree = proto_item_add_subtree(tf, ett_ip_dsfield);
      proto_tree_add_item(field_tree, hf_ip_dsfield_dscp, tvb, offset + 1, 1, ENC_NA);
      proto_tree_add_item(field_tree, hf_ip_dsfield_ecn, tvb, offset + 1, 1, ENC_NA);
    } else {
      tf = proto_tree_add_uint_format_value(ip_tree, hf_ip_tos, tvb, offset + 1, 1,
                                      iph->ip_tos,
                                      "0x%02x (%s)",
                                      iph->ip_tos,
                                      val_to_str_const(IPTOS_TOS(iph->ip_tos),
                                                       iptos_vals, "Unknown"));

      field_tree = proto_item_add_subtree(tf, ett_ip_tos);
      proto_tree_add_item(field_tree, hf_ip_tos_precedence, tvb, offset + 1, 1, ENC_NA);
      proto_tree_add_item(field_tree, hf_ip_tos_delay, tvb, offset + 1, 1, ENC_NA);
      proto_tree_add_item(field_tree, hf_ip_tos_throughput, tvb, offset + 1, 1, ENC_NA);
      proto_tree_add_item(field_tree, hf_ip_tos_reliability, tvb, offset + 1, 1, ENC_NA);
      proto_tree_add_item(field_tree, hf_ip_tos_cost, tvb, offset + 1, 1, ENC_NA);
    }
  }

  /* Length of IP datagram.
     XXX - what if this is greater than the reported length of the
     tvbuff?  This could happen, for example, in an IP datagram
     inside an ICMP datagram; we need to somehow let the
     dissector we call know that, as it might want to avoid
     doing its checksumming. */
  iph->ip_len = tvb_get_ntohs(tvb, offset + 2);

  if (iph->ip_len < hlen) {
    if (ip_tso_supported && !iph->ip_len) {
      /* TSO support enabled, and zero length.  Assume the zero length is
       * the result of TSO, and use the reported length instead.  Note that
       * we need to use the frame/reported length instead of the actually-
       * available length, just in case a snaplen was used on capture. */
      iph->ip_len = tvb_reported_length(tvb);
      if (tree) {
        tf = proto_tree_add_uint_format_value(ip_tree, hf_ip_len, tvb, offset + 2, 2,
          iph->ip_len,
          "%u bytes (reported as 0, presumed to be because of \"TCP segmentation offload\" (TSO))",
          iph->ip_len);
        proto_item_set_generated(tf);
      }
    } else {
      /* TSO support not enabled, or non-zero length, so treat it as an error. */
      col_add_fstr(pinfo->cinfo, COL_INFO,
                   "Bogus IP length (%u, less than header length %u)",
                   iph->ip_len, hlen);
      tf = proto_tree_add_uint_format_value(ip_tree, hf_ip_len, tvb, offset + 2, 2,
          iph->ip_len,
          "%u bytes (bogus, less than header length %u)",
          iph->ip_len, hlen);
      expert_add_info(pinfo, tf, &ei_ip_bogus_ip_length);
      /* Can't dissect any further */
      return tvb_captured_length(tvb);
    }
  } else {
    tf = proto_tree_add_uint(ip_tree, hf_ip_len, tvb, offset + 2, 2, iph->ip_len);
    if (iph->ip_len > tvb_reported_length(tvb)) {
      /*
       * Length runs past the data we're given.
       * Note that if not in a ICMP error packet.
       */
      if (!pinfo->flags.in_error_pkt) {
        expert_add_info_format(pinfo, tf, &ei_ip_bogus_ip_length,
                               "IPv4 total length exceeds packet length (%u bytes)",
                               tvb_reported_length(tvb));
      }
    } else {
      /*
       * Now that we know that the total length of this IP datagram isn't
       * obviously bogus, adjust the length of this tvbuff to include only
       * the IP datagram.
       */
      set_actual_length(tvb, iph->ip_len);
    }
  }

  /* Only export after adjusting the length */
  export_pdu(tvb, pinfo);

  iph->ip_id  = tvb_get_ntohs(tvb, offset + 4);
  if (tree)
    proto_tree_add_uint(ip_tree, hf_ip_id, tvb, offset + 4, 2, iph->ip_id);

  iph->ip_off = tvb_get_ntohs(tvb, offset + 6);

  if (ip_security_flag) {
    /* RFC 3514 - The Security Flag in the IPv4 Header (April Fool's joke) */
    static int * const ip_flags_evil[] = {
        &hf_ip_flags_sf,
        &hf_ip_flags_df,
        &hf_ip_flags_mf,
        NULL
    };

    tf = proto_tree_add_bitmask_with_flags(ip_tree, tvb, offset + 6, hf_ip_flags,
        ett_ip_flags, ip_flags_evil, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_TFS | BMT_NO_INT);
    if (iph->ip_off & IP_RF) {
        expert_add_info(pinfo, tf, &ei_ip_evil_packet);
    }
  } else {
    static int * const ip_flags[] = {
        &hf_ip_flags_rf,
        &hf_ip_flags_df,
        &hf_ip_flags_mf,
        NULL
    };
    tf = proto_tree_add_bitmask_with_flags(ip_tree, tvb, offset + 6, hf_ip_flags,
        ett_ip_flags, ip_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_TFS | BMT_NO_INT);
  }

  tf = proto_tree_add_uint(ip_tree, hf_ip_frag_offset, tvb, offset + 6, 2, (iph->ip_off & IP_OFFSET)*8);

  iph->ip_ttl = tvb_get_guint8(tvb, offset + 8);
  ttl_item = proto_tree_add_item(ip_tree, hf_ip_ttl, tvb, offset + 8, 1, ENC_BIG_ENDIAN);

  iph->ip_proto = tvb_get_guint8(tvb, offset + 9);
  if (tree) {
    proto_tree_add_item(ip_tree, hf_ip_proto, tvb, offset + 9, 1, ENC_BIG_ENDIAN);
  }

  iph->ip_sum = tvb_get_ntohs(tvb, offset + 10);

  /*
   * If checksum checking is enabled, and we have the entire IP header
   * available, check the checksum.
   */
  if (ip_check_checksum && tvb_bytes_exist(tvb, offset, hlen)) {
    ipsum = ip_checksum_tvb(tvb, offset, hlen);
    item = proto_tree_add_checksum(ip_tree, tvb, offset + 10, hf_ip_checksum, hf_ip_checksum_status, &ei_ip_checksum_bad, pinfo, ipsum,
                                ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY|PROTO_CHECKSUM_IN_CKSUM);
    /*
     * ip_checksum_tvb() should never return 0xFFFF here, because, to
     * quote RFC 1624 section 3 "Discussion":
     *
     *     In one's complement, there are two representations of
     *     zero: the all zero and the all one bit values, often
     *     referred to as +0 and -0.  One's complement addition
     *     of non-zero inputs can produce -0 as a result, but
     *     never +0.  Since there is guaranteed to be at least
     *     one non-zero field in the IP header, and the checksum
     *     field in the protocol header is the complement of the
     *     sum, the checksum field can never contain ~(+0), which
     *     is -0 (0xFFFF).  It can, however, contain ~(-0), which
     *     is +0 (0x0000).
     *
     * ip_checksum_tvb() checksums the IPv4 header, where the "version"
     * field is 4, ensuring that, in a valid IPv4 header, there is at
     * least one non-zero field.  We've already verified that the
     * version is 4.
     *
     * ip_checksum_tvb() returns the negation of the one's-complement
     * sum of all the data handed to it, and that data won't be
     * all zero, so the sum won't be 0 (+0), and thus the negation
     * won't be -0, i.e. won't be 0xFFFF.
     */
    if (ipsum == 0) {
      /* XXX - Keeping hf_ip_checksum_calculated field for now.  Doesn't fit into the
        proto_tree_add_checksum design, but IP is a popular enough dissector that somebody
        may have a legitimate reason for wanting it filtered */
      item = proto_tree_add_uint(ip_tree, hf_ip_checksum_calculated, tvb,
                                    offset + 10, 2, iph->ip_sum);
      proto_item_set_generated(item);
    } else {
      proto_item_append_text(item, "(may be caused by \"IP checksum offload\"?)");

      item = proto_tree_add_uint(ip_tree, hf_ip_checksum_calculated, tvb,
                                      offset + 10, 2, in_cksum_shouldbe(iph->ip_sum, ipsum));
      proto_item_set_generated(item);
    }
  } else {
    ipsum = 0;
    proto_tree_add_uint_format_value(ip_tree, hf_ip_checksum, tvb,
                                        offset + 10, 2, iph->ip_sum,
                                        "0x%04x [%s]",
                                        iph->ip_sum,
                                        ip_check_checksum ?
                                            "not all data available" :
                                            "validation disabled");
    item = proto_tree_add_uint(ip_tree, hf_ip_checksum_status, tvb,
                                    offset + 10, 0, PROTO_CHECKSUM_E_UNVERIFIED);
    proto_item_set_generated(item);
  }
  src32 = tvb_get_ntohl(tvb, offset + IPH_SRC);
  set_address_tvb(&pinfo->net_src, AT_IPv4, 4, tvb, offset + IPH_SRC);
  copy_address_shallow(&pinfo->src, &pinfo->net_src);
  copy_address_shallow(&iph->ip_src, &pinfo->src);
  if (tree) {
    const char *src_host;

    memcpy(&addr, iph->ip_src.data, 4);
    src_host = get_hostname(addr);
    if (ip_summary_in_tree) {
      proto_item_append_text(ti, ", Src: %s", address_with_resolution_to_str(pinfo->pool, &iph->ip_src));
    }
    proto_tree_add_ipv4(ip_tree, hf_ip_src, tvb, offset + 12, 4, addr);
    item = proto_tree_add_ipv4(ip_tree, hf_ip_addr, tvb, offset + 12, 4, addr);
    proto_item_set_hidden(item);
    item = proto_tree_add_string(ip_tree, hf_ip_src_host, tvb, offset + 12, 4,
                                 src_host);
    proto_item_set_generated(item);
    proto_item_set_hidden(item);
    item = proto_tree_add_string(ip_tree, hf_ip_host, tvb, offset + 12, 4,
                                 src_host);
    proto_item_set_generated(item);
    proto_item_set_hidden(item);
  }

  /* If there's an IP strict or loose source routing option, then the final
   * L3 IP destination address will be the last entry in the routing header
   * EXCEPT when the table is exhausted (pointer is greater than the length).
   * In this case, the final L3 IP destination address is the one in the L3
   * header. (REF: https://tools.ietf.org/html/rfc791#section-3.1)
   */
  if (hlen > IPH_MIN_LEN) {
    /* There's more than just the fixed-length header.  See if we've got
     * either a strict or loose source route option and if so, return the
     * offset into the tvb to where the real destination IP address is located.
     */
    dst_off = get_dst_offset(tvb, offset + 20, hlen - IPH_MIN_LEN);
  }
  else
    dst_off = 0;

  dst32 = tvb_get_ntohl(tvb, offset + IPH_DST + dst_off);
  set_address_tvb(&pinfo->net_dst, AT_IPv4, 4, tvb, offset + IPH_DST + dst_off);
  copy_address_shallow(&pinfo->dst, &pinfo->net_dst);
  copy_address_shallow(&iph->ip_dst, &pinfo->net_dst);

  /* If an IP is destined for an IP address in the Local Network Control Block
   * (e.g. 224.0.0.0/24), the packet should never be routed and the TTL would
   * be expected to be 1.  (see RFC 3171)  Flag a TTL greater than 1.
   *
   * Flag a low TTL if the packet is not destined for a multicast address
   * (e.g. 224.0.0.0/4) ... and the payload isn't protocol 103 (PIM).
   * (see https://tools.ietf.org/html/rfc3973#section-4.7).
   */
  if (in4_addr_is_local_network_control_block(dst32)) {
    if (iph->ip_proto == IP_PROTO_IGMP)
      ttl_valid = IPLOCAL_NETWRK_CTRL_BLK_DEFAULT_TTL;
    else
      ttl_valid = local_network_control_block_addr_valid_ttl(dst32);
    if (iph->ip_ttl != ttl_valid && ttl_valid != IPLOCAL_NETWRK_CTRL_BLK_ANY_TTL) {
      expert_add_info_format(pinfo, ttl_item, &ei_ip_ttl_lncb, "\"Time To Live\" != %d for a packet sent to the "
                             "Local Network Control Block (see RFC 3171)",
                             ttl_valid);
    }
  } else if (iph->ip_ttl < 5 && !in4_addr_is_multicast(dst32) &&
        /* At least BGP should appear here as well */
        iph->ip_proto != IP_PROTO_PIM &&
        iph->ip_proto != IP_PROTO_OSPF) {
    expert_add_info_format(pinfo, ttl_item, &ei_ip_ttl_too_small, "\"Time To Live\" only %u", iph->ip_ttl);
  }

  if (tree) {
    const char *dst_host;

    memcpy(&addr, iph->ip_dst.data, 4);
    dst_host = get_hostname(addr);
    if (ip_summary_in_tree) {
      proto_item_append_text(ti, ", Dst: %s", address_with_resolution_to_str(pinfo->pool, &iph->ip_dst));
    }

    if (dst_off) {
      guint32 cur_rt;

      cur_rt = tvb_get_ipv4(tvb, offset + 16);
      if (ip_summary_in_tree) {
        proto_item_append_text(ti, ", Via: %s",
            tvb_address_with_resolution_to_str(pinfo->pool, tvb, AT_IPv4, offset + 16));
      }
      proto_tree_add_ipv4(ip_tree, hf_ip_cur_rt, tvb, offset + 16, 4, cur_rt);
      item = proto_tree_add_string(ip_tree, hf_ip_cur_rt_host, tvb,
                                   offset + 16, 4, get_hostname(cur_rt));
      proto_item_set_generated(item);
      proto_item_set_hidden(item);
    }
    else {
      proto_tree_add_ipv4(ip_tree, hf_ip_dst, tvb, offset + 16, 4, addr);
      item = proto_tree_add_ipv4(ip_tree, hf_ip_addr, tvb, offset + 16, 4,
                                 addr);
      proto_item_set_hidden(item);
      item = proto_tree_add_string(ip_tree, hf_ip_dst_host, tvb, offset + 16,
                                   4, dst_host);
      proto_item_set_generated(item);
      proto_item_set_hidden(item);
      item = proto_tree_add_string(ip_tree, hf_ip_host, tvb,
                                   offset + 16 + dst_off, 4, dst_host);
      proto_item_set_generated(item);
      proto_item_set_hidden(item);
    }

    if (ip_use_geoip) {
      add_geoip_info(ip_tree, pinfo, tvb, offset, src32, dst32);
    }
  }

  /* Decode IP options, if any. */
  if (hlen > IPH_MIN_LEN) {
    /* There's more than just the fixed-length header.  Decode the options. */
    optlen = hlen - IPH_MIN_LEN;  /* length of options, in bytes */
    field_tree = proto_tree_add_subtree_format(ip_tree, tvb, offset + 20, optlen,
                             ett_ip_options, &tf, "Options: (%u bytes)", optlen);
    dissect_ip_options(tvb, offset + 20, optlen, pinfo, field_tree, tf, iph);
  }

  p_add_proto_data(pinfo->pool, pinfo, proto_ip, pinfo->curr_layer_num, GUINT_TO_POINTER((guint)iph->ip_proto));
  tap_queue_packet(ip_tap, pinfo, iph);

  /* Skip over header + options */
  offset += hlen;

  /* If ip_defragment is on, this is a fragment, we have all the data
   * in the fragment, and the header checksum is valid, then just add
   * the fragment to the hashtable.
   */
  save_fragmented = pinfo->fragmented;
  if (ip_defragment && (iph->ip_off & (IP_MF|IP_OFFSET)) &&
      iph->ip_len > hlen &&
      tvb_bytes_exist(tvb, offset, iph->ip_len - hlen) &&
      ipsum == 0) {
    guint32 frag_id;
    frag_id = iph->ip_proto ^ iph->ip_id ^ src32 ^ dst32;
    /* XXX: Should there be a way to force the VLAN ID not to
     * be taken into account for reassembly even with non publicly
     * routable IP addresses?
     */
    if (in4_addr_is_private(dst32) || in4_addr_is_private(src32) ||
        in4_addr_is_link_local(dst32) || in4_addr_is_link_local(src32) ||
        prefs.strict_conversation_tracking_heuristics) {
      frag_id ^= pinfo->vlan_id;
    }
    ipfd_head = fragment_add_check(&ip_reassembly_table, tvb, offset,
                                   pinfo,
                                   frag_id,
                                   NULL,
                                   (iph->ip_off & IP_OFFSET) * 8,
                                   iph->ip_len - hlen,
                                   iph->ip_off & IP_MF);

    next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled IPv4",
                                        ipfd_head, &ip_frag_items,
                                        &update_col_info, ip_tree);
  } else {
    /* If this is the first fragment, dissect its contents, otherwise
       just show it as a fragment.

       XXX - if we eventually don't save the reassembled contents of all
       fragmented datagrams, we may want to always reassemble. */
    if (iph->ip_off & IP_OFFSET) {
      /* Not the first fragment - don't dissect it. */
      next_tvb = NULL;
    } else {
      /* First fragment, or not fragmented.  Dissect what we have here. */

      /* Get a tvbuff for the payload. */
      next_tvb = tvb_new_subset_remaining(tvb, offset);

      /*
       * If this is the first fragment, but not the only fragment,
       * tell the next protocol that.
       */
      if (iph->ip_off & IP_MF)
        pinfo->fragmented = TRUE;
      else
        pinfo->fragmented = FALSE;
    }
  }

  if (next_tvb == NULL) {
    /* Just show this as a fragment. */
    col_add_fstr(pinfo->cinfo, COL_INFO,
                 "Fragmented IP protocol (proto=%s %u, off=%u, ID=%04x)",
                 ipprotostr(iph->ip_proto), iph->ip_proto,
                 (iph->ip_off & IP_OFFSET) * 8, iph->ip_id);
    if ( ipfd_head && ipfd_head->reassembled_in != pinfo->num ) {
      col_append_frame_number(pinfo, COL_INFO, " [Reassembled in #%u]",
                      ipfd_head->reassembled_in);
    }

    call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo,
                   parent_tree);
    pinfo->fragmented = save_fragmented;
    return tvb_captured_length(tvb);
  }

  if (tvb_reported_length(next_tvb) > 0) {
    /* Hand off to the next protocol.

     XXX - setting the columns only after trying various dissectors means
     that if one of those dissectors throws an exception, the frame won't
     even be labeled as an IP frame; ideally, if a frame being dissected
     throws an exception, it'll be labeled as a mangled frame of the
     type in question. */
    if (!ip_try_dissect(try_heuristic_first, iph->ip_proto, next_tvb, pinfo,
                        parent_tree, iph)) {
      /* Unknown protocol */
      if (update_col_info) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s (%u)",
                   ipprotostr(iph->ip_proto), iph->ip_proto);
      }
      call_data_dissector(next_tvb, pinfo, parent_tree);
    }
  }
  pinfo->fragmented = save_fragmented;
  return tvb_captured_length(tvb);
}

static int
dissect_ip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree *ip_tree;
  proto_item *ti, *tf;
  guint8 version;

  version = tvb_get_guint8(tvb, 0) >> 4;

  if(version == 4){
    return dissect_ip_v4(tvb, pinfo, tree, data);
  }
  if(version == 6){
    return call_dissector(ipv6_handle, tvb, pinfo, tree);
  }

  /* Bogus IP version */
  ti = proto_tree_add_protocol_format(tree, proto_ip, tvb, 0, 1, "Internet Protocol, bogus version (%u)", version);
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "IP");
  col_clear(pinfo->cinfo, COL_INFO);
  col_add_fstr(pinfo->cinfo, COL_INFO, "Bogus IP version (%u)", version);
  ip_tree = proto_item_add_subtree(ti, ett_ip);
  tf = proto_tree_add_bits_item(ip_tree, hf_ip_version, tvb, 0, 4, ENC_NA);
  expert_add_info(pinfo, tf, &ei_ip_bogus_ip_version);
  return 1;
}

static gboolean
dissect_ip_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int length, tot_length;
    guint8 oct, version, ihl;

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
    length = tvb_captured_length(tvb);
    if(length<4){
        /* Need at least 4 bytes to make some sort of decision */
        return FALSE;
    }
    oct = tvb_get_guint8(tvb,0);
    ihl = oct & 0x0f;
    version = oct >> 4;
    if(version == 6){
/*
    3.  IPv6 Header Format

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |Version| Traffic Class |           Flow Label                  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |         Payload Length        |  Next Header  |   Hop Limit   |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               |
        +                                                               +
        |                                                               |
        +                         Source Address                        +
        |                                                               |
        +                                                               +
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               |
        +                                                               +
        |                                                               |
        +                      Destination Address                      +
        |                                                               |
        +                                                               +
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Version              4-bit Internet Protocol version number = 6.

        Traffic Class        8-bit traffic class field.  See section 7.

        Flow Label           20-bit flow label.  See section 6.

        Payload Length       16-bit unsigned integer.  Length of the IPv6
                             payload, i.e., the rest of the packet following
                             this IPv6 header, in octets.  (Note that any
                             extension headers [section 4] present are
                             considered part of the payload, i.e., included
                             in the length count.)


*/
        if(length<8){
            /* Need at least 8 bytes to make a decision */
            return FALSE;
        }
        tot_length = tvb_get_ntohs(tvb,4);
        if((tot_length + 40) != (int)tvb_reported_length(tvb)){
            return FALSE;
        }
        call_dissector(ipv6_handle, tvb, pinfo, tree);
        return TRUE;
    }
    /* version == IPv4 , the minimum value for a correct header is 5 */
    if((version != 4)|| (ihl < 5)){
        return FALSE;
    }
    /* Total Length is the length of the datagram, measured in octets,
     *  including internet header and data.
     */
    tot_length = tvb_get_ntohs(tvb,2);

    if(tot_length != (int)tvb_reported_length(tvb)){
        return FALSE;
    }

    dissect_ip_v4(tvb, pinfo, tree, data);
    return TRUE;
}

void
proto_register_ip(void)
{
  static hf_register_info hf[] = {
    { &hf_ip_version,
      { "Version", "ip.version", FT_UINT8, BASE_DEC,
        NULL, 0x00, NULL, HFILL }},

    // "IHL" in https://tools.ietf.org/html/rfc791#section-3.1 and
    // https://en.wikipedia.org/wiki/IPv4#Header
    { &hf_ip_hdr_len,
      { "Header Length", "ip.hdr_len", FT_UINT8, BASE_DEC,
        NULL, 0x0, "Header length in 32-bit words", HFILL }},

    { &hf_ip_dsfield,
      { "Differentiated Services Field", "ip.dsfield", FT_UINT8, BASE_HEX,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_dsfield_dscp,
      { "Differentiated Services Codepoint", "ip.dsfield.dscp", FT_UINT8, BASE_DEC | BASE_EXT_STRING,
        &dscp_vals_ext, IPDSFIELD_DSCP_MASK, NULL, HFILL }},

    { &hf_ip_dsfield_ecn,
      { "Explicit Congestion Notification", "ip.dsfield.ecn", FT_UINT8, BASE_DEC | BASE_EXT_STRING,
        &ecn_vals_ext, IPDSFIELD_ECN_MASK, NULL, HFILL }},

    { &hf_ip_tos,
      { "Type of Service", "ip.tos", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_tos_precedence,
      { "Precedence", "ip.tos.precedence", FT_UINT8, BASE_DEC,
        VALS(precedence_vals), IPTOS_PREC_MASK, NULL, HFILL }},

    { &hf_ip_tos_delay,
      { "Delay", "ip.tos.delay", FT_BOOLEAN, 8,
        TFS(&tfs_low_normal), IPTOS_LOWDELAY, NULL, HFILL }},

    { &hf_ip_tos_throughput,
      { "Throughput", "ip.tos.throughput", FT_BOOLEAN, 8,
        TFS(&tfs_high_normal), IPTOS_THROUGHPUT, NULL, HFILL }},

    { &hf_ip_tos_reliability,
      { "Reliability", "ip.tos.reliability", FT_BOOLEAN, 8,
        TFS(&tfs_high_normal), IPTOS_RELIABILITY, NULL, HFILL }},

    { &hf_ip_tos_cost,
      { "Cost", "ip.tos.cost", FT_BOOLEAN, 8,
        TFS(&tfs_low_normal), IPTOS_LOWCOST, NULL, HFILL }},

    { &hf_ip_len,
      { "Total Length", "ip.len", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_id,
      { "Identification", "ip.id", FT_UINT16, BASE_HEX_DEC,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_dst,
      { "Destination Address", "ip.dst", FT_IPv4, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_dst_host,
      { "Destination Host", "ip.dst_host", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_src,
      { "Source Address", "ip.src", FT_IPv4, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_src_host,
      { "Source Host", "ip.src_host", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_addr,
      { "Source or Destination Address", "ip.addr", FT_IPv4, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_host,
      { "Source or Destination Host", "ip.host", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},

    { &hf_geoip_country,
      { "Source or Destination GeoIP Country", "ip.geoip.country",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_geoip_country_iso,
      { "Source or Destination GeoIP ISO Two Letter Country Code", "ip.geoip.country_iso",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_geoip_city,
      { "Source or Destination GeoIP City", "ip.geoip.city",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_geoip_as_number,
      { "Source or Destination GeoIP AS Number", "ip.geoip.asnum",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_geoip_as_org,
      { "Source or Destination GeoIP AS Organization", "ip.geoip.org",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_geoip_latitude,
      { "Source or Destination GeoIP Latitude", "ip.geoip.lat",
        FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_geoip_longitude,
      { "Source or Destination GeoIP Longitude", "ip.geoip.lon",
        FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_geoip_src_summary,
      { "Source GeoIP", "ip.geoip.src_summary",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_geoip_src_country,
      { "Source GeoIP Country", "ip.geoip.src_country",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_geoip_src_country_iso,
      { "Source GeoIP ISO Two Letter Country Code", "ip.geoip.src_country_iso",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_geoip_src_city,
      { "Source GeoIP City", "ip.geoip.src_city",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_geoip_src_as_number,
      { "Source GeoIP AS Number", "ip.geoip.src_asnum",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_geoip_src_as_org,
      { "Source GeoIP AS Organization", "ip.geoip.src_org",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_geoip_src_latitude,
      { "Source GeoIP Latitude", "ip.geoip.src_lat",
        FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_geoip_src_longitude,
      { "Source GeoIP Longitude", "ip.geoip.src_lon",
        FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_geoip_dst_summary,
      { "Destination GeoIP", "ip.geoip.dst_summary",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_geoip_dst_country,
      { "Destination GeoIP Country", "ip.geoip.dst_country",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_geoip_dst_country_iso,
      { "Destination GeoIP ISO Two Letter Country Code", "ip.geoip.dst_country_iso",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_geoip_dst_city,
      { "Destination GeoIP City", "ip.geoip.dst_city",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_geoip_dst_as_number,
      { "Destination GeoIP AS Number", "ip.geoip.dst_asnum",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_geoip_dst_as_org,
      { "Destination GeoIP AS Organization", "ip.geoip.dst_org",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_geoip_dst_latitude,
      { "Destination GeoIP Latitude", "ip.geoip.dst_lat",
        FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_geoip_dst_longitude,
      { "Destination GeoIP Longitude", "ip.geoip.dst_lon",
        FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_ip_flags,
      { "Flags", "ip.flags", FT_UINT8, BASE_HEX,
        NULL, 0xE0, "Flags (3 bits)", HFILL }},

    { &hf_ip_flags_sf,
      { "Security flag", "ip.flags.sf", FT_BOOLEAN, 8,
        TFS(&flags_sf_set_evil), 0x80, "Security flag (RFC 3514)", HFILL }},

    { &hf_ip_flags_rf,
      { "Reserved bit", "ip.flags.rb", FT_BOOLEAN, 8,
        TFS(&tfs_set_notset), 0x80, NULL, HFILL }},

    { &hf_ip_flags_df,
      { "Don't fragment", "ip.flags.df", FT_BOOLEAN, 8,
        TFS(&tfs_set_notset), 0x40, NULL, HFILL }},

    { &hf_ip_flags_mf,
      { "More fragments", "ip.flags.mf", FT_BOOLEAN, 8,
        TFS(&tfs_set_notset), 0x20, NULL, HFILL }},

    { &hf_ip_frag_offset,
      { "Fragment Offset", "ip.frag_offset", FT_UINT16, BASE_DEC,
        NULL, IP_OFFSET, "Fragment offset (13 bits)", HFILL }},

    { &hf_ip_ttl,
      { "Time to Live", "ip.ttl", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_proto,
      { "Protocol", "ip.proto", FT_UINT8, BASE_DEC | BASE_EXT_STRING,
        &ipproto_val_ext, 0x0, NULL, HFILL }},

    { &hf_ip_checksum,
      { "Header Checksum", "ip.checksum", FT_UINT16, BASE_HEX,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_checksum_calculated,
    { "Calculated Checksum", "ip.checksum_calculated", FT_UINT16, BASE_HEX, NULL, 0x0,
        "The expected IP checksum field as calculated from the IP datagram", HFILL }},

    { &hf_ip_checksum_status,
      { "Header checksum status", "ip.checksum.status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
        NULL, HFILL }},

    /* IP options related fields */
    { &hf_ip_opt_type,
      { "Type", "ip.opt.type", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_opt_type_copy,
      { "Copy on fragmentation", "ip.opt.type.copy", FT_BOOLEAN, 8,
        TFS(&tfs_yes_no), IPOPT_COPY_MASK, NULL, HFILL }},

    { &hf_ip_opt_type_class,
      { "Class", "ip.opt.type.class", FT_UINT8, BASE_DEC,
        VALS(ipopt_type_class_vals), IPOPT_CLASS_MASK, NULL, HFILL }},

    { &hf_ip_opt_type_number,
      { "Number", "ip.opt.type.number", FT_UINT8, BASE_DEC,
        VALS(ipopt_type_number_vals), IPOPT_NUMBER_MASK, NULL, HFILL }},

    { &hf_ip_opt_len,
      { "Length", "ip.opt.len", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_opt_ptr,
      { "Pointer", "ip.opt.ptr", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_opt_sid,
      { "Stream Identifier", "ip.opt.sid", FT_UINT16, BASE_DEC,
        NULL, 0x0, "SATNET stream identifier", HFILL }},

    { &hf_ip_opt_mtu,
      { "MTU", "ip.opt.mtu", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_opt_id_number,
      { "ID Number", "ip.opt.id_number", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_opt_ohc,
      { "Outbound Hop Count", "ip.opt.ohc", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_opt_rhc,
      { "Return Hop Count", "ip.opt.rhc", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_opt_originator,
      { "Originator IP Address", "ip.opt.originator", FT_IPv4, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_opt_ra,
      { "Router Alert", "ip.opt.ra", FT_UINT16, BASE_DEC | BASE_RANGE_STRING,
        RVALS(ra_rvals), 0x0, NULL, HFILL }},

    { &hf_ip_opt_addr,
      { "IP Address", "ip.opt.addr", FT_IPv4, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_opt_padding,
      { "Padding", "ip.opt.padding", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_opt_qs_func,
      { "Function", "ip.opt.qs_func", FT_UINT8, BASE_DEC,
        VALS(qs_func_vals), QS_FUNC_MASK, NULL, HFILL }},

    { &hf_ip_opt_qs_rate,
      { "Rate", "ip.opt.qs_rate", FT_UINT8, BASE_DEC | BASE_EXT_STRING,
        &qs_rate_vals_ext, QS_RATE_MASK, NULL, HFILL }},

    { &hf_ip_opt_qs_ttl,
      { "QS TTL", "ip.opt.qs_ttl", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_opt_qs_ttl_diff,
      { "TTL Diff", "ip.opt.qs_ttl_diff", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_opt_qs_unused,
      { "Not Used", "ip.opt.qs_unused", FT_UINT8, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_opt_qs_nonce,
      { "QS Nonce", "ip.opt.qs_nonce", FT_UINT32, BASE_HEX,
        NULL, 0xFFFFFFFC, NULL, HFILL }},

    { &hf_ip_opt_qs_reserved,
      { "Reserved", "ip.opt.qs_reserved", FT_UINT32, BASE_HEX,
        NULL, 0x00000003, NULL, HFILL }},

    { &hf_ip_opt_sec_rfc791_sec,
      { "Security", "ip.opt.sec_rfc791_sec", FT_UINT16, BASE_HEX,
        VALS(secl_rfc791_vals), 0x0, NULL, HFILL }},

    { &hf_ip_opt_sec_rfc791_comp,
      { "Compartments", "ip.opt.sec_rfc791_comp", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_opt_sec_rfc791_hr,
      { "Handling Restrictions", "ip.opt.sec_rfc791_hr", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_opt_sec_rfc791_tcc,
      { "Transmission Control Code", "ip.opt.sec_rfc791_tcc", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_opt_sec_cl,
      { "Classification Level", "ip.opt.sec_cl", FT_UINT8, BASE_HEX,
        VALS(sec_cl_vals), 0x0, NULL, HFILL }},

    { &hf_ip_opt_sec_prot_auth_flags,
      { "Protection Authority Flags", "ip.opt.sec_prot_auth_flags", FT_UINT8, BASE_HEX,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_opt_sec_prot_auth_genser,
      { "GENSER", "ip.opt.sec_prot_auth_genser", FT_BOOLEAN, 8,
        TFS(&ip_opt_sec_prot_auth_flag_tfs), 0x80, NULL, HFILL }},

    { &hf_ip_opt_sec_prot_auth_siop_esi,
      { "SIOP-ESI", "ip.opt.sec_prot_auth_siop_esi", FT_BOOLEAN, 8,
        TFS(&ip_opt_sec_prot_auth_flag_tfs), 0x40, NULL, HFILL }},

    { &hf_ip_opt_sec_prot_auth_sci,
      { "SCI", "ip.opt.sec_prot_auth_sci", FT_BOOLEAN, 8,
        TFS(&ip_opt_sec_prot_auth_flag_tfs), 0x20, NULL, HFILL }},

    { &hf_ip_opt_sec_prot_auth_nsa,
      { "NSA", "ip.opt.sec_prot_auth_nsa", FT_BOOLEAN, 8,
        TFS(&ip_opt_sec_prot_auth_flag_tfs), 0x10, NULL, HFILL }},

    { &hf_ip_opt_sec_prot_auth_doe,
      { "DOE", "ip.opt.sec_prot_auth_doe", FT_BOOLEAN, 8,
        TFS(&ip_opt_sec_prot_auth_flag_tfs), 0x08, NULL, HFILL }},

    { &hf_ip_opt_sec_prot_auth_unassigned,
      { "Unassigned", "ip.opt.sec_prot_auth_unassigned", FT_UINT8, BASE_HEX,
        NULL, 0x06, NULL, HFILL }},

    { &hf_ip_opt_sec_prot_auth_unassigned2,
      { "Unassigned", "ip.opt.sec_prot_auth_unassigned", FT_UINT8, BASE_HEX,
        NULL, 0xFE, NULL, HFILL }},

    { &hf_ip_opt_sec_prot_auth_fti,
      { "Field Termination Indicator", "ip.opt.sec_prot_auth_fti", FT_BOOLEAN, 8,
        TFS(&ip_opt_sec_prot_auth_fti_tfs), 0x01, NULL, HFILL }},

    { &hf_ip_opt_ext_sec_add_sec_info_format_code,
      { "Additional Security Info Format Code", "ip.opt.ext_sec_add_sec_info_format_code", FT_UINT8, BASE_HEX,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_opt_ext_sec_add_sec_info,
      { "Additional Security Info", "ip.opt.ext_sec_add_sec_info", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_rec_rt,
      { "Recorded Route", "ip.rec_rt", FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_ip_rec_rt_host,
      { "Recorded Route Host", "ip.rec_rt_host", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_cur_rt,
      { "Current Route", "ip.cur_rt", FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_ip_cur_rt_host,
      { "Current Route Host", "ip.cur_rt_host", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_src_rt,
      { "Source Route", "ip.src_rt", FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_ip_src_rt_host,
      { "Source Route Host", "ip.src_rt_host", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_empty_rt,
      { "Empty Route", "ip.empty_rt", FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_ip_empty_rt_host,
      { "Empty Route Host", "ip.empty_rt_host", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_cipso_tag_type,
      { "Tag Type", "ip.cipso.tag_type", FT_UINT8, BASE_DEC,
        VALS(cipso_tag_type_vals), 0x0, NULL, HFILL }},


    { &hf_ip_fragment_overlap,
      { "Fragment overlap", "ip.fragment.overlap", FT_BOOLEAN, BASE_NONE,
        NULL, 0x0, "Fragment overlaps with other fragments", HFILL }},

    { &hf_ip_fragment_overlap_conflict,
      { "Conflicting data in fragment overlap", "ip.fragment.overlap.conflict",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "Overlapping fragments contained conflicting data", HFILL }},

    { &hf_ip_fragment_multiple_tails,
      { "Multiple tail fragments found", "ip.fragment.multipletails",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "Several tails were found when defragmenting the packet", HFILL }},

    { &hf_ip_fragment_too_long_fragment,
      { "Fragment too long", "ip.fragment.toolongfragment",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "Fragment contained data past end of packet", HFILL }},

    { &hf_ip_fragment_error,
      { "Defragmentation error", "ip.fragment.error", FT_FRAMENUM, BASE_NONE,
        NULL, 0x0, "Defragmentation error due to illegal fragments", HFILL }},

    { &hf_ip_fragment_count,
      { "Fragment count", "ip.fragment.count", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_fragment,
      { "IPv4 Fragment", "ip.fragment", FT_FRAMENUM, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_fragments,
      { "IPv4 Fragments", "ip.fragments", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},

    { &hf_ip_reassembled_in,
      { "Reassembled IPv4 in frame", "ip.reassembled_in", FT_FRAMENUM, BASE_NONE,
      NULL, 0x0, "This IPv4 packet is reassembled in this frame", HFILL }},

    { &hf_ip_reassembled_length,
      { "Reassembled IPv4 length", "ip.reassembled.length", FT_UINT32, BASE_DEC,
        NULL, 0x0, "The total length of the reassembled payload", HFILL }},

    { &hf_ip_reassembled_data,
      { "Reassembled IPv4 data", "ip.reassembled.data", FT_BYTES, BASE_NONE,
        NULL, 0x0, "The reassembled payload", HFILL }},

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_ip_cipso_doi, { "DOI", "ip.cipso.doi", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ip_cipso_sensitivity_level, { "Sensitivity Level", "ip.cipso.sensitivity_level", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ip_cipso_categories, { "Categories", "ip.cipso.categories", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ip_cipso_tag_data, { "Tag data", "ip.cipso.tag_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ip_opt_overflow, { "Overflow", "ip.opt.overflow", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }},
      { &hf_ip_opt_flag, { "Flag", "ip.opt.flag", FT_UINT8, BASE_HEX, VALS(ipopt_timestamp_flag_vals), 0x0F, NULL, HFILL }},
      { &hf_ip_opt_time_stamp, { "Time stamp", "ip.opt.time_stamp", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ip_opt_time_stamp_addr, { "Address", "ip.opt.time_stamp_addr", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},

};

  static gint *ett[] = {
    &ett_ip,
    &ett_ip_dsfield,
    &ett_ip_tos,
    &ett_ip_flags,
    &ett_ip_options,
    &ett_ip_option_eool,
    &ett_ip_option_nop,
    &ett_ip_option_sec,
    &ett_ip_option_route,
    &ett_ip_option_timestamp,
    &ett_ip_option_ext_security,
    &ett_ip_option_cipso,
    &ett_ip_option_sid,
    &ett_ip_option_mtu,
    &ett_ip_option_tr,
    &ett_ip_option_ra,
    &ett_ip_option_sdb,
    &ett_ip_option_qs,
    &ett_ip_option_other,
    &ett_ip_fragments,
    &ett_ip_fragment,
    &ett_ip_opt_type,
    &ett_ip_opt_sec_prot_auth_flags,
    &ett_ip_unknown_opt,
    &ett_geoip_info
  };
  static ei_register_info ei[] = {
     { &ei_ip_opt_len_invalid, { "ip.opt.len.invalid", PI_PROTOCOL, PI_WARN, "Invalid length for option", EXPFILL }},
     { &ei_ip_opt_sec_prot_auth_fti, { "ip.opt.len.invalid", PI_PROTOCOL, PI_WARN, "Field Termination Indicator set to 1 for last byte of option", EXPFILL }},
     { &ei_ip_extraneous_data, { "ip.opt.len.invalid", PI_PROTOCOL, PI_WARN, "Extraneous data in option", EXPFILL }},
     { &ei_ip_opt_ptr_before_address, { "ip.opt.ptr.before_address", PI_PROTOCOL, PI_WARN, "Pointer points before first address", EXPFILL }},
     { &ei_ip_opt_ptr_middle_address, { "ip.opt.ptr.middle_address", PI_PROTOCOL, PI_WARN, "Pointer points to middle of address", EXPFILL }},
     { &ei_ip_subopt_too_long, { "ip.subopt_too_long", PI_PROTOCOL, PI_WARN, "Suboption would go past end of option", EXPFILL }},
     { &ei_ip_nop, { "ip.nop", PI_PROTOCOL, PI_WARN, "4 NOP in a row - a router may have removed some options", EXPFILL }},
     { &ei_ip_bogus_ip_length, { "ip.bogus_ip_length", PI_PROTOCOL, PI_ERROR, "Bogus IP length", EXPFILL }},
     { &ei_ip_evil_packet, { "ip.evil_packet", PI_PROTOCOL, PI_WARN, "Packet has evil intent", EXPFILL }},
     { &ei_ip_checksum_bad, { "ip.checksum_bad.expert", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
     { &ei_ip_ttl_lncb, { "ip.ttl.lncb", PI_SEQUENCE, PI_NOTE, "Time To Live", EXPFILL }},
     { &ei_ip_ttl_too_small, { "ip.ttl.too_small", PI_SEQUENCE, PI_NOTE, "Time To Live", EXPFILL }},
     { &ei_ip_cipso_tag, { "ip.cipso.malformed", PI_SEQUENCE, PI_ERROR, "Malformed CIPSO tag", EXPFILL }},
     { &ei_ip_bogus_ip_version, { "ip.bogus_ip_version", PI_PROTOCOL, PI_ERROR, "Bogus IP version", EXPFILL }},
     { &ei_ip_bogus_header_length, { "ip.bogus_header_length", PI_PROTOCOL, PI_ERROR, "Bogus IP header length", EXPFILL }},
  };

  /* Decode As handling */
  static build_valid_func ip_da_build_value[1] = {ip_value};
  static decode_as_value_t ip_da_values = {ip_prompt, 1, ip_da_build_value};
  static decode_as_t ip_da = {"ip", "ip.proto", 1, 0, &ip_da_values, NULL, NULL,
                              decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

  module_t *ip_module;
  expert_module_t* expert_ip;

  proto_ip = proto_register_protocol("Internet Protocol Version 4", "IPv4", "ip");
  proto_register_field_array(proto_ip, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_ip = expert_register_protocol(proto_ip);
  expert_register_field_array(expert_ip, ei, array_length(ei));

  /* subdissector code */
  ip_dissector_table = register_dissector_table("ip.proto", "IP protocol",
                                                proto_ip, FT_UINT8, BASE_DEC);
  ip_option_table = register_dissector_table("ip.option", "IP Options",
                                                proto_ip, FT_UINT8, BASE_DEC);
  heur_subdissector_list = register_heur_dissector_list("ip", proto_ip);
  register_capture_dissector_table("ip.proto", "IP protocol");

  /* Register configuration options */
  ip_module = prefs_register_protocol(proto_ip, NULL);
  prefs_register_bool_preference(ip_module, "decode_tos_as_diffserv",
    "Decode IPv4 TOS field as DiffServ field",
    "Whether the IPv4 type-of-service field should be decoded as a "
    "Differentiated Services field (see RFC2474/RFC2475)", &g_ip_dscp_actif);
  prefs_register_bool_preference(ip_module, "defragment",
    "Reassemble fragmented IPv4 datagrams",
    "Whether fragmented IPv4 datagrams should be reassembled", &ip_defragment);
  prefs_register_bool_preference(ip_module, "summary_in_tree",
    "Show IPv4 summary in protocol tree",
    "Whether the IPv4 summary line should be shown in the protocol tree",
    &ip_summary_in_tree);
  prefs_register_bool_preference(ip_module, "check_checksum",
  "Validate the IPv4 checksum if possible",
  "Whether to validate the IPv4 checksum", &ip_check_checksum);
  prefs_register_bool_preference(ip_module, "tso_support",
    "Support packet-capture from IP TSO-enabled hardware",
    "Whether to correct for TSO-enabled (TCP segmentation offload) hardware "
    "captures, such as spoofing the IP packet length", &ip_tso_supported);
  prefs_register_bool_preference(ip_module, "use_geoip",
    "Enable IPv4 geolocation",
    "Whether to look up IP addresses in each MaxMind database we have loaded",
    &ip_use_geoip);
  prefs_register_bool_preference(ip_module, "security_flag" ,
    "Interpret Reserved flag as Security flag (RFC 3514)",
    "Whether to interpret the originally reserved flag as security flag",
    &ip_security_flag);
  prefs_register_bool_preference(ip_module, "try_heuristic_first",
    "Try heuristic sub-dissectors first",
    "Try to decode a packet using an heuristic sub-dissector before using a sub-dissector registered to a specific port",
    &try_heuristic_first);

  ip_handle = register_dissector("ip", dissect_ip, proto_ip);
  reassembly_table_register(&ip_reassembly_table,
                        &addresses_reassembly_table_functions);
  ip_tap = register_tap("ip");

  /* This needs a different (& more user-friendly) name than the other tap */
  exported_pdu_tap = register_export_pdu_tap_with_encap("IP", WTAP_ENCAP_RAW_IP);

  register_decode_as(&ip_da);
  register_conversation_table(proto_ip, TRUE, ip_conversation_packet, ip_endpoint_packet);
  register_conversation_filter("ip", "IPv4", ip_filter_valid, ip_build_filter);

  ip_cap_handle = register_capture_dissector("ip", capture_ip, proto_ip);

  /* Register IP options as their own protocols so we can get the name of the option */
  proto_ip_option_eol = proto_register_protocol_in_name_only("IP Option - End of Options List (EOL)", "End of Options List (EOL)", "ip.options.eol", proto_ip, FT_BYTES);
  proto_ip_option_nop = proto_register_protocol_in_name_only("IP Option - No-Operation (NOP)", "No Operation (NOP)", "ip.options.nop", proto_ip, FT_BYTES);
  proto_ip_option_security = proto_register_protocol_in_name_only("IP Option - Security", "Security", "ip.options.security", proto_ip, FT_BYTES);
  proto_ip_option_route = proto_register_protocol_in_name_only("IP Option - Loose Source Route", "Loose Source Route", "ip.options.route", proto_ip, FT_BYTES);
  proto_ip_option_timestamp = proto_register_protocol_in_name_only("IP Option - Time Stamp", "Time Stamp", "ip.options.timestamp", proto_ip, FT_BYTES);
  proto_ip_option_ext_security = proto_register_protocol_in_name_only("IP Option - Extended Security", "Extended Security", "ip.options.ext_security", proto_ip, FT_BYTES);
  proto_ip_option_cipso = proto_register_protocol_in_name_only("IP Option - Commercial Security", "Commercial Security", "ip.options.cipso", proto_ip, FT_BYTES);
  proto_ip_option_record_route = proto_register_protocol_in_name_only("IP Option - Record Route", "Record Route", "ip.options.record_route", proto_ip, FT_BYTES);
  proto_ip_option_sid = proto_register_protocol_in_name_only("IP Option - Stream ID", "Stream ID", "ip.options.sid", proto_ip, FT_BYTES);
  proto_ip_option_source_route = proto_register_protocol_in_name_only("IP Option - Strict Source Route", "Strict Source Route", "ip.options.source_route", proto_ip, FT_BYTES);
  proto_ip_option_mtu_probe = proto_register_protocol_in_name_only("IP Option - MTU Probe", "MTU Probe", "ip.options.mtu_probe", proto_ip, FT_BYTES);
  proto_ip_option_mtu_reply = proto_register_protocol_in_name_only("IP Option - MTU Reply", "MTU Reply", "ip.options.mtu_reply", proto_ip, FT_BYTES);
  proto_ip_option_traceroute = proto_register_protocol_in_name_only("IP Option - Traceroute", "Traceroute", "ip.options.traceroute", proto_ip, FT_BYTES);
  proto_ip_option_routeralert = proto_register_protocol_in_name_only("IP Option - Router Alert", "Router Alert", "ip.options.routeralert", proto_ip, FT_BYTES);
  proto_ip_option_sdb = proto_register_protocol_in_name_only("IP Option - Selective Directed Broadcast", "Selective Directed Broadcast", "ip.options.sdb", proto_ip, FT_BYTES);
  proto_ip_option_qs = proto_register_protocol_in_name_only("IP Option - Quick-Start", "Quick-Start", "ip.options.qs", proto_ip, FT_BYTES);
}

void
proto_reg_handoff_ip(void)
{
  dissector_handle_t ipv4_handle;
  capture_dissector_handle_t clip_cap_handle;
  int proto_clip;

  ipv6_handle = find_dissector("ipv6");
  ipv4_handle = create_dissector_handle(dissect_ip_v4, proto_ip);

  dissector_add_uint("ethertype", ETHERTYPE_IP, ipv4_handle);
  dissector_add_uint("erf.types.type", ERF_TYPE_IPV4, ip_handle);
  dissector_add_uint("ppp.protocol", PPP_IP, ip_handle);
  dissector_add_uint("ppp.protocol", ETHERTYPE_IP, ip_handle);
  dissector_add_uint("gre.proto", ETHERTYPE_IP, ip_handle);
  dissector_add_uint("gre.proto", GRE_WCCP, ip_handle);
  dissector_add_uint("llc.dsap", SAP_IP, ip_handle);
  dissector_add_uint("ip.proto", IP_PROTO_IPIP, ip_handle);
  dissector_add_uint("null.type", BSD_AF_INET, ip_handle);
  dissector_add_uint("chdlc.protocol", ETHERTYPE_IP, ip_handle);
  dissector_add_uint("osinl.excl", NLPID_IP, ip_handle);
  dissector_add_uint("fr.nlpid", NLPID_IP, ip_handle);
  dissector_add_uint("x.25.spi", NLPID_IP, ip_handle);
  dissector_add_uint("arcnet.protocol_id", ARCNET_PROTO_IP_1051, ip_handle);
  dissector_add_uint("arcnet.protocol_id", ARCNET_PROTO_IP_1201, ip_handle);
  dissector_add_uint("ax25.pid", AX25_P_IP, ip_handle);
  dissector_add_uint("juniper.proto", JUNIPER_PROTO_IP, ip_handle);
  dissector_add_uint("juniper.proto", JUNIPER_PROTO_MPLS_IP, ip_handle);
  dissector_add_uint("pwach.channel_type", PW_ACH_TYPE_IPV4, ip_handle);
  dissector_add_uint("mcc.proto", PW_ACH_TYPE_IPV4, ip_handle);
  dissector_add_uint("sflow_245.header_protocol", SFLOW_245_HEADER_IPv4, ip_handle);
  dissector_add_uint("l2tp.pw_type", L2TPv3_PW_IP, ip_handle);
  dissector_add_for_decode_as_with_preference("udp.port", ip_handle);
  dissector_add_for_decode_as("pcli.payload", ip_handle);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_RAW_IP4, ip_handle);
  dissector_add_uint("enc", BSD_AF_INET, ip_handle);
  dissector_add_uint("vxlan.next_proto", VXLAN_IPV4, ip_handle);
  dissector_add_uint("nsh.next_proto", NSH_IPV4, ip_handle);

  heur_dissector_add("tipc", dissect_ip_heur, "IP over TIPC", "ip_tipc", proto_ip, HEURISTIC_ENABLE);
  heur_dissector_add("zbee_zcl_se.tun", dissect_ip_heur, "IP over ZigBee SE Tunneling", "ip_zbee_zcl_se.tun", proto_ip, HEURISTIC_ENABLE);

  capture_dissector_add_uint("ethertype", ETHERTYPE_IP, ip_cap_handle);
  capture_dissector_add_uint("ax25.pid", AX25_P_IP, ip_cap_handle);
  capture_dissector_add_uint("enc", BSD_AF_INET, ip_cap_handle);
  capture_dissector_add_uint("ppp_hdlc", PPP_IP, ip_cap_handle);
  capture_dissector_add_uint("llc.dsap", SAP_IP, ip_cap_handle);
  capture_dissector_add_uint("null.bsd", BSD_AF_INET, ip_cap_handle);
  capture_dissector_add_uint("fr.nlpid", NLPID_IP, ip_cap_handle);

  /* Create dissection function handles for all IP options */
  dissector_add_uint("ip.option", IPOPT_SEC, create_dissector_handle( dissect_ipopt_security, proto_ip_option_security ));
  dissector_add_uint("ip.option", IPOPT_LSR, create_dissector_handle( dissect_ipopt_loose_route, proto_ip_option_route ));
  dissector_add_uint("ip.option", IPOPT_TS, create_dissector_handle( dissect_ipopt_timestamp, proto_ip_option_timestamp ));
  dissector_add_uint("ip.option", IPOPT_ESEC, create_dissector_handle( dissect_ipopt_ext_security, proto_ip_option_ext_security ));
  dissector_add_uint("ip.option", IPOPT_CIPSO, create_dissector_handle( dissect_ipopt_cipso, proto_ip_option_cipso ));
  dissector_add_uint("ip.option", IPOPT_RR, create_dissector_handle( dissect_ipopt_record_route, proto_ip_option_record_route ));
  dissector_add_uint("ip.option", IPOPT_SID, create_dissector_handle( dissect_ipopt_sid, proto_ip_option_sid ));
  dissector_add_uint("ip.option", IPOPT_SSR, create_dissector_handle( dissect_ipopt_source_route, proto_ip_option_source_route ));
  dissector_add_uint("ip.option", IPOPT_MTUP, create_dissector_handle( dissect_ipopt_mtu_probe, proto_ip_option_mtu_probe ));
  dissector_add_uint("ip.option", IPOPT_MTUR, create_dissector_handle( dissect_ipopt_mtu_reply, proto_ip_option_mtu_reply ));
  dissector_add_uint("ip.option", IPOPT_TR, create_dissector_handle( dissect_ipopt_tr, proto_ip_option_traceroute ));
  dissector_add_uint("ip.option", IPOPT_RTRALT, create_dissector_handle( dissect_ipopt_ra, proto_ip_option_routeralert ));
  dissector_add_uint("ip.option", IPOPT_SDB, create_dissector_handle( dissect_ipopt_sdb, proto_ip_option_sdb ));
  dissector_add_uint("ip.option", IPOPT_QS, create_dissector_handle( dissect_ipopt_qs, proto_ip_option_qs ));

  /* Classic IP uses the same capture function, but wants its own
     protocol associated with it.  To eliminate linking dependencies,
     just add it here */
  proto_clip = proto_get_id_by_filter_name( "clip" );
  clip_cap_handle = register_capture_dissector("clip", capture_ip, proto_clip);
  capture_dissector_add_uint("wtap_encap", WTAP_ENCAP_LINUX_ATM_CLIP, clip_cap_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
