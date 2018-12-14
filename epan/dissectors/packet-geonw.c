/* packet-geonw.c
 * Routines for GeoNetworking and BTP-A/B dissection
 * Coyright 2018, C. Guerber <cguerber@yahoo.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * The GeoNetworking protocol is a network layer protocol that provides packet
 * routing in an ad hoc network. It makes use of geographical positions for
 * packet transport. GeoNetworking supports the communication among individual
 * ITS stations as well as the distribution of packets in geographical areas.
 * (Extracted from ETSI EN 302 636-4-1)
 *
 * The Basic Transport Protocol (BTP) provides an end-to-end, connection-less
 * transport service in the ITS ad hoc network. Its main purpose is the
 * multiplexing of messages from different processes at the ITS facilities
 * layer, e.g. CAM and DENM from the cooperative awareness basic service and
 * the distributed environmental notification basic service, for the
 * transmission of packets via the GeoNetworking protocol as well as the
 * de-multiplexing at the destination.
 * (Extracted from ETSI EN 302 636-5-1)
 *
 * Reference standards:
 * ETSI EN 302 636-4-1 v1.2.0 (2013-10)
 * Intelligent Transport Systems (ITS); Vehicular Communications; GeoNetworking;
 * Part 4:     Geographical addressing and forwarding for point-to-point and
 *             point-to-multipoint communications;
 * Sub-part 1: Media-Independent Functionality
 *
 * ETSI EN 302 636-5-1 v1.2.1 (2014-08)
 * Intelligent Transport Systems (ITS); Vehicular Communications; GeoNetworking;
 * Part 5:     Transport Protocols;
 * Sub-part 1: Basic Transport Protocol
 *
 * ETSI EN 302 636-6-1 v1.2.1 (2014-05)
 * Intelligent Transport Systems (ITS); Vehicular Communications; GeoNetworking;
 * Part 6:     Internet Integration;
 * Sub-part 1: Transmission of IPv6 Packets over GeoNetworking Protocols
 *
 * ETSI TS 103 248 v1.2.1 (2018-08)
 * Intelligent Transport Systems (ITS); GeoNetworking;
 * Port Numbers for the Basic Transport Protocol (BTP)
 *
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>
#include <epan/address_types.h>
#include <epan/addr_resolv.h>
#include <epan/to_str.h>
#include <epan/to_str-int.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include <epan/etypes.h>

#include <wsutil/utf8_entities.h>
#include <wsutil/ws_printf.h>

#include "packet-e164.h"
#include "packet-geonw.h"

/*
 * Prototypes
 */
void proto_reg_handoff_btpb(void);
void proto_register_btpb(void);
void proto_reg_handoff_btpa(void);
void proto_register_btpa(void);
void proto_reg_handoff_geonw(void);
void proto_register_geonw(void);

/*
 * Constants
 */
#define HT_MASK           0xf0
#define HST_MASK          0x0f

// Definition of header types See section 8.7.4 table 9
#define HT_BEACON         0x10
#define HT_GEOUNICAST     0x20
#define HT_GEOANYCAST     0x30
#define HT_GEOBROADCAST   0x40
#define HT_TSB            0x50
#define HT_LS             0x60

// Area subtypes
#define HST_CIRCULAR      0x00
#define HST_RECTANGULAR   0x01
#define HST_ELLIPSOIDAL   0x02

// TSB subtype
#define HST_SINGLE_HOP    0x00
#define HST_MULTI_HOP     0x01

// LS subtypes
#define HST_REQUEST       0x00
#define HST_REPLY         0x01

// Types and subtype combined
#define HTST_BEACON       (HT_BEACON)
#define HTST_GEOUNICAST   (HT_GEOUNICAST)
#define HTST_GAC_CIRCLE   (HT_GEOANYCAST|HST_CIRCULAR)
#define HTST_GAC_RECT     (HT_GEOANYCAST|HST_RECTANGULAR)
#define HTST_GAC_ELLIPSE  (HT_GEOANYCAST|HST_ELLIPSOIDAL)
#define HTST_GBC_CIRCLE   (HT_GEOBROADCAST|HST_CIRCULAR)
#define HTST_GBC_RECT     (HT_GEOBROADCAST|HST_RECTANGULAR)
#define HTST_GBC_ELLIPSE  (HT_GEOBROADCAST|HST_ELLIPSOIDAL)
#define HTST_TSB_SINGLE   (HT_TSB|HST_SINGLE_HOP)
#define HTST_TSB_MULT     (HT_TSB|HST_MULTI_HOP)
#define HTST_LS_REQUEST   (HT_LS|HST_REQUEST)
#define HTST_LS_REPLY     (HT_LS|HST_REPLY)

#define BH_LEN            4
#define BH_NH_COMMON_HDR  1
#define BH_NH_SECURED_PKT 2

#define CH_LEN            8
#define CH_NH_BTP_A       1
#define CH_NH_BTP_B       2
#define CH_NH_IPV6        3

#define GUC_LEN           48
#define TSB_LEN           28
#define GAC_LEN           44
#define GBC_LEN           44
#define BEACON_LEN        24
#define LS_REQUEST_LEN    36
#define LS_REPLY_LEN      48

#define TST_MAX 0xffffffff

/*
 * Variables
 */
static wmem_map_t *geonw_hashtable = NULL;

static int proto_geonw = -1;
static int proto_btpa = -1;
static int proto_btpb = -1;

static int geonw_tap = -1;
static int btpa_tap = -1;
static int btpa_follow_tap = -1;
static int btpb_tap = -1;
static int btpb_follow_tap = -1;

static int hf_geonw_bh = -1;
static int hf_geonw_bh_version = -1;
static int hf_geonw_bh_next_header = -1;
static int hf_geonw_bh_reserved = -1;
static int hf_geonw_bh_life_time = -1;
static int hf_geonw_bh_lt_mult = -1;
static int hf_geonw_bh_lt_base = -1;
static int hf_geonw_bh_remain_hop_limit = -1;

static int hf_geonw_ch = -1;
static int hf_geonw_ch_next_header = -1;
static int hf_geonw_ch_reserved1 = -1;
static int hf_geonw_ch_header_type = -1;
//static int hf_geonw_ch_header_subtype = -1;
static int hf_geonw_ch_traffic_class = -1;
static int hf_geonw_ch_tc_scf = -1;
static int hf_geonw_ch_tc_offload = -1;
static int hf_geonw_ch_tc_id = -1;
static int hf_geonw_ch_flags = -1;
static int hf_geonw_ch_flags_mob = -1;
static int hf_geonw_ch_flags_reserved = -1;
static int hf_geonw_ch_payload_length = -1;
static int hf_geonw_ch_max_hop_limit = -1;
static int hf_geonw_ch_reserved2 = -1;

static int hf_geonw_seq_num = -1;
static int hf_geonw_reserved = -1;
static int hf_geonw_so_pv = -1;
static int hf_geonw_so_pv_addr = -1;
static int hf_geonw_so_pv_addr_manual = -1;
static int hf_geonw_so_pv_addr_type = -1;
static int hf_geonw_so_pv_addr_country = -1;
static int hf_geonw_so_pv_addr_mid = -1;
static int hf_geonw_so_pv_time = -1;
static int hf_geonw_so_pv_lat = -1;
static int hf_geonw_so_pv_lon = -1;
static int hf_geonw_so_pv_pai = -1;
static int hf_geonw_so_pv_speed = -1;
static int hf_geonw_so_pv_heading = -1;
static int hf_geonw_de_pv = -1;
static int hf_geonw_de_pv_addr = -1;
static int hf_geonw_de_pv_addr_manual = -1;
static int hf_geonw_de_pv_addr_type = -1;
static int hf_geonw_de_pv_addr_country = -1;
static int hf_geonw_de_pv_addr_mid = -1;
static int hf_geonw_de_pv_time = -1;
static int hf_geonw_de_pv_lat = -1;
static int hf_geonw_de_pv_lon = -1;

static int hf_geonw_gxc_latitude = -1;
static int hf_geonw_gxc_longitude = -1;
static int hf_geonw_gxc_radius = -1;
static int hf_geonw_gxc_distancea = -1;
static int hf_geonw_gxc_distanceb = -1;
static int hf_geonw_gxc_angle = -1;
static int hf_geonw_gxc_reserved = -1;

static int hf_geonw_shb_reserved = -1;

static int hf_geonw_lsrq_addr = -1;
static int hf_geonw_lsrq_addr_manual = -1;
static int hf_geonw_lsrq_addr_type = -1;
static int hf_geonw_lsrq_addr_country = -1;
static int hf_geonw_lsrq_addr_mid = -1;

static int hf_geonw_beacon = -1;
static int hf_geonw_guc = -1;
static int hf_geonw_gac = -1;
static int hf_geonw_gbc = -1;
static int hf_geonw_tsb = -1;
static int hf_geonw_ls = -1;
static int hf_geonw_analysis_flags = -1;

static int hf_btpa_dstport = -1;
static int hf_btpa_srcport = -1;
static int hf_btpa_port = -1;
static int hf_btpb_dstport = -1;
static int hf_btpb_dstport_info = -1;

static int hf_geonw_resp_in = -1;
static int hf_geonw_resp_to = -1;
static int hf_geonw_no_resp = -1;
static int hf_geonw_resptime = -1;

static gint ett_geonw = -1;
static gint ett_geonw_bh = -1;
static gint ett_geonw_bh_lt = -1;
static gint ett_geonw_ch = -1;
static gint ett_geonw_ch_tc = -1;
static gint ett_geonw_sh = -1;
static gint ett_geonw_so = -1;
static gint ett_geonw_so_add = -1;
static gint ett_geonw_de = -1;
static gint ett_geonw_de_add = -1;
static gint ett_geonw_lsrq_add = -1;
static gint ett_geonw_analysis = -1;
static gint ett_btpa = -1;
static gint ett_btpb = -1;

static int geonw_address_type = -1;

static expert_field ei_geonw_nz_reserved        = EI_INIT;
static expert_field ei_geonw_version_err        = EI_INIT;
static expert_field ei_geonw_rhl_lncb           = EI_INIT;
static expert_field ei_geonw_rhl_too_low        = EI_INIT;
static expert_field ei_geonw_mhl_lt_rhl         = EI_INIT;
static expert_field ei_geonw_scc_too_big        = EI_INIT;
static expert_field ei_geonw_analysis_duplicate = EI_INIT;
static expert_field ei_geonw_resp_not_found     = EI_INIT;
static expert_field ei_geonw_out_of_range       = EI_INIT;
static expert_field ei_geonw_payload_len        = EI_INIT;

static dissector_table_t geonw_subdissector_table;
static dissector_table_t btpa_subdissector_table;
static dissector_table_t btpb_subdissector_table;

static const value_string ch_header_type_names[] = {
    { HTST_BEACON, "Beacon" },
    { HTST_GEOUNICAST, "Geo Unicast" },
    { HTST_GAC_CIRCLE, "Geo-scoped Anycast Circular area" },
    { HTST_GAC_RECT, "Geo-scoped Anycast Rectangular area" },
    { HTST_GAC_ELLIPSE, "Geo-scoped Anycast Ellipsoidal area" },
    { HTST_GBC_CIRCLE, "Geo-scoped Broadcast Circular area" },
    { HTST_GBC_RECT, "Geo-scoped Broadcast Rectangular area" },
    { HTST_GBC_ELLIPSE, "Geo-scoped Broadcast Ellipsoidal area" },
    { HTST_TSB_SINGLE, "Topologucally-scoped broadcast Single-hop broadcast (SHB)" },
    { HTST_TSB_MULT, "Topologucally-scoped broadcast Multi-hop broadcast (TSB)" },
    { HTST_LS_REQUEST, "Location Service Request" },
    { HTST_LS_REPLY, "Location Service Reply" },
    { 0x00, NULL}
};

static dissector_handle_t geonw_handle;
static dissector_handle_t btpa_handle;
static dissector_handle_t btpb_handle;
static dissector_handle_t ipv6_handle;

static heur_dissector_list_t btpa_heur_subdissector_list;
static heur_dissector_list_t btpb_heur_subdissector_list;

/*
 * Basic Transport Protocol A dissector
 */
static int
dissect_btpa(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    heur_dtbl_entry_t *hdtbl_entry;
    int low_port, high_port;
    int dst_port, src_port;
    proto_item *hidden_item;
    struct btpaheader *btpah;

    btpah = wmem_new0(wmem_packet_scope(), struct btpaheader);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BTPA");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_btpa, tvb, 0, 4, ENC_NA);
    proto_tree *btpa_tree = proto_item_add_subtree(ti, ett_btpa);

    proto_tree_add_item_ret_uint(btpa_tree, hf_btpa_dstport, tvb, 0, 2, ENC_BIG_ENDIAN, &dst_port);
    proto_tree_add_item_ret_uint(btpa_tree, hf_btpa_srcport, tvb, 2, 2, ENC_BIG_ENDIAN, &src_port);

    pinfo->srcport = src_port;
    pinfo->destport = dst_port;

    col_append_ports(pinfo->cinfo, COL_INFO, PT_NONE, pinfo->srcport, pinfo->destport);

    // Add hidden port field
    hidden_item = proto_tree_add_item(btpa_tree, hf_btpa_port, tvb, 0, 2, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    hidden_item = proto_tree_add_item(btpa_tree, hf_btpa_port, tvb, 2, 2, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    btpah->btp_psrc = src_port;
    btpah->btp_pdst = dst_port;
    copy_address_shallow(&btpah->gnw_src, &pinfo->src);
    copy_address_shallow(&btpah->gnw_dst, &pinfo->dst);
    tap_queue_packet(btpa_tap, pinfo, btpah);

    tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, 4);

    if (have_tap_listener(btpa_follow_tap))
        // XXX Do as in tcp to provide port numbers?
        tap_queue_packet(btpa_follow_tap, pinfo, next_tvb);

    // XXX try heuristic first preference?

    if (src_port > dst_port) {
        low_port = dst_port;
        high_port = src_port;
    } else {
        low_port = src_port;
        high_port = dst_port;
    }

    if (dissector_try_uint_new(btpa_subdissector_table, low_port, next_tvb, pinfo, tree, TRUE, NULL))
        return tvb_captured_length(tvb);

    if (dissector_try_uint_new(btpa_subdissector_table, high_port, next_tvb, pinfo, tree, TRUE, NULL))
        return tvb_captured_length(tvb);

    if (dissector_try_heuristic(btpa_heur_subdissector_list, next_tvb, pinfo, tree, &hdtbl_entry, NULL))
        return tvb_captured_length(tvb);

    call_data_dissector(next_tvb, pinfo, tree);
    return tvb_captured_length(tvb);
}

/*
 * Basic Transport Protocol B dissector
 */
static int
dissect_btpb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    heur_dtbl_entry_t *hdtbl_entry;
    guint32 dst_port;
    guint32 dst_info;
    struct btpbheader *btpbh;

    btpbh = wmem_new0(wmem_packet_scope(), struct btpbheader);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BTPB");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_btpb, tvb, 0, 4, ENC_NA);
    proto_tree *btpb_tree = proto_item_add_subtree(ti, ett_btpb);

    proto_tree_add_item_ret_uint(btpb_tree, hf_btpb_dstport, tvb, 0, 2, ENC_BIG_ENDIAN, &dst_port);
    proto_tree_add_item_ret_uint(btpb_tree, hf_btpb_dstport_info, tvb, 2, 2, ENC_BIG_ENDIAN, &dst_info);

    pinfo->destport = dst_port;

    char buf_dst[32];
    ws_snprintf(buf_dst, 32, "%"G_GUINT16_FORMAT, dst_port);
    col_append_lstr(pinfo->cinfo, COL_INFO, " " UTF8_RIGHTWARDS_ARROW " ", buf_dst, COL_ADD_LSTR_TERMINATOR);

    // XXX Dissector table for destination port info?

    btpbh->btp_pdst = dst_port;
    btpbh->btp_idst = dst_info;
    copy_address_shallow(&btpbh->gnw_src, &pinfo->src);
    copy_address_shallow(&btpbh->gnw_dst, &pinfo->dst);
    tap_queue_packet(btpb_tap, pinfo, btpbh);

    tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, 4);

    if (have_tap_listener(btpb_follow_tap))
        // XXX Do as in tcp to provide port numbers?
        tap_queue_packet(btpb_follow_tap, pinfo, next_tvb);

    // XXX try heuristic first preference?

    if (dissector_try_uint_new(btpb_subdissector_table, dst_port, next_tvb, pinfo, tree, TRUE, NULL)) {
        return tvb_captured_length(tvb);
    }
    if (dissector_try_heuristic(btpa_heur_subdissector_list, next_tvb, pinfo, tree, &hdtbl_entry, NULL)) {
        return tvb_captured_length(tvb);
    }

    call_data_dissector(next_tvb, pinfo, tree);
    return tvb_captured_length(tvb);
}

/*
 * ===========================================================================
 * GeoNetworking dissector
 * ===========================================================================
 */

typedef struct _geonw_transaction_t {
    guint32 rqst_frame;
    guint32 resp_frame;
    nstime_t rqst_time;
    nstime_t resp_time;
} geonw_transaction_t;

typedef struct _geonw_conv_info_t {
    wmem_stack_t *unmatched_pdus;
    wmem_tree_t  *matched_pdus;
} geonw_conv_info_t;

const gchar * get_geonw_name(const guint8 *addr);
const gchar* geonw_name_resolution_str(const address* addr);
int geonw_name_resolution_len(void);

static geonw_transaction_t *transaction_start(packet_info * pinfo, proto_tree * tree);
static geonw_transaction_t *transaction_end(packet_info * pinfo, proto_tree * tree);

static gboolean geonw_analyze_seq           = TRUE;

/*
 * GeoNetworking Address Type
 */

/* Adapter from ethernet and ipv4 Address Type code */
struct hashgeonw;
typedef struct hashgeonw hashgeonw_t;

struct hashgeonw {
    guint             status;
    guint8            addr[8];
    char              hexaddr[28];
    char              resolved_name[MAXNAMELEN];

    // Node follow up used for duplication detection
    guint32           timestamp;
    guint32           sequence_number;
};


static int
geonw_str_len(const address* addr _U_)
{
    // (0/1)'.'(0..31)'.'(0..1023)'.'{eth}
    return 28;
}

static int
_geonw_to_str(const guint8* addrdata, gchar *buf, int buf_len _U_)
{
    address eth_addr;

    // Initial or Manual
    if (addrdata[0] & 0x80)
        *buf++ = '1';
    else
        *buf++ = '0';
    *buf++ = '.';
    // Station Type
    guint32_to_str_buf((addrdata[0] & 0x7C) >> 2, buf, 26);
    buf += (unsigned) strlen(buf);
    *buf++ = '.';
    // Country Code
    guint32_to_str_buf(((guint32)(addrdata[0] & 0x03) << 8) + addrdata[1], buf, 23); // > 23
    buf += (unsigned) strlen(buf);
    *buf++ = '.';
    // LL_ADDR
    set_address(&eth_addr, AT_ETHER, 6, &(addrdata[2]));
    ether_to_str(&eth_addr, buf, 18);

    return 28;
}

static int
geonw_to_str(const address* addr, gchar *buf, int buf_len _U_)
{
    return _geonw_to_str((const guint8 *)addr->data, buf, buf_len);
}

static const char*
geonw_col_filter_str(const address* addr _U_, gboolean is_src)
{
    if (is_src)
        return "geonw.src_pos.addr";

    return "geonw.dst_pos.addr";
}

static int
geonw_len(void)
{
    return 8;
}

static guint
geonw_addr_hash(gconstpointer key)
{
    return wmem_strong_hash((const guint8 *)key, 8);
}

static gboolean
geonw_addr_cmp(gconstpointer a, gconstpointer b)
{
    return (memcmp(a, b, 8) == 0);
}

/*
 * These two value_string are used for address resolv:
 */
static const value_string itss_type_small_names[] = {
    { 0,  "unk" },
    { 1,  "ped" },
    { 2,  "cyc" },
    { 3,  "mop" },
    { 4,  "mot" },
    { 5,  "pas" },
    { 6,  "bus" },
    { 7,  "ltr" },
    { 8,  "htr" },
    { 9,  "trl" },
    { 10, "spe" },
    { 11, "trm" },
    { 15, "rsu" },
    { 0, NULL}
};

/* Resolve geonetworking address */
static hashgeonw_t *
geonw_addr_resolve(hashgeonw_t *tp) {
    const guint8 *addr = tp->addr;
    guint16 val;
    char *rname = tp->resolved_name;
    address eth_addr;
    guint8 l1, l2;

    // Initial or Manual
    if (addr[0] & 0x80)
        *rname++ = 'm';
    else
        *rname++ = 'i';
    *rname++ = '.';
    // Station Type
    val = (addr[0] & 0x7C) >> 2;
    const char *string = try_val_to_str(val, itss_type_small_names);
    if (string == NULL) {
        guint32_to_str_buf(val, rname, MAXNAMELEN-2);
        l1 = (guint8) strlen(rname);
    }
    else {
        l1 = (guint8) g_strlcpy(rname, string, MAXNAMELEN-2);
    }
    rname += l1;
    *rname++ = '.';
    // Country Code
    val = ((guint32)(addr[0] & 0x03) << 8) + addr[1];
    string = try_val_to_str(val, E164_ISO3166_country_code_short_value);
    if (string == NULL) {
        guint32_to_str_buf(val, rname, MAXNAMELEN-12);
        l2 = (guint8) strlen(rname);
    }
    else {
        l2 = (guint8) g_strlcpy(rname, string, MAXNAMELEN-l1-3);
    }
    rname += l2;
    l1 += l2;
    *rname++ = '.';
    // LL_ADDR
    set_address(&eth_addr, AT_ETHER, 6, &(addr[2]));
    ether_to_str(&eth_addr, rname, 18);
    // XXX We could use ether_name_resolution_str:
    //     g_strlcpy(rname, ether_name_resolution_str(&eth_addr), MAXNAMELEN-l1-4);

    tp->status = 1;

    return tp;
}

static hashgeonw_t *
geonw_hash_new_entry(const guint8 *addr, gboolean resolve)
{
    hashgeonw_t *tp;

    tp = wmem_new(wmem_file_scope(), hashgeonw_t);
    memcpy(tp->addr, addr, sizeof(tp->addr));
    /* Values returned by bytes_to_hexstr_punct() are *not* null-terminated */
    _geonw_to_str(addr, tp->hexaddr, 28);
    tp->resolved_name[0] = '\0';
    tp->status = 0;

    if (resolve)
        geonw_addr_resolve(tp);

    wmem_map_insert(geonw_hashtable, tp->addr, tp);

    return tp;
} /* geonw_hash_new_entry */

static hashgeonw_t *
geonw_name_lookup(const guint8 *addr, gboolean resolve)
{
    hashgeonw_t  *tp;

    tp = (hashgeonw_t *)wmem_map_lookup(geonw_hashtable, addr);

    if (tp == NULL) {
        tp = geonw_hash_new_entry(addr, resolve);
    } else {
        if (resolve && !tp->status) {
            geonw_addr_resolve(tp); /* Found but needs to be resolved */
        }
    }

    return tp;

} /* geonw_name_lookup */

const gchar *
get_geonw_name(const guint8 *addr)
{
    hashgeonw_t *tp;
    gboolean resolve = gbl_resolv_flags.network_name;

    tp = geonw_name_lookup(addr, resolve);

    return resolve ? tp->resolved_name : tp->hexaddr;

} /* get_geonw_name */

const gchar* geonw_name_resolution_str(const address* addr)
{
    return get_geonw_name((const guint8 *)addr->data);
}

int geonw_name_resolution_len(void)
{
    return MAX_ADDR_STR_LEN; /* XXX - This can be lower */
}

/*
 * Conversations for GeoNetworking
 */

/* Adapted from ICMP echo request/reply code */

/* GeoNw LS request/reply transaction statistics ... XXX used by GeoNw tap(s) */
static geonw_transaction_t *transaction_start(packet_info * pinfo, proto_tree * tree)
{
    conversation_t *conversation;
    geonw_conv_info_t *geonw_info;
    geonw_transaction_t *geonw_trans;
    wmem_tree_key_t geonw_key[3];
    proto_item *it;

    /* Handle the conversation tracking */
    conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, conversation_pt_to_endpoint_type(pinfo->ptype), HT_LS, HT_LS, 0);
    if (conversation == NULL) {
        /* No, this is a new conversation. */
        conversation = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, conversation_pt_to_endpoint_type(pinfo->ptype), HT_LS, HT_LS, 0);
    }
    geonw_info = (geonw_conv_info_t *)conversation_get_proto_data(conversation, proto_geonw);
    if (geonw_info == NULL) {
        geonw_info = wmem_new(wmem_file_scope(), geonw_conv_info_t);
        geonw_info->unmatched_pdus = wmem_stack_new(wmem_file_scope());
        geonw_info->matched_pdus   = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(conversation, proto_geonw, geonw_info);
    }

    if (!PINFO_FD_VISITED(pinfo)) {
        /* this is a new request, create a new transaction structure and map it to the
           unmatched table
         */
        geonw_trans = wmem_new(wmem_file_scope(), geonw_transaction_t);
        geonw_trans->rqst_frame = pinfo->num;
        geonw_trans->resp_frame = 0;
        geonw_trans->rqst_time = pinfo->abs_ts;
        nstime_set_zero(&geonw_trans->resp_time);
        wmem_stack_push(geonw_info->unmatched_pdus, (void *) geonw_trans);
    } else {
        /* Already visited this frame */
        guint32 frame_num = pinfo->num;

        geonw_key[0].length = 1;
        geonw_key[0].key = &frame_num;
        geonw_key[1].length = 0;
        geonw_key[1].key = NULL;

        geonw_trans = (geonw_transaction_t *)wmem_tree_lookup32_array(geonw_info->matched_pdus, geonw_key);
    }
    if (geonw_trans == NULL) {
        if (PINFO_FD_VISITED(pinfo)) {
            /* No response found - add field and expert info */
            it = proto_tree_add_item(tree, hf_geonw_no_resp, NULL, 0, 0, ENC_NA);
            PROTO_ITEM_SET_GENERATED(it);

            col_append_fstr(pinfo->cinfo, COL_INFO, " (no response found!)");

            /* Expert info. */
            expert_add_info_format(pinfo, it, &ei_geonw_resp_not_found, "No response seen to LS Request");
        }

        return NULL;
    }

    /* Print state tracking in the tree */
    if (geonw_trans->resp_frame) {
        it = proto_tree_add_uint(tree, hf_geonw_resp_in, NULL, 0, 0, geonw_trans->resp_frame);
        PROTO_ITEM_SET_GENERATED(it);

        col_append_frame_number(pinfo, COL_INFO, " (reply in %u)", geonw_trans->resp_frame);
    }

    return geonw_trans;

} /* transaction_start() */

static geonw_transaction_t *transaction_end(packet_info * pinfo, proto_tree * tree)
{
    conversation_t *conversation;
    geonw_conv_info_t *geonw_info;
    geonw_transaction_t *geonw_trans;
    wmem_tree_key_t geonw_key[3];
    proto_item *it;
    nstime_t ns;
    double resp_time;

    conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, conversation_pt_to_endpoint_type(pinfo->ptype), HT_LS, HT_LS, 0);
    if (conversation == NULL) {
        return NULL;
    }

    geonw_info = (geonw_conv_info_t *)conversation_get_proto_data(conversation, proto_geonw);
    if (geonw_info == NULL) {
        return NULL;
    }

    if (!PINFO_FD_VISITED(pinfo)) {
        guint32 frame_num;

        geonw_trans = (geonw_transaction_t *)wmem_stack_peek(geonw_info->unmatched_pdus);
        if (geonw_trans == NULL) {
            return NULL;
        }

        /* we have already seen this response, or an identical one */
        if (geonw_trans->resp_frame != 0) {
            return NULL;
        }

        geonw_trans->resp_frame = pinfo->num;

        /* we found a match. Add entries to the matched table for both request and reply frames
         */
        geonw_key[0].length = 1;
        geonw_key[0].key = &frame_num;
        geonw_key[1].length = 0;
        geonw_key[1].key = NULL;

        frame_num = geonw_trans->rqst_frame;
        wmem_tree_insert32_array(geonw_info->matched_pdus, geonw_key, (void *) geonw_trans);

        frame_num = geonw_trans->resp_frame;
        wmem_tree_insert32_array(geonw_info->matched_pdus, geonw_key, (void *) geonw_trans);
    } else {
        /* Already visited this frame */
        guint32 frame_num = pinfo->num;

        geonw_key[0].length = 1;
        geonw_key[0].key = &frame_num;
        geonw_key[1].length = 0;
        geonw_key[1].key = NULL;

        geonw_trans = (geonw_transaction_t *)wmem_tree_lookup32_array(geonw_info->matched_pdus, geonw_key);

        if (geonw_trans == NULL) {
            return NULL;
        }
    }


    it = proto_tree_add_uint(tree, hf_geonw_resp_to, NULL, 0, 0, geonw_trans->rqst_frame);
    PROTO_ITEM_SET_GENERATED(it);

    nstime_delta(&ns, &pinfo->abs_ts, &geonw_trans->rqst_time);
    geonw_trans->resp_time = ns;
    resp_time = nstime_to_msec(&ns);
    it = proto_tree_add_double_format_value(tree, hf_geonw_resptime, NULL, 0, 0, resp_time, "%.3f ms", resp_time);
    PROTO_ITEM_SET_GENERATED(it);

    col_append_frame_number(pinfo, COL_INFO, " (request in %d)", geonw_trans->rqst_frame);

    return geonw_trans;

} /* transaction_end() */

// Adapted from TCP sequence number analysis

// Conversation data
struct geonw_analysis {
    // Node follow up used for duplication detection
    guint32           timestamp;
    guint16           sequence_number;
};

// The actual dissector
// XXX COL_INFO to be improved
static int
dissect_geonw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint8 bh_next_header;
    guint32 ch_next_header;
    guint32 header_type;
    guint32 rhl;
    guint32 tmp_val;
    gint offset = 0;
    proto_item *ti;
    gint hdr_len = 0;
    guint32 payload_len = 0;
    int reserved;
    guint32 timestamp;
    guint32 sequence_number = SN_MAX + 1;
    struct geonwheader *geonwh;
    gint32 latlon;

    geonwh = wmem_new0(wmem_packet_scope(), struct geonwheader);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GEONW");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    bh_next_header = tvb_get_guint8(tvb, 0) & 0x0f;
    header_type = tvb_get_guint8(tvb, 5);

    if (bh_next_header == BH_NH_SECURED_PKT) {
        hdr_len = BH_LEN;
    }
    else {
        hdr_len = BH_LEN + CH_LEN;
        switch(header_type & HT_MASK) {
            case HT_BEACON:
                hdr_len += BEACON_LEN;
                break;
            case HT_GEOUNICAST:
                hdr_len += GUC_LEN;
                break;
            case HT_GEOANYCAST:
                hdr_len += GAC_LEN;
                break;
            case HT_GEOBROADCAST:
                hdr_len += GBC_LEN;
                break;
            case HT_TSB:
                hdr_len += TSB_LEN;
                break;
            case HT_LS:
                hdr_len += LS_REQUEST_LEN;
                if (header_type == HTST_LS_REPLY) {
                    hdr_len += (LS_REPLY_LEN - LS_REQUEST_LEN);
                }
                break;
            default:
                hdr_len = -1;
        }
    }
    ti = proto_tree_add_item(tree, proto_geonw, tvb, 0, hdr_len, ENC_NA);
    proto_tree *geonw_tree = proto_item_add_subtree(ti, ett_geonw);

    // Basic Header subtree
    ti = proto_tree_add_item(geonw_tree, hf_geonw_bh, tvb, 0, 4, ENC_NA);
    proto_tree *geonw_bh_tree = proto_item_add_subtree(ti, ett_geonw_bh);

    ti = proto_tree_add_item_ret_uint(geonw_bh_tree, hf_geonw_bh_version, tvb, offset, 1, ENC_BIG_ENDIAN, &tmp_val);
    geonwh->gnw_ver = tmp_val;
    // Shall be 0
    if (tmp_val) {
        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "Bogus GeoNetworking version (%u, must be 0)", tmp_val);
        expert_add_info_format(pinfo, ti, &ei_geonw_version_err, "Bogus GeoNetworking version");
        return tvb_captured_length(tvb);
    }
    proto_tree_add_item(geonw_bh_tree, hf_geonw_bh_next_header, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    // Reserved byte
    // Expert info if not zero?
    ti = proto_tree_add_item_ret_uint(geonw_bh_tree, hf_geonw_bh_reserved, tvb, offset, 1, ENC_NA, &reserved);
    if (reserved) {
        expert_add_info(pinfo, ti, &ei_geonw_nz_reserved);
    }
    offset += 1;

    // Subtree and lt_mult and lt_base
    ti = proto_tree_add_item_ret_uint(geonw_bh_tree, hf_geonw_bh_life_time, tvb, offset, 1, ENC_BIG_ENDIAN, &tmp_val);
    geonwh->gnw_lt = tmp_val;
    proto_tree *geonw_bh_lt_tree = proto_item_add_subtree(ti, ett_geonw_bh_lt);

    proto_tree_add_item(geonw_bh_lt_tree, hf_geonw_bh_lt_mult, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(geonw_bh_lt_tree, hf_geonw_bh_lt_base, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_item *rhl_ti = proto_tree_add_item_ret_uint(geonw_bh_tree, hf_geonw_bh_remain_hop_limit, tvb, offset, 1, ENC_BIG_ENDIAN, &rhl);
    geonwh->gnw_rhl = rhl;
    /*
     * Flag a low RHL if the next header is not a common header
     */
    if (rhl < 5 && bh_next_header != BH_NH_COMMON_HDR) {
        expert_add_info_format(pinfo, rhl_ti, &ei_geonw_rhl_too_low, "\"Remain Hop Limit\" only %u", rhl);
    }
    offset += 1;

    if (bh_next_header == BH_NH_SECURED_PKT) {
        // XXX Try to decrypt?
        ti = proto_tree_add_item(tree, proto_geonw, tvb, 0, -1, ENC_NA);
        return tvb_captured_length(tvb);
    }

    if (bh_next_header == BH_NH_COMMON_HDR) {
        // Common Header subtree
        ti = proto_tree_add_item(geonw_tree, hf_geonw_ch, tvb, offset, 8, ENC_NA);
        proto_tree *geonw_ch_tree = proto_item_add_subtree(ti, ett_geonw_ch);

        // Next Header
        proto_tree_add_item_ret_uint(geonw_ch_tree, hf_geonw_ch_next_header, tvb, offset, 1, ENC_BIG_ENDIAN, &ch_next_header);
        geonwh->gnw_proto = ch_next_header;
        // Reserved
        ti = proto_tree_add_item_ret_uint(geonw_ch_tree, hf_geonw_ch_reserved1, tvb, offset, 1, ENC_NA, &reserved);
        if (reserved) {
            expert_add_info(pinfo, ti, &ei_geonw_nz_reserved);
        }
        offset += 1;

        // HT
        proto_tree_add_item_ret_uint(geonw_ch_tree, hf_geonw_ch_header_type, tvb, offset, 1, ENC_BIG_ENDIAN, &header_type);
        geonwh->gnw_htype = header_type;
        col_add_str(pinfo->cinfo, COL_INFO, val_to_str(header_type, ch_header_type_names, "Unknown (%u)"));
        offset += 1;

        /* Now that we know the header type, lets add expert info on RHL
         * RHL shall be
         *  = 1 if parameter Packet transport type in the service primitive
         *    GN-DATA.request is SHB, or if Header type HT = 1 (BEACON)
         *  = Value of optional Maximum hop limit parameter from service
         *    primitive GN-DATA.request
         *  = Otherwise GN protocol constant itsGnDefaultHopLimit if
         *    GN-DATA.request parameter Packet transport type is GUC, GBC, GBC
         *    or TSB
         * Flag a low RHL if the packet is not BEACON or SHB.
         */
        if (header_type == HTST_BEACON || header_type == HTST_TSB_SINGLE) {
            if (rhl > 1) {
                expert_add_info_format(pinfo, rhl_ti, &ei_geonw_rhl_lncb, "\"Remain Hop Limit\" != 1 for BEACON or SHB (%u)", rhl);
            }
        } else if (rhl < 5) {
            expert_add_info_format(pinfo, rhl_ti, &ei_geonw_rhl_too_low, "\"Remain Hop Limit\" only %u", rhl);
        }

        // TC
        ti = proto_tree_add_item_ret_uint(geonw_ch_tree, hf_geonw_ch_traffic_class, tvb, offset, 1, ENC_BIG_ENDIAN, &tmp_val);
        geonwh->gnw_tc = tmp_val;
        proto_tree *geonw_ch_tc_tree = proto_item_add_subtree(ti, ett_geonw_ch_tc);

        proto_tree_add_item(geonw_ch_tc_tree, hf_geonw_ch_tc_scf, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(geonw_ch_tc_tree, hf_geonw_ch_tc_offload, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(geonw_ch_tc_tree, hf_geonw_ch_tc_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        ti = proto_tree_add_item(geonw_ch_tree, hf_geonw_ch_flags, tvb, offset, 1, ENC_NA);
        proto_tree *geonw_ch_flag_tree = proto_item_add_subtree(ti, ett_geonw_ch_tc);
        // Flag (itsGnIsMobile)
        proto_tree_add_item_ret_uint(geonw_ch_flag_tree, hf_geonw_ch_flags_mob, tvb, offset, 1, ENC_BIG_ENDIAN, &tmp_val);
        geonwh->gnw_flags = tmp_val;
        ti = proto_tree_add_item_ret_uint(geonw_ch_flag_tree, hf_geonw_ch_flags_reserved, tvb, offset, 1, ENC_BIG_ENDIAN, &reserved);
        if (reserved & 0x7f) {
            expert_add_info(pinfo, ti, &ei_geonw_nz_reserved);
        }
        offset += 1;

        // PL (16 bits)
        ti = proto_tree_add_item_ret_uint(geonw_ch_tree, hf_geonw_ch_payload_length, tvb, offset, 2, ENC_BIG_ENDIAN, &payload_len);
        geonwh->gnw_len = payload_len;
        if (hdr_len > 0) { // We know the length of the header
            if (payload_len) {
                if (((header_type & HT_MASK) == HT_LS) || (header_type == HT_BEACON)) {
                    expert_add_info(pinfo, ti, &ei_geonw_nz_reserved);
                }
                else if ((payload_len + (unsigned) hdr_len) > tvb_reported_length(tvb)) {
                    expert_add_info(pinfo, ti, &ei_geonw_payload_len);
                }
                else {
                    /*
                     * Now that we know that the total length of this IP datagram isn't
                     * obviously bogus, adjust the length of this tvbuff to include only
                     * the IP datagram.
                     */
                    set_actual_length(tvb, hdr_len + payload_len);
                }
            }
            else {
                set_actual_length(tvb, hdr_len);
            }
        }
        offset += 2;

        // MHL
        proto_tree_add_item_ret_uint(geonw_ch_tree, hf_geonw_ch_max_hop_limit, tvb, offset, 1, ENC_BIG_ENDIAN, &tmp_val);
        geonwh->gnw_mhl = tmp_val;
        // Expert mhl < rhl: packet will be ignored
        if (tmp_val < rhl) {
            expert_add_info_format(pinfo, rhl_ti, &ei_geonw_mhl_lt_rhl, "Ignored: \"Remain Hop Limit\" > %u (mhl)", tmp_val);
        }
        offset += 1;

        // Reserved...
        ti = proto_tree_add_item_ret_uint(geonw_ch_tree, hf_geonw_ch_reserved2, tvb, offset, 1, ENC_NA, &reserved);
        // Expert info if not zero
        if (reserved) {
            expert_add_info(pinfo, ti, &ei_geonw_nz_reserved);
        }
        offset += 1;

        geonwh->gnw_sn = SN_MAX+1;

        proto_tree *geonw_sh_tree;
        switch(header_type & HT_MASK) {
            case HT_BEACON:
                ti = proto_tree_add_item(geonw_tree, hf_geonw_beacon, tvb, offset, hdr_len-offset, ENC_NA);
                break;
            case HT_GEOUNICAST:
                ti = proto_tree_add_item(geonw_tree, hf_geonw_guc, tvb, offset, hdr_len-offset, ENC_NA);
                break;
            case HT_GEOANYCAST:
                ti = proto_tree_add_item(geonw_tree, hf_geonw_gac, tvb, offset, hdr_len-offset, ENC_NA);
                break;
            case HT_GEOBROADCAST:
                ti = proto_tree_add_item(geonw_tree, hf_geonw_gbc, tvb, offset, hdr_len-offset, ENC_NA);
                break;
            case HT_TSB:
                ti = proto_tree_add_item(geonw_tree, hf_geonw_tsb, tvb, offset, hdr_len-offset, ENC_NA);
                break;
            case HT_LS:
                ti = proto_tree_add_item(geonw_tree, hf_geonw_ls, tvb, offset, hdr_len-offset, ENC_NA);
                break;
            default:
                // XXX Malformed or expert info?
                // Exit if header_type unknown?
                return tvb_captured_length(tvb);
        }
        geonw_sh_tree = proto_item_add_subtree(ti, ett_geonw_sh);

        switch(header_type) {
            case HTST_GEOUNICAST:
            case HTST_GAC_CIRCLE:
            case HTST_GAC_RECT:
            case HTST_GAC_ELLIPSE:
            case HTST_GBC_CIRCLE:
            case HTST_GBC_RECT:
            case HTST_GBC_ELLIPSE:
            case HTST_TSB_MULT:
            case HTST_LS_REQUEST:
            case HTST_LS_REPLY:
                // Seq num
                proto_tree_add_item_ret_uint(geonw_sh_tree, hf_geonw_seq_num, tvb, offset, 2, ENC_BIG_ENDIAN, &sequence_number);
                geonwh->gnw_sn = sequence_number;
                offset += 2;
                // 16 bits reserved
                ti = proto_tree_add_item_ret_uint(geonw_sh_tree, hf_geonw_reserved, tvb, offset, 2, ENC_BIG_ENDIAN, &reserved);
                // Expert info if not zero?
                if (reserved) {
                    expert_add_info(pinfo, ti, &ei_geonw_nz_reserved);
                }
                offset += 2;
                // XXX Seq num matching?
            case HTST_TSB_SINGLE:
            case HTST_BEACON:
                break;
        }

        // Every packet has source address
        ti = proto_tree_add_item(geonw_sh_tree, hf_geonw_so_pv, tvb, offset, 24, ENC_NA);
        proto_tree *geonw_so_tree = proto_item_add_subtree(ti, ett_geonw_so);

        ti = proto_tree_add_item(geonw_so_tree, hf_geonw_so_pv_addr, tvb, offset, 8, ENC_NA);
        proto_tree *geonw_so_add_tree = proto_item_add_subtree(ti, ett_geonw_so);
        set_address_tvb(&pinfo->net_src, geonw_address_type, 8, tvb, offset);
        copy_address_shallow(&pinfo->src, &pinfo->net_src);
        copy_address_shallow(&geonwh->gnw_src, &pinfo->src);

        proto_tree_add_item(geonw_so_add_tree, hf_geonw_so_pv_addr_manual, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(geonw_so_add_tree, hf_geonw_so_pv_addr_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        ti = proto_tree_add_item_ret_uint(geonw_so_add_tree, hf_geonw_so_pv_addr_country, tvb, offset, 2, ENC_BIG_ENDIAN, &reserved);
        if (reserved > 999) {
            expert_add_info(pinfo, ti, &ei_geonw_scc_too_big);
        }
        offset += 2;
        proto_tree_add_item(geonw_so_add_tree, hf_geonw_so_pv_addr_mid, tvb, offset, 6, ENC_NA);
        offset += 6;

        ti = proto_tree_add_item_ret_uint(geonw_so_tree, hf_geonw_so_pv_time, tvb, offset, 4, ENC_BIG_ENDIAN, &timestamp);
        geonwh->gnw_tst = timestamp;

        // XXX Is it possible to "follow" a station when updating its GN_ADDR?

        if(geonw_analyze_seq && !(pinfo->fd->flags.visited)) {
            // Duplication detection uses SN and TST or only TST (see Annex A of ETSI EN 302 636-4-1)
            // We rely on address type and hashtable as this shall be done on a per station basis (i.e. not over a conversation)
            // We do not try to consider GN_ADDR updates (due to duplicate address detection or anonymous setting)
            hashgeonw_t *tp = (hashgeonw_t *)wmem_map_lookup(geonw_hashtable, pinfo->net_src.data);
            if (tp == NULL) {
                tp = geonw_hash_new_entry((const guint8 *)pinfo->net_src.data, FALSE);
                tp->sequence_number = sequence_number;
                tp->timestamp = timestamp;
            } else {
                if ((sequence_number <= SN_MAX) && (tp->sequence_number > SN_MAX)) {
                    tp->sequence_number = sequence_number;
                    tp->timestamp = timestamp;
                }
                else if (sequence_number <= SN_MAX) {
                    /*
                     * 1   P is the received GeoNetworking packet
                     * 2   SN(P) is the sequence number in the received GeoNetworking packet
                     * 3   SN(SO) is the last received sequence number from source SO
                     * 4   SN_MAX is the maximum sequence number = 2^16 - 1
                     * 5   TST(P) is the timestamp in the received GeoNetworking packet
                     * 6   TST(SO) is the last received timestamp from source SO
                     * 7   TST_MAX is the maximum value of the timestamp = 2^32 - 1
                     * 8
                     * 9   IF (((TST(P) > TST(SO) AND ((TST(P) - TST(SO)) <= TST_MAX/2)) OR
                     *             ((TST(SO) > TST(P)) AND ((TST(SO) - TST(P)) > TST_MAX/2))) THEN
                     * 10                                                  # TST(P) is greater than TST(SO)
                     * 11      TST(SO) = TST(P)
                     * 12      SN(SO) = SN(P)                              # P is not a duplicate packet
                     * 13  ELSEIF TST(P) = TST(SO) THEN
                     * 14      IF (((SN(P) > SN(SO) AND ((SN(P) - SN(SO)) <= SN_MAX/2)) OR
                     *              ((SN(SO) > SN(P)) AND ((SN(SO) - SN(P)) > SN_MAX/2))) THEN
                     * 15                                                  # SN(P) is greater than SN(SO)
                     * 16          TST(SO) = TST(P)
                     * 17          SN(SO) = SN(P)                          # P is not a duplicate packet
                     * 18      ELSE
                     * 19                                                  # SN(P) is not greater than SN(SO)
                     * 20                                                  # P is a duplicate
                     * 21      ENDIF
                     * 22  ELSE
                     * 23                                                  # TST(P) not greater than TST(SO)
                     * 24  ENDIF
                     */
                    if (((timestamp > tp->timestamp) && (((guint64)timestamp - (guint64)tp->timestamp) <= (guint64)TST_MAX/2)) ||
                            ((tp->timestamp > timestamp) && (((guint64)tp->timestamp - (guint64)timestamp) > (guint64)TST_MAX/2))) {
                                                                    // TST(P) is greater than TST(SO)
                        tp->sequence_number = sequence_number;
                        tp->timestamp = timestamp;                  // P is not a duplicate packet
                    } else if (timestamp == tp->timestamp) {
                        if (((sequence_number > tp->sequence_number) && ((sequence_number - tp->sequence_number) <= SN_MAX/2)) ||
                             ((tp->sequence_number > sequence_number) && ((tp->sequence_number - sequence_number) > SN_MAX/2))) {
                                                                    // SN(P) is greater than SN(SO)
                            tp->timestamp = timestamp;
                            tp->sequence_number = sequence_number;  // P is not a duplicate packet
                        } else {
                                                                    // SN(P) is not greater than SN(SO)
                                                                    // P is a duplicate
                            ti = proto_tree_add_item(geonw_tree, hf_geonw_analysis_flags, tvb, 0, 0, ENC_NA);
                            PROTO_ITEM_SET_GENERATED(ti);
                            expert_add_info(pinfo, ti, &ei_geonw_analysis_duplicate);
                            col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[Duplicate packet] ");
                        }
                    } // else { # TST(P) not greater than TST(SO) }
                }
                else {
                    /*
                     * 1   P is the received GeoNetworking packet
                     * 2   TST(P) is the timestamp in the received GeoNetworking packet
                     * 3   TST(SO) is the last received timestamp from source SO
                     * 4   TS_MAX is the maximum value of the timestamp = 2^32 - 1
                     * 5
                     * 6   IF (((TST(P) > TST(SO) AND ((TST(P) - TST(SO)) <= TST_MAX/2)) OR
                     *             ((TST(SO) > TST(P)) AND ((TST(SO) - TST(P)) > TST_MAX/2))) THEN
                     * 7                                       # TST(P) is greater than TST(SO)
                     * 8       TST(SO) = TST(P)                # P is not a duplicate packet
                     * 9   ELSE
                     * 10                                      # P is a duplicate
                     * 11  ENDIF
                     */
                    if (((timestamp > tp->timestamp) && (((guint64)timestamp - (guint64)tp->timestamp) <= (guint64)TST_MAX/2)) ||
                            ((tp->timestamp > timestamp) && (((guint64)tp->timestamp - (guint64)timestamp) > (guint64)TST_MAX/2))) {
                                                        // TST(P) is greater than TST(SO)
                        tp->timestamp = timestamp;      // P is not a duplicate packet
                    } else {
                                                        // P is a duplicate
                        ti = proto_tree_add_item(geonw_tree, hf_geonw_analysis_flags, tvb, 0, 0, ENC_NA);
                        PROTO_ITEM_SET_GENERATED(ti);
                        expert_add_info(pinfo, ti, &ei_geonw_analysis_duplicate);
                        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[Duplicate packet] ");
                    }
                }
            }
        }

        offset += 4;
        ti = proto_tree_add_item_ret_int(geonw_so_tree, hf_geonw_so_pv_lat, tvb, offset, 4, ENC_BIG_ENDIAN, &latlon);
        if (latlon < -900000000 || latlon > 900000000) {
            expert_add_info_format(pinfo, ti, &ei_geonw_out_of_range, "Latitude out of range (%f)", (float)latlon/10000000);
        }
        geonwh->gnw_lat = latlon;
        offset += 4;
        ti = proto_tree_add_item_ret_int(geonw_so_tree, hf_geonw_so_pv_lon, tvb, offset, 4, ENC_BIG_ENDIAN, &latlon);
        if (latlon < -1800000000 || latlon > 1800000000) {
            expert_add_info_format(pinfo, ti, &ei_geonw_out_of_range, "Latitude out of range (%f)", (float)latlon/10000000);
        }
        geonwh->gnw_lon = latlon;
        offset += 4;
        proto_tree_add_item(geonw_so_tree, hf_geonw_so_pv_pai, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(geonw_so_tree, hf_geonw_so_pv_speed, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        ti = proto_tree_add_item_ret_uint(geonw_so_tree, hf_geonw_so_pv_heading, tvb, offset, 2, ENC_BIG_ENDIAN, &tmp_val);
        if (tmp_val > 3600) {
            expert_add_info_format(pinfo, ti, &ei_geonw_out_of_range, "Out of range [0..360] (%f)", (float)tmp_val/10);
        }
        offset += 2;

        proto_tree *geonw_de_tree = NULL;
        proto_tree *geonw_de_add_tree = NULL;
        switch(header_type) {
            case HTST_GEOUNICAST:
            case HTST_LS_REPLY:
                // Destination address
                ti = proto_tree_add_item(geonw_sh_tree, hf_geonw_de_pv, tvb, offset, 20, ENC_NA);
                geonw_de_tree = proto_item_add_subtree(ti, ett_geonw_de);

                ti = proto_tree_add_item(geonw_de_tree, hf_geonw_de_pv_addr, tvb, offset, 8, ENC_NA);
                geonw_de_add_tree = proto_item_add_subtree(ti, ett_geonw_de);
                set_address_tvb(&pinfo->net_dst, geonw_address_type, 8, tvb, offset);
                copy_address_shallow(&pinfo->dst, &pinfo->net_dst);
                copy_address_shallow(&geonwh->gnw_dst, &pinfo->dst);

                if (header_type == HTST_LS_REPLY) {
                    transaction_end(pinfo, geonw_tree);
                }
                // XXX else could "find or create conversation" using HTST_GEOUNICAST as port if needed

                proto_tree_add_item(geonw_de_add_tree, hf_geonw_de_pv_addr_manual, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(geonw_de_add_tree, hf_geonw_de_pv_addr_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                ti = proto_tree_add_item_ret_uint(geonw_de_add_tree, hf_geonw_de_pv_addr_country, tvb, offset, 2, ENC_BIG_ENDIAN, &reserved);
                if (reserved > 999) {
                    expert_add_info(pinfo, ti, &ei_geonw_scc_too_big);
                }
                offset += 2;
                proto_tree_add_item(geonw_de_add_tree, hf_geonw_de_pv_addr_mid, tvb, offset, 6, ENC_NA);
                offset += 6;

                proto_tree_add_item(geonw_de_tree, hf_geonw_de_pv_time, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                ti = proto_tree_add_item_ret_int(geonw_de_tree, hf_geonw_de_pv_lat, tvb, offset, 4, ENC_BIG_ENDIAN, &latlon);
                if (latlon < -900000000 || latlon > 900000000) {
                    expert_add_info_format(pinfo, ti, &ei_geonw_out_of_range, "Latitude out of range (%f)", (float)latlon/10000000);
                }
                offset += 4;
                ti = proto_tree_add_item_ret_int(geonw_de_tree, hf_geonw_de_pv_lon, tvb, offset, 4, ENC_BIG_ENDIAN, &latlon);
                if (latlon < -1800000000 || latlon > 1800000000) {
                    expert_add_info_format(pinfo, ti, &ei_geonw_out_of_range, "Latitude out of range (%f)", (float)latlon/10000000);
                }
                offset += 4;
                break;
            case HTST_TSB_SINGLE:
                // Reserved 32 bits
                ti = proto_tree_add_item_ret_uint(geonw_sh_tree, hf_geonw_shb_reserved, tvb, offset, 4, ENC_BIG_ENDIAN, &reserved);
                if (reserved) {
                    expert_add_info(pinfo, ti, &ei_geonw_nz_reserved);
                }
                offset += 4;
                break;
            case HTST_GAC_CIRCLE:
            case HTST_GAC_RECT:
            case HTST_GAC_ELLIPSE:
            case HTST_GBC_CIRCLE:
            case HTST_GBC_RECT:
            case HTST_GBC_ELLIPSE:
                ti = proto_tree_add_item_ret_int(geonw_sh_tree, hf_geonw_gxc_latitude, tvb, offset, 4, ENC_BIG_ENDIAN, &latlon);
                if (latlon < -900000000 || latlon > 900000000) {
                    expert_add_info_format(pinfo, ti, &ei_geonw_out_of_range, "Latitude out of range (%f)", (float)latlon/10000000);
                }
                offset += 4;
                ti = proto_tree_add_item_ret_int(geonw_sh_tree, hf_geonw_gxc_longitude, tvb, offset, 4, ENC_BIG_ENDIAN, &latlon);
                if (latlon < -1800000000 || latlon > 1800000000) {
                    expert_add_info_format(pinfo, ti, &ei_geonw_out_of_range, "Latitude out of range (%f)", (float)latlon/10000000);
                }
                offset += 4;
                switch(header_type&0x0f) {
                    case HST_CIRCULAR:
                        /*
                         * According to EN 302 363-4-1:
                         * In case of a circular area (GeoNetworking packet
                         * sub-type HST = 0), the fields shall be set to the
                         * following values:
                         *  1) Distance a is set to the radius r.
                         *  2) Distance b is set to 0.
                         *  3) Angle is set to 0.
                         */
                        proto_tree_add_item(geonw_sh_tree, hf_geonw_gxc_radius, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        ti = proto_tree_add_item_ret_uint(geonw_sh_tree, hf_geonw_gxc_distanceb, tvb, offset, 2, ENC_BIG_ENDIAN, &reserved);
                        if (reserved) {
                            expert_add_info(pinfo, ti, &ei_geonw_nz_reserved);
                        }
                        offset += 2;
                        ti = proto_tree_add_item_ret_uint(geonw_sh_tree, hf_geonw_gxc_angle, tvb, offset, 2, ENC_BIG_ENDIAN, &reserved);
                        if (reserved) {
                            expert_add_info(pinfo, ti, &ei_geonw_nz_reserved);
                        }
                        offset += 2;
                        break;
                    case HST_RECTANGULAR:
                    case HST_ELLIPSOIDAL:
                        proto_tree_add_item(geonw_sh_tree, hf_geonw_gxc_distancea, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        proto_tree_add_item(geonw_sh_tree, hf_geonw_gxc_distanceb, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        ti = proto_tree_add_item_ret_uint(geonw_sh_tree, hf_geonw_gxc_angle, tvb, offset, 2, ENC_BIG_ENDIAN, &tmp_val);
                        if (tmp_val > 360) {
                            expert_add_info_format(pinfo, ti, &ei_geonw_out_of_range, "Out of range [0..360] (%f)", (float)tmp_val);
                        }
                        offset += 2;
                }
                ti = proto_tree_add_item_ret_uint(geonw_sh_tree, hf_geonw_gxc_reserved, tvb, offset, 2, ENC_BIG_ENDIAN, &reserved);
                if (reserved) {
                    expert_add_info(pinfo, ti, &ei_geonw_nz_reserved);
                }
                offset += 2;
                break;
            case HTST_LS_REQUEST:
                // GN_ADDR
                ti = proto_tree_add_item(geonw_sh_tree, hf_geonw_lsrq_addr, tvb, offset, 8, ENC_NA);
                geonw_de_add_tree = proto_item_add_subtree(ti, ett_geonw_lsrq_add);
                set_address_tvb(&pinfo->net_dst, geonw_address_type, 8, tvb, offset);
                copy_address_shallow(&pinfo->dst, &pinfo->net_dst);

                proto_tree_add_item(geonw_de_add_tree, hf_geonw_lsrq_addr_manual, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(geonw_de_add_tree, hf_geonw_lsrq_addr_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                ti = proto_tree_add_item_ret_uint(geonw_de_add_tree, hf_geonw_lsrq_addr_country, tvb, offset, 2, ENC_BIG_ENDIAN, &reserved);
                if (reserved > 999) {
                    expert_add_info(pinfo, ti, &ei_geonw_scc_too_big);
                }
                offset += 2;
                proto_tree_add_item(geonw_de_add_tree, hf_geonw_lsrq_addr_mid, tvb, offset, 6, ENC_NA);
                offset += 6;
                transaction_start(pinfo, geonw_tree);
                break;
            //case HTST_BEACON:
            //case HTST_TSB_MULT:
        }

        tap_queue_packet(geonw_tap, pinfo, geonwh);

        if (payload_len) {
            // TODO expert info if payload_len different from remaining
            tvbuff_t *next_tvb = tvb_new_subset_length(tvb, offset, payload_len);
            switch(ch_next_header) {
                case CH_NH_BTP_A:
                    call_dissector(btpa_handle, next_tvb, pinfo, tree);
                    break;
                case CH_NH_BTP_B:
                    call_dissector(btpb_handle, next_tvb, pinfo, tree);
                    break;
                case CH_NH_IPV6:
                    call_dissector(ipv6_handle, next_tvb, pinfo, tree);
                    break;
                default:
                    if (!dissector_try_uint(geonw_subdissector_table, ch_next_header, next_tvb, pinfo, tree)) {
                        call_data_dissector(next_tvb, pinfo, tree);
                    }
            }
        }

    }

    return tvb_captured_length(tvb);
}

/*
 * Decode_as
 */
static void
btpa_src_prompt(packet_info *pinfo _U_, gchar* result)
{
    guint32 port = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, hf_btpa_srcport, pinfo->curr_layer_num));

    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "source (%u%s)", port, UTF8_RIGHTWARDS_ARROW);
}

static gpointer
btpa_src_value(packet_info *pinfo _U_)
{
    return p_get_proto_data(pinfo->pool, pinfo, hf_btpa_srcport, pinfo->curr_layer_num);
}

static void
btpa_dst_prompt(packet_info *pinfo, gchar *result)
{
    guint32 port = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, hf_btpa_dstport, pinfo->curr_layer_num));

    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "destination (%s%u)", UTF8_RIGHTWARDS_ARROW, port);
}

static gpointer
btpa_dst_value(packet_info *pinfo)
{
    return p_get_proto_data(pinfo->pool, pinfo, hf_btpa_dstport, pinfo->curr_layer_num);
}

static void
btpa_both_prompt(packet_info *pinfo, gchar *result)
{
    guint32 srcport = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, hf_btpa_srcport, pinfo->curr_layer_num)),
            destport = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, hf_btpa_dstport, pinfo->curr_layer_num));
    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "both (%u%s%u)", srcport, UTF8_LEFT_RIGHT_ARROW, destport);
}

static void
btpb_dst_prompt(packet_info *pinfo, gchar *result)
{
    guint32 port = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, hf_btpb_dstport, pinfo->curr_layer_num));

    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "destination (%s%u)", UTF8_RIGHTWARDS_ARROW, port);
}

static gpointer
btpb_dst_value(packet_info *pinfo)
{
    return p_get_proto_data(pinfo->pool, pinfo, hf_btpb_dstport, pinfo->curr_layer_num);
}

/*
 * Register
 */
void
proto_register_btpa(void)
{
    static hf_register_info hf_btpa[] = {
        // BTP A
        { &hf_btpa_dstport,
          { "Destination Port", "btpa.dstport",
            FT_UINT16, BASE_PT_UDP, NULL, 0x0,
            NULL, HFILL }},

        { &hf_btpa_srcport,
          { "Source Port", "btpa.srcport",
            FT_UINT16, BASE_PT_UDP, NULL, 0x0,
            NULL, HFILL }},

        { &hf_btpa_port,
          { "Port", "btpa.port",
            FT_UINT16, BASE_PT_UDP, NULL, 0x0,
            NULL, HFILL }},

    };
    static gint *ett[] = {
        &ett_btpa,
    };
    proto_btpa = proto_register_protocol("BTP-A", "BTPA", "btpa");
    btpa_handle = register_dissector("btpa", dissect_btpa, proto_btpa);
    proto_register_field_array(proto_btpa, hf_btpa, array_length(hf_btpa));

    proto_register_subtree_array(ett, array_length(ett));

    // Register subdissector table
    btpa_subdissector_table = register_dissector_table("btpa.port",
        "BTP-A port", proto_btpa, FT_UINT16, BASE_HEX);

    btpa_heur_subdissector_list = register_heur_dissector_list("btpa.payload", proto_btpa);

    // Decode as
    static build_valid_func btpa_da_src_values[1] = {btpa_src_value};
    static build_valid_func btpa_da_dst_values[1] = {btpa_dst_value};
    static build_valid_func btpa_da_both_values[2] = {btpa_src_value, btpa_dst_value};
    static decode_as_value_t btpa_da_values[3] = {{btpa_src_prompt, 1, btpa_da_src_values}, {btpa_dst_prompt, 1, btpa_da_dst_values}, {btpa_both_prompt, 2, btpa_da_both_values}};
    static decode_as_t btpa_da = {"btpa", "Transport", "btpa.port", 3, 2, btpa_da_values, "BTP-A", "port(s) as",
                                 decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    register_decode_as(&btpa_da);
}

void
proto_reg_handoff_btpa(void)
{
    dissector_handle_t btpa_handle_;

    btpa_handle_ = create_dissector_handle(dissect_btpa, proto_btpa);
    dissector_add_uint("geonw.ch.nh", 1, btpa_handle_);

    find_dissector_add_dependency("gnw", proto_btpa);

    btpa_tap = register_tap("btpa");
    btpa_follow_tap = register_tap("btpa_follow");
}

void
proto_register_btpb(void)
{
    static hf_register_info hf_btpb[] = {
        // BTP B
        { &hf_btpb_dstport,
          { "Destination Port", "btpb.dstport",
            FT_UINT16, BASE_PT_UDP, NULL, 0x0,
            NULL, HFILL }},

        { &hf_btpb_dstport_info,
          { "Destination Port info", "btpb.dstportinf",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

    };
    static gint *ett[] = {
        &ett_btpb,
    };
    proto_btpb = proto_register_protocol("BTP-B", "BTPB", "btpb");
    btpb_handle = register_dissector("btpb", dissect_btpb, proto_btpb);
    proto_register_field_array(proto_btpb, hf_btpb, array_length(hf_btpb));

    proto_register_subtree_array(ett, array_length(ett));

    // Register subdissector table
    btpb_subdissector_table = register_dissector_table("btpb.port",
        "BTP-B dst port", proto_btpb, FT_UINT16, BASE_HEX);

    btpb_heur_subdissector_list = register_heur_dissector_list("btpb.payload", proto_btpb);

    // Decode as
    static build_valid_func btpb_da_build_value[1] = {btpb_dst_value};
    static decode_as_value_t btpb_da_values = {btpb_dst_prompt, 1, btpb_da_build_value};
    static decode_as_t btpb_da = {"btpb", "BTP-B dest. port", "btpb.port", 1, 0, &btpb_da_values, NULL, NULL,
                                    decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    register_decode_as(&btpb_da);
}

void
proto_reg_handoff_btpb(void)
{
    dissector_handle_t btpb_handle_;

    btpb_handle_ = create_dissector_handle(dissect_btpb, proto_btpb);
    dissector_add_uint("geonw.ch.nh", 2, btpb_handle_);

    find_dissector_add_dependency("gnw", proto_btpb);

    btpb_tap = register_tap("btpb");
    btpb_follow_tap = register_tap("btpb_follow");
}

// Display functions
static void
display_latitude( gchar *result, gint32 hexver )
{
    g_snprintf( result, ITEM_LABEL_LENGTH, "%ud%u'%.2f\"%c",
            abs(hexver)/10000000,
            abs(hexver%10000000)*6/1000000,
            abs(hexver*6%1000000)*6./100000.,
            hexver>=0?'N':'S');
}

static void
display_longitude( gchar *result, gint32 hexver )
{
    g_snprintf( result, ITEM_LABEL_LENGTH, "%ud%u'%.2f\"%c",
            abs(hexver)/10000000,
            abs(hexver%10000000)*6/1000000,
            abs(hexver*6%1000000)*6./100000.,
            hexver>=0?'E':'W');
}

static void
display_speed( gchar *result, gint32 hexver )
{
    g_snprintf( result, ITEM_LABEL_LENGTH, "%.2f m/s", abs(hexver)/100.);
}

static void
display_heading( gchar *result, guint32 hexver )
{
    g_snprintf( result, ITEM_LABEL_LENGTH, "%.1f degrees", hexver/10.);
}

void
proto_register_geonw(void)
{
    static const value_string bh_next_header_names[] = {
        { 1, "Common Header" },
        { 2, "Secured Packet" },
        { 0, NULL}
    };

    static const value_string bh_lt_base_names[] = {
        { 0, "50 ms" },
        { 1, "1 s" },
        { 2, "10 s" },
        { 3, "100 s"},
        { 0, NULL}
    };

    static const value_string ch_next_header_names[] = {
        { CH_NH_BTP_A, "BTP-A Transport protocol" },
        { CH_NH_BTP_B, "BTP-B Transport protocol" },
        { CH_NH_IPV6, "IPv6 header" },
        { 0, NULL}
    };

    static const value_string itss_type_names[] = {
        { 0, "Unknown" },
        { 1, "Pedestrian" },
        { 2, "Cyclist" },
        { 3, "Moped" },
        { 4, "Motorcycle" },
        { 5, "Passenger Car" },
        { 6, "Bus" },
        { 7, "Light Truck" },
        { 8, "Heavy Truck" },
        { 9, "Trailer" },
        { 10, "Special Vehicle" },
        { 11, "Tram" },
        { 15, "Road Side Unit" },
        { 0, NULL}
    };

    static hf_register_info hf_geonw[] = {

        { &hf_geonw_bh,
         { "Basic Header", "geonw.bh", FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        { &hf_geonw_bh_version,
          { "Version", "geonw.bh.version",
            FT_UINT8, BASE_DEC, NULL, 0xF0,
            NULL, HFILL }},

        { &hf_geonw_bh_reserved,
         { "Reserved", "geonw.bh.reserved", FT_UINT8,
           BASE_HEX, NULL, 0x0, "It SHOULD be set to 0", HFILL }},

        { &hf_geonw_bh_next_header,
          { "Next Header", "geonw.bh.nh",
            FT_UINT8, BASE_DEC, VALS(bh_next_header_names), 0x0F,
            NULL, HFILL }},

        { &hf_geonw_bh_life_time,
          { "Life Time", "geonw.bh.lt",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }},

        { &hf_geonw_bh_lt_mult,
          { "Life Time multiplier", "geonw.bh.lt.mult",
            FT_UINT8, BASE_DEC, NULL, 0xFC,
            NULL, HFILL }},

        { &hf_geonw_bh_lt_base,
          { "Life Time base", "geonw.bh.lt.base",
            FT_UINT8, BASE_DEC, VALS(bh_lt_base_names), 0x03,
            NULL, HFILL }},

        { &hf_geonw_bh_remain_hop_limit,
          { "Remaining Hop Limit", "geonw.bh.rhl",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }},

        { &hf_geonw_ch,
         { "Common Header", "geonw.ch", FT_NONE, BASE_NONE, NULL, 0x0,
           NULL, HFILL }},

        { &hf_geonw_ch_next_header,
          { "Next Header", "geonw.ch.nh",
            FT_UINT8, BASE_DEC, VALS(ch_next_header_names), 0xF0,
            NULL, HFILL }},

        { &hf_geonw_ch_reserved1,
         { "Reserved", "geonw.ch.reserved1", FT_UINT8,
           BASE_HEX, NULL, 0x0F, "It SHOULD be set to 0", HFILL }},

        { &hf_geonw_ch_header_type,
          { "Header type", "geonw.ch.htype",
            FT_UINT8, BASE_HEX, VALS(ch_header_type_names), 0x00,
            NULL, HFILL }},

        { &hf_geonw_ch_traffic_class,
          { "Traffic class", "geonw.ch.tclass",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }},

        { &hf_geonw_ch_tc_scf,
          { "Store Carry Forward", "geonw.ch.tc.buffer",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }},

        { &hf_geonw_ch_tc_offload,
          { "Channel offload", "geonw.ch.tc.offload",
            FT_UINT8, BASE_DEC, NULL, 0x40,
            NULL, HFILL }},

        { &hf_geonw_ch_tc_id,
          { "Mobility", "geonw.ch.tc.id",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }},

        { &hf_geonw_ch_flags,
         { "Flags", "geonw.ch.flags", FT_NONE,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_geonw_ch_flags_mob,
          { "Mobility flag", "geonw.ch.flags.mob",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }},

        { &hf_geonw_ch_flags_reserved,
          { "Reserved", "geonw.ch.flags.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x7F,
            NULL, HFILL }},

        { &hf_geonw_ch_payload_length,
          { "Payload length", "geonw.ch.plength",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }},

        { &hf_geonw_ch_max_hop_limit,
          { "Maximum Hop Limit", "geonw.ch.mhl",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }},

        { &hf_geonw_ch_reserved2,
         { "Reserved", "geonw.ch.reserved2", FT_UINT8,
           BASE_HEX, NULL, 0x00, "It SHOULD be set to 0", HFILL }},

        { &hf_geonw_seq_num,
          { "Sequence number", "geonw.seq_num",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }},

        { &hf_geonw_reserved,
          { "Reserved", "geonw.reserved",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }},

        // Long Position
        { &hf_geonw_so_pv,
          { "Source position", "geonw.src_pos",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }},

        { &hf_geonw_so_pv_addr,
          { "GN_ADDR", "geonw.src_pos.addr",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }},

        { &hf_geonw_so_pv_addr_manual,
          { "Manual", "geonw.src_pos.addr.manual",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }},

        { &hf_geonw_so_pv_addr_type,
          { "ITS-S type", "geonw.src_pos.addr.type",
            FT_UINT8, BASE_DEC, VALS(itss_type_names), 0x7C,
            NULL, HFILL }},

        { &hf_geonw_so_pv_addr_country,
          { "ITS-S Country Code", "geonw.src_pos.addr.country",
            FT_UINT16, BASE_DEC, VALS(E164_country_code_value), 0x03FF,
            NULL, HFILL }},

        { &hf_geonw_so_pv_addr_mid,
          { "MID", "geonw.src_pos.addr.mid",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_geonw_so_pv_time,
          { "Timestamp", "geonw.src_pos.tst",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x00,
            NULL, HFILL }},

        { &hf_geonw_so_pv_lat,
          { "Latitude", "geonw.src_pos.lat",
            FT_INT32, BASE_CUSTOM, CF_FUNC(display_latitude), 0x00,
            NULL, HFILL }},

        { &hf_geonw_so_pv_lon,
          { "Longitude", "geonw.src_pos.long",
            FT_INT32, BASE_CUSTOM, CF_FUNC(display_longitude), 0x00,
            NULL, HFILL }},

        { &hf_geonw_so_pv_pai,
          { "Position accuracy indicator", "geonw.src_pos.pai",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }},

        { &hf_geonw_so_pv_speed,
          { "Speed", "geonw.src_pos.speed",
            FT_INT16, BASE_CUSTOM, CF_FUNC(display_speed), 0x00,
            NULL, HFILL }},

        { &hf_geonw_so_pv_heading,
          { "Heading", "geonw.src_pos.hdg",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(display_heading), 0x00,
            NULL, HFILL }},

        // Short Position
        { &hf_geonw_de_pv,
          { "Destination position", "geonw.dst_pos",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }},

        { &hf_geonw_de_pv_addr,
          { "GN_ADDR", "geonw.dst_pos.addr",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }},

        { &hf_geonw_de_pv_addr_manual,
          { "Manual", "geonw.dst_pos.addr.manual",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }},

        { &hf_geonw_de_pv_addr_type,
          { "ITS-S type", "geonw.dst_pos.addr.type",
            FT_UINT8, BASE_DEC, VALS(itss_type_names), 0x7C,
            NULL, HFILL }},

        { &hf_geonw_de_pv_addr_country,
          { "ITS-S Country Code", "geonw.dst_pos.addr.country",
            FT_UINT16, BASE_DEC, VALS(E164_country_code_value), 0x03FF,
            NULL, HFILL }},

        { &hf_geonw_de_pv_addr_mid,
          { "MID", "geonw.dst_pos.addr.mid",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_geonw_de_pv_time,
          { "Timestamp", "geonw.dst_pos.tst",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0x00,
            NULL, HFILL }},

        { &hf_geonw_de_pv_lat,
          { "Latitude", "geonw.dst_pos.lat",
            FT_INT32, BASE_CUSTOM, CF_FUNC(display_latitude), 0x00,
            NULL, HFILL }},

        { &hf_geonw_de_pv_lon,
          { "Longitude", "geonw.dst_pos.long",
            FT_INT32, BASE_CUSTOM, CF_FUNC(display_longitude), 0x00,
            NULL, HFILL }},

        // GBC/GAC
        { &hf_geonw_gxc_latitude,
          { "Latitude", "geonw.gxc.latitude",
            FT_INT32, BASE_CUSTOM, CF_FUNC(display_latitude), 0x00,
            NULL, HFILL }},

        { &hf_geonw_gxc_longitude,
          { "Longitude", "geonw.gxc.longitude",
            FT_INT32, BASE_CUSTOM, CF_FUNC(display_longitude), 0x00,
            NULL, HFILL }},

        { &hf_geonw_gxc_radius,
          { "Radius r", "geonw.gxc.radius",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_meters, 0x00,
            NULL, HFILL }},

        { &hf_geonw_gxc_distancea,
          { "Distance a", "geonw.gxc.distancea",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_meters, 0x00,
            NULL, HFILL }},

        { &hf_geonw_gxc_distanceb,
          { "Distance b", "geonw.gxc.distanceb",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_meters, 0x00,
            NULL, HFILL }},

        { &hf_geonw_gxc_angle,
          { "Angle", "geonw.gxc.angle",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_degree_degrees, 0x00,
            NULL, HFILL }},

        { &hf_geonw_gxc_reserved,
          { "Reserved", "geonw.gxc.reserved",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }},

        // SHB
        { &hf_geonw_shb_reserved,
          { "Reserved", "geonw.shb.reserved",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }},

        // LS Request
        { &hf_geonw_lsrq_addr,
          { "GN_ADDR", "geonw.ls_req.addr",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }},

        { &hf_geonw_lsrq_addr_manual,
          { "Manual", "geonw.ls_req.addr.manual",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }},

        { &hf_geonw_lsrq_addr_type,
          { "ITS-S type", "geonw.ls_req.addr.type",
            FT_UINT8, BASE_DEC, VALS(itss_type_names), 0x7C,
            NULL, HFILL }},

        { &hf_geonw_lsrq_addr_country,
          { "ITS-S Country Code", "geonw.ls_req.addr.country",
            FT_UINT16, BASE_DEC, VALS(E164_country_code_value), 0x03FF,
            NULL, HFILL }},

        { &hf_geonw_lsrq_addr_mid,
          { "MID", "geonw.ls_req.addr.mid",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_geonw_beacon,
         { "Beacon Packet", "geonw.beacon", FT_NONE,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_geonw_guc,
         { "GeoUniCast Packet", "geonw.guc", FT_NONE,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_geonw_gac,
         { "GeoAnyCast Packet", "geonw.gac", FT_NONE,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_geonw_gbc,
         { "GeoBroadCast Packet", "geonw.gbc", FT_NONE,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_geonw_tsb,
         { "Topologically-Scoped Broadcast Packet", "geonw.gbc", FT_NONE,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_geonw_ls,
         { "Location Service Packet", "geonw.ls", FT_NONE,
           BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_geonw_resp_in,
         { "Response frame", "geonw.resp_in", FT_FRAMENUM, BASE_NONE,
           FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
           "The frame number of the corresponding response",
           HFILL}},

        { &hf_geonw_no_resp,
         { "No response seen", "geonw.no_resp", FT_NONE, BASE_NONE,
           NULL, 0x0,
           "No corresponding response frame was seen",
           HFILL}},

        { &hf_geonw_resp_to,
         { "Request frame", "geonw.resp_to", FT_FRAMENUM, BASE_NONE,
           FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
           "The frame number of the corresponding request", HFILL}},

        { &hf_geonw_resptime,
         { "Response time", "geonw.resptime", FT_DOUBLE, BASE_NONE,
           NULL, 0x0,
           "The time between the request and the response, in ms.",
           HFILL}},

        { &hf_geonw_analysis_flags,
        { "GeoNetworking Analysis Flags",     "geonw.analysis.flags", FT_NONE, BASE_NONE, NULL, 0x0,
            "This frame has some of the GeoNetworking analysis flags set", HFILL }},

    };
    static ei_register_info ei[] = {
        { &ei_geonw_nz_reserved, { "geonw.reserved_not_zero", PI_PROTOCOL, PI_WARN, "Incorrect, should be 0", EXPFILL }},
        { &ei_geonw_version_err, { "geonw.bogus_version", PI_MALFORMED, PI_ERROR, "Bogus GeoNetworking Version", EXPFILL }},
        { &ei_geonw_rhl_lncb,    { "geonw.rhl.lncb", PI_SEQUENCE, PI_NOTE, "Remaining Hop Limit", EXPFILL }},
        { &ei_geonw_rhl_too_low, { "geonw.rhl.too_small", PI_SEQUENCE, PI_NOTE, "Remaining Hop Limit", EXPFILL }},
        { &ei_geonw_mhl_lt_rhl,  { "geonw.rhl.ht_mhl", PI_SEQUENCE, PI_WARN, "Remaining Hop Limit To Live", EXPFILL }},
        { &ei_geonw_scc_too_big, { "geonw.scc_too_big", PI_MALFORMED, PI_ERROR, "Country code should be less than 1000", EXPFILL }},
        { &ei_geonw_analysis_duplicate, { "geonw.analysis_duplicate", PI_SEQUENCE, PI_NOTE, "Duplicate packet", EXPFILL }},
        { &ei_geonw_resp_not_found, { "geonw.resp_not_found", PI_SEQUENCE, PI_WARN, "Response not found", EXPFILL }},
        { &ei_geonw_out_of_range, { "geonw.position_oor", PI_MALFORMED, PI_WARN, "Position out of range", EXPFILL }},
        { &ei_geonw_payload_len, { "geonw.bogus_geonw_length", PI_PROTOCOL, PI_ERROR, "Bogus GeoNetworking length", EXPFILL }},
    };
    static gint *ett[] = {
        &ett_geonw,
        &ett_geonw_bh,
        &ett_geonw_bh_lt,
        &ett_geonw_ch,
        &ett_geonw_ch_tc,
        &ett_geonw_sh,
        &ett_geonw_so,
        &ett_geonw_so_add,
        &ett_geonw_de,
        &ett_geonw_de_add,
        &ett_geonw_lsrq_add,
        &ett_geonw_analysis,
    };

    expert_module_t* expert_geonw;
    module_t *geonw_module;

    proto_geonw = proto_register_protocol("GeoNetworking", "GNW", "gnw");


    geonw_handle = register_dissector("gnw", dissect_geonw, proto_geonw);

    proto_register_field_array(proto_geonw, hf_geonw, array_length(hf_geonw));
    proto_register_subtree_array(ett, array_length(ett));

    expert_geonw = expert_register_protocol(proto_geonw);
    expert_register_field_array(expert_geonw, ei, array_length(ei));

    geonw_subdissector_table = register_dissector_table("geonw.ch.nh",
        "GeoNetworking Next Header", proto_geonw, FT_UINT8, BASE_HEX);

    geonw_address_type = address_type_dissector_register("AT_GEONW", "GeoNetworking address", geonw_to_str, geonw_str_len, NULL, geonw_col_filter_str, geonw_len, geonw_name_resolution_str, geonw_name_resolution_len);

    /* Register configuration preferences */
    geonw_module = prefs_register_protocol(proto_geonw, NULL);
    prefs_register_bool_preference(geonw_module, "analyze_sequence_numbers",
        "Analyze GeoNetworking sequence numbers",
        "Make the GeoNetworking dissector analyze GeoNetworking sequence numbers to find and flag duplicate packet (Annex A)",
        &geonw_analyze_seq);

    geonw_hashtable = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), geonw_addr_hash, geonw_addr_cmp);
}

void
proto_reg_handoff_geonw(void)
{
    dissector_handle_t geonw_handle_;

    geonw_handle_ = create_dissector_handle(dissect_geonw, proto_geonw);

    dissector_add_uint_with_preference("ethertype", ETHERTYPE_GEONETWORKING, geonw_handle_);

    // IPv6 over GeoNetworking Protocols
    ipv6_handle = find_dissector("ipv6");
    dissector_add_uint("geonw.ch.nh", 3, ipv6_handle);

    geonw_tap = register_tap("geonw");
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
