/* packet-gre.c
 * Routines for the Generic Routing Encapsulation (GRE) protocol
 * Brad Robel-Forrest <brad.robel-forrest@watchguard.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/etypes.h>
#include <epan/in_cksum.h>
#include <epan/expert.h>
#include <epan/ipproto.h>
#include <epan/llcsaps.h>
#include "packet-gre.h"
#include "packet-wccp.h"

#define GRE_IN_UDP_PORT 4754

void proto_register_gre(void);
void proto_reg_handoff_gre(void);

/*
 * See RFC 1701 "Generic Routing Encapsulation (GRE)", RFC 1702
 * "Generic Routing Encapsulation over IPv4 networks", RFC 2637
 * "Point-to-Point Tunneling Protocol (PPTP)", RFC 2784 "Generic
 * Routing Encapsulation (GRE)", RFC 2890 "Key and Sequence
 * Number Extensions to GRE", RFC 8086 "GRE-in-UDP Encapsulation",
 * and draft-ietf-mpls-in-ip-or-gre-07.txt
 * "Encapsulating MPLS in IP or Generic Routing Encapsulation (GRE)".
 */

static int proto_gre = -1;
static int hf_gre_proto = -1;
static int hf_gre_flags_and_version = -1;
static int hf_gre_flags_checksum = -1;
static int hf_gre_flags_routing = -1;
static int hf_gre_flags_key = -1;
static int hf_gre_flags_sequence_number = -1;
static int hf_gre_flags_strict_source_route = -1;
static int hf_gre_flags_recursion_control = -1;
static int hf_gre_flags_ack = -1;
static int hf_gre_flags_reserved_ppp = -1;
static int hf_gre_flags_reserved = -1;
static int hf_gre_flags_version = -1;
static int hf_gre_checksum = -1;
static int hf_gre_checksum_status = -1;
static int hf_gre_offset = -1;
static int hf_gre_key = -1;
static int hf_gre_key_payload_length = -1;
static int hf_gre_key_call_id = -1;
static int hf_gre_sequence_number = -1;
static int hf_gre_ack_number = -1;
static int hf_gre_routing = -1;
static int hf_gre_routing_address_family = -1;
static int hf_gre_routing_sre_length = -1;
static int hf_gre_routing_sre_offset = -1;
static int hf_gre_routing_information = -1;

/* Ref 3GPP2 A.S0012-C v2.0 and A.S0008-A v1.0 */
static int hf_gre_3gpp2_attrib = -1;
static int hf_gre_3gpp2_attrib_id = -1;
static int hf_gre_3gpp2_attrib_length = -1;
static int hf_gre_3gpp2_sdi = -1;
static int hf_gre_3gpp2_fci = -1;
static int hf_gre_3gpp2_di = -1;
static int hf_gre_3gpp2_flow_disc = -1;
static int hf_gre_3gpp2_seg = -1;

static int hf_gre_wccp_redirect_header = -1;
static int hf_gre_wccp_dynamic_service = -1;
static int hf_gre_wccp_alternative_bucket_used = -1;
static int hf_gre_wccp_redirect_header_valid = -1;
static int hf_gre_wccp_service_id = -1;
static int hf_gre_wccp_alternative_bucket = -1;
static int hf_gre_wccp_primary_bucket = -1;

static gint ett_gre = -1;
static gint ett_gre_flags = -1;
static gint ett_gre_routing = -1;
static gint ett_gre_wccp2_redirect_header = -1;
static gint ett_3gpp2_attribs = -1;
static gint ett_3gpp2_attr = -1;

static expert_field ei_gre_checksum_incorrect = EI_INIT;

static dissector_table_t gre_dissector_table;

static const value_string gre_version[] = {
    { 0, "GRE" },                /* [RFC2784] */
    { 1, "Enhanced GRE" },       /* [RFC2637] */
    { 0, NULL}
};
const value_string gre_typevals[] = {
    { GRE_KEEPALIVE,       "Possible GRE keepalive packet" },
    { ETHERTYPE_PPP,       "PPP" },
    { ETHERTYPE_IP,        "IP" },
    { ETHERTYPE_ARP,       "ARP" },
    { SAP_OSINL5,          "OSI"},
    { GRE_WCCP,            "WCCP"},
    { GRE_CISCO_CDP,       "CDP (Cisco)"},
    { GRE_NHRP,            "NHRP"},
    { GRE_ERSPAN_88BE,     "ERSPAN"},
    { GRE_ERSPAN_22EB,     "ERSPAN III"},
    { GRE_MIKROTIK_EOIP,   "MIKROTIK EoIP"},
    { GRE_AIROHIVE,        "AIROHIVE AP AP"},
    { ETHERTYPE_IPX,       "IPX"},
    { ETHERTYPE_ETHBRIDGE, "Transparent Ethernet bridging" },
    { ETHERTYPE_RAW_FR,    "Frame Relay"},
    { ETHERTYPE_IPv6,      "IPv6" },
    { ETHERTYPE_MPLS,      "MPLS label switched packet" },
    { ETHERTYPE_NSH,       "Network Service Header" },
    { ETHERTYPE_CDMA2000_A10_UBS,"CDMA2000 A10 Unstructured byte stream" },
    { ETHERTYPE_3GPP2,     "CDMA2000 A10 3GPP2 Packet" },
    { ETHERTYPE_CMD,       "CiscoMetaData" },
    { GRE_GREBONDING,      "Huawei GRE bonding" },
    { GRE_ARUBA_8200,      "ARUBA WLAN" },
    { GRE_ARUBA_8210,      "ARUBA WLAN" },
    { GRE_ARUBA_8220,      "ARUBA WLAN" },
    { GRE_ARUBA_8230,      "ARUBA WLAN" },
    { GRE_ARUBA_8240,      "ARUBA WLAN" },
    { GRE_ARUBA_8250,      "ARUBA WLAN" },
    { GRE_ARUBA_8260,      "ARUBA WLAN" },
    { GRE_ARUBA_8270,      "ARUBA WLAN" },
    { GRE_ARUBA_8280,      "ARUBA WLAN" },
    { GRE_ARUBA_8290,      "ARUBA WLAN" },
    { GRE_ARUBA_82A0,      "ARUBA WLAN" },
    { GRE_ARUBA_82B0,      "ARUBA WLAN" },
    { GRE_ARUBA_82C0,      "ARUBA WLAN" },
    { GRE_ARUBA_82D0,      "ARUBA WLAN" },
    { GRE_ARUBA_82E0,      "ARUBA WLAN" },
    { GRE_ARUBA_82F0,      "ARUBA WLAN" },
    { GRE_ARUBA_8300,      "ARUBA WLAN" },
    { GRE_ARUBA_8310,      "ARUBA WLAN" },
    { GRE_ARUBA_8320,      "ARUBA WLAN" },
    { GRE_ARUBA_8330,      "ARUBA WLAN" },
    { GRE_ARUBA_8340,      "ARUBA WLAN" },
    { GRE_ARUBA_8350,      "ARUBA WLAN" },
    { GRE_ARUBA_8360,      "ARUBA WLAN" },
    { GRE_ARUBA_8370,      "ARUBA WLAN" },
    { GRE_ARUBA_9000,      "ARUBA WLAN" },
    { 0,                   NULL }
};

#define ID_3GPP2_SDI_FLAG 1
#define ID_3GPP2_FLOW_CTRL 2
#define ID_3GPP2_FLOW_DISCRIMINATOR 3
#define ID_3GPP2_SEG 4

static const value_string gre_3gpp2_seg_vals[] = {
    { 0x00, "Packet Started" },
    { 0x01, "Packet continued" },
    { 0x02, "Packet Ended" },
    { 0,    NULL }
};
/* 3GPP2 A.S0012-C v2.0
 * 2.6.1 GRE Attributes
 */
static const value_string gre_3gpp2_attrib_id_vals[] = {
    { 0x01, "1x SDB/HRPD DOS Indicator" },
    { 0x02, "Flow Control Indication" },
    /* A.S0008-A v1.0 */
    { 0x03, "IP Flow Discriminator" },
    { 0x04, "Segmentation Indication" },
    { 0,    NULL }
};

static const true_false_string gre_3gpp2_sdi_val = {
    "Packet suitable for 1x SDB or HRPD DOS transmission",
    "Reserved"
};

static const true_false_string gre_3gpp2_fci_val = {
    "XOFF",
    "XON"
};

static const true_false_string gre_3gpp2_di_val = {
    "INDEFINITE:",
    "TEMPORARY"
};

static const true_false_string gre_wccp_dynamic_service_val = {
    "Dynamic service",
    "Well-known service"
};

static const true_false_string gre_wccp_alternative_bucket_used_val = {
    "Alternative bucket used",
    "Primary bucket used",
};

static const true_false_string gre_wccp_redirect_header_valid_val = {
    "Header is present, but ignore contents",
    "Header contents are valid",
};


static int
dissect_gre_3gpp2_attribs(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    gboolean    last_attrib  = FALSE;
    proto_item *attr_item;
    proto_tree *attr_tree;
    guint8      value;
    int         start_offset = offset;

    proto_item *ti = proto_tree_add_item(tree, hf_gre_3gpp2_attrib, tvb, offset, 0, ENC_NA);
    proto_tree *atree = proto_item_add_subtree(ti, ett_3gpp2_attribs);

    while(last_attrib != TRUE)
    {
        guint8 attrib_id = tvb_get_guint8(tvb, offset);
        guint8 attrib_length = tvb_get_guint8(tvb, offset + 1);

        attr_tree = proto_tree_add_subtree(atree, tvb, offset, attrib_length + 1 + 1, ett_3gpp2_attr, &attr_item,
                                        val_to_str((attrib_id&0x7f), gre_3gpp2_attrib_id_vals, "%u (Unknown)"));

        proto_tree_add_item(attr_tree, hf_gre_3gpp2_attrib_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(attr_tree, hf_gre_3gpp2_attrib_length, tvb, offset+1, 1, ENC_BIG_ENDIAN);

        offset += 2;
        last_attrib = (attrib_id & 0x80)?TRUE:FALSE;
        attrib_id &= 0x7F;

        switch(attrib_id)
        {
        case ID_3GPP2_FLOW_DISCRIMINATOR:
        {
            value = tvb_get_guint8(tvb,offset);
            proto_tree_add_item(attr_tree, hf_gre_3gpp2_flow_disc, tvb, offset, attrib_length, ENC_NA);
            proto_item_append_text(attr_item," - 0x%x",value);
        }
        break;
        case ID_3GPP2_SDI_FLAG:
        {
            value = tvb_get_guint8(tvb,offset);
            proto_tree_add_item(attr_tree, hf_gre_3gpp2_sdi, tvb, offset, attrib_length, ENC_BIG_ENDIAN);
            proto_item_append_text(attr_item," - %s",
                                   (value & 0x80) ? "Packet suitable for 1x SDB or HRPD DOS transmission" : "Reserved");

        }
        break;
        case ID_3GPP2_SEG:
        {
            value = tvb_get_guint8(tvb,offset) >>6;
            proto_tree_add_item(attr_tree, hf_gre_3gpp2_seg, tvb, offset, attrib_length, ENC_BIG_ENDIAN);
            proto_item_append_text(attr_item," - %s",val_to_str(value, gre_3gpp2_seg_vals, "0x%02X - Unknown"));
        }
        break;
        case ID_3GPP2_FLOW_CTRL:
        {
            value = tvb_get_guint8(tvb,offset);
            proto_tree_add_item(attr_tree, hf_gre_3gpp2_fci, tvb, offset, attrib_length, ENC_BIG_ENDIAN);
            proto_item_append_text(attr_item," - %s",
                                   (value & 0x80) ? "XON" : "XOFF");
            proto_tree_add_item(attr_tree, hf_gre_3gpp2_di, tvb, offset, attrib_length, ENC_BIG_ENDIAN);
            proto_item_append_text(attr_item,"/%s",
                                   (value & 0x40) ? "INDEFINITE" : "TEMPORARY");
        }
        break;
        }

        offset += attrib_length;
    }
    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static void
dissect_gre_wccp2_redirect_header(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *rh_tree;

    ti = proto_tree_add_item(tree, hf_gre_wccp_redirect_header, tvb, offset, 4, ENC_NA);
    rh_tree = proto_item_add_subtree(ti, ett_gre_wccp2_redirect_header);

    proto_tree_add_item(rh_tree, hf_gre_wccp_dynamic_service, tvb, offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(rh_tree, hf_gre_wccp_alternative_bucket_used, tvb, offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(rh_tree, hf_gre_wccp_redirect_header_valid, tvb, offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(rh_tree, hf_gre_wccp_service_id, tvb, offset +1, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(rh_tree, hf_gre_wccp_alternative_bucket, tvb, offset +2, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(rh_tree, hf_gre_wccp_primary_bucket, tvb, offset +3, 1, ENC_BIG_ENDIAN);
}

static gboolean
capture_gre(const guchar *pd _U_, int offset _U_, int len _U_, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
    capture_dissector_increment_count(cpinfo, proto_gre);
    return TRUE;
}

static int
dissect_gre(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{

    int         offset             = 0;
    guint16     flags_and_ver;
    guint16     type;
    gboolean    is_ppp             = FALSE;
    gboolean    is_wccp2           = FALSE;
    proto_item *ti, *it_flags;
    proto_tree *gre_tree, *fv_tree = NULL;
    guint16     sre_af;
    guint8      sre_length;
    tvbuff_t   *next_tvb;

    flags_and_ver = tvb_get_ntohs(tvb, offset);
    type = tvb_get_ntohs(tvb, offset + 2);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GRE");

    col_add_fstr(pinfo->cinfo, COL_INFO, "Encapsulated %s", val_to_str(type, gre_typevals, "0x%04X (unknown)"));

    switch (type) {

    case ETHERTYPE_PPP:
        if (flags_and_ver & GRE_VERSION)
            is_ppp = TRUE;
        break;
    case ETHERTYPE_3GPP2:
    case ETHERTYPE_CDMA2000_A10_UBS:
        is_ppp = TRUE;
        break;

    case GRE_WCCP:
        /* WCCP2 puts an extra 4 octets into the header, but uses the same
           encapsulation type; if it looks as if the first octet of the packet
           isn't the beginning of an IPv4 header, assume it's WCCP2. */
        if ((tvb_get_guint8(tvb, offset + 2 + 2) & 0xF0) != 0x40) {
            is_wccp2 = TRUE;
        }
        break;
    }

    /* Per README.developer, section 1.2, we must call subdissectors regardless
     * of whether "tree" is NULL or not.  That is done below using
     * call_dissector(), but since the next_tvb must begin at the correct offset,
     * it's easier and more readable to always enter this block in order to
     * compute the correct offset to pass to tvb_new_subset_remaining().
     */
    if (1) {
        ti = proto_tree_add_protocol_format(tree, proto_gre, tvb, offset, -1, "Generic Routing Encapsulation (%s)",
                                            val_to_str(type, gre_typevals, "0x%04X - unknown"));
        gre_tree = proto_item_add_subtree(ti, ett_gre);


        it_flags = proto_tree_add_item(gre_tree, hf_gre_flags_and_version, tvb, offset, 2, ENC_BIG_ENDIAN);
        fv_tree = proto_item_add_subtree(it_flags, ett_gre_flags);

        proto_tree_add_item(fv_tree, hf_gre_flags_checksum, tvb, offset, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(fv_tree, hf_gre_flags_routing, tvb, offset, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(fv_tree, hf_gre_flags_key, tvb, offset, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(fv_tree, hf_gre_flags_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(fv_tree, hf_gre_flags_strict_source_route, tvb, offset, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(fv_tree, hf_gre_flags_recursion_control, tvb, offset, 2, ENC_BIG_ENDIAN);

        /* RFC2637 Section 4.1 : Enhanced GRE Header */
        if (is_ppp) {
            proto_tree_add_item(fv_tree, hf_gre_flags_ack, tvb, offset, 2, ENC_BIG_ENDIAN);

            proto_tree_add_item(fv_tree, hf_gre_flags_reserved_ppp, tvb, offset, 2, ENC_BIG_ENDIAN);
        }
        else {
            proto_tree_add_item(fv_tree, hf_gre_flags_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
        }

        proto_tree_add_item(fv_tree, hf_gre_flags_version, tvb, offset, 2, ENC_BIG_ENDIAN);

        offset += 2;

        proto_tree_add_item(gre_tree, hf_gre_proto, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        if (flags_and_ver & GRE_CHECKSUM || flags_and_ver & GRE_ROUTING) {
            guint length, reported_length;
            vec_t cksum_vec[1];

            /* Checksum check !... */
            length = tvb_captured_length(tvb);
            reported_length = tvb_reported_length(tvb);
            /* The Checksum Present bit is set, and the packet isn't part of a
               fragmented datagram and isn't truncated, so we can checksum it. */
            if ((flags_and_ver & GRE_CHECKSUM) && !pinfo->fragmented && length >= reported_length) {
                SET_CKSUM_VEC_TVB(cksum_vec[0], tvb, 0, reported_length);
                proto_tree_add_checksum(gre_tree, tvb, offset, hf_gre_checksum, hf_gre_checksum_status, &ei_gre_checksum_incorrect, pinfo, in_cksum(cksum_vec, 1),
                                ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY|PROTO_CHECKSUM_IN_CKSUM);
            } else {
                proto_tree_add_checksum(gre_tree, tvb, offset, hf_gre_checksum, hf_gre_checksum_status, &ei_gre_checksum_incorrect, pinfo, 0,
                                ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
            }
            offset += 2;

            proto_tree_add_item(gre_tree, hf_gre_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }

        if (flags_and_ver & GRE_KEY) {
            /* RFC2637 Section 4.1 : Enhanced GRE Header */
            if (is_ppp && type!=ETHERTYPE_CDMA2000_A10_UBS) {

                proto_tree_add_item(gre_tree, hf_gre_key_payload_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                proto_tree_add_item(gre_tree, hf_gre_key_call_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }
            else {
                proto_tree_add_item(gre_tree, hf_gre_key, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            }
        }
        if (flags_and_ver & GRE_SEQUENCE) {

            proto_tree_add_item(gre_tree, hf_gre_sequence_number , tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
        if (is_ppp && (flags_and_ver & GRE_ACK)) {

            proto_tree_add_item(gre_tree, hf_gre_ack_number , tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
        if (flags_and_ver & GRE_ROUTING) {
            proto_item *it_routing;
            proto_tree *r_tree;
            for (;;) {

                it_routing = proto_tree_add_item(gre_tree, hf_gre_routing, tvb, offset, -1, ENC_NA);
                r_tree = proto_item_add_subtree(ti, ett_gre_routing);

                sre_af = tvb_get_ntohs(tvb, offset);
                proto_tree_add_item(r_tree, hf_gre_routing_address_family , tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                proto_tree_add_item(r_tree, hf_gre_routing_sre_offset , tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                sre_length = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(r_tree, hf_gre_routing_sre_length , tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                proto_item_set_len(it_routing, 2 + 1 +1 + sre_length);
                if (sre_af == 0 && sre_length == 0)
                    break;

                proto_tree_add_item(r_tree, hf_gre_routing_information , tvb, offset, sre_length, ENC_NA);
                offset += sre_length;
            }
        }

        if (type == GRE_WCCP && is_wccp2) {
            dissect_gre_wccp2_redirect_header(tvb, offset, gre_tree);
            offset += 4;
        }
        if (type == ETHERTYPE_3GPP2) {
            offset = dissect_gre_3gpp2_attribs(tvb, offset, gre_tree);
        }

        proto_item_set_len(ti, offset);

        /* If the S bit is not set, this packet might not have a payload, so
           check whether there's any data left, first.

           XXX - the S bit isn't in RFC 2784, which deprecates that bit
           and some other bits in RFC 1701 and says that they should be
           zero for RFC 2784-compliant GRE; as such, the absence of the
           S bit doesn't necessarily mean there's no payload.  */
        if (!(flags_and_ver & GRE_SEQUENCE)) {
            if (tvb_reported_length_remaining(tvb, offset) <= 0)
                return offset; /* no payload */
        }
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        pinfo->flags.in_gre_pkt = TRUE;
        if (!dissector_try_uint_new(gre_dissector_table, type, next_tvb, pinfo, tree, TRUE, &flags_and_ver))
            call_data_dissector(next_tvb, pinfo, gre_tree);
    }
    return tvb_captured_length(tvb);
}


void
proto_register_gre(void)
{
    static hf_register_info hf[] = {
        { &hf_gre_proto,
          { "Protocol Type", "gre.proto",
            FT_UINT16, BASE_HEX, VALS(gre_typevals), 0x0,
            "The protocol that is GRE encapsulated", HFILL }
        },
        { &hf_gre_flags_and_version,
          { "Flags and Version", "gre.flags_and_version",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "The GRE flags are encoded in the first two octets", HFILL }
        },
        { &hf_gre_flags_checksum,
          { "Checksum Bit", "gre.flags.checksum",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), GRE_CHECKSUM,
            "Indicates if the Checksum field is present", HFILL }
        },
        { &hf_gre_flags_routing,
          { "Routing Bit", "gre.flags.routing",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), GRE_ROUTING,
            "Indicates if the Routing and Checksum/Offset field are present", HFILL }
        },
        { &hf_gre_flags_key,
          { "Key Bit", "gre.flags.key",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), GRE_KEY,
            "Indicates if the Key field is present", HFILL }
        },
        { &hf_gre_flags_sequence_number,
          { "Sequence Number Bit", "gre.flags.sequence_number",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), GRE_SEQUENCE,
            "Indicates if the Sequence Number field is present", HFILL }
        },
        { &hf_gre_flags_strict_source_route,
          { "Strict Source Route Bit", "gre.flags.strict_source_route",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), GRE_STRICTSOURCE,
            NULL, HFILL }
        },
        { &hf_gre_flags_recursion_control,
          { "Recursion control", "gre.flags.recursion_control",
            FT_UINT16, BASE_DEC, NULL, GRE_RECURSION,
            NULL, HFILL }
        },
        { &hf_gre_flags_ack,
          { "Acknowledgment", "gre.flags.ack",
            FT_BOOLEAN, 16, TFS(&tfs_yes_no), GRE_ACK,
            "Indicates if the packet contains an Acknowledgment Number to be used for acknowledging previously transmitted data", HFILL }
        },
        { &hf_gre_flags_reserved,
          { "Flags (Reserved)", "gre.flags.reserved",
            FT_UINT16, BASE_DEC, NULL, GRE_RESERVED,
            NULL, HFILL }
        },
        { &hf_gre_flags_reserved_ppp,
          { "Flags (Reserved)", "gre.flags.reserved",
            FT_UINT16, BASE_DEC, NULL, GRE_RESERVED_PPP,
            NULL, HFILL }
        },
        { &hf_gre_flags_version,
          { "Version", "gre.flags.version",
            FT_UINT16, BASE_DEC, VALS(gre_version), GRE_VERSION,
            NULL, HFILL }
        },
        { &hf_gre_checksum,
          { "Checksum", "gre.checksum",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "The Checksum field contains the IP (one's complement) checksum of the GRE header and the payload packet", HFILL }
        },
        { &hf_gre_checksum_status,
          { "Checksum Status", "gre.checksum.status",
            FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_gre_offset,
          { "Offset", "gre.offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "The offset field indicates the octet offset from the start of the Routing field to the first octet of the active Source Route Entry to be examined", HFILL }
        },
        { &hf_gre_key,
          { "Key", "gre.key",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "The Key field contains a four octet number which was inserted by the encapsulator", HFILL }
        },
        { &hf_gre_key_payload_length,
          { "Payload Length", "gre.key.payload_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Size of the payload, not including the GRE header", HFILL }
        },
        { &hf_gre_key_call_id,
          { "Call ID", "gre.key.call_id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Contains the Peer's Call ID for the session to which this packet belongs.", HFILL }
        },
        { &hf_gre_sequence_number,
          { "Sequence Number", "gre.sequence_number",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "The Sequence Number field contains an unsigned 32 bit integer which is inserted by the encapsulator", HFILL }
        },
        { &hf_gre_ack_number,
          { "Acknowledgment Number", "gre.ack_number",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Contains the sequence number of the highest numbered GRE packet received by the sending peer for this user session", HFILL }
        },
        { &hf_gre_routing,
          { "Routing", "gre.routing",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "The Routing field is a list of Source Route Entries (SREs)", HFILL }
        },
        { &hf_gre_routing_address_family,
          { "Address Family", "gre.routing.address_family",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "The Address Family field contains a two octet value which indicates the syntax and semantics of the Routing Information field", HFILL }
        },
        { &hf_gre_routing_sre_offset,
          { "SRE Offset", "gre.routing.sre_offset",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "The Address Family field contains a two octet value which indicates the syntax and semantics of the Routing Information field", HFILL }
        },
        { &hf_gre_routing_sre_length,
          { "SRE Length", "gre.routing.src_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "The SRE Length field contains the number of octets in the SRE", HFILL }
        },
        { &hf_gre_routing_information,
          { "Routing Information", "gre.routing.information",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "The Routing Information field contains data which may be used in routing this packet", HFILL }
        },
        { &hf_gre_3gpp2_attrib,
          { "3GPP2 Attributes", "gre.3gpp2_attrib",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gre_3gpp2_attrib_id,
          { "Type", "gre.3gpp2_attrib_id",
            FT_UINT8, BASE_HEX, VALS(gre_3gpp2_attrib_id_vals), 0x7f,
            NULL, HFILL }
        },
        { &hf_gre_3gpp2_attrib_length,
          { "Length", "gre.3gpp2_attrib_length",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gre_3gpp2_sdi,
          { "SDI/DOS", "gre.3gpp2_sdi",
            FT_BOOLEAN, 16, TFS(&gre_3gpp2_sdi_val), 0x8000,
            "Short Data Indicator(SDI)/Data Over Signaling (DOS)", HFILL }
        },
        { &hf_gre_3gpp2_fci,
          { "Flow Control Indicator", "gre.3gpp2_fci",
            FT_BOOLEAN, 16, TFS(&gre_3gpp2_fci_val), 0x8000,
            NULL, HFILL }
        },
        { &hf_gre_3gpp2_di,
          { "Duration Indicator", "gre.3gpp2_di",
            FT_BOOLEAN, 16, TFS(&gre_3gpp2_di_val), 0x4000,
            NULL, HFILL }
        },
        { &hf_gre_3gpp2_flow_disc,
          { "Flow ID", "gre.ggp2_flow_disc",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gre_3gpp2_seg,
          { "Type", "gre.ggp2_3gpp2_seg",
            FT_UINT16, BASE_HEX, VALS(gre_3gpp2_seg_vals), 0xc000,
            NULL, HFILL }
        },

        { &hf_gre_wccp_redirect_header,
          { "Redirect Header", "gre.wccp.redirect_header",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gre_wccp_dynamic_service,
          { "Dynamic Service", "gre.wccp.dynamic_service",
            FT_BOOLEAN, 8, TFS(&gre_wccp_dynamic_service_val), 0x01,
            NULL, HFILL }
        },
        { &hf_gre_wccp_alternative_bucket_used,
          { "Alternative bucket used", "gre.wccp.alternative_bucket_used",
            FT_BOOLEAN, 8, TFS(&gre_wccp_alternative_bucket_used_val), 0x02,
            NULL, HFILL }
        },
        { &hf_gre_wccp_redirect_header_valid,
          { "WCCP Redirect header is valid", "gre.wccp.redirect_header_valid",
            FT_BOOLEAN, 8, TFS(&gre_wccp_redirect_header_valid_val), 0x04,
            NULL, HFILL }
        },
        { &hf_gre_wccp_service_id,
          { "Service ID", "gre.wccp.service_id",
            FT_UINT8, BASE_DEC, VALS(service_id_vals), 0x00,
            "Service Group identifier", HFILL }
        },
        { &hf_gre_wccp_alternative_bucket,
          { "Alternative Bucket", "gre.wccp.alternative_bucket",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Alternative bucket index used to redirect the packet.", HFILL }
        },
        { &hf_gre_wccp_primary_bucket,
          { "Primary Bucket", "gre.wccp.primary_bucket",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Primary bucket index used to redirect the packet.", HFILL  }
        },
    };
    static gint *ett[] = {
        &ett_gre,
        &ett_gre_flags,
        &ett_gre_routing,
        &ett_gre_wccp2_redirect_header,
        &ett_3gpp2_attribs,
        &ett_3gpp2_attr,
    };


    static ei_register_info ei[] = {
        { &ei_gre_checksum_incorrect, { "gre.checksum.incorrect", PI_PROTOCOL, PI_WARN, "Incorrect GRE Checksum", EXPFILL }},
    };

    expert_module_t* expert_gre;

    proto_gre = proto_register_protocol("Generic Routing Encapsulation",
                                        "GRE", "gre");
    proto_register_field_array(proto_gre, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_gre = expert_register_protocol(proto_gre);
    expert_register_field_array(expert_gre, ei, array_length(ei));

    /*
     * Dissector table.
     *
     * XXX - according to
     *
     *    https://www.iana.org/assignments/gre-parameters/gre-parameters.xhtml#gre-parameters-1
     *
     * these are just Ethertypes; should we use "gre.proto" only for
     * protocols *not* registered as Ethertypes, such as those listed
     * in the table in "Current List of Protocol Types" in RFC 1701
     * ("For historical reasons, a number of other values have been
     * used for some protocols."), and for protocols encapsulated in GRE
     * differently from the way they're encapsulated over LAN protocols
     * (for example, Cisco MetaData), and if we don't get a match there,
     * use the "ethertype" table?
     *
     * And should we also somehow do something similar for mapping values
     * to strings, falling back on etype_vals?
     */
    gre_dissector_table = register_dissector_table("gre.proto",
                                                   "GRE protocol type", proto_gre, FT_UINT16, BASE_HEX);
}

void
proto_reg_handoff_gre(void)
{
    dissector_handle_t gre_handle;
    capture_dissector_handle_t gre_cap_handle;

    gre_handle = create_dissector_handle(dissect_gre, proto_gre);
    dissector_add_uint("ip.proto", IP_PROTO_GRE, gre_handle);
    dissector_add_uint("udp.port", GRE_IN_UDP_PORT, gre_handle);
    gre_cap_handle = create_capture_dissector_handle(capture_gre, proto_gre);
    capture_dissector_add_uint("ip.proto", IP_PROTO_GRE, gre_cap_handle);
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
