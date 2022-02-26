/* packet-li5g.c
 * Routines for ETSI TS 103 221-2 V1.1.1 (2019-03), Internal Network Interface X2/X3 for Lawful Interception
 * Roy Zhang <roy.zhang@nokia-sbell.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"
#include <epan/packet.h>
#include <epan/ipproto.h>

void proto_reg_handoff_li5g(void);
void proto_register_li5g(void);

static int proto_li5g = -1;
static int hf_li5g_version = -1;
static int hf_li5g_pduType = -1;
static int hf_li5g_headerLen = -1;
static int hf_li5g_payloadLen = -1;
static int hf_li5g_payloadFormat = -1;
static int hf_li5g_payloadDirection = -1;
static int hf_li5g_xid = -1;
static int hf_li5g_cid = -1;
static int hf_li5g_attrType = -1;
static int hf_li5g_attrLen = -1;
static int hf_li5g_pld = -1;

/* the min Attribute Type is 1 */
#define LI_5G_ATTR_TYPE_MAX 19
/* the min header length */
#define LI_5G_HEADER_LEN_MIN 40
/* 13 payload format */
#define LI_5G_PAYLOAD_FORMAT_MAX 14

static gint ett_li5g = -1;
static gint ett_attrContents[LI_5G_ATTR_TYPE_MAX];
static int hf_li5g_attrContents[LI_5G_ATTR_TYPE_MAX];
static dissector_handle_t li5g_handle;
static dissector_handle_t subProtocol_handle[LI_5G_PAYLOAD_FORMAT_MAX]={NULL};

static const value_string pdu_type_vals[] = {
    {1, "X2 xIRI"},
    {2, "X3 xCC"},
    {3, "Keepalive"},
    {4, "Keepalive Acknowledgement"},
    {0, NULL}
};

static const value_string payload_format_vals[] = {
    { 0, "Reserved for Keepalive"},
    { 1, "ETSI TS 102 232-1 Defined Payload"},
    { 2, "3GPP TS 33.128 Defined Payload"},
    { 3, "3GPP TS 33.108 Defined Payload"},
    { 4, "Proprietary Payload"},
    { 5, "IPv4 Packet"},
    { 6, "IPv6 Packet"},
    { 7, "Ethernet Frame"},
    { 8, "RTP Packet"},
    { 9, "SIP Message"},
    {10, "DHCP Message"},
    {11, "RADIUS Packet"},
    {12, "GTP-U Message"},
    {13, "MSRP Message"},
    { 0, NULL}
};

static const value_string payload_dir_vals[] = {
    {0, "Reserved for Keepalive"},
    {1, "The direction of the intercepted data or event is not known to the POI"},
    {2, "The intercepted data or event was sent to (i.e. received by) the target"},
    {3, "The intercepted data or event was sent from the target"},
    {4, "The intercepted data or event is a result of intercepted data or events in more than one direction"},
    {5, "The concept of direction is not applicable to this intercepted data or event"},
    {0, NULL}
};

static const value_string attribute_type_vals[] = {
    { 1, "ETSI TS 102 232-1 Defined Attribute"},
    { 2, "3GPP TS 33.128 Defined Attribute"},
    { 3, "3GPP TS 33.108 Defined Attribute"},
    { 4, "Proprietary Attribute"},
    { 5, "Domain ID (DID)"},
    { 6, "Network Function ID (NFID)"},
    { 7, "Interception Point ID (IPID)"},
    { 8, "Sequence Number"},
    { 9, "Timestamp"},
    {10, "Source IPv4 Address"},
    {11, "Destination IPv4 Address"},
    {12, "Source IPv6 Address"},
    {13, "Destination IPv6 Address"},
    {14, "Source Port"},
    {15, "Destination Port"},
    {16, "IP Protocol"},
    {17, "Matched Target Identifier"},
    {18, "Other Target Identifier"},
    {0, NULL}
};

static int
dissect_li5g(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree  *li5g_tree, *attr_tree, *parent=NULL;
    proto_item  *ti, *attr_ti;
    int offset = LI_5G_HEADER_LEN_MIN, hf_attr = -1;
    guint32 headerLen, payloadLen, pduType;
    guint16 payloadFormat, attrType, attrLen;
    const char* info;

    address src_addr;
    address dst_addr;
    guint32 src_port;
    guint32 dst_port;

    headerLen = tvb_get_ntohl(tvb, 4);
    payloadLen = tvb_get_ntohl(tvb, 8);
    payloadFormat = tvb_get_ntohs(tvb, 12);

    ti = proto_tree_add_item(tree, proto_li5g, tvb, 0, headerLen+payloadLen, ENC_NA);
    li5g_tree = proto_item_add_subtree(ti, ett_li5g);
    proto_tree_add_item(li5g_tree, hf_li5g_version, tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(li5g_tree, hf_li5g_pduType, tvb, 2, 2, ENC_BIG_ENDIAN, &pduType);
    proto_tree_add_item(li5g_tree, hf_li5g_headerLen, tvb, 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(li5g_tree, hf_li5g_payloadLen, tvb, 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(li5g_tree, hf_li5g_payloadFormat, tvb, 12, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(li5g_tree, hf_li5g_payloadDirection, tvb, 14, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(li5g_tree, hf_li5g_xid, tvb, 16, 16, ENC_NA);
    proto_tree_add_item(li5g_tree, hf_li5g_cid, tvb, 32, 8, ENC_NA);

    /* Get the Conditional Attribute */
    while(headerLen - offset > 0){
        attrType = tvb_get_ntohs(tvb, offset);
        attrLen = tvb_get_ntohs(tvb, offset+2);
        /* The first 4 types not supporting now */
        if (attrType > 4 && attrType < LI_5G_ATTR_TYPE_MAX){
            hf_attr = hf_li5g_attrContents[attrType];

            attr_ti = proto_tree_add_item(li5g_tree, hf_attr, tvb, offset+4, attrLen, ENC_NA);
            attr_tree = proto_item_add_subtree(attr_ti, ett_attrContents[attrType]);
            proto_tree_add_item(attr_tree, hf_li5g_attrType, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(attr_tree, hf_li5g_attrLen, tvb, offset+2, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(attr_tree, hf_attr, tvb, offset+4, attrLen, ENC_BIG_ENDIAN);
        }

        offset = offset + 4 + attrLen;
    }

    proto_tree_add_item(li5g_tree, hf_li5g_pld, tvb, headerLen, payloadLen, ENC_NA);

    /* the key is address+port+frame_num for reassemble list, the address/port can be changed in pinfo because of the inner TCP protocol */
    copy_address_shallow(&src_addr, &pinfo->src);
    copy_address_shallow(&dst_addr, &pinfo->dst);
    src_port = pinfo->srcport;
    dst_port = pinfo->destport;

    /* to make all the sub protocol(such as DNS) under li5g*/
    if (li5g_tree && li5g_tree->parent){
        parent=li5g_tree->parent;
        li5g_tree->parent=NULL;
    }

    if (subProtocol_handle[payloadFormat])
        call_dissector(subProtocol_handle[payloadFormat], tvb_new_subset_length(tvb, offset, payloadLen), pinfo, li5g_tree);

    if (parent)
        li5g_tree->parent=parent;

    /* have another li5g in the same packet? */
    if (tvb_captured_length(tvb)>offset+payloadLen)
        dissect_li5g(tvb_new_subset_remaining(tvb, offset+payloadLen), pinfo, tree, NULL);

    /* set these info at the end*/
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "5GLI");
    col_clear_fence(pinfo->cinfo, COL_INFO);
    col_clear(pinfo->cinfo, COL_INFO);
    info = try_val_to_str(pduType, pdu_type_vals);
    if (info != NULL) {
        col_set_str(pinfo->cinfo, COL_INFO, info);
    }

    /* copy back to the original value when return from innner protocol */
    copy_address_shallow(&pinfo->src, &src_addr);
    copy_address_shallow(&pinfo->dst, &dst_addr);
    pinfo->srcport = src_port;
    pinfo->destport = dst_port;

    return tvb_captured_length(tvb);
}

static gboolean
dissect_li5g_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (tvb_captured_length(tvb) < LI_5G_HEADER_LEN_MIN)
        return FALSE;
    /* the version should be 1 */
    if (tvb_get_ntohs(tvb, 0) != 1)
        return FALSE;
    /* only 4 types supported*/
    if(tvb_get_ntohs(tvb, 2) < 1 || tvb_get_ntohs(tvb, 2) > 4)
        return (FALSE);

    /* TLS can hold it, no need to find the disect every time */
    *(dissector_handle_t *)data = li5g_handle;
    dissect_li5g(tvb, pinfo, tree, data);

    return TRUE;
}

void
proto_register_li5g(void)
{
    memset(ett_attrContents, -1, sizeof(ett_attrContents));
    memset(hf_li5g_attrContents, -1, sizeof(hf_li5g_attrContents));

    static hf_register_info hf[] = {
        { &hf_li5g_version, { "Version", "li5g.ver", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_li5g_pduType, { "PDU Type", "li5g.type", FT_UINT16, BASE_DEC, VALS(pdu_type_vals), 0x0, NULL, HFILL }},
        { &hf_li5g_headerLen, { "Header Length", "li5g.hl", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL }},
        { &hf_li5g_payloadLen, { "Payload Length", "li5g.pl", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL }},
        { &hf_li5g_payloadFormat, { "Payload Format", "li5g.pf", FT_UINT16, BASE_DEC, VALS(payload_format_vals), 0x0, NULL, HFILL }},
        { &hf_li5g_payloadDirection, { "Payload Direction", "li5g.pd", FT_UINT16, BASE_DEC, VALS(payload_dir_vals), 0x0, NULL, HFILL }},
        { &hf_li5g_xid, { "XID", "li5g.xid", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_li5g_cid, { "Correlation ID", "li5g.cid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_li5g_attrType, { "Attribute Type", "li5g.attrType", FT_UINT16, BASE_DEC, VALS(attribute_type_vals), 0x0, NULL, HFILL }},
        { &hf_li5g_attrLen, { "Attribute Length", "li5g.attrLen", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL }},
        { &hf_li5g_attrContents[5], { "Domain ID", "li5g.did", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_li5g_attrContents[6], { "Network Function ID", "li5g.nfid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_li5g_attrContents[7], { "Interception Point ID", "li5g.ipid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_li5g_attrContents[8], { "Sequence Number", "li5g.sq", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_li5g_attrContents[9], { "Timestamp", "li5g.ts", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, NULL, HFILL }},
        { &hf_li5g_attrContents[10], { "Source IPv4 address", "li5g.srcip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_li5g_attrContents[11], { "Destination IPv4 address", "li5g.dstip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_li5g_attrContents[12], { "Source IPv6 address", "li5g.srcipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_li5g_attrContents[13], { "Destination IPv6 address", "li5g.dstipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_li5g_attrContents[14], { "Source Port", "li5g.srcport", FT_UINT16, BASE_PT_TCP, NULL, 0x0, NULL, HFILL }},
        { &hf_li5g_attrContents[15], { "Destination Port", "li5g.dstport", FT_UINT16, BASE_PT_TCP, NULL, 0x0, NULL, HFILL }},
        { &hf_li5g_attrContents[16], { "IP Protocol", "li5g.ipproto", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &ipproto_val_ext, 0x0, NULL, HFILL }},
        { &hf_li5g_attrContents[17], { "Matched Target Identifier", "li5g.mti", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_li5g_attrContents[18], { "Other Target Identifier", "li5g.oti", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_li5g_pld, { "Payload", "li5g.pld", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_li5g,
        &ett_attrContents[5],
        &ett_attrContents[6],
        &ett_attrContents[7],
        &ett_attrContents[8],
        &ett_attrContents[9],
        &ett_attrContents[10],
        &ett_attrContents[11],
        &ett_attrContents[12],
        &ett_attrContents[13],
        &ett_attrContents[14],
        &ett_attrContents[15],
        &ett_attrContents[16],
        &ett_attrContents[17],
        &ett_attrContents[18],
    };

    proto_li5g = proto_register_protocol("5G Lawful Interception", "5GLI", "5gli");
    proto_register_field_array(proto_li5g, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_li5g(void)
{
    subProtocol_handle[2]=find_dissector_add_dependency("xiri", proto_li5g);
    subProtocol_handle[5]=find_dissector("ip");
    subProtocol_handle[6]=find_dissector("ipv6");
    subProtocol_handle[7]=find_dissector("eth");
    subProtocol_handle[8]=find_dissector("rtp");
    subProtocol_handle[9]=find_dissector("sip");
    subProtocol_handle[10]=find_dissector("dhcp");
    subProtocol_handle[11]=find_dissector("radius");
    subProtocol_handle[12]=find_dissector("gtp");
    subProtocol_handle[13]=find_dissector("msrp");

    li5g_handle = register_dissector("li5g", dissect_li5g, proto_li5g);
    dissector_add_uint_range_with_preference("tcp.port", "", li5g_handle);
    dissector_add_uint_range_with_preference("udp.port", "", li5g_handle);
    heur_dissector_add("tls", dissect_li5g_heur, "5G LI over TLS", "li5g_tls", proto_li5g, HEURISTIC_ENABLE);
}
