/* packet-pktc.c
 * Declarations of routines for PKTC PacketCable packet disassembly
 * Ronnie Sahlberg 2004
 * See the spec: PKT-SP-SEC-I10-040113.pdf
 *
 * $Id: packet-pktc.c,v 1.1 2004/05/18 08:22:26 sahlberg Exp $
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include "packet-pktc.h"
#include "packet-kerberos.h"

#define PKTC_PORT	1293

static int proto_pktc = -1;
static gint hf_pktc_kmmid = -1;
static gint hf_pktc_doi = -1;
static gint hf_pktc_version_major = -1;
static gint hf_pktc_version_minor = -1;
static gint hf_pktc_server_nonce = -1;

static gint ett_pktc = -1;

#define KMMID_WAKEUP		0x01
#define KMMID_AP_REQUEST	0x02
#define KMMID_AP_REPLY		0x03
#define KMMID_SEC_PARAM_REC	0x04
#define KMMID_REKEY		0x05
#define KMMID_ERROR_REPLY	0x06
static const value_string kmmid_types[] = {
    { KMMID_WAKEUP		, "Wake Up" },
    { KMMID_AP_REQUEST		, "AP Request" },
    { KMMID_AP_REPLY		, "AP Reply" },
    { KMMID_SEC_PARAM_REC	, "Security Parameter Recovered" },
    { KMMID_REKEY		, "Rekey" },
    { KMMID_ERROR_REPLY		, "Error Reply" },
    { 0, NULL }
};

#define DOI_IPSEC	1
#define DOI_SNMPv3	2
static const value_string doi_types[] = {
    { DOI_IPSEC		, "IPSec" },
    { DOI_SNMPv3	, "SNMPv3" },
    { 0, NULL }
};


static int
dissect_pktc_ap_request(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
    tvbuff_t *pktc_tvb;
    guint32 snonce;

    /* AP Request  kerberos blob */
    pktc_tvb = tvb_new_subset(tvb, offset, -1, -1); 
    offset += dissect_kerberos_main(pktc_tvb, pinfo, tree, FALSE);

    /* Server Nonce */
    snonce=tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(tree, hf_pktc_server_nonce, tvb, offset, 4, snonce);

/* XXX  here all the remaining stuff should go */
    return offset;
}

static int
dissect_pktc_ap_reply(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
    tvbuff_t *pktc_tvb;

    /* AP Reply  kerberos blob */
    pktc_tvb = tvb_new_subset(tvb, offset, -1, -1); 
    offset += dissect_kerberos_main(pktc_tvb, pinfo, tree, FALSE);

/* XXX  here all the remaining stuff should go */
    return offset;
}

static void
dissect_pktc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 kmmid, doi, version;
    int offset=0;
    proto_tree *pktc_tree = NULL;
    proto_item *item = NULL;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "PKTC");

    if (tree) {
        item = proto_tree_add_item(tree, proto_pktc, tvb, 0, 3, FALSE);
        pktc_tree = proto_item_add_subtree(item, ett_pktc);
    }

    /* key management message id */
    kmmid=tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(pktc_tree, hf_pktc_kmmid, tvb, offset, 1, kmmid);
    offset+=1;

    /* domain of interpretation */
    doi=tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(pktc_tree, hf_pktc_doi, tvb, offset, 1, doi);
    offset+=1;
    
    /* version */
    version=tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(pktc_tree, hf_pktc_version_major, tvb, offset, 1, (version>>4)&0x0f);
    proto_tree_add_uint(pktc_tree, hf_pktc_version_minor, tvb, offset, 1, (version)&0x0f);
    offset+=1;

    switch(kmmid){
    case KMMID_AP_REQUEST:
        offset=dissect_pktc_ap_request(pinfo, pktc_tree, tvb, offset);
        break;
    case KMMID_AP_REPLY:
        offset=dissect_pktc_ap_reply(pinfo, pktc_tree, tvb, offset);
        break;
    };
}

void
proto_register_pktc(void)
{
    static hf_register_info hf[] = {
	{ &hf_pktc_kmmid, {
	    "Key Management Message ID", "pktc.kmmid", FT_UINT8, BASE_HEX,
	    VALS(kmmid_types), 0, "Key Management Message ID", HFILL }},
	{ &hf_pktc_doi, {
	    "Domain of Interpretation", "pktc.doi", FT_UINT8, BASE_DEC,
	    VALS(doi_types), 0, "Domain of Interpretation", HFILL }},
	{ &hf_pktc_version_major, {
	    "Major version", "pktc.version.major", FT_UINT8, BASE_DEC,
	    NULL, 0, "Major version of PKTC", HFILL }},
	{ &hf_pktc_version_minor, {
	    "Minor version", "pktc.version.minor", FT_UINT8, BASE_DEC,
	    NULL, 0, "Minor version of PKTC", HFILL }},
	{ &hf_pktc_server_nonce, {
	    "Server Nonce", "pktc.server_nonce", FT_UINT32, BASE_HEX,
	    NULL, 0, "Server Nonce random number", HFILL }},
    };
    static gint *ett[] = {
        &ett_pktc,
    };

    proto_pktc = proto_register_protocol("PacketCable",
	"PKTC", "pktc");
    proto_register_field_array(proto_pktc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pktc(void)
{
    dissector_handle_t pktc_handle;

    pktc_handle = create_dissector_handle(dissect_pktc, proto_pktc);
    dissector_add("udp.port", PKTC_PORT, pktc_handle);
}
