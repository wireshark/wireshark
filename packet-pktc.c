/* packet-pktc.c
 * Routines for PacketCable (PKTC) Kerberized Key Management packet disassembly
 *
 * References: 
 * [1] PacketCable Security Specification, PKT-SP-SEC-I10-040113, January 13, 
 *     2004, Cable Television Laboratories, Inc., http://www.PacketCable.com/
 *
 * Ronnie Sahlberg 2004
 * Thomas Anders 2004
 *
 * $Id: packet-pktc.c,v 1.7 2004/06/04 11:32:52 sahlberg Exp $
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
#define PKTC_MTAFQDNMAP_PORT	2246

static int proto_pktc = -1;
static gint hf_pktc_app_spec_data = -1;
static gint hf_pktc_list_of_ciphersuites = -1;
static gint hf_pktc_list_of_ciphersuites_len = -1;
static gint hf_pktc_kmmid = -1;
static gint hf_pktc_doi = -1;
static gint hf_pktc_version_major = -1;
static gint hf_pktc_version_minor = -1;
static gint hf_pktc_server_nonce = -1;
static gint hf_pktc_server_principal = -1;
static gint hf_pktc_timestamp = -1;
static gint hf_pktc_snmpEngineID_len = -1;
static gint hf_pktc_snmpEngineID = -1;
static gint hf_pktc_snmpEngineBoots = -1;
static gint hf_pktc_snmpEngineTime = -1;
static gint hf_pktc_usmUserName_len = -1;
static gint hf_pktc_usmUserName = -1;
static gint hf_pktc_ipsec_spi = -1;
static gint hf_pktc_snmpAuthenticationAlgorithm = -1;
static gint hf_pktc_snmpEncryptionTransformID = -1;
static gint hf_pktc_ipsecAuthenticationAlgorithm = -1;
static gint hf_pktc_ipsecEncryptionTransformID = -1;
static gint hf_pktc_reestablish_flag = -1;
static gint hf_pktc_ack_required_flag = -1;
static gint hf_pktc_sha1_hmac = -1;
static gint hf_pktc_sec_param_lifetime = -1;
static gint hf_pktc_grace_period = -1;
static gint hf_pktc_mtafqdnmap = -1;

static gint ett_pktc = -1;
static gint ett_pktc_app_spec_data = -1;
static gint ett_pktc_list_of_ciphersuites = -1;
static gint ett_pktc_mtafqdnmap = -1;

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
#define SNMPv3_NULL    0x20
#define SNMPv3_DES     0x21
#define SNMPv3_HMAC_MD5        0x21
#define SNMPv3_HMAC_SHA1 0x22
#define ESP_3DES       0x03
#define ESP_RC5                0x04
#define ESP_IDEA       0x05
#define ESP_CAST       0x06
#define ESP_BLOWFISH   0x07
#define ESP_NULL       0x0b
#define ESP_AES                0x0c
#define HMAC_MD5_96    0x01
#define HMAC_SHA1_96   0x02


/* Domain of Interpretation */static const value_string doi_types[] = {
    { DOI_IPSEC		, "IPSec" },
    { DOI_SNMPv3	, "SNMPv3" },
    { 0, NULL }
};

/* SNMPv3 ciphersuites */
static const value_string snmp_authentication_algorithm_vals[] = {
    { SNMPv3_HMAC_MD5  , "HMAC-MD5" },
    { SNMPv3_HMAC_SHA1 , "HMAC-SHA1" },
    { 0        , NULL }
};
static const value_string snmp_transform_id_vals[] = {
    { SNMPv3_NULL      , "NULL (no encryption)" },
    { SNMPv3_DES       , "DES" },
    { 0        , NULL }
};

/* IPsec ciphersuites */
static const value_string ipsec_transform_id_vals[] = {
    { ESP_3DES         , "3DES" },
    { ESP_RC5          , "RC5" },
    { ESP_IDEA         , "IDEA" },
    { ESP_CAST         , "CAST" },
    { ESP_BLOWFISH     , "BLOWFISH" },
    { ESP_NULL         , "NULL (no encryption)" },
    { ESP_AES          , "AES-128" },
    { 0	, NULL }
};

static const value_string ipsec_authentication_algorithm_vals[] = {
    { HMAC_MD5_96      , "HMAC-MD5-96" },
    { HMAC_SHA1_96     , "HMAC-SHA-1-96" },
    { 0	, NULL }
};

static int
dissect_pktc_app_specific_data(packet_info *pinfo _U_, proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint8 doi, guint8 kmmid)
{
    int old_offset=offset;
    proto_tree *tree = NULL;
    proto_item *item = NULL;
    guint8 len;

    if (parent_tree) {
        item = proto_tree_add_item(parent_tree, hf_pktc_app_spec_data, tvb, offset, -1, FALSE);
        tree = proto_item_add_subtree(item, ett_pktc_app_spec_data);
    }

    switch(doi){
    case DOI_SNMPv3:
        switch(kmmid){
        /* we dont distinguish between manager and agent engineid.
           feel free to add separation for this if it is imporant enough
           for you. */
        case KMMID_AP_REQUEST:
        case KMMID_AP_REPLY:
            /* snmpEngineID Length */
            len=tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(tree, hf_pktc_snmpEngineID_len, tvb, offset, 1, len);
            offset+=1;

            /* snmpEngineID */
            proto_tree_add_item(tree, hf_pktc_snmpEngineID, tvb, offset, len, FALSE);
            offset+=len;

            /* boots */
            proto_tree_add_item(tree, hf_pktc_snmpEngineBoots, tvb, offset, 4, FALSE);
            offset+=4;

            /* time */
            proto_tree_add_item(tree, hf_pktc_snmpEngineTime, tvb, offset, 4, FALSE);
            offset+=4;

            /* usmUserName Length */
            len=tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(tree, hf_pktc_usmUserName_len, tvb, offset, 1, len);
            offset+=1;

            /* usmUserName */
            proto_tree_add_item(tree, hf_pktc_usmUserName, tvb, offset, len, FALSE);
            offset+=len;

            break;
        default:
            proto_tree_add_text(tree, tvb, offset, 1, "Unknown KMMID");
            tvb_get_guint8(tvb, 9999); /* bail out and inform user we cant dissect the packet */
        };
        break;
    case DOI_IPSEC:
        switch(kmmid){
        /* we dont distinguish between SPIs for inbound Security Associations 
	   of the client (AP-REQ) vs. server (AP-REP, REKEY). Feel free to add 
	   separation for this if it is imporant enough for you. */
        case KMMID_AP_REQUEST:
        case KMMID_AP_REPLY:
        case KMMID_REKEY:
            /* Security Parameter Index (SPI) */
            proto_tree_add_item(tree, hf_pktc_ipsec_spi, tvb, offset, 4, FALSE);
            offset+=4;

	    break;
        default:
            proto_tree_add_text(tree, tvb, offset, 1, "Unknown KMMID");
            tvb_get_guint8(tvb, 9999); /* bail out and inform user we cant dissect the packet */
        };
	break;
    default:
        proto_tree_add_text(tree, tvb, offset, 1, "Unknown DOI");
        tvb_get_guint8(tvb, 9999); /* bail out and inform user we cant dissect the packet */
    }

    proto_item_set_len(item, offset-old_offset);
    return offset;
}

static int
dissect_pktc_list_of_ciphersuites(packet_info *pinfo _U_, proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint8 doi)
{
    int old_offset=offset;
    proto_tree *tree = NULL;
    proto_item *item = NULL;
    guint8 len, i;

    if (parent_tree) {
        item = proto_tree_add_item(parent_tree, hf_pktc_list_of_ciphersuites, tvb, offset, -1, FALSE);
        tree = proto_item_add_subtree(item, ett_pktc_list_of_ciphersuites);
    }


    /* key management message id */
    len=tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_pktc_list_of_ciphersuites_len, tvb, offset, 1, len);
    offset+=1;

    switch(doi){
    case DOI_SNMPv3:
        for(i=0;i<len;i++){
            /* SNMPv3 authentication algorithm */
            proto_tree_add_item(tree, hf_pktc_snmpAuthenticationAlgorithm, tvb, offset, 1, FALSE);
            offset+=1;

            /* SNMPv3 encryption transform id */
            proto_tree_add_item(tree, hf_pktc_snmpEncryptionTransformID, tvb, offset, 1, FALSE);
            offset+=1;
	}
	break;
    case DOI_IPSEC:
        for(i=0;i<len;i++){
            /* IPsec authentication algorithm */
            proto_tree_add_item(tree, hf_pktc_ipsecAuthenticationAlgorithm, tvb, offset, 1, FALSE);
            offset+=1;

            /* IPsec encryption transform id */
            proto_tree_add_item(tree, hf_pktc_ipsecEncryptionTransformID, tvb, offset, 1, FALSE);
            offset+=1;
	}
        break;
    default:
        proto_tree_add_text(tree, tvb, offset, 1, "Unknown DOI");
	tvb_get_guint8(tvb, 9999); /* bail out and inform user we cant dissect the packet */
    }

    proto_item_set_len(item, offset-old_offset);
    return offset;
}

static int
dissect_pktc_wakeup(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    guint32 snonce;
    guint string_len;

    /* Server Nonce */
    snonce=tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(tree, hf_pktc_server_nonce, tvb, offset, 4, snonce);
    offset+=4;

    /* Server Kerberos Principal Identifier */
    string_len=tvb_strsize(tvb, offset);
    proto_tree_add_item(tree, hf_pktc_server_principal, tvb, offset, string_len, FALSE);
    offset+=string_len;

    return offset;
}

static int
dissect_pktc_ap_request(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, guint8 doi)
{
    tvbuff_t *pktc_tvb;
    guint32 snonce;

    /* AP Request  kerberos blob */
    pktc_tvb = tvb_new_subset(tvb, offset, -1, -1); 
    offset += dissect_kerberos_main(pktc_tvb, pinfo, tree, FALSE, NULL);

    /* Server Nonce */
    snonce=tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(tree, hf_pktc_server_nonce, tvb, offset, 4, snonce);
    offset+=4;

    /* app specific data */
    offset=dissect_pktc_app_specific_data(pinfo, tree, tvb, offset, doi, KMMID_AP_REQUEST);

    /* list of ciphersuites */
    offset=dissect_pktc_list_of_ciphersuites(pinfo, tree, tvb, offset, doi);

    /* re-establish flag */
    proto_tree_add_item(tree, hf_pktc_reestablish_flag, tvb, offset, 1, FALSE);
    offset+=1;

    /* sha-1 hmac */
    proto_tree_add_item(tree, hf_pktc_sha1_hmac, tvb, offset, 20, FALSE);
    offset+=20;

    return offset;
}

static int
dissect_pktc_ap_reply(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, guint8 doi)
{
    tvbuff_t *pktc_tvb;

    /* AP Reply  kerberos blob */
    pktc_tvb = tvb_new_subset(tvb, offset, -1, -1); 
    offset += dissect_kerberos_main(pktc_tvb, pinfo, tree, FALSE, NULL);

    /* app specific data */
    offset=dissect_pktc_app_specific_data(pinfo, tree, tvb, offset, doi, KMMID_AP_REPLY);

    /* selected ciphersuite */
    offset=dissect_pktc_list_of_ciphersuites(pinfo, tree, tvb, offset, doi);

    /* sec param lifetime */
    proto_tree_add_item(tree, hf_pktc_sec_param_lifetime, tvb, offset, 4, FALSE);
    offset+=4;

    /* grace period */
    proto_tree_add_item(tree, hf_pktc_grace_period, tvb, offset, 4, FALSE);
    offset+=4;

    /* re-establish flag */
    proto_tree_add_item(tree, hf_pktc_reestablish_flag, tvb, offset, 1, FALSE);
    offset+=1;

    /* ack required flag */
    proto_tree_add_item(tree, hf_pktc_ack_required_flag, tvb, offset, 1, FALSE);
    offset+=1;

    /* sha-1 hmac */
    proto_tree_add_item(tree, hf_pktc_sha1_hmac, tvb, offset, 20, FALSE);
    offset+=20;

    return offset;
}

static int
dissect_pktc_sec_param_rec(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    /* sha-1 hmac of the subkey of the preceding AP-REP */
    proto_tree_add_item(tree, hf_pktc_sha1_hmac, tvb, offset, 20, FALSE);
    offset+=20;

    return offset;
}

static int
dissect_pktc_rekey(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, guint8 doi)
{
    guint32 snonce;
    guint string_len;
    const guint8 *timestr;

    /* Server Nonce */
    snonce=tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(tree, hf_pktc_server_nonce, tvb, offset, 4, snonce);
    offset+=4;

    /* Server Kerberos Principal Identifier */
    string_len=tvb_strsize(tvb, offset);
    proto_tree_add_item(tree, hf_pktc_server_principal, tvb, offset, string_len, FALSE);
    offset+=string_len;

    /* Timestamp: YYMMDDhhmmssZ */
    /* They really came up with a two-digit year in late 1990s! =8o */
    timestr=tvb_get_ptr(tvb, offset, 13);
    proto_tree_add_string_format(tree, hf_pktc_timestamp, tvb, offset, 13, timestr, 
				 "Timestamp: %.2s-%.2s-%.2s %.2s:%.2s:%.2s", 
				 timestr, timestr+2, timestr+4, timestr+6, timestr+8, timestr+10);
    offset+=13;

    /* app specific data */
    offset=dissect_pktc_app_specific_data(pinfo, tree, tvb, offset, doi, KMMID_REKEY);

    /* list of ciphersuites */
    offset=dissect_pktc_list_of_ciphersuites(pinfo, tree, tvb, offset, doi);

    /* sec param lifetime */
    proto_tree_add_item(tree, hf_pktc_sec_param_lifetime, tvb, offset, 4, FALSE);
    offset+=4;

    /* grace period */
    proto_tree_add_item(tree, hf_pktc_grace_period, tvb, offset, 4, FALSE);
    offset+=4;

    /* re-establish flag */
    proto_tree_add_item(tree, hf_pktc_reestablish_flag, tvb, offset, 1, FALSE);
    offset+=1;

    /* sha-1 hmac */
    proto_tree_add_item(tree, hf_pktc_sha1_hmac, tvb, offset, 20, FALSE);
    offset+=20;

    return offset;
}

static int
dissect_pktc_error_reply(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
    tvbuff_t *pktc_tvb;

    /* KRB_ERROR */
    pktc_tvb = tvb_new_subset(tvb, offset, -1, -1); 
    offset += dissect_kerberos_main(pktc_tvb, pinfo, tree, FALSE, NULL);

    return offset;
}

static int
dissect_pktc_appspecificdata(packet_info *pinfo _U_, tvbuff_t *tvb _U_, proto_tree *tree _U_)
{
	int offset=0;
	/*XXX add dissection of the app specific data here */
	return offset;
}

static kerberos_callbacks cb[] = {
	{ KRB_CBTAG_SAFE_USER_DATA,	dissect_pktc_appspecificdata },
	{ 0, NULL }
};

static void
dissect_pktc_mtafqdnmap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset=0;
    proto_tree *pktc_mtafqdnmap_tree = NULL;
    proto_item *item = NULL;
    tvbuff_t *pktc_mtafqdnmap_tvb;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "PKTC");

    if (tree) {
        item = proto_tree_add_item(tree, proto_pktc, tvb, 0, 0, FALSE);
        pktc_mtafqdnmap_tree = proto_item_add_subtree(item, ett_pktc_mtafqdnmap);
    }

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "MTAFQDNMAP %s",
		     pinfo->srcport == pinfo->match_port ? "Reply":"Request");
    }

    /* KRB_AP_RE[QP] */
    pktc_mtafqdnmap_tvb = tvb_new_subset(tvb, offset, -1, -1); 
    offset += dissect_kerberos_main(pktc_mtafqdnmap_tvb, pinfo, pktc_mtafqdnmap_tree, FALSE, NULL);

    /* KRB_SAFE */
    pktc_mtafqdnmap_tvb = tvb_new_subset(tvb, offset, -1, -1); 
    offset += dissect_kerberos_main(pktc_mtafqdnmap_tvb, pinfo, pktc_mtafqdnmap_tree, FALSE, cb);

    proto_item_set_len(item, offset);
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

    /* fill COL_INFO */
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_add_str(pinfo->cinfo, COL_INFO, 
		    val_to_str(kmmid, kmmid_types, "Unknown KMMID %#x"));
	col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
		        val_to_str(doi, doi_types, "Unknown DOI %#x"));
    }

    switch(kmmid){
    case KMMID_WAKEUP:
        offset=dissect_pktc_wakeup(pktc_tree, tvb, offset);
	break;
    case KMMID_AP_REQUEST:
        offset=dissect_pktc_ap_request(pinfo, pktc_tree, tvb, offset, doi);
        break;
    case KMMID_AP_REPLY:
        offset=dissect_pktc_ap_reply(pinfo, pktc_tree, tvb, offset, doi);
        break;
    case KMMID_SEC_PARAM_REC:
        offset=dissect_pktc_sec_param_rec(pktc_tree, tvb, offset);
	break;
    case KMMID_REKEY:
        offset=dissect_pktc_rekey(pinfo, pktc_tree, tvb, offset, doi);
	break;
    case KMMID_ERROR_REPLY:
        offset=dissect_pktc_error_reply(pinfo, pktc_tree, tvb, offset);
	break;
    };

    proto_item_set_len(item, offset);
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
	{ &hf_pktc_server_principal, {
	    "Server Kerberos Principal Identifier", "pktc.server_principal", FT_STRING, BASE_DEC,
	    NULL, 0, "Server Kerberos Principal Identifier", HFILL }},
	{ &hf_pktc_timestamp, {
	    "Timestamp", "pktc.timestamp", FT_STRING, BASE_NONE,
	    NULL, 0, "Timestamp (UTC)", HFILL }},
	{ &hf_pktc_app_spec_data, {
	    "Application Specific Data", "pktc.asd", FT_NONE, BASE_HEX,
	    NULL, 0, "KMMID/DOI application specific data", HFILL }},
	{ &hf_pktc_list_of_ciphersuites, {
	    "List of Ciphersuites", "pktc.list_of_ciphersuites", FT_NONE, BASE_HEX,
	    NULL, 0, "List of Ciphersuites", HFILL }},
	{ &hf_pktc_list_of_ciphersuites_len, {
	    "Number of Ciphersuites", "pktc.list_of_ciphersuites.len", FT_UINT8, BASE_DEC,
	    NULL, 0, "Number of Ciphersuites", HFILL }},
	{ &hf_pktc_snmpAuthenticationAlgorithm, {
           "SNMPv3 Authentication Algorithm", "pktc.asd.snmp_auth_alg", FT_UINT8, BASE_HEX,
           VALS(snmp_authentication_algorithm_vals), 0, "SNMPv3 Authentication Algorithm", HFILL }},
	{ &hf_pktc_snmpEncryptionTransformID, {
           "SNMPv3 Encryption Transform ID", "pktc.asd.snmp_enc_alg", FT_UINT8, BASE_HEX,
           VALS(snmp_transform_id_vals), 0, "SNMPv3 Encryption Transform ID", HFILL }},
	{ &hf_pktc_ipsecAuthenticationAlgorithm, {
           "IPsec Authentication Algorithm", "pktc.asd.ipsec_auth_alg", FT_UINT8, BASE_HEX,
           VALS(ipsec_authentication_algorithm_vals), 0, "IPsec Authentication Algorithm", HFILL }},
	{ &hf_pktc_ipsecEncryptionTransformID, {
           "IPsec Encryption Transform ID", "pktc.asd.ipsec_enc_alg", FT_UINT8, BASE_HEX,
           VALS(ipsec_transform_id_vals), 0, "IPsec Encryption Transform ID", HFILL }},
	{ &hf_pktc_snmpEngineID_len, {
           "SNMPv3 Engine ID Length", "pktc.asd.snmp_engine_id.len", FT_UINT8, BASE_DEC,
           NULL, 0, "Length of SNMPv3 Engine ID", HFILL }},
	{ &hf_pktc_snmpEngineID, {
           "SNMPv3 Engine ID", "pktc.asd.snmp_engine_id", FT_BYTES, BASE_HEX,
           NULL, 0, "SNMPv3 Engine ID", HFILL }},
	{ &hf_pktc_snmpEngineBoots, {
           "SNMPv3 Engine Boots", "pktc.asd.snmp_engine_boots", FT_UINT32, BASE_DEC,
           NULL, 0, "SNMPv3 Engine Boots", HFILL }},
	{ &hf_pktc_snmpEngineTime, {
           "SNMPv3 Engine Time", "pktc.asd.snmp_engine_time", FT_UINT32, BASE_DEC,
           NULL, 0, "SNMPv3 Engine ID Time", HFILL }},
	{ &hf_pktc_usmUserName_len, {
           "SNMPv3 USM User Name Length", "pktc.asd.snmp_usm_username.len", FT_UINT8, BASE_DEC,
           NULL, 0, "Length of SNMPv3 USM User Name", HFILL }},
	{ &hf_pktc_usmUserName, {
           "SNMPv3 USM User Name", "pktc.asd.snmp_usm_username", FT_STRING, BASE_DEC,
           NULL, 0, "SNMPv3 USM User Name", HFILL }},
	{ &hf_pktc_ipsec_spi, {
           "IPsec Security Parameter Index", "pktc.asd.ipsec_spi", FT_UINT32, BASE_DEC,
           NULL, 0, "Security Parameter Index for inbound Security Association (IPsec)", HFILL }},
	{ &hf_pktc_reestablish_flag, {
	    "Re-establish Flag", "pktc.reestablish", FT_BOOLEAN, BASE_NONE,
	    NULL, 0, "Re-establish Flag", HFILL }},
	{ &hf_pktc_ack_required_flag, {
	    "ACK Required Flag", "pktc.ack_required", FT_BOOLEAN, BASE_NONE,
	    NULL, 0, "ACK Required Flag", HFILL }},
	{ &hf_pktc_sec_param_lifetime, {
	    "Security Parameter Lifetime", "pktc.spl", FT_UINT32, BASE_DEC,
	    NULL, 0, "Lifetime in seconds of security parameter", HFILL }},
        { &hf_pktc_sha1_hmac, {
           "SHA-1 HMAC", "pktc.sha1_hmac", FT_BYTES, BASE_HEX,
           NULL, 0, "SHA-1 HMAC", HFILL }},
	{ &hf_pktc_grace_period, {
	    "Grace Period", "pktc.grace_period", FT_UINT32, BASE_DEC,
	    NULL, 0, "Grace Period in seconds", HFILL }},
    };
    static gint *ett[] = {
        &ett_pktc,
        &ett_pktc_app_spec_data,
        &ett_pktc_list_of_ciphersuites,
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

void
proto_register_pktc_mtafqdnmap(void)
{
    static hf_register_info hf[] = {
	{ &hf_pktc_mtafqdnmap, {
	    "MTAFQDNMAP", "pktc.mtafqdnmap", FT_BOOLEAN, BASE_NONE,
	    NULL, 0, "MTAFQDNMAP Message", HFILL }},
    };
    static gint *ett[] = {
        &ett_pktc_mtafqdnmap,
    };

    proto_register_field_array(proto_pktc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pktc_mtafqdnmap(void)
{
    dissector_handle_t pktc_mtafqdnmap_handle;

    pktc_mtafqdnmap_handle = create_dissector_handle(dissect_pktc_mtafqdnmap, proto_pktc);
    dissector_add("udp.port", PKTC_MTAFQDNMAP_PORT, pktc_mtafqdnmap_handle);
}
