/* packet-pktc.c
 * Routines for PacketCable (PKTC) Kerberized Key Management and
 *              PacketCable (PKTC) MTA FQDN                  packet disassembly
 *
 * References:
 * [1] PacketCable 1.0 Security Specification, PKT-SP-SEC-I11-040730, July 30,
 *     2004, Cable Television Laboratories, Inc., http://www.PacketCable.com/
 *
 * Ronnie Sahlberg 2004
 * Thomas Anders 2004
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
#include <epan/asn1.h>
#include "packet-pktc.h"
#include "packet-kerberos.h"
#include "packet-snmp.h"

#define PKTC_PORT	1293
#define PKTC_MTAFQDN_PORT	2246

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

static gint hf_pktc_mtafqdn_msgtype = -1;
static gint hf_pktc_mtafqdn_enterprise = -1;
static gint hf_pktc_mtafqdn_version = -1;
static gint hf_pktc_mtafqdn_mac = -1;
static gint hf_pktc_mtafqdn_pub_key_hash = -1;
static gint hf_pktc_mtafqdn_manu_cert_revoked = -1;
static gint hf_pktc_mtafqdn_fqdn = -1;
static gint hf_pktc_mtafqdn_ip = -1;

static gint ett_pktc = -1;
static gint ett_pktc_app_spec_data = -1;
static gint ett_pktc_list_of_ciphersuites = -1;
static gint ett_pktc_engineid = -1;

static gint ett_pktc_mtafqdn = -1;

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


/* Domain of Interpretation */
static const value_string doi_types[] = {
    { DOI_IPSEC                , "IPsec" },
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
    { SNMPv3_NULL      , "NULL" }, /* no encryption */
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
    { ESP_NULL         , "NULL" }, /* no encryption, RFC 2410 */
    { ESP_AES          , "AES-128" },
    { 0	, NULL }
};

static const value_string ipsec_authentication_algorithm_vals[] = {
    { HMAC_MD5_96      , "HMAC-MD5-96" },   /* RFC 2403 */
    { HMAC_SHA1_96     , "HMAC-SHA-1-96" }, /* RFC 2404 */
    { 0        , NULL }
};

/* MTA FQDN Message Types */
#define PKTC_MTAFQDN_REQ       0x01
#define PKTC_MTAFQDN_REP       0x02
#define PKTC_MTAFQDN_ERR       0x03
static const value_string pktc_mtafqdn_msgtype_vals[] = {
    { PKTC_MTAFQDN_REQ,        "MTA FQDN Request" },
    { PKTC_MTAFQDN_REP,        "MTA FQDN Reply" },
    { PKTC_MTAFQDN_ERR,        "MTA FQDN Error Reply" },
    { 0	, NULL }
};

static int
dissect_pktc_app_specific_data(packet_info *pinfo _U_, proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint8 doi, guint8 kmmid)
{
    int old_offset=offset;
    proto_tree *tree = NULL;
    proto_tree *engineid_tree = NULL;
    proto_item *item = NULL;
    proto_item *engineid_item = NULL;
    guint8 len;

    if (parent_tree) {
        item = proto_tree_add_item(parent_tree, hf_pktc_app_spec_data, tvb, offset, -1, ENC_NA);
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
            engineid_item = proto_tree_add_item(tree, hf_pktc_snmpEngineID, tvb, offset, len, ENC_NA);
	    engineid_tree = proto_item_add_subtree(engineid_item, ett_pktc_engineid);
	    dissect_snmp_engineid(engineid_tree, tvb, offset, len);
            offset+=len;

            /* boots */
            proto_tree_add_item(tree, hf_pktc_snmpEngineBoots, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;

            /* time */
            proto_tree_add_item(tree, hf_pktc_snmpEngineTime, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;

            /* usmUserName Length */
            len=tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(tree, hf_pktc_usmUserName_len, tvb, offset, 1, len);
            offset+=1;

            /* usmUserName */
            proto_tree_add_item(tree, hf_pktc_usmUserName, tvb, offset, len, ENC_ASCII|ENC_NA);
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
            proto_tree_add_item(tree, hf_pktc_ipsec_spi, tvb, offset, 4, ENC_BIG_ENDIAN);
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
    proto_item *item = NULL, *hidden_item;
    guint8 len, i;

    if (parent_tree) {
        item = proto_tree_add_item(parent_tree, hf_pktc_list_of_ciphersuites, tvb, offset, -1, ENC_NA);
        tree = proto_item_add_subtree(item, ett_pktc_list_of_ciphersuites);
    }


    /* number of ciphersuites */
    len=tvb_get_guint8(tvb, offset);
    if (len>0) {
      proto_item_append_text(tree, " (%d):", len);
    }
    hidden_item = proto_tree_add_uint(tree, hf_pktc_list_of_ciphersuites_len, tvb, offset, 1, len);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    offset+=1;

    switch(doi){
    case DOI_SNMPv3:
        for(i=0;i<len;i++){
            /* SNMPv3 authentication algorithm */
            proto_tree_add_item(tree, hf_pktc_snmpAuthenticationAlgorithm, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(tree, " %s", val_to_str(tvb_get_guint8(tvb, offset), snmp_authentication_algorithm_vals, "%0x"));
            offset+=1;

            /* SNMPv3 encryption transform id */
            proto_tree_add_item(tree, hf_pktc_snmpEncryptionTransformID, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(tree, "/%s", val_to_str(tvb_get_guint8(tvb, offset), snmp_transform_id_vals, "%0x"));
            offset+=1;
	}
	break;
    case DOI_IPSEC:
        for(i=0;i<len;i++){
            /* IPsec authentication algorithm */
            proto_tree_add_item(tree, hf_pktc_ipsecAuthenticationAlgorithm, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(tree, " %s", val_to_str(tvb_get_guint8(tvb, offset), ipsec_authentication_algorithm_vals, "%0x"));
            offset+=1;

            /* IPsec encryption transform id */
            proto_tree_add_item(tree, hf_pktc_ipsecEncryptionTransformID, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(tree, "/%s", val_to_str(tvb_get_guint8(tvb, offset), ipsec_transform_id_vals, "%0x"));
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
    proto_tree_add_item(tree, hf_pktc_server_principal, tvb, offset, string_len, ENC_ASCII|ENC_NA);
    offset+=string_len;

    return offset;
}

static int
dissect_pktc_ap_request(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, guint8 doi)
{
    tvbuff_t *pktc_tvb;
    guint32 snonce;

    /* AP Request  kerberos blob */
    pktc_tvb = tvb_new_subset_remaining(tvb, offset);
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
    proto_tree_add_item(tree, hf_pktc_reestablish_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    /* sha-1 hmac */
    proto_tree_add_item(tree, hf_pktc_sha1_hmac, tvb, offset, 20, ENC_NA);
    offset+=20;

    return offset;
}

static int
dissect_pktc_ap_reply(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, guint8 doi)
{
    tvbuff_t *pktc_tvb;

    /* AP Reply  kerberos blob */
    pktc_tvb = tvb_new_subset_remaining(tvb, offset);
    offset += dissect_kerberos_main(pktc_tvb, pinfo, tree, FALSE, NULL);

    /* app specific data */
    offset=dissect_pktc_app_specific_data(pinfo, tree, tvb, offset, doi, KMMID_AP_REPLY);

    /* selected ciphersuite */
    offset=dissect_pktc_list_of_ciphersuites(pinfo, tree, tvb, offset, doi);

    /* sec param lifetime */
    proto_tree_add_uint_format(tree, hf_pktc_sec_param_lifetime, tvb, offset, 4,
                               tvb_get_ntohl(tvb, offset), "%s: %s",
                               proto_registrar_get_name(hf_pktc_sec_param_lifetime),
                               time_secs_to_str(tvb_get_ntohl(tvb, offset)));
    offset+=4;

    /* grace period */
    proto_tree_add_item(tree, hf_pktc_grace_period, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* re-establish flag */
    proto_tree_add_item(tree, hf_pktc_reestablish_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    /* ack required flag */
    proto_tree_add_item(tree, hf_pktc_ack_required_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    /* sha-1 hmac */
    proto_tree_add_item(tree, hf_pktc_sha1_hmac, tvb, offset, 20, ENC_NA);
    offset+=20;

    return offset;
}

static int
dissect_pktc_sec_param_rec(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    /* sha-1 hmac of the subkey of the preceding AP-REP */
    proto_tree_add_item(tree, hf_pktc_sha1_hmac, tvb, offset, 20, ENC_NA);
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
    proto_tree_add_item(tree, hf_pktc_server_principal, tvb, offset, string_len, ENC_ASCII|ENC_NA);
    offset+=string_len;

    /* Timestamp: YYMMDDhhmmssZ */
    /* They really came up with a two-digit year in late 1990s! =8o */
    timestr=tvb_get_ptr(tvb, offset, 13);
    proto_tree_add_string_format(tree, hf_pktc_timestamp, tvb, offset, 13, timestr,
                                "%s: %.2s-%.2s-%.2s %.2s:%.2s:%.2s",
                                proto_registrar_get_name(hf_pktc_timestamp),
				 timestr, timestr+2, timestr+4, timestr+6, timestr+8, timestr+10);
    offset+=13;

    /* app specific data */
    offset=dissect_pktc_app_specific_data(pinfo, tree, tvb, offset, doi, KMMID_REKEY);

    /* list of ciphersuites */
    offset=dissect_pktc_list_of_ciphersuites(pinfo, tree, tvb, offset, doi);

    /* sec param lifetime */
    proto_tree_add_item(tree, hf_pktc_sec_param_lifetime, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* grace period */
    proto_tree_add_item(tree, hf_pktc_grace_period, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    /* re-establish flag */
    proto_tree_add_item(tree, hf_pktc_reestablish_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    /* sha-1 hmac */
    proto_tree_add_item(tree, hf_pktc_sha1_hmac, tvb, offset, 20, ENC_NA);
    offset+=20;

    return offset;
}

static int
dissect_pktc_error_reply(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
    tvbuff_t *pktc_tvb;

    /* KRB_ERROR */
    pktc_tvb = tvb_new_subset_remaining(tvb, offset);
    offset += dissect_kerberos_main(pktc_tvb, pinfo, tree, FALSE, NULL);

    return offset;
}

static int
dissect_pktc_mtafqdn_krbsafeuserdata(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree)
{
    int offset=0, string_len=0;
    guint8 msgtype;
    guint32 bignum;
    nstime_t ts;

    /* message type */
    msgtype = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_pktc_mtafqdn_msgtype, tvb, offset, 1, msgtype);
    offset+=1;

    if (check_col(pinfo->cinfo, COL_INFO))
        col_add_str(pinfo->cinfo, COL_INFO,
                   val_to_str(msgtype, pktc_mtafqdn_msgtype_vals, "MsgType %u"));

    /* enterprise */
    proto_tree_add_uint(tree, hf_pktc_mtafqdn_enterprise, tvb, offset, 4, tvb_get_ntohl(tvb, offset));
    offset+=4;

    /* protocol version */
    proto_tree_add_uint(tree, hf_pktc_mtafqdn_version, tvb, offset, 1, tvb_get_guint8(tvb, offset));
    offset+=1;

    switch(msgtype) {
    case PKTC_MTAFQDN_REQ:
        /* MTA MAC address */
        proto_tree_add_item(tree, hf_pktc_mtafqdn_mac, tvb, offset, 6, ENC_NA);
       offset+=6;

       /* MTA pub key hash */
       proto_tree_add_item(tree, hf_pktc_mtafqdn_pub_key_hash, tvb, offset, 20, ENC_NA);
       offset+=20;

       /* manufacturer cert revocation time */
       bignum = tvb_get_ntohl(tvb, offset);
       ts.secs = bignum;
       proto_tree_add_time_format(tree, hf_pktc_mtafqdn_manu_cert_revoked, tvb, offset, 4,
                                  &ts, "%s: %s",
                                  proto_registrar_get_name(hf_pktc_mtafqdn_manu_cert_revoked),
                                  (bignum==0) ? "not revoked" : abs_time_secs_to_str(bignum, ABSOLUTE_TIME_LOCAL, TRUE));
       break;

    case PKTC_MTAFQDN_REP:
        /* MTA FQDN */
        string_len = tvb_length_remaining(tvb, offset) - 4;
        if (string_len <= 0)
                THROW(ReportedBoundsError);
        proto_tree_add_item(tree, hf_pktc_mtafqdn_fqdn, tvb, offset, string_len, ENC_ASCII|ENC_NA);
        offset+=string_len;

        /* MTA IP address */
        tvb_memcpy(tvb, (guint8 *)&bignum, offset, sizeof(bignum));
        proto_tree_add_ipv4(tree, hf_pktc_mtafqdn_ip, tvb, offset, 4, bignum);

        break;
    }

    return offset;
}

static kerberos_callbacks cb[] = {
    { KRB_CBTAG_SAFE_USER_DATA,      dissect_pktc_mtafqdn_krbsafeuserdata },
    { 0, NULL }
};

static void
dissect_pktc_mtafqdn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset=0;
    proto_tree *pktc_mtafqdn_tree = NULL;
    proto_item *item = NULL;
    tvbuff_t *pktc_mtafqdn_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PKTC");

    if (tree) {
        item = proto_tree_add_item(tree, proto_pktc, tvb, 0, 0, FALSE);
        pktc_mtafqdn_tree = proto_item_add_subtree(item, ett_pktc_mtafqdn);
    }

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "MTA FQDN %s",
                    pinfo->srcport == pinfo->match_uint ? "Reply":"Request");
    }


    /* KRB_AP_RE[QP] */
    pktc_mtafqdn_tvb = tvb_new_subset_remaining(tvb, offset);
    offset += dissect_kerberos_main(pktc_mtafqdn_tvb, pinfo, pktc_mtafqdn_tree, FALSE, NULL);

    /* KRB_SAFE */
    pktc_mtafqdn_tvb = tvb_new_subset_remaining(tvb, offset);
    offset += dissect_kerberos_main(pktc_mtafqdn_tvb, pinfo, pktc_mtafqdn_tree, FALSE, cb);

    proto_item_set_len(item, offset);
}


static void
dissect_pktc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 kmmid, doi, version;
    int offset=0;
    proto_tree *pktc_tree = NULL;
    proto_item *item = NULL, *hidden_item;

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
    proto_tree_add_text(pktc_tree, tvb, offset, 1, "Version: %d.%d", (version>>4)&0x0f, (version)&0x0f);
    hidden_item = proto_tree_add_uint(pktc_tree, hf_pktc_version_major, tvb, offset, 1, (version>>4)&0x0f);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
    hidden_item = proto_tree_add_uint(pktc_tree, hf_pktc_version_minor, tvb, offset, 1, (version)&0x0f);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
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
	    VALS(kmmid_types), 0, NULL, HFILL }},
	{ &hf_pktc_doi, {
	    "Domain of Interpretation", "pktc.doi", FT_UINT8, BASE_DEC,
	    VALS(doi_types), 0, NULL, HFILL }},
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
	    "Server Kerberos Principal Identifier", "pktc.server_principal", FT_STRING, BASE_NONE,
	    NULL, 0, NULL, HFILL }},
	{ &hf_pktc_timestamp, {
	    "Timestamp", "pktc.timestamp", FT_STRING, BASE_NONE,
	    NULL, 0, "Timestamp (UTC)", HFILL }},
	{ &hf_pktc_app_spec_data, {
	    "Application Specific Data", "pktc.asd", FT_NONE, BASE_NONE,
	    NULL, 0, "KMMID/DOI application specific data", HFILL }},
	{ &hf_pktc_list_of_ciphersuites, {
            "List of Ciphersuites", "pktc.ciphers", FT_NONE, BASE_NONE,
	    NULL, 0, NULL, HFILL }},
	{ &hf_pktc_list_of_ciphersuites_len, {
            "Number of Ciphersuites", "pktc.ciphers.len", FT_UINT8, BASE_DEC,
	    NULL, 0, NULL, HFILL }},
	{ &hf_pktc_snmpAuthenticationAlgorithm, {
           "SNMPv3 Authentication Algorithm", "pktc.asd.snmp_auth_alg", FT_UINT8, BASE_HEX,
           VALS(snmp_authentication_algorithm_vals), 0, NULL, HFILL }},
	{ &hf_pktc_snmpEncryptionTransformID, {
           "SNMPv3 Encryption Transform ID", "pktc.asd.snmp_enc_alg", FT_UINT8, BASE_HEX,
           VALS(snmp_transform_id_vals), 0, NULL, HFILL }},
	{ &hf_pktc_ipsecAuthenticationAlgorithm, {
           "IPsec Authentication Algorithm", "pktc.asd.ipsec_auth_alg", FT_UINT8, BASE_HEX,
           VALS(ipsec_authentication_algorithm_vals), 0, NULL, HFILL }},
	{ &hf_pktc_ipsecEncryptionTransformID, {
           "IPsec Encryption Transform ID", "pktc.asd.ipsec_enc_alg", FT_UINT8, BASE_HEX,
           VALS(ipsec_transform_id_vals), 0, NULL, HFILL }},
	{ &hf_pktc_snmpEngineID_len, {
           "SNMPv3 Engine ID Length", "pktc.asd.snmp_engine_id.len", FT_UINT8, BASE_DEC,
           NULL, 0, "Length of SNMPv3 Engine ID", HFILL }},
	{ &hf_pktc_snmpEngineID, {
           "SNMPv3 Engine ID", "pktc.asd.snmp_engine_id", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL }},
	{ &hf_pktc_snmpEngineBoots, {
           "SNMPv3 Engine Boots", "pktc.asd.snmp_engine_boots", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL }},
	{ &hf_pktc_snmpEngineTime, {
           "SNMPv3 Engine Time", "pktc.asd.snmp_engine_time", FT_UINT32, BASE_DEC,
           NULL, 0, "SNMPv3 Engine ID Time", HFILL }},
	{ &hf_pktc_usmUserName_len, {
           "SNMPv3 USM User Name Length", "pktc.asd.snmp_usm_username.len", FT_UINT8, BASE_DEC,
           NULL, 0, "Length of SNMPv3 USM User Name", HFILL }},
	{ &hf_pktc_usmUserName, {
           "SNMPv3 USM User Name", "pktc.asd.snmp_usm_username", FT_STRING, BASE_NONE,
           NULL, 0, NULL, HFILL }},
	{ &hf_pktc_ipsec_spi, {
           "IPsec Security Parameter Index", "pktc.asd.ipsec_spi", FT_UINT32, BASE_HEX,
           NULL, 0, "Security Parameter Index for inbound Security Association (IPsec)", HFILL }},
	{ &hf_pktc_reestablish_flag, {
	    "Re-establish Flag", "pktc.reestablish", FT_BOOLEAN, BASE_NONE,
	    NULL, 0x0, NULL, HFILL }},
	{ &hf_pktc_ack_required_flag, {
	    "ACK Required Flag", "pktc.ack_required", FT_BOOLEAN, BASE_NONE,
	    NULL, 0x0, NULL, HFILL }},
	{ &hf_pktc_sec_param_lifetime, {
	    "Security Parameter Lifetime", "pktc.spl", FT_UINT32, BASE_DEC,
	    NULL, 0, "Lifetime in seconds of security parameter", HFILL }},
        { &hf_pktc_sha1_hmac, {
           "SHA-1 HMAC", "pktc.sha1_hmac", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL }},
	{ &hf_pktc_grace_period, {
	    "Grace Period", "pktc.grace_period", FT_UINT32, BASE_DEC,
	    NULL, 0, "Grace Period in seconds", HFILL }},
    };
    static gint *ett[] = {
        &ett_pktc,
        &ett_pktc_app_spec_data,
        &ett_pktc_list_of_ciphersuites,
	&ett_pktc_engineid,
    };

    proto_pktc = proto_register_protocol("PacketCable", "PKTC", "pktc");
    proto_register_field_array(proto_pktc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pktc(void)
{
    dissector_handle_t pktc_handle;

    pktc_handle = create_dissector_handle(dissect_pktc, proto_pktc);
    dissector_add_uint("udp.port", PKTC_PORT, pktc_handle);
}


void
proto_register_pktc_mtafqdn(void)
{
    static hf_register_info hf[] = {
       { &hf_pktc_mtafqdn_msgtype, {
           "Message Type", "pktc.mtafqdn.msgtype", FT_UINT8, BASE_DEC,
           VALS(pktc_mtafqdn_msgtype_vals), 0, "MTA FQDN Message Type", HFILL }},
       { &hf_pktc_mtafqdn_enterprise, {
           "Enterprise Number", "pktc.mtafqdn.enterprise", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL }},
       { &hf_pktc_mtafqdn_version, {
           "Protocol Version", "pktc.mtafqdn.version", FT_UINT8, BASE_DEC,
           NULL, 0, "MTA FQDN Protocol Version", HFILL }},
       /* MTA FQDN REQ */
       { &hf_pktc_mtafqdn_mac, {
           "MTA MAC address", "pktc.mtafqdn.mac", FT_ETHER, BASE_NONE,
           NULL, 0, NULL, HFILL }},
       { &hf_pktc_mtafqdn_pub_key_hash, {
           "MTA Public Key Hash", "pktc.mtafqdn.pub_key_hash", FT_BYTES, BASE_NONE,
           NULL, 0, "MTA Public Key Hash (SHA-1)", HFILL }},
       { &hf_pktc_mtafqdn_manu_cert_revoked, {
           "Manufacturer Cert Revocation Time", "pktc.mtafqdn.manu_cert_revoked", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
           NULL, 0, "Manufacturer Cert Revocation Time (UTC) or 0 if not revoked", HFILL }},
       /* MTA FQDN REP */
       { &hf_pktc_mtafqdn_fqdn, {
           "MTA FQDN", "pktc.mtafqdn.fqdn", FT_STRING, BASE_NONE,
           NULL, 0, NULL, HFILL }},
       { &hf_pktc_mtafqdn_ip, {
           "MTA IP Address", "pktc.mtafqdn.ip", FT_IPv4, BASE_NONE,
           NULL, 0, "MTA IP Address (all zeros if not supplied)", HFILL }},
    };
    static gint *ett[] = {
        &ett_pktc_mtafqdn,
    };

    proto_register_field_array(proto_pktc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pktc_mtafqdn(void)
{
    dissector_handle_t pktc_mtafqdn_handle;

    pktc_mtafqdn_handle = create_dissector_handle(dissect_pktc_mtafqdn, proto_pktc);
    dissector_add_uint("udp.port", PKTC_MTAFQDN_PORT, pktc_mtafqdn_handle);
}
