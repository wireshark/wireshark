/* packet-cdp.c
 * Routines for the disassembly of the "Cisco Discovery Protocol"
 * (c) Copyright Hannes R. Boehm <hannes@boehm.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <epan/in_cksum.h>
#include <epan/oui.h>
#include <epan/nlpid.h>


/*
 * See
 *
 *    http://www.cisco.com/c/en/us/td/docs/ios-xml/ios/cdp/configuration/15-mt/cdp-15-mt-book/nm-cdp-discover.html#GUID-84FBA50B-677C-4D90-AF56-2FB96F2DC085
 *
 * and
 *
 *      http://www.cisco.com/c/en/us/support/docs/switches/catalyst-4500-series-switches/13414-103.html#cdp
 *
 * for some more information on CDP version 2 (a superset of version 1).
 */

void proto_register_cdp(void);
void proto_reg_handoff_cdp(void);

/* Offsets in TLV structure. */
#define TLV_TYPE        0
#define TLV_LENGTH      2

static int proto_cdp = -1;
static int hf_cdp_version = -1;
static int hf_cdp_checksum = -1;
static int hf_cdp_checksum_status = -1;
static int hf_cdp_ttl = -1;
static int hf_cdp_tlvtype = -1;
static int hf_cdp_tlvlength = -1;
static int hf_cdp_nrgyz_tlvtype = -1;
static int hf_cdp_nrgyz_tlvlength = -1;
static int hf_cdp_deviceid = -1;
static int hf_cdp_platform = -1;
static int hf_cdp_portid = -1;
static int hf_cdp_capabilities = -1;
static int hf_cdp_capabilities_router = -1;
static int hf_cdp_capabilities_trans_bridge = -1;
static int hf_cdp_capabilities_src_bridge = -1;
static int hf_cdp_capabilities_switch = -1;
static int hf_cdp_capabilities_host = -1;
static int hf_cdp_capabilities_igmp_capable = -1;
static int hf_cdp_capabilities_repeater = -1;
static int hf_cdp_spare_poe_tlv = -1;
static int hf_cdp_spare_poe_tlv_poe = -1;
static int hf_cdp_spare_poe_tlv_spare_pair_arch = -1;
static int hf_cdp_spare_poe_tlv_req_spare_pair_poe = -1;
static int hf_cdp_spare_poe_tlv_pse_spare_pair_poe = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_cdp_num_tlvs_table = -1;
static int hf_cdp_encrypted_data = -1;
static int hf_cdp_cluster_ip = -1;
static int hf_cdp_nrgyz_reply_to_backup_server_ip = -1;
static int hf_cdp_nrgyz_reply_to_port = -1;
static int hf_cdp_unknown_pad = -1;
static int hf_cdp_cluster_version = -1;
static int hf_cdp_hello_unknown = -1;
static int hf_cdp_management_id = -1;
static int hf_cdp_data = -1;
static int hf_cdp_nrgyz_reply_to_ip_address = -1;
static int hf_cdp_nrgyz_reply_to_name = -1;
static int hf_cdp_nrgyz_reply_to_domain = -1;
static int hf_cdp_nrgyz_reply_to_role = -1;
static int hf_cdp_nrgyz_ip_address = -1;
static int hf_cdp_model_number = -1;
static int hf_cdp_nrgyz_reply_to_unknown_field = -1;
static int hf_cdp_len_tlv_table = -1;
static int hf_cdp_vtp_management_domain = -1;
static int hf_cdp_hardware_version_id = -1;
static int hf_cdp_cluster_unknown = -1;
static int hf_cdp_native_vlan = -1;
static int hf_cdp_ip_prefix = -1;
static int hf_cdp_odr_default_gateway = -1;
static int hf_cdp_power_consumption = -1;
static int hf_cdp_cluster_status = -1;
static int hf_cdp_power_requested = -1;
static int hf_cdp_trust_bitmap = -1;
static int hf_cdp_seen_sequence = -1;
static int hf_cdp_system_name = -1;
static int hf_cdp_power_available = -1;
static int hf_cdp_cluster_commander_mac = -1;
static int hf_cdp_mtu = -1;
static int hf_cdp_protocol_length = -1;
static int hf_cdp_system_serial_number = -1;
static int hf_cdp_sequence_number = -1;
static int hf_cdp_duplex = -1;
static int hf_cdp_voice_vlan = -1;
static int hf_cdp_request_id = -1;
static int hf_cdp_cluster_sub_version = -1;
static int hf_cdp_oui = -1;
static int hf_cdp_nrgyz_reply_to_backup_server_port = -1;
static int hf_cdp_cluster_master_ip = -1;
static int hf_cdp_protocol = -1;
static int hf_cdp_protocol_type = -1;
static int hf_cdp_address = -1;
static int hf_cdp_system_object_identifier = -1;
static int hf_cdp_location_unknown = -1;
static int hf_cdp_nrgyz_unknown_values = -1;
static int hf_cdp_address_length = -1;
static int hf_cdp_protocol_id = -1;
static int hf_cdp_cluster_switch_mac = -1;
static int hf_cdp_location = -1;
static int hf_cdp_untrusted_port_cos = -1;
static int hf_cdp_number_of_addresses = -1;
static int hf_cdp_cluster_management_vlan = -1;
static int hf_cdp_software_version = -1;

static gint ett_cdp = -1;
static gint ett_cdp_tlv = -1;
static gint ett_cdp_nrgyz_tlv = -1;
static gint ett_cdp_address = -1;
static gint ett_cdp_capabilities = -1;
static gint ett_cdp_spare_poe_tlv = -1;
static gint ett_cdp_checksum = -1;

static expert_field ei_cdp_invalid_data = EI_INIT;
static expert_field ei_cdp_nrgyz_tlvlength = EI_INIT;

static int
dissect_address_tlv(tvbuff_t *tvb, int offset, int length, proto_tree *tree);
static void
dissect_capabilities(tvbuff_t *tvb, int offset, int length, proto_tree *tree);
static void
dissect_nrgyz_tlv(tvbuff_t *tvb, packet_info* pinfo, int offset, guint16 length, guint16 num,
  proto_tree *tree);
static void
dissect_spare_poe_tlv(tvbuff_t *tvb, int offset, int length, proto_tree *tree);
static void
add_multi_line_string_to_tree(proto_tree *tree, tvbuff_t *tvb, gint start,
  gint len, int hf);

#define TYPE_DEVICE_ID          0x0001
#define TYPE_ADDRESS            0x0002
#define TYPE_PORT_ID            0x0003
#define TYPE_CAPABILITIES       0x0004
#define TYPE_IOS_VERSION        0x0005
#define TYPE_PLATFORM           0x0006
#define TYPE_IP_PREFIX          0x0007
#define TYPE_PROTOCOL_HELLO     0x0008 /* Protocol Hello */
#define TYPE_VTP_MGMT_DOMAIN    0x0009 /* VTP Domain, CTPv2 - see second URL */
#define TYPE_NATIVE_VLAN        0x000a /* Native VLAN, CTPv2 - see second URL */
#define TYPE_DUPLEX             0x000b /* Full/Half Duplex - see second URL */
/*                              0x000c */
/*                              0x000d */
#define TYPE_VOIP_VLAN_REPLY    0x000e /* VoIP VLAN reply */
#define TYPE_VOIP_VLAN_QUERY    0x000f /* VoIP VLAN query */
#define TYPE_POWER              0x0010 /* Power consumption */
#define TYPE_MTU                0x0011 /* MTU */
#define TYPE_TRUST_BITMAP       0x0012 /* Trust bitmap */
#define TYPE_UNTRUSTED_COS      0x0013 /* Untrusted port CoS */
#define TYPE_SYSTEM_NAME        0x0014 /* System Name */
#define TYPE_SYSTEM_OID         0x0015 /* System OID */
#define TYPE_MANAGEMENT_ADDR    0x0016 /* Management Address(es) */
#define TYPE_LOCATION           0x0017 /* Location */
#define TYPE_EXT_PORT_ID        0x0018 /* External Port-ID */
#define TYPE_POWER_REQUESTED    0x0019 /* Power Requested */
#define TYPE_POWER_AVAILABLE    0x001a /* Power Available */
#define TYPE_PORT_UNIDIR        0x001b /* Port Unidirectional */
#define TYPE_NRGYZ              0x001d /* EnergyWise over CDP */
#define TYPE_SPARE_POE          0x001f /* Spare Pair PoE */

#define TYPE_HP_BSSID           0x1000 /* BSSID */
#define TYPE_HP_SERIAL          0x1001 /* Serial number */
#define TYPE_HP_SSID            0x1002 /* SSID */
#define TYPE_HP_RADIO1_CH       0x1003 /* Radio1 channel */
/*                              0x1004 */
/*                              0x1005 */
#define TYPE_HP_SNMP_PORT       0x1006 /* SNMP listening UDP port */
#define TYPE_HP_MGMT_PORT       0x1007 /* Web interface TCP port */
#define TYPE_HP_SOURCE_MAC      0x1008 /* Sender MAC address for the AP, bouth wired and wireless */
#define TYPE_HP_RADIO2_CH       0x1009 /* Radio2 channel */
#define TYPE_HP_RADIO1_OMODE    0x100A /* Radio1 Operating mode */
#define TYPE_HP_RADIO2_OMODE    0x100B /* Radio2 Operating mode */
#define TYPE_HP_RADIO1_RMODE    0x100C /* Radio1 Radio mode */
#define TYPE_HP_RADIO2_RMODE    0x100D /* Radio2 Radio mode */

static const value_string type_vals[] = {
    { TYPE_DEVICE_ID,       "Device ID" },
    { TYPE_ADDRESS,         "Addresses" },
    { TYPE_PORT_ID,         "Port ID" },
    { TYPE_CAPABILITIES,    "Capabilities" },
    { TYPE_IOS_VERSION,     "Software version" },
    { TYPE_PLATFORM,        "Platform" },
    { TYPE_IP_PREFIX,       "IP Prefix/Gateway (used for ODR)" },
    { TYPE_PROTOCOL_HELLO,  "Protocol Hello" },
    { TYPE_VTP_MGMT_DOMAIN, "VTP Management Domain" },
    { TYPE_NATIVE_VLAN,     "Native VLAN" },
    { TYPE_DUPLEX,          "Duplex" },
    { TYPE_VOIP_VLAN_REPLY, "VoIP VLAN Reply" },
    { TYPE_VOIP_VLAN_QUERY, "VoIP VLAN Query" },
    { TYPE_POWER,           "Power consumption" },
    { TYPE_MTU,             "MTU"},
    { TYPE_TRUST_BITMAP,    "Trust Bitmap" },
    { TYPE_UNTRUSTED_COS,   "Untrusted Port CoS" },
    { TYPE_SYSTEM_NAME,     "System Name" },
    { TYPE_SYSTEM_OID,      "System Object ID" },
    { TYPE_MANAGEMENT_ADDR, "Management Address" },
    { TYPE_LOCATION,        "Location" },
    { TYPE_EXT_PORT_ID,     "External Port-ID" },
    { TYPE_POWER_REQUESTED, "Power Requested" },
    { TYPE_POWER_AVAILABLE, "Power Available" },
    { TYPE_PORT_UNIDIR,     "Port Unidirectional" },
    { TYPE_NRGYZ,           "EnergyWise" },
    { TYPE_SPARE_POE,       "Spare PoE" },
    { TYPE_HP_BSSID,        "BSSID" },
    { TYPE_HP_SERIAL,       "Serial number" },
    { TYPE_HP_SSID,         "SSID" },
    { TYPE_HP_RADIO1_CH,    "Radio1 channel" },
    { TYPE_HP_SNMP_PORT,    "SNMP UDP port" },
    { TYPE_HP_MGMT_PORT,    "Web TCP port" },
    { TYPE_HP_SOURCE_MAC,   "Source MAC address" },
    { TYPE_HP_RADIO2_CH,    "Radio2 channel" },
    { TYPE_HP_RADIO1_OMODE, "Radio1 Operating mode" },
    { TYPE_HP_RADIO2_OMODE, "Radio2 Operating mode" },
    { TYPE_HP_RADIO1_RMODE, "Radio1 Radio mode" },
    { TYPE_HP_RADIO2_RMODE, "Radio2 Radio mode" },
    { 0, NULL }
};

#define TYPE_HELLO_CLUSTER_MGMT    0x0112

static const value_string type_hello_vals[] = {
    { TYPE_HELLO_CLUSTER_MGMT,   "Cluster Management" },
    { 0, NULL }
};

#define TYPE_NRGYZ_ROLE    0x00000007
#define TYPE_NRGYZ_DOMAIN  0x00000008
#define TYPE_NRGYZ_NAME    0x00000009
#define TYPE_NRGYZ_REPLYTO 0x00000017

static const value_string type_nrgyz_vals[] = {
    { TYPE_NRGYZ_ROLE,    "Role" },
    { TYPE_NRGYZ_DOMAIN,  "Domain" },
    { TYPE_NRGYZ_NAME,    "Name" },
    { TYPE_NRGYZ_REPLYTO, "Reply To" },
    { 0, NULL }
};

static int
dissect_cdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *cdp_tree;
    int         offset   = 0;
    guint16     type;
    guint16     length, data_length;
    proto_item *tlvi     = NULL;
    proto_tree *tlv_tree = NULL;
    int         real_length;
    guint32     naddresses;
    guint32     power_avail_len, power_avail;
    guint32     power_req_len, power_req;
    int         addr_length;
    vec_t       cksum_vec[1];

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CDP");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_cdp, tvb, offset, -1, ENC_NA);
    cdp_tree = proto_item_add_subtree(ti, ett_cdp);

    /* CDP header */
    proto_tree_add_item(cdp_tree, hf_cdp_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_uint_format_value(cdp_tree, hf_cdp_ttl, tvb, offset, 1,
                                        tvb_get_guint8(tvb, offset),
                                        "%u seconds",
                                        tvb_get_guint8(tvb, offset));
    offset += 1;

    /* Checksum display & verification code */

    data_length = tvb_reported_length(tvb);

    /* CDP doesn't adhere to RFC 1071 section 2. (B). It incorrectly assumes
     * checksums are calculated on a big endian platform, therefore i.s.o.
     * padding odd sized data with a zero byte _at the end_ it sets the last
     * big endian _word_ to contain the last network _octet_. This byteswap
     * has to be done on the last octet of network data before feeding it to
     * the Internet checksum routine.
     * CDP checksumming code has a bug in the addition of this last _word_
     * as a signed number into the long word intermediate checksum. When
     * reducing this long to word size checksum an off-by-one error can be
     * made. This off-by-one error is compensated for in the last _word_ of
     * the network data.
     */
    if (data_length & 1) {
        guint8 *padded_buffer;
        /* Allocate new buffer */
        padded_buffer = (guint8 *)wmem_alloc(wmem_packet_scope(), data_length+1);
        tvb_memcpy(tvb, padded_buffer, 0, data_length);
        /* Swap bytes in last word */
        padded_buffer[data_length] = padded_buffer[data_length-1];
        padded_buffer[data_length-1] = 0;
        /* Compensate off-by-one error */
        if (padded_buffer[data_length] & 0x80) {
          padded_buffer[data_length]--;
          padded_buffer[data_length-1]--;
        }
        /* Setup checksum routine data buffer */
        SET_CKSUM_VEC_PTR(cksum_vec[0], padded_buffer, data_length+1);
    } else {
        /* Setup checksum routine data buffer */
        SET_CKSUM_VEC_TVB(cksum_vec[0], tvb, 0, data_length);
    }

    proto_tree_add_checksum(cdp_tree, tvb, offset, hf_cdp_checksum, hf_cdp_checksum_status, NULL, pinfo, in_cksum(cksum_vec, 1),
                                ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY|PROTO_CHECKSUM_IN_CKSUM);
    offset += 2;

    while (tvb_reported_length_remaining(tvb, offset) != 0) {
        type = tvb_get_ntohs(tvb, offset + TLV_TYPE);
        length = tvb_get_ntohs(tvb, offset + TLV_LENGTH);
        if (length < 4) {
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb, offset, 4,
                                           ett_cdp_tlv, NULL, "TLV with invalid length %u (< 4)",
                                           length);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
            }
            offset += 4;
            break;
        }

        switch (type) {

        case TYPE_DEVICE_ID:
            /* Device ID */

            col_append_fstr(pinfo->cinfo, COL_INFO,
                            "Device ID: %s  ",
                            tvb_format_stringzpad(tvb, offset + 4, length - 4));

            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb, offset,
                                           length, ett_cdp_tlv, NULL, "Device ID: %s",
                                           tvb_format_stringzpad(tvb, offset + 4, length - 4));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_deviceid, tvb, offset + 4, length - 4, ENC_ASCII|ENC_NA);
            }
            offset += length;
            break;

        case TYPE_PORT_ID:
            real_length = length;
            if ((tvb_reported_length_remaining(tvb, offset) >= length + 3) &&
                (tvb_get_guint8(tvb, offset + real_length) != 0x00)) {
                /* The length in the TLV doesn't appear to be the
                   length of the TLV, as the byte just past it
                   isn't the first byte of a 2-byte big-endian
                   small integer; make the length of the TLV the length
                   in the TLV, plus 4 bytes for the TLV type and length,
                   minus 1 because that's what makes one capture work. */
                real_length = length + 3;
            }

            col_append_fstr(pinfo->cinfo, COL_INFO,
                            "Port ID: %s  ",
                            tvb_format_stringzpad(tvb, offset + 4,
                                                  length - 4));

            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb, offset,
                                           real_length, ett_cdp_tlv, NULL, "Port ID: %s",
                                           tvb_format_text(tvb, offset + 4, real_length - 4));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_portid, tvb, offset + 4, real_length - 4, ENC_ASCII|ENC_NA);
            }
            offset += real_length;
            break;

        case TYPE_ADDRESS:
            /* Addresses */
            if (tree) {
                tlv_tree = proto_tree_add_subtree(cdp_tree, tvb, offset,
                                           length, ett_cdp_tlv, NULL, "Addresses");
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
            }
            offset += 4;
            length -= 4;
            naddresses = tvb_get_ntohl(tvb, offset);
            proto_tree_add_item(tlv_tree, hf_cdp_number_of_addresses, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            length -= 4;
            while (naddresses != 0) {
                addr_length = dissect_address_tlv(tvb, offset, length,
                                                  tlv_tree);
                if (addr_length < 0)
                    break;
                offset += addr_length;
                length -= addr_length;

                naddresses--;
            }
            offset += length;
            break;

        case TYPE_CAPABILITIES:
            if (tree) {
                tlv_tree = proto_tree_add_subtree(cdp_tree, tvb, offset,
                                           length, ett_cdp_tlv, NULL, "Capabilities");
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
            }
            offset += 4;
            length -= 4;
            dissect_capabilities(tvb, offset, length, tlv_tree);
            offset += length;
            break;

        case TYPE_IOS_VERSION:
            if (tree) {
                tlv_tree = proto_tree_add_subtree(cdp_tree, tvb, offset,
                                           length, ett_cdp_tlv, NULL, "Software Version");
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                add_multi_line_string_to_tree(tlv_tree, tvb, offset + 4,
                                              length - 4, hf_cdp_software_version);
            }
            offset += length;
            break;

        case TYPE_PLATFORM:
            /* ??? platform */
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "Platform: %s",
                                           tvb_format_text(tvb, offset + 4, length - 4));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_platform, tvb, offset + 4, length - 4, ENC_ASCII|ENC_NA);
            }
            offset += length;
            break;

        case TYPE_IP_PREFIX:
            if (length == 8) {
                /* if length is 8 then this is default gw not prefix */
                if (tree) {
                    tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb, offset,
                                               length, ett_cdp_tlv, NULL, "ODR Default gateway: %s",
                                               tvb_ip_to_str(tvb, offset+4));
                    proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tlv_tree, hf_cdp_odr_default_gateway, tvb, offset+4, 4, ENC_BIG_ENDIAN);
                }
                offset += 8;
            } else {
                if (tree) {
                    tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb, offset,
                                               length, ett_cdp_tlv, NULL, "IP Prefixes: %d",length/5);

                    /* the actual number of prefixes is (length-4)/5
                       but if the variable is not a "float" but "integer"
                       then length/5=(length-4)/5  :)  */

                    proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                }
                offset += 4;
                length -= 4;
                while (length > 0) {
                    proto_tree_add_ipv4_format_value(tlv_tree, hf_cdp_ip_prefix, tvb, offset, 5, tvb_get_ntohl(tvb, offset),
                                    "%s/%u", tvb_ip_to_str(tvb, offset), tvb_get_guint8(tvb,offset+4));
                    offset += 5;
                    length -= 5;
                }
            }
            break;

        case TYPE_PROTOCOL_HELLO:
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                           offset,length, ett_cdp_tlv, NULL, "Protocol Hello: %s",
                                           val_to_str(tvb_get_ntohs(tvb, offset+7), type_hello_vals, "Unknown (0x%04x)"));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_oui, tvb, offset+4, 3, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_protocol_id, tvb, offset+7, 2, ENC_BIG_ENDIAN);

                switch(tvb_get_ntohs(tvb, offset+7)) {

                case TYPE_HELLO_CLUSTER_MGMT:
                    proto_tree_add_item(tlv_tree, hf_cdp_cluster_master_ip, tvb, offset+9, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tlv_tree, hf_cdp_cluster_ip, tvb, offset+13, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tlv_tree, hf_cdp_cluster_version, tvb, offset+17, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tlv_tree, hf_cdp_cluster_sub_version, tvb, offset+18, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tlv_tree, hf_cdp_cluster_status, tvb, offset+19, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tlv_tree, hf_cdp_cluster_unknown, tvb, offset+20, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tlv_tree, hf_cdp_cluster_commander_mac, tvb, offset+21, 6, ENC_NA);
                    proto_tree_add_item(tlv_tree, hf_cdp_cluster_switch_mac, tvb, offset+27, 6, ENC_NA);
                    proto_tree_add_item(tlv_tree, hf_cdp_cluster_unknown, tvb, offset+33, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tlv_tree, hf_cdp_cluster_management_vlan, tvb, offset+34, 2, ENC_BIG_ENDIAN);
                    break;
                default:
                    proto_tree_add_item(tlv_tree, hf_cdp_hello_unknown, tvb, offset + 9, length - 9, ENC_NA);
                    break;
                }
            }
            offset += length;
            break;

        case TYPE_VTP_MGMT_DOMAIN:
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "VTP Management Domain: %s",
                                           tvb_format_text(tvb, offset + 4, length - 4));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_vtp_management_domain, tvb, offset + 4, length - 4, ENC_NA|ENC_ASCII);
            }
            offset += length;
            break;

        case TYPE_NATIVE_VLAN:
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "Native VLAN: %u",
                                           tvb_get_ntohs(tvb, offset + 4));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_native_vlan, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
            }
            offset += length;
            break;

        case TYPE_DUPLEX:
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "Duplex: %s",
                                           tvb_get_guint8(tvb, offset + 4) ?
                                           "Full" : "Half" );
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_duplex, tvb, offset + 4, 1, ENC_NA);
            }
            offset += length;
            break;

        case TYPE_VOIP_VLAN_REPLY:
            if (tree) {
                if (length >= 7) {
                    tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb, offset, length, ett_cdp_tlv, NULL,
                                               "VoIP VLAN Reply: %u", tvb_get_ntohs(tvb, offset + 5));
                } else {
                    /*
                     * XXX - what are these?  I've seen them in some captures;
                     * they have a length of 6, and run up to the end of
                     * the packet, so if we try to dissect it the same way
                     * we dissect the 7-byte ones, we report a malformed
                     * frame.
                     */
                    tlv_tree = proto_tree_add_subtree(cdp_tree, tvb,
                                               offset, length, ett_cdp_tlv, NULL, "VoIP VLAN Reply");
                }
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_data, tvb, offset + 4, 1, ENC_NA);
                if (length >= 7) {
                    proto_tree_add_item(tlv_tree, hf_cdp_voice_vlan, tvb, offset + 5, 2, ENC_BIG_ENDIAN);
                }
            }
            offset += length;
            break;

        case TYPE_VOIP_VLAN_QUERY:
            if (tree) {
                if (length >= 7) {
                    tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb, offset, length,
                                               ett_cdp_tlv, NULL, "VoIP VLAN Query: %u", tvb_get_ntohs(tvb, offset + 5));
                } else {
                    /*
                     * XXX - what are these?  I've seen them in some captures;
                     * they have a length of 6, and run up to the end of
                     * the packet, so if we try to dissect it the same way
                     * we dissect the 7-byte ones, we report a malformed
                     * frame.
                     */
                    tlv_tree = proto_tree_add_subtree(cdp_tree, tvb,
                                               offset, length, ett_cdp_tlv, NULL, "VoIP VLAN Query");
                }
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_data, tvb, offset + 4, 1, ENC_NA);
                if (length >= 7) {
                    proto_tree_add_item(tlv_tree, hf_cdp_voice_vlan, tvb, offset + 5, 2, ENC_BIG_ENDIAN);
                }
            }
            offset += length;
            break;

        case TYPE_POWER:
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "Power Consumption: %u mW",
                                           tvb_get_ntohs(tvb, offset + 4));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_uint_format_value(tlv_tree, hf_cdp_power_consumption, tvb, offset + 4, 2,
                                    tvb_get_ntohs(tvb, offset + 4), "%u mW", tvb_get_ntohs(tvb, offset + 4));
            }
            offset += length;
            break;

        case TYPE_MTU:
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "MTU: %u",
                                           tvb_get_ntohl(tvb,offset + 4));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_mtu, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            }
            offset += length;
            break;

        case TYPE_TRUST_BITMAP:
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "Trust Bitmap: 0x%02X",
                                           tvb_get_guint8(tvb, offset + 4));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_trust_bitmap, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
            }
            offset += length;
            break;

        case TYPE_UNTRUSTED_COS:
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "Untrusted port CoS: 0x%02X",
                                           tvb_get_guint8(tvb, offset + 4));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_untrusted_port_cos, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
            }
            offset += length;
            break;

        case TYPE_SYSTEM_NAME:
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "System Name: %s",
                                           tvb_format_text(tvb, offset + 4, length - 4));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_system_name, tvb, offset + 4, length - 4, ENC_NA|ENC_ASCII);
            }
            offset += length;
            break;

        case TYPE_SYSTEM_OID:
            if (tree) {
                tlv_tree = proto_tree_add_subtree(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "System Object Identifier");
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_system_object_identifier, tvb, offset + 4, length - 4, ENC_NA);
            }
            offset += length;
            break;

        case TYPE_MANAGEMENT_ADDR:
            if (tree) {
                tlv_tree = proto_tree_add_subtree(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "Management Addresses");
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
            }
            offset += 4;
            length -= 4;
            naddresses = tvb_get_ntohl(tvb, offset);
            if (tree) {
                proto_tree_add_item(tlv_tree, hf_cdp_number_of_addresses, tvb, offset, 4, ENC_BIG_ENDIAN);
            }
            offset += 4;
            length -= 4;
            while (naddresses != 0) {
                addr_length = dissect_address_tlv(tvb, offset, length,
                                                  tlv_tree);
                if (addr_length < 0)
                    break;
                offset += addr_length;
                length -= addr_length;

                naddresses--;
            }
            offset += length;
            break;

        case TYPE_LOCATION:
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "Location: %s",
                                           tvb_format_text(tvb, offset + 5, length - 5));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_location_unknown, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_location, tvb, offset + 5, length - 5, ENC_NA|ENC_ASCII);
            }
            offset += length;
            break;

        case TYPE_POWER_REQUESTED:
            if (tree) {
                tlv_tree = proto_tree_add_subtree(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "Power Request: ");
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_request_id, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_management_id, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
            }
            power_req_len = (tvb_get_ntohs(tvb, offset + TLV_LENGTH)) - 8;
            /* Move offset to where the list of Power Request Values Exist */
            offset += 8;
            while(power_req_len) {
                if (power_req_len > 4) {
                    power_req = tvb_get_ntohl(tvb, offset);
                    proto_tree_add_uint_format_value(tlv_tree, hf_cdp_power_requested, tvb, offset, 4, power_req, "%u mW", power_req);
                    proto_item_append_text(tlvi, "%u mW, ", power_req);
                    power_req_len -= 4;
                    offset += 4;
                } else {
                    if (power_req_len == 4) {
                        power_req = tvb_get_ntohl(tvb, offset);
                        proto_tree_add_uint_format_value(tlv_tree, hf_cdp_power_requested, tvb, offset, 4, power_req, "%u mW", power_req);
                        proto_item_append_text(tlvi, "%u mW", power_req);
                    }
                    offset += power_req_len;
                    break;
                }
            }
            break;

        case TYPE_POWER_AVAILABLE:
            if (tree) {
                tlv_tree = proto_tree_add_subtree(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "Power Available: ");
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_request_id, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_management_id, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
            }
            power_avail_len = (tvb_get_ntohs(tvb, offset + TLV_LENGTH)) - 8;
            /* Move offset to where the list of Power Available Values Exist */
            offset += 8;
            while(power_avail_len) {
                if (power_avail_len >= 4) {
                    power_avail = tvb_get_ntohl(tvb, offset);
                    proto_tree_add_uint_format_value(tlv_tree, hf_cdp_power_available, tvb, offset, 4, power_avail, "%u mW", power_avail);
                    proto_item_append_text(tlvi, "%u mW, ", power_avail);
                    power_avail_len -= 4;
                    offset += 4;
                } else {
                    offset += power_avail_len;
                    break;
                }
            }
            break;

        case TYPE_NRGYZ:
            if (tree) {
                tlv_tree = proto_tree_add_subtree(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "EnergyWise");
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_encrypted_data, tvb, offset + 4, 20, ENC_NA);
                proto_tree_add_item(tlv_tree, hf_cdp_seen_sequence, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_sequence_number, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_model_number, tvb, offset + 32, 16, ENC_NA|ENC_ASCII);
                proto_tree_add_item(tlv_tree, hf_cdp_unknown_pad, tvb, offset + 48, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_hardware_version_id, tvb, offset + 50, 3, ENC_NA|ENC_ASCII);
                proto_tree_add_item(tlv_tree, hf_cdp_system_serial_number, tvb, offset + 53, 11, ENC_NA|ENC_ASCII);
                proto_tree_add_item(tlv_tree, hf_cdp_nrgyz_unknown_values, tvb, offset + 64, 8, ENC_NA);
                proto_tree_add_item(tlv_tree, hf_cdp_len_tlv_table, tvb, offset + 72, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_num_tlvs_table, tvb, offset + 74, 2, ENC_BIG_ENDIAN);

                dissect_nrgyz_tlv(tvb, pinfo, offset + 76,
                                  tvb_get_ntohs(tvb, offset + 72),
                                  tvb_get_ntohs(tvb, offset + 74),
                                  tlv_tree);


            }
            offset += length;
            break;

        case TYPE_SPARE_POE:
            if (tree) {
                tlv_tree = proto_tree_add_subtree(cdp_tree, tvb, offset, length,
                                           ett_cdp_tlv, NULL, "Spare Pair PoE");

                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
            }
            offset += 4;
            length -= 4;
            dissect_spare_poe_tlv(tvb, offset, length, tlv_tree);
            offset += length;
            break;

        case TYPE_HP_BSSID:
            /* BSSID */
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "BSSID: %s",
                                           tvb_format_text(tvb, offset + 4, length - 4));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_platform, tvb, offset + 4, length - 4, ENC_ASCII|ENC_NA);
            }
            offset += length;
            break;

        case TYPE_HP_SERIAL:
            /* Serial number */
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "Serial: %s",
                                           tvb_format_text(tvb, offset + 4, length - 4));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_platform, tvb, offset + 4, length - 4, ENC_ASCII|ENC_NA);
            }
            offset += length;
            break;

        case TYPE_HP_SSID:
            /* SSID */
            if (tree) {
                if (length == 4) {
                    tlv_tree = proto_tree_add_subtree(cdp_tree, tvb,
                                               offset, length, ett_cdp_tlv, NULL, "SSID: [Empty]");
                    proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                } else {
                    tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                               offset, length, ett_cdp_tlv, NULL, "SSID: %s",
                                               tvb_format_text(tvb, offset + 4, length - 4));
                    proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tlv_tree, hf_cdp_platform, tvb, offset + 4, length - 4, ENC_ASCII|ENC_NA);
                }
            }
            offset += length;
            break;

        case TYPE_HP_RADIO1_CH:
            /* Radio1 channel */
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "Radio 1 channel: %s",
                                           tvb_format_text(tvb, offset + 4, length - 4));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_platform, tvb, offset + 4, length - 4, ENC_ASCII|ENC_NA);
            }
            offset += length;
            break;

        case TYPE_HP_SNMP_PORT:
            /* SNMP listening UDP port */
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "SNMP port: %s",
                                           tvb_format_text(tvb, offset + 4, length - 4));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_platform, tvb, offset + 4, length - 4, ENC_ASCII|ENC_NA);
            }
            offset += length;
            break;

        case TYPE_HP_MGMT_PORT:
            /* Web interface TCP port */
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "Web mgmt port: %s",
                                           tvb_format_text(tvb, offset + 4, length - 4));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_platform, tvb, offset + 4, length - 4, ENC_ASCII|ENC_NA);
            }
            offset += length;
            break;

        case TYPE_HP_SOURCE_MAC:
            /* Sender MAC address for the AP, bouth wired and wireless */
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "Source MAC: %s",
                                           tvb_format_text(tvb, offset + 4, length - 4));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_platform, tvb, offset + 4, length - 4, ENC_ASCII|ENC_NA);
            }
            offset += length;
            break;

        case TYPE_HP_RADIO2_CH:
            /* Radio2 channel */
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "Radio 2 channel: %s",
                                           tvb_format_text(tvb, offset + 4, length - 4));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_platform, tvb, offset + 4, length - 4, ENC_ASCII|ENC_NA);
            }
            offset += length;
            break;

        case TYPE_HP_RADIO1_OMODE:
            /* Radio1 Operating mode */
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "Radio 1 operating mode: %s",
                                           tvb_format_text(tvb, offset + 4, length - 4));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_platform, tvb, offset + 4, length - 4, ENC_ASCII|ENC_NA);
            }
            offset += length;
            break;

        case TYPE_HP_RADIO2_OMODE:
            /* Radio2 Operating mode */
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "Radio 2 operating mode: %s",
                                           tvb_format_text(tvb, offset + 4, length - 4));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_platform, tvb, offset + 4, length - 4, ENC_ASCII|ENC_NA);
            }
            offset += length;
            break;

        case TYPE_HP_RADIO1_RMODE:
            /* Radio1 Radio mode */
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "Radio 1 radio mode: %s",
                                           tvb_format_text(tvb, offset + 4, length - 4));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_platform, tvb, offset + 4, length - 4, ENC_ASCII|ENC_NA);
            }
            offset += length;
            break;

        case TYPE_HP_RADIO2_RMODE:
            /* Radio2 Radio mode */
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb,
                                           offset, length, ett_cdp_tlv, NULL, "Radio 2 radio mode: %s",
                                           tvb_format_text(tvb, offset + 4, length - 4));
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_platform, tvb, offset + 4, length - 4, ENC_ASCII|ENC_NA);
            }
            offset += length;
            break;

        default:
            if (tree) {
                tlv_tree = proto_tree_add_subtree_format(cdp_tree, tvb, offset,
                                           length, ett_cdp_tlv, NULL, "Type: %s, length: %u",
                                           val_to_str(type, type_vals, "Unknown (0x%04x)"),
                                           length);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvtype, tvb, offset + TLV_TYPE, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv_tree, hf_cdp_tlvlength, tvb, offset + TLV_LENGTH, 2, ENC_BIG_ENDIAN);
                if (length > 4) {
                    proto_tree_add_item(tlv_tree, hf_cdp_data, tvb, offset + 4, length - 4, ENC_NA);
                } else {
                    return tvb_captured_length(tvb);
                }
            }
            offset += length;
        }
    }
    call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, cdp_tree);
    return tvb_captured_length(tvb);
}

#define PROTO_TYPE_NLPID       1
#define PROTO_TYPE_IEEE_802_2  2

static const value_string proto_type_vals[] = {
    { PROTO_TYPE_NLPID,      "NLPID" },
    { PROTO_TYPE_IEEE_802_2, "802.2" },
    { 0,                     NULL }
};

static int
dissect_address_tlv(tvbuff_t *tvb, int offset, int length, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *address_tree;
    guint8      protocol_type;
    guint8      protocol_length;
    int         nlpid;
    guint16     address_length;
    int         hf_addr = -1;

    if (length < 1)
        return -1;
    address_tree = proto_tree_add_subtree(tree, tvb, offset, length, ett_cdp_address, &ti, "Truncated address");
    protocol_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(address_tree, hf_cdp_protocol_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    length -= 1;

    if (length < 1)
        return -1;
    protocol_length = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(address_tree, hf_cdp_protocol_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    length -= 1;

    if (length < protocol_length) {
        if (length != 0) {
            ti = proto_tree_add_item(address_tree, hf_cdp_protocol, tvb, offset, length, ENC_NA);
            proto_item_append_text(ti, " (truncated)");
        }
        return -1;
    }

    if ((protocol_type == PROTO_TYPE_NLPID) && (protocol_length == 1)) {
        nlpid = tvb_get_guint8(tvb, offset);
        proto_tree_add_bytes_format_value(address_tree, hf_cdp_protocol, tvb, offset, protocol_length, NULL, "%s",
                            val_to_str(nlpid, nlpid_vals, "Unknown (0x%02x)"));
    } else {
        nlpid = -1;
        proto_tree_add_item(address_tree, hf_cdp_protocol, tvb, offset, protocol_length, ENC_NA);
    }
    offset += protocol_length;
    length -= protocol_length;

    if (length < 2)
        return -1;
    address_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(address_tree, hf_cdp_address_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    length -= 2;

    if (length < address_length) {
        if (length != 0) {
            ti = proto_tree_add_item(address_tree, hf_cdp_address, tvb, offset, length, ENC_NA);
            proto_item_append_text(ti, " (truncated)");
        }
        return -1;
    }
    /* XXX - the Cisco document seems to be saying that, for 802.2-format
       protocol types, 0xAAAA03 0x000000 0x0800 is IPv6, but 0x0800 is
       the Ethernet protocol type for IPv4. */
    if ((protocol_type == PROTO_TYPE_NLPID) && (protocol_length == 1)) {
        switch (nlpid) {

        /* XXX - dissect NLPID_ISO8473_CLNP as OSI CLNP address? */

        case NLPID_IP:
            if (address_length == 4) {
                /* The address is an IP address. */
                proto_item_set_text(ti, "IP address: %s", tvb_ip_to_str(tvb, offset));
                hf_addr = hf_cdp_nrgyz_ip_address;
                proto_tree_add_item(address_tree, hf_cdp_nrgyz_ip_address, tvb, offset, address_length, ENC_BIG_ENDIAN);
            }
            break;
        }
    }

    if (hf_addr == -1)
    {
        proto_tree_add_item(address_tree, hf_cdp_address, tvb, offset, address_length, ENC_NA);
        proto_item_set_text(ti, "Address: %s", tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, address_length));
    }

    return 2 + protocol_length + 2 + address_length;
}

static void
dissect_capabilities(tvbuff_t *tvb, int offset, int length, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *capabilities_tree;

    if (length < 4)
        return;
    ti = proto_tree_add_item(tree, hf_cdp_capabilities, tvb, offset, 4, ENC_BIG_ENDIAN);
    capabilities_tree = proto_item_add_subtree(ti, ett_cdp_capabilities);
    proto_tree_add_item(capabilities_tree, hf_cdp_capabilities_router, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(capabilities_tree, hf_cdp_capabilities_trans_bridge, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(capabilities_tree, hf_cdp_capabilities_src_bridge, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(capabilities_tree, hf_cdp_capabilities_switch, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(capabilities_tree, hf_cdp_capabilities_host, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(capabilities_tree, hf_cdp_capabilities_igmp_capable, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(capabilities_tree, hf_cdp_capabilities_repeater, tvb, offset, 4, ENC_BIG_ENDIAN);
}

static void
dissect_nrgyz_tlv(tvbuff_t *tvb, packet_info* pinfo, int offset, guint16 length, guint16 num,
                  proto_tree *tree)
{
    guint32     tlvt, tlvl;
    proto_tree *etree = NULL;
    char const *ttext = NULL;

    while (num-- && (length >= 8)) {
        tlvt = tvb_get_ntohl(tvb, offset);
        tlvl = tvb_get_ntohl(tvb, offset + 4);

        if (length < tlvl)
            break;
        length -= tlvl;

        if (tlvl < 8) {
            proto_tree_add_expert_format(tree, pinfo, &ei_cdp_nrgyz_tlvlength, tvb, offset, 8, "TLV with invalid length %u (< 8)", tlvl);
            offset += 8;
            break;
        }
        else {
            ttext = val_to_str(tlvt, type_nrgyz_vals, "Unknown (0x%04x)");
            switch (tlvt) {
            case TYPE_NRGYZ_ROLE:
            case TYPE_NRGYZ_DOMAIN:
            case TYPE_NRGYZ_NAME:
                etree  = proto_tree_add_subtree_format(tree, tvb, offset,
                                         tlvl, ett_cdp_nrgyz_tlv, NULL, "EnergyWise %s: %s", ttext,
                                         tvb_format_stringzpad(tvb, offset + 8, tlvl - 8)
                    );
                break;
            case TYPE_NRGYZ_REPLYTO:
                etree  = proto_tree_add_subtree_format(tree, tvb, offset,
                                         tlvl, ett_cdp_nrgyz_tlv, NULL, "EnergyWise %s: %s port %u",
                                         ttext,
                                         tvb_ip_to_str(tvb, offset + 12),
                                         tvb_get_ntohs(tvb, offset + 10)
                    );
                break;
            default:
                etree  = proto_tree_add_subtree_format(tree, tvb, offset,
                                         tlvl, ett_cdp_nrgyz_tlv, NULL, "EnergyWise %s TLV", ttext);
            }
            proto_tree_add_item(etree, hf_cdp_nrgyz_tlvtype, tvb, offset, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(etree, hf_cdp_nrgyz_tlvlength, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            switch (tlvt) {
            case TYPE_NRGYZ_ROLE:
                proto_tree_add_item(etree, hf_cdp_nrgyz_reply_to_role, tvb, offset + 8, tlvl - 8, ENC_NA|ENC_ASCII);
                break;
            case TYPE_NRGYZ_DOMAIN:
                proto_tree_add_item(etree, hf_cdp_nrgyz_reply_to_domain, tvb, offset + 8, tlvl - 8, ENC_NA|ENC_ASCII);
                break;
            case TYPE_NRGYZ_NAME:
                proto_tree_add_item(etree, hf_cdp_nrgyz_reply_to_name, tvb, offset + 8, tlvl - 8, ENC_NA|ENC_ASCII);
                break;
            case TYPE_NRGYZ_REPLYTO:
                proto_tree_add_item(etree, hf_cdp_nrgyz_reply_to_unknown_field, tvb, offset + 8, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(etree, hf_cdp_nrgyz_reply_to_port, tvb, offset + 10, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(etree, hf_cdp_nrgyz_reply_to_ip_address, tvb, offset + 12, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(etree, hf_cdp_nrgyz_reply_to_backup_server_port, tvb, offset + 16, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(etree, hf_cdp_nrgyz_reply_to_backup_server_ip, tvb, offset + 18, 4, ENC_BIG_ENDIAN);
                break;
            default:
                if (tlvl > 8) {
                    proto_tree_add_item(etree, hf_cdp_data, tvb, offset + 8, tlvl - 8, ENC_NA);
                }
            }
            offset += tlvl;
        }
    }
    if (length) {
        proto_tree_add_expert(tree, pinfo, &ei_cdp_invalid_data, tvb, offset, length);
    }
}

static void
dissect_spare_poe_tlv(tvbuff_t *tvb, int offset, int length,
                      proto_tree *tree)
{
    proto_item *ti;
    proto_tree *tlv_tree;

    if (length == 0) {
        return;
    }

    ti = proto_tree_add_item(tree, hf_cdp_spare_poe_tlv, tvb, offset, 1, ENC_BIG_ENDIAN);
    tlv_tree = proto_item_add_subtree(ti, ett_cdp_spare_poe_tlv);
    proto_tree_add_item(tlv_tree, hf_cdp_spare_poe_tlv_poe, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_tree, hf_cdp_spare_poe_tlv_spare_pair_arch, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_tree, hf_cdp_spare_poe_tlv_req_spare_pair_poe, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_tree, hf_cdp_spare_poe_tlv_pse_spare_pair_poe, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
add_multi_line_string_to_tree(proto_tree *tree, tvbuff_t *tvb, gint start,
  gint len, int hf)
{
    gint next;
    int  line_len;
    int  data_len;

    while (len > 0) {
        line_len = tvb_find_line_end(tvb, start, len, &next, FALSE);
        data_len = next - start;
        proto_tree_add_string(tree, hf, tvb, start, data_len, tvb_format_stringzpad(tvb, start, line_len));
        start += data_len;
        len   -= data_len;
    }
}

void
proto_register_cdp(void)
{
    static hf_register_info hf[] = {
        { &hf_cdp_version,
        { "Version",            "cdp.version",  FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_cdp_ttl,
        { "TTL",                "cdp.ttl", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_cdp_checksum,
        { "Checksum",           "cdp.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},

        { &hf_cdp_checksum_status,
          { "Checksum Status",       "cdp.checksum.status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
            NULL, HFILL }},

        { &hf_cdp_tlvtype,
        { "Type",               "cdp.tlv.type", FT_UINT16, BASE_HEX, VALS(type_vals), 0x0,
          NULL, HFILL }},

        { &hf_cdp_tlvlength,
        { "Length",             "cdp.tlv.len", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_cdp_nrgyz_tlvtype,
        { "TLV Type",               "cdp.nrgyz.tlv.type", FT_UINT16, BASE_HEX, VALS(type_nrgyz_vals), 0x0,
          NULL, HFILL }},

        { &hf_cdp_nrgyz_tlvlength,
        { "TLV Length",             "cdp.nrgyz.tlv.len", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_cdp_deviceid,
        {"Device ID", "cdp.deviceid", FT_STRING, BASE_NONE,
         NULL, 0, NULL, HFILL }},

        { &hf_cdp_platform,
        {"Platform", "cdp.platform", FT_STRING, BASE_NONE,
         NULL, 0, NULL, HFILL }},

        { &hf_cdp_portid,
        {"Sent through Interface", "cdp.portid", FT_STRING, BASE_NONE,
                NULL, 0, NULL, HFILL }},

        { &hf_cdp_capabilities,
        {"Capabilities", "cdp.capabilities", FT_UINT32, BASE_HEX,
                NULL, 0, NULL, HFILL }},

        { &hf_cdp_capabilities_router,
        {"Router", "cdp.capabilities.router", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), 0x01, NULL, HFILL }},

        { &hf_cdp_capabilities_trans_bridge,
        {"Transparent Bridge", "cdp.capabilities.trans_bridge", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), 0x02, NULL, HFILL }},

        { &hf_cdp_capabilities_src_bridge,
        {"Source Route Bridge", "cdp.capabilities.src_bridge", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), 0x04, NULL, HFILL }},

        { &hf_cdp_capabilities_switch,
        {"Switch", "cdp.capabilities.switch", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), 0x08, NULL, HFILL }},

        { &hf_cdp_capabilities_host,
        {"Host", "cdp.capabilities.host", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), 0x10, NULL, HFILL }},

        { &hf_cdp_capabilities_igmp_capable,
        {"IGMP capable", "cdp.capabilities.igmp_capable", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), 0x20, NULL, HFILL }},

        { &hf_cdp_capabilities_repeater,
        {"Repeater", "cdp.capabilities.repeater", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), 0x40, NULL, HFILL }},

        { &hf_cdp_spare_poe_tlv,
        { "Spare Pair PoE", "cdp.spare_poe_tlv", FT_UINT8, BASE_HEX,
                NULL, 0x0, NULL, HFILL }
        },

        { &hf_cdp_spare_poe_tlv_poe,
        { "PSE Four-Wire PoE", "cdp.spare_poe_tlv.poe", FT_BOOLEAN, 8,
                TFS(&tfs_supported_not_supported), 0x01, NULL, HFILL }
        },

        { &hf_cdp_spare_poe_tlv_spare_pair_arch,
        { "PD Spare Pair Architecture", "cdp.spare_poe_tlv.spare_pair_arch", FT_BOOLEAN, 8,
                TFS(&tfs_shared_independent), 0x02, NULL, HFILL }
        },

        { &hf_cdp_spare_poe_tlv_req_spare_pair_poe,
        { "PD Request Spare Pair PoE", "cdp.spare_poe_tlv.req_spare_pair_poe", FT_BOOLEAN, 8,
                TFS(&tfs_on_off), 0x04, NULL, HFILL }
        },

        { &hf_cdp_spare_poe_tlv_pse_spare_pair_poe,
        { "PSE Spare Pair PoE", "cdp.spare_poe_tlv.pse_spare_pair_poe", FT_BOOLEAN, 8,
                TFS(&tfs_on_off), 0x08, NULL, HFILL }
        },

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_cdp_number_of_addresses, { "Number of addresses", "cdp.number_of_addresses", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_odr_default_gateway, { "ODR Default gateway", "cdp.odr_default_gateway", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_ip_prefix, { "IP Prefix", "cdp.ip_prefix", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_oui, { "OUI", "cdp.oui", FT_UINT24, BASE_HEX, VALS(oui_vals), 0x0, NULL, HFILL }},
      { &hf_cdp_protocol_id, { "Protocol ID", "cdp.protocol_id", FT_UINT16, BASE_HEX, VALS(type_hello_vals), 0x0, NULL, HFILL }},
      { &hf_cdp_cluster_master_ip, { "Cluster Master IP", "cdp.cluster.master_ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_cluster_ip, { "IP?", "cdp.cluster.ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_cluster_version, { "Version?", "cdp.cluster.version", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_cluster_sub_version, { "Sub Version?", "cdp.cluster.sub_version", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_cluster_status, { "Status?", "cdp.cluster.status", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_cluster_unknown, { "UNKNOWN", "cdp.cluster.unknown", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_cluster_commander_mac, { "Cluster Commander MAC", "cdp.cluster.commander_mac", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_cluster_switch_mac, { "Switch's MAC", "cdp.cluster.switch_mac", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_cluster_management_vlan, { "Management VLAN", "cdp.cluster.management_vlan", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_hello_unknown, { "Unknown", "cdp.hello.unknown", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_vtp_management_domain, { "VTP Management Domain", "cdp.vtp_management_domain", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_native_vlan, { "Native VLAN", "cdp.native_vlan", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_duplex, { "Duplex", "cdp.duplex", FT_BOOLEAN, BASE_NONE, TFS(&tfs_full_half), 0x0, NULL, HFILL }},
      { &hf_cdp_data, { "Data", "cdp.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_voice_vlan, { "Voice VLAN", "cdp.voice_vlan", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_power_consumption, { "Power Consumption", "cdp.power_consumption", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_mtu, { "MTU", "cdp.mtu", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_trust_bitmap, { "Trust Bitmap", "cdp.trust_bitmap", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_untrusted_port_cos, { "Untrusted port CoS", "cdp.untrusted_port_cos", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_system_name, { "System Name", "cdp.system_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_system_object_identifier, { "System Object Identifier", "cdp.system_object_identifier", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_location_unknown, { "UNKNOWN", "cdp.location.unknown", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_location, { "Location", "cdp.location", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_request_id, { "Request-ID", "cdp.request_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_management_id, { "Management-ID", "cdp.management_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_power_requested, { "Power Requested", "cdp.power_requested", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_power_available, { "Power Available", "cdp.power_available", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_encrypted_data, { "Encrypted Data", "cdp.encrypted_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_seen_sequence, { "Seen Sequence?", "cdp.seen_sequence", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_sequence_number, { "Sequence Number", "cdp.sequence_number", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_model_number, { "Model Number", "cdp.model_number", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_unknown_pad, { "Unknown Pad", "cdp.unknown_pad", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_hardware_version_id, { "Hardware Version ID", "cdp.hardware_version_id", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_system_serial_number, { "System Serial Number", "cdp.system_serial_number", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_nrgyz_unknown_values, { "Unknown Values", "cdp.nrgyz_unknown_values", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_len_tlv_table, { "Length of TLV table", "cdp.len_tlv_table", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_num_tlvs_table, { "Number of TLVs in table", "cdp.num_tlvs_table", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_protocol, { "Protocol", "cdp.protocol", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_protocol_type, { "Protocol type", "cdp.protocol_type", FT_UINT8, BASE_HEX, VALS(proto_type_vals), 0x0, NULL, HFILL }},
      { &hf_cdp_protocol_length, { "Protocol length", "cdp.protocol_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_address, { "Address", "cdp.address", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_address_length, { "Address length", "cdp.address_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_nrgyz_reply_to_unknown_field, { "Unknown Field", "cdp.nrgyz_reply_to.unknown_field", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_nrgyz_reply_to_port, { "Port", "cdp.nrgyz_reply_to.port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_nrgyz_ip_address, { "IP Address", "cdp.nrgyz.ip_address", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_nrgyz_reply_to_ip_address, { "IP Address", "cdp.nrgyz_reply_to.ip_address", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_nrgyz_reply_to_backup_server_port, { "Backup server Port?", "cdp.nrgyz_reply_to.backup_server_port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_nrgyz_reply_to_backup_server_ip, { "Backup Server IP?", "cdp.nrgyz_reply_to.backup_server_ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_nrgyz_reply_to_name, { "Name", "cdp.nrgyz_reply_to.name", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_nrgyz_reply_to_domain, { "Domain", "cdp.nrgyz_reply_to.domain", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_nrgyz_reply_to_role, { "Role", "cdp.nrgyz_reply_to.role", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_cdp_software_version, { "Software version", "cdp.software_version", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_cdp,
        &ett_cdp_tlv,
        &ett_cdp_nrgyz_tlv,
        &ett_cdp_address,
        &ett_cdp_capabilities,
        &ett_cdp_checksum,
        &ett_cdp_spare_poe_tlv
    };

    static ei_register_info ei[] = {
        { &ei_cdp_invalid_data, { "cdp.invalid_data", PI_MALFORMED, PI_ERROR, "Invalid bytes at end", EXPFILL }},
        { &ei_cdp_nrgyz_tlvlength, { "cdp.nrgyz_tlv.length.invalid", PI_MALFORMED, PI_ERROR, "TLV with invalid length", EXPFILL }},
    };
    expert_module_t* expert_cdp;

    proto_cdp = proto_register_protocol("Cisco Discovery Protocol", "CDP", "cdp");

    proto_register_field_array(proto_cdp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_cdp = expert_register_protocol(proto_cdp);
    expert_register_field_array(expert_cdp, ei, array_length(ei));
}

void
proto_reg_handoff_cdp(void)
{
    dissector_handle_t cdp_handle;

    cdp_handle  = create_dissector_handle(dissect_cdp, proto_cdp);
    dissector_add_uint("llc.cisco_pid", 0x2000, cdp_handle);
    dissector_add_uint("chdlc.protocol", 0x2000, cdp_handle);
    dissector_add_uint("ppp.protocol",  0x0207, cdp_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
