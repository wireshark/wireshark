/* packet-hsrp.c
 * Routines for the Cisco Hot Standby Router Protocol (HSRP)
 *
 * Heikki Vatiainen <hessu@cs.tut.fi>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-vrrp.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * RFC 2281 describes opcodes 0 - 2
 *
 * Op Code 3: **** HSRP Interface State Advertisements ****
 * http://www.cisco.com/en/US/products/sw/iosswrel/ps1834/products_feature_guide09186a00800e9763.html
 *
 * An HSRP interface-state advertisement is sent:
 *
 *   * when HSRP on the interface enters or leaves the passive state
 *   * when a group on the interface learns a new Active router
 *   * periodically while the interface is in the passive state
 *
 *                        1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Version     |  Op Code = 3  |           TLV Type            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |            TLV Length         |      State    |   Reserved    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |     Active Group Count        |     Passive Group Count       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                           Reserved                            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  Passive Group Count:  2 octet
 *
 *     A count of the number of passive groups on the interface.  The range
 *     of values are 0-256.
 *
 *  Active Group Count:  2 octet
 *
 *     A count of the number of active groups on the interface.  The range
 *     of values are 0-256.
 *
 *
 * HSRP Version 2
 *  Ref. http://www.smartnetworks.jp/2006/02/hsrp_8_hsrp_version_2.html (Japanese Only)
 *
 *  Group State TLV
 *
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    Type=1     |  Length=40    | HSRP Version  |    Opcode     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |     State     |   IP Version  |         Group Number          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Identifier(6octets)                   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         Identifier            |       Priority(4octets)       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |       Priority cont.          |      Hello Time(4octets)      |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |       Hello Time cont.        |      Hold Time(4octets)       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |       Hold Time cont.         |  Virtual IP Address(16octets) |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                  Virtual IP Address cont.                     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                  Virtual IP Address cont.                     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                  Virtual IP Address cont.                     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    Virtual IP Address cont.   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  Interface State TLV
 *
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    Type=2     |    Length=4   |         Active Groups         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |       Passive Groups          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  Text Authentication TLV
 *
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    Type=3     |   Length=8    |  Authentication Data(8octets) |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                   Authentication Data cont.                   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Authentication Data cont.   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * MD5 Authentication TLV
 *
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    Type=4     |    Length     |   Algorithm   |   Padding     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |             Flags             |      IP Address(4octets)      |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |       IP Address cont.        |         Key ID(4octets)       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         Key ID cont.          | Authentication Data(16octets) |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                   Authentication Data cont.                   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                   Authentication Data cont.                   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                   Authentication Data cont.                   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Authentication Data cont.   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/expert.h>

void proto_register_hsrp(void);
void proto_reg_handoff_hsrp(void);

static gint proto_hsrp = -1;

static gint hf_hsrp_version = -1;
static gint hf_hsrp_opcode = -1;
/* Opcode 0-2 */
static gint hf_hsrp_state = -1;
static gint hf_hsrp_hellotime = -1;
static gint hf_hsrp_holdtime = -1;
static gint hf_hsrp_priority = -1;
static gint hf_hsrp_group = -1;
static gint hf_hsrp_reserved = -1;
static gint hf_hsrp_auth_data = -1;
static gint hf_hsrp_virt_ip_addr = -1;
/* Advertise (3) */
static gint hf_hsrp_adv_type = -1;
static gint hf_hsrp_adv_length = -1;
static gint hf_hsrp_adv_state = -1;
static gint hf_hsrp_adv_reserved1 = -1;
static gint hf_hsrp_adv_activegrp = -1;
static gint hf_hsrp_adv_passivegrp = -1;
static gint hf_hsrp_adv_reserved2 = -1;

static gint ett_hsrp = -1;

/* HSRPv2 */
static gint hf_hsrp2_version = -1;
static gint hf_hsrp2_opcode = -1;
static gint hf_hsrp2_state = -1;
static gint hf_hsrp2_group_state_tlv = -1;
static gint hf_hsrp2_interface_state_tlv = -1;
static gint hf_hsrp2_text_auth_tlv = -1;
static gint hf_hsrp2_md5_auth_tlv = -1;
static gint hf_hsrp2_ipversion = -1;
static gint hf_hsrp2_hellotime = -1;
static gint hf_hsrp2_holdtime = -1;
static gint hf_hsrp2_priority = -1;
static gint hf_hsrp2_identifier = -1;
static gint hf_hsrp2_group = -1;
static gint hf_hsrp2_virt_ip_addr = -1;
static gint hf_hsrp2_virt_ip_addr_v6 = -1;
static gint hf_hsrp2_auth_data = -1;
static gint hf_hsrp2_active_group = -1;
static gint hf_hsrp2_passive_group = -1;
static gint hf_hsrp2_md5_algorithm = -1;
static gint hf_hsrp2_md5_padding = -1;
static gint hf_hsrp2_md5_flags = -1;
static gint hf_hsrp2_md5_ip_address= -1;
static gint hf_hsrp2_md5_key_id= -1;
static gint hf_hsrp2_md5_auth_data= -1;

static gint ett_hsrp2_group_state_tlv = -1;
static gint ett_hsrp2_interface_state_tlv = -1;
static gint ett_hsrp2_text_auth_tlv = -1;
static gint ett_hsrp2_md5_auth_tlv = -1;

static expert_field ei_hsrp_unknown_tlv = EI_INIT;

#define UDP_PORT_HSRP   1985
#define UDP_PORT_HSRP2_V6   2029
#define HSRP_DST_IP_ADDR 0xE0000002
#define HSRP2_DST_IP_ADDR 0xE0000066

struct hsrp_packet {          /* Multicast to 224.0.0.2, TTL 1, UDP, port 1985 */
        guint8  version;      /* RFC2281 describes version 0 */
        guint8  opcode;
        guint8  state;
#define HSRP_DEFAULT_HELLOTIME 3
        guint8  hellotime;    /* In seconds */
#define HSRP_DEFAULT_HOLDTIME 10
        guint8  holdtime;     /* In seconds */
        guint8  priority;     /* Higher is stronger, highest IP address tie-breaker */
        guint8  group;        /* Identifies the standby group */
        guint8  reserved;
        guint8  auth_data[8]; /* Clear-text password, recommended default is `cisco' */
        guint32 virt_ip_addr; /* The virtual IP address used by this group */
};

struct hsrpv2_packet {        /* Multicast to 224.0.0.102, TTL 1, UDP, port 1985 */
        guint8  version;
        guint8  opcode;
        guint8  state;
#define HSRP2_DEFAULT_HELLOTIME 3000
        guint32 hellotime;    /* In msecs */
#define HSRP2_DEFAULT_HOLDTIME 10000
        guint32 holdtime;     /* In msecs */
        guint32 priority;     /* Higher is stronger, highest IP address tie-breaker */
        guint16 group;        /* Identifies the standby group */
        guint8  identifier[6]; /* Identifier of sender's MAC address */
        guint8  auth_data[8]; /* Clear-text password, recommended default is `cisco' */
        gchar   virt_ip_addr[16]; /* The virtual IPv4/IPv6 address used by this group */
        guint8  md5_algorithm;  /* MD5 Hash algorithm */
        guint8  md5_flags;      /* Undefined */
        guint8  md5_ip_address; /* IP address of sender interface */
        guint8  md5_key_id;     /* Name of key chain */
        guint8  md5_auth_data[16]; /* MD5 digest data */
};

#define HSRP_OPCODE_HELLO     0
#define HSRP_OPCODE_COUP      1
#define HSRP_OPCODE_RESIGN    2
#define HSRP_OPCODE_ADVERTISE 3
static const value_string hsrp_opcode_vals[] = {
        {HSRP_OPCODE_HELLO,     "Hello"},
        {HSRP_OPCODE_COUP,      "Coup"},
        {HSRP_OPCODE_RESIGN,    "Resign"},
        {HSRP_OPCODE_ADVERTISE, "Advertise"},
        {0, NULL}
};

#define HSRP_STATE_INITIAL  0
#define HSRP_STATE_LEARN    1
#define HSRP_STATE_LISTEN   2
#define HSRP_STATE_SPEAK    4
#define HSRP_STATE_STANDBY  8
#define HSRP_STATE_ACTIVE  16
static const value_string hsrp_state_vals[] = {
        {HSRP_STATE_INITIAL, "Initial"},
        {HSRP_STATE_LEARN,   "Learn"},
        {HSRP_STATE_LISTEN,  "Listen"},
        {HSRP_STATE_SPEAK,   "Speak"},
        {HSRP_STATE_STANDBY, "Standby"},
        {HSRP_STATE_ACTIVE,  "Active"},
        {0, NULL}
};

#define HSRP_ADV_TYPE_INTSTATE 1
#define HSRP_ADV_TYPE_IPREDUN  2
static const value_string hsrp_adv_type_vals[] = {
        {HSRP_ADV_TYPE_INTSTATE, "HSRP interface state"},
        {HSRP_ADV_TYPE_IPREDUN,  "IP redundancy"},
        {0, NULL}
};

#define HSRP_ADV_STATE_DORMANT 1
#define HSRP_ADV_STATE_PASSIVE 2
#define HSRP_ADV_STATE_ACTIVE  3
static const value_string hsrp_adv_state_vals[] = {
        {HSRP_ADV_STATE_DORMANT, "Dormant"},
        {HSRP_ADV_STATE_PASSIVE, "Passive"},
        {HSRP_ADV_STATE_ACTIVE,  "Active"},
        {0, NULL}
};

#define HSRP2_OPCODE_HELLO     0
#define HSRP2_OPCODE_COUP      1
#define HSRP2_OPCODE_RESIGN    2
static const value_string hsrp2_opcode_vals[] = {
        {HSRP2_OPCODE_HELLO,     "Hello"},
        {HSRP2_OPCODE_COUP,      "Coup"},
        {HSRP2_OPCODE_RESIGN,    "Resign"},
        {0, NULL}
};

#define HSRP2_STATE_DISABLED 0
#define HSRP2_STATE_INIT     1
#define HSRP2_STATE_LEARN    2
#define HSRP2_STATE_LISTEN   3
#define HSRP2_STATE_SPEAK    4
#define HSRP2_STATE_STANDBY  5
#define HSRP2_STATE_ACTIVE   6
static const value_string hsrp2_state_vals[] = {
        {HSRP2_STATE_INIT,    "Init"},
        {HSRP2_STATE_LEARN,   "Learn"},
        {HSRP2_STATE_LISTEN,  "Listen"},
        {HSRP2_STATE_SPEAK,   "Speak"},
        {HSRP2_STATE_STANDBY, "Standby"},
        {HSRP2_STATE_ACTIVE,  "Active"},
        {0, NULL}
};

#define HSRP2_IPVERSION_IPV4 4
#define HSRP2_IPVERSION_IPV6 6
static const value_string hsrp2_ipversion_vals[] = {
        {HSRP2_IPVERSION_IPV4, "IPv4"},
        {HSRP2_IPVERSION_IPV6, "IPv6"},
        {0, NULL}
};

#define HSRP2_MD5_ALGORITHM 1
static const value_string hsrp2_md5_algorithm_vals[] = {
        {HSRP2_MD5_ALGORITHM, "MD5"},
        {0, NULL}
};

static void
process_hsrp_md5_tlv_sequence(tvbuff_t *tvb, proto_tree *hsrp_tree, guint offset)
{
        guint8 type = tvb_get_guint8(tvb, offset);
        guint8 len = tvb_get_guint8(tvb, offset+1);
        proto_item *ti;
        proto_tree *md5_auth_tlv;

        ti = proto_tree_add_uint_format_value(hsrp_tree, hf_hsrp2_md5_auth_tlv, tvb, offset, 1, type, "Type=%d Len=%d", type, len);
        offset+=2;

        /* Making MD5 Authentication TLV subtree */
        md5_auth_tlv = proto_item_add_subtree(ti, ett_hsrp2_md5_auth_tlv);
        proto_tree_add_item(md5_auth_tlv, hf_hsrp2_md5_algorithm, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* padding field */
        proto_tree_add_item(md5_auth_tlv, hf_hsrp2_md5_padding, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(md5_auth_tlv, hf_hsrp2_md5_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        proto_tree_add_item(md5_auth_tlv, hf_hsrp2_md5_ip_address, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        proto_tree_add_item(md5_auth_tlv, hf_hsrp2_md5_key_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4; /* this now points to the start of the MD5 hash */
        proto_tree_add_item(md5_auth_tlv, hf_hsrp2_md5_auth_data, tvb, offset, 16, ENC_NA);
}

static int
dissect_hsrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
        tvbuff_t   *next_tvb;
        guint32 hsrpv1 = g_htonl(HSRP_DST_IP_ADDR),
                hsrpv2 = g_htonl(HSRP2_DST_IP_ADDR);

        /* Return if this isn't really HSRP traffic
         * (source and destination port must be UDP_PORT_HSRP on HSRPv1 or HSRPv2(IPv4))
         * (source and destination port must be UDP_PORT_HSRP2_V6 on HSRPv2(IPv6))
         */
        if(pinfo->destport != UDP_PORT_HSRP && pinfo->destport != UDP_PORT_HSRP2_V6)
                return 0;

        /*
         * To check whether this is an HSRPv1 packet or HSRPv2 on dest IPv4 addr.
         */
        if (pinfo->dst.type == AT_IPv4 && memcmp(pinfo->dst.data, &hsrpv1, 4) == 0) {
                /* HSRPv1 */
                guint8 opcode, state = 0;
                proto_item *ti;
                proto_tree *hsrp_tree;
                gint offset;
                guint8 hellotime, holdtime;
                gchar auth_buf[8 + 1];

                col_set_str(pinfo->cinfo, COL_PROTOCOL, "HSRP");

                opcode = tvb_get_guint8(tvb, 1);
                col_set_str(pinfo->cinfo, COL_INFO,
                                     val_to_str_const(opcode, hsrp_opcode_vals, "Unknown"));

                if (opcode < 3) {
                        state = tvb_get_guint8(tvb, 2);
                        col_append_fstr(pinfo->cinfo, COL_INFO, " (state %s)",
                                     val_to_str_const(state, hsrp_state_vals, "Unknown"));
                } else if (opcode == 3) {
                        state = tvb_get_guint8(tvb, 6);
                        col_append_fstr(pinfo->cinfo, COL_INFO, " (state %s)",
                                        val_to_str_const(state, hsrp_adv_state_vals, "Unknown"));
                }

                offset = 0;
                ti = proto_tree_add_item(tree, proto_hsrp, tvb, offset, -1, ENC_NA);
                hsrp_tree = proto_item_add_subtree(ti, ett_hsrp);

                proto_tree_add_item(hsrp_tree, hf_hsrp_version, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                proto_tree_add_uint(hsrp_tree, hf_hsrp_opcode, tvb, offset, 1, opcode);
                offset++;
                if (opcode < 3) {
                        proto_tree_add_uint(hsrp_tree, hf_hsrp_state, tvb, offset, 1, state);
                        offset++;
                        hellotime = tvb_get_guint8(tvb, offset);
                        proto_tree_add_uint_format_value(hsrp_tree, hf_hsrp_hellotime, tvb, offset, 1, hellotime,
                                           "%sDefault (%u)",
                                           (hellotime == HSRP_DEFAULT_HELLOTIME) ? "" : "Non-",
                                           hellotime);
                        offset++;
                        holdtime = tvb_get_guint8(tvb, offset);
                        proto_tree_add_uint_format_value(hsrp_tree, hf_hsrp_holdtime, tvb, offset, 1, holdtime,
                                           "%sDefault (%u)",
                                           (holdtime == HSRP_DEFAULT_HOLDTIME) ? "" : "Non-",
                                           holdtime);
                        offset++;
                        proto_tree_add_item(hsrp_tree, hf_hsrp_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                        proto_tree_add_item(hsrp_tree, hf_hsrp_group, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                        proto_tree_add_item(hsrp_tree, hf_hsrp_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                        tvb_memcpy(tvb, auth_buf, offset, 8);
                        auth_buf[sizeof auth_buf - 1] = '\0';
                        proto_tree_add_string_format_value(hsrp_tree, hf_hsrp_auth_data, tvb, offset, 8, auth_buf,
                                             "%sDefault (%s)",
                                             (tvb_strneql(tvb, offset, "cisco", strlen("cisco"))) == 0 ? "" : "Non-",
                                             auth_buf);
                        offset += 8;
                        proto_tree_add_item(hsrp_tree, hf_hsrp_virt_ip_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
                        /* offset += 4; */
                } else if (opcode == 3) {
                        proto_tree_add_item(hsrp_tree, hf_hsrp_adv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        proto_tree_add_item(hsrp_tree, hf_hsrp_adv_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        proto_tree_add_item(hsrp_tree, hf_hsrp_adv_state, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                        proto_tree_add_item(hsrp_tree, hf_hsrp_adv_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                        proto_tree_add_item(hsrp_tree, hf_hsrp_adv_activegrp, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        proto_tree_add_item(hsrp_tree, hf_hsrp_adv_passivegrp, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        proto_tree_add_item(hsrp_tree, hf_hsrp_adv_reserved2, tvb, offset, 4, ENC_BIG_ENDIAN);
                        /* offset += 4; */
                } else {
                        next_tvb = tvb_new_subset_remaining(tvb, offset);
                        call_data_dissector(next_tvb, pinfo, hsrp_tree);
                }
                /* is MD5 authentication being used with HSRPv1? */
                if (tvb_captured_length(tvb) == 50) { /* 20 bytes of regular HSRP data + 30 bytes of authentication payload */
                        guint offset2 = offset + 4; /* this now points to the start of a possible TLV sequence */
                        guint8 type = tvb_get_guint8(tvb, offset2);
                        guint8 len = tvb_get_guint8(tvb, offset2+1);
                        if (type == 4 && len == 28) {
                                /* MD5 Authentication TLV */
                                if (tree) {
                                        process_hsrp_md5_tlv_sequence(tvb, hsrp_tree, offset2);
                                }
                        } else {
                                expert_add_info_format(pinfo, ti, &ei_hsrp_unknown_tlv,
                                                "Unknown TLV sequence in HSRPv1 dissection, Type=(%d) Len=(%d)", type, len);
                        }
                }
        } else if ((pinfo->dst.type == AT_IPv4 && memcmp(pinfo->dst.data, &hsrpv2, 4) == 0) ||
                   (pinfo->dst.type == AT_IPv6 && pinfo->destport == UDP_PORT_HSRP2_V6)) {
                /* HSRPv2 */
                guint offset = 0, offset2;
                proto_item *ti = NULL;
                proto_tree *hsrp_tree = NULL;
                guint8 type,len;

                col_set_str(pinfo->cinfo, COL_PROTOCOL, "HSRPv2");

                if (tree) {
                        ti = proto_tree_add_item(tree, proto_hsrp, tvb, offset, -1, ENC_NA);
                        hsrp_tree = proto_item_add_subtree(ti, ett_hsrp);
                }

                while (tvb_reported_length_remaining(tvb, offset) > 0) {
                        type = tvb_get_guint8(tvb, offset);
                        len = tvb_get_guint8(tvb, offset+1);

                        offset2 = offset;
                        if (type == 1 && len == 40) {
                                /* Group State TLV */
                                guint8 opcode, state = 0, ipver;
                                guint32 hellotime, holdtime;
                                proto_tree *group_state_tlv;

                                if (tree) {
                                        ti = proto_tree_add_uint_format_value(hsrp_tree, hf_hsrp2_group_state_tlv, tvb, offset, 2, type,
                                        "Type=%d Len=%d", type, len);
                                }
                                offset+=2;

                                opcode = tvb_get_guint8(tvb, offset+1);
                                col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
                                                     val_to_str_const(opcode, hsrp2_opcode_vals, "Unknown"));

                                state = tvb_get_guint8(tvb, offset+2);
                                col_append_fstr(pinfo->cinfo, COL_INFO, " (state %s)",
                                                val_to_str_const(state, hsrp2_state_vals, "Unknown"));

                                if (tree) {
                                        /* Making Group State TLV subtree. */
                                        group_state_tlv = proto_item_add_subtree(ti, ett_hsrp2_group_state_tlv);
                                        proto_tree_add_item(group_state_tlv, hf_hsrp2_version, tvb, offset, 1, ENC_BIG_ENDIAN);
                                        offset++;
                                        proto_tree_add_uint(group_state_tlv, hf_hsrp2_opcode, tvb, offset, 1, opcode);
                                        offset++;
                                        proto_tree_add_uint(group_state_tlv, hf_hsrp2_state, tvb, offset, 1, state);
                                        offset++;
                                        ipver = tvb_get_guint8(tvb, offset);
                                        proto_tree_add_uint(group_state_tlv, hf_hsrp2_ipversion, tvb, offset, 1, ipver);
                                        offset++;
                                        proto_tree_add_item(group_state_tlv, hf_hsrp2_group, tvb, offset, 2, ENC_BIG_ENDIAN);
                                        offset+=2;
                                        proto_tree_add_item(group_state_tlv, hf_hsrp2_identifier, tvb, offset, 6, ENC_NA);
                                        offset+=6;
                                        proto_tree_add_item(group_state_tlv, hf_hsrp2_priority, tvb, offset, 4, ENC_BIG_ENDIAN);
                                        offset+=4;

                                        hellotime = tvb_get_ntohl(tvb, offset);
                                        proto_tree_add_uint_format_value(group_state_tlv, hf_hsrp2_hellotime, tvb, offset, 4, hellotime,
                                                           "%sDefault (%u)",
                                                           (hellotime == HSRP2_DEFAULT_HELLOTIME) ? "" : "Non-",
                                                           hellotime);
                                        offset+=4;
                                        holdtime = tvb_get_ntohl(tvb, offset);
                                        proto_tree_add_uint_format_value(group_state_tlv, hf_hsrp2_holdtime, tvb, offset, 4, holdtime,
                                                           "%sDefault (%u)",
                                                           (holdtime == HSRP2_DEFAULT_HOLDTIME) ? "" : "Non-",
                                                           holdtime);
                                        offset+=4;
                                        if (ipver == 4) {
                                                /* Fetch Virtual IP as IPv4 */
                                                proto_tree_add_item(group_state_tlv, hf_hsrp2_virt_ip_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
                                        } else if (ipver == 6) {
                                                /* Fetch Virtual IP as IPv6 */
                                                proto_tree_add_item(group_state_tlv, hf_hsrp2_virt_ip_addr_v6, tvb, offset, 16, ENC_NA);
                                        } else {
                                                /* Unknown protocol */
                                                next_tvb = tvb_new_subset_remaining(tvb, offset);
                                                call_data_dissector(next_tvb, pinfo, hsrp_tree);
                                                break;
                                        }
                                        /* offset+=16; */
                                }
                        } else if (type == 2 && len == 4) {
                                /* Interface State TLV */
                                guint16 active,passive;
                                active = tvb_get_ntohs(tvb, offset+2);
                                passive = tvb_get_ntohs(tvb, offset+4);

                                col_add_fstr(pinfo->cinfo, COL_INFO, "Interface State TLV (Act=%d Pass=%d)",active,passive);

                                if (tree) {
                                        proto_tree *interface_state_tlv;
                                        ti = proto_tree_add_uint_format_value(hsrp_tree, hf_hsrp2_interface_state_tlv, tvb, offset, 1, type,
                                        "Type=%d Len=%d", type, len);
                                        offset+=2;

                                        /* Making Interface State TLV subtree */
                                        interface_state_tlv = proto_item_add_subtree(ti, ett_hsrp2_interface_state_tlv);
                                        proto_tree_add_item(interface_state_tlv, hf_hsrp2_active_group, tvb, offset, 2, ENC_BIG_ENDIAN);
                                        offset+=2;
                                        proto_tree_add_item(interface_state_tlv, hf_hsrp2_passive_group, tvb, offset, 2, ENC_BIG_ENDIAN);
                                        /* offset+=2; */
                                }
                        } else if (type == 3 && len == 8) {
                                /* Text Authentication TLV */
                                if (tree) {
                                        proto_tree *text_auth_tlv;
                                        gchar auth_buf[8 + 1];

                                        ti = proto_tree_add_uint_format_value(hsrp_tree, hf_hsrp2_text_auth_tlv, tvb, offset, 1, type,
                                        "Type=%d Len=%d", type, len);
                                        offset+=2;

                                        /* Making Text Authentication TLV subtree */
                                        text_auth_tlv = proto_item_add_subtree(ti, ett_hsrp2_text_auth_tlv);

                                        tvb_memcpy(tvb, auth_buf, offset, 8);
                                        auth_buf[sizeof auth_buf - 1] = '\0';
                                        proto_tree_add_string_format_value(text_auth_tlv, hf_hsrp2_auth_data, tvb, offset, 8, auth_buf,
                                                             "%sDefault (%s)",
                                                             (tvb_strneql(tvb, offset, "cisco", strlen("cisco"))) == 0 ? "" : "Non-",
                                                             auth_buf);
                                        /* offset += 8; */
                                }
                        } else if (type == 4 && len == 28) {
                                /* MD5 Authentication TLV */
                                if (tree) {
                                        process_hsrp_md5_tlv_sequence(tvb, hsrp_tree, offset);
                                        /* offset += 16; */
                                }
                        } else {
                                /* Undefined TLV */
                                next_tvb = tvb_new_subset_remaining(tvb, offset);
                                call_data_dissector(next_tvb, pinfo, hsrp_tree);
                                break;
                        }
                        offset = offset2+len+2;
                }
        }

        return tvb_captured_length(tvb);
}

void proto_register_hsrp(void)
{
        expert_module_t* expert_hsrp;

        static hf_register_info hf[] = {
                { &hf_hsrp_version,
                  { "Version", "hsrp.version",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    "The version of the HSRP messages", HFILL }},

                { &hf_hsrp_opcode,
                  { "Op Code", "hsrp.opcode",
                    FT_UINT8, BASE_DEC, VALS(hsrp_opcode_vals), 0x0,
                    "The type of message contained in this packet", HFILL }},

                { &hf_hsrp_state,
                  { "State", "hsrp.state",
                    FT_UINT8, BASE_DEC, VALS(hsrp_state_vals), 0x0,
                    "The current state of the router sending the message", HFILL }},

                { &hf_hsrp_hellotime,
                  { "Hellotime", "hsrp.hellotime",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    "The approximate period between the Hello messages that the router sends", HFILL }},

                { &hf_hsrp_holdtime,
                  { "Holdtime", "hsrp.holdtime",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    "Time that the current Hello message should be considered valid", HFILL }},

                { &hf_hsrp_priority,
                  { "Priority", "hsrp.priority",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    "Used to elect the active and standby routers. Numerically higher priority wins vote", HFILL }},

                { &hf_hsrp_group,
                  { "Group", "hsrp.group",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    "This field identifies the standby group", HFILL }},

                { &hf_hsrp_reserved,
                  { "Reserved", "hsrp.reserved",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    NULL, HFILL }},

                { &hf_hsrp_auth_data,
                  { "Authentication Data", "hsrp.auth_data",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "Contains a clear-text 8 character reused password", HFILL }},

                { &hf_hsrp_virt_ip_addr,
                  { "Virtual IP Address", "hsrp.virt_ip",
                    FT_IPv4, BASE_NONE, NULL, 0x0,
                    "The virtual IP address used by this group", HFILL }},

                { &hf_hsrp_adv_type,
                  { "Adv type", "hsrp.adv.tlvtype",
                    FT_UINT16, BASE_DEC, VALS(hsrp_adv_type_vals), 0x0,
                    "Advertisement tlv type", HFILL }},

                { &hf_hsrp_adv_length,
                  { "Adv length", "hsrp.adv.tlvlength",
                    FT_UINT16, BASE_DEC, NULL, 0x0,
                    "Advertisement tlv length", HFILL }},

                { &hf_hsrp_adv_state,
                  { "Adv state", "hsrp.adv.state",
                    FT_UINT8, BASE_DEC, VALS(hsrp_adv_state_vals), 0x0,
                    "Advertisement tlv length", HFILL }},

                { &hf_hsrp_adv_reserved1,
                  { "Adv reserved1", "hsrp.adv.reserved1",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    "Advertisement tlv length", HFILL }},

                { &hf_hsrp_adv_activegrp,
                  { "Adv active groups", "hsrp.adv.activegrp",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    "Advertisement active group count", HFILL }},

                { &hf_hsrp_adv_passivegrp,
                  { "Adv passive groups", "hsrp.adv.passivegrp",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    "Advertisement passive group count", HFILL }},

                { &hf_hsrp_adv_reserved2,
                  { "Adv reserved2", "hsrp.adv.reserved2",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "Advertisement tlv length", HFILL }},

                { &hf_hsrp2_version,
                  { "Version", "hsrp2.version",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    "The version of the HSRP messages", HFILL }},

                { &hf_hsrp2_opcode,
                  { "Op Code", "hsrp2.opcode",
                    FT_UINT8, BASE_DEC, VALS(hsrp2_opcode_vals), 0x0,
                    "The type of message contained in this packet", HFILL }},

                { &hf_hsrp2_state,
                  { "State", "hsrp2.state",
                    FT_UINT8, BASE_DEC, VALS(hsrp2_state_vals), 0x0,
                    "The current state of the router sending the message", HFILL }},

                { &hf_hsrp2_group_state_tlv,
                  { "Group State TLV", "hsrp2.group_state_tlv",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    NULL, HFILL }},

                { &hf_hsrp2_interface_state_tlv,
                  { "Interface State TLV", "hsrp2.interface_state_tlv",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    NULL, HFILL }},

                { &hf_hsrp2_text_auth_tlv,
                  { "Text Authentication TLV", "hsrp2.text_auth_tlv",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    NULL, HFILL }},

                { &hf_hsrp2_md5_auth_tlv,
                  { "MD5 Authentication TLV", "hsrp2.md5_auth_tlv",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    NULL, HFILL }},

                { &hf_hsrp2_ipversion,
                  { "IP Ver.", "hsrp2.ipversion",
                    FT_UINT8, BASE_DEC, VALS(hsrp2_ipversion_vals), 0x0,
                    "The IP protocol version used in this hsrp message", HFILL }},

                { &hf_hsrp2_group,
                  { "Group", "hsrp2.group",
                    FT_UINT16, BASE_DEC, NULL, 0x0,
                    "This field identifies the standby group", HFILL }},

                { &hf_hsrp2_identifier,
                  { "Identifier", "hsrp2.identifier",
                    FT_ETHER, BASE_NONE, NULL, 0x0,
                    "BIA value of a sender interface", HFILL }},

                { &hf_hsrp2_hellotime,
                  { "Hellotime", "hsrp2.hellotime",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "The approximate period between the Hello messages that the router sends", HFILL }},

                { &hf_hsrp2_holdtime,
                  { "Holdtime", "hsrp2.holdtime",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "Time that the current Hello message should be considered valid", HFILL }},

                { &hf_hsrp2_priority,
                  { "Priority", "hsrp2.priority",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "Used to elect the active and standby routers. Numerically higher priority wins vote", HFILL }},

                { &hf_hsrp2_auth_data,
                  { "Authentication Data", "hsrp2.auth_data",
                    FT_STRING, BASE_NONE, NULL, 0x0,
                    "Contains a clear-text 8 character reused password", HFILL }},

                { &hf_hsrp2_virt_ip_addr,
                  { "Virtual IP Address", "hsrp2.virt_ip",
                    FT_IPv4, BASE_NONE, NULL, 0x0,
                    "The virtual IP address used by this group", HFILL }},

                { &hf_hsrp2_virt_ip_addr_v6,
                  { "Virtual IPv6 Address", "hsrp2.virt_ip_v6",
                    FT_IPv6, BASE_NONE, NULL, 0x0,
                    "The virtual IPv6 address used by this group", HFILL }},

                { &hf_hsrp2_active_group,
                  { "Active Groups", "hsrp2.active_groups",
                    FT_UINT16, BASE_DEC, NULL, 0x0,
                    "Active group number which becomes the active router myself", HFILL }},

                { &hf_hsrp2_passive_group,
                  { "Passive Groups", "hsrp2.passive_groups",
                    FT_UINT16, BASE_DEC, NULL, 0x0,
                    "Standby group number which doesn't become the active router myself", HFILL }},

                { &hf_hsrp2_md5_algorithm,
                  { "MD5 Algorithm", "hsrp2.md5_algorithm",
                    FT_UINT8, BASE_DEC, VALS(hsrp2_md5_algorithm_vals), 0x0,
                    "Hash Algorithm used by this group", HFILL }},

                { &hf_hsrp2_md5_padding,
                  { "Padding", "hsrp2.md5_padding",
                    FT_UINT8, BASE_HEX, NULL, 0x0,
                    "Must be zero", HFILL }},

                { &hf_hsrp2_md5_flags,
                  { "MD5 Flags", "hsrp2.md5_flags",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    "Undefined", HFILL }},

                { &hf_hsrp2_md5_ip_address,
                  { "Sender's IP Address", "hsrp.md5_ip_address",
                    FT_IPv4, BASE_NONE, NULL, 0x0,
                    "IP Address of the sender interface", HFILL }},

                { &hf_hsrp2_md5_key_id,
                  { "MD5 Key ID", "hsrp2.md5_key_id",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "This field contains Key chain ID", HFILL }},

                { &hf_hsrp2_md5_auth_data,
                  { "MD5 Authentication Data", "hsrp2.md5_auth_data",
                    FT_BYTES, BASE_NONE, NULL, 0x0,
                    "MD5 digest string is contained.", HFILL }}
        };

        static gint *ett[] = {
                &ett_hsrp,
                &ett_hsrp2_group_state_tlv,
                &ett_hsrp2_interface_state_tlv,
                &ett_hsrp2_text_auth_tlv,
                &ett_hsrp2_md5_auth_tlv
        };

        static ei_register_info ei[] = {
                { &ei_hsrp_unknown_tlv, { "hsrp.unknown_tlv", PI_UNDECODED, PI_WARN, "Unknown TLV sequence (HSRPv1)", EXPFILL }},
        };

        proto_hsrp = proto_register_protocol("Cisco Hot Standby Router Protocol",
            "HSRP", "hsrp");
        proto_register_field_array(proto_hsrp, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
        expert_hsrp = expert_register_protocol(proto_hsrp);
        expert_register_field_array(expert_hsrp, ei, array_length(ei));

        return;
}

void
proto_reg_handoff_hsrp(void)
{
        dissector_handle_t hsrp_handle;

        hsrp_handle = create_dissector_handle(dissect_hsrp, proto_hsrp);
        dissector_add_uint("udp.port", UDP_PORT_HSRP, hsrp_handle);
        dissector_add_uint("udp.port", UDP_PORT_HSRP2_V6, hsrp_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 expandtab:
 * :indentSize=8:tabSize=8:noTabs=true:
 */
