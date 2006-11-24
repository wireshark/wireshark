/* packet-hsrp.c
 * Routines for the Cisco Hot Standby Router Protocol (HSRP)
 *
 * Heikki Vatiainen <hessu@cs.tut.fi>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>

static gint proto_hsrp = -1;
static dissector_handle_t data_handle;

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

#define UDP_PORT_HSRP   1985

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


#define HSRP_OPCODE_HELLO     0
#define HSRP_OPCODE_COUP      1
#define HSRP_OPCODE_RESIGN    2
#define HSRP_OPCODE_ADVERTISE 3
static const value_string hsrp_opcode_vals[] = {
        {HSRP_OPCODE_HELLO,     "Hello"},
        {HSRP_OPCODE_COUP,      "Coup"},
        {HSRP_OPCODE_RESIGN,    "Resign"},
        {HSRP_OPCODE_ADVERTISE, "Advertise"},
	{0, NULL},
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
	{0, NULL},
};

#define HSRP_ADV_TYPE_INTSTATE 1
#define HSRP_ADV_TYPE_IPREDUN  2
static const value_string hsrp_adv_type_vals[] = {
        {HSRP_ADV_TYPE_INTSTATE, "HSRP interface state"},
        {HSRP_ADV_TYPE_IPREDUN,  "IP redundancy"},
	{0, NULL},
};

#define HSRP_ADV_STATE_DORMANT 1
#define HSRP_ADV_STATE_PASSIVE 2
#define HSRP_ADV_STATE_ACTIVE  3
static const value_string hsrp_adv_state_vals[] = {
        {HSRP_ADV_STATE_DORMANT, "Dormant"},
        {HSRP_ADV_STATE_PASSIVE, "Passive"},
        {HSRP_ADV_STATE_ACTIVE,  "Active"},
	{0, NULL},
};

static int
dissect_hsrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        guint8 opcode, state = 0;
	tvbuff_t   *next_tvb;

	/* Return if this isn't really HSRP traffic
	 * (source and destination port must be UDP_PORT_HSRP) */
	if(pinfo->destport != UDP_PORT_HSRP)
		return 0;

        if (check_col(pinfo->cinfo, COL_PROTOCOL))
                col_set_str(pinfo->cinfo, COL_PROTOCOL, "HSRP");

        opcode = tvb_get_guint8(tvb, 1);
        if (check_col(pinfo->cinfo, COL_INFO)) {
                col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
                             val_to_str(opcode, hsrp_opcode_vals, "Unknown"));
	}
	if (opcode < 3) {
        	state = tvb_get_guint8(tvb, 2);
		if (check_col(pinfo->cinfo, COL_INFO)) {
                	col_append_fstr(pinfo->cinfo, COL_INFO, " (state %s)",
                       		     val_to_str(state, hsrp_state_vals, "Unknown"));
		}
        } else if (opcode == 3) {
        	state = tvb_get_guint8(tvb, 6);
		if (check_col(pinfo->cinfo, COL_INFO)) {
                	col_append_fstr(pinfo->cinfo, COL_INFO, " (state %s)",
                       		     val_to_str(state, hsrp_adv_state_vals, "Unknown"));
		}
	}

        if (tree) {
                proto_item *ti;
                proto_tree *hsrp_tree;
                int offset;
                guint8 hellotime, holdtime;
                guint8 auth_buf[8 + 1];

                offset = 0;
                ti = proto_tree_add_item(tree, proto_hsrp, tvb, offset, -1, FALSE);
                hsrp_tree = proto_item_add_subtree(ti, ett_hsrp);

                proto_tree_add_item(hsrp_tree, hf_hsrp_version, tvb, offset, 1, FALSE);
                offset++;
                proto_tree_add_uint(hsrp_tree, hf_hsrp_opcode, tvb, offset, 1, opcode);
                offset++;
		if (opcode < 3) {
			proto_tree_add_uint(hsrp_tree, hf_hsrp_state, tvb, offset, 1, state);
			offset++;
			hellotime = tvb_get_guint8(tvb, offset);
			proto_tree_add_uint_format(hsrp_tree, hf_hsrp_hellotime, tvb, offset, 1, hellotime,
                                           "Hellotime: %sDefault (%u)",
                                           (hellotime == HSRP_DEFAULT_HELLOTIME) ? "" : "Non-",
                                           hellotime);
			offset++;
			holdtime = tvb_get_guint8(tvb, offset);
			proto_tree_add_uint_format(hsrp_tree, hf_hsrp_holdtime, tvb, offset, 1, holdtime,
                                           "Holdtime: %sDefault (%u)",
                                           (holdtime == HSRP_DEFAULT_HOLDTIME) ? "" : "Non-",
                                           holdtime);
			offset++;
			proto_tree_add_item(hsrp_tree, hf_hsrp_priority, tvb, offset, 1, FALSE);
			offset++;
			proto_tree_add_item(hsrp_tree, hf_hsrp_group, tvb, offset, 1, FALSE);
			offset++;
			proto_tree_add_item(hsrp_tree, hf_hsrp_reserved, tvb, offset, 1, FALSE);
			offset++;
			tvb_memcpy(tvb, auth_buf, offset, 8);
			auth_buf[sizeof auth_buf - 1] = '\0';
			proto_tree_add_string_format(hsrp_tree, hf_hsrp_auth_data, tvb, offset, 8, auth_buf,
                                             "Authentication Data: %sDefault (%s)",
                                             (tvb_strneql(tvb, offset, "cisco", strlen("cisco"))) == 0 ? "" : "Non-",
                                             auth_buf);
			offset += 8;
			proto_tree_add_item(hsrp_tree, hf_hsrp_virt_ip_addr, tvb, offset, 4, FALSE);
			offset += 4;
		} else if (opcode == 3) {
			proto_tree_add_item(hsrp_tree, hf_hsrp_adv_type, tvb, offset, 2, FALSE);
			offset += 2;
			proto_tree_add_item(hsrp_tree, hf_hsrp_adv_length, tvb, offset, 2, FALSE);
			offset += 2;
			proto_tree_add_item(hsrp_tree, hf_hsrp_adv_state, tvb, offset, 1, FALSE);
			offset += 1;
			proto_tree_add_item(hsrp_tree, hf_hsrp_adv_reserved1, tvb, offset, 1, FALSE);
			offset += 1;
			proto_tree_add_item(hsrp_tree, hf_hsrp_adv_activegrp, tvb, offset, 2, FALSE);
			offset += 2;
			proto_tree_add_item(hsrp_tree, hf_hsrp_adv_passivegrp, tvb, offset, 2, FALSE);
			offset += 2;
			proto_tree_add_item(hsrp_tree, hf_hsrp_adv_reserved2, tvb, offset, 4, FALSE);
			offset += 4;
		} else {
			next_tvb = tvb_new_subset(tvb, offset, -1, -1);
			call_dissector(data_handle, next_tvb, pinfo, hsrp_tree);
		}
        }

        return tvb_length(tvb);
}

void proto_register_hsrp(void)
{
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
                    "Reserved", HFILL }},

                { &hf_hsrp_auth_data,
                  { "Authentication Data", "hsrp.auth_data",
                    FT_STRING, 0, NULL, 0x0,
                    "Contains a clear-text 8 character reused password", HFILL }},

                { &hf_hsrp_virt_ip_addr,
                  { "Virtual IP Address", "hsrp.virt_ip",
                    FT_IPv4, 0, NULL, 0x0,
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

        };

        static gint *ett[] = {
                &ett_hsrp,
        };

        proto_hsrp = proto_register_protocol("Cisco Hot Standby Router Protocol",
	    "HSRP", "hsrp");
        proto_register_field_array(proto_hsrp, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));

        return;
}

void
proto_reg_handoff_hsrp(void)
{
	dissector_handle_t hsrp_handle;

	data_handle = find_dissector("data");
	hsrp_handle = new_create_dissector_handle(dissect_hsrp, proto_hsrp);
	dissector_add("udp.port", UDP_PORT_HSRP, hsrp_handle);
}
