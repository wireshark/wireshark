/* packet-ipmi.c
 * Routines for IPMI-over-LAN packet dissection
 *
 * Duncan Laurie <duncan@sun.com>
 *
 * $Id: packet-ipmi.c,v 1.2 2003/06/04 08:51:36 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-rmcp.c
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 *
 * See the IPMI spec at
 *
 *	http://www.intel.com/design/servers/ipmi/
 *
 * IPMI LAN Message Request
 *  ipmi.session.authtype
 *  ipmi.session.sequence
 *  ipmi.session.id
 * [ipmi.session.authcode]
 *  ipmi.msg.len
 *  ipmi.msg.rsaddr
 *  ipmi.msg.netfn << 2 | ipmi.msg.rslun
 *  ipmi.msg.csum1
 *  ipmi.msg.rqaddr
 *  ipmi.msg.seq << 2 | ipmi.msg.rqlun
 *  ipmi.msg.cmd
 *  ipmi.msg.DATA
 *  ipmi.msg.csum2
 *
 * IPMI LAN Message Response
 *  ipmi.session.authtype
 *  ipmi.session.sequence
 *  ipmi.session.id
 * [ipmi.session.authcode]
 *  ipmi.msg.len
 *  ipmi.msg.rqaddr
 *  ipmi.msg.netfn << 2 | ipmi.msg.rqlun
 *  ipmi.msg.csum1
 *  ipmi.msg.rsaddr
 *  ipmi.msg.seq << 2 | ipmi.msg.rslun
 *  ipmi.msg.cmd
 *  ipmi.msg.ccode
 *  ipmi.msg.DATA
 *  ipmi.msg.csum2
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#define RMCP_CLASS_IPMI 0x07

static dissector_handle_t data_handle;
static int proto_ipmi = -1;

static gint ett_ipmi = -1;
static gint ett_ipmi_session = -1;
static gint ett_ipmi_msg_nlfield = -1;
static gint ett_ipmi_msg_slfield = -1;

/* IPMI session header */
static int hf_ipmi_session_id = -1;
static int hf_ipmi_session_authtype = -1;
static int hf_ipmi_session_sequence = -1;
static int hf_ipmi_session_authcode = -1;

/* IPMI message header */
static int hf_ipmi_msg_len = -1;
static int hf_ipmi_msg_rsaddr = -1;
static int hf_ipmi_msg_nlfield = -1;
static int hf_ipmi_msg_netfn = -1;
static int hf_ipmi_msg_rqlun = -1;
static int hf_ipmi_msg_csum1 = -1;
static int hf_ipmi_msg_rqaddr = -1;
static int hf_ipmi_msg_slfield = -1;
static int hf_ipmi_msg_seq = -1;
static int hf_ipmi_msg_rslun = -1;
static int hf_ipmi_msg_cmd = -1;
static int hf_ipmi_msg_ccode = -1;
static int hf_ipmi_msg_csum2 = -1;

static const value_string ipmi_netfn_vals[] = {
	{ 0x00, "Chassis Request" },
	{ 0x01,	"Chassis Response" },
	{ 0x02,	"Bridge Request" },
	{ 0x03,	"Bridge Response" },
	{ 0x04,	"Sensor/Event Request" },
	{ 0x05,	"Sensor/Event Response" },
	{ 0x06,	"Application Request" },
	{ 0x07,	"Application Response" },
	{ 0x08,	"Firmware Request" },
	{ 0x09,	"Frimware Response" },
	{ 0x0a,	"Storage Request" },
	{ 0x0b,	"Storage Response" },
	{ 0x0c,	"Transport Request" },
	{ 0x0d,	"Transport Response" },
	{ 0x2c,	"Group Extension Request" },
	{ 0x2d,	"Group Extension Response" },
	{ 0x30,	"OEM Request" },
	{ 0x31,	"OEM Response" },
	{ 0x00,	NULL },
};

static const value_string ipmi_authtype_vals[] = {
	{ 0x00,	"NONE" },
	{ 0x01,	"MD2" },
	{ 0x02,	"MD5" },
	{ 0x04,	"PASSWORD" },
	{ 0x05,	"OEM" },
	{ 0x00,	NULL }
};

static const value_string ipmi_ccode_vals[] = {
	{ 0x00, "Command completed normally" },
	{ 0xc0, "Node busy" },
	{ 0xc1, "Unrecognized or unsupported command" },
	{ 0xc2, "Command invalid for given LUN" },
	{ 0xc3, "Timeout while processing command" },
	{ 0xc4, "Out of space" },
	{ 0xc5, "Reservation cancelled or invalid reservation ID" },
	{ 0xc6, "Request data truncated" },
	{ 0xc7, "Request data length invalid" },
	{ 0xc8, "Request data field length limit exceeded" },
	{ 0xc9, "Parameter out of range" },
	{ 0xca, "Cannot return number of requested data bytes" },
	{ 0xcb, "Requested sensor, data, or record not present" },
	{ 0xcc, "Invalid data field in request" },
	{ 0xcd, "Command illegal for specified sensor or record type" },
	{ 0xce, "Command response could not be provided" },
	{ 0xcf, "Cannot execute duplicated request" },
	{ 0xd0, "SDR repository in update mode" },
	{ 0xd1, "Device in firmware update mode" },
	{ 0xd2, "BMC initialization or initialization agent running" },
	{ 0xd3, "Destination unavailable" },
	{ 0xd4, "Insufficient privilege level" },
	{ 0xd5, "Command or param not supported in present state" },
	{ 0xff, "Unspecified error" },
	{ 0x00, NULL },
};

static const value_string ipmi_addr_vals[] = {
	{ 0x20, "BMC Slave Address" },
	{ 0x81,	"Remote Console Software ID" },
	{ 0x00,	NULL },
};

static const value_string ipmi_chassis_cmd_vals[] = {
	/* Chassis Device Commands */
	{ 0x00,	"Get Chassis Capabilities" },
	{ 0x01,	"Get Chassis Status" },
	{ 0x02,	"Chassis Control" },
	{ 0x03,	"Chassis Reset" },
	{ 0x04,	"Chassis Identify" },
	{ 0x05,	"Set Chassis Capabilities" },
	{ 0x06,	"Set Power Restore Policy" },
	{ 0x07,	"Get System Restart Cause" },
	{ 0x08,	"Set System Boot Options" },
	{ 0x09,	"Get System Boot Options" },
	{ 0x0f,	"Get POH Counter" },
	{ 0x00,	NULL },
};

static const value_string ipmi_bridge_cmd_vals[] = {
	/* ICMB Bridge Management Commands */
	{ 0x00,	"Get Bridge State" },
	{ 0x01,	"Set Bridge State" },
	{ 0x02,	"Get ICMB Address" },
	{ 0x03,	"Set ICMB Address" },
	{ 0x04,	"Set Bridge ProxyAddress" },
	{ 0x05,	"Get Bridge Statistics" },
	{ 0x06,	"Get ICMB Capabilities" },
	{ 0x08,	"Clear Bridge Statistics" },
	{ 0x09,	"Get Bridge Proxy Address" },
	{ 0x0a,	"Get ICMB Connector Info" },
	{ 0x0b,	"Get ICMB Connection ID" },
	{ 0x0c,	"Send ICMB Connection ID" },
	/* ICMB Discovery Commands */
	{ 0x10,	"Prepare For Discovery" },
	{ 0x11,	"Get Addresses" },
	{ 0x12,	"Set Discovered" },
	{ 0x13,	"Get Chassis Device ID" },
	{ 0x14,	"Set Chassis Device ID" },
	/* ICMB Bridging Commands */
	{ 0x20,	"Bridge Request" },
	{ 0x21,	"Bridge Message" },
	/* ICMB Event Commands */
	{ 0x30,	"Get Event Count" },
	{ 0x31,	"Set Event Destination" },
	{ 0x32,	"Set Event Reception State" },
	{ 0x33,	"Send ICMB Event Message" },
	{ 0x34,	"Get Event Destination" },
	{ 0x35,	"Get Event Recption State" },
	{ 0x00,	NULL },
};

static const value_string ipmi_se_cmd_vals[] = {
	/* Event Commands */
	{ 0x00,	"Set Event Receiver" },
	{ 0x01,	"Get Event Receiver" },
	{ 0x02,	"Platform Event Message" },
	/* PEF and Alerting Commands */
	{ 0x10,	"Get PEF Capabilities" },
	{ 0x11,	"Arm PEF Postpone Timer" },
	{ 0x12,	"Set PEF Config Params" },
	{ 0x13,	"Get PEF Config Params" },
	{ 0x14,	"Set Last Processed Event ID" },
	{ 0x15,	"Get Last Processed Event ID" },
	{ 0x16,	"Alert Immediate" },
	{ 0x17,	"PET Acknowledge" },
	/* Sensor Device Commands */
	{ 0x20,	"Get Device SDR Info" },
	{ 0x21,	"Get Device SDR" },
	{ 0x22,	"Reserve Device SDR Repository" },
	{ 0x23,	"Get Sensor Reading Factors" },
	{ 0x24,	"Set Sensor Hysteresis" },
	{ 0x25,	"Get Sensor Hysteresis" },
	{ 0x26,	"Set Sensor Threshold" },
	{ 0x27,	"Get Sensor Threshold" },
	{ 0x28,	"Set Sensor Event Enable" },
	{ 0x29,	"Get Sensor Event Enable" },
	{ 0x2a,	"Re-arm Sensor Events" },
	{ 0x2b,	"Get Sensor Event Status" },
	{ 0x2d,	"Get Sensor Reading" },
	{ 0x2e,	"Set Sensor Type" },
	{ 0x2f,	"Get Sensor Type" },
	{ 0x00,	NULL },
};

static const value_string ipmi_storage_cmd_vals[] = {
	/* FRU Device Commands */
	{ 0x10,	"Get FRU Inventory Area Info" },
	{ 0x11,	"Read FRU Data" },
	{ 0x12,	"Write FRU Data" },
	/* SDR Device Commands */
	{ 0x20,	"Get SDR Repository Info" },
	{ 0x21,	"Get SDR Repository Allocation Info" },
	{ 0x22,	"Reserve SDR Repository" },
	{ 0x23,	"Get SDR" },
	{ 0x24,	"Add SDR" },
	{ 0x25,	"Partial Add SDR" },
	{ 0x26,	"Delete SDR" },
	{ 0x27,	"Clear SDR Repository" },
	{ 0x28,	"Get SDR Repository Time" },
	{ 0x29,	"Set SDR Repository Time" },
	{ 0x2a,	"Enter SDR Repository Update Mode" },
	{ 0x2b,	"Exit SDR Repository Update Mode" },
	{ 0x2c,	"Run Initialization Agent" },
	/* SEL Device Commands */
	{ 0x40,	"Get SEL Info" },
	{ 0x41,	"Get SEL Allocation Info" },
	{ 0x42,	"Reserve SEL" },
	{ 0x43,	"Get SEL Entry" },
	{ 0x44,	"Add SEL Entry" },
	{ 0x45,	"Partial Add SEL Entry" },
	{ 0x46,	"Delete SEL Entry" },
	{ 0x47,	"Clear SEL" },
	{ 0x48,	"Get SEL Time" },
	{ 0x49,	"Set SEL Time" },
	{ 0x5a,	"Get Auxillary Log Status" },
	{ 0x5b,	"Set Auxillary Log Status" },
	{ 0x00,	NULL },
};

static const value_string ipmi_transport_cmd_vals[] = {
	/* LAN Device Commands */
	{ 0x01,	"Set LAN Config Param" },
	{ 0x02,	"Get LAN Config Param" },
	{ 0x03,	"Suspend BMC ARPs" },
	{ 0x04,	"Get IP/UDP/RMCP Statistics" },
	/* Serial/Modem Device Commands */
	{ 0x10,	"Set Serial/Modem Config" },
	{ 0x11,	"Get Serial/Modem Config" },
	{ 0x12,	"Get Serial/Modem Mux" },
	{ 0x13,	"Get TAP Response Codes" },
	{ 0x14,	"Set PPP UDP Proxy Transmit Data" },
	{ 0x15,	"Get PPP UDP Proxy Transmit Data" },
	{ 0x16,	"Send PPP UDP Proxy Packet" },
	{ 0x17,	"Get PPP UDP Proxy Data" },
	{ 0x18,	"Serial/Modem Connection Active" },
	{ 0x19,	"Callback" },
	{ 0x1a,	"Set User Callback Options" },
	{ 0x1b,	"Get User Callback Options" },
	{ 0x00,	NULL },
};

static const value_string ipmi_app_cmd_vals[] = {
	/* Device "Global" Commands */
	{ 0x01,	"Get Device ID" },
	{ 0x02,	"Cold Reset" },
	{ 0x03,	"Warm Reset" },
	{ 0x04,	"Get Self Test Results" },
	{ 0x05,	"Manufacturing Test On" },
	{ 0x06,	"Set ACPI Power State" },
	{ 0x07,	"Get ACPI Power State" },
	{ 0x08,	"Get Device GUID" },
	/* BMC Watchdog Timer Commands */
	{ 0x22,	"Reset Watchdog Timer" },
	{ 0x24,	"Set Watchdog Timer" },
	{ 0x25,	"Get Watchdog Timer" },
	/* BMC Device and Messaging Commands */
	{ 0x2e,	"Set BMC Global Enables" },
	{ 0x2f,	"Get BMC Global Enables" },
	{ 0x30,	"Clear Message Flags" },
	{ 0x31,	"Get Message Flags" },
	{ 0x32,	"Enable Message Channel Receive" },
	{ 0x33,	"Get Message" },
	{ 0x34,	"Send Message" },
	{ 0x35,	"Read Event Message Buffer" },
	{ 0x36,	"Get BT Interface Capabilities" },
	{ 0x37,	"Get System GUID" },
	{ 0x38,	"Get Channel Auth Capabilities" },
	{ 0x39,	"Get Session Challenge" },
	{ 0x3a,	"Activate Session" },
	{ 0x3b,	"Set Session Privilege Level" },
	{ 0x3c,	"Close Session" },
	{ 0x3d,	"Get Session Info" },
	{ 0x3e,	"unassigned" },
	{ 0x3f,	"Get AuthCode" },
	{ 0x40,	"Set Channel Access" },
	{ 0x41,	"Get Channel Access" },
	{ 0x42,	"Get Channel Info" },
	{ 0x43,	"Set User Access" },
	{ 0x44,	"Get User Access" },
	{ 0x45,	"Set User Name" },
	{ 0x46,	"Get User Name" },
	{ 0x47,	"Set User Password" },
	{ 0x52,	"Master Write-Read" },
	{ 0x00,	NULL },
};

static const char *
get_netfn_cmd_text(guint8 netfn, guint8 cmd)
{
	switch (netfn) {
	case 0x00:
	case 0x01:
		return val_to_str(cmd, ipmi_chassis_cmd_vals, "Unknown (0x%02x)");
	case 0x02:
	case 0x03:
		return val_to_str(cmd, ipmi_bridge_cmd_vals, "Unknown (0x%02x)");
	case 0x04:
	case 0x05:
		return val_to_str(cmd, ipmi_se_cmd_vals, "Unknown (0x%02x)");
	case 0x06:
	case 0x07:
		return val_to_str(cmd, ipmi_app_cmd_vals, "Unknown (0x%02x)");
	case 0x0a:
	case 0x0b:
		return val_to_str(cmd, ipmi_storage_cmd_vals, "Unknown (0x%02x)");
	case 0x0c:
	case 0x0d:
		return val_to_str(cmd, ipmi_transport_cmd_vals, "Unknown (0x%02x)");
	default:
		return (netfn & 1) ? "Unknown Response" : "Unknown Request";
	}
}

static void
dissect_ipmi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*ipmi_tree = NULL, *field_tree = NULL;
	proto_item	*ti = NULL, *tf;
	gint		offset = 0;
	tvbuff_t	*next_tvb;
	guint32		session_id;
	guint8		authtype, netfn, cmd, ccode, len;
	gint		response;

	/* session authtype, 0=no authcode present */
	authtype = tvb_get_guint8(tvb, 0);

	/* session ID */
	session_id = tvb_get_letohl(tvb, 5);

	/* network function code */
	netfn = tvb_get_guint8(tvb, authtype ? 27 : 11) >> 2;

	/* bit 0 of netfn: even=request odd=response */
	response =  netfn & 1;

	/* command */
	cmd = tvb_get_guint8(tvb, authtype ? 31 : 15);

	/* completion code */
	ccode = response ? tvb_get_guint8(tvb, authtype ? 32 : 16) : 0;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPMI");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);
	if (check_col(pinfo->cinfo, COL_INFO)) {
		if (ccode)
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s, %s: %s",
			     get_netfn_cmd_text(netfn, cmd),
			     val_to_str(netfn, ipmi_netfn_vals,	"Unknown (0x%02x)"),
			     val_to_str(ccode, ipmi_ccode_vals,	"Unknown (0x%02x)"));
		else
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s, %s",
			     get_netfn_cmd_text(netfn, cmd),
			     val_to_str(netfn, ipmi_netfn_vals,	"Unknown (0x%02x)"));
	}

	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_ipmi,
			    tvb, offset, authtype ? 32 : 16,
			    "Intelligent Platform Management Interface, "
			    "NetFn: %s (0x%02x), Cmd: %s (0x%02x)",
			    val_to_str(netfn, ipmi_netfn_vals, "Unknown (0x%02x)"),
			    netfn, get_netfn_cmd_text(netfn, cmd), cmd);
		ipmi_tree = proto_item_add_subtree(ti, ett_ipmi);
	}

	/* ipmi session field */
	if (tree) {
		tf = proto_tree_add_text(ipmi_tree, tvb, offset,
				 authtype ? 25 : 9,
				 "Session: ID 0x%08x (%d bytes)",
				 session_id, authtype ? 25 : 9);
		field_tree = proto_item_add_subtree(tf, ett_ipmi_session);
		proto_tree_add_item(field_tree, hf_ipmi_session_authtype,
			    tvb, offset++, 1, TRUE);
		proto_tree_add_item(field_tree, hf_ipmi_session_sequence,
			    tvb, offset, 4, TRUE);
		offset += 4;
		proto_tree_add_item(field_tree, hf_ipmi_session_id,
			    tvb, offset, 4, TRUE);
		offset += 4;
		if (authtype) {
			proto_tree_add_item(field_tree, hf_ipmi_session_authcode,
				    tvb, offset, 16, TRUE);
			offset += 16;
		}
	}

	/* message length */
	if (tree) {
		proto_tree_add_item(ipmi_tree, hf_ipmi_msg_len,
			    tvb, offset++, 1, TRUE);
	}

	/* r[sq]addr */
	if (tree) {
		proto_tree_add_item(ipmi_tree,
			    response ? hf_ipmi_msg_rqaddr : hf_ipmi_msg_rsaddr,
			    tvb, offset++, 1, TRUE);
	}

	/* netfn/lun */
	if (tree) {
		tf = proto_tree_add_text(ipmi_tree, tvb, offset, 1,
			 "NetFn/LUN: %s", val_to_str(netfn,
			 ipmi_netfn_vals, "Unknown (0x%02x)"));

		field_tree = proto_item_add_subtree(tf, ett_ipmi_msg_nlfield);

		proto_tree_add_item(field_tree, hf_ipmi_msg_netfn,
				    tvb, offset, 1, TRUE);
		proto_tree_add_item(field_tree,
				    response ? hf_ipmi_msg_rqlun : hf_ipmi_msg_rslun,
				    tvb, offset, 1, TRUE);
		offset += 1;
	}

	/* checksum */
	if (tree) {
		proto_tree_add_item(ipmi_tree, hf_ipmi_msg_csum1,
				    tvb, offset++, 1, TRUE);
	}

	/* r[sq]addr */
	if (tree) {
		proto_tree_add_item(ipmi_tree,
				    response ? hf_ipmi_msg_rsaddr : hf_ipmi_msg_rqaddr,
				    tvb, offset++, 1, TRUE);
	}

	/* seq/lun */
	if (tree) {
		tf = proto_tree_add_item(ipmi_tree, hf_ipmi_msg_slfield,
					 tvb, offset, 1, TRUE);
		field_tree = proto_item_add_subtree(tf, ett_ipmi_msg_slfield);

		proto_tree_add_item(field_tree, hf_ipmi_msg_seq,
				    tvb, offset, 1, TRUE);
		proto_tree_add_item(field_tree,
				    response ? hf_ipmi_msg_rslun : hf_ipmi_msg_rqlun,
				    tvb, offset, 1, TRUE);
		offset += 1;
	}

	/* command */
	if (tree) {
		proto_tree_add_text(ipmi_tree, tvb, offset++, 1,
				    "Command: %s (0x%02x)",
				    get_netfn_cmd_text(netfn, cmd), cmd);
	}

	/* completion code */
	if (tree && response) {
		proto_tree_add_item(ipmi_tree, hf_ipmi_msg_ccode,
				    tvb, offset++, 1, TRUE);
	}

	/* determine data length */
	len = tvb_get_guint8(tvb, authtype ? 25 : 9) - 7 - (response ? 1 : 0);

	/* dissect the data block */
	next_tvb = tvb_new_subset(tvb, offset, len, len);
	call_dissector(data_handle, next_tvb, pinfo, tree);
	offset += len;

	/* checksum 2 */
	if (tree) {
		proto_tree_add_item(ipmi_tree, hf_ipmi_msg_csum2,
				    tvb, offset++, 1, TRUE);
	}
}

void
proto_register_ipmi(void)
{
	static hf_register_info hf_session[] = {
		{ &hf_ipmi_session_authtype, {
			"Authentication Type", "ipmi.session.authtype",
			FT_UINT8, BASE_HEX, VALS(ipmi_authtype_vals), 0,
			"IPMI Authentication Type", HFILL }},
		{ &hf_ipmi_session_sequence, {
			"Session Sequence Number", "ipmi.session.sequence",
			FT_UINT32, BASE_HEX, NULL, 0,
			"IPMI Session Sequence Number", HFILL }},
		{ &hf_ipmi_session_id, {
			"Session ID", "ipmi.session.id",
			FT_UINT32, BASE_HEX, NULL, 0,
			"IPMI Session ID", HFILL }},
		{ &hf_ipmi_session_authcode, {
			"Authentication Code", "ipmi.session.authcode",
			FT_BYTES, BASE_HEX, NULL, 0,
			"IPMI Message Authentication Code", HFILL }},
	};
	static hf_register_info hf_msg[] = {
		{ &hf_ipmi_msg_len, {
			"Message Length", "ipmi.msg.len",
			FT_UINT8, BASE_DEC, NULL, 0,
			"IPMI Message Length", HFILL }},
		{ &hf_ipmi_msg_rsaddr, {
			"Response Address", "ipmi.msg.rsaddr",
			FT_UINT8, BASE_HEX, VALS(ipmi_addr_vals), 0,
			"Responder's Slave Address", HFILL }},
		{ &hf_ipmi_msg_csum1, {
			"Checksum 1", "ipmi.msg.csum1",
			FT_UINT8, BASE_HEX, NULL, 0,
			"2s Complement Checksum", HFILL }},
		{ &hf_ipmi_msg_rqaddr, {
			"Request Address", "ipmi.msg.rqaddr",
			FT_UINT8, BASE_HEX, VALS(ipmi_addr_vals), 0,
			"Requester's Address (SA or SWID)", HFILL }},
		{ &hf_ipmi_msg_cmd, {
			"Command", "ipmi.msg.cmd",
			FT_UINT8, BASE_HEX, NULL, 0,
			"IPMI Command Byte", HFILL }},
		{ &hf_ipmi_msg_ccode, {
			"Completion Code", "ipmi.msg.ccode",
			FT_UINT8, BASE_HEX, VALS(ipmi_ccode_vals), 0,
			"Completion Code for Request", HFILL }},
		{ &hf_ipmi_msg_csum2, {
			"Checksum 2", "ipmi.msg.csum2",
			FT_UINT8, BASE_HEX, NULL, 0,
			"2s Complement Checksum", HFILL }},
	};
	static hf_register_info hf_msg_field[] = {
		{ &hf_ipmi_msg_nlfield, {
			"NetFn/LUN", "ipmi.msg.nlfield",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Network Function and LUN field", HFILL }},
		{ &hf_ipmi_msg_netfn, {
			"NetFn", "ipmi.msg.nlfield.netfn",
			FT_UINT8, BASE_HEX, VALS(ipmi_netfn_vals), 0xfc,
			"Network Function Code", HFILL }},
		{ &hf_ipmi_msg_rqlun, {
			"Request LUN", "ipmi.msg.nlfield.rqlun",
			FT_UINT8, BASE_HEX, NULL, 0x03,
			"Requester's Logical Unit Number", HFILL }},
		{ &hf_ipmi_msg_slfield, {
			"Seq/LUN", "ipmi.msg.slfield",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Sequence and LUN field", HFILL }},
		{ &hf_ipmi_msg_seq, {
			"Sequence", "ipmi.msg.slfield.seq",
			FT_UINT8, BASE_HEX, NULL, 0xfc,
			"Sequence Number (requester)", HFILL }},
		{ &hf_ipmi_msg_rslun, {
			"Response LUN", "ipmi.msg.slfield.rslun",
			FT_UINT8, BASE_HEX, NULL, 0x03,
			"Responder's Logical Unit Number", HFILL }},
	};
	static gint *ett[] = {
		&ett_ipmi,
		&ett_ipmi_session,
		&ett_ipmi_msg_nlfield,
		&ett_ipmi_msg_slfield,
	};

	proto_ipmi = proto_register_protocol(
		"Intelligent Platform Management Interface", "IPMI", "ipmi");

	proto_register_field_array(proto_ipmi, hf_session,
			   array_length(hf_session));
	proto_register_field_array(proto_ipmi, hf_msg,
			   array_length(hf_msg));
	proto_register_field_array(proto_ipmi, hf_msg_field,
			   array_length(hf_msg_field));

	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ipmi(void)
{
	dissector_handle_t ipmi_handle;

	data_handle = find_dissector("data");

	ipmi_handle = create_dissector_handle(dissect_ipmi, proto_ipmi);
	dissector_add("rmcp.class", RMCP_CLASS_IPMI, ipmi_handle);
}
