/* packet-cfm.c
 * Routines for CFM EOAM (IEEE 802.1ag) dissection
 * Copyright 2007, Keith Mercer <keith.mercer@alcatel-lucent.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* This code is based on the IEEE P802.1ag/D8.1 document, which is not formally
 * released at the time of this dissector development, and may change requiring
 * additional modifications to this code.
 *
 * The CFM dissector will recognize ITU Y.1731 opcodes but will not be
 * dissected, with the exception of AIS, until a future version of this code.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/prefs.h>
#include <stdio.h>
#include <glib.h>
#include <string.h>
#include <epan/etypes.h>
#include "packet-cfm.h"

/* forward reference */
static void dissect_cfm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static int proto_cfm = -1;
static dissector_handle_t cfm_handle;


static const value_string opcodetypenames[] = {
	{ IEE8021, 	"Reserved for IEE 802.1" },
	{ CCM, 		"Continuity Check Message (CCM)" },
	{ LBR, 		"Loopback Reply (LBR)" },
	{ LBM, 		"Loopback Message (LBM)" },
	{ LTR, 		"Linktrace Reply (LTR)" },
	{ LTM, 		"Linktrace Message (LTM)" },
	{ AIS,		"Alarm Indication Signal (AIS)" },
	{ LCK,		"Lock Signal (LCK)" },
	{ TST,		"Test Signal (TST)" },
	{ APS,		"Automatic Protection Switching (APS)" },
	{ MCC,		"Maintenance Communication Channel (MCC)" },
	{ LMM,		"Loss Measurement Message (LMM)" },
	{ LMR,		"Loss Measurement Reply (LMR)" },
	{ ODM,		"One Way Delay Measurement (1DM)" },
	{ DMM,		"Delay Measurement Message (DMM)" },
	{ DMR,		"Delay Measurement Reply (DMR)" },
	{ EXM,		"Experimental OAM Message (EXM)" },
	{ EXR,		"Experimental OAM Reply (EXR)" },
	{ VSM,		"Vendor Specific Message (VSM)" },
	{ VSR,		"Vendor Specific Reply (VSR)" },
	{ 0,            NULL }
};
static const value_string CCM_IntervalFieldEncoding[] = {
	{ 0, "invalid" },
	{ 1, "Trans Int 3.33ms, max Lifetime 11.66ms, min Lifetime 10.83ms" },
	{ 2, "Trans Int 10ms, max Lifetime 35ms, min Lifetime 32.5ms" },
	{ 3, "Trans Int 100ms, max Lifetime 350ms, min Lifetime 325ms" },
	{ 4, "Trans Int 1ms, max Lifetime 3.5s, min Lifetime 3.25s" },
	{ 5, "Trans Int 10s, max Lifetime 35s, min Lifetime 32.5s" },
	{ 6, "Trans Int 1min, max Lifetime 3.5min, min Lifetime 3.25min" },
	{ 7, "Trans Int 10min, max Lifetime 35min, min Lifetime 32.5min" },
	{ 0, NULL }
};
static const value_string mdnameformattypes[] = {
	{ 0, "Reserved for IEEE 802.1" },
	{ 1, "No Maintenance Domain Name preset" },
	{ 2, "RFC1035 DNS Name" },
	{ 3, "MAC address + 2-octet integer" },
	{ 4, "Character String" },
	{ 0, NULL }
};
static const value_string manameformattypes[] = {
	{ 0, "Reserved for IEEE 802.1" },
	{ 1, "Primary VID" },
	{ 2, "Character String" },
	{ 3, "2-octet integer" },
	{ 4, "RFC 2685 VPN ID" },
	{ 0, NULL }
};
static const value_string relayactiontypes[] = {
	{ 1, "RlyHit" },
	{ 2, "RlyFDB" },
	{ 3, "RlyMPDB" },
	{ 0, NULL }
};
static const value_string aislckperiodtypes[] = {
	{ 0, "Invalid Value for AIS/LCK PDU's" },
	{ 1, "Invalid Value for AIS/LCK PDU's" },
	{ 2, "Invalid Value for AIS/LCK PDU's" },
	{ 3, "Invalid Value for AIS/LCK PDU's" },
	{ 4, "1 frame per second" },
	{ 5, "Invalid Value for AIS/LCK PDU's" },
	{ 6, "1 frame per minute" },
	{ 7, "Invalid Value for AIS/LCK PDU's" },
	{ 0, NULL }
};
static const value_string tlvtypefieldvalues[] = {
	{ END_TLV		, "End TLV" },
	{ SENDER_ID_TLV		, "Sender ID TLV" },
	{ PORT_STAT_TLV		, "Port Status TLV" },
	{ DATA_TLV		, "Data TLV" },
	{ INTERF_STAT_TLV	, "Interface Status TLV" },
	{ REPLY_ING_TLV		, "Reply Ingress TLV" },
	{ REPLY_EGR_TLV		, "Reply Egress TLV" },
	{ LTM_EGR_ID_TLV	, "LTM Egress Identifier TLV" },
	{ LTR_EGR_ID_TLV	, "LTR Egress Identifier TLV" },
	{ ORG_SPEC_TLV		, "Organizational-Specific TLV" },
	{ 0                     , NULL }
};
static const value_string portstatTLVvalues[] = {
	{ 1, "psBlocked" },
	{ 2, "psUp" },
	{ 0, NULL }
};
static const value_string interfacestatTLVvalues[] = {
	{ 1, "isUp" },
	{ 2, "isDown" },
	{ 3, "isTesting" },
	{ 4, "isUnknown" },
	{ 5, "isDormant" },
	{ 6, "isNotPresent" },
	{ 7, "isLowerLayerDown" },
	{ 0, NULL }
};
static const value_string replyingressTLVvalues[] = {
	{ 1, "IngOK" },
	{ 2, "IngDown" },
	{ 3, "IngBlocked" },
	{ 4, "IngVID" },
	{ 0, NULL }
};
static const value_string replyegressTLVvalues[] = {
	{ 1, "EgrOK" },
	{ 2, "EgrDown" },
	{ 3, "EgrBlocked" },
	{ 4, "EgrVID" },
	{ 0, NULL }
};


static int hf_cfm_md_level = -1;
static int hf_cfm_version = -1;
static int hf_cfm_opcode = -1;

static int hf_cfm_flags = -1;
static int hf_cfm_flags_RDI = -1;
static int hf_cfm_flags_ccm_Reserved = -1;
static int hf_cfm_flags_Interval = -1;
static int hf_cfm_flags_UseFDBonly = -1;
static int hf_cfm_flags_ltm_Reserved = -1;
static int hf_cfm_flags_ltr_Reserved = -1;
static int hf_cfm_flags_FwdYes = -1;
static int hf_cfm_flags_TerminalMEP = -1;
static int hf_cfm_first_tlv_offset = -1;

static int hf_cfm_ccm_pdu = -1;
static int hf_cfm_ccm_seq_number = -1;
static int hf_cfm_ccm_ma_ep_id = -1;
static int hf_cfm_ccm_maid = -1;
static int hf_cfm_maid_md_name_format = -1;
static int hf_cfm_maid_md_name_length = -1;
static int hf_cfm_maid_md_name_string = -1;
static int hf_cfm_maid_md_name_hex = -1;
static int hf_cfm_maid_ma_name_format = -1;
static int hf_cfm_maid_ma_name_length = -1;
static int hf_cfm_maid_ma_name_string = -1;
static int hf_cfm_maid_ma_name_hex = -1;
static int hf_cfm_maid_padding = -1;
static int hf_cfm_ccm_itu_t_y1731 = -1;

static int hf_cfm_lbm_pdu = -1;
static int hf_cfm_lb_transaction_id = -1;

static int hf_cfm_lbr_pdu = -1;

static int hf_cfm_ltm_pdu = -1;
static int hf_cfm_lt_transaction_id = -1;
static int hf_cfm_lt_ttl = -1;
static int hf_cfm_ltm_orig_addr = -1;
static int hf_cfm_ltm_targ_addr = -1;

static int hf_cfm_ltr_pdu = -1;
static int hf_cfm_ltr_relay_action = -1;

static int hf_cfm_ais_pdu = -1;
static int hf_cfm_flags_ais_lck_Reserved = -1;
static int hf_cfm_flags_ais_lck_Period = -1;

static int hf_cfm_all_tlvs = -1;
static int hf_cfm_tlv_type = -1;
static int hf_cfm_tlv_length = -1;
static int hf_tlv_chassis_id_length = -1;
static int hf_tlv_chassis_id_subtype = -1;
static int hf_tlv_chassis_id = -1;
static int hf_tlv_ma_domain_length = -1;
static int hf_tlv_ma_domain = -1;
static int hf_tlv_management_addr_length = -1;
static int hf_tlv_management_addr = -1;
static int hf_tlv_port_status_value = -1;
static int hf_tlv_data_value = -1;
static int hf_tlv_interface_status_value = -1;

static int hf_tlv_reply_ingress_action = -1;
static int hf_tlv_reply_ingress_mac_address = -1;
static int hf_tlv_reply_ing_egr_portid_length = -1;
static int hf_tlv_reply_ing_egr_portid_subtype = -1;
static int hf_tlv_reply_ing_egr_portid = -1;
static int hf_tlv_reply_egress_action = -1;
static int hf_tlv_reply_egress_mac_address = -1;
static int hf_tlv_ltr_egress_last_id = -1;
static int hf_tlv_ltr_egress_next_id = -1;
static int hf_tlv_ltm_egress_id_mac = -1;
static int hf_tlv_ltm_egress_id_unique_identifier = -1;
static int hf_tlv_org_spec_oui = -1;
static int hf_tlv_org_spec_subtype = -1;
static int hf_tlv_org_spec_value = -1;

static gint ett_cfm = -1;
static gint ett_cfm_ccm = -1;
static gint ett_cfm_flags = -1;
static gint ett_cfm_ccm_maid = -1;
static gint ett_cfm_lbm = -1;
static gint ett_cfm_lbr = -1;
static gint ett_cfm_ltm = -1;
static gint ett_cfm_ltr = -1;
static gint ett_cfm_ais = -1;
static gint ett_cfm_all_tlvs = -1;
static gint ett_cfm_tlv = -1;

/* Register CFM EOAM protocol */
void proto_register_cfm(void)
{
	static hf_register_info hf[] = {
		{ &hf_cfm_md_level,
			{ "CFM MD Level", "cfm.md.level", FT_UINT8,
			BASE_DEC, NULL, 0xe0, NULL, HFILL }
		},
		{ &hf_cfm_version,
			{ "CFM Version", "cfm.version", FT_UINT8,
			BASE_DEC, NULL, 0x1f, NULL, HFILL }
		},
		{ &hf_cfm_opcode,
			{ "CFM OpCode", "cfm.opcode", FT_UINT8,
			BASE_DEC, VALS(opcodetypenames), 0x0, NULL, HFILL }
		},

		/* CFM CCM*/
		{ &hf_cfm_ccm_pdu,
			{ "CFM CCM PDU", "cfm.ccm.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL	}
		},
		{ &hf_cfm_flags,
			{ "Flags", "cfm.flags", FT_UINT8,
			BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_flags_RDI,
			{ "RDI", "cfm.flags.rdi", FT_UINT8,
			BASE_DEC, NULL, 0x80, NULL, HFILL }
		},
		{ &hf_cfm_flags_ccm_Reserved,
			{ "Reserved", "cfm.flags.ccm.reserved", FT_UINT8,
			BASE_DEC, NULL, 0x78, NULL, HFILL }
		},
		{ &hf_cfm_flags_Interval,
			{ "Interval Field", "cfm.flags.interval", FT_UINT8,
			BASE_DEC, VALS(CCM_IntervalFieldEncoding), 0x07, NULL, HFILL }
		},
		{ &hf_cfm_first_tlv_offset,
			{ "First TLV Offset", "cfm.first.tlv.offset", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_ccm_seq_number,
			{ "Sequence Number", "cfm.ccm.seq.num", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_ccm_ma_ep_id,
			{ "Maintenance Association End Point Identifier", "cfm.ccm.ma.ep.id",
			 FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_ccm_maid,
			{ "Maintenance Association Identifier", "cfm.ccm.maid", FT_NONE,
			 BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_maid_md_name_format,
			{ "MD Name Format", "cfm.maid.md.name.format", FT_UINT8,
			BASE_DEC, VALS(mdnameformattypes), 0x0, NULL, HFILL }
		},
		{ &hf_cfm_maid_md_name_length,
			{ "MD Name Length", "cfm.maid.md.name.length", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_maid_md_name_string,
			{ "MD Name", "cfm.maid.md.name", FT_STRING,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_maid_md_name_hex,
			{ "MD Name", "cfm.maid.md.name", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_maid_ma_name_format,
			{ "Short MA Name Format", "cfm.maid.ma.name.format", FT_UINT8,
			BASE_DEC, VALS(manameformattypes), 0x0, NULL, HFILL }
		},
		{ &hf_cfm_maid_ma_name_length,
			{ "Short MA Name Length", "cfm.maid.ma.name.length", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_maid_ma_name_string,
			{ "Short MA Name", "cfm.maid.ma.name", FT_STRING,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_maid_ma_name_hex,
			{ "Short MA Name", "cfm.maid.ma.name", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_maid_padding,
			{ "0 Padding", "cfm.ccm.maid.padding", FT_NONE,
			 BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cfm_ccm_itu_t_y1731,
			{ "Defined by ITU-T Y.1731", "cfm.ccm.itu.t.y1731", FT_NONE,
			 BASE_NONE, NULL, 0x0, NULL, HFILL }
		},

		/* CFM LBM*/
		{ &hf_cfm_lbm_pdu,
			{ "CFM LBM PDU", "cfm.lbm.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL	}
		},
		{ &hf_cfm_lb_transaction_id,
			{ "Loopback Transaction Identifier", "cfm.lb.transaction.id", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL	}
		},

		/* CFM LBR*/
		{ &hf_cfm_lbr_pdu,
			{ "CFM LBR PDU", "cfm.lbr.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL	}
		},

		/* CFM LTM*/
		{ &hf_cfm_ltm_pdu,
			{ "CFM LTM PDU", "cfm.ltm.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL	}
		},
		{ &hf_cfm_flags_UseFDBonly,
			{ "RDI", "cfm.flags.usefdbonly", FT_UINT8,
			BASE_DEC, NULL, 0x80, NULL, HFILL }
		},
		{ &hf_cfm_flags_ltm_Reserved,
			{ "Reserved", "cfm.flags.ltm.reserved", FT_UINT8,
			BASE_DEC, NULL, 0x7F, NULL, HFILL }
		},
		{ &hf_cfm_lt_transaction_id,
			{ "Linktrace Transaction Identifier", "cfm.lt.transaction.id", FT_UINT32,
			BASE_DEC, NULL, 0x0, NULL, HFILL	}
		},
		{ &hf_cfm_lt_ttl,
			{ "Linktrace TTL", "cfm.lt.ttl", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL	}
		},
		{ &hf_cfm_ltm_orig_addr,
			{ "Linktrace Message: Original Address", "cfm.ltm.orig.addr", FT_ETHER,
			BASE_NONE, NULL, 0x0, NULL, HFILL	}
		},
		{ &hf_cfm_ltm_targ_addr,
			{ "Linktrace Message:   Target Address", "cfm.ltm.targ.addr", FT_ETHER,
			BASE_NONE, NULL, 0x0, NULL, HFILL	}
		},

		/* CFM LTR*/
		{ &hf_cfm_ltr_pdu,
			{ "CFM LTR PDU", "cfm.ltr.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL	}
		},
		{ &hf_cfm_flags_FwdYes,
			{ "FwdYes", "cfm.flags.fwdyes", FT_UINT8,
			BASE_DEC, NULL, 0x40, NULL, HFILL }
		},
		{ &hf_cfm_flags_TerminalMEP,
			{ "TerminalMEP", "cfm.flags.ltr.terminalmep", FT_UINT8,
			BASE_DEC, NULL, 0x20, NULL, HFILL }
		},
		{ &hf_cfm_flags_ltr_Reserved,
			{ "Reserved", "cfm.flags.ltr.reserved", FT_UINT8,
			BASE_DEC, NULL, 0x1F, NULL, HFILL }
		},
		{ &hf_cfm_ltr_relay_action,
			{ "Linktrace Reply Relay Action", "cfm.ltr.relay.action", FT_UINT8,
			BASE_DEC, VALS(relayactiontypes), 0x0, NULL, HFILL}
		},

		/* CFM AIS*/
		{ &hf_cfm_ais_pdu,
			{ "CFM AIS PDU", "cfm.ais.pdu", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL	}
		},
		{ &hf_cfm_flags_ais_lck_Reserved,
			{ "Reserved", "cfm.flags.reserved", FT_UINT8,
			BASE_DEC, NULL, 0xF8, NULL, HFILL }
		},
		{ &hf_cfm_flags_ais_lck_Period,
			{ "Period", "cfm.flags.period", FT_UINT8,
			BASE_DEC, VALS(aislckperiodtypes), 0x07, NULL, HFILL }
		},

		/******************************* TLVs ****************************/
		{ &hf_cfm_all_tlvs,
			{ "CFM TLVs", "cfm.all.tlvs", FT_NONE,
			BASE_NONE, NULL, 0x0, NULL, HFILL	}
		},
		{ &hf_cfm_tlv_type,
			{ "TLV Type", "cfm.tlv.type", FT_UINT8,
			BASE_DEC, VALS(tlvtypefieldvalues), 0x0, NULL, HFILL}
		},
		{ &hf_cfm_tlv_length,
			{ "TLV Length", "cfm.tlv.length", FT_UINT16,
			BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
				/* Sender ID TLV */
		{ &hf_tlv_chassis_id_length,
			{ "Chassis ID Length", "cfm.tlv.chassis.id.length", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{ &hf_tlv_chassis_id_subtype,
			{ "Chassis ID Sub-type", "cfm.tlv.chassis.id.subtype", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{ &hf_tlv_chassis_id,
			{ "Chassis ID", "cfm.tlv.chassis.id", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{ &hf_tlv_ma_domain_length,
			{ "Management Address Domain Length", "cfm.tlv.ma.domain.length", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{ &hf_tlv_ma_domain,
			{ "Management Address Domain", "cfm.tlv.ma.domain", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{ &hf_tlv_management_addr_length,
			{ "Management Address Length", "cfm.tlv.management.addr.length", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{ &hf_tlv_management_addr,
			{ "Management Address", "cfm.tlv.management.addr", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL}
		},

				/* Port Status TLV */
		{ &hf_tlv_port_status_value,
			{ "Port Status value", "cfm.tlv.port.status.value", FT_UINT8,
			BASE_DEC, VALS(portstatTLVvalues), 0x0, NULL, HFILL}
		},

				/* Data TLV */
		{ &hf_tlv_data_value,
			{ "Data Value", "cfm.tlv.data.value", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL}
		},

				/* Interface status TLV */
		{ &hf_tlv_interface_status_value,
			{ "Interface Status value", "cfm.tlv.port.interface.value", FT_UINT8,
			BASE_DEC, VALS(interfacestatTLVvalues), 0x0, NULL, HFILL}
		},

				/* Reply Ingress TLV */
		{ &hf_tlv_reply_ingress_action,
			{ "Ingress Action", "cfm.tlv.reply.ingress.action", FT_UINT8,
			BASE_DEC, VALS(replyingressTLVvalues), 0x0, NULL, HFILL}
		},
		{ &hf_tlv_reply_ingress_mac_address,
			{ "Ingress MAC address", "cfm.tlv.reply.ingress.mac.address", FT_ETHER,
			BASE_NONE, NULL, 0x0, NULL, HFILL	}
		},
		{ &hf_tlv_reply_ing_egr_portid_length,
			{ "Chassis ID Length", "cfm.tlv.chassis.id.length", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{ &hf_tlv_reply_ing_egr_portid_subtype,
			{ "Chassis ID Sub-type", "cfm.tlv.chassis.id.subtype", FT_UINT8,
			BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{ &hf_tlv_reply_ing_egr_portid,
			{ "Chassis ID", "cfm.tlv.chassis.id", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL}
		},

				/* Reply Egress TLV */
		{ &hf_tlv_reply_egress_action,
			{ "Egress Action", "cfm.tlv.reply.egress.action", FT_UINT8,
			BASE_DEC, VALS(replyegressTLVvalues), 0x0, NULL, HFILL}
		},
		{ &hf_tlv_reply_egress_mac_address,
			{ "Egress MAC address", "cfm.tlv.reply.egress.mac.address", FT_ETHER,
			BASE_NONE, NULL, 0x0, NULL, HFILL	}
		},

				/* LTM Egress Identifier TLV */
		{ &hf_tlv_ltm_egress_id_mac,
			{ "Egress Identifier - MAC of LT Initiator/Responder", "cfm.tlv.ltm.egress.id", FT_ETHER,
			BASE_NONE, NULL, 0x0, NULL, HFILL	}
		},
		{ &hf_tlv_ltm_egress_id_unique_identifier,
			{ "Egress Identifier - Unique Identifier", "cfm.tlv.ltm.egress.id", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL	}
		},

				/* LTR Egress Identifier TLV */
		{ &hf_tlv_ltr_egress_last_id,
			{ "Last Egress Identifier", "cfm.tlv.ltr.egress.last.id", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL	}
		},
		{ &hf_tlv_ltr_egress_next_id,
			{ "Next Egress Identifier", "cfm.tlv.ltr.egress.next.id", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL	}
		},

				/* Organization-Specific TLV */
		{ &hf_tlv_org_spec_oui,
			{ "OUI", "cfm.tlv.org.spec.oui", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL	}
		},
		{ &hf_tlv_org_spec_subtype,
			{ "Sub-Type", "cfm.tlv.org.spec.subtype", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL	}
		},
		{ &hf_tlv_org_spec_value,
			{ "Value", "cfm.tlv.org.spec.value", FT_BYTES,
			BASE_NONE, NULL, 0x0, NULL, HFILL	}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_cfm,
		&ett_cfm_ccm,
		&ett_cfm_flags,
		&ett_cfm_ccm_maid,
		&ett_cfm_lbm,
		&ett_cfm_lbr,
		&ett_cfm_ltm,
		&ett_cfm_ltr,
		&ett_cfm_ais,
		&ett_cfm_all_tlvs,
		&ett_cfm_tlv
	};

	proto_cfm = proto_register_protocol (
		"CFM EOAM 802.1ag/ITU Protocol", /* name */
		"CFM", /* short name */
		"cfm" /* abbrev */
		);

	register_dissector("cfm", dissect_cfm, proto_cfm);

	proto_register_field_array(proto_cfm, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}

/* Register CFM OEAM protocol handler */
void proto_reg_handoff_cfm(void)
{
	static int initialized=FALSE;
	if (!initialized) {
		cfm_handle = create_dissector_handle(dissect_cfm, proto_cfm);
		dissector_add("ethertype", ETHERTYPE_CFM, cfm_handle);
	}
}

/* CFM EOAM sub-protocol dissectors: CCM, LBM, LBR, LTM, LTR */
static int dissect_cfm_ccm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	gint maid_offset = 0;
	gint padding_length = 0;

	guint8 cfm_maid_md_name_format = 0;
	guint8 cfm_maid_md_name_length = 0;
	guint8 cfm_maid_ma_name_format = 0;
	guint8 cfm_maid_ma_name_length = 0;

	proto_item *ti = NULL;
	proto_item *fi = NULL;
	proto_item *mi = NULL;
	proto_tree *cfm_ccm_tree = NULL;
	proto_tree *cfm_flag_tree = NULL;
	proto_tree *cfm_ccm_maid_tree = NULL;


	ti = proto_tree_add_item(tree, hf_cfm_ccm_pdu, tvb, offset, -1, FALSE);
	cfm_ccm_tree = proto_item_add_subtree(ti, ett_cfm_ccm);

	fi = proto_tree_add_item(cfm_ccm_tree, hf_cfm_flags, tvb, offset, 1, FALSE);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_RDI, tvb, offset, 1, FALSE);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_ccm_Reserved, tvb, offset, 1, FALSE);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_Interval, tvb, offset, 1, FALSE);

	offset += 1;
	proto_tree_add_item(cfm_ccm_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(cfm_ccm_tree, hf_cfm_ccm_seq_number, tvb, offset, 4, FALSE);
	offset += 4;
	proto_tree_add_item(cfm_ccm_tree, hf_cfm_ccm_ma_ep_id, tvb, offset, 2, FALSE);
	offset += 2;

	mi = proto_tree_add_item(cfm_ccm_tree, hf_cfm_ccm_maid, tvb, offset, 48, FALSE);
	cfm_ccm_maid_tree = proto_item_add_subtree(mi, ett_cfm_ccm_maid);
	maid_offset = offset;
	proto_tree_add_item(cfm_ccm_maid_tree, hf_cfm_maid_md_name_format, tvb, maid_offset, 1, FALSE);
	cfm_maid_md_name_format = tvb_get_guint8(tvb, maid_offset);
	maid_offset += 1;
	if (cfm_maid_md_name_format != 1) {
		proto_tree_add_item(cfm_ccm_maid_tree, hf_cfm_maid_md_name_length,
			       	tvb, maid_offset, 1, FALSE);
		cfm_maid_md_name_length = tvb_get_guint8(tvb, maid_offset);
		maid_offset += 1;
		if (cfm_maid_md_name_length) {
			if (cfm_maid_md_name_format == 3) {
				proto_tree_add_item(cfm_ccm_maid_tree, hf_cfm_maid_md_name_hex,  
					tvb, maid_offset, cfm_maid_md_name_length, FALSE);
			} else {
				proto_tree_add_item(cfm_ccm_maid_tree, hf_cfm_maid_md_name_string,  
					tvb, maid_offset, cfm_maid_md_name_length, FALSE);
			}
			maid_offset += cfm_maid_md_name_length;
		}
	}
	proto_tree_add_item(cfm_ccm_maid_tree, hf_cfm_maid_ma_name_format, tvb, maid_offset, 1, FALSE);
	cfm_maid_ma_name_format = tvb_get_guint8(tvb, maid_offset);
	maid_offset += 1;
	proto_tree_add_item(cfm_ccm_maid_tree, hf_cfm_maid_ma_name_length, tvb, maid_offset, 1, FALSE);
	cfm_maid_ma_name_length = tvb_get_guint8(tvb, maid_offset);
	maid_offset += 1;
	if (cfm_maid_ma_name_format == 2) {
		proto_tree_add_item(cfm_ccm_maid_tree, hf_cfm_maid_ma_name_string,  
			tvb, maid_offset, cfm_maid_ma_name_length, FALSE);
	} else {
		proto_tree_add_item(cfm_ccm_maid_tree, hf_cfm_maid_ma_name_hex,  
			tvb, maid_offset, cfm_maid_ma_name_length, FALSE);
	}
	maid_offset += cfm_maid_ma_name_length;
	offset += 48;
	if (offset > maid_offset) {
		padding_length = offset - maid_offset;
		proto_tree_add_item(cfm_ccm_maid_tree, hf_cfm_maid_padding,  
			tvb, maid_offset, padding_length, FALSE);
	}

	proto_tree_add_item(cfm_ccm_tree, hf_cfm_ccm_itu_t_y1731, tvb, offset, 16, FALSE);
	offset += 16;
	return offset;
}

static int dissect_cfm_lbm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti = NULL;
	proto_tree *cfm_lbm_tree = NULL;

	ti = proto_tree_add_item(tree, hf_cfm_lbm_pdu, tvb, offset, -1, FALSE);
	cfm_lbm_tree = proto_item_add_subtree(ti, ett_cfm_lbm);

	proto_tree_add_item(cfm_lbm_tree, hf_cfm_flags, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(cfm_lbm_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(cfm_lbm_tree, hf_cfm_lb_transaction_id, tvb, offset, 4, FALSE);
	offset += 4;
	return offset;
}

static int dissect_cfm_lbr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti = NULL;
	proto_tree *cfm_lbr_tree = NULL;

	ti = proto_tree_add_item(tree, hf_cfm_lbr_pdu, tvb, offset, -1, FALSE);
	cfm_lbr_tree = proto_item_add_subtree(ti, ett_cfm_lbr);

	proto_tree_add_item(cfm_lbr_tree, hf_cfm_flags, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(cfm_lbr_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(cfm_lbr_tree, hf_cfm_lb_transaction_id, tvb, offset, 4, FALSE);
	offset += 4;
	return offset;
}

static int dissect_cfm_ltm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti = NULL;
	proto_item *fi = NULL;
	proto_tree *cfm_ltm_tree = NULL;
	proto_tree *cfm_flag_tree = NULL;

	ti = proto_tree_add_item(tree, hf_cfm_ltm_pdu, tvb, offset, -1, FALSE);
	cfm_ltm_tree = proto_item_add_subtree(ti, ett_cfm_ltm);

	fi = proto_tree_add_item(cfm_ltm_tree, hf_cfm_flags, tvb, offset, 1, FALSE);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_UseFDBonly, tvb, offset, 1, FALSE);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_ltm_Reserved, tvb, offset, 1, FALSE);
	offset += 1;

	proto_tree_add_item(cfm_ltm_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(cfm_ltm_tree, hf_cfm_lt_transaction_id, tvb, offset, 4, FALSE);
	offset += 4;
	proto_tree_add_item(cfm_ltm_tree, hf_cfm_lt_ttl, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(cfm_ltm_tree, hf_cfm_ltm_orig_addr, tvb, offset, 6, FALSE);
	offset += 6;
	proto_tree_add_item(cfm_ltm_tree, hf_cfm_ltm_targ_addr, tvb, offset, 6, FALSE);
	offset += 6;
	return offset;
}

static int dissect_cfm_ltr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti = NULL;
	proto_item *fi = NULL;
	proto_tree *cfm_ltr_tree = NULL;
	proto_tree *cfm_flag_tree = NULL;

	ti = proto_tree_add_item(tree, hf_cfm_ltr_pdu, tvb, offset, -1, FALSE);
	cfm_ltr_tree = proto_item_add_subtree(ti, ett_cfm_ltr);

	fi = proto_tree_add_item(cfm_ltr_tree, hf_cfm_flags, tvb, offset, 1, FALSE);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_UseFDBonly, tvb, offset, 1, FALSE);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_FwdYes, tvb, offset, 1, FALSE);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_TerminalMEP, tvb, offset, 1, FALSE);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_ltr_Reserved, tvb, offset, 1, FALSE);
	offset += 1;

	proto_tree_add_item(cfm_ltr_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(cfm_ltr_tree, hf_cfm_lt_transaction_id, tvb, offset, 4, FALSE);
	offset += 4;
	proto_tree_add_item(cfm_ltr_tree, hf_cfm_lt_ttl, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(cfm_ltr_tree, hf_cfm_ltr_relay_action, tvb, offset, 1, FALSE);
	offset += 1;
	return offset;
}

static int dissect_cfm_ais(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_item *ti = NULL;
	proto_item *fi = NULL;
	proto_tree *cfm_ais_tree = NULL;
	proto_tree *cfm_flag_tree = NULL;

	ti = proto_tree_add_item(tree, hf_cfm_ais_pdu, tvb, offset, -1, FALSE);
	cfm_ais_tree = proto_item_add_subtree(ti, ett_cfm_ais);

	fi = proto_tree_add_item(cfm_ais_tree, hf_cfm_flags, tvb, offset, 1, FALSE);
	cfm_flag_tree = proto_item_add_subtree(fi, ett_cfm_flags);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_ais_lck_Reserved, tvb, offset, 1, FALSE);
	proto_tree_add_item(cfm_flag_tree, hf_cfm_flags_ais_lck_Period, tvb, offset, 1, FALSE);
	offset += 1;

	proto_tree_add_item(cfm_ais_tree, hf_cfm_first_tlv_offset, tvb, offset, 1, FALSE);
	offset += 1;
	
	return offset;
}



/* Main CFM EOAM protocol dissector */
static void dissect_cfm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint offset = 0;
	gint cfm_tlv_offset = 0;
	gint tlv_header_modifier = 0;
	gint tlv_data_offset = 0;

	guint8 cfm_pdu_type = 0;
	guint8 cfm_tlv_type = 255;
	guint16 cfm_tlv_length = 0;
	guint8 tlv_chassis_id_length = 0;
	guint8 tlv_ma_domain_length = 0;
	guint8 tlv_management_addr_length = 0;
	guint8 tlv_reply_ingress_portid_length = 0;
	guint8 tlv_reply_egress_portid_length = 0;

	proto_item *ti = NULL;
	proto_item *fi = NULL;
	proto_tree *cfm_tree = NULL;
	proto_tree *cfm_all_tlvs_tree = NULL;
	proto_tree *cfm_tlv_tree = NULL;

        /* display the CFM protol name */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "CFM");
	}

	/* Clear out stuff in the info column */
	if (check_col(pinfo->cinfo,COL_INFO)) {
		col_clear(pinfo->cinfo,COL_INFO);
	}

	/* provide info column with CFM packet type (opcode)*/
	cfm_pdu_type = tvb_get_guint8(tvb, 1);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "Type %s",
		val_to_str(cfm_pdu_type, opcodetypenames, "Unknown (0x%02x)"));
	}

	if (tree) { /* we are being asked for details */


		/* isolate the payload of the packet */
		ti = proto_tree_add_item(tree, proto_cfm, tvb, 0, -1, FALSE);


		/* report type of CFM packet to base of dissection tree */
		proto_item_append_text(ti, ", Type %s",
			val_to_str(cfm_pdu_type, opcodetypenames, "Unknown (0x%02x)"));

		/* dissecting the common CFM header */
		cfm_tree = proto_item_add_subtree(ti, ett_cfm);	
		proto_tree_add_item(cfm_tree, hf_cfm_md_level, tvb, offset, 1, FALSE);
		proto_tree_add_item(cfm_tree, hf_cfm_version, tvb, offset, 1, FALSE);	
		offset += 1;
		proto_tree_add_item(cfm_tree, hf_cfm_opcode, tvb, offset, 1, FALSE);	
		offset += 1;

		switch(cfm_pdu_type) {
		case CCM:
			offset = dissect_cfm_ccm(tvb, pinfo, tree, offset);
			break;
		case LBM:
			offset = dissect_cfm_lbm(tvb, pinfo, tree, offset);
			break;
		case LBR:
			offset = dissect_cfm_lbr(tvb, pinfo, tree, offset);
			break;
		case LTM:
			offset = dissect_cfm_ltm(tvb, pinfo, tree, offset);
			break;
		case LTR:
			offset = dissect_cfm_ltr(tvb, pinfo, tree, offset);
			break;
		case AIS:
			offset = dissect_cfm_ais(tvb, pinfo, tree, offset);
		}

		/* Get the TLV offset and add the offset of the common CFM header*/
		cfm_tlv_offset = tvb_get_guint8(tvb, 3);
		cfm_tlv_offset += 4;

		/* Begin dissecting the TLV's */
		   /* the TLV offset should be the same as where the pdu left off or we have a problem */
		if ((cfm_tlv_offset == offset) && (cfm_tlv_offset > 4)) {
			ti = proto_tree_add_item(tree, hf_cfm_all_tlvs, tvb, cfm_tlv_offset, -1, FALSE);
			cfm_all_tlvs_tree = proto_item_add_subtree(ti, ett_cfm_all_tlvs);

			while (cfm_tlv_type != END_TLV)
			{
				cfm_tlv_type = tvb_get_guint8(tvb, cfm_tlv_offset);
				
				if (cfm_tlv_type == END_TLV) {
					tlv_header_modifier = 1;
					cfm_tlv_length = 0;
				} else {
					tlv_header_modifier = 3;
					cfm_tlv_length = tvb_get_ntohs(tvb, cfm_tlv_offset+1);
				}

				fi = proto_tree_add_text(cfm_all_tlvs_tree, tvb, cfm_tlv_offset, cfm_tlv_length+tlv_header_modifier,
					       "TLV: %s (t=%d,l=%d)", val_to_str(cfm_tlv_type, tlvtypefieldvalues, "Unknown (0x%02x)"),
					       cfm_tlv_type, cfm_tlv_length);
				cfm_tlv_tree = proto_item_add_subtree(fi, ett_cfm_tlv);

				proto_tree_add_item(cfm_tlv_tree, hf_cfm_tlv_type, tvb, cfm_tlv_offset, 1, FALSE);
				cfm_tlv_offset += 1;
				if  ((cfm_tlv_type != END_TLV) && (cfm_tlv_length != 0)) {
					proto_tree_add_item(cfm_tlv_tree, hf_cfm_tlv_length, tvb, cfm_tlv_offset, 2, FALSE);
					cfm_tlv_offset += 2;

					tlv_data_offset = cfm_tlv_offset;

					switch(cfm_tlv_type) {
					case SENDER_ID_TLV:
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_chassis_id_length,
							       	tvb, tlv_data_offset, 1, FALSE);
						tlv_chassis_id_length = tvb_get_guint8(tvb,tlv_data_offset);
						tlv_data_offset += 1;

						if (tlv_chassis_id_length > 0) {
							proto_tree_add_item(cfm_tlv_tree, hf_tlv_chassis_id_subtype,
								       	tvb, tlv_data_offset, 1, FALSE);
							tlv_data_offset += 1;
							proto_tree_add_item(cfm_tlv_tree, hf_tlv_chassis_id,
								       	tvb, tlv_data_offset, tlv_chassis_id_length, FALSE);
							tlv_data_offset += tlv_chassis_id_length;
						}

						proto_tree_add_item(cfm_tlv_tree, hf_tlv_ma_domain_length,
							       	tvb, tlv_data_offset, 1, FALSE);
						tlv_ma_domain_length = tvb_get_guint8(tvb,tlv_data_offset);
						tlv_data_offset += 1;
						if (tlv_ma_domain_length > 0) {
							proto_tree_add_item(cfm_tlv_tree, hf_tlv_ma_domain,
								       	tvb, tlv_data_offset, tlv_ma_domain_length, FALSE);
							tlv_data_offset += tlv_ma_domain_length;
						}

						proto_tree_add_item(cfm_tlv_tree, hf_tlv_management_addr_length,
							       	tvb, tlv_data_offset, 1, FALSE);
						tlv_management_addr_length = tvb_get_guint8(tvb,tlv_data_offset);
						tlv_data_offset += 1;
						if (tlv_management_addr_length > 0) {
							proto_tree_add_item(cfm_tlv_tree, hf_tlv_management_addr,
								       	tvb, tlv_data_offset, tlv_management_addr_length, FALSE);
							tlv_data_offset += tlv_management_addr_length;
						}						
						break;
					case PORT_STAT_TLV:
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_port_status_value,
							       	tvb, tlv_data_offset, 1, FALSE);
						tlv_data_offset += 1;
						break;
					case DATA_TLV:
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_data_value,
							       	tvb, tlv_data_offset, cfm_tlv_length, FALSE);
						tlv_data_offset += cfm_tlv_length;						
						break;
					case INTERF_STAT_TLV:
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_interface_status_value,
							       	tvb, tlv_data_offset, 1, FALSE);
						tlv_data_offset += 1;
						break;
					case REPLY_ING_TLV:
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ingress_action,
							       	tvb, tlv_data_offset, 1, FALSE);
						tlv_data_offset += 1;
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ingress_mac_address,
							       	tvb, tlv_data_offset, 6, FALSE);
						tlv_data_offset += 6;

						proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ing_egr_portid_length,
							       	tvb, tlv_data_offset, 1, FALSE);
						tlv_reply_ingress_portid_length = tvb_get_guint8(tvb,tlv_data_offset);
						tlv_data_offset += 1;

						if (tlv_reply_ingress_portid_length > 0) {
							proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ing_egr_portid_subtype,
								       	tvb, tlv_data_offset, 1, FALSE);
							tlv_data_offset += 1;
							proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ing_egr_portid,
								       	tvb, tlv_data_offset, tlv_reply_ingress_portid_length, FALSE);
							tlv_data_offset += tlv_reply_ingress_portid_length;
						}				
						break;
					case REPLY_EGR_TLV:
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_egress_action,
							       	tvb, tlv_data_offset, 1, FALSE);
						tlv_data_offset += 1;
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_egress_mac_address,
							       	tvb, tlv_data_offset, 6, FALSE);
						tlv_data_offset += 6;
					
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ing_egr_portid_length,
							       	tvb, tlv_data_offset, 1, FALSE);
						tlv_reply_egress_portid_length = tvb_get_guint8(tvb,tlv_data_offset);
						tlv_data_offset += 1;

						if (tlv_reply_egress_portid_length > 0) {
							proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ing_egr_portid_subtype,
								       	tvb, tlv_data_offset, 1, FALSE);
							tlv_data_offset += 1;
							proto_tree_add_item(cfm_tlv_tree, hf_tlv_reply_ing_egr_portid,
								       	tvb, tlv_data_offset, tlv_reply_egress_portid_length, FALSE);
							tlv_data_offset += tlv_reply_egress_portid_length;
						}			
						break;
					case LTM_EGR_ID_TLV:
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_ltm_egress_id_mac,
							       	tvb, tlv_data_offset, 6, FALSE);
						tlv_data_offset += 6;
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_ltm_egress_id_unique_identifier,
							       	tvb, tlv_data_offset, 2, FALSE);
						tlv_data_offset += 2;
						break;
					case LTR_EGR_ID_TLV:
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_ltr_egress_last_id,
							       	tvb, tlv_data_offset, 8, FALSE);
						tlv_data_offset += 8;
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_ltr_egress_next_id,
							       	tvb, tlv_data_offset, 8, FALSE);
						tlv_data_offset += 8;
						break;
					case ORG_SPEC_TLV:
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_org_spec_oui,
							       	tvb, tlv_data_offset, 3, FALSE);
						tlv_data_offset += 3;
						proto_tree_add_item(cfm_tlv_tree, hf_tlv_org_spec_subtype,
							       	tvb, tlv_data_offset, 1, FALSE);
						tlv_data_offset += 1;

						if (cfm_tlv_length > 0) {   
							proto_tree_add_item(cfm_tlv_tree, hf_tlv_org_spec_value,
							       	tvb, tlv_data_offset, cfm_tlv_length, FALSE);
							tlv_data_offset -= 4;
						}
						tlv_data_offset += cfm_tlv_length;
						

						break;
					}


					cfm_tlv_offset += cfm_tlv_length;
				}

				

			}
		}
		
	}

}

