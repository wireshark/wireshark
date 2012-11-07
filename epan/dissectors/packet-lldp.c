/* packet-lldp.c
 * Routines for LLDP dissection
 * By Juan Gonzalez <juan.gonzalez@pikatech.com>
 * Copyright 2005 MITEL
 *
 * July 2005
 * Modified by: Brian Bogora <brian_bogora@mitel.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/etypes.h>
#include <epan/oui.h>
#include <epan/afn.h>
#include <epan/addr_resolv.h>
#include "packet-lldp.h"

/* Sub Dissector Tables */
static dissector_table_t oui_unique_code_table;

/* Initialize the protocol and registered fields */
static int proto_lldp = -1;
static int hf_lldp_tlv_type = -1;
static int hf_lldp_tlv_len = -1;
static int hf_lldp_tlv_system_cap = -1;
static int hf_lldp_tlv_system_cap_other = -1;
static int hf_lldp_tlv_system_cap_repeater = -1;
static int hf_lldp_tlv_system_cap_bridge = -1;
static int hf_lldp_tlv_system_cap_wlan_access_pt = -1;
static int hf_lldp_tlv_system_cap_router = -1;
static int hf_lldp_tlv_system_cap_telephone = -1;
static int hf_lldp_tlv_system_cap_docsis_cable_device = -1;
static int hf_lldp_tlv_system_cap_station_only = -1;
static int hf_lldp_tlv_enable_system_cap = -1;
static int hf_lldp_tlv_enable_system_cap_other = -1;
static int hf_lldp_tlv_enable_system_cap_repeater = -1;
static int hf_lldp_tlv_enable_system_cap_bridge = -1;
static int hf_lldp_tlv_enable_system_cap_wlan_access_pt = -1;
static int hf_lldp_tlv_enable_system_cap_router = -1;
static int hf_lldp_tlv_enable_system_cap_telephone = -1;
static int hf_lldp_tlv_enable_system_cap_docsis_cable_device = -1;
static int hf_lldp_tlv_enable_system_cap_station_only = -1;
static int hf_chassis_id_subtype = -1;
static int hf_chassis_id = -1;
static int hf_chassis_id_mac = -1;
static int hf_chassis_id_ip4 = -1;
static int hf_chassis_id_ip6 = -1;
static int hf_port_id_subtype = -1;
static int hf_port_id_mac = -1;
static int hf_lldp_network_address_family = -1;
static int hf_port_id_ip4 = -1;
static int hf_port_id_ip6 = -1;
static int hf_time_to_live = -1;
static int hf_mgn_addr_ipv4 = -1;
static int hf_mgn_addr_ipv6 = -1;
static int hf_mgn_addr_hex = -1;
static int hf_mgn_obj_id = -1;
static int hf_org_spc_oui = -1;
static int hf_ieee_802_1_subtype = -1;
static int hf_ieee_802_1_port_and_vlan_id_flag = -1;
static int hf_ieee_802_1_port_and_vlan_id_flag_supported = -1;
static int hf_ieee_802_1_port_and_vlan_id_flag_enabled = -1;
static int hf_ieee_802_3_subtype = -1;
static int hf_ieee_802_3_mac_phy_auto_neg_status = -1;
static int hf_ieee_802_3_mac_phy_auto_neg_status_supported = -1;
static int hf_ieee_802_3_mac_phy_auto_neg_status_enabled = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_tfd = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_t = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_xfd = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_x = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_bpause = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_spause = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_apause = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_pause = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_t2fd = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_t2 = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_txfd = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_tx = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_t4 = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_10base_tfd = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_10base_t = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_other = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_tfd = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_t = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_xfd = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_x = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_bpause = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_spause = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_apause = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_pause = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_t2fd = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_t2 = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_txfd = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_tx = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_t4 = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_10base_tfd = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_10base_t = -1;
static int hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_other = -1;
static int hf_ieee_802_3_mdi_power_support = -1;
static int hf_ieee_802_3_mdi_power_support_port_class = -1;
static int hf_ieee_802_3_mdi_power_support_pse_power_support = -1;
static int hf_ieee_802_3_mdi_power_support_pse_power_enabled = -1;
static int hf_ieee_802_3_mdi_power_support_pse_pairs = -1;
static int hf_ieee_802_3_aggregation_status = -1;
static int hf_ieee_802_3_aggregation_status_cap = -1;
static int hf_ieee_802_3_aggregation_status_enabled = -1;
static int hf_ieee_802_1qbg_subtype = -1;
static int hf_ieee_802_1qbg_evb_support_caps = -1;
static int hf_ieee_802_1qbg_evb_support_caps_std = -1;
static int hf_ieee_802_1qbg_evb_support_caps_rr = -1;
static int hf_ieee_802_1qbg_evb_support_caps_rte = -1;
static int hf_ieee_802_1qbg_evb_support_caps_ecp = -1;
static int hf_ieee_802_1qbg_evb_support_caps_vdp = -1;
static int hf_ieee_802_1qbg_evb_configure_caps = -1;
static int hf_ieee_802_1qbg_evb_configure_caps_std = -1;
static int hf_ieee_802_1qbg_evb_configure_caps_rr = -1;
static int hf_ieee_802_1qbg_evb_configure_caps_rte = -1;
static int hf_ieee_802_1qbg_evb_configure_caps_ecp = -1;
static int hf_ieee_802_1qbg_evb_configure_caps_vdp = -1;
static int hf_media_tlv_subtype = -1;
static int hf_media_tlv_subtype_caps = -1;
static int hf_media_tlv_subtype_caps_llpd = -1;
static int hf_media_tlv_subtype_caps_network_policy = -1;
static int hf_media_tlv_subtype_caps_location_id = -1;
static int hf_media_tlv_subtype_caps_mdi_pse = -1;
static int hf_media_tlv_subtype_caps_mid_pd = -1;
static int hf_media_tlv_subtype_caps_inventory = -1;
static int hf_media_policy_flag = -1;
static int hf_media_tag_flag = -1;
static int hf_profinet_tlv_subtype = -1;
static int hf_profinet_class2_port_status = -1;
static int hf_profinet_class3_port_status = -1;
static int hf_profinet_class3_port_status_Fragmentation = -1;
static int hf_profinet_class3_port_status_reserved = -1;
static int hf_profinet_class3_port_status_PreambleLength = -1;
static int hf_profinet_port_rx_delay_local = -1;
static int hf_profinet_port_rx_delay_remote = -1;
static int hf_profinet_port_tx_delay_local = -1;
static int hf_profinet_port_tx_delay_remote = -1;
static int hf_profinet_cable_delay_local = -1;
static int hf_profinet_mrp_domain_uuid = -1;
static int hf_profinet_mrrt_port_status = -1;
static int hf_profinet_cm_mac = -1;
static int hf_profinet_master_source_address = -1;
static int hf_profinet_subdomain_uuid = -1;
static int hf_profinet_ir_data_uuid = -1;
static int hf_profinet_length_of_period_valid = -1;
static int hf_profinet_length_of_period_length = -1;
static int hf_profinet_red_period_begin_valid = -1;
static int hf_profinet_red_period_begin_offset = -1;
static int hf_profinet_orange_period_begin_valid = -1;
static int hf_profinet_orange_period_begin_offset = -1;
static int hf_profinet_green_period_begin_valid = -1;
static int hf_profinet_green_period_begin_offset = -1;
static int hf_cisco_subtype = -1;
static int hf_cisco_four_wire_power = -1;
static int hf_cisco_four_wire_power_poe = -1;
static int hf_cisco_four_wire_power_spare_pair_arch = -1;
static int hf_cisco_four_wire_power_req_spare_pair_poe = -1;
static int hf_cisco_four_wire_power_pse_spare_pair_poe = -1;
static int hf_unknown_subtype = -1;
static int hf_unknown_subtype_content = -1;

/* Initialize the subtree pointers */
static gint ett_lldp = -1;
static gint ett_chassis_id = -1;
static gint ett_port_id = -1;
static gint ett_time_to_live = -1;
static gint ett_end_of_lldpdu = -1;
static gint ett_port_description = -1;
static gint ett_system_name = -1;
static gint ett_system_cap = -1;
static gint ett_system_cap_summary = -1;
static gint ett_system_cap_enabled = -1;
static gint ett_management_address = -1;
static gint ett_unknown_tlv = -1;
static gint ett_org_spc_def =-1;
static gint ett_org_spc_ieee_802_1_1 = -1;
static gint ett_org_spc_ieee_802_1_2 = -1;
static gint ett_org_spc_ieee_802_1_3 = -1;
static gint ett_org_spc_ieee_802_1_4 = -1;

static gint ett_org_spc_ieee_802_3_1 = -1;
static gint ett_org_spc_ieee_802_3_2 = -1;
static gint ett_org_spc_ieee_802_3_3 = -1;
static gint ett_org_spc_ieee_802_3_4 = -1;

static gint ett_org_spc_media_1 = -1;
static gint ett_org_spc_media_2 = -1;
static gint ett_org_spc_media_3 = -1;
static gint ett_org_spc_media_4 = -1;
static gint ett_org_spc_media_5 = -1;
static gint ett_org_spc_media_6 = -1;
static gint ett_org_spc_media_7 = -1;
static gint ett_org_spc_media_8 = -1;
static gint ett_org_spc_media_9 = -1;
static gint ett_org_spc_media_10 = -1;
static gint ett_org_spc_media_11 = -1;

#if 0
static gint ett_org_spc_mediaClass_0 = -1;
static gint ett_org_spc_mediaClass_1 = -1;
static gint ett_org_spc_mediaClass_2 = -1;
static gint ett_org_spc_mediaClass_3 = -1;
static gint ett_org_spc_mediaClass_4 = -1;
#endif
static gint ett_org_spc_ProfinetSubTypes_1 = -1;
static gint ett_org_spc_ProfinetSubTypes_2 = -1;
static gint ett_org_spc_ProfinetSubTypes_3 = -1;
static gint ett_org_spc_ProfinetSubTypes_4 = -1;
static gint ett_org_spc_ProfinetSubTypes_5 = -1;
static gint ett_org_spc_ProfinetSubTypes_6 = -1;
static gint ett_org_spc_tlv = -1;
static gint ett_port_vlan_flags = -1;
static gint ett_802_3_flags = -1;
static gint ett_802_3_autoneg_advertised = -1;
static gint ett_802_3_power = -1;
static gint ett_802_3_aggregation = -1;
static gint ett_802_1qbg_capabilities_flags = -1;
static gint ett_media_capabilities = -1;
static gint ett_profinet_period = -1;
static gint ett_cisco_fourwire_tlv = -1;

static const value_string tlv_types[] = {
	{ END_OF_LLDPDU_TLV_TYPE, 			"End of LLDPDU"},
	{ CHASSIS_ID_TLV_TYPE,				"Chassis Id"},
	{ PORT_ID_TLV_TYPE,					"Port Id"},
	{ TIME_TO_LIVE_TLV_TYPE,			"Time to Live"},
	{ PORT_DESCRIPTION_TLV_TYPE,		"Port Description"},
	{ SYSTEM_NAME_TLV_TYPE,				"System Name"},
	{ SYSTEM_DESCRIPTION_TLV_TYPE,		"System Description"},
	{ SYSTEM_CAPABILITIES_TLV_TYPE,		"System Capabilities"},
	{ MANAGEMENT_ADDR_TLV_TYPE,			"Management Address"},
	{ ORGANIZATION_SPECIFIC_TLV_TYPE,	"Organization Specific"},
	{ 0, NULL}
};

static const value_string chassis_id_subtypes[] = {
	{ 0,	"Reserved"},
	{ 1,	"Chassis component"},
	{ 2,	"Interface alias"},
	{ 3,	"Port component"},
	{ 4, 	"MAC address"},
	{ 5,	"Network address"},
	{ 6,	"Interface name"},
	{ 7,	"Locally assigned"},
	{ 0, NULL}
};

static const value_string port_id_subtypes[] = {
	{ 0,	"Reserved"},
	{ 1,	"Interface alias"},
	{ 2,	"Port component"},
	{ 3, 	"MAC address"},
	{ 4,	"Network address"},
	{ 5,	"Interface name"},
	{ 6, 	"Agent circuit Id"},
	{ 7,	"Locally assigned"},
	{ 0, NULL}
};

static const value_string interface_subtype_values[] = {
	{ 1,	"Unknown"},
	{ 2,	"ifIndex"},
	{ 3, 	"System port number"},
	{ 0, NULL}
};

/* IEEE 802.1 Subtypes */
static const value_string ieee_802_1_subtypes[] = {
	{ 0x01,	"Port VLAN ID" },
	{ 0x02, "Port and Protocol VLAN ID" },
	{ 0x03, "VLAN Name" },
	{ 0x04, "Protocol Identity" },
	{ 0, NULL }
};

/* IEEE 802.3 Subtypes */
static const value_string ieee_802_3_subtypes[] = {
	{ 0x01,	"MAC/PHY Configuration/Status" },
	{ 0x02,	"Power Via MDI" },
	{ 0x03,	"Link Aggregation" },
	{ 0x04, "Maximum Frame Size" },
	{ 0, NULL }
};

/* Media Subtypes */
static const value_string media_subtypes[] = {
	{ 1,	"Media Capabilities" },
	{ 2, 	"Network Policy" },
	{ 3, 	"Location Identification" },
	{ 4, 	"Extended Power-via-MDI" },
	{ 5,	"Inventory - Hardware Revision" },
	{ 6,	"Inventory - Firmware Revision" },
	{ 7,	"Inventory - Software Revision" },
	{ 8,	"Inventory - Serial Number" },
	{ 9,	"Inventory - Manufacturer Name" },
	{ 10,	"Inventory - Model Name" },
	{ 11, 	"Inventory - Asset ID" },
	{ 0, NULL }
};

/* Media Class Values */
static const value_string media_class_values[] = {
	{ 0,	"Type Not Defined" },
	{ 1,	"Endpoint Class I" },
	{ 2,	"Endpoint Class II" },
	{ 3,	"Endpoint Class III" },
	{ 4,	"Network Connectivity" },
	{ 0, NULL }
};

/* Media Application Types */
static const value_string media_application_type[] = {
	{ 0,	"Reserved" },
	{ 1,	"Voice" },
	{ 2,	"Voice Signaling" },
	{ 3,	"Guest Voice" },
	{ 4,	"Guest Voice Signaling" },
	{ 5,	"Softphone Voice" },
	{ 6,	"Video Conferencing" },
	{ 7,	"Streaming Video" },
	{ 8,	"Video Signaling" },
	{ 0, NULL }
};

/* PROFINET subtypes */
static const value_string profinet_subtypes[] = {
	{ 1, "Measured Delay Values" },
	{ 2, "Port Status" },
	{ 3, "Alias" },
	{ 4, "MRP Port Status" },
	{ 5, "Chassis MAC" },
	{ 6, "PTCP Status" },
	{ 0, NULL }
};

/* Cisco Subtypes */
static const value_string cisco_subtypes[] = {
	{ 1, "Four-wire Power-via-MDI" },
	{ 0, NULL }
};

/* 802.3 Power Type */
static const value_string power_type_802_3[] = {
	{ 0,	"Type 2" },
	{ 1,	"Type 2" },
	{ 2,	"Type 1" },
	{ 3,	"Type 1" },
	{ 0, NULL }
};

static const true_false_string tfs_ieee_802_3_pse_pd = { "PSE", "PD" };
static const true_false_string tfs_unknown_defined = { "Unknown", "Defined" };

/* Power Type */
static const value_string media_power_type[] = {
	{ 0,	"PSE Device" },
	{ 1,	"PD Device" },
	{ 2,	"PSE Device" },
	{ 3,	"PD Device" },
	{ 0, NULL }
};

/* Power Priority */
static const value_string media_power_priority[] = {
	{ 0, 	"Unknown" },
	{ 1,	"Critical" },
	{ 2,	"High" },
	{ 3,	"Low" },
	{ 0, NULL }
};

/* Power Sources */
static const value_string media_power_pd_device[] = {
	{ 0,	"Unknown" },
	{ 1,	"PSE" },
	{ 2,	"Local" },
	{ 3,	"PSE and Local" },
	{ 0, NULL }
};
static const value_string media_power_pse_device[] = {
	{ 0,	"Unknown" },
	{ 1,	"Primary Power Source" },
	{ 2,	"Backup Power Source" },
	{ 0, NULL }
};

/* Location data format */
static const value_string location_data_format[] = {
	{ 0, 	"Invalid " },
	{ 1,	"Coordinate-based LCI" },
	{ 2,	"Civic Address LCI" },
	{ 3, 	"ECS ELIN" },
	{ 0, NULL }
};

/* Civic Address LCI - What field */
static const value_string civic_address_what_values[] = {
	{ 0,	"Location of the DHCP server" },
	{ 1,	"Location of the network element believed to be closest to the client" },
	{ 2,	"Location of the client"},
	{ 0, NULL}
};

/* Civic Address Type field */
static const value_string civic_address_type_values[] = {
	{ 0,	"Language" },
	{ 1,	"National subdivisions (province, state, etc)" },
	{ 2,	"County, parish, district" },
	{ 3,	"City, township" },
	{ 4,	"City division, borough, ward" },
	{ 5,	"Neighborhood, block" },
	{ 6,	"Street" },
	{ 16,	"Leading street direction" },
	{ 17,	"Trailing street suffix" },
	{ 18,	"Street suffix" },
	{ 19,	"House number" },
	{ 20,	"House number suffix" },
	{ 21,	"Landmark or vanity address" },
	{ 22,	"Additional location information" },
	{ 23,	"Name" },
	{ 24, 	"Postal/ZIP code" },
	{ 25,	"Building" },
	{ 26,	"Unit" },
	{ 27,	"Floor" },
	{ 28,	"Room number" },
	{ 29,	"Place type" },
	{ 128,	"Script" },
	{ 0, NULL }
};

/*
 * Define the text strings for the LLDP 802.3 MAC/PHY Configuration/Status
 * Operational MAU Type field.
 *
 * These values are taken from the DESCRIPTION field of the dot3MauType
 * objects defined in RFC 3636 (or subsequent revisions).
 */

static const value_string operational_mau_type_values[] = {
	{ 1,	"AUI - no internal MAU, view from AUI" },
	{ 2,	"10Base5 - thick coax MAU" },
	{ 3,	"Foirl - FOIRL MAU" },
	{ 4,	"10Base2 - thin coax MAU" },
	{ 5,	"10BaseT - UTP MAU" },
	{ 6,	"10BaseFP - passive fiber MAU" },
	{ 7,	"10BaseFB - sync fiber MAU" },
	{ 8,	"10BaseFL - async fiber MAU" },
	{ 9,	"10Broad36 - broadband DTE MAU" },
	{ 10,	"10BaseTHD - UTP MAU, half duplex mode" },
	{ 11,	"10BaseTFD - UTP MAU, full duplex mode" },
	{ 12,	"10BaseFLHD - async fiber MAU, half duplex mode" },
	{ 13,	"10BaseFLDF - async fiber MAU, full duplex mode" },
	{ 14,	"10BaseT4 - 4 pair category 3 UTP" },
	{ 15,	"100BaseTXHD - 2 pair category 5 UTP, half duplex mode" },
	{ 16,	"100BaseTXFD - 2 pair category 5 UTP, full duplex mode" },
	{ 17,	"100BaseFXHD - X fiber over PMT, half duplex mode" },
	{ 18,	"100BaseFXFD - X fiber over PMT, full duplex mode" },
	{ 19,	"100BaseT2HD - 2 pair category 3 UTP, half duplex mode" },
	{ 20,	"100BaseT2DF - 2 pair category 3 UTP, full duplex mode" },
	{ 21,	"1000BaseXHD - PCS/PMA, unknown PMD, half duplex mode" },
	{ 22,	"1000BaseXFD - PCS/PMA, unknown PMD, full duplex mode" },
	{ 23,	"1000BaseLXHD - Fiber over long-wavelength laser, half duplex mode" },
	{ 24,	"1000BaseLXFD - Fiber over long-wavelength laser, full duplex mode" },
	{ 25,	"1000BaseSXHD - Fiber over short-wavelength laser, half duplex mode" },
	{ 26,	"1000BaseSXFD - Fiber over short-wavelength laser, full duplex mode" },
	{ 27,	"1000BaseCXHD - Copper over 150-Ohm balanced cable, half duplex mode" },
	{ 28,	"1000BaseCXFD - Copper over 150-Ohm balanced cable, full duplex mode" },
	{ 29,	"1000BaseTHD - Four-pair Category 5 UTP, half duplex mode" },
	{ 30,	"1000BaseTFD - Four-pair Category 5 UTP, full duplex mode" },
	{ 31,	"10GigBaseX - X PCS/PMA, unknown PMD." },
	{ 32,	"10GigBaseLX4 - X fiber over WWDM optics" },
	{ 33,	"10GigBaseR - R PCS/PMA, unknown PMD." },
	{ 34,	"10GigBaseER - R fiber over 1550 nm optics" },
	{ 35,	"10GigBaseLR - R fiber over 1310 nm optics" },
	{ 36,	"10GigBaseSR - R fiber over 850 nm optics" },
	{ 37,	"10GigBaseW - W PCS/PMA, unknown PMD." },
	{ 38,	"10GigBaseEW - W fiber over 1550 nm optics" },
	{ 39,	"10GigBaseLW - W fiber over 1310 nm optics" },
	{ 40,	"10GigBaseSW - W fiber over 850 nm optics" },
	{ 0, NULL }
};

/* System Capabilities */
#define SYSTEM_CAPABILITY_OTHER 	0x0001
#define SYSTEM_CAPABILITY_REPEATER 	0x0002
#define SYSTEM_CAPABILITY_BRIDGE 	0x0004
#define SYSTEM_CAPABILITY_WLAN 		0x0008
#define SYSTEM_CAPABILITY_ROUTER 	0x0010
#define SYSTEM_CAPABILITY_TELEPHONE	0x0020
#define SYSTEM_CAPABILITY_DOCSIS 	0x0040
#define SYSTEM_CAPABILITY_STATION 	0x0080

/* Media Capabilities */
#define MEDIA_CAPABILITY_LLDP				0x0001
#define MEDIA_CAPABILITY_NETWORK_POLICY		0x0002
#define MEDIA_CAPABILITY_LOCATION_ID		0x0004
#define MEDIA_CAPABILITY_MDI_PSE			0x0008
#define MEDIA_CAPABILITY_MDI_PD				0x0010
#define MEDIA_CAPABILITY_INVENTORY			0x0020

/*
 * Define constants for the LLDP 802.3 MAC/PHY Configuration/Status
 * PMD Auto-Negotiation Advertised Capability field.
 * These values are taken from the ifMauAutoNegCapAdvertisedBits
 * object defined in RFC 3636.
 */

#define AUTONEG_OTHER			0x8000 /* bOther(0),        -- other or unknown */
#define AUTONEG_10BASE_T		0x4000 /* b10baseT(1),      -- 10BASE-T  half duplex mode */
#define AUTONEG_10BASET_FD		0x2000 /* b10baseTFD(2),    -- 10BASE-T  full duplex mode */
#define AUTONEG_100BASE_T4		0x1000 /* b100baseT4(3),    -- 100BASE-T4 */
#define AUTONEG_100BASE_TX		0x0800 /* b100baseTX(4),    -- 100BASE-TX half duplex mode */
#define AUTONEG_100BASE_TXFD	0x0400 /* b100baseTXFD(5),  -- 100BASE-TX full duplex mode */
#define AUTONEG_100BASE_T2		0x0200 /* b100baseT2(6),    -- 100BASE-T2 half duplex mode */
#define AUTONEG_100BASE_T2FD	0x0100 /* b100baseT2FD(7),  -- 100BASE-T2 full duplex mode */
#define AUTONEG_FDX_PAUSE		0x0080 /* bFdxPause(8),     -- PAUSE for full-duplex links */
#define AUTONEG_FDX_APAUSE		0x0040 /* bFdxAPause(9),    -- Asymmetric PAUSE for full-duplex links */
#define AUTONEG_FDX_SPAUSE		0x0020 /* bFdxSPause(10),   -- Symmetric PAUSE for full-duplex links */
#define AUTONEG_FDX_BPAUSE		0x0010 /* bFdxBPause(11),   -- Asymmetric and Symmetric PAUSE for full-duplex links */
#define AUTONEG_1000BASE_X		0x0008 /* b1000baseX(12),   -- 1000BASE-X, -LX, -SX, -CX half duplex mode */
#define AUTONEG_1000BASE_XFD	0x0004 /* b1000baseXFD(13), -- 1000BASE-X, -LX, -SX, -CX full duplex mode */
#define AUTONEG_1000BASE_T		0x0002 /* b1000baseT(14),   -- 1000BASE-T half duplex mode */
#define AUTONEG_1000BASE_TFD	0x0001 /* b1000baseTFD(15)  -- 1000BASE-T full duplex mode */

/* Some vendors interpreted the standard to invert the bitorder:
 * according to a IEEE ruling, this is now officially wrong.
 * See https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=1455
 * for all the gory details
 */

#define INV_AUTONEG_OTHER		0x0001 /* bOther(0),        -- other or unknown */
#define INV_AUTONEG_10BASE_T		0x0002 /* b10baseT(1),      -- 10BASE-T  half duplex mode */
#define INV_AUTONEG_10BASET_FD		0x0004 /* b10baseTFD(2),    -- 10BASE-T  full duplex mode */
#define INV_AUTONEG_100BASE_T4		0x0008 /* b100baseT4(3),    -- 100BASE-T4 */
#define INV_AUTONEG_100BASE_TX		0x0010 /* b100baseTX(4),    -- 100BASE-TX half duplex mode */
#define INV_AUTONEG_100BASE_TXFD	0x0020 /* b100baseTXFD(5),  -- 100BASE-TX full duplex mode */
#define INV_AUTONEG_100BASE_T2		0x0040 /* b100baseT2(6),    -- 100BASE-T2 half duplex mode */
#define INV_AUTONEG_100BASE_T2FD	0x0080 /* b100baseT2FD(7),  -- 100BASE-T2 full duplex mode */
#define INV_AUTONEG_FDX_PAUSE		0x0100 /* bFdxPause(8),     -- PAUSE for full-duplex links */
#define INV_AUTONEG_FDX_APAUSE		0x0200 /* bFdxAPause(9),    -- Asymmetric PAUSE for full-duplex links */
#define INV_AUTONEG_FDX_SPAUSE		0x0400 /* bFdxSPause(10),   -- Symmetric PAUSE for full-duplex links */
#define INV_AUTONEG_FDX_BPAUSE		0x0800 /* bFdxBPause(11),   -- Asymmetric and Symmetric PAUSE for full-duplex links */
#define INV_AUTONEG_1000BASE_X		0x1000 /* b1000baseX(12),   -- 1000BASE-X, -LX, -SX, -CX half duplex mode */
#define INV_AUTONEG_1000BASE_XFD	0x2000 /* b1000baseXFD(13), -- 1000BASE-X, -LX, -SX, -CX full duplex mode */
#define INV_AUTONEG_1000BASE_T		0x4000 /* b1000baseT(14),   -- 1000BASE-T half duplex mode */
#define INV_AUTONEG_1000BASE_TFD	0x8000 /* b1000baseTFD(15)  -- 1000BASE-T full duplex mode */

#define EVB_CAPA_STD		0x8000
#define EVB_CAPA_RR		0x4000

#define EVB_CAPA_RTE		0x0004
#define EVB_CAPA_ECP		0x0002
#define EVB_CAPA_VDP		0x0001

#define MAX_MAC_LEN	6


static const value_string profinet_port2_status_vals[] = {
	{ 0,	"OFF" },
	{ 1,	"SYNCDATA_LOADED" },
	{ 2,	"RTCLASS2_UP" },
	{ 3,	"Reserved" },
	/* all other bits reserved */
	{ 0,	NULL }
};

static const value_string profinet_port3_status_vals[] = {
	{ 0,	"OFF" },
	{ 1,	"IRDATA_LOADED" },
	{ 2,	"RTCLASS3_UP" },
	{ 3,	"RTCLASS3_DOWN" },
	{ 4,	"RTCLASS3_RUN" },
	/* all other bits reserved */
	{ 0,	NULL }
};

static const value_string profinet_port3_status_OnOff[] = {
	{ 0,	"OFF" },
	{ 1,	"ON" },
	{ 0,	NULL }
};

static const value_string profinet_port3_status_PreambleLength[] = {
	{ 0,	"Seven octets" },
	{ 1,	"One octet" },
	{ 0,	NULL }
};
static const value_string profinet_mrrt_port_status_vals[] = {
	{ 0,	"OFF" },
	{ 1,	"MRRT_CONFIGURED" },
	{ 2,	"MRRT_UP" },
	/* all other bits reserved */
	{ 0,	NULL }
};

/* Calculate Latitude and Longitude string */
/*
	Parameters:
		option = 0 -> Latitude
		option = 1 -> Longitude
*/
static gchar *
get_latitude_or_longitude(int option, guint64 value)
{
	guint64 tempValue = value;
	gboolean negativeNum = FALSE;
	guint32 integerPortion = 0;
	const char *direction;

	/* The latitude and longitude are 34 bit fixed point value consisting
	   of 9 bits of integer and 25 bits of fraction.
	   When option is equal to 0, positive numbers are represent a location
	   north of the equator and negative (2s complement) numbers are south of the equator.
	   When option is equal to 1, positive values are east of the prime
	   meridian and negative (2s complement) numbers are west of the prime meridian.
	*/

	if (value & G_GINT64_CONSTANT(0x0000000200000000))
	{
		/* Have a negative number (2s complement) */
		negativeNum = TRUE;

		tempValue = ~value;
		tempValue += 1;
	}

	/* Get the integer portion */
	integerPortion = (guint32)((tempValue & G_GINT64_CONSTANT(0x00000003FE000000)) >> 25);

	/* Calculate decimal portion (using 25 bits for fraction) */
	tempValue = (tempValue & G_GINT64_CONSTANT(0x0000000001FFFFFF))/33554432;

	if (option == 0)
	{
		/* Latitude - north/south directions */
		if (negativeNum)
			direction = "South";
		else
			direction = "North";
	}
	else
	{
		/* Longitude - east/west directions */
		if (negativeNum)
			direction = "West";
		else
			direction = "East";
	}

	return ep_strdup_printf("%u.%04" G_GINT64_MODIFIER "u degrees %s",
	    integerPortion, tempValue, direction);
}

/* Dissect Chassis Id TLV (Mandatory) */
static gint32
dissect_lldp_chassis_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset)
{
	guint8 tempType;
	guint16 tempShort;
	guint32 tempLen = 0;
	const char *strPtr=NULL;
	guint8 incorrectLen = 0;	/* incorrect length if 1 */
	guint32 ip_addr = 0;
	struct e_in6_addr ip6_addr;
	guint8 addr_family = 0;

	proto_tree	*chassis_tree = NULL;
	proto_item 	*tf = NULL;

	/* Get tlv type */
	tempShort = tvb_get_ntohs(tvb, offset);
	tempType = TLV_TYPE(tempShort);
	if (tempType != CHASSIS_ID_TLV_TYPE)
	{
		if (tree)
		{
			tf = proto_tree_add_text(tree, tvb, offset, 2, "Invalid Chassis ID (0x%02X)", tempType);
			chassis_tree = proto_item_add_subtree(tf, ett_chassis_id);
			proto_tree_add_text(chassis_tree, tvb, offset, 2, " Invalid Chassis ID (%u)", tempType);
		}

		return -1;
	}

	/* Get tlv length */
	tempLen = TLV_INFO_LEN(tempShort);
	if (tempLen < 2)
	{
		if (tree)
		{
			tf = proto_tree_add_text(tree, tvb, offset, 2, "Invalid Chassis ID Length (%u)", tempLen);
			chassis_tree = proto_item_add_subtree(tf, ett_chassis_id);
			proto_tree_add_item(chassis_tree, hf_lldp_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_text(chassis_tree, tvb, offset, 2, " Invalid Length: %u", tempLen);
		}

		return -1;
	}

	/* Get tlv subtype */
	tempType = tvb_get_guint8(tvb, (offset+2));

	switch (tempType)
	{
	case 4:	/* MAC address */
	{
		if (tempLen != 7)
		{
			incorrectLen = 1; 	/* Invalid length */
			break;
		}

		strPtr = tvb_ether_to_str(tvb, offset+3);

		break;
	}
	case 5:	/* Network address */
	{
		/* Get network address family */
		addr_family = tvb_get_guint8(tvb,offset+3);
		/* Check for IPv4 or IPv6 */
		switch(addr_family){
		case AFNUM_INET:
			if (tempLen == 6){
				ip_addr = tvb_get_ipv4(tvb, (offset+4));
				strPtr = ip_to_str((guint8 *)&ip_addr);
			}else{
				incorrectLen = 1; 	/* Invalid length */
			}
			break;
		case AFNUM_INET6:
			if  (tempLen == 18){
				tvb_get_ipv6(tvb, (offset+4), &ip6_addr);
				strPtr = ip6_to_str(&ip6_addr);
			}else{
				incorrectLen = 1; 	/* Invalid length */
			}
			break;
		default:
			strPtr = tvb_bytes_to_str(tvb, (offset+4), (tempLen-2));
			break;
		}
		break;
	}
	case 2:	/* Interface alias */
	case 6: /* Interface name */
	case 7:	/* Locally assigned */
	{
		if (tempLen > 256)
		{
			incorrectLen = 1; 	/* Invalid length */
			break;
		}

		strPtr = tvb_format_stringzpad(tvb, (offset+3), (tempLen-1));

		break;
	}
	case 1:	/* Chassis component */
	case 3:	/* Port component */
	{
		if (tempLen > 256)
		{
			incorrectLen = 1; 	/* Invalid length */
			break;
		}

		strPtr = tvb_bytes_to_str(tvb, (offset+3), (tempLen-1));
		break;
	}
	default:	/* Reserved types */
	{
		if (tempLen > 256)
		{
			incorrectLen = 1; 	/* Invalid length */
			break;
		}

		strPtr = "Reserved";

		break;
	}
	}

	if (incorrectLen == 1)
	{
		if (tree)
		{
			tf = proto_tree_add_text(tree, tvb, offset, 2, "Invalid Chassis ID Length (%u)", tempLen);
			chassis_tree = proto_item_add_subtree(tf, ett_chassis_id);
			proto_tree_add_item(chassis_tree, hf_lldp_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_text(chassis_tree, tvb, offset, 2, " Invalid Length: %u", tempLen);
			/* Get chassis id subtype */
			proto_tree_add_item(chassis_tree, hf_chassis_id_subtype, tvb, (offset+2), 1, ENC_BIG_ENDIAN);

		}

		return -1;
	}

	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO, "Chassis Id = %s ", strPtr);

	if (tree)
	{
		/* Set chassis tree */
		tf = proto_tree_add_text(tree, tvb, offset, (tempLen + 2), "Chassis Subtype = %s",
								val_to_str_const(tempType, chassis_id_subtypes, "Reserved" ));
		chassis_tree = proto_item_add_subtree(tf, ett_chassis_id);

		proto_tree_add_item(chassis_tree, hf_lldp_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(chassis_tree, hf_lldp_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);

		/* Get chassis id subtype */
		proto_tree_add_item(chassis_tree, hf_chassis_id_subtype, tvb, (offset+2), 1, ENC_BIG_ENDIAN);

		/* Get chassis id */
		switch (tempType)
		{
		case 4:	/* MAC address */
			proto_tree_add_item(chassis_tree, hf_chassis_id_mac, tvb, (offset+3), 6, ENC_NA);
			proto_item_append_text(tf, ", Id: %s", strPtr);
			break;
		case 5: /* Network address */
			proto_tree_add_item(chassis_tree, hf_lldp_network_address_family, tvb, offset+3, 1, ENC_BIG_ENDIAN);
			switch(addr_family){
			case AFNUM_INET:
				proto_tree_add_ipv4(chassis_tree, hf_chassis_id_ip4, tvb, (offset+4), 4, ip_addr);
				break;
			case AFNUM_INET6:
				proto_tree_add_ipv6(chassis_tree, hf_chassis_id_ip6, tvb, (offset+4), 16, ip6_addr.bytes);
				break;
			default:
				proto_tree_add_text(chassis_tree, tvb, (offset+4), (tempLen-2), "Chassis Id: %s", strPtr);
				break;
			}
			break;
		case 2:	/* Interface alias */
		case 6: /* Interface name */
		case 7:	/* Locally assigned */
			proto_tree_add_text(chassis_tree, tvb, (offset+3), (tempLen-1), "Chassis Id: %s", strPtr);
			proto_item_append_text(tf, ", Id: %s", strPtr);
			break;
		case 1:	/* Chassis component */
		case 3:	/* Port component */
			proto_tree_add_item(chassis_tree, hf_chassis_id, tvb, (offset+3), (tempLen-1), ENC_NA);
			break;
		}
	}

	return (tempLen + 2);
}

/* Dissect Port Id TLV (Mandatory) */
static gint32
dissect_lldp_port_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset)
{
	guint8 tempType;
	guint16 tempShort;
	guint32 tempLen = 0;
	const char *strPtr;
	guint32 ip_addr = 0;
	struct e_in6_addr ip6_addr;
	guint8 addr_family = 0;

	proto_tree	*port_tree = NULL;
	proto_item 	*tf = NULL;

	/* Get tlv type */
	tempShort = tvb_get_ntohs(tvb, offset);
	tempType = TLV_TYPE(tempShort);
	if (tempType != PORT_ID_TLV_TYPE)
		return -1;

	/* Get tlv length and subtype */
	tempLen = TLV_INFO_LEN(tempShort);
	tempType = tvb_get_guint8(tvb, (offset+2));

	/* Get port id */
	switch (tempType)
	{
	case 3:	/* MAC address */
	{
		if (tempLen != 7)
			return -1; 	/* Invalid port id */

		strPtr = tvb_ether_to_str(tvb, offset+3);

		break;
	}
	case 4:	/* Network address */
	{
		/* Get network address family */
		addr_family = tvb_get_guint8(tvb,offset+3);
		/* Check for IPv4 or IPv6 */
		switch(addr_family){
		case AFNUM_INET:
			if (tempLen == 6){
				ip_addr = tvb_get_ipv4(tvb, (offset+4));
				strPtr = ip_to_str((guint8 *)&ip_addr);
			}else{
				return -1;
			}
			break;
		case AFNUM_INET6:
			if  (tempLen == 18){
				tvb_get_ipv6(tvb, (offset+4), &ip6_addr);
				strPtr = ip6_to_str(&ip6_addr);
			}else{
				return -1;	/* Invalid chassis id */
			}
			break;
		default:
			strPtr = tvb_bytes_to_str(tvb, (offset+4), (tempLen-2));
			break;
		}
		break;
	}
	default:
	{
		strPtr = tvb_format_stringzpad(tvb, (offset+3), (tempLen-1));

		break;
	}
	}

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, "Port Id = %s ", strPtr);

	if (tree)
	{
		/* Set port tree */
		tf = proto_tree_add_text(tree, tvb, offset, (tempLen + 2), "Port Subtype = %s",
								val_to_str_const(tempType, port_id_subtypes, "Unknown" ));
		port_tree = proto_item_add_subtree(tf, ett_port_id);

		proto_tree_add_item(port_tree, hf_lldp_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(port_tree, hf_lldp_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);

		/* Get port id subtype */
		proto_tree_add_item(port_tree, hf_port_id_subtype, tvb, (offset+2), 1, ENC_BIG_ENDIAN);

		/* Get port id */
		/*proto_tree_add_text(port_tree, tvb, (offset+3), (tempLen-1), "Port Id: %s", strPtr);*/
		switch (tempType)
		{
		case 3:	/* MAC address */
			proto_tree_add_item(port_tree, hf_port_id_mac, tvb, (offset+3), 6, ENC_NA);
			break;
		case 4: /* Network address */
			/* Network address
			 * networkAddress is an octet string that identifies a particular network address family
			 * and an associated network address that are encoded in network octet order.
 			 */
			/* Network address family */
			proto_tree_add_item(port_tree, hf_lldp_network_address_family, tvb, offset+3, 1, ENC_BIG_ENDIAN);
			switch(addr_family){
			case AFNUM_INET:
				proto_tree_add_ipv4(port_tree, hf_port_id_ip4, tvb, (offset+4), 4, ip_addr);
				break;
			case AFNUM_INET6:
				proto_tree_add_ipv6(port_tree, hf_port_id_ip6, tvb, (offset+4), 16, ip6_addr.bytes);
				break;
			default:
				proto_tree_add_text(port_tree, tvb, (offset+4), (tempLen-2), "Port Id: %s", strPtr);
				break;
			}
			break;
		default:
			proto_tree_add_text(port_tree, tvb, (offset+3), (tempLen-1), "Port Id: %s", strPtr);
			proto_item_append_text(tf, ", Id: %s", strPtr);
			break;
		}

	}

	return (tempLen + 2);
}

/* Dissect Time To Live TLV (Mandatory) */
static gint32
dissect_lldp_time_to_live(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset)
{
	guint8 tempType;
	guint16 tempShort;
	guint32 tempLen = 0;

	proto_tree	*time_to_live_tree = NULL;
	proto_item 	*tf = NULL;

	/* Get tlv type */
	tempShort = tvb_get_ntohs(tvb, offset);
	tempType = TLV_TYPE(tempShort);
	if (tempType != TIME_TO_LIVE_TLV_TYPE)
		return -1;

	/* Get tlv length and seconds field */
	tempLen = TLV_INFO_LEN(tempShort);
	tempShort = tvb_get_ntohs(tvb, (offset+2));

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, "TTL = %u ", tempShort);

	if (tree)
	{
		/* Set port tree */
		tf = proto_tree_add_text(tree, tvb, offset, (tempLen + 2), "Time To Live = %u sec", tempShort);
		time_to_live_tree = proto_item_add_subtree(tf, ett_time_to_live);

		proto_tree_add_item(time_to_live_tree, hf_lldp_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(time_to_live_tree, hf_lldp_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);

		/* Display time to live information */
		proto_tree_add_item(time_to_live_tree, hf_time_to_live, tvb, (offset+2), 2, ENC_BIG_ENDIAN);
	}

	return (tempLen + 2);
}

/* Dissect End of LLDPDU TLV (Mandatory) */
gint32
dissect_lldp_end_of_lldpdu(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset)
{
	guint16 tempLen;
	guint16 tempShort;

	proto_tree	*end_of_lldpdu_tree = NULL;
	proto_item 	*tf = NULL;

	/* Get tlv type and length */
	tempShort = tvb_get_ntohs(tvb, offset);

	/* Get tlv length */
	tempLen = TLV_INFO_LEN(tempShort);

	if (tree)
	{
		/* Set port tree */
		tf = proto_tree_add_text(tree, tvb, offset, (tempLen + 2), "End of LLDPDU");
		end_of_lldpdu_tree = proto_item_add_subtree(tf, ett_end_of_lldpdu);

		proto_tree_add_item(end_of_lldpdu_tree, hf_lldp_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(end_of_lldpdu_tree, hf_lldp_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	}

	return -1;	/* Force the lldp dissector to terminate */
}

/* Dissect Port Description TLV */
static gint32
dissect_lldp_port_desc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset)
{
	guint16 tempShort;
	guint32 tempLen = 0;
	const char *strPtr;

	proto_tree	*port_desc_tree = NULL;
	proto_item 	*tf = NULL;

	/* Get tlv type and length */
	tempShort = tvb_get_ntohs(tvb, offset);

	/* Get tlv length */
	tempLen = TLV_INFO_LEN(tempShort);

	if (tree)
	{
		strPtr = tvb_format_stringzpad(tvb, (offset+2), tempLen);

		/* Set port tree */
		tf = proto_tree_add_text(tree, tvb, offset, (tempLen + 2), "Port Description = %s", strPtr);
		port_desc_tree = proto_item_add_subtree(tf, ett_port_description);

		proto_tree_add_item(port_desc_tree, hf_lldp_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(port_desc_tree, hf_lldp_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);

		/* Display port description information */
		proto_tree_add_text(port_desc_tree, tvb, (offset+2), tempLen, "Port Description: %s",
		    strPtr);
	}

	return (tempLen + 2);
}

/* Dissect System Name and description TLV */
static gint32
dissect_lldp_system_name(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset)
{
	guint16 tempShort;
	guint32 tempLen = 0;
	guint8 tempType;
	const char *strPtr;

	proto_tree	*system_name_tree = NULL;
	proto_item 	*tf = NULL;

	/* Get tlv type and length */
	tempShort = tvb_get_ntohs(tvb, offset);
	tempType = TLV_TYPE(tempShort);

	/* Get tlv length */
	tempLen = TLV_INFO_LEN(tempShort);

	if (tree)
	{
		strPtr = tvb_format_stringzpad(tvb, (offset+2), tempLen);

		/* Set system name tree */
		if (tempType == SYSTEM_NAME_TLV_TYPE) {
			tf = proto_tree_add_text(tree, tvb, offset, (tempLen + 2), "System Name = %s", strPtr);
			if (check_col(pinfo->cinfo, COL_INFO))
				col_append_fstr(pinfo->cinfo, COL_INFO, "System Name = %s ", strPtr);
		} else
			tf = proto_tree_add_text(tree, tvb, offset, (tempLen + 2), "System Description = %s", strPtr);
		system_name_tree = proto_item_add_subtree(tf, ett_system_name);

		proto_tree_add_item(system_name_tree, hf_lldp_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(system_name_tree, hf_lldp_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);

		/* Display system name information */
		proto_tree_add_text(system_name_tree, tvb, (offset+2), tempLen, "%s = %s",
					((tempType == SYSTEM_NAME_TLV_TYPE) ? "System Name" : "System Description"),
					strPtr);
	}

	return (tempLen + 2);
}

/* Dissect System Capabilities TLV */
static gint32
dissect_lldp_system_capabilities(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset)
{
	guint16 tempShort;
	guint32 tempLen = 0;

	proto_tree	*system_capabilities_tree = NULL;
	proto_tree	*capabilities_summary_tree = NULL;
	proto_tree  *capabilities_enabled_tree = NULL;
	proto_item 	*tf = NULL;

	/* Get tlv type and length */
	tempShort = tvb_get_ntohs(tvb, offset);

	/* Get tlv length */
	tempLen = TLV_INFO_LEN(tempShort);

	if (tree)
	{
		/* Set system capabilities tree */
		tf = proto_tree_add_text(tree, tvb, offset, (tempLen + 2), "Capabilities");
		system_capabilities_tree = proto_item_add_subtree(tf, ett_system_cap);

		proto_tree_add_item(system_capabilities_tree, hf_lldp_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(system_capabilities_tree, hf_lldp_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);

		/* Display system capability information */
		tf = proto_tree_add_item(system_capabilities_tree, hf_lldp_tlv_system_cap, tvb, offset+2, 2, ENC_BIG_ENDIAN);
		capabilities_summary_tree = proto_item_add_subtree(tf, ett_system_cap_summary);

		/* Add capabilities to summary tree */
		proto_tree_add_item(capabilities_summary_tree, hf_lldp_tlv_system_cap_other, tvb, offset+2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(capabilities_summary_tree, hf_lldp_tlv_system_cap_repeater, tvb, offset+2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(capabilities_summary_tree, hf_lldp_tlv_system_cap_bridge, tvb, offset+2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(capabilities_summary_tree, hf_lldp_tlv_system_cap_wlan_access_pt, tvb, offset+2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(capabilities_summary_tree, hf_lldp_tlv_system_cap_router, tvb, offset+2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(capabilities_summary_tree, hf_lldp_tlv_system_cap_telephone, tvb, offset+2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(capabilities_summary_tree, hf_lldp_tlv_system_cap_docsis_cable_device, tvb, offset+2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(capabilities_summary_tree, hf_lldp_tlv_system_cap_station_only, tvb, offset+2, 2, ENC_BIG_ENDIAN);

		/* Get enabled summary */

		/* Display system capability information */
		tf = proto_tree_add_item(system_capabilities_tree, hf_lldp_tlv_enable_system_cap, tvb, offset+4, 2, ENC_BIG_ENDIAN);
		capabilities_enabled_tree = proto_item_add_subtree(tf, ett_system_cap_enabled);
		proto_tree_add_item(capabilities_enabled_tree, hf_lldp_tlv_enable_system_cap_other, tvb, offset+4, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(capabilities_enabled_tree, hf_lldp_tlv_enable_system_cap_repeater, tvb, offset+4, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(capabilities_enabled_tree, hf_lldp_tlv_enable_system_cap_bridge, tvb, offset+4, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(capabilities_enabled_tree, hf_lldp_tlv_enable_system_cap_wlan_access_pt, tvb, offset+4, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(capabilities_enabled_tree, hf_lldp_tlv_enable_system_cap_router, tvb, offset+4, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(capabilities_enabled_tree, hf_lldp_tlv_enable_system_cap_telephone, tvb, offset+4, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(capabilities_enabled_tree, hf_lldp_tlv_enable_system_cap_docsis_cable_device, tvb, offset+4, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(capabilities_enabled_tree, hf_lldp_tlv_enable_system_cap_station_only, tvb, offset+4, 2, ENC_BIG_ENDIAN);
	}

	return (tempLen + 2);
}

/* Dissect Management Address TLV */
static gint32
dissect_lldp_management_address(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset)
{
	guint16 tempShort;
	guint32 tempLen = 0;
	guint8  tempByte;
	guint8  stringLen = 0;
	guint32 tempOffset = offset;
	guint32 tempLong;

	proto_tree	*system_mgm_addr = NULL;
	proto_item 	*tf = NULL;

	/* Get tlv type and length */
	tempShort = tvb_get_ntohs(tvb, tempOffset);

	/* Get tlv length */
	tempLen = TLV_INFO_LEN(tempShort);

	if (tree)
	{
		/* Set system capabilities tree */
		tf = proto_tree_add_text(tree, tvb, tempOffset, (tempLen + 2), "Management Address");
		system_mgm_addr = proto_item_add_subtree(tf, ett_management_address);

		proto_tree_add_item(system_mgm_addr, hf_lldp_tlv_type, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(system_mgm_addr, hf_lldp_tlv_len, tvb, tempOffset, 2, ENC_BIG_ENDIAN);

		tempOffset += 2;

		/* Get management address string length */
		stringLen = tvb_get_guint8(tvb, tempOffset);
		proto_tree_add_text(system_mgm_addr, tvb, tempOffset, 1, "Address String Length: %u", stringLen);

		tempOffset++;

		/* Get management address subtype */
		tempByte = tvb_get_guint8(tvb, tempOffset);
		proto_tree_add_text(system_mgm_addr, tvb, tempOffset, 1, "Address Subtype: %s (%u)",
							val_to_str_const(tempByte, afn_vals, "Undefined"),
							tempByte);

		tempOffset++;

		/* Get address */
		switch (tempByte)
		{
		/* XXX - Should we throw an exception if stringLen doesn't match our address length? */
		case 1:		/* IPv4 */
			proto_tree_add_item(system_mgm_addr, hf_mgn_addr_ipv4, tvb, tempOffset, 4, ENC_BIG_ENDIAN);
			break;
		case 2:		/* IPv6 */
			proto_tree_add_item(system_mgm_addr, hf_mgn_addr_ipv6, tvb, tempOffset, 16, ENC_NA);
			break;
		default:
			proto_tree_add_item(system_mgm_addr, hf_mgn_addr_hex, tvb, tempOffset, (stringLen-1), ENC_NA);
			break;
		}

		tempOffset += (stringLen-1);

		/* Get interface numbering subtype */
		tempByte = tvb_get_guint8(tvb, tempOffset);
		proto_tree_add_text(system_mgm_addr, tvb, tempOffset, 1, "Interface Subtype: %s (%u)",
							val_to_str_const(tempByte, interface_subtype_values, "Undefined"),
							tempByte);

		tempOffset++;

		/* Get interface number */
		tempLong = tvb_get_ntohl(tvb, tempOffset);
		proto_tree_add_text(system_mgm_addr, tvb, tempOffset, 4, "Interface Number: %u", tempLong);

		tempOffset += 4;

		/* Get OID string length */
		stringLen = tvb_get_guint8(tvb, tempOffset);
		proto_tree_add_text(system_mgm_addr, tvb, tempOffset, 1, "OID String Length: %u", stringLen);

		if (stringLen > 0)
		{
			tempOffset++;

			/* Get OID identifier */
			proto_tree_add_item(system_mgm_addr, hf_mgn_obj_id, tvb, tempOffset, stringLen, ENC_NA);
		}
	}

	return (tempLen + 2);
}

/* Dissect IEEE 802.1 TLVs */
static void
dissect_ieee_802_1_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset)
{
	guint8 subType;
	guint8 tempByte;
	guint16 tempShort;
	guint32 tempOffset = offset;

	proto_tree	*vlan_flags_tree = NULL;
	proto_item 	*tf = NULL;

	/* Get subtype */
	subType = tvb_get_guint8(tvb, tempOffset);

	if (tree)
		proto_tree_add_item(tree, hf_ieee_802_1_subtype, tvb, tempOffset, 1, ENC_BIG_ENDIAN);

	tempOffset++;

	switch (subType)
	{
	case 0x01:	/* Port VLAN ID */
	{
		/* Get port vland id */
		tempShort = tvb_get_ntohs(tvb, tempOffset);
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 2, "Port VLAN Identifier: %u (0x%04X)", tempShort, tempShort);

		break;
	}
	case 0x02:	/* Port and Protocol VLAN ID */
	{
		/* Get flags */
		if (tree)
		{
			tf = proto_tree_add_item(tree, hf_ieee_802_1_port_and_vlan_id_flag, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
			vlan_flags_tree = proto_item_add_subtree(tf, ett_port_vlan_flags);

			proto_tree_add_item(vlan_flags_tree, hf_ieee_802_1_port_and_vlan_id_flag_supported, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(vlan_flags_tree, hf_ieee_802_1_port_and_vlan_id_flag_enabled, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
		}

		tempOffset++;

		/* Get port and protocol vlan id */
		tempShort = tvb_get_ntohs(tvb, tempOffset);
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 2, "Port and Protocol VLAN Identifier: %u (0x%04X)", tempShort, tempShort);

		break;
	}
	case 0x03:	/* VLAN Name */
	{
		/* Get vlan id */
		tempShort = tvb_get_ntohs(tvb, tempOffset);
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 2, "VLAN Identifier: %u (0x%04X)", tempShort, tempShort);

		tempOffset += 2;

		/* Get vlan name length */
		tempByte = tvb_get_guint8(tvb, tempOffset);
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 1, "VLAN Name Length: %u", tempByte);

		tempOffset++;

		if (tempByte > 0)
		{
			if (tree)
				proto_tree_add_text(tree, tvb, tempOffset, tempByte, "VLAN Name: %s",
				    tvb_format_stringzpad(tvb, tempOffset, tempByte));
		}

		break;
	}
	case 0x04:	/* Protocol ID */
	{
		/* Get protocal id length */
		tempByte = tvb_get_guint8(tvb, tempOffset);
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 1, "Protocol Identity Length: %u", tempByte);

		tempOffset++;

		if (tempByte > 0)
		{
			if (tree)
				proto_tree_add_text(tree, tvb, tempOffset, tempByte, "Protocol Identity: %s",
					tvb_bytes_to_str(tvb, tempOffset, tempByte));
		}

		break;
	}
	}

	return;
}

/* Dissect IEEE 802.1Qbg TLVs */
static void
dissect_oui_default_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset)
{
	guint8 subType;
	subType = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_unknown_subtype, tvb, offset, 1, subType);
	proto_tree_add_item(tree, hf_unknown_subtype_content, tvb, (offset+1), -1, ENC_NA);
}

static void
dissect_ieee_802_1qbg_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset)
{
	guint8 subType;
	guint8 tempByte;
	guint16 tempShort;
	guint32 tempOffset = offset;

	proto_tree *evb_capabilities_subtree = NULL;

	proto_item *tf = NULL;
	subType = tvb_get_guint8(tvb, tempOffset);

	if (tree)
		proto_tree_add_item(tree, hf_ieee_802_1qbg_subtype, tvb, tempOffset, 1, ENC_BIG_ENDIAN);

	tempOffset++;

	switch (subType) {
		case 0x00:
			/* Get EVB capabilities */
			if (tree) {
				tf = proto_tree_add_item(tree, hf_ieee_802_1qbg_evb_support_caps, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
				evb_capabilities_subtree = proto_item_add_subtree(tf, ett_802_1qbg_capabilities_flags);

				proto_tree_add_item(evb_capabilities_subtree, hf_ieee_802_1qbg_evb_support_caps_std, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(evb_capabilities_subtree, hf_ieee_802_1qbg_evb_support_caps_rr, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(evb_capabilities_subtree, hf_ieee_802_1qbg_evb_support_caps_rte, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(evb_capabilities_subtree, hf_ieee_802_1qbg_evb_support_caps_ecp, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(evb_capabilities_subtree, hf_ieee_802_1qbg_evb_support_caps_vdp, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			}

			tempOffset += 2;

			if (tree) {
				tf = proto_tree_add_item(tree, hf_ieee_802_1qbg_evb_configure_caps, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
				evb_capabilities_subtree = proto_item_add_subtree(tf, ett_802_1qbg_capabilities_flags);

				proto_tree_add_item(evb_capabilities_subtree, hf_ieee_802_1qbg_evb_configure_caps_std, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(evb_capabilities_subtree, hf_ieee_802_1qbg_evb_configure_caps_rr, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(evb_capabilities_subtree, hf_ieee_802_1qbg_evb_configure_caps_rte, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(evb_capabilities_subtree, hf_ieee_802_1qbg_evb_configure_caps_ecp, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(evb_capabilities_subtree, hf_ieee_802_1qbg_evb_configure_caps_vdp, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			}

			tempOffset += 2;

			tempShort = tvb_get_ntohs(tvb, tempOffset);
			if (tree) {
				proto_tree_add_text(tree, tvb, tempOffset, 2, "supported no. of VSIs: %04u", tempShort);
			}

			tempOffset += 2;

			tempShort = tvb_get_ntohs(tvb, tempOffset);
			if (tree) {
				proto_tree_add_text(tree, tvb, tempOffset, 2, "configured no. of VSIs: %04u", tempShort);
			}

			tempOffset += 2;

			tempByte= tvb_get_guint8(tvb, tempOffset);
			if (tree) {
				proto_tree_add_text(tree, tvb, tempOffset, 1, "retransmission timer exponent: %02u", tempByte);
			}

			break;
	}

	return;
}


/* Dissect IEEE 802.3 TLVs */
static void
dissect_ieee_802_3_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset)
{
	guint8 subType;
	guint8 tempByte;
	guint16 tempShort;
	guint32 tempLong;
	guint32 tempOffset = offset;
	guint16 tlvLen = tvb_length(tvb)-offset;

	proto_tree	*mac_phy_flags = NULL;
	proto_tree	*autoneg_advertised_subtree = NULL;

	proto_item 	*tf = NULL;

	/* Get subtype */
	subType = tvb_get_guint8(tvb, tempOffset);

	if (tree)
		proto_tree_add_item(tree, hf_ieee_802_3_subtype, tvb, tempOffset, 1, ENC_BIG_ENDIAN);

	tempOffset++;

	switch (subType)
	{
	case 0x01:	/* MAC/PHY Configuration/Status */
	{
		/* Get auto-negotiation info */
		tempByte = tvb_get_guint8(tvb, tempOffset);
		if (tree)
		{
			tf = proto_tree_add_item(tree, hf_ieee_802_3_mac_phy_auto_neg_status, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
			mac_phy_flags = proto_item_add_subtree(tf, ett_802_3_flags);

			proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_mac_phy_auto_neg_status_supported, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_mac_phy_auto_neg_status_enabled, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
		}

		tempOffset++;

		/* Get pmd auto-negotiation advertised capability */
		if (tree)
		{
			tf = proto_tree_add_item(tree, hf_ieee_802_3_pmd_auto_neg_advertised_caps, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			autoneg_advertised_subtree = proto_item_add_subtree(tf, ett_802_3_autoneg_advertised);

			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_tfd, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_t, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_xfd, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_x, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_bpause, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_spause, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_apause, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_pause, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_t2fd, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_t2, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_txfd, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_tx, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_t4, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_10base_tfd, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_10base_t, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_other, tvb, tempOffset, 2, ENC_BIG_ENDIAN);

			tf = proto_tree_add_text(tree, tvb, tempOffset, 2, "Same in inverse (wrong) bitorder");
			autoneg_advertised_subtree = proto_item_add_subtree(tf, ett_802_3_autoneg_advertised);

			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_tfd, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_t, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_xfd, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_x, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_bpause, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_spause, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_apause, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_pause, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_t2fd, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_t2, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_txfd, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_tx, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_t4, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_10base_tfd, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_10base_t, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(autoneg_advertised_subtree, hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_other, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
		}

		tempOffset += 2;

		/* Get operational MAU type */
		tempShort = tvb_get_ntohs(tvb, tempOffset);
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 2, "Operational MAU Type: %s (0x%04X)",
							val_to_str_const(tempShort,operational_mau_type_values,"Unknown"),
							tempShort);

		tempOffset += 2;

		break;
	}
	case 0x02:	/* MDI Power Support */
	{
		const char *strPtr;

		/* Get MDI power support info */
		if (tree)
		{
			tf = proto_tree_add_item(tree, hf_ieee_802_3_mdi_power_support, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
			mac_phy_flags = proto_item_add_subtree(tf, ett_802_3_power);

			proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_mdi_power_support_port_class, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_mdi_power_support_pse_power_support, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_mdi_power_support_pse_power_enabled, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_mdi_power_support_pse_pairs, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
		}

		tempOffset++;

		/* Get PSE power pair */
		tempByte = tvb_get_guint8(tvb, tempOffset);
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 1, "PSE Power Pair: %u", tempByte);

		tempOffset++;

		/* Get power class */
		tempByte = tvb_get_guint8(tvb, tempOffset);
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 1, "Power Class: %u", tempByte);

		tempOffset++;

		if (tlvLen == 4)
			break;

		/* Get first byte */
		tempByte = tvb_get_guint8(tvb, tempOffset);

		/* Determine power type */
		subType = ((tempByte & 0xC0) >> 6);
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 1, "Power Type %s %s",
				val_to_str_const(subType, power_type_802_3, "Unknown"),
				val_to_str_const(subType, media_power_type, "Unknown"));

		/* Determine power source */
		switch (subType)
		{
		case 0:
		case 2:
		{
			subType = ((tempByte & 0x30) >> 4);
			strPtr = val_to_str_const(subType, media_power_pse_device, "Reserved");

			break;
		}
		case 1:
		case 3:
		{
			subType = ((tempByte & 0x30) >> 4);
			strPtr = val_to_str_const(subType, media_power_pd_device, "Reserved");

			break;
		}
		default:
		{
			strPtr = "Unknown";
			break;
		}
		}
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 1, "Power Source %s", strPtr);

		/* Determine power priority */
		subType = (tempByte & 0x0F);
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 1, "Power Priority %s",
				val_to_str_const(subType, media_power_priority, "Reserved"));

		tempOffset++;

		/* Power Value: 1 to 510 expected  */
		tempShort = tvb_get_ntohs(tvb, tempOffset);
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 2, "PD Requested Power Value: %u.%u Watt", tempShort/10, tempShort%10);

		tempOffset+=2;

		/* Power Value: 1 to 510 expected */
		tempShort = tvb_get_ntohs(tvb, tempOffset);
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 2, "PSE Allocated Power Value: %u.%u Watt", tempShort/10, tempShort%10);

		tempOffset+=2;

		break;
	}
	case 0x03:	/* Link Aggregation */
	{
		/* Get aggregation status */
		if (tree)
		{
			tf = proto_tree_add_item(tree, hf_ieee_802_3_aggregation_status, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
			mac_phy_flags = proto_item_add_subtree(tf, ett_802_3_aggregation);
			proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_aggregation_status_cap, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(mac_phy_flags, hf_ieee_802_3_aggregation_status_enabled, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
		}

		tempOffset++;

		/* Get aggregated port id */
		tempLong = tvb_get_ntohl(tvb, tempOffset);
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 4, "Aggregated Port Id: %u", tempLong);

		tempOffset += 4;

		break;
	}
	case 0x04:	/* Maximum Frame Size */
	{
		/* Get maximum frame size */
		tempShort = tvb_get_ntohs(tvb, tempOffset);
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 2, "Maximum Frame Size: %u", tempShort);

		tempOffset += 2;

		break;
	}
	}

	return;
}

/* Dissect Media TLVs */
static void
dissect_media_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset)
{
	guint32 tempOffset = offset;
	guint16 tlvLen = tvb_length(tvb)-offset;
	guint8 subType;
	guint16 tempShort;
	guint16 tempVLAN;
	guint8 tempByte;
	guint32 tempLong;
	const char *strPtr;
	guint32 LCI_Length;
	guint64 temp64bit = 0;

	proto_tree	*media_flags = NULL;
	proto_item 	*tf = NULL;
	/* Get subtype */
	subType = tvb_get_guint8(tvb, tempOffset);
	if (tree)
		proto_tree_add_item(tree, hf_media_tlv_subtype, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
	tempOffset++;
	tlvLen--;

	switch (subType)
	{
	case 1:		/* LLDP-MED Capabilities */
	{
		/* Get capabilities */
		if (tlvLen < 2)
		{
			proto_tree_add_text(tree, tvb, tempOffset, 0, "TLV too short");
			return;
		}
		if (tree)
		{
			tf = proto_tree_add_item(tree, hf_media_tlv_subtype_caps, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			media_flags = proto_item_add_subtree(tf, ett_media_capabilities);
			proto_tree_add_item(media_flags, hf_media_tlv_subtype_caps_llpd, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(media_flags, hf_media_tlv_subtype_caps_network_policy, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(media_flags, hf_media_tlv_subtype_caps_location_id, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(media_flags, hf_media_tlv_subtype_caps_mdi_pse, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(media_flags, hf_media_tlv_subtype_caps_mid_pd, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(media_flags, hf_media_tlv_subtype_caps_inventory, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
		}
		tempOffset += 2;
		tlvLen -= 2;

		/* Get Class type */
		if (tlvLen < 1)
		{
			proto_tree_add_text(tree, tvb, tempOffset, 0, "TLV too short");
			return;
		}
		tempByte = tvb_get_guint8(tvb, tempOffset);
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 1, "Class Type: %s", val_to_str_const(tempByte, media_class_values, "Unknown"));
		tempOffset++;
		tlvLen--;

		break;
	}
	case 2:		/* Network Policy */
	{
		/* Get application type */
		if (tlvLen < 1)
		{
			proto_tree_add_text(tree, tvb, tempOffset, 0, "TLV too short");
			return;
		}
		tempByte = tvb_get_guint8(tvb, tempOffset);
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 1, "Application Type: %s (%u)",
							val_to_str_const(tempByte, media_application_type, "Unknown"), tempByte);
		tempOffset++;
		tlvLen--;

		/* Get flags */
		if (tlvLen < 2)
		{
			proto_tree_add_text(tree, tvb, tempOffset, 0, "TLV too short");
			return;
		}
		tempShort = tvb_get_ntohs(tvb, tempOffset);

		if (tree)
		{
			proto_tree_add_item(tree, hf_media_policy_flag, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_media_tag_flag, tvb, tempOffset, 2, ENC_BIG_ENDIAN);
		}

		/* Get vlan id */
		tempVLAN = (tempShort & 0x1FFE) >> 1;
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 2, "VLAN Id: %u", tempVLAN);
		tempOffset++;
		tlvLen--;

		/* Get L2 priority */
		if (tlvLen < 1)
		{
			proto_tree_add_text(tree, tvb, tempOffset, 0, "TLV too short");
			return;
		}
		tempShort = tvb_get_ntohs(tvb, tempOffset);
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 2, "L2 Priority: %u",
												((tempShort & 0x01C0) >> 6));
		tempOffset++;
		tlvLen--;

		/* Get DSCP value */
		tempByte = tvb_get_guint8(tvb, tempOffset);
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 1, "DSCP Value: %u",
												(tempByte & 0x3F));

		break;
	}
	case 3:	/* Location Identification */
	{
		/* Get location data format */
		if (tlvLen < 1)
		{
			proto_tree_add_text(tree, tvb, tempOffset, 0, "TLV too short");
			return;
		}
		tempByte = tvb_get_guint8(tvb, tempOffset);
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 1, "Location Data Format: %s (%u)",
							val_to_str_const(tempByte, location_data_format, "Unknown"), tempByte);
		tempOffset++;
		tlvLen--;

		switch (tempByte)
		{
		case 1:	/* Coordinate-based LCI */
		{
			/*
			 * See RFC 3825.
			 * XXX - should this be handled by the BOOTP
			 * dissector, and exported to us?
			 */
			if (tlvLen < 16)
			{
				proto_tree_add_text(tree, tvb, tempOffset, 0, "TLV too short");
				return;
			}

			/* Get latitude resolution */
			tempByte = tvb_get_guint8(tvb, tempOffset);
			if (tree)
				proto_tree_add_text(tree, tvb, tempOffset, 1, "Latitude Resolution: %u",
												((tempByte & 0xFC) >> 2));

			/* Get latitude */
			temp64bit = tvb_get_ntoh64(tvb, tempOffset);
			temp64bit = (temp64bit & G_GINT64_CONSTANT(0x03FFFFFFFF000000)) >> 24;
			if (tree)
				proto_tree_add_text(tree, tvb, tempOffset, 5, "Latitude: %s (0x%16" G_GINT64_MODIFIER "X)",
				    get_latitude_or_longitude(0, temp64bit),
				    temp64bit);

			tempOffset += 5;

			/* Get longitude resolution */
			tempByte = tvb_get_guint8(tvb, tempOffset);
			if (tree)
				proto_tree_add_text(tree, tvb, tempOffset, 1, "Longitude Resolution: %u",
											((tempByte & 0xFC) >> 2));

			/* Get longitude */
			temp64bit = tvb_get_ntoh64(tvb, tempOffset);
			temp64bit = (temp64bit & G_GINT64_CONSTANT(0x03FFFFFFFF000000)) >> 24;
			;
			if (tree)
				proto_tree_add_text(tree, tvb, tempOffset, 5, "Longitude: %s (0x%16" G_GINT64_MODIFIER "X)",
				    get_latitude_or_longitude(1,temp64bit),
				    temp64bit);

			tempOffset += 5;

			/* Altitude Type */
			tempByte = tvb_get_guint8(tvb, tempOffset);
			if (tree)
			{
				tf = proto_tree_add_text(tree, tvb, tempOffset, 1, "Altitude Type:");

				switch ((tempByte >> 4))
				{
				case 1:
					proto_item_append_text(tf, "Meters (1)");
					break;
				case 2:
					proto_item_append_text(tf, "Floors (2)");
					break;
				default:
					proto_item_append_text(tf, " Unknown (%u)", (tempByte >> 4));
					break;
				}
			}

			/* Get Altitude Resolution */
			tempShort = tvb_get_ntohs(tvb, tempOffset);
			if (tree)
				proto_tree_add_text(tree, tvb, tempOffset, 2, "Altitude Resolution: %u",
						((tempShort & 0x0FC0) >> 6));

			tempOffset++;

			/* Get Altitude */
			tempLong = (tvb_get_ntohl(tvb, tempOffset) & 0x03FFFFFFF);
			if (tree)
				proto_tree_add_text(tree, tvb, tempOffset, 4, "Altitude: 0x%08X", tempLong);

			tempOffset += 4;

			/* Get datum */
			tempByte = tvb_get_guint8(tvb, tempOffset);
			if (tree)
				proto_tree_add_text(tree, tvb, tempOffset, 1, "Datum: %u", tempByte);

			break;
		}
		case 2: /* Civic Address LCI */
		{
			/*
			 * See draft-ietf-geopriv-dhcp-civil-07.
			 * XXX - should this be handled by the BOOTP
			 * dissector, and exported to us?
			 */
			if (tlvLen < 1)
			{
				proto_tree_add_text(tree, tvb, tempOffset, 0, "TLV too short");
				return;
			}

			/* Get LCI length */
			tempByte = tvb_get_guint8(tvb, tempOffset);
			tlvLen--;
			if (tempByte > tlvLen)
			{
				if (tree)
					proto_tree_add_text(tree, tvb, tempOffset, 1, "LCI Length: %u (greater than TLV length)", tempByte);

				return;
			}

			if (tree)
				proto_tree_add_text(tree, tvb, tempOffset, 1, "LCI Length: %u", tempByte);

			LCI_Length = (guint32)tempByte;

			tempOffset++;

			/* Get what value */
			if (LCI_Length < 1)
			{
				proto_tree_add_text(tree, tvb, tempOffset, 0, "LCI Length too short");
				return;
			}
			tempByte = tvb_get_guint8(tvb, tempOffset);
			if (tree)
				proto_tree_add_text(tree, tvb, tempOffset, 1, "What: %s (%u)",
									val_to_str_const(tempByte,civic_address_what_values,"Unknown"),
									tempByte);
			tempOffset++;
			LCI_Length--;

			/* Get country code */
			if (LCI_Length < 2)
			{
				proto_tree_add_text(tree, tvb, tempOffset, 0, "LCI Length too short");
				return;
			}
			if (tree)
				proto_tree_add_text(tree, tvb, tempOffset, 2, "Country: %s",
				    tvb_format_text(tvb, tempOffset, 2));

			tempOffset += 2;
			LCI_Length -= 2;

			while (LCI_Length > 0)
			{
				/* Get CA Type */
				if (LCI_Length < 1)
				{
					proto_tree_add_text(tree, tvb, tempOffset, 0, "LCI Length too short");
					return;
				}
				tempByte = tvb_get_guint8(tvb, tempOffset);
				if (tree)
					proto_tree_add_text(tree, tvb, tempOffset, 1, "CA Type: %s (%u)",
									val_to_str_const(tempByte,civic_address_type_values,"Unknown"),
									tempByte);

				tempOffset++;
				LCI_Length--;

				/* Get CA Length */
				if (LCI_Length < 1)
				{
					proto_tree_add_text(tree, tvb, tempOffset, 0, "LCI Length too short");
					return;
				}
				tempByte = tvb_get_guint8(tvb, tempOffset);
				if (tree)
					proto_tree_add_text(tree, tvb, tempOffset, 1, "CA Length: %u", tempByte);

				tempOffset++;
				LCI_Length--;

				/* Make sure the CA value is within the specified length */
				if (tempByte > LCI_Length)
					return;

				if (tempByte > 0)
				{
					/* Get CA Value */
					if (tree)
						proto_tree_add_text(tree, tvb, tempOffset, tempByte, "CA Value: %s",
						    tvb_format_stringzpad(tvb, tempOffset, tempByte));

					tempOffset += tempByte;
					LCI_Length -= tempByte;
				}
			}

			break;
		}
		case 3: /* ECS ELIN */
		{
			if (tlvLen > 0)
			{
				if (tree)
					proto_tree_add_text(tree, tvb, tempOffset, tlvLen, "ELIN: %s",
					    tvb_format_stringzpad(tvb, tempOffset, tlvLen));

			}

			break;
		}
		}

		break;
	}
	case 4: /* Extended Power-via-MDI */
	{
		/* Get first byte */
		tempByte = tvb_get_guint8(tvb, tempOffset);

		/* Determine power type */
		subType = ((tempByte & 0xC0) >> 6);
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 1, "Power Type %s",
									val_to_str_const(subType, media_power_type, "Unknown"));

		/* Determine power source */
		switch (subType)
		{
		case 0:
		{
			subType = ((tempByte & 0x30) >> 4);
			strPtr = val_to_str_const(subType, media_power_pse_device, "Reserved");

			break;
		}
		case 1:
		{
			subType = ((tempByte & 0x30) >> 4);
			strPtr = val_to_str_const(subType, media_power_pd_device, "Reserved");

			break;
		}
		default:
		{
			strPtr = "Unknown";
			break;
		}
		}
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 1, "Power Source: %s", strPtr);

		/* Determine power priority */
		subType = (tempByte & 0x0F);
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 1, "Power Priority: %s",
									val_to_str_const(subType, media_power_priority, "Reserved"));

		tempOffset++;

		/* Power Value: 0 to 102.3 Watts (0.1 W increments) */
		tempShort = tvb_get_ntohs(tvb, tempOffset) * 100;
		if (tree)
			proto_tree_add_text(tree, tvb, tempOffset, 2, "Power Value: %u mW", tempShort);

		break;
	}
	case 5:	/* Hardware Revision */
	{
		/* Figure out the length of the hardware revision field */
		if (tlvLen > 0)
		{
			if (tree)
				proto_tree_add_text(tree, tvb, tempOffset, tlvLen, "Hardware Revision: %s",
				    tvb_format_stringzpad(tvb, tempOffset, tlvLen));
		}

		break;
	}
	case 6:	/* Firmware Revision */
	{
		/* Figure out the length of the firmware revision field */
		if (tlvLen > 0)
		{
			if (tree)
				proto_tree_add_text(tree, tvb, tempOffset, tlvLen, "Firmware Revision: %s",
				    tvb_format_stringzpad(tvb, tempOffset, tlvLen));
		}

		break;
	}
	case 7:	/* Software Revision */
	{
		/* Figure out the length of the software revision field */
		if (tlvLen > 0)
		{
			if (tree)
				proto_tree_add_text(tree, tvb, tempOffset, tlvLen, "Software Revision: %s",
				    tvb_format_stringzpad(tvb, tempOffset, tlvLen));
		}

		break;
	}
	case 8:	/* Serial Number */
	{
		/* Figure out the length of the serial number field */
		if (tlvLen > 0)
		{
			if (tree)
				proto_tree_add_text(tree, tvb, tempOffset, tlvLen, "Serial Number: %s",
				    tvb_format_stringzpad(tvb, tempOffset, tlvLen));
		}

		break;
	}
	case 9:	/* Manufacturer Name */
	{
		/* Figure out the length of the manufacturer name field */
		if (tlvLen > 0)
		{
			if (tree)
				proto_tree_add_text(tree, tvb, tempOffset, tlvLen, "Manufacturer Name: %s",
				    tvb_format_stringzpad(tvb, tempOffset, tlvLen));
		}

		break;
	}
	case 10:	/* Model Name */
	{
		/* Figure out the length of the model name field */
		if (tlvLen > 0)
		{
			if (tree)
				proto_tree_add_text(tree, tvb, tempOffset, tlvLen, "Model Name: %s",
				    tvb_format_stringzpad(tvb, tempOffset, tlvLen));
		}

		break;
	}
	case 11:	/* Asset ID */
	{
		/* Figure out the length of the asset id field */
		if (tlvLen > 0)
		{
			if (tree)
				proto_tree_add_text(tree, tvb, tempOffset, tlvLen, "Asset ID: %s",
				    tvb_format_stringzpad(tvb, tempOffset, tlvLen));
		}

		break;
	}
	}

	return;
}


static guint32
dissect_profinet_period(tvbuff_t *tvb, proto_tree *tree, guint32 offset, const gchar *name, int hf_valid, int hf_value)
{
    guint32 period;
    proto_tree	*period_tree;
    proto_item 	*period_item;


    period = tvb_get_ntohl(tvb, offset);

    period_item = proto_tree_add_text(tree, tvb, offset, 4, "%s: %s, %uns",
        name, (period & 0x80000000) ? "Valid" : "Invalid", period & 0x7FFFFFFF);
    period_tree = proto_item_add_subtree(period_item, ett_profinet_period);

    proto_tree_add_uint(period_tree, hf_valid, tvb, offset, 4, period);
    proto_tree_add_uint(period_tree, hf_value, tvb, offset, 4, period);
    offset+=4;

    return offset;
}


/* Dissect PROFINET TLVs */
static void
dissect_profinet_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset)
{
	guint8 subType;
	proto_item 	*tf = NULL;
	guint16 class2_PortStatus;
	guint16 class3_PortStatus;
	guint32 port_rx_delay_local;
	guint32 port_rx_delay_remote;
	guint32 port_tx_delay_local;
	guint32 port_tx_delay_remote;
	guint32 cable_delay_local;
	e_guid_t * uuid;
	guint16 mrrt_PortStatus;


	/* Get subtype */
	subType = tvb_get_guint8(tvb, offset);
	if (tree)
		proto_tree_add_uint(tree, hf_profinet_tlv_subtype, tvb, offset, 1, subType);
	offset++;

	switch (subType)
	{
	case 1:		/* LLDP_PNIO_DELAY */
	{
		port_rx_delay_local = tvb_get_ntohl(tvb, offset);
		tf = proto_tree_add_uint(tree, hf_profinet_port_rx_delay_local, tvb, offset, 4, port_rx_delay_local);
		if(port_rx_delay_local) {
			proto_item_append_text(tf, "ns");
		} else {
			proto_item_append_text(tf, " (unknown)");
		}
		offset+=4;
		port_rx_delay_remote = tvb_get_ntohl(tvb, offset);
		tf = proto_tree_add_uint(tree, hf_profinet_port_rx_delay_remote, tvb, offset, 4, port_rx_delay_remote);
		if(port_rx_delay_remote) {
			proto_item_append_text(tf, "ns");
		} else {
			proto_item_append_text(tf, " (unknown)");
		}
		offset+=4;
		port_tx_delay_local = tvb_get_ntohl(tvb, offset);
		tf = proto_tree_add_uint(tree, hf_profinet_port_tx_delay_local, tvb, offset, 4, port_tx_delay_local);
		if(port_tx_delay_local) {
			proto_item_append_text(tf, "ns");
		} else {
			proto_item_append_text(tf, " (unknown)");
		}
		offset+=4;
		port_tx_delay_remote = tvb_get_ntohl(tvb, offset);
		tf = proto_tree_add_uint(tree, hf_profinet_port_tx_delay_remote, tvb, offset, 4, port_tx_delay_remote);
		if(port_tx_delay_remote) {
			proto_item_append_text(tf, "ns");
		} else {
			proto_item_append_text(tf, " (unknown)");
		}
		offset+=4;
		cable_delay_local = tvb_get_ntohl(tvb, offset);
		tf = proto_tree_add_uint(tree, hf_profinet_cable_delay_local, tvb, offset, 4, cable_delay_local);
		if(cable_delay_local) {
			proto_item_append_text(tf, "ns");
		} else {
			proto_item_append_text(tf, " (unknown)");
		}
		offset+=4;
		break;
	}
	case 2:		/* LLDP_PNIO_PORTSTATUS */
	{
		class2_PortStatus = tvb_get_ntohs(tvb, offset);
		proto_tree_add_uint(tree, hf_profinet_class2_port_status, tvb, offset, 2, class2_PortStatus);
		offset+=2;
		class3_PortStatus = tvb_get_ntohs(tvb, offset);
		proto_tree_add_uint(tree, hf_profinet_class3_port_status, tvb, offset, 2, class3_PortStatus);
		proto_tree_add_uint(tree, hf_profinet_class3_port_status_reserved, tvb, offset, 2, class3_PortStatus);
		proto_tree_add_uint(tree, hf_profinet_class3_port_status_Fragmentation, tvb, offset, 2, class3_PortStatus);
		proto_tree_add_uint(tree, hf_profinet_class3_port_status_PreambleLength, tvb, offset, 2, class3_PortStatus);

        col_append_fstr(pinfo->cinfo, COL_INFO,"RTClass3 Port Status = %s", val_to_str((class3_PortStatus & 0x7), profinet_port3_status_vals, "Unknown %d"));
		offset+=2;
		break;
	}
	/*case 3:*/	/* XXX - LLDP_PNIO_ALIAS */
	case 4:		/* LLDP_PNIO_MRPPORTSTATUS */
	{
	    /* DomainUUID */
	    tvb_get_ntohguid (tvb, offset, (e_guid_t *) &uuid);
	    proto_tree_add_guid(tree, hf_profinet_mrp_domain_uuid, tvb, offset, 16, (e_guid_t *) &uuid);
	    offset += 16;

	    /* MRRT PortStatus */
	    mrrt_PortStatus = tvb_get_ntohs(tvb, offset);
	    proto_tree_add_uint(tree, hf_profinet_mrrt_port_status, tvb, offset, 2, mrrt_PortStatus);
	    offset+=2;
	    break;
	}
    case 5:     /* LLDP_PNIO_CHASSIS_MAC */
    {
	proto_tree_add_item(tree, hf_profinet_cm_mac, tvb, offset, 6, ENC_NA);
        offset += 6;
        break;
    }
    case 6:     /* LLDP_PNIO_PTCPSTATUS */
    {
	    /* MasterSourceAddress */
	    proto_tree_add_item(tree, hf_profinet_master_source_address, tvb, offset, 6, ENC_NA);
	    offset += 6;
	    /* SubdomainUUID */
	    tvb_get_ntohguid (tvb, offset, (e_guid_t *) &uuid);
	    proto_tree_add_guid(tree, hf_profinet_subdomain_uuid, tvb, offset, 16, (e_guid_t *) &uuid);
	    offset += 16;
        /* IRDataUUID */
	    tvb_get_ntohguid (tvb, offset, (e_guid_t *) &uuid);
	    proto_tree_add_guid(tree, hf_profinet_ir_data_uuid, tvb, offset, 16, (e_guid_t *) &uuid);
	    offset += 16;
        /* LengthOfPeriod */
        offset = dissect_profinet_period(tvb, tree, offset, "LengthOfPeriod",
            hf_profinet_length_of_period_valid, hf_profinet_length_of_period_length);
        /* RedPeriodBegin */
        offset = dissect_profinet_period(tvb, tree, offset, "RedPeriodBegin",
            hf_profinet_red_period_begin_valid, hf_profinet_red_period_begin_offset);
        /* OrangePeriodBegin */
        offset = dissect_profinet_period(tvb, tree, offset, "OrangePeriodBegin",
            hf_profinet_orange_period_begin_valid, hf_profinet_orange_period_begin_offset);
        /* GreenPeriodBegin */
        offset = dissect_profinet_period(tvb, tree, offset, "GreenPeriodBegin",
            hf_profinet_green_period_begin_valid, hf_profinet_green_period_begin_offset);
        break;
    }
	default:
		proto_tree_add_item(tree, hf_unknown_subtype_content, tvb, offset, -1, ENC_NA);
	}
}

/* Dissect Cisco OUI TLVs */
static void
dissect_cisco_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset)
{
	guint8 subType;
	guint32 tempOffset = offset;

	proto_tree *fourwire_data = NULL;
	proto_item *tf = NULL;

	/* Get subtype */
	subType = tvb_get_guint8(tvb, tempOffset);

	proto_tree_add_item(tree, hf_cisco_subtype, tvb, tempOffset, 1, ENC_BIG_ENDIAN);

	tempOffset++;

	switch (subType)
	{
	case 0x01: /* Four-Wire Power-via-MDI TLV */
		if (tree) {
			tf = proto_tree_add_item(tree, hf_cisco_four_wire_power, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
			fourwire_data = proto_item_add_subtree(tf, ett_cisco_fourwire_tlv);
			proto_tree_add_item(fourwire_data, hf_cisco_four_wire_power_poe, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(fourwire_data, hf_cisco_four_wire_power_spare_pair_arch, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(fourwire_data, hf_cisco_four_wire_power_req_spare_pair_poe, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(fourwire_data, hf_cisco_four_wire_power_pse_spare_pair_poe, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
		}
		break;
	default:
		proto_tree_add_item(tree, hf_unknown_subtype_content, tvb, offset, -1, ENC_NA);
		break;
	}
}

/* Dissect Organizational Specific TLV */
static gint32
dissect_organizational_specific_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset)
{
	guint16 tempLen;
	guint16 tempShort;
	gint    tempTree;
	guint32 oui, tLength = tvb_length(tvb);
	guint8 subType;
	const char *ouiStr;
	const char *subTypeStr;

	proto_tree	*org_tlv_tree = NULL;
	proto_item 	*tf = NULL;
	/* Get tlv type and length */
	tempShort = tvb_get_ntohs(tvb, offset);

	/* Get tlv length */
	tempLen = TLV_INFO_LEN(tempShort);
	/* Get OUI value */
	oui = tvb_get_ntoh24(tvb, (offset+2));
	subType = tvb_get_guint8(tvb, (offset+5));

	/* check for registered dissectors for the OUI  If none found continue, else call dissector */
	if( dissector_try_uint(oui_unique_code_table, oui, tvb, pinfo, tree) ) {
		return tLength;
	}
	/* maintain previous OUI names.  If not included, look in manuf database for OUI */
	ouiStr = val_to_str_const(oui, tlv_oui_subtype_vals, "Unknown");
	if (strcmp(ouiStr, "Unknown")==0) {
		ouiStr = uint_get_manuf_name_if_known(oui);
		if(ouiStr==NULL) ouiStr="Unknown";
	}

	/* Set a default value */
	tempTree = ett_org_spc_ProfinetSubTypes_1;
	switch(oui)
	{
	case OUI_IEEE_802_1:
		subTypeStr = val_to_str(subType, ieee_802_1_subtypes, "Unknown subtype 0x%x");
		switch(subType)
		{
		case 1:	tempTree = ett_org_spc_ieee_802_1_1;
			break;
		case 2:	tempTree = ett_org_spc_ieee_802_1_2;
			break;
		case 3:	tempTree = ett_org_spc_ieee_802_1_3;
			break;
		case 4:	tempTree = ett_org_spc_ieee_802_1_4;
			break;
		}
		break;
	case OUI_IEEE_802_3:
		subTypeStr = val_to_str(subType, ieee_802_3_subtypes, "Unknown subtype 0x%x");
		switch(subType)
		{
		case 1:	tempTree = ett_org_spc_ieee_802_3_1;
			break;
		case 2:	tempTree = ett_org_spc_ieee_802_3_2;
			break;
		case 3:	tempTree = ett_org_spc_ieee_802_3_3;
			break;
		case 4:	tempTree = ett_org_spc_ieee_802_3_4;
			break;
		}
		break;
	case OUI_MEDIA_ENDPOINT:
		subTypeStr = val_to_str(subType, media_subtypes, "Unknown subtype 0x%x");
		switch(subType)
		{
		case 1:	tempTree = ett_org_spc_media_1;
			break;
		case 2:	tempTree = ett_org_spc_media_2;
			break;
		case 3:	tempTree = ett_org_spc_media_3;
			break;
		case 4:	tempTree = ett_org_spc_media_4;
			break;
		case 5:	tempTree = ett_org_spc_media_5;
			break;
		case 6:	tempTree = ett_org_spc_media_6;
			break;
		case 7:	tempTree = ett_org_spc_media_7;
			break;
		case 8:	tempTree = ett_org_spc_media_8;
			break;
		case 9:	tempTree = ett_org_spc_media_9;
			break;
		case 10:	tempTree = ett_org_spc_media_10;
			break;
		case 11:	tempTree = ett_org_spc_media_11;
			break;
		}
		break;
	case OUI_PROFINET:
		subTypeStr = val_to_str(subType, profinet_subtypes, "Reserved (0x%x)");
		switch(subType)
		{
		case 1:	tempTree = ett_org_spc_ProfinetSubTypes_1;
			break;
		case 2:	tempTree = ett_org_spc_ProfinetSubTypes_2;
			break;
		case 3:	tempTree = ett_org_spc_ProfinetSubTypes_3;
			break;
		case 4:	tempTree = ett_org_spc_ProfinetSubTypes_4;
			break;
		case 5:	tempTree = ett_org_spc_ProfinetSubTypes_5;
			break;
		case 6:	tempTree = ett_org_spc_ProfinetSubTypes_6;
			break;
		}
		break;
	case OUI_CISCO_2:
		subTypeStr = val_to_str(subType, cisco_subtypes, "Unknown subtype (0x%x)");
		break;
	case OUI_IEEE_802_1QBG:
		subTypeStr = val_to_str(subType, ieee_802_1qbg_subtypes, "Unknown subtype 0x%x");
		break;
	default:
		subTypeStr = ep_strdup_printf("Unknown (%d)",subType);
		break;
	}
	if (tree)
	{
		tf = proto_tree_add_text(tree, tvb, offset, tLength, "%s - %s", ouiStr, subTypeStr);
		org_tlv_tree = proto_item_add_subtree(tf, tempTree); /* change to temp: ett_org_spc_tlv */
		proto_tree_add_item(org_tlv_tree, hf_lldp_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	}
	if (tempLen < 4)
	{
		if (tree)
			proto_tree_add_uint_format(org_tlv_tree, hf_lldp_tlv_len, tvb, offset, 2,
			    tempShort, "TLV Length: %u (too short, must be >= 4)", tempLen);
		return tLength;
	}
	if (tree)
	{
		proto_tree_add_item(org_tlv_tree, hf_lldp_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);

		/* Display organizational unique id */
		proto_tree_add_uint(org_tlv_tree, hf_org_spc_oui, tvb, (offset + 2), 3, oui);
	}

	switch (oui)
	{
	case OUI_IEEE_802_1:
		dissect_ieee_802_1_tlv(tvb, pinfo, org_tlv_tree, (offset + 5));
		break;
	case OUI_IEEE_802_3:
		dissect_ieee_802_3_tlv(tvb, pinfo, org_tlv_tree, (offset + 5));
		break;
	case OUI_MEDIA_ENDPOINT:
		dissect_media_tlv(tvb, pinfo, org_tlv_tree, (offset + 5));
		break;
	case OUI_PROFINET:
		dissect_profinet_tlv(tvb, pinfo, org_tlv_tree, (offset + 5));
		break;
	case OUI_CISCO_2:
		dissect_cisco_tlv(tvb, pinfo, org_tlv_tree, (offset + 5));
		break;
	case OUI_IEEE_802_1QBG:
		dissect_ieee_802_1qbg_tlv(tvb, pinfo, org_tlv_tree, (offset + 5));
		break;
	default:
		dissect_oui_default_tlv(tvb, pinfo, org_tlv_tree, (offset + 5));
	}

	return offset + tvb_length(tvb);
}

/* Dissect Unknown TLV */
static gint32
dissect_lldp_unknown_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset)
{
	guint16 tempLen;
	guint16 tempShort;

	proto_tree	*unknown_tlv_tree = NULL;
	proto_item 	*tf = NULL;

	/* Get tlv type and length */
	tempShort = tvb_get_ntohs(tvb, offset);

	/* Get tlv length */
	tempLen = TLV_INFO_LEN(tempShort);

	if (tree)
	{
		tf = proto_tree_add_text(tree, tvb, offset, (tempLen + 2), "Unknown TLV");
		unknown_tlv_tree = proto_item_add_subtree(tf, ett_unknown_tlv);

		proto_tree_add_item(unknown_tlv_tree, hf_lldp_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(unknown_tlv_tree, hf_lldp_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	}

	return (tempLen + 2);
}


/* Dissect LLDP packets */
static void
dissect_lldp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *lldp_tree = NULL;
	tvbuff_t *new_tvb = NULL;
	guint32 offset = 0;
	gint32 rtnValue = 0;
	guint16 tempShort;
	guint8 tempType;
	gboolean reachedEnd = FALSE;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LLDP");

	/* Clear the information column on summary display */
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree)
	{
		ti = proto_tree_add_item(tree, proto_lldp, tvb, offset, -1, ENC_NA);
		lldp_tree = proto_item_add_subtree(ti, ett_lldp);
	}

	/* Get chassis id tlv */
	rtnValue = dissect_lldp_chassis_id(tvb, pinfo, lldp_tree, offset);
	if (rtnValue < 0)
	{
		col_set_str(pinfo->cinfo, COL_INFO, "Invalid Chassis ID TLV");

		return;
	}

	offset += rtnValue;

	/* Get port id tlv */
	rtnValue = dissect_lldp_port_id(tvb, pinfo, lldp_tree, offset);
	if (rtnValue < 0)
	{
		col_set_str(pinfo->cinfo, COL_INFO, "Invalid Port ID TLV");

		return;
	}

	offset += rtnValue;

	/* Get time to live tlv */
	rtnValue = dissect_lldp_time_to_live(tvb, pinfo, lldp_tree, offset);
	if (rtnValue < 0)
	{
		col_set_str(pinfo->cinfo, COL_INFO, "Invalid Time-to-Live TLV");

		return;
	}

	offset += rtnValue;

	/* Dissect optional tlv's until end-of-lldpdu is reached */
	while (!reachedEnd)
	{
		tempShort = tvb_get_ntohs(tvb, offset);
		tempType = TLV_TYPE(tempShort);
		/* pass only TLV to dissectors, Zero offset (point to front of tlv) */
		new_tvb = tvb_new_subset(tvb, offset, TLV_INFO_LEN(tempShort)+2, TLV_INFO_LEN(tempShort)+2); 
		switch (tempType)
		{
		case CHASSIS_ID_TLV_TYPE:
			rtnValue = dissect_lldp_chassis_id(new_tvb, pinfo, lldp_tree, 0);
			rtnValue = -1;	/* Duplicate chassis id tlv */
			col_set_str(pinfo->cinfo, COL_INFO, "Duplicate Chassis ID TLV");
			break;
		case PORT_ID_TLV_TYPE:
			rtnValue = dissect_lldp_port_id(new_tvb, pinfo, lldp_tree, 0);
			rtnValue = -1;	/* Duplicate port id tlv */
			col_set_str(pinfo->cinfo, COL_INFO, "Duplicate Port ID TLV");
			break;
		case TIME_TO_LIVE_TLV_TYPE:
			rtnValue = dissect_lldp_time_to_live(new_tvb, pinfo, lldp_tree, 0);
			rtnValue = -1;	/* Duplicate time-to-live tlv */
			col_set_str(pinfo->cinfo, COL_INFO, "Duplicate Time-To-Live TLV");
			break;
		case END_OF_LLDPDU_TLV_TYPE:
			rtnValue = dissect_lldp_end_of_lldpdu(new_tvb, pinfo, lldp_tree, 0);
			break;
		case PORT_DESCRIPTION_TLV_TYPE:
			rtnValue = dissect_lldp_port_desc(new_tvb, pinfo, lldp_tree, 0);
			break;
		case SYSTEM_NAME_TLV_TYPE:
		case SYSTEM_DESCRIPTION_TLV_TYPE:
			rtnValue = dissect_lldp_system_name(new_tvb, pinfo, lldp_tree, 0);
			break;
		case SYSTEM_CAPABILITIES_TLV_TYPE:
			rtnValue = dissect_lldp_system_capabilities(new_tvb, pinfo, lldp_tree, 0);
			break;
		case MANAGEMENT_ADDR_TLV_TYPE:
			rtnValue = dissect_lldp_management_address(new_tvb, pinfo, lldp_tree, 0);
			break;
		case ORGANIZATION_SPECIFIC_TLV_TYPE:
			rtnValue = dissect_organizational_specific_tlv(new_tvb, pinfo, lldp_tree, 0);
			break;
		default:
			rtnValue = dissect_lldp_unknown_tlv(new_tvb, pinfo, lldp_tree, 0);
			break;
		}

		if (rtnValue < 0)
			reachedEnd = TRUE;
		else
			offset += rtnValue;
	}

}

/* Register the protocol with Wireshark */
void
proto_register_lldp(void)
{
	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_lldp_tlv_type,
			{ "TLV Type", "lldp.tlv.type", FT_UINT16, BASE_DEC,
			VALS(tlv_types), TLV_TYPE_MASK, NULL, HFILL }
		},
		{ &hf_lldp_tlv_len,
			{ "TLV Length", "lldp.tlv.len", FT_UINT16, BASE_DEC,
			NULL, TLV_INFO_LEN_MASK, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_cap,
			{ "Capabilities", "lldp.tlv.system_cap", FT_UINT16, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_cap_other,
			{ "Other", "lldp.tlv.system_cap.other", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_OTHER, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_cap_repeater,
			{ "Repeater", "lldp.tlv.system_cap.repeater", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_REPEATER, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_cap_bridge,
			{ "Bridge", "lldp.tlv.system_cap.bridge", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_BRIDGE, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_cap_wlan_access_pt,
			{ "WLAN access point", "lldp.tlv.system_cap.wlan_access_pt", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_WLAN, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_cap_router,
			{ "Router", "lldp.tlv.system_cap.router", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_ROUTER, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_cap_telephone,
			{ "Telephone", "lldp.tlv.system_cap.telephone", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_TELEPHONE, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_cap_docsis_cable_device,
			{ "DOCSIS cable device", "lldp.tlv.system_cap.docsis_cable_device", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_DOCSIS, NULL, HFILL }
		},
		{ &hf_lldp_tlv_system_cap_station_only,
			{ "Station only", "lldp.tlv.system_cap.station_only", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_STATION, NULL, HFILL }
		},
		{ &hf_lldp_tlv_enable_system_cap,
			{ "Enabled Capabilities", "lldp.tlv.enable_system_cap", FT_UINT16, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_lldp_tlv_enable_system_cap_other,
			{ "Other", "lldp.tlv.enable_system_cap.other", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_OTHER, NULL, HFILL }
		},
		{ &hf_lldp_tlv_enable_system_cap_repeater,
			{ "Repeater", "lldp.tlv.enable_system_cap.repeater", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_REPEATER, NULL, HFILL }
		},
		{ &hf_lldp_tlv_enable_system_cap_bridge,
			{ "Bridge", "lldp.tlv.enable_system_cap.bridge", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_BRIDGE, NULL, HFILL }
		},
		{ &hf_lldp_tlv_enable_system_cap_wlan_access_pt,
			{ "WLAN access point", "lldp.tlv.enable_system_cap.wlan_access_pt", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_WLAN, NULL, HFILL }
		},
		{ &hf_lldp_tlv_enable_system_cap_router,
			{ "Router", "lldp.tlv.enable_system_cap.router", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_ROUTER, NULL, HFILL }
		},
		{ &hf_lldp_tlv_enable_system_cap_telephone,
			{ "Telephone", "lldp.tlv.enable_system_cap.telephone", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_TELEPHONE, NULL, HFILL }
		},
		{ &hf_lldp_tlv_enable_system_cap_docsis_cable_device,
			{ "DOCSIS cable device", "lldp.tlv.enable_system_cap.docsis_cable_device", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_DOCSIS, NULL, HFILL }
		},
		{ &hf_lldp_tlv_enable_system_cap_station_only,
			{ "Station only", "lldp.tlv.enable_system_cap.station_only", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), SYSTEM_CAPABILITY_STATION, NULL, HFILL }
		},
		{ &hf_chassis_id_subtype,
			{ "Chassis Id Subtype", "lldp.chassis.subtype", FT_UINT8, BASE_DEC,
			VALS(chassis_id_subtypes), 0, NULL, HFILL }
		},
		{ &hf_chassis_id,
			{ "Chassis Id", "lldp.chassis.id", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_chassis_id_mac,
			{ "Chassis Id", "lldp.chassis.id.mac", FT_ETHER, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_chassis_id_ip4,
			{ "Chassis Id", "lldp.chassis.id.ip4", FT_IPv4, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_chassis_id_ip6,
			{ "Chassis Id", "lldp.chassis.id.ip6", FT_IPv6, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_port_id_subtype,
			{ "Port Id Subtype", "lldp.port.subtype", FT_UINT8, BASE_DEC,
			VALS(port_id_subtypes), 0, NULL, HFILL }
		},
		{ &hf_port_id_mac,
			{ "Port Id", "lldp.port.id.mac", FT_ETHER, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_lldp_network_address_family,
			{ "Network Address family", "lldp.network_address.subtype", FT_UINT8, BASE_DEC,
			VALS(afn_vals), 0, NULL, HFILL }
		},
		{ &hf_port_id_ip4,
			{ "Port Id", "lldp.port.id.ip4", FT_IPv4, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_port_id_ip6,
			{ "Port Id", "lldp.port.id.ip6", FT_IPv6, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_time_to_live,
			{ "Seconds", "lldp.time_to_live", FT_UINT16, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_mgn_addr_ipv4,
			{ "Management Address", "lldp.mgn.addr.ip4", FT_IPv4, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_mgn_addr_ipv6,
			{ "Management Address", "lldp.mgn.addr.ip6", FT_IPv6, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_mgn_addr_hex,
			{ "Management Address", "lldp.mgn.addr.hex", FT_BYTES, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_mgn_obj_id,
			{ "Object Identifier", "lldp.mgn.obj.id", FT_OID, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_org_spc_oui,
			{ "Organization Unique Code", "lldp.orgtlv.oui", FT_UINT24, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_1_subtype,
			{ "IEEE 802.1 Subtype", "lldp.ieee.802_1.subtype", FT_UINT8, BASE_HEX,
			VALS(ieee_802_1_subtypes), 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_1_port_and_vlan_id_flag,
			{ "Flags", "lldp.ieee.802_1.port_and_vlan_id_flag", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_1_port_and_vlan_id_flag_supported,
			{ "Port and Protocol VLAN", "lldp.ieee.802_1.port_and_vlan_id_flag.supported", FT_BOOLEAN, 8,
			TFS(&tfs_supported_not_supported), 0x02, NULL, HFILL }
		},
		{ &hf_ieee_802_1_port_and_vlan_id_flag_enabled,
			{ "Port and Protocol VLAN", "lldp.ieee.802_1.port_and_vlan_id_flag.enabled", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x04, NULL, HFILL }
		},
		{ &hf_ieee_802_3_subtype,
			{ "IEEE 802.3 Subtype", "lldp.ieee.802_3.subtype", FT_UINT8, BASE_HEX,
			VALS(ieee_802_3_subtypes), 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_mac_phy_auto_neg_status,
			{ "Auto-Negotiation Support/Status", "lldp.ieee.802_3.mac_phy_auto_neg_status", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_mac_phy_auto_neg_status_supported,
			{ "Auto-Negotiation", "lldp.ieee.802_3.mac_phy_auto_neg_status.supported", FT_BOOLEAN, 8,
			TFS(&tfs_supported_not_supported), 0x02, NULL, HFILL }
		},
		{ &hf_ieee_802_3_mac_phy_auto_neg_status_enabled,
			{ "Auto-Negotiation", "lldp.ieee.802_3.mac_phy_auto_neg_status.enabled", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x04, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps,
			{ "PMD Auto-Negotiation Advertised Capability", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_tfd,
			{ "1000BASE-T (full duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_tfd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_1000BASE_TFD, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_t,
			{ "1000BASE-T (half duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_t", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_1000BASE_T, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_xfd,
			{ "1000BASE-X (-LX, -SX, -CX full duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_xfd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_1000BASE_XFD, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_1000base_x,
			{ "1000BASE-X (-LX, -SX, -CX half duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_x", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_1000BASE_X, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_bpause,
			{ "Asymmetric and Symmetric PAUSE (for full-duplex links)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_bpause", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_FDX_BPAUSE, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_spause,
			{ "Symmetric PAUSE (for full-duplex links)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_spause", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_FDX_SPAUSE, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_apause,
			{ "Asymmetric PAUSE (for full-duplex links)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_apause", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_FDX_APAUSE, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_fdx_pause,
			{ "PAUSE (for full-duplex links)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_pause", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_FDX_PAUSE, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_t2fd,
			{ "100BASE-T2 (full duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_t2fd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_100BASE_T2FD, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_t2,
			{ "100BASE-T2 (half duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_t2", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_100BASE_T2, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_txfd,
			{ "100BASE-TX (full duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_txfd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_100BASE_TXFD, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_tx,
			{ "100BASE-TX (half duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_tx", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_100BASE_TX, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_100base_t4,
			{ "100BASE-T4", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_t4", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_100BASE_T4, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_10base_tfd,
			{ "10BASE-T (full duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.10base_tfd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_10BASET_FD, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_10base_t,
			{ "10BASE-T (half duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.10base_t", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_10BASE_T, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_other,
			{ "Other or unknown", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.other", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), AUTONEG_OTHER, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_tfd,
			{ "1000BASE-T (full duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_tfd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_1000BASE_TFD, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_t,
			{ "1000BASE-T (half duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_t", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_1000BASE_T, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_xfd,
			{ "1000BASE-X (-LX, -SX, -CX full duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_xfd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_1000BASE_XFD, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_1000base_x,
			{ "1000BASE-X (-LX, -SX, -CX half duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_x", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_1000BASE_X, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_bpause,
			{ "Asymmetric and Symmetric PAUSE (for full-duplex links)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_bpause", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_FDX_BPAUSE, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_spause,
			{ "Symmetric PAUSE (for full-duplex links)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_spause", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_FDX_SPAUSE, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_apause,
			{ "Asymmetric PAUSE (for full-duplex links)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_apause", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_FDX_APAUSE, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_fdx_pause,
			{ "PAUSE (for full-duplex links)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_pause", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_FDX_PAUSE, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_t2fd,
			{ "100BASE-T2 (full duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_t2fd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_100BASE_T2FD, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_t2,
			{ "100BASE-T2 (half duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_t2", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_100BASE_T2, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_txfd,
			{ "100BASE-TX (full duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_txfd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_100BASE_TXFD, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_tx,
			{ "100BASE-TX (half duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_tx", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_100BASE_TX, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_100base_t4,
			{ "100BASE-T4", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_t4", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_100BASE_T4, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_10base_tfd,
			{ "10BASE-T (full duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.10base_tfd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_10BASET_FD, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_10base_t,
			{ "10BASE-T (half duplex mode)", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.10base_t", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_10BASE_T, NULL, HFILL }
		},
		{ &hf_ieee_802_3_pmd_auto_neg_advertised_caps_inv_other,
			{ "Other or unknown", "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.other", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), INV_AUTONEG_OTHER, NULL, HFILL }
		},
		{ &hf_ieee_802_3_mdi_power_support,
			{ "MDI Power Support", "lldp.ieee.802_3.mdi_power_support", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_mdi_power_support_port_class,
			{ "Port Class", "lldp.ieee.802_3.mdi_power_support.port_class", FT_BOOLEAN, 8,
			TFS(&tfs_ieee_802_3_pse_pd), 0x01, NULL, HFILL }
		},
		{ &hf_ieee_802_3_mdi_power_support_pse_power_support,
			{ "PSE MDI Power", "lldp.ieee.802_3.mdi_power_support.supported", FT_BOOLEAN, 8,
			TFS(&tfs_supported_not_supported), 0x02, NULL, HFILL }
		},
		{ &hf_ieee_802_3_mdi_power_support_pse_power_enabled,
			{ "PSE MDI Power", "lldp.ieee.802_3.mdi_power_support.enabled", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x04, NULL, HFILL }
		},
		{ &hf_ieee_802_3_mdi_power_support_pse_pairs,
			{ "PSE Pairs Control Ability", "lldp.ieee.802_3.mdi_power_support.pse_pairs", FT_BOOLEAN, 8,
			TFS(&tfs_yes_no), 0x08, NULL, HFILL }
		},
		{ &hf_ieee_802_3_aggregation_status,
			{ "Aggregation Status", "lldp.ieee.802_3.aggregation_status", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_3_aggregation_status_cap,
			{ "Aggregation Capability", "lldp.ieee.802_3.aggregation_status.cap", FT_BOOLEAN, 8,
			TFS(&tfs_yes_no), 0x01, NULL, HFILL }
		},
		{ &hf_ieee_802_3_aggregation_status_enabled,
			{ "Aggregation Status", "lldp.ieee.802_3.aggregation_status.enabled", FT_BOOLEAN, 8,
			TFS(&tfs_enabled_disabled), 0x02, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_subtype,
			{ "IEEE 802.1Qbg Subtype", "lldp.ieee.802_1qbg.subtype", FT_UINT8, BASE_HEX,
			VALS(ieee_802_1qbg_subtypes), 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_support_caps,
			{ "Supported capabilities", "lldp.ieee.802_1qbg.evb_support_caps", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_support_caps_std,
			{ "Standard bridging (STD)", "lldp.ieee.802_1qbg.evb_support_caps.std", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), EVB_CAPA_STD, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_support_caps_rr,
			{ "Reflective relay (RR)", "lldp.ieee.802_1qbg.evb_support_caps.rr", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), EVB_CAPA_RR, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_support_caps_rte,
			{ "Retransmission timer exponent (RTE)", "lldp.ieee.802_1qbg.evb_support_caps.rte", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), EVB_CAPA_RTE, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_support_caps_ecp,
			{ "Edge control protocol (ECP)", "lldp.ieee.802_1qbg.evb_support_caps.ecp", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), EVB_CAPA_ECP, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_support_caps_vdp,
			{ "VSI discovery protocol (VDP)", "lldp.ieee.802_1qbg.evb_support_caps.vdp", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), EVB_CAPA_VDP, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_configure_caps,
			{ "Configured capabilities", "lldp.ieee.802_1qbg.evb_configure_caps", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_configure_caps_std,
			{ "Standard bridging (STD)", "lldp.ieee.802_1qbg.evb_configure_caps.std", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), EVB_CAPA_STD, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_configure_caps_rr,
			{ "Reflective relay (RR)", "lldp.ieee.802_1qbg.evb_configure_caps.rr", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), EVB_CAPA_RR, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_configure_caps_rte,
			{ "Retransmission timer exponent (RTE)", "lldp.ieee.802_1qbg.evb_configure_caps.rte", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), EVB_CAPA_RTE, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_configure_caps_ecp,
			{ "Edge control protocol (ECP)", "lldp.ieee.802_1qbg.evb_configure_caps.ecp", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), EVB_CAPA_ECP, NULL, HFILL }
		},
		{ &hf_ieee_802_1qbg_evb_configure_caps_vdp,
			{ "VSI discovery protocol (VDP)", "lldp.ieee.802_1qbg.evb_configure_caps.vdp", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), EVB_CAPA_VDP, NULL, HFILL }
		},
		{ &hf_media_tlv_subtype,
			{ "Media Subtype",	"lldp.media.subtype", FT_UINT8, BASE_HEX,
	   		VALS(media_subtypes), 0x0, NULL, HFILL }
		},
		{ &hf_media_tlv_subtype_caps,
			{ "Capabilities", "lldp.media.subtype.caps", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_media_tlv_subtype_caps_llpd,
			{ "LLDP-MED Capabilities", "lldp.media.subtype.caps.llpd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), MEDIA_CAPABILITY_LLDP, NULL, HFILL }
		},
		{ &hf_media_tlv_subtype_caps_network_policy,
			{ "Network Policy", "lldp.media.subtype.caps.network_policy", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), MEDIA_CAPABILITY_NETWORK_POLICY, NULL, HFILL }
		},
		{ &hf_media_tlv_subtype_caps_location_id,
			{ "Location Identification", "lldp.media.subtype.caps.location_id", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), MEDIA_CAPABILITY_LOCATION_ID, NULL, HFILL }
		},
		{ &hf_media_tlv_subtype_caps_mdi_pse,
			{ "Extended Power via MDI-PSE", "lldp.media.subtype.caps.mdi_pse", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), MEDIA_CAPABILITY_MDI_PSE, NULL, HFILL }
		},
		{ &hf_media_tlv_subtype_caps_mid_pd,
			{ "Extended Power via MDI-PD", "lldp.media.subtype.caps.mid_pd", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), MEDIA_CAPABILITY_MDI_PD, NULL, HFILL }
		},
		{ &hf_media_tlv_subtype_caps_inventory,
			{ "Inventory", "lldp.media.subtype.caps.inventory", FT_BOOLEAN, 16,
			TFS(&tfs_capable_not_capable), MEDIA_CAPABILITY_INVENTORY, NULL, HFILL }
		},
		{ &hf_media_policy_flag,
			{ "Policy", "lldp.media.policy_flag", FT_BOOLEAN, 16,
			TFS(&tfs_unknown_defined), 0x8000, NULL, HFILL }
		},
		{ &hf_media_tag_flag,
			{ "Tagged", "lldp.media.tag_flag", FT_BOOLEAN, 16,
			TFS(&tfs_yes_no), 0x4000, NULL, HFILL }
		},
		{ &hf_profinet_tlv_subtype,
			{ "Subtype",	"lldp.profinet.subtype", FT_UINT8, BASE_HEX,
			VALS(profinet_subtypes), 0x0, "PROFINET Subtype", HFILL }
		},
		{ &hf_profinet_port_rx_delay_local,
			{ "Port RX Delay Local",	"lldp.profinet.port_rx_delay_local", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_port_rx_delay_remote,
			{ "Port RX Delay Remote",	"lldp.profinet.port_rx_delay_remote", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_port_tx_delay_local,
			{ "Port TX Delay Local",	"lldp.profinet.port_tx_delay_local", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_port_tx_delay_remote,
			{ "Port TX Delay Remote",	"lldp.profinet.port_tx_delay_remote", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_cable_delay_local,
			{ "Port Cable Delay Local",	"lldp.profinet.cable_delay_local", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_class2_port_status,
			{ "RTClass2 Port Status",	"lldp.profinet.rtc2_port_status", FT_UINT16, BASE_HEX,
			VALS(profinet_port2_status_vals), 0x0, NULL, HFILL }
		},
		{ &hf_profinet_class3_port_status,
			{ "RTClass3 Port Status",	"lldp.profinet.rtc3_port_status", FT_UINT16, BASE_HEX,
			VALS(profinet_port3_status_vals), 0x0, NULL, HFILL }
		},
        /* class3_port state got some new BITs */
		{ &hf_profinet_class3_port_status_Fragmentation,
			{ "RTClass3_PortStatus.Fragmentation",	"lldp.profinet.rtc3_port_status.fragmentation", FT_UINT16, BASE_HEX,
	   		VALS(profinet_port3_status_OnOff), 0x1000, NULL, HFILL }
		},
		{ &hf_profinet_class3_port_status_reserved,
			{ "RTClass3_PortStatus.reserved",	"lldp.profinet.rtc3_port_status.reserved", FT_UINT16, BASE_HEX,
	   		  NULL, 0x0FF8, "reserved", HFILL }
		},
		{ &hf_profinet_class3_port_status_PreambleLength,
			{ "RTClass3_PortStatus.PreambleLength",	"lldp.profinet.rtc3_port_status.preambleLength", FT_UINT16, BASE_HEX,
	   		VALS(profinet_port3_status_PreambleLength), 0x2000, NULL, HFILL }
		},
		{ &hf_profinet_mrp_domain_uuid,
			{ "MRP DomainUUID",	"lldp.profinet.mrp_domain_uuid", FT_GUID, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_mrrt_port_status,
			{ "MRRT PortStatus",	"lldp.profinet.mrrt_port_status", FT_UINT16, BASE_HEX,
			VALS(profinet_mrrt_port_status_vals), 0x0, NULL, HFILL }
		},
		{ &hf_profinet_cm_mac,
			{ "CMMacAdd",	"lldp.profinet.cm_mac_add", FT_ETHER, BASE_NONE,
			NULL, 0x0, "CMResponderMacAdd or CMInitiatorMacAdd", HFILL }
		},
		{ &hf_profinet_master_source_address,
			{ "MasterSourceAddress",	"lldp.profinet.master_source_address", FT_ETHER, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_subdomain_uuid,
			{ "SubdomainUUID",	"lldp.profinet.subdomain_uuid", FT_GUID, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_ir_data_uuid,
			{ "IRDataUUID",	"lldp.profinet.ir_data_uuid", FT_GUID, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_profinet_length_of_period_valid,
			{ "LengthOfPeriod.Valid",	"lldp.profinet.length_of_period_valid", FT_UINT32, BASE_DEC,
			NULL, 0x80000000, "Length field is valid/invalid", HFILL }
		},
		{ &hf_profinet_length_of_period_length,
			{ "LengthOfPeriod.Length",	"lldp.profinet.length_of_period_length", FT_UINT32, BASE_DEC,
			NULL, 0x7FFFFFFF, "Duration of a cycle in nanoseconds", HFILL }
		},
		{ &hf_profinet_red_period_begin_valid,
			{ "RedPeriodBegin.Valid",	"lldp.profinet.red_period_begin_valid", FT_UINT32, BASE_DEC,
			NULL, 0x80000000, "Offset field is valid/invalid", HFILL }
		},
		{ &hf_profinet_red_period_begin_offset,
			{ "RedPeriodBegin.Offset",	"lldp.profinet.red_period_begin_offset", FT_UINT32, BASE_DEC,
			NULL, 0x7FFFFFFF, "RT_CLASS_3 period, offset to cycle begin in nanoseconds", HFILL }
		},
		{ &hf_profinet_orange_period_begin_valid,
			{ "OrangePeriodBegin.Valid",	"lldp.profinet.orange_period_begin_valid", FT_UINT32, BASE_DEC,
			NULL, 0x80000000, "Offset field is valid/invalid", HFILL }
		},
		{ &hf_profinet_orange_period_begin_offset,
			{ "OrangePeriodBegin.Offset","lldp.profinet.orange_period_begin_offset", FT_UINT32, BASE_DEC,
			NULL, 0x7FFFFFFF, "RT_CLASS_2 period, offset to cycle begin in nanoseconds", HFILL }
		},
		{ &hf_profinet_green_period_begin_valid,
			{ "GreenPeriodBegin.Valid",	"lldp.profinet.green_period_begin_valid", FT_UINT32, BASE_DEC,
			NULL, 0x80000000, "Offset field is valid/invalid", HFILL }
		},
		{ &hf_profinet_green_period_begin_offset,
			{ "GreenPeriodBegin.Offset",	"lldp.profinet.green_period_begin_offset", FT_UINT32, BASE_DEC,
			NULL, 0x7FFFFFFF, "Unrestricted period, offset to cycle begin in nanoseconds", HFILL }
		},
		{ &hf_cisco_subtype,
			{ "Cisco Subtype",	"lldp.cisco.subtype", FT_UINT8, BASE_HEX,
			VALS(cisco_subtypes), 0x0, NULL, HFILL }
		},
		{ &hf_cisco_four_wire_power,
			{ "Four-Wire Power-via-MDI", "lldp.cisco.four_wire_power", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_cisco_four_wire_power_poe,
			{ "PSE Four-Wire PoE", "lldp.cisco.four_wire_power.poe", FT_BOOLEAN, 8,
			TFS(&tfs_supported_not_supported), 0x01, NULL, HFILL }
		},
		{ &hf_cisco_four_wire_power_spare_pair_arch,
			{ "PD Spare Pair Architecture", "lldp.cisco.four_wire_power.spare_pair_arch", FT_BOOLEAN, 8,
			TFS(&tfs_shared_independent), 0x02, NULL, HFILL }
		},
		{ &hf_cisco_four_wire_power_req_spare_pair_poe,
			{ "PD Request Spare Pair PoE", "lldp.cisco.four_wire_power.req_spare_pair_poe", FT_BOOLEAN, 8,
			TFS(&tfs_on_off), 0x04, NULL, HFILL }
		},
		{ &hf_cisco_four_wire_power_pse_spare_pair_poe,
			{ "PSE Spare Pair PoE", "lldp.cisco.four_wire_power.pse_spare_pair_poe", FT_BOOLEAN, 8,
			TFS(&tfs_on_off), 0x08, NULL, HFILL }
		},
		{ &hf_unknown_subtype,
			{ "Unknown Subtype","lldp.unknown_subtype", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }
		},
		{ &hf_unknown_subtype_content,
			{ "Unknown Subtype Content","lldp.unknown_subtype.content", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_lldp,
		&ett_chassis_id,
		&ett_port_id,
		&ett_time_to_live,
		&ett_end_of_lldpdu,
		&ett_port_description,
		&ett_system_name,
		&ett_system_cap,
		&ett_system_cap_summary,
		&ett_system_cap_enabled,
		&ett_management_address,
		&ett_unknown_tlv,
		&ett_org_spc_tlv,
		&ett_org_spc_def,
		&ett_org_spc_ieee_802_1_1,
		&ett_org_spc_ieee_802_1_2,
		&ett_org_spc_ieee_802_1_3,
		&ett_org_spc_ieee_802_1_4,
		&ett_org_spc_ieee_802_3_1,
		&ett_org_spc_ieee_802_3_2,
		&ett_org_spc_ieee_802_3_3,
		&ett_org_spc_ieee_802_3_4,
		&ett_org_spc_media_1,
		&ett_org_spc_media_2,
		&ett_org_spc_media_3,
		&ett_org_spc_media_4,
		&ett_org_spc_media_5,
		&ett_org_spc_media_6,
		&ett_org_spc_media_7,
		&ett_org_spc_media_8,
		&ett_org_spc_media_9,
		&ett_org_spc_media_10,
		&ett_org_spc_media_11,
		&ett_org_spc_ProfinetSubTypes_1,
		&ett_org_spc_ProfinetSubTypes_2,
		&ett_org_spc_ProfinetSubTypes_3,
		&ett_org_spc_ProfinetSubTypes_4,
		&ett_org_spc_ProfinetSubTypes_5,
		&ett_org_spc_ProfinetSubTypes_6,
		&ett_port_vlan_flags,
		&ett_802_3_flags,
		&ett_802_3_autoneg_advertised,
		&ett_802_3_power,
		&ett_802_3_aggregation,
		&ett_802_1qbg_capabilities_flags,
		&ett_media_capabilities,
		&ett_profinet_period,
		&ett_cisco_fourwire_tlv
	};

	/* Register the protocol name and description */
	proto_lldp = proto_register_protocol("Link Layer Discovery Protocol", "LLDP", "lldp");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_lldp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	oui_unique_code_table = register_dissector_table("lldp.orgtlv.oui", "LLDP OUI", FT_UINT24, BASE_HEX );
}

void
proto_reg_handoff_lldp(void)
{
	dissector_handle_t lldp_handle;

	lldp_handle = create_dissector_handle(dissect_lldp,proto_lldp);
	dissector_add_uint("ethertype", ETHERTYPE_LLDP, lldp_handle);
}
