/* packet-bootp.c
 * Routines for BOOTP/DHCP packet disassembly
 *
 * Copyright 1998, Gilbert Ramirez <gram@alumni.rice.edu>
 * Copyright 2004, Thomas Anders <thomas.anders [AT] blue-cable.de>
 *
 * Added option field filters
 * Copyright 2011, Michael Mann
 *
 * Added option	 77 : RFC 3004 - The User Class Option for DHCP
 * Added option 117 : RFC 2937 - The Name Service Search Option for DHCP
 * Added option 119 : RFC 3397 - Dynamic Host Configuration Protocol (DHCP) Domain Search Option
 *		      RFC 3396 - Encoding Long Options in the Dynamic Host Configuration Protocol (DHCPv4)
 * Improved opt 120 : Add support of RFC 3396 - Encoding Long Options in the Dynamic Host Configuration Protocol (DHCPv4)
 *		      Add support compression according to the encoding in Section 4.1.4 of RFC 1035 - DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
 *
 *
 * Copyright 2012, Jerome LAFORGE <jerome.laforge [AT] gmail.com>
 *
 * The information used comes from:
 * RFC	951: Bootstrap Protocol
 * RFC 1035: Domain Names - Implementation And Specification
 * RFC 1497: BOOTP extensions
 * RFC 1542: Clarifications and Extensions for the Bootstrap Protocol
 * RFC 2131: Dynamic Host Configuration Protocol
 * RFC 2132: DHCP Options and BOOTP Vendor Extensions
 * RFC 2241: DHCP Options for Novell Directory Services
 * RFC 2242: NetWare/IP Domain Name and Information
 * RFC 2489: Procedure for Defining New DHCP Options
 * RFC 2610: DHCP Options for Service Location Protocol
 * RFC 2685: Virtual Private Networks Identifier
 * RFC 2937: The Name Service Search Option for DHCP
 * RFC 3004: The User Class Option for DHCP
 * RFC 3046: DHCP Relay Agent Information Option
 * RFC 3118: Authentication for DHCP Messages
 * RFC 3203: DHCP reconfigure extension
 * RFC 3315: Dynamic Host Configuration Protocol for IPv6 (DHCPv6)
 * RFC 3396: Encoding Long Options in the Dynamic Host Configuration Protocol (DHCPv4)
 * RFC 3397: Dynamic Host Configuration Protocol (DHCP) Domain Search Option
 * RFC 3495: DHCP Option (122) for CableLabs Client Configuration
 * RFC 3594: PacketCable Security Ticket Control Sub-Option (122.9)
 * RFC 3442: Classless Static Route Option for DHCP version 4
 * RFC 3825: Dynamic Host Configuration Protocol Option for Coordinate-based Location Configuration Information
 * RFC 3925: Vendor-Identifying Vendor Options for Dynamic Host Configuration Protocol version 4 (DHCPv4)
 * RFC 3942: Reclassifying DHCPv4 Options
 * RFC 4174: The IPv4 Dynamic Host Configuration Protocol (DHCP) Option for the Internet Storage Name Service
 * RFC 4243: Vendor-Specific Information Suboption for the Dynamic Host Configuration Protocol (DHCP) Relay Agent Option
 * RFC 4361: Node-specific Client Identifiers for Dynamic Host Configuration Protocol Version Four (DHCPv4)
 * RFC 4388: Dynamic Host Configuration Protocol (DHCP) Leasequery
 * RFC 4578: Dynamic Host Configuration Protocol (DHCP) Options for PXE
 * RFC 4776: Dynamic Host Configuration Protocol (DHCPv4 and DHCPv6) Option for Civic Addresses Configuration Information
 * RFC 5223: Discovering Location-to-Service Translation (LoST) Servers Using the Dynamic Host Configuration Protocol (DHCP)
 * RFC 5417: CAPWAP Access Controller DHCP Option
 * RFC 5969: IPv6 Rapid Deployment on IPv4 Infrastructures (6rd)
 * RFC 6607: Virtual Subnet Selection Options for DHCPv4 and DHCPv6
 * draft-ietf-dhc-fqdn-option-07.txt
 * TFTP Server Address Option for DHCPv4 [draft-raj-dhc-tftp-addr-option-06.txt: http://tools.ietf.org/html/draft-raj-dhc-tftp-addr-option-06]
 * BOOTP and DHCP Parameters
 *     http://www.iana.org/assignments/bootp-dhcp-parameters
 * DOCSIS(TM) 2.0 Radio Frequency Interface Specification
 *     http://www.cablelabs.com/specifications/CM-SP-RFI2.0-I11-060602.pdf
 * DOCSIS(TM) 3.0 MAC and Upper Layer Protocols Interface Specification
 *     http://www.cablelabs.com/specifications/CM-SP-MULPIv3.0-I20-121113.pdf
 * PacketCable(TM) 1.0 MTA Device Provisioning Specification
 *     http://www.cablelabs.com/packetcable/downloads/specs/PKT-SP-PROV-I11-050812.pdf
 *     http://www.cablelabs.com/specifications/archives/PKT-SP-PROV-I05-021127.pdf (superseded by above)
 * PacketCable(TM) 1.5 MTA Device Provisioning Specification
 *     http://www.cablelabs.com/packetcable/downloads/specs/PKT-SP-PROV1.5-I02-050812.pdf
 * PacketCable(TM) 2.0 EUE Device Provisioning Specification
 *     http://www.cablelabs.com/specifications/PKT-SP-EUE-DATA-I03-090528.pdf
 * Business Services over DOCSIS(R) Layer 2 Virtual Private Networks
 *     http://www.cablelabs.com/specifications/CM-SP-L2VPN-I09-100611.pdf
 * CableHome(TM) 1.1 Specification
 *     http://www.cablelabs.com/projects/cablehome/downloads/specs/CH-SP-CH1.1-I11-060407.pdf
 * Broadband Forum TR-111
 *     http://www.broadband-forum.org/technical/download/TR-111.pdf
 * Boot Server Discovery Protocol (BSDP)
 *     http://opensource.apple.com/source/bootp/bootp-198.1/Documentation/BSDP.doc
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * Some of the development of the BOOTP/DHCP protocol decoder was sponsored by
 * Cable Television Laboratories, Inc. ("CableLabs") based upon proprietary
 * CableLabs' specifications. Your license and use of this protocol decoder
 * does not mean that you are licensed to use the CableLabs'
 * specifications.  If you have questions about this protocol, contact
 * jf.mule [AT] cablelabs.com or c.stuart [AT] cablelabs.com for additional
 * information.
 */


#include "config.h"

#include <stdio.h>

#include <epan/packet.h>
#include <epan/exceptions.h>
#include "packet-arp.h"
#include "packet-dns.h"				/* for get_dns_name() */
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/arptypes.h>
#include <epan/sminmpec.h>
#include <epan/expert.h>
#include <epan/uat.h>
#include <epan/oui.h>
#include <wsutil/str_util.h>
void proto_register_bootp(void);
void proto_reg_handoff_bootp(void);

static int bootp_dhcp_tap = -1;
static int proto_bootp = -1;
static int hf_bootp_type = -1;
static int hf_bootp_hw_type = -1;
static int hf_bootp_hw_len = -1;
static int hf_bootp_hops = -1;
static int hf_bootp_id = -1;
static int hf_bootp_secs = -1;
static int hf_bootp_flags = -1;
static int hf_bootp_flags_broadcast = -1;
static int hf_bootp_flags_reserved = -1;
static int hf_bootp_ip_client = -1;
static int hf_bootp_ip_your = -1;
static int hf_bootp_ip_server = -1;
static int hf_bootp_ip_relay = -1;
static int hf_bootp_hw_addr = -1;
static int hf_bootp_hw_addr_padding = -1;
static int hf_bootp_hw_ether_addr = -1;
static int hf_bootp_server = -1;
static int hf_bootp_file = -1;
static int hf_bootp_cookie = -1;
static int hf_bootp_vendor_specific_options = -1;
static int hf_bootp_dhcp = -1;
static int hf_bootp_fqdn_flags = -1;
static int hf_bootp_fqdn_s = -1;
static int hf_bootp_fqdn_o = -1;
static int hf_bootp_fqdn_e = -1;
static int hf_bootp_fqdn_n = -1;
static int hf_bootp_fqdn_mbz = -1;
static int hf_bootp_fqdn_rcode1 = -1;
static int hf_bootp_fqdn_rcode2 = -1;
static int hf_bootp_fqdn_name = -1;
static int hf_bootp_fqdn_asciiname = -1;
static int hf_bootp_pkt_mta_cap_len = -1;
static int hf_bootp_pkt_mta_cap_type = -1;
static int hf_bootp_docsis_cm_cap_type = -1;
static int hf_bootp_docsis_cm_cap_len = -1;
static int hf_bootp_client_identifier_uuid = -1;
static int hf_bootp_client_id_iaid = -1;
static int hf_bootp_client_id_duid_type = -1;
static int hf_bootp_client_hardware_address = -1;
static int hf_bootp_client_identifier_duid_llt_hw_type = -1;
static int hf_bootp_client_identifier_duid_ll_hw_type = -1;
static int hf_bootp_client_identifier_time = -1;
static int hf_bootp_client_identifier_link_layer_address = -1;
static int hf_bootp_client_identifier_enterprise_num = -1;
static int hf_bootp_client_identifier = -1;
static int hf_bootp_client_identifier_type = -1;
static int hf_bootp_client_identifier_undef = -1;
static int hf_bootp_option_type = -1;
static int hf_bootp_option_length = -1;
static int hf_bootp_option_value = -1;
static int hf_bootp_option_value_8 = -1;
static int hf_bootp_option_value_16 = -1;
static int hf_bootp_option_value_u32 = -1;
static int hf_bootp_option_value_i32 = -1;
static int hf_bootp_option_value_stringz = -1;
static int hf_bootp_option_value_ip_address = -1;
static int hf_bootp_option_value_boolean = -1;
static int hf_bootp_suboption_length = -1;

static int hf_bootp_option_padding = -1;				/* 0 */
static int hf_bootp_option_subnet_mask = -1;				/* 1 */
static int hf_bootp_option_time_offset = -1;				/* 2 */
static int hf_bootp_option_router = -1;					/* 3 */
static int hf_bootp_option_time_server = -1;				/* 4 */
static int hf_bootp_option_name_server = -1;				/* 5 */
static int hf_bootp_option_domain_name_server = -1;			/* 6 */
static int hf_bootp_option_log_server = -1;				/* 7 */
static int hf_bootp_option_quotes_server = -1;				/* 8 */
static int hf_bootp_option_lpr_server = -1;				/* 9 */
static int hf_bootp_option_impress_server = -1;				/* 10 */
static int hf_bootp_option_resource_location_server = -1;		/* 11 */
static int hf_bootp_option_hostname = -1;				/* 12 */
static int hf_bootp_option_boot_file_size = -1;				/* 13 */
static int hf_bootp_option_merit_dump_file = -1;			/* 14 */
static int hf_bootp_option_domain_name = -1;				/* 15 */
static int hf_bootp_option_swap_server = -1;				/* 16 */
static int hf_bootp_option_root_path = -1;				/* 17 */
static int hf_bootp_option_extension_path = -1;				/* 18 */
static int hf_bootp_option_ip_forwarding = -1;				/* 19 */
static int hf_bootp_option_non_local_source_routing = -1;		/* 20 */
static int hf_bootp_option_policy_filter_ip = -1;			/* 21 - IP address */
static int hf_bootp_option_policy_filter_subnet_mask = -1;		/* 21 - Subnet mask */
static int hf_bootp_option_max_datagram_reassembly_size = -1;		/* 22 */
static int hf_bootp_option_default_ip_ttl = -1;				/* 23 */
static int hf_bootp_option_path_mtu_aging_timeout = -1;			/* 24 */
static int hf_bootp_option_path_mtu_plateau_table_item = -1;		/* 25 */
static int hf_bootp_option_interface_mtu = -1;				/* 26 */
static int hf_bootp_option_all_subnets_are_local = -1;			/* 27 */
static int hf_bootp_option_broadcast_address = -1;			/* 28 */
static int hf_bootp_option_perform_mask_discovery = -1;			/* 29 */
static int hf_bootp_option_mask_supplier = -1;				/* 30 */
static int hf_bootp_option_perform_router_discover = -1;		/* 31 */
static int hf_bootp_option_router_solicitation_address = -1;		/* 32 */
static int hf_bootp_option_static_route_ip = -1;			/* 33 - Destination IP */
static int hf_bootp_option_static_route_router = -1;			/* 33 - Router */
static int hf_bootp_option_trailer_encapsulation = -1;			/* 34 */
static int hf_bootp_option_arp_cache_timeout = -1;			/* 35 */
static int hf_bootp_option_ethernet_encapsulation = -1;			/* 36 */
static int hf_bootp_option_tcp_default_ttl = -1;			/* 37 */
static int hf_bootp_option_tcp_keepalive_interval = -1;			/* 38 */
static int hf_bootp_option_tcp_keepalive_garbage = -1;			/* 39 */
static int hf_bootp_option_nis_domain = -1;				/* 40 */
static int hf_bootp_option_nis_server = -1;				/* 41 */
static int hf_bootp_option_ntp_server = -1;				/* 42 */

static int hf_bootp_option43_value = -1;				/* 43 suboption value */
static int hf_bootp_option43_value_8 = -1;				/* 43 suboption value */
static int hf_bootp_option43_value_32 = -1;				/* 43 suboption value */
static int hf_bootp_option43_value_stringz = -1;			/* 43 suboption value */
static int hf_bootp_option43_value_ip_address = -1;			/* 43 suboption value */

static int hf_bootp_option43_pxeclient_suboption = -1;			/* 43 suboption */
static int hf_bootp_option43_pxeclient_padding = -1;			/* 43:0 PXE  */
static int hf_bootp_option43_pxeclient_mtftp_ip = -1;			/* 43:1 PXE  */
static int hf_bootp_option43_pxeclient_mtftp_client_port = -1;		/* 43:2 PXE  */
static int hf_bootp_option43_pxeclient_mtftp_server_port = -1;		/* 43:3 PXE  */
static int hf_bootp_option43_pxeclient_mtftp_timeout = -1;		/* 43:4 PXE  */
static int hf_bootp_option43_pxeclient_mtftp_delay = -1;		/* 43:5 PXE  */
static int hf_bootp_option43_pxeclient_discovery_control = -1;		/* 43:6 PXE  */
static int hf_bootp_option43_pxeclient_multicast_address = -1;		/* 43:7 PXE  */
static int hf_bootp_option43_pxeclient_boot_servers = -1;		/* 43:8 PXE  */
static int hf_bootp_option43_pxeclient_boot_menu = -1;			/* 43:9 PXE  */
static int hf_bootp_option43_pxeclient_menu_prompt = -1;		/* 43:10 PXE  */
static int hf_bootp_option43_pxeclient_multicast_address_alloc = -1;	/* 43:11 PXE  */
static int hf_bootp_option43_pxeclient_credential_types = -1;		/* 43:12 PXE  */
static int hf_bootp_option43_pxeclient_boot_item = -1;			/* 43:71 PXE  */
static int hf_bootp_option43_pxeclient_end = -1;			/* 43:255 PXE */

static int hf_bootp_option43_cl_suboption = -1;				/* 43 suboption */
static int hf_bootp_option43_cl_padding = -1;				/* 43:0 CL  */
static int hf_bootp_option43_cl_suboption_request_list = -1;		/* 43:1 CL  */
static int hf_bootp_option43_cl_device_type = -1;			/* 43:2 CL  */
static int hf_bootp_option43_cl_esafe_type = -1;			/* 43:3 CL  */
static int hf_bootp_option43_cl_serial_number = -1;			/* 43:4 CL  */
static int hf_bootp_option43_cl_hardware_version = -1;			/* 43:5 CL  */
static int hf_bootp_option43_cl_software_version = -1;			/* 43:6 CL  */
static int hf_bootp_option43_cl_boot_rom_version = -1;			/* 43:7 CL  */
static int hf_bootp_option43_cl_oui_bytes = -1;				/* 43:8 CL  */
static int hf_bootp_option43_cl_oui_string = -1;			/* 43:8 CL  */
static int hf_bootp_option43_cl_model_number = -1;			/* 43:9 CL  */
static int hf_bootp_option43_cl_vendor_name10 = -1;			/* 43:10 CL  */
static int hf_bootp_option43_cl_address_realm = -1;			/* 43:11 CL  */
static int hf_bootp_option43_cl_cm_ps_system_desc = -1;			/* 43:12 CL  */
static int hf_bootp_option43_cl_cm_ps_firmware_revision = -1;		/* 43:13 CL  */
static int hf_bootp_option43_cl_firewall_policy_file_version = -1;	/* 43:14 CL  */
static int hf_bootp_option43_cl_esafe_config_file_devices = -1;		/* 43:15 CL  */
static int hf_bootp_option43_cl_video_security_tape = -1;		/* 43:18 CL  */
static int hf_bootp_option43_cl_mta_mac_address = -1;			/* 43:31 CL  */
static int hf_bootp_option43_cl_correlation_ID = -1;			/* 43:32 CL  */
static int hf_bootp_option43_cl_vendor_name51 = -1;			/* 43:51 CL  */
static int hf_bootp_option43_cl_cablecard_capability = -1;		/* 43:52 CL  */
static int hf_bootp_option43_cl_device_id_ca = -1;			/* 43:53 CL  */
static int hf_bootp_option43_cl_device_id_x509 = -1;			/* 43:54 CL  */
static int hf_bootp_option43_cl_end = -1;				/* 43:255 CL */

static int hf_bootp_option43_bsdp_suboption = -1;			/* 43 suboption */
static int hf_bootp_option43_bsdp_message_type = -1;			/* 43:1 BSDP  */
static int hf_bootp_option43_bsdp_version = -1;				/* 43:2 BSDP  */
static int hf_bootp_option43_bsdp_server_identifier = -1;		/* 43:3 BSDP  */
static int hf_bootp_option43_bsdp_server_priority = -1;			/* 43:4 BSDP  */
static int hf_bootp_option43_bsdp_reply_port = -1;			/* 43:5 BSDP  */
static int hf_bootp_option43_bsdp_boot_image_list_path = -1;		/* 43:6 BSDP  */
static int hf_bootp_option43_bsdp_default_boot_image_id = -1;		/* 43:7 BSDP  */
static int hf_bootp_option43_bsdp_selected_boot_image_id = -1;		/* 43:8 BSDP  */
static int hf_bootp_option43_bsdp_boot_image_list = -1;			/* 43:9 BSDP  */
static int hf_bootp_option43_bsdp_netboot_firmware = -1;		/* 43:10 BSDP  */
static int hf_bootp_option43_bsdp_attributes_filter_list = -1;		/* 43:11 BSDP  */
static int hf_bootp_option43_bsdp_message_size = -1;			/* 43:12 BSDP  */
static int hf_bootp_option43_bsdp_boot_image_index = -1;		/* 43 BSDP  */
static int hf_bootp_option43_bsdp_boot_image_attribute = -1;		/* 43 BSDP  */
static int hf_bootp_option43_bsdp_boot_image_attribute_install = -1;	/* 43 BSDP  */
static int hf_bootp_option43_bsdp_boot_image_attribute_kind = -1;	/* 43 BSDP  */
static int hf_bootp_option43_bsdp_boot_image_attribute_reserved = -1;	/* 43 BSDP  */
static int hf_bootp_option43_bsdp_image_desc = -1;			/* 43 BSDP  */
static int hf_bootp_option43_bsdp_boot_image_name = -1;			/* 43 BSDP  */
static int hf_bootp_option43_bsdp_boot_image_name_len = -1;		/* 43 BSDP  */

static int hf_bootp_option43_alcatel_suboption = -1;			/* 43 suboption */
static int hf_bootp_option43_alcatel_padding = -1;			/* 43:0 Alcatel	 */
static int hf_bootp_option43_alcatel_vlan_id = -1;			/* 43:58 Alcatel  */
static int hf_bootp_option43_alcatel_tftp1 = -1;			/* 43:64 Alcatel  */
static int hf_bootp_option43_alcatel_tftp2 = -1;			/* 43:65 Alcatel  */
static int hf_bootp_option43_alcatel_app_type = -1;			/* 43:66 Alcatel  */
static int hf_bootp_option43_alcatel_sip_url = -1;			/* 43:67 Alcatel  */
static int hf_bootp_option43_alcatel_end = -1;				/* 43:255 Alcatel */

static int hf_bootp_option43_arubaap_controllerip = -1;			/* 43: ArubaAP*/
static int hf_bootp_option43_arubaiap = -1;				/* 43: ArubaIAP*/
static int hf_bootp_option43_arubaiap_nameorg = -1;			/* 43: ArubaIAP: Name Organisation*/
static int hf_bootp_option43_arubaiap_ampip = -1;			/* 43: ArubaIAP: AMP IP Address*/
static int hf_bootp_option43_arubaiap_password = -1;			/* 43 :ArubaIAP: Password*/

static int hf_bootp_option_netbios_over_tcpip_name_server = -1;		/* 44 */
static int hf_bootp_option_netbios_over_tcpip_dd_name_server = -1;	/* 45 */
static int hf_bootp_option_netbios_over_tcpip_node_type = -1;		/* 46 */
static int hf_bootp_option_netbios_over_tcpip_scope = -1;		/* 47 */
static int hf_bootp_option_xwindows_system_font_server = -1;		/* 48 */
static int hf_bootp_option_xwindows_system_display_manager = -1;	/* 49 */
static int hf_bootp_option_requested_ip_address = -1;			/* 50 */
static int hf_bootp_option_ip_address_lease_time = -1;			/* 51 */
static int hf_bootp_option_option_overload = -1;			/* 52 */
static int hf_bootp_option_dhcp = -1;					/* 53 */
static int hf_bootp_option_dhcp_server_id = -1;				/* 54 */
static int hf_bootp_option_parameter_request_list_item = -1;		/* 55 */
static int hf_bootp_option_message = -1;				/* 56 */
static int hf_bootp_option_dhcp_max_message_size = -1;			/* 57 */
static int hf_bootp_option_renewal_time_value = -1;			/* 58 */
static int hf_bootp_option_rebinding_time_value = -1;			/* 59 */
static int hf_bootp_option_vendor_class_id = -1;			/* 60 */
static int hf_bootp_option_vendor_class_data = -1;			/* 60 */

static int hf_bootp_option_novell_netware_ip_domain = -1;		/* 62 */

static int hf_bootp_option63_suboption = -1;				/* 63 suboption */
static int hf_bootp_option63_value = -1;				/* 63 suboption value */
static int hf_bootp_option63_value_8 = -1;				/* 63 suboption value */
static int hf_bootp_option63_value_ip_address = -1;			/* 63 suboption value */
static int hf_bootp_option63_value_boolean = -1;			/* 63 suboption value */
static int hf_bootp_option63_broadcast = -1;				/* 63:5 */
static int hf_bootp_option63_preferred_dss_server = -1;			/* 63:6 */
static int hf_bootp_option63_nearest_nwip_server = -1;			/* 63:7 */
static int hf_bootp_option63_autoretries = -1;				/* 63:8 */
static int hf_bootp_option63_autoretry_delay = -1;			/* 63:9 */
static int hf_bootp_option63_support_netware_v1_1 = -1;			/* 63:10 */
static int hf_bootp_option63_primary_dss = -1;				/* 63:11 */

static int hf_bootp_option_nis_plus_domain = -1;			/* 64 */
static int hf_bootp_option_nis_plus_server = -1;			/* 65 */
static int hf_bootp_option_tftp_server_name = -1;			/* 66 */
static int hf_bootp_option_bootfile_name = -1;				/* 67 */
static int hf_bootp_option_mobile_ip_home_agent = -1;			/* 68 */
static int hf_bootp_option_smtp_server = -1;				/* 69 */
static int hf_bootp_option_pop3_server = -1;				/* 70 */
static int hf_bootp_option_nntp_server = -1;				/* 71 */
static int hf_bootp_option_default_www_server = -1;			/* 72 */
static int hf_bootp_option_default_finger_server = -1;			/* 73 */
static int hf_bootp_option_default_irc_server = -1;			/* 74 */
static int hf_bootp_option_streettalk_server = -1;			/* 75 */
static int hf_bootp_option_streettalk_da_server = -1;			/* 76 */
static int hf_bootp_option77_user_class = -1;				/* 77 User Class instance */
static int hf_bootp_option77_user_class_length = -1;			/* 77 length of User Class instance */
static int hf_bootp_option77_user_class_data = -1;			/* 77 data of User Class instance */
static int hf_bootp_option_slp_directory_agent_value = -1;		/* 78 */
static int hf_bootp_option_slp_directory_agent_slpda_address = -1;	/* 78 */
static int hf_bootp_option_slp_service_scope_value = -1;		/* 79 */
static int hf_bootp_option_slp_service_scope_string = -1;		/* 79 */

static int hf_bootp_option82_suboption = -1;				/* 82 suboption */
static int hf_bootp_option82_value = -1;				/* 82 suboption value */
static int hf_bootp_option82_value_8 = -1;				/* 82 suboption value */
static int hf_bootp_option82_value_32 = -1;				/* 82 suboption value */
static int hf_bootp_option82_value_ip_address = -1;			/* 82 suboption value */
static int hf_bootp_option82_value_stringz = -1;			/* 82 suboption value */
static int hf_bootp_option82_padding = -1;				/* 82:0 */
static int hf_bootp_option82_agent_circuit_id = -1;			/* 82:1 */
static int hf_bootp_option82_agent_remote_id = -1;			/* 82:2 */
static int hf_bootp_option82_reserved = -1;				/* 82:3 */
static int hf_bootp_option82_docsis_device_class = -1;			/* 82:4 */
static int hf_bootp_option82_link_selection = -1;			/* 82:5 */
static int hf_bootp_option82_subscriber_id = -1;			/* 82:6 */
static int hf_bootp_option82_radius_attributes = -1;			/* 82:7 */
static int hf_bootp_option82_authentication = -1;			/* 82:8 */
static int hf_bootp_option82_vi = -1;					/* 82:9 */
									/* 82:9 suboptions */
static int hf_bootp_option82_vi_enterprise = -1;
static int hf_bootp_option82_vi_data_length = -1;
static int hf_bootp_option82_vi_cl_option = -1;
static int hf_bootp_option82_vi_cl_length = -1;
static int hf_bootp_option82_vi_cl_tag = -1;
static int hf_bootp_option82_vi_cl_tag_length = -1;
static int hf_bootp_option82_vi_cl_docsis_version = -1;
									/* 82:9 suboptions end */
static int hf_bootp_option82_flags = -1;				/* 82:10 */
static int hf_bootp_option82_server_id_override = -1;			/* 82:11 */
static int hf_bootp_option82_link_selection_cisco = -1;			/* 82:150 */
static int hf_bootp_option82_vrf_name_vpn_id = -1;			/* 82:151 */
									/* 82:151 suboptions */
static int hf_bootp_option82_vrf_name_global = -1;
static int hf_bootp_option82_vrf_name = -1;
static int hf_bootp_option82_vrf_name_vpn_id_oui = -1;
static int hf_bootp_option82_vrf_name_vpn_id_index = -1;
									/* 82:151 suboptions end */
static int hf_bootp_option82_server_id_override_cisco = -1;		/* 82:152 */

static int hf_bootp_option_isns_functions = -1;
static int hf_bootp_option_isns_functions_enabled = -1;
static int hf_bootp_option_isns_functions_dd_authorization = -1;
static int hf_bootp_option_isns_functions_sec_policy_distibution = -1;
static int hf_bootp_option_isns_functions_reserved = -1;

static int hf_bootp_option_isns_discovery_domain_access = -1;
static int hf_bootp_option_isns_discovery_domain_access_enabled = -1;
static int hf_bootp_option_isns_discovery_domain_access_control_node = -1;
static int hf_bootp_option_isns_discovery_domain_access_iscsi_target = -1;
static int hf_bootp_option_isns_discovery_domain_access_iscsi_inititator = -1;
static int hf_bootp_option_isns_discovery_domain_access_ifcp_target_port = -1;
static int hf_bootp_option_isns_discovery_domain_access_ifcp_initiator_port = -1;
static int hf_bootp_option_isns_discovery_domain_access_reserved = -1;

static int hf_bootp_option_isns_administrative_flags = -1;
static int hf_bootp_option_isns_administrative_flags_enabled = -1;
static int hf_bootp_option_isns_administrative_flags_heartbeat = -1;
static int hf_bootp_option_isns_administrative_flags_management_scns = -1;
static int hf_bootp_option_isns_administrative_flags_default_dd = -1;
static int hf_bootp_option_isns_administrative_flags_reserved = -1;

static int hf_bootp_option_isns_server_security_bitmap = -1;
static int hf_bootp_option_isns_server_security_bitmap_enabled = -1;
static int hf_bootp_option_isns_server_security_bitmap_ike_ipsec_enabled = -1;
static int hf_bootp_option_isns_server_security_bitmap_main_mode = -1;
static int hf_bootp_option_isns_server_security_bitmap_aggressive_mode = -1;
static int hf_bootp_option_isns_server_security_bitmap_pfs = -1;
static int hf_bootp_option_isns_server_security_bitmap_transport_mode = -1;
static int hf_bootp_option_isns_server_security_bitmap_tunnel_mode = -1;
static int hf_bootp_option_isns_server_security_bitmap_reserved = -1;

static int hf_bootp_option_isns_heartbeat_originator_addr = -1;
static int hf_bootp_option_isns_primary_server_addr = -1;
static int hf_bootp_option_isns_secondary_server_addr_list = -1;

static int hf_bootp_option_novell_dss_string = -1;			/* 85 */
static int hf_bootp_option_novell_dss_ip = -1;				/* 85 */
static int hf_bootp_option_novell_ds_tree_name = -1;			/* 86 */
static int hf_bootp_option_novell_ds_context = -1;			/* 87 */
static int hf_bootp_option_dhcp_authentication_protocol = -1;		/* 90 */
static int hf_bootp_option_dhcp_authentication_alg_delay = -1;		/* 90 */
static int hf_bootp_option_dhcp_authentication_algorithm = -1;		/* 90 */
static int hf_bootp_option_dhcp_authentication_rdm = -1;		/* 90 */
static int hf_bootp_option_dhcp_authentication_rdm_replay_detection = -1;   /* 90 */
static int hf_bootp_option_dhcp_authentication_rdm_rdv = -1;		/* 90 */
static int hf_bootp_option_dhcp_authentication_secret_id = -1;		/* 90 */
static int hf_bootp_option_dhcp_authentication_hmac_md5_hash = -1;	/* 90 */
static int hf_bootp_option_dhcp_authentication_information = -1;	/* 90 */
static int hf_bootp_option_client_last_transaction_time = -1;		/* 91 */
static int hf_bootp_option_associated_ip_option = -1;			/* 92 */
static int hf_bootp_option_client_system_architecture = -1;		/* 93 */
static int hf_bootp_option_client_network_id_major_ver = -1;		/* 94 */
static int hf_bootp_option_client_network_id_minor_ver = -1;		/* 94 */
static int hf_bootp_option_civic_location_what = -1;			/* 99 */
static int hf_bootp_option_civic_location_country = -1;			/* 99 */
static int hf_bootp_option_civic_location_ca_type = -1;			/* 99 */
static int hf_bootp_option_civic_location_ca_length = -1;		/* 99 */
static int hf_bootp_option_civic_location_ca_value = -1;		/* 99 */
static int hf_bootp_option_netinfo_parent_server_address = -1;		/* 112 */
static int hf_bootp_option_netinfo_parent_server_tag = -1;		/* 113 */
static int hf_bootp_option_dhcp_auto_configuration = -1;		/* 116 */
static int hf_bootp_option_dhcp_name_service_search_option = -1;		/* 117 */
static int hf_bootp_option_dhcp_dns_domain_search_list_rfc_3396_detected = -1;	/* 119 */
static int hf_bootp_option_dhcp_dns_domain_search_list_refer_last_option = -1;	/* 119 */
static int hf_bootp_option_dhcp_dns_domain_search_list_fqdn = -1;		/* 119 */
static int hf_bootp_option_sip_server_rfc_3396_detected = -1;			/* 120 */
static int hf_bootp_option_sip_server_refer_last_option = -1;			/* 120 */
static int hf_bootp_option_sip_server_enc = -1;				/* 120 */
static int hf_bootp_option_sip_server_name = -1;				/* 120 */
static int hf_bootp_option_sip_server_address = -1;				/* 120 */
static int hf_bootp_option_sip_server_address_stringz = -1;		/* 120 */
static int hf_bootp_option_classless_static_route = -1;			/* 120 */
static int hf_bootp_option_rfc3825_error = -1;					/* 123 */
static int hf_bootp_option_rfc3825_latitude = -1;				/* 123 */
static int hf_bootp_option_rfc3825_longitude = -1;				/* 123 */
static int hf_bootp_option_rfc3825_latitude_res = -1;			/* 123 */
static int hf_bootp_option_rfc3825_longitude_res = -1;			/* 123 */
static int hf_bootp_option_rfc3825_altitude = -1;				/* 123 */
static int hf_bootp_option_rfc3825_altitide_res = -1;			/* 123 */
static int hf_bootp_option_rfc3825_altitude_type = -1;			/* 123 */
static int hf_bootp_option_rfc3825_map_datum = -1;				/* 123 */
static int hf_bootp_option_cl_dss_id_option = -1;			/* 123 CL */
static int hf_bootp_option_cl_dss_id_len = -1;				/* 123 CL */
static int hf_bootp_option_cl_dss_id = -1;				/* 123 CL */
static int hf_bootp_option_vi_class_cl_address_mode = -1;		/* 124 */
static int hf_bootp_option_vi_class_enterprise = -1;			/* 124 */
static int hf_bootp_option_vi_class_data_length = -1;			/* 124 */
static int hf_bootp_option_vi_class_data = -1;				/* 124 */

static int hf_bootp_option125_enterprise = -1;
static int hf_bootp_option125_length = -1;
static int hf_bootp_option125_value = -1;				/* 125 suboption value */
static int hf_bootp_option125_value_8 = -1;				/* 125 suboption value */
static int hf_bootp_option125_value_16 = -1;				/* 125 suboption value */
static int hf_bootp_option125_value_ip_address = -1;			/* 125 suboption value */
static int hf_bootp_option125_value_stringz = -1;			/* 125 suboption value */
static int hf_bootp_option125_tr111_suboption = -1;			/* 125 suboption */
static int hf_bootp_option125_tr111_device_manufacturer_oui = -1;	/* 125:TR-111 1 */
static int hf_bootp_option125_tr111_device_serial_number = -1;		/* 125:TR-111 2 */
static int hf_bootp_option125_tr111_device_product_class = -1;		/* 125:TR-111 3 */
static int hf_bootp_option125_tr111_gateway_manufacturer_oui = -1;	/* 125:TR-111 4 */
static int hf_bootp_option125_tr111_gateway_serial_number = -1;		/* 125:TR-111 5 */
static int hf_bootp_option125_tr111_gateway_product_class = -1;		/* 125:TR-111 6 */
static int hf_bootp_option125_cl_suboption = -1;			/* 125 suboption */
static int hf_bootp_option125_cl_option_request = -1;			/* 125:CL 1 */
static int hf_bootp_option125_cl_tftp_server_addresses = -1;		/* 125:CL 2 */
static int hf_bootp_option125_cl_erouter_container_option = -1;		/* 125:CL 3 */
static int hf_bootp_option125_cl_mib_environment_indicator_option = -1; /* 125:CL 4 */
static int hf_bootp_option125_cl_modem_capabilities = -1;		/* 125:CL 5 */

static int hf_bootp_option_subnet_selection_option = -1;		/* 118 */
static int hf_bootp_option_lost_server_domain_name = -1;		/* 137 */
static int hf_bootp_option_capwap_access_controller = -1;		/* 138 */
static int hf_bootp_option_tftp_server_address = -1;			/* 150 */
static int hf_bootp_option_pxe_config_file = -1;			/* 209 */
static int hf_bootp_option_pxe_path_prefix = -1;			/* 210 */
static int hf_bootp_option_6RD_ipv4_mask_len = -1;			/* 212 */
static int hf_bootp_option_6RD_prefix_len = -1;				/* 212 */
static int hf_bootp_option_6RD_prefix = -1;				/* 212 */
static int hf_bootp_option_6RD_border_relay_ip = -1;			/* 212 */
static int hf_bootp_option242_avaya = -1;				/* 242 */
static int hf_bootp_option242_avaya_tlssrvr = -1;			/* 242 */
static int hf_bootp_option242_avaya_httpsrvr = -1;			/* 242 */
static int hf_bootp_option242_avaya_httpdir = -1;			/* 242 */
static int hf_bootp_option242_avaya_static = -1;			/* 242 */
static int hf_bootp_option242_avaya_mcipadd = -1;			/* 242 */
static int hf_bootp_option242_avaya_dot1x = -1;				/* 242 */
static int hf_bootp_option242_avaya_icmpdu = -1;			/* 242 */
static int hf_bootp_option242_avaya_icmpred = -1;			/* 242 */
static int hf_bootp_option242_avaya_l2q = -1;				/* 242 */
static int hf_bootp_option242_avaya_l2qvlan = -1;			/* 242 */
static int hf_bootp_option242_avaya_loglocal = -1;			/* 242 */
static int hf_bootp_option242_avaya_phy1stat = -1;			/* 242 */
static int hf_bootp_option242_avaya_phy2stat = -1;			/* 242 */
static int hf_bootp_option242_avaya_procpswd = -1;			/* 242 */
static int hf_bootp_option242_avaya_procstat = -1;			/* 242 */
static int hf_bootp_option242_avaya_snmpadd = -1;			/* 242 */
static int hf_bootp_option242_avaya_snmpstring = -1;			/* 242 */
static int hf_bootp_option242_avaya_vlantest = -1;			/* 242 */
static int hf_bootp_option_private_proxy_autodiscovery = -1;		/* 252 */
static int hf_bootp_option_end = -1;					/* 255 */
static int hf_bootp_option_end_overload = -1;				/* 255 (with overload)*/
static int hf_bootp_vendor_unknown_suboption = -1;
static int hf_bootp_suboption_data = -1;
static int hf_bootp_pc_ietf_ccc_suboption = -1;
static int hf_bootp_pc_i05_ccc_suboption = -1;

static int hf_bootp_cl_ietf_ccc_dev_realm_unc_key_nom_timeout = -1;
static int hf_bootp_cl_ietf_ccc_dev_realm_unc_key_max_timeout = -1;
static int hf_bootp_cl_ietf_ccc_dev_realm_unc_key_max_retries = -1;
static int hf_bootp_cl_ietf_ccc_dev_prov_unc_key_nom_timeout = -1;
static int hf_bootp_cl_ietf_ccc_dev_prov_unc_key_max_timeout = -1;
static int hf_bootp_cl_ietf_ccc_dev_prov_unc_key_max_retries = -1;

static gint ett_bootp = -1;
static gint ett_bootp_flags = -1;
static gint ett_bootp_option = -1;
static gint ett_bootp_option43_suboption = -1;
static gint ett_bootp_option63_suboption = -1;
static gint ett_bootp_option77_instance = -1;
static gint ett_bootp_option82_suboption = -1;
static gint ett_bootp_option82_suboption9 = -1;
static gint ett_bootp_option125_suboption = -1;
static gint ett_bootp_option125_tr111_suboption = -1;
static gint ett_bootp_option125_cl_suboption = -1;
static gint ett_bootp_option242_suboption = -1;
static gint ett_bootp_fqdn = -1;
static gint ett_bootp_fqdn_flags = -1;
static gint ett_bootp_filename_option = -1;
static gint ett_bootp_server_hostname = -1;
static gint ett_bootp_isns_functions = -1;
static gint ett_bootp_isns_discovery_domain_access = -1;
static gint ett_bootp_isns_administrative_flags = -1;
static gint ett_bootp_isns_server_security_bitmap = -1;
static gint ett_bootp_isns_secondary_server_addr = -1;
static gint ett_bootp_o43_bsdp_boot_image = -1;
static gint ett_bootp_o43_bsdp_attributes = -1;
static gint ett_bootp_o43_bsdp_image_desc_list = -1;
static gint ett_bootp_o43_bsdp_image_desc = -1;
static gint ett_bootp_o43_bsdp_attributes_flags = -1;

static expert_field ei_bootp_bad_length = EI_INIT;
static expert_field ei_bootp_bad_bitfield = EI_INIT;
static expert_field ei_bootp_missing_subopt_length = EI_INIT;
static expert_field ei_bootp_missing_subopt_value = EI_INIT;
static expert_field ei_bootp_mal_duid = EI_INIT;
static expert_field hf_bootp_opt_overload_file_end_missing = EI_INIT;
static expert_field hf_bootp_opt_overload_sname_end_missing = EI_INIT;
static expert_field hf_bootp_subopt_unknown_type = EI_INIT;
static expert_field ei_bootp_option77_user_class_malformed = EI_INIT;
static expert_field ei_bootp_option_civic_location_bad_cattype = EI_INIT;
static expert_field ei_bootp_option_dhcp_name_service_invalid = EI_INIT;
static expert_field ei_bootp_option_sip_server_address_encoding = EI_INIT;
static expert_field ei_bootp_option_classless_static_route = EI_INIT;
static expert_field ei_bootp_option125_enterprise_malformed = EI_INIT;
static expert_field ei_bootp_option_6RD_malformed = EI_INIT;
static expert_field ei_bootp_option82_vi_cl_tag_unknown = EI_INIT;
static expert_field ei_bootp_option_parse_err = EI_INIT;
static expert_field ei_bootp_suboption_invalid = EI_INIT;
static expert_field ei_bootp_secs_le = EI_INIT;
static expert_field ei_bootp_end_option_missing = EI_INIT;
static expert_field ei_bootp_client_address_not_given = EI_INIT;
static expert_field ei_bootp_server_name_overloaded_by_dhcp = EI_INIT;
static expert_field ei_bootp_boot_filename_overloaded_by_dhcp = EI_INIT;
static expert_field ei_bootp_option_isns_ignored_bitfield = EI_INIT;

static dissector_handle_t bootp_handle;

/* RFC2937 The Name Service Search Option for DHCP */
#define RFC2937_LOCAL_NAMING_INFORMATION			   0
#define RFC2937_DOMAIN_NAME_SERVER_OPTION			   6
#define RFC2937_NETWORK_INFORMATION_SERVERS_OPTION		  41
#define RFC2937_NETBIOS_OVER_TCP_IP_NAME_SERVER_OPTION		  44
#define RFC2937_NETWORK_INFORMATION_SERVICE_PLUS_SERVERS_OPTION	  65

/* RFC3825decoder error codes of the conversion function */
#define RFC3825_NOERROR				  0
#define RFC3825_LATITUDE_OUTOFRANGE		  1
#define RFC3825_LATITUDE_UNCERTAINTY_OUTOFRANGE	  2
#define RFC3825_LONGITUDE_OUTOFRANGE		  3
#define RFC3825_LONGITUDE_UNCERTAINTY_OUTOFRANGE  4
#define RFC3825_ALTITUDE_OUTOFRANGE		  5
#define RFC3825_ALTITUDE_UNCERTAINTY_OUTOFRANGE	  6
#define RFC3825_ALTITUDE_TYPE_OUTOFRANGE	  7
#define RFC3825_DATUM_TYPE_OUTOFRANGE		  8

#define	DUID_LLT		1
#define	DUID_EN			2
#define	DUID_LL			3

struct rfc3825_location_fixpoint_t {

	gint64 latitude;	/* latitude in degrees, allowed range from -90deg to 90deg.
				   Fixpoint A(8,25) with 34 bits */
	guint8 latitude_res;	/* the resolution of the latitude in bits, allowed range is from 0 to 34.
				   6 bits. */
	gint64 longitude;	/* longitude in degrees, range from -180deg to 180deg.
				   Fixpoint A(8,25) with 34 bits */
	guint8 longitude_res;	/* the resolution of the longitude in bits, allowed range is from 0 to 34.
				   6 bits. */
	gint32 altitude;	/* the altitude, 30 bits.
				   Depending on alt_type this are meters or floors, no range limit.
				   altitude_type==1: A(13,8) with 22 bits
				   altitude_type==2: A(13,8) with 22 bits */
	guint8 altitude_res;	/* the resolution of the altitude in bits, allowed range is from 0 to 30.
				   6 bits.
				   altitude_type==1: any value between 0 and 30
				   altitude_type==2: either 0 (floor unknown) or 30 */
	guint8 altitude_type;	/* the type of the altitude, 4 bits. allowed values are:
				   0: unknown
				   1: altitude in meters
				   2: altitude in floors */
	guint8 datum_type;	/* the map datum used for the coordinates. 8 bits.
				   All values are allowed although currently only the
				   following ones are defined:
				   1: WGS84
				   2: NAD83/NAVD88
				   3: NAD83/MLLW */
};

/* The rfc3825_location_decimal_t structure holds the location parameters
 * in decimal (floating point) format.
 */
struct rfc3825_location_decimal_t {

	double latitude;	/* latitude in degrees, allowed range from -90deg to 90deg */
	double latitude_res;	/* the uncertainty of the latitude in grad, "0.01" means +-0.01deg
				   from the altitude. During conversion this will be rounded to
				   next smaller value which can be represented in fixpoint arithmetic */
	double longitude;	/* longitude in degrees, range from -180deg to 180deg */
	double longitude_res;	/* the uncertainty of the longitude in grad, "0.01" means +-0.01deg
				   from the longitude. During conversion this will be rounded to
				   next smaller value which can be represented in fixpoint arithmetic */
	double altitude;	/* the altitude, depending on alt_type this are meters or floors, no range limit */
	double altitude_res;	/* the uncertainty of the altitude in either:
				   - altitude-type=meters: "10" means 10 meters which means +-10 meters from the altitude
				   - altitude-type=floors: either 0 (unknown) or 30 (exact) */
	int altitude_type;	/* the type of the altitude, allowed values are
				   0: unknown
				   1: altitude in meters
				   2: altitude in floors */
	int datum_type;		 /* the map datum used for the coordinates.
				    All values are allowed although currently only the
				    following ones are defined:
				    1: WGS84
				    2: NAD83/NAVD88
				    3: NAD83/MLLW */
};

/* For managing split options with RFC 3396 */
struct rfc3396_for_option_t {
	unsigned int total_number_of_block;
	unsigned int index_current_block;
	tvbuff_t* tvb_composite;
};

/* The RFC 3397 allows to cut long option (RFC 3396). */
struct rfc3396_for_option_t rfc3396_dns_domain_search_list;

/* The RFC 3361 allows to cut long option (RFC 3396). */
struct rfc3396_for_option_t rfc3396_sip_server;

enum {
	RFC_3361_ENC_FQDN,
	RFC_3361_ENC_IPADDR
};

static void dissect_vendor_avaya_param(proto_tree *tree, packet_info *pinfo, proto_item *vti,
		tvbuff_t *tvb, int optoff, wmem_strbuf_t *avaya_param_buf);

/* converts fixpoint presentation into decimal presentation
   also converts values which are out of range to allow decoding of received data */
static int rfc3825_fixpoint_to_decimal(struct rfc3825_location_fixpoint_t *fixpoint, struct rfc3825_location_decimal_t *decimal);

/* decodes the LCI string received from DHCP into the fixpoint values */
static void rfc3825_lci_to_fixpoint(const unsigned char lci[16], struct rfc3825_location_fixpoint_t *fixpoint);


/* Map Datum Types used for the coordinates (RFC 3825) */
static const value_string map_datum_type_values[] = {
	{ 1,	"WGS 84" },
	{ 2,	"NAD83 (NAVD88)" },
	{ 3,	"NAD83 (MLLW)" },
	{ 0,	NULL }
};


/* Altitude Types used for the coordinates (RFC 3825) */
static const value_string altitude_type_values[] = {
	{ 1,	"Meters" },
	{ 2,	"Floors" },
	{ 0,	NULL }
};

/* AutoConfigure (RFC 2563) */
static const value_string dhcp_autoconfig[] = {
	{ 0,	"DoNotAutoConfigure"},
	{ 1,	"AutoConfigure"},
	{ 0,	NULL }
};

/* Error Types for RFC 3825 coordinate location decoding */
static const value_string rfc3825_error_types[] = {
	{ 1,	"Latitude is out of range [-90,90]"},
	{ 2,	"Latitude Uncertainty is out of range [0,90]"},
	{ 3,	"Longitude is out of range [-180,180]"},
	{ 4,	"Longitude Uncertainty is out of range [0,180]"},
	{ 5,	"Altitude is out of range [-(2^21),(2^21)-1]"},
	{ 6,	"Altitude Uncertainty is out of range [0,2^20]"},
	{ 7,	"Altitude Type is out of range [0,2]"},
	{ 8,	"Datum is out of range [1,3]"},
	{ 0,	NULL }
};



/* Civic Address What field (RFC 4776) */
static const value_string civic_address_what_values[] = {
	{ 0,	"Location of the DHCP server" },
	{ 1,	"Location of the network element believed to be closest to the client" },
	{ 2,	"Location of the client"},
	{ 0, NULL}
};

/* Civic Address Type field (RFC 4119, RFC 4776, RFC 5139) */
static const value_string civic_address_type_values[] = {
	{   0,	"Language" },
	{   1,	"A1" },
	{   2,	"A2" },
	{   3,	"A3" },
	{   4,	"A4" },
	{   5,	"A5" },
	{   6,	"A6" },
	{  16,	"PRD (Leading street direction)" },
	{  17,	"POD (Trailing street suffix)" },
	{  18,	"STS (Street suffix)" },
	{  19,	"HNO (House number)" },
	{  20,	"HNS (House number suffix)" },
	{  21,	"LMK (Landmark or vanity address)" },
	{  22,	"LOC (Additional location information)" },
	{  23,	"NAM" },
	{  24,	"PC (Postal/ZIP code)" },
	{  25,	"BLD (Building)" },
	{  26,	"UNIT" },
	{  27,	"FLR (Floor)" },
	{  28,	"ROOM" },
	{  29,	"PLC (Place-type)" },
	{  30,	"PCN (Postal community name)" },
	{  31,	"POBOX" },
	{  32,	"ADDCODE (Additional Code)" },
	{  33,	"SEAT" },
	{  34,	"RD (Primary road or street)" },
	{  35,	"RDSEC (Road section)" },
	{  36,	"RDBR (Road branch)" },
	{  37,	"RDSUBBR (Road sub-branch)" },
	{  38,	"PRM (Road pre-modifier)" },
	{  39,	"POM (Road post-modifier" },
	{ 128,	"Script" },
	{ 0, NULL }
};

static const value_string cablelab_ipaddr_mode_vals[] = {
	{ 1, "IPv4" },
	{ 2, "IPv6" },
	{ 0, NULL }
};

static const value_string duidtype_vals[] =
{
	{ DUID_LLT,	"link-layer address plus time" },
	{ DUID_EN,	"assigned by vendor based on Enterprise number" },
	{ DUID_LL,	"link-layer address" },
	{ 0, NULL }
};

static gboolean novell_string = FALSE;

static guint bootp_uuid_endian = ENC_LITTLE_ENDIAN;

static const enum_val_t bootp_uuid_endian_vals[] = {
	{ "Little Endian", "Little Endian",	ENC_LITTLE_ENDIAN},
	{ "Big Endian",	 "Big Endian", ENC_BIG_ENDIAN },
	{ NULL, NULL, 0 }
};

#define UDP_PORT_BOOTPS	 67
#define UDP_PORT_BOOTPC	 68

#define BOOTP_BC	0x8000
#define BOOTP_MBZ	0x7FFF

/* FQDN stuff */
#define F_FQDN_S	0x01
#define F_FQDN_O	0x02
#define F_FQDN_E	0x04
#define F_FQDN_N	0x08
#define F_FQDN_MBZ	0xf0

#define ISNS_BITFIELD_NZ_MUST_BE_IGNORED(mask, ena_flag)		\
	((mask) && !((mask) & (ena_flag)))

/* iSNS bit fields */
#define F_ISNS_FUNCTIONS_ENABLED	0x0001
#define F_ISNS_FUNCTIONS_DD_AUTH	0x0002
#define F_ISNS_FUNCTIONS_SEC_POLICY	0x0004
#define F_ISNS_FUNCTIONS_RESERVED	0xFFF8

#define F_ISNS_DD_ACCESS_ENABLED		0x0001
#define F_ISNS_DD_ACCESS_CTRL_NODE		0x0002
#define F_ISNS_DD_ACCESS_ISCSI_TARGET		0x0004
#define F_ISNS_DD_ACCESS_ISCSI_INITIATOR	0x0008
#define F_ISNS_DD_ACCESS_IFCP_TARGET_PORT	0x0010
#define F_ISNS_DD_ACCESS_IFCP_INITIATOR_PORT	0x0020
#define F_ISNS_DD_ACCESS_RESERVED		0xFFC0

#define F_ISNS_ADMIN_FLAGS_ENABLED		0x0001
#define F_ISNS_ADMIN_FLAGS_HEARTBEAT		0x0002
#define F_ISNS_ADMIN_FLAGS_MANAGEMENT_SCNS	0x0004
#define F_ISNS_ADMIN_FLAGS_DEFAULT_DD		0x0008
#define F_ISNS_ADMIN_FLAGS_RESERVED		0xFFF0

#define F_ISNS_SRV_SEC_BITMAP_ENABLED		0x0001
#define F_ISNS_SRV_SEC_BITMAP_IKE_IPSEC		0x0002
#define F_ISNS_SRV_SEC_BITMAP_MAIN_MODE		0x0004
#define F_ISNS_SRV_SEC_BITMAP_AGGRESSIVE	0x0008
#define F_ISNS_SRV_SEC_BITMAP_PFS		0x0010
#define F_ISNS_SRV_SEC_BITMAP_TRASPORT_MODE	0x0020
#define F_ISNS_SRV_SEC_BITMAP_TUNNEL_MODE	0x0040
#define F_ISNS_SRV_SEC_BITMAP_RESERVED		0xFF80

static const true_false_string tfs_fqdn_s = {
	"Server",
	"Client"
};

static const true_false_string tfs_fqdn_o = {
	"Override",
	"No override"
};

static const true_false_string tfs_fqdn_e = {
	"Binary encoding",
	"ASCII encoding"
};

static const true_false_string tfs_fqdn_n = {
	"No server updates",
	"Some server updates"
};

static const true_false_string tfs_isns_function_dd_based_auth = {
	"Automatically allowed access",
	"Explicitly performed",
};

static const true_false_string tfs_isns_functions_sec_distrib = {
	"Download from iSNS server",
	"By other means",
};

enum field_type {
	special,
	none,
	presence,
	ipv4,			/* single IPv4 address */
	ipv4_list,		/* list of IPv4 addresses */
	string,
	bytes,
	opaque,
	val_boolean,
	val_u_byte,
	val_u_short,
	val_u_short_list,
	val_u_le_short,
	val_u_long,
	time_in_s_secs,		/* Signed */
	time_in_u_secs,		/* Unsigned (not micro) */
	fqdn,
	ipv4_or_fqdn,
	oui
};

struct opt_info {
	const char	*text;
	enum field_type ftype;
	int* phf;
};

static const true_false_string flag_set_broadcast = {
	"Broadcast",
	"Unicast"
};

#define BOOTP_MAX_NO_CHAR 64

/* PacketCable/DOCSIS definitions */
#define PACKETCABLE_MTA_CAP10 "pktc1.0:"
#define PACKETCABLE_MTA_CAP15 "pktc1.5:"
#define PACKETCABLE_MTA_CAP20 "pktc2.0:"
#define PACKETCABLE_CM_CAP11  "docsis1.1:"
#define PACKETCABLE_CM_CAP20  "docsis2.0:"
#define PACKETCABLE_CM_CAP30  "docsis3.0:"

#define PACKETCABLE_CCC_I05	 1
#define PACKETCABLE_CCC_DRAFT5	 2
#define PACKETCABLE_CCC_RFC_3495 3

static const enum_val_t pkt_ccc_protocol_versions[] = {
	{ "ccc_i05",	 "PKT-SP-PROV-I05-021127", PACKETCABLE_CCC_I05 },
	{ "ccc_draft_5", "IETF Draft 5",	   PACKETCABLE_CCC_DRAFT5 },
	{ "rfc_3495",	 "RFC 3495",		   PACKETCABLE_CCC_RFC_3495 },
	{ NULL, NULL, 0 }
};

#define PACKETCABLE_BSDP  "AAPLBSDPC"
#define PACKETCABLE_BSDPD "AAPLBSDPC/"

static gint pkt_ccc_protocol_version = PACKETCABLE_CCC_RFC_3495;
static guint pkt_ccc_option = 122;


static int dissect_vendor_pxeclient_suboption(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
					      tvbuff_t *tvb, int optoff, int optend);
static int dissect_vendor_cablelabs_suboption(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
					      tvbuff_t *tvb, int optoff, int optend);
static int dissect_vendor_bsdp_suboption(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
					      tvbuff_t *tvb, int optoff, int optend);
static gboolean test_encapsulated_vendor_options(tvbuff_t *tvb, int optoff, int optend);
static int dissect_vendor_alcatel_suboption(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
					    tvbuff_t *tvb, int optoff, int optend);
static int dissect_netware_ip_suboption(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
					    tvbuff_t *tvb, int optoff, int optend);
static int dissect_vendor_tr111_suboption(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
					    tvbuff_t *tvb, int optoff, int optend);
static int bootp_dhcp_decode_agent_info(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
					    tvbuff_t *tvb, int optoff, int optend);
static void dissect_packetcable_mta_cap(proto_tree *v_tree, packet_info *pinfo, tvbuff_t *tvb,
					int voff, int len);
static void dissect_docsis_cm_cap(proto_tree *v_tree, tvbuff_t *tvb,
				  int voff, int len, gboolean opt125);
static int dissect_packetcable_i05_ccc(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
				       tvbuff_t *tvb, int optoff, int optend);
static int dissect_packetcable_ietf_ccc(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
					tvbuff_t *tvb, int optoff, int optend, int revision);
static int dissect_vendor_cl_suboption(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
					    tvbuff_t *tvb, int optoff, int optend);
static int dissect_vendor_generic_suboption(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
					    tvbuff_t *tvb, int optoff, int optend);
static int dissect_isns(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
			tvbuff_t *tvb, int optoff, int optlen);
static void dissect_vendor_bsdp_boot_image(proto_tree *v_tree, tvbuff_t *tvb, int optoff);

#define OPT53_DISCOVER "Discover"
/* http://www.iana.org/assignments/bootp-dhcp-parameters */
static const value_string opt53_text[] = {
	{  1,	OPT53_DISCOVER },
	{  2,	"Offer" },
	{  3,	"Request" },
	{  4,	"Decline" },
	{  5,	"ACK" },
	{  6,	"NAK" },
	{  7,	"Release" },
	{  8,	"Inform" },
	{  9,	"Force Renew" },
	{ 10,	"Lease query" },		/* RFC4388 */
	{ 11,	"Lease Unassigned" },		/* RFC4388 */
	{ 12,	"Lease Unknown" },		/* RFC4388 */
	{ 13,	"Lease Active" },		/* RFC4388 */
	/* draft-ietf-dhc-leasequery-09.txt
	{ 13,	"Lease query" },			*/
	{ 14,	"Lease known" },
	{ 15,	"Lease unknown" },
	{ 16,	"Lease active" },
	{ 17,	"Unimplemented" },

	{ 0,	NULL }
};

/* DHCP Authentication protocols */
#define AUTHEN_PROTO_CONFIG_TOKEN	0
#define AUTHEN_PROTO_DELAYED_AUTHEN	1

/* DHCP Authentication algorithms for delayed authentication */
#define AUTHEN_DELAYED_ALGO_HMAC_MD5	1

/* DHCP Authentication Replay Detection Methods */
#define AUTHEN_RDM_MONOTONIC_COUNTER	0x00

/* DHCP Option Overload (option code 52) */
#define OPT_OVERLOAD_FILE		1
#define OPT_OVERLOAD_SNAME		2
#define OPT_OVERLOAD_BOTH		3

/* Server name and boot file offsets and lengths */
#define SERVER_NAME_OFFSET		44
#define SERVER_NAME_LEN			64
#define FILE_NAME_OFFSET		108
#define FILE_NAME_LEN			128
#define VENDOR_INFO_OFFSET		236

static const value_string bootp_nbnt_vals[] = {
	{0x1,	"B-node" },
	{0x2,	"P-node" },
	{0x4,	"M-node" },
	{0x8,	"H-node" },
	{0,	NULL	 }
};

static const value_string bootp_client_arch[] = {
	{ 0x0000, "IA x86 PC" },
	{ 0x0001, "NEC/PC98" },
	{ 0x0002, "IA64 PC" },
	{ 0x0003, "DEC Alpha" },
	{ 0x0004, "ArcX86" },
	{ 0x0005, "Intel Lean Client" },
	{ 0x0006, "EFI IA32" },
	{ 0x0007, "EFI BC" },
	{ 0x0008, "EFI Xscale" },
	{ 0x0009, "EFI x86-64" },
	{ 0,	  NULL }
};

static const value_string opt_overload_vals[] = {
	{ OPT_OVERLOAD_FILE,  "Boot file name holds options",		     },
	{ OPT_OVERLOAD_SNAME, "Server host name holds options",		     },
	{ OPT_OVERLOAD_BOTH,  "Boot file and server host names hold options" },
	{ 0,		      NULL					     } };

static const value_string slpda_vals[] = {
	{0x00,	 "Dynamic Discovery" },
	{0x01,	 "Static Discovery" },
	{0x80,	 "Backwards compatibility" },
	{0,	NULL	 } };

static const value_string slp_scope_vals[] = {
	{0x00,	 "Preferred Scope" },
	{0x01,	 "Mandatory Scope" },
	{0,	NULL	 } };

static const value_string authen_protocol_vals[] = {
	{AUTHEN_PROTO_CONFIG_TOKEN,   "configuration token" },
	{AUTHEN_PROTO_DELAYED_AUTHEN, "delayed authentication" },
	{0,			      NULL     } };

static const value_string authen_da_algo_vals[] = {
	{AUTHEN_DELAYED_ALGO_HMAC_MD5, "HMAC_MD5" },
	{0,			       NULL	} };

static const value_string authen_rdm_vals[] = {
	{AUTHEN_RDM_MONOTONIC_COUNTER, "Monotonically-increasing counter" },
	{0,			       NULL	} };

static const value_string cl_dss_id_type_vals[] = {
	{1, "Primary DSS_ID" },
	{2, "Secondary DSS_ID" },
	{0, NULL }
};

static const value_string sip_server_enc_vals[] = {
	{0, "Fully Qualified Domain Name" },
	{1, "IPv4 Address" },
	{0, NULL }
};

static const value_string o43_bsdp_boot_image_install_vals[] = {
	{ 0, "non-install" },
	{ 1, "install" },
	{ 0, NULL }
};

static const value_string o43_bsdp_boot_image_kind_vals[] = {
	{ 0, "Mac OS 9" },
	{ 1, "Mac OS X" },
	{ 2, "Mac OS X Server" },
	{ 3, "Hardware Diagnostics" },
	{ 0, NULL }
};

static const value_string o43_bsdp_message_type_vals[] = {
	{ 1, "LIST" },
	{ 2, "SELECT" },
	{ 3, "FAILED" },
	{ 0, NULL }
};

static const string_string option242_avaya_phystat_vals[] = {
	{ "0", "Disabled" },
	{ "1", "Auto" },
	{ "2", "10Mbps half" },
	{ "3", "10Mbps full" },
	{ "4", "100Mbps half" },
	{ "5", "100Mbps full" },
	{ "6", "1000Mbps full" },
	{ 0, NULL }
};

static const string_string option242_avaya_l2q_vals[] = {
	{ "0", "Auto" },
	{ "1", "Enabled" },
	{ "2", "Disabled" },
	{ 0, NULL }
};

static const string_string option242_avaya_dot1x_vals[] = {
	{ "0", "With PAE pass-through" },
	{ "1", "With PAE pass-through and proxy Logoff" },
	{ "2", "Without PAE pass-through or proxy Logoff" },
	{ 0, NULL }
};

static const string_string option242_avaya_icmpdu_vals[] = {
	{ "0", "No ICMP Destination Unreachable messages" },
	{ "1", "Send limited Port Unreachable messages" },
	{ "2", "Send Protocol and Port Unreachable messages" },
	{ 0, NULL }
};

static const string_string option242_avaya_icmpred_vals[] = {
	{ "0", "Ignore ICMP Redirect messages" },
	{ "1", "Process ICMP Redirect messages" },
	{ 0, NULL }
};

static const string_string option242_avaya_loglocal_vals[] = {
	{ "0", "Disabled" },
	{ "1", "Emergencie" },
	{ "2", "Alerts" },
	{ "3", "Critical" },
	{ "4", "Errors" },
	{ "5", "Warnings" },
	{ "6", "Notices" },
	{ "7", "Information" },
	{ "8", "Debug" },
	{ 0, NULL }
};

static const string_string option242_avaya_procstat_vals[] = {
	{ "0", "All administrative options" },
	{ "1", "Only view administrative options" },
	{ 0, NULL }
};

static const string_string option242_avaya_static_vals[] = {
	{ "0", "Static programming never overrides call server (DHCP) or call server administered data" },
	{ "1", "Static programming overrides only file server administered data" },
	{ "2", "Static programming overrides only call server administered data" },
	{ "3", "Static programming overrides both file server- and call server-administered data" },
	{ 0, NULL }
};

/* bootp options administration */
#define BOOTP_OPT_NUM	256

/* Re-define structure.	 Values to be updated by bootp_init_protocol */
static struct opt_info bootp_opt[BOOTP_OPT_NUM];

static struct opt_info default_bootp_opt[BOOTP_OPT_NUM] = {
/*   0 */ { "Padding",					none, &hf_bootp_option_padding },
/*   1 */ { "Subnet Mask",				ipv4, &hf_bootp_option_subnet_mask },
/*   2 */ { "Time Offset",				time_in_s_secs, &hf_bootp_option_time_offset },
/*   3 */ { "Router",					ipv4_list, &hf_bootp_option_router },
/*   4 */ { "Time Server",				ipv4_list, &hf_bootp_option_time_server },
/*   5 */ { "Name Server",				ipv4_list, &hf_bootp_option_name_server },
/*   6 */ { "Domain Name Server",			ipv4_list, &hf_bootp_option_domain_name_server },
/*   7 */ { "Log Server",				ipv4_list, &hf_bootp_option_log_server },
/*   8 */ { "Quotes Server",				ipv4_list, &hf_bootp_option_quotes_server },
/*   9 */ { "LPR Server",				ipv4_list, &hf_bootp_option_lpr_server },
/*  10 */ { "Impress Server",				ipv4_list, &hf_bootp_option_impress_server },
/*  11 */ { "Resource Location Server",			ipv4_list, &hf_bootp_option_resource_location_server },
/*  12 */ { "Host Name",				string, &hf_bootp_option_hostname },
/*  13 */ { "Boot File Size",				val_u_short, &hf_bootp_option_boot_file_size },
/*  14 */ { "Merit Dump File",				string, &hf_bootp_option_merit_dump_file },
/*  15 */ { "Domain Name",				string, &hf_bootp_option_domain_name },
/*  16 */ { "Swap Server",				ipv4, &hf_bootp_option_swap_server },
/*  17 */ { "Root Path",				string, &hf_bootp_option_root_path },
/*  18 */ { "Extensions Path",				string, &hf_bootp_option_extension_path },
/*  19 */ { "IP Forwarding",				val_boolean, &hf_bootp_option_ip_forwarding },
/*  20 */ { "Non-Local Source Routing",			val_boolean, &hf_bootp_option_non_local_source_routing },
/*  21 */ { "Policy Filter",				special, NULL },
/*  22 */ { "Maximum Datagram Reassembly Size",		val_u_short, &hf_bootp_option_max_datagram_reassembly_size },
/*  23 */ { "Default IP Time-to-Live",			val_u_byte, &hf_bootp_option_default_ip_ttl },
/*  24 */ { "Path MTU Aging Timeout",			time_in_u_secs, &hf_bootp_option_path_mtu_aging_timeout },
/*  25 */ { "Path MTU Plateau Table",			val_u_short_list, &hf_bootp_option_path_mtu_plateau_table_item },
/*  26 */ { "Interface MTU",				val_u_short, &hf_bootp_option_interface_mtu },
/*  27 */ { "All Subnets are Local",			val_boolean, &hf_bootp_option_all_subnets_are_local },
/*  28 */ { "Broadcast Address",			ipv4, &hf_bootp_option_broadcast_address },
/*  29 */ { "Perform Mask Discovery",			val_boolean, &hf_bootp_option_perform_mask_discovery },
/*  30 */ { "Mask Supplier",				val_boolean, &hf_bootp_option_mask_supplier },
/*  31 */ { "Perform Router Discover",			val_boolean, &hf_bootp_option_perform_router_discover },
/*  32 */ { "Router Solicitation Address",		ipv4, &hf_bootp_option_router_solicitation_address },
/*  33 */ { "Static Route",				special, NULL },
/*  34 */ { "Trailer Encapsulation",			val_boolean, &hf_bootp_option_trailer_encapsulation },
/*  35 */ { "ARP Cache Timeout",			time_in_u_secs, &hf_bootp_option_arp_cache_timeout },
/*  36 */ { "Ethernet Encapsulation",			val_boolean, &hf_bootp_option_ethernet_encapsulation },
/*  37 */ { "TCP Default TTL",				val_u_byte, &hf_bootp_option_tcp_default_ttl },
/*  38 */ { "TCP Keepalive Interval",			time_in_u_secs, &hf_bootp_option_tcp_keepalive_interval },
/*  39 */ { "TCP Keepalive Garbage",			val_boolean, &hf_bootp_option_tcp_keepalive_garbage },
/*  40 */ { "Network Information Service Domain",	string, &hf_bootp_option_nis_domain },
/*  41 */ { "Network Information Service Servers",	ipv4_list, &hf_bootp_option_nis_server },
/*  42 */ { "Network Time Protocol Servers",		ipv4_list, &hf_bootp_option_ntp_server },
/*  43 */ { "Vendor-Specific Information",		special, NULL },
/*  44 */ { "NetBIOS over TCP/IP Name Server",		ipv4_list, &hf_bootp_option_netbios_over_tcpip_name_server },
/*  45 */ { "NetBIOS over TCP/IP Datagram Distribution Name Server", ipv4_list, &hf_bootp_option_netbios_over_tcpip_dd_name_server },
/*  46 */ { "NetBIOS over TCP/IP Node Type",		val_u_byte, &hf_bootp_option_netbios_over_tcpip_node_type },
/*  47 */ { "NetBIOS over TCP/IP Scope",		string, &hf_bootp_option_netbios_over_tcpip_scope },
/*  48 */ { "X Window System Font Server",		ipv4_list, &hf_bootp_option_xwindows_system_font_server },
/*  49 */ { "X Window System Display Manager",		ipv4_list, &hf_bootp_option_xwindows_system_display_manager },
/*  50 */ { "Requested IP Address",			ipv4, &hf_bootp_option_requested_ip_address },
/*  51 */ { "IP Address Lease Time",			time_in_u_secs, &hf_bootp_option_ip_address_lease_time },
/*  52 */ { "Option Overload",				special, &hf_bootp_option_option_overload },
/*  53 */ { "DHCP Message Type",			val_u_byte, &hf_bootp_option_dhcp },
/*  54 */ { "DHCP Server Identifier",			ipv4, &hf_bootp_option_dhcp_server_id },
/*  55 */ { "Parameter Request List",			special, &hf_bootp_option_parameter_request_list_item },
/*  56 */ { "Message",					string, &hf_bootp_option_message },
/*  57 */ { "Maximum DHCP Message Size",		val_u_short, &hf_bootp_option_dhcp_max_message_size },
/*  58 */ { "Renewal Time Value",			time_in_u_secs, &hf_bootp_option_renewal_time_value },
/*  59 */ { "Rebinding Time Value",			time_in_u_secs, &hf_bootp_option_rebinding_time_value },
/*  60 */ { "Vendor class identifier",			special, NULL },
/*  61 */ { "Client identifier",			special, NULL },
/*  62 */ { "Novell/Netware IP domain",			string, &hf_bootp_option_novell_netware_ip_domain },
/*  63 */ { "Novell Options",				special, NULL },
/*  64 */ { "Network Information Service+ Domain",	string, &hf_bootp_option_nis_plus_domain },
/*  65 */ { "Network Information Service+ Servers",	ipv4_list, &hf_bootp_option_nis_plus_server },
/*  66 */ { "TFTP Server Name",				string, &hf_bootp_option_tftp_server_name },
/*  67 */ { "Bootfile name",				string, &hf_bootp_option_bootfile_name },
/*  68 */ { "Mobile IP Home Agent",			ipv4_list, &hf_bootp_option_mobile_ip_home_agent  },
/*  69 */ { "SMTP Server",				ipv4_list, &hf_bootp_option_smtp_server },
/*  70 */ { "POP3 Server",				ipv4_list, &hf_bootp_option_pop3_server },
/*  71 */ { "NNTP Server",				ipv4_list, &hf_bootp_option_nntp_server },
/*  72 */ { "Default WWW Server",			ipv4_list, &hf_bootp_option_default_www_server },
/*  73 */ { "Default Finger Server",			ipv4_list, &hf_bootp_option_default_finger_server },
/*  74 */ { "Default IRC Server",			ipv4_list, &hf_bootp_option_default_irc_server },
/*  75 */ { "StreetTalk Server",			ipv4_list, &hf_bootp_option_streettalk_server },
/*  76 */ { "StreetTalk Directory Assistance Server",	ipv4_list, &hf_bootp_option_streettalk_da_server },
/*  77 */ { "User Class Information",			special, NULL },
/*  78 */ { "Directory Agent Information",		special, NULL },
/*  79 */ { "Service Location Agent Scope",		special, NULL },
/*  80 */ { "Rapid commit",				opaque, NULL },
/*  81 */ { "Client Fully Qualified Domain Name",	special, NULL},
/*  82 */ { "Agent Information Option",			special, NULL},
/*  83 */ { "iSNS",					opaque, NULL },
/*  84 */ { "Removed/Unassigned",			opaque, NULL },
/*  85 */ { "Novell Directory Services Servers",	special, NULL},
/*  86 */ { "Novell Directory Services Tree Name",	string, &hf_bootp_option_novell_ds_tree_name },
/*  87 */ { "Novell Directory Services Context",	string, &hf_bootp_option_novell_ds_context },
/*  88 */ { "BCMCS Controller Domain Name [TODO:RFC4280]",	opaque, NULL },
/*  89 */ { "BCMCS Controller IPv4 address [TODO:RFC4280]",	opaque, NULL },
/*  90 */ { "Authentication",				special, NULL},
/*  91 */ { "Client last transaction time",		time_in_u_secs, &hf_bootp_option_client_last_transaction_time },
/*  92 */ { "Associated IP option",			ipv4_list, &hf_bootp_option_associated_ip_option },
/*  93 */ { "Client System Architecture",		val_u_short, &hf_bootp_option_client_system_architecture },
/*  94 */ { "Client Network Device Interface",		special, NULL},
/*  95 */ { "LDAP [TODO:RFC3679]",			opaque, NULL },
/*  96 */ { "Removed/Unassigned",			opaque, NULL },
/*  97 */ { "UUID/GUID-based Client Identifier",	special, NULL},
/*  98 */ { "Open Group's User Authentication [TODO:RFC2485]",	opaque, NULL },
/*  99 */ { "Civic Addresses Configuration",		special, NULL},
/* 100 */ { "PCode [TODO:RFC4833]",			opaque, NULL },
/* 101 */ { "TCode [TODO:RFC4833]",			opaque, NULL },
/* 102 */ { "Removed/unassigned",			opaque, NULL },
/* 103 */ { "Removed/unassigned",			opaque, NULL },
/* 104 */ { "Removed/unassigned",			opaque, NULL },
/* 105 */ { "Removed/unassigned",			opaque, NULL },
/* 106 */ { "Removed/unassigned",			opaque, NULL },
/* 107 */ { "Removed/unassigned",			opaque, NULL },
/* 108 */ { "Removed/Unassigned",			opaque, NULL },
/* 109 */ { "Unassigned",				opaque, NULL },
/* 110 */ { "Removed/Unassigned",			opaque, NULL },
/* 111 */ { "Unassigned",				opaque, NULL },
/* 112 */ { "NetInfo Parent Server Address",		ipv4_list, &hf_bootp_option_netinfo_parent_server_address },
/* 113 */ { "NetInfo Parent Server Tag",		string, &hf_bootp_option_netinfo_parent_server_tag },
/* 114 */ { "URL [TODO:RFC3679]",			opaque, NULL },
/* 115 */ { "Removed/Unassigned",			opaque, NULL },
/* 116 */ { "DHCP Auto-Configuration",			val_u_byte, &hf_bootp_option_dhcp_auto_configuration },
/* 117 */ { "Name Service Search",			special, NULL },
/* 118 */ { "Subnet Selection Option",			ipv4_list, &hf_bootp_option_subnet_selection_option },
/* 119 */ { "Domain Search",				special, NULL },
/* 120 */ { "SIP Servers",		special, NULL },
/* 121 */ { "Classless Static Route",			special, NULL},
/* 122 */ { "CableLabs Client Configuration [TODO:RFC3495]",	opaque, NULL },
/* 123 */ { "Coordinate-based Location Configuration",	special, NULL},
/* 124 */ { "V-I Vendor Class",				special, NULL},
/* 125 */ { "V-I Vendor-specific Information",		special, NULL},
/* 126 */ { "Removed/Unassigned",			opaque, NULL },
/* 127 */ { "Removed/Unassigned",			opaque, NULL },
/* 128 */ { "DOCSIS full security server IP [TODO]",	opaque, NULL },
/* 129 */ { "PXE - undefined (vendor specific)",	opaque, NULL },
/* 130 */ { "PXE - undefined (vendor specific)",	opaque, NULL },
/* 131 */ { "PXE - undefined (vendor specific)",	opaque, NULL },
/* 132 */ { "PXE - undefined (vendor specific)",	opaque, NULL },
/* 133 */ { "PXE - undefined (vendor specific)",	opaque, NULL },
/* 134 */ { "PXE - undefined (vendor specific)",	opaque, NULL },
/* 135 */ { "PXE - undefined (vendor specific)",	opaque, NULL },
/* 136 */ { "OPTION_PANA_AGENT [TODO:RFC5192]",		opaque, NULL },
/* 137 */ { "LoST Server Domain Name",			string, &hf_bootp_option_lost_server_domain_name },
/* 138 */ { "CAPWAP Access Controllers",		ipv4_list, &hf_bootp_option_capwap_access_controller },
/* 139 */ { "IPv4 Address-MoS",				opaque, NULL },
/* 140 */ { "IPv4 FQDN-MoS",				opaque, NULL },
/* 141 */ { "SIP UA Configuration Domains",		opaque, NULL },
/* 142 */ { "Unassigned",				opaque, NULL },
/* 143 */ { "Unassigned",				opaque, NULL },
/* 144 */ { "Unassigned",				opaque, NULL },
/* 145 */ { "Unassigned",				opaque, NULL },
/* 146 */ { "Unassigned",				opaque, NULL },
/* 147 */ { "Unassigned",				opaque, NULL },
/* 148 */ { "Unassigned",				opaque, NULL },
/* 149 */ { "Unassigned",				opaque, NULL },
/* 150 */ { "TFTP Server Address",			ipv4_list, &hf_bootp_option_tftp_server_address },
/* 151 */ { "Unassigned",				opaque, NULL },
/* 152 */ { "Unassigned",				opaque, NULL },
/* 153 */ { "Unassigned",				opaque, NULL },
/* 154 */ { "Unassigned",				opaque, NULL },
/* 155 */ { "Unassigned",				opaque, NULL },
/* 156 */ { "Unassigned",				opaque, NULL },
/* 157 */ { "Unassigned",				opaque, NULL },
/* 158 */ { "Unassigned",				opaque, NULL },
/* 159 */ { "Unassigned",				opaque, NULL },
/* 160 */ { "Unassigned",				opaque, NULL },
/* 161 */ { "Unassigned",				opaque, NULL },
/* 162 */ { "Unassigned",				opaque, NULL },
/* 163 */ { "Unassigned",				opaque, NULL },
/* 164 */ { "Unassigned",				opaque, NULL },
/* 165 */ { "Unassigned",				opaque, NULL },
/* 166 */ { "Unassigned",				opaque, NULL },
/* 167 */ { "Unassigned",				opaque, NULL },
/* 168 */ { "Unassigned",				opaque, NULL },
/* 169 */ { "Unassigned",				opaque, NULL },
/* 170 */ { "Unassigned",				opaque, NULL },
/* 171 */ { "Unassigned",				opaque, NULL },
/* 172 */ { "Unassigned",				opaque, NULL },
/* 173 */ { "Unassigned",				opaque, NULL },
/* 174 */ { "Unassigned",				opaque, NULL },
/* 175 */ { "Etherboot",				opaque, NULL },
/* 176 */ { "IP Telephone",				opaque, NULL },
/* 177 */ { "Etherboot",				opaque, NULL },
/* 178 */ { "Unassigned",				opaque, NULL },
/* 179 */ { "Unassigned",				opaque, NULL },
/* 180 */ { "Unassigned",				opaque, NULL },
/* 181 */ { "Unassigned",				opaque, NULL },
/* 182 */ { "Unassigned",				opaque, NULL },
/* 183 */ { "Unassigned",				opaque, NULL },
/* 184 */ { "Unassigned",				opaque, NULL },
/* 185 */ { "Unassigned",				opaque, NULL },
/* 186 */ { "Unassigned",				opaque, NULL },
/* 187 */ { "Unassigned",				opaque, NULL },
/* 188 */ { "Unassigned",				opaque, NULL },
/* 189 */ { "Unassigned",				opaque, NULL },
/* 190 */ { "Unassigned",				opaque, NULL },
/* 191 */ { "Unassigned",				opaque, NULL },
/* 192 */ { "Unassigned",				opaque, NULL },
/* 193 */ { "Unassigned",				opaque, NULL },
/* 194 */ { "Unassigned",				opaque, NULL },
/* 195 */ { "Unassigned",				opaque, NULL },
/* 196 */ { "Unassigned",				opaque, NULL },
/* 197 */ { "Unassigned",				opaque, NULL },
/* 198 */ { "Unassigned",				opaque, NULL },
/* 199 */ { "Unassigned",				opaque, NULL },
/* 200 */ { "Unassigned",				opaque, NULL },
/* 201 */ { "Unassigned",				opaque, NULL },
/* 202 */ { "Unassigned",				opaque, NULL },
/* 203 */ { "Unassigned",				opaque, NULL },
/* 204 */ { "Unassigned",				opaque, NULL },
/* 205 */ { "Unassigned",				opaque, NULL },
/* 206 */ { "Unassigned",				opaque, NULL },
/* 207 */ { "Unassigned",				opaque, NULL },
/* 208 */ { "PXELINUX Magic",				opaque, NULL },
/* 209 */ { "PXE Configuration file",			string, &hf_bootp_option_pxe_config_file },
/* 210 */ { "PXE Path Prefix",				string, &hf_bootp_option_pxe_path_prefix },
/* 211 */ { "Reboot Time",				opaque, NULL },
/* 212 */ { "6RD",					opaque, NULL },
/* 213 */ { "V4 Access Domain",				opaque, NULL },
/* 214 */ { "Unassigned",				opaque, NULL },
/* 215 */ { "Unassigned",				opaque, NULL },
/* 216 */ { "Unassigned",				opaque, NULL },
/* 217 */ { "Unassigned",				opaque, NULL },
/* 218 */ { "Unassigned",				opaque, NULL },
/* 219 */ { "Unassigned",				opaque, NULL },
/* 220 */ { "Subnet Allocation",			opaque, NULL },
/* 221 */ { "Virtual Subnet Selection",			opaque, NULL },
/* 222 */ { "Unassigned",				opaque, NULL },
/* 223 */ { "Unassigned",				opaque, NULL },
/* 224 */ { "Private",					opaque, NULL },
/* 225 */ { "Private",					opaque, NULL },
/* 226 */ { "Private",					opaque, NULL },
/* 227 */ { "Private",					opaque, NULL },
/* 228 */ { "Private",					opaque, NULL },
/* 229 */ { "Private",					opaque, NULL },
/* 230 */ { "Private",					opaque, NULL },
/* 231 */ { "Private",					opaque, NULL },
/* 232 */ { "Private",					opaque, NULL },
/* 233 */ { "Private",					opaque, NULL },
/* 234 */ { "Private",					opaque, NULL },
/* 235 */ { "Private",					opaque, NULL },
/* 236 */ { "Private",					opaque, NULL },
/* 237 */ { "Private",					opaque, NULL },
/* 238 */ { "Private",					opaque, NULL },
/* 239 */ { "Private",					opaque, NULL },
/* 240 */ { "Private",					opaque, NULL },
/* 241 */ { "Private",					opaque, NULL },
/* 242 */ { "Private/Avaya IP Telephone",		special, NULL },
/* 243 */ { "Private",					opaque, NULL },
/* 244 */ { "Private",					opaque, NULL },
/* 245 */ { "Private",					opaque, NULL },
/* 246 */ { "Private",					opaque, NULL },
/* 247 */ { "Private",					opaque, NULL },
/* 248 */ { "Private",					opaque, NULL },
/* 249 */ { "Private/Classless Static Route (Microsoft)",	special, NULL},
/* 250 */ { "Private",					opaque, NULL },
/* 251 */ { "Private",					opaque, NULL },
/* 252 */ { "Private/Proxy autodiscovery",			string, &hf_bootp_option_private_proxy_autodiscovery },
/* 253 */ { "Private",					opaque, NULL },
/* 254 */ { "Private",					opaque, NULL },
/* 255 */ { "End",					opaque, NULL }
};

/*-------------------------------------
 * UAT for BOOTP
 *-------------------------------------
 */
/* UAT entry structure. */
typedef struct {
	guint  opt;
	gchar *text;
	enum field_type ftype;

} uat_bootp_record_t;

static uat_bootp_record_t *uat_bootp_records = NULL;
static uat_t *bootp_uat = NULL;
static guint num_bootp_records_uat = 0;

static void* uat_bootp_record_copy_cb(void* n, const void* o, size_t siz _U_) {
	uat_bootp_record_t* new_record = (uat_bootp_record_t *)n;
	const uat_bootp_record_t* old_record = (const uat_bootp_record_t *)o;

	if (old_record->text) {
		new_record->text = g_strdup(old_record->text);
	} else {
		new_record->text = NULL;
	}

	return new_record;
}

static gboolean uat_bootp_record_update_cb(void* r, char** err) {
	uat_bootp_record_t* rec = (uat_bootp_record_t *)r;

	if ((rec->opt == 0) || (rec->opt >=BOOTP_OPT_NUM-1)) {
		*err = g_strdup_printf("Option must be between 1 and %d", BOOTP_OPT_NUM-2);
		return FALSE;
	}
	return TRUE;
}

static void uat_bootp_record_free_cb(void*r) {
	uat_bootp_record_t* rec = (uat_bootp_record_t *)r;

	if (rec->text) g_free(rec->text);
}

UAT_DEC_CB_DEF(uat_bootp_records, opt, uat_bootp_record_t)
UAT_CSTRING_CB_DEF(uat_bootp_records, text, uat_bootp_record_t)
UAT_VS_DEF(uat_bootp_records, ftype, uat_bootp_record_t, enum field_type, special, "string")


static struct opt_info* bootp_get_opt(unsigned int idx)
{
	if(idx>=BOOTP_OPT_NUM)
		return NULL;

	return &bootp_opt[idx];
}

static const char *
bootp_get_opt_text(unsigned int idx)
{
	if(idx>=BOOTP_OPT_NUM)
		return "unknown";
	return bootp_opt[idx].text;
}

struct basic_types_hfs {
	gint* bytes;
	gint* ipv4;
	gint* ipv4_list;
	gint* string;
	gint* val_boolean;
	gint* val_u_byte;
	gint* val_u_short;
	gint* val_u_short_list;
	gint* val_u_long;
	gint* time_in_s_secs;
	gint* time_in_u_secs;
};

/* Handle "basic" datatypes adding to a tree */
static int
bootp_handle_basic_types(packet_info *pinfo, proto_tree *tree, proto_item *item, tvbuff_t *tvb,
			 enum field_type ftype, int offset, int total_len,
			 gint *hf, struct basic_types_hfs* hf_default)
{
	int	i, left;
	gint32	time_s_secs;
	guint32 time_u_secs;
	int	consumed = 0;

	switch (ftype) {
	case bytes:
		if (hf != NULL)
			proto_tree_add_item(tree, *hf, tvb, offset, total_len, ENC_BIG_ENDIAN);
		else if (hf_default->bytes != NULL)
			proto_tree_add_item(tree, *hf_default->bytes, tvb, offset, total_len, ENC_BIG_ENDIAN);
		consumed = total_len;
		break;

	case ipv4:
		if (total_len != 4) {
			expert_add_info_format(pinfo, item, &ei_bootp_bad_length, "length isn't 4");
			break;
		}

		if (hf != NULL)
			proto_tree_add_item(tree, *hf, tvb, offset, 4, ENC_BIG_ENDIAN);
		else if (hf_default->ipv4 != NULL)
			proto_tree_add_item(tree, *hf_default->ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
		consumed = 4;
		break;

	case ipv4_list:
		for (i = offset, left = total_len; left > 0; i += 4, left -= 4) {
			if (left < 4) {
				expert_add_info_format(pinfo, item, &ei_bootp_bad_length, "Option length isn't a multiple of 4");
				break;
			}

			if (hf != NULL)
				proto_tree_add_item(tree, *hf, tvb, i, 4, ENC_BIG_ENDIAN);
			else if (hf_default->ipv4_list != NULL)
				proto_tree_add_item(tree, *hf_default->ipv4_list, tvb, i, 4, ENC_BIG_ENDIAN);
			consumed += 4;
		}

		break;

	case string:
		if (hf != NULL)
			proto_tree_add_item(tree, *hf, tvb, offset, total_len, ENC_BIG_ENDIAN);
		else if (hf_default->string != NULL)
			proto_tree_add_item(tree, *hf_default->string, tvb, offset, total_len, ENC_BIG_ENDIAN);
		consumed = total_len;
		break;

	case val_boolean:
		if (total_len != 1) {
			expert_add_info_format(pinfo, item, &ei_bootp_bad_length, "length isn't 1");
			break;
		}

		if (hf != NULL)
			proto_tree_add_item(tree, *hf, tvb, offset, 1, ENC_BIG_ENDIAN);
		else if (hf_default->val_boolean != NULL)
			proto_tree_add_item(tree, *hf_default->val_boolean, tvb, offset, 1, ENC_BIG_ENDIAN);
		consumed = 1;
		break;

	case val_u_byte:
		if (total_len != 1) {
			expert_add_info_format(pinfo, item, &ei_bootp_bad_length, "length isn't 1");
			break;
		}

		if (hf != NULL)
			proto_tree_add_item(tree, *hf, tvb, offset, 1, ENC_BIG_ENDIAN);
		else if (hf_default->val_u_byte != NULL)
			proto_tree_add_item(tree, *hf_default->val_u_byte, tvb, offset, 1, ENC_BIG_ENDIAN);
		consumed = 1;
		break;

	case val_u_short:
		if (total_len != 2) {
			expert_add_info_format(pinfo, item, &ei_bootp_bad_length, "length isn't 2");
			break;
		}

		if (hf != NULL)
			proto_tree_add_item(tree, *hf, tvb, offset, 2, ENC_BIG_ENDIAN);
		else if (hf_default->val_u_short != NULL)
			proto_tree_add_item(tree, *hf_default->val_u_short, tvb, offset, 2, ENC_BIG_ENDIAN);
		consumed = 2;
		break;

	case val_u_le_short:
		if (total_len != 2) {
			expert_add_info_format(pinfo, item, &ei_bootp_bad_length, "length isn't 2");
			break;
		}

		if (hf != NULL)
			proto_tree_add_item(tree, *hf, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		else if (hf_default->val_u_short != NULL)
			proto_tree_add_item(tree, *hf_default->val_u_short, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		consumed = 2;
		break;

	case val_u_short_list:
		for (i = offset, left = total_len; left > 0; i += 2, left -= 2) {
			if (left < 2) {
				expert_add_info_format(pinfo, item, &ei_bootp_bad_length, "Option length isn't a multiple of 2");
				break;
			}

			if (hf != NULL)
				proto_tree_add_item(tree, *hf, tvb, i, 2, ENC_BIG_ENDIAN);
			else if (hf_default->val_u_short_list != NULL)
				proto_tree_add_item(tree, *hf_default->val_u_short_list, tvb, i, 2, ENC_BIG_ENDIAN);
			consumed += 2;
		}
		break;

	case val_u_long:
		if (total_len != 4) {
			expert_add_info_format(pinfo, item, &ei_bootp_bad_length, "length isn't 4");
			break;
		}

		if (hf != NULL)
			proto_tree_add_item(tree, *hf, tvb, offset, 4, ENC_BIG_ENDIAN);
		else if (hf_default->val_u_long != NULL)
			proto_tree_add_item(tree, *hf_default->val_u_long, tvb, offset, 4, ENC_BIG_ENDIAN);
		consumed = 4;
		break;

	case time_in_s_secs:
		if (total_len != 4) {
			expert_add_info_format(pinfo, item, &ei_bootp_bad_length, "length isn't 4");
			break;
		}

		if (hf != NULL) {
			time_s_secs = (gint32) tvb_get_ntohl(tvb, offset);
			proto_tree_add_int_format_value(tree, *hf,
				tvb, offset, 4, time_s_secs, "(%ds) %s", time_s_secs, signed_time_secs_to_str(wmem_packet_scope(), time_s_secs));
		}
		else if (hf_default->time_in_s_secs != NULL)
			proto_tree_add_item(tree, *hf_default->time_in_s_secs, tvb, offset, 4, ENC_BIG_ENDIAN);

		consumed = 4;
		break;

	case time_in_u_secs:
		if (total_len != 4) {
			expert_add_info_format(pinfo, item, &ei_bootp_bad_length, "length isn't 4");
			break;
		}

		if (hf != NULL) {
			time_u_secs = tvb_get_ntohl(tvb, offset);
			proto_tree_add_uint_format_value(tree, *hf,
				tvb, offset, 4, time_u_secs, "(%us) %s", time_u_secs,
				((time_u_secs == 0xffffffff) ? "infinity" : unsigned_time_secs_to_str(wmem_packet_scope(), time_u_secs)));
		}
		else if (hf_default->time_in_u_secs != NULL)
			proto_tree_add_item(tree, *hf_default->time_in_u_secs, tvb, offset, 4, ENC_BIG_ENDIAN);
		consumed = 4;
		break;
	default:
		/* Ignore other field_types */
		break;
	}

	return consumed;
}

/* Returns the number of bytes consumed by this option. */
static int
bootp_option(tvbuff_t *tvb, packet_info *pinfo, proto_tree *bp_tree, proto_item *bp_item, int voff,
	     int eoff, gboolean first_pass, gboolean *at_end, const char **dhcp_type_p,
	     const guint8 **vendor_class_id_p, guint8 *overload_p)
{
	struct opt_info *opt;
	enum field_type	 ftype;
	guchar		 code = tvb_get_guint8(tvb, voff);
	int		 optlen;
	guchar		 byte;
	int		 i, consumed, basictype_consumed;
	int		 optoff, optleft, optend;
	proto_tree	*v_tree;
	proto_item	*vti, *ti;
	guint8		 protocol;
	guint8		 algorithm;
	guint8		 rdm;
	guint8		 fqdn_flags;
	int		 o52voff, o52eoff;
	gboolean	 o52at_end;
	guint8		 s_option;
	guint8		 s_len;
	const guchar	*dns_name;
	gboolean	 option_handled = TRUE;

	struct basic_types_hfs default_hfs = {
		&hf_bootp_option_value,
		&hf_bootp_option_value_ip_address,
		&hf_bootp_option_value_ip_address,
		&hf_bootp_option_value_stringz,
		&hf_bootp_option_value_boolean,
		&hf_bootp_option_value_8,
		&hf_bootp_option_value_16,
		&hf_bootp_option_value_16,
		&hf_bootp_option_value_u32,
		&hf_bootp_option_value_i32,
		&hf_bootp_option_value_u32
	};

	/* Options whose length isn't "optlen + 2". */
	switch (code) {

	case 0:		/* Padding */
		/* check how much padding we have */
		for (i = voff + 1; i < eoff; i++ ) {
			if (tvb_get_guint8(tvb, i) != 0) {
				break;
			}
		}
		i = i - voff;
		if (!first_pass) {
			if (bp_tree != NULL) {
				vti = proto_tree_add_uint_format_value(bp_tree, hf_bootp_option_type,
						tvb, voff, 1, 0, "(0) Padding");
				v_tree = proto_item_add_subtree(vti, ett_bootp_option);
				proto_tree_add_item(v_tree, hf_bootp_option_padding, tvb, voff, i, ENC_NA);
			}
		}
		consumed = i;
		return consumed;

	case 255:	/* End Option */
		if (!first_pass) {
			if (bp_tree != NULL) {
				vti = proto_tree_add_uint_format_value(bp_tree, hf_bootp_option_type,
						tvb, voff, 1, 0, "(255) End");
				v_tree = proto_item_add_subtree(vti, ett_bootp_option);
				if (*overload_p)
					proto_tree_add_item(v_tree, hf_bootp_option_end_overload, tvb, voff, 1, ENC_BIG_ENDIAN);
				else
					proto_tree_add_item(v_tree, hf_bootp_option_end, tvb, voff, 1, ENC_BIG_ENDIAN);
			}
		}
		*at_end = TRUE;
		consumed = 1;
		return consumed;
	}

	/*
	 * Get the length of the option, and the number of bytes it
	 * consumes (the length doesn't include the option code or
	 * length bytes).
	 *
	 * On the first pass, check first whether we have the length
	 * byte, so that we don't throw an exception; if we throw an
	 * exception in the first pass, which is only checking for options
	 * whose values we need in order to properly dissect the packet
	 * on the second pass, we won't actually dissect the options, so
	 * you won't be able to see which option had the problem.
	 */
	if (first_pass) {
		if (!tvb_bytes_exist(tvb, voff+1, 1)) {
			/*
			 * We don't have the length byte; just return 1
			 * as the number of bytes we consumed, to count
			 * the code byte.
			 */
			return 1;
		}
	}
	optlen = tvb_get_guint8(tvb, voff+1);
	consumed = optlen + 2;

	/*
	 * In the first pass, we don't put anything into the protocol
	 * tree; we just check for some options we have to look at
	 * in order to properly process the packet:
	 *
	 *	52 (Overload) - we need this to properly dissect the
	 *	   file and sname fields
	 *
	 *	53 (DHCP message type) - if this is present, this is DHCP
	 *
	 *	60 (Vendor class identifier) - we need this in order to
	 *	   interpret the vendor-specific info
	 *
	 * We also check, before fetching anything, to make sure we
	 * have the entire item we're fetching, so that we don't throw
	 * an exception.
	 */
	if (first_pass) {
		if (tvb_bytes_exist(tvb, voff+2, consumed-2)) {
			switch (code) {

			case 52:
				*overload_p = tvb_get_guint8(tvb, voff+2);
				break;

			case 53:
				*dhcp_type_p =
				    val_to_str(tvb_get_guint8(tvb, voff+2),
					opt53_text,
					"Unknown Message Type (0x%02x)");
				break;

			case 60:
				*vendor_class_id_p =
				    tvb_get_ptr(tvb, voff+2, consumed-2);
				break;
			case 119:
				rfc3396_dns_domain_search_list.total_number_of_block++;
				break;
			case 120:
				rfc3396_sip_server.total_number_of_block++;
				break;
			}
		}

		/*
		 * We don't do anything else here.
		 */
		return consumed;
	}

	/* Normal cases */
	opt = bootp_get_opt(code);
	if (opt == NULL)
	{
		/* THIS SHOULD NEVER HAPPEN!!! */
		return consumed;
	}

	/* function type may be overridden and that shouldn't be a 'saved' change */
	ftype = opt->ftype;

	optoff = voff+2;

	vti = proto_tree_add_uint_format_value(bp_tree, hf_bootp_option_type,
		tvb, voff, consumed, code, "(%d) %s", code, opt->text);
	v_tree = proto_item_add_subtree(vti, ett_bootp_option);
	proto_tree_add_item(v_tree, hf_bootp_option_length, tvb, voff+1, 1, ENC_BIG_ENDIAN);

	ti = proto_tree_add_item(v_tree, hf_bootp_option_value, tvb, voff+2, optlen, ENC_NA);
	PROTO_ITEM_SET_HIDDEN(ti);

	/* Special cases */
	switch (code) {

	case 21:	/* Policy Filter */
		for (i = optoff, optleft = optlen;
			optleft > 0; i += 8, optleft -= 8) {
			if (optleft < 8) {
				expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "Option length isn't a multiple of 8");
				break;
			}

			proto_tree_add_item(v_tree, hf_bootp_option_policy_filter_ip, tvb, i, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(v_tree, hf_bootp_option_policy_filter_subnet_mask, tvb, i+4, 4, ENC_BIG_ENDIAN);
		}
		break;

	case 33:	/* Static Route */
		for (i = optoff, optleft = optlen;
			optleft > 0; i += 8, optleft -= 8) {
			if (optleft < 8) {
				expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "Option length isn't a multiple of 8");
				break;
			}

			proto_tree_add_item(v_tree, hf_bootp_option_static_route_ip, tvb, i, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(v_tree, hf_bootp_option_static_route_router, tvb, i+4, 4, ENC_BIG_ENDIAN);
		}
		break;

	case 43:	/* Vendor-Specific Info */
		s_option = tvb_get_guint8(tvb, optoff);

		/* PXE protocol 2.1 as described in the Intel specs */
		if (*vendor_class_id_p != NULL &&
		    strncmp((const gchar*)*vendor_class_id_p, "PXEClient", strlen("PXEClient")) == 0) {
			proto_item_append_text(vti, " (PXEClient)");
			v_tree = proto_item_add_subtree(vti, ett_bootp_option);

			optend = optoff + optlen;
			while (optoff < optend) {
				optoff = dissect_vendor_pxeclient_suboption(pinfo, vti, v_tree,
					tvb, optoff, optend);
			}
		} else if (*vendor_class_id_p != NULL &&
			   ((strncmp((const gchar*)*vendor_class_id_p, "pktc", strlen("pktc")) == 0) ||
			    (strncmp((const gchar*)*vendor_class_id_p, "docsis", strlen("docsis")) == 0) ||
			    (strncmp((const gchar*)*vendor_class_id_p, "OpenCable2.0", strlen("OpenCable2.0")) == 0) ||
			    (strncmp((const gchar*)*vendor_class_id_p, "CableHome", strlen("CableHome")) == 0))) {
			/* CableLabs standard - see www.cablelabs.com/projects */
			proto_item_append_text(vti, " (CableLabs)");

			optend = optoff + optlen;
			while (optoff < optend) {
				optoff = dissect_vendor_cablelabs_suboption(pinfo, vti, v_tree,
					tvb, optoff, optend);
			}
		} else if (*vendor_class_id_p != NULL &&
			   ((strncmp((const gchar*)*vendor_class_id_p, "ArubaAP", strlen("ArubaAP")) == 0) )) {
			/* Aruba AP */
			proto_item_append_text(vti, " (Aruba AP)");
			proto_tree_add_item(v_tree, hf_bootp_option43_arubaap_controllerip, tvb, optoff, optlen, ENC_ASCII|ENC_NA);
		} else if (*vendor_class_id_p != NULL &&
			   ((strncmp((const gchar*)*vendor_class_id_p, "ArubaInstantAP", strlen("ArubaInstantAP")) == 0) )) {
			gint32 nameorglen, ampiplen;
			/* Aruba  Instant AP */
			proto_item_append_text(vti, " (Aruba Instant AP)");
			vti = proto_tree_add_item(v_tree, hf_bootp_option43_arubaiap, tvb, optoff, optlen, ENC_ASCII|ENC_NA);
			v_tree = proto_item_add_subtree(vti, ett_bootp_option43_suboption);
			nameorglen = tvb_find_guint8(tvb, optoff, optlen, ',') - optoff;
			proto_tree_add_item(v_tree, hf_bootp_option43_arubaiap_nameorg, tvb, optoff, nameorglen, ENC_ASCII|ENC_NA);
			ampiplen = tvb_find_guint8(tvb, optoff+nameorglen+1, optlen-nameorglen-1, ',') - (optoff+nameorglen+1);
			proto_tree_add_item(v_tree, hf_bootp_option43_arubaiap_ampip, tvb, optoff+nameorglen+1, ampiplen, ENC_ASCII|ENC_NA);
			proto_tree_add_item(v_tree, hf_bootp_option43_arubaiap_password, tvb, optoff+nameorglen+1+ampiplen+1, optlen-(nameorglen+1+ampiplen+1), ENC_ASCII|ENC_NA);
		} else if (*vendor_class_id_p != NULL &&
			   ((strncmp((const gchar*)*vendor_class_id_p, PACKETCABLE_BSDP, strlen(PACKETCABLE_BSDP)) == 0) )) {
			/* Apple BSDP */
			proto_item_append_text(vti, " (Boot Server Discovery Protocol (BSDP))");

			optend = optoff + optlen;
			while (optoff < optend) {
				optoff = dissect_vendor_bsdp_suboption(pinfo, vti, v_tree,
					tvb, optoff, optend);
			}
		} else if ((s_option==58 || s_option==64 || s_option==65
			|| s_option==66 || s_option==67)
			&& test_encapsulated_vendor_options(tvb, optoff, optoff+optlen)) {
			/* Note that this is a rather weak (permissive) heuristic, */
			/* but since it comes last, I guess this is OK. */
			/* Add any stronger (less permissive) heuristics before this! */
			/* Alcatel-Lucent DHCP Extensions */
			proto_item_append_text(vti, " (Alcatel-Lucent)");
			optend = optoff + optlen;
			while (optoff < optend) {
				optoff = dissect_vendor_alcatel_suboption(pinfo, vti, v_tree,
					tvb, optoff, optend);
			}
		} else {
			/* Default Vendor-Specific Info.. display in bytes */
			proto_tree_add_item(v_tree, hf_bootp_option43_value, tvb, optoff, optlen, ENC_NA);
		}
		break;

	case 52:	/* Option Overload */
		if (optlen < 1) {
			expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "length isn't >= 1");
			break;
		}

		byte = tvb_get_guint8(tvb, optoff);
		proto_tree_add_item(v_tree, *opt->phf, tvb, optoff, 1, ENC_BIG_ENDIAN);

		/* Just in case we find an option 52 in sname or file */
		if (voff > VENDOR_INFO_OFFSET && byte >= 1 && byte <= 3) {
			if (byte & OPT_OVERLOAD_FILE) {
				proto_item *oti;
				proto_tree_add_subtree(bp_tree, tvb,
					FILE_NAME_OFFSET, FILE_NAME_LEN, ett_bootp_filename_option, &oti,
					"Boot file name option overload");
				o52voff = FILE_NAME_OFFSET;
				o52eoff = FILE_NAME_OFFSET + FILE_NAME_LEN;
				o52at_end = FALSE;
				rfc3396_dns_domain_search_list.index_current_block = 0;
				rfc3396_sip_server.index_current_block = 0;
				while (o52voff < o52eoff && !o52at_end) {
					o52voff += bootp_option(tvb, pinfo, bp_tree, bp_item, o52voff,
						o52eoff, FALSE, &o52at_end,
						dhcp_type_p, vendor_class_id_p,
						overload_p);
				}
				if (!o52at_end)
				{
					expert_add_info(pinfo, oti, &hf_bootp_opt_overload_file_end_missing);
				}
			}
			if (byte & OPT_OVERLOAD_SNAME) {
				proto_item *oti;
				proto_tree_add_subtree(bp_tree, tvb,
					SERVER_NAME_OFFSET, SERVER_NAME_LEN, ett_bootp_server_hostname, &oti,
					"Server host name option overload");
				o52voff = SERVER_NAME_OFFSET;
				o52eoff = SERVER_NAME_OFFSET + SERVER_NAME_LEN;
				o52at_end = FALSE;
				rfc3396_dns_domain_search_list.index_current_block = 0;
				rfc3396_sip_server.index_current_block = 0;
				while (o52voff < o52eoff && !o52at_end) {
					o52voff += bootp_option(tvb, pinfo, bp_tree, bp_item, o52voff,
						o52eoff, FALSE, &o52at_end,
						dhcp_type_p, vendor_class_id_p,
						overload_p);
				}
				if (!o52at_end)
				{
					expert_add_info(pinfo, oti, &hf_bootp_opt_overload_sname_end_missing);
				}
			}
			/* The final end option is not in overload */
			*overload_p = 0;
		}
		break;

	case 53:
		/* Show the message type name on the Message Type option, and in the protocol root */
		proto_item_append_text(vti, " (%s)", val_to_str(tvb_get_guint8(tvb, voff+2),
				       opt53_text,
				       "Unknown Message Type (0x%02x)"));
		proto_item_append_text(bp_item, " (%s)", val_to_str(tvb_get_guint8(tvb, voff+2),
				       opt53_text,
				       "Unknown Message Type (0x%02x)"));
		break;

	case 55:	/* Parameter Request List */
		for (i = 0; i < optlen; i++) {
			byte = tvb_get_guint8(tvb, optoff+i);
			proto_tree_add_uint_format_value(v_tree, hf_bootp_option_parameter_request_list_item,
					tvb, optoff+i, 1, byte, "(%d) %s", byte, bootp_get_opt_text(byte));
		}
		break;

	case 60:	/* Vendor class identifier */
		/*
		 * XXX - RFC 2132 says this is a string of octets;
		 * should we check for non-printables?
		 */

		proto_tree_add_item(v_tree, hf_bootp_option_vendor_class_id, tvb, optoff, consumed-2, ENC_ASCII|ENC_NA);
		if ((tvb_memeql(tvb, optoff, (const guint8*)PACKETCABLE_MTA_CAP10,
				      (int)strlen(PACKETCABLE_MTA_CAP10)) == 0)
		    ||
		    (tvb_memeql(tvb, optoff, (const guint8*)PACKETCABLE_MTA_CAP15,
				      (int)strlen(PACKETCABLE_MTA_CAP15)) == 0)
			||
			(tvb_memeql(tvb, optoff, (const guint8*)PACKETCABLE_MTA_CAP20,
				      (int)strlen(PACKETCABLE_MTA_CAP20)) == 0))
		{
			dissect_packetcable_mta_cap(v_tree, pinfo, tvb, optoff, optlen);
		} else
			if ((tvb_memeql(tvb, optoff, (const guint8*)PACKETCABLE_CM_CAP11,
				(int)strlen(PACKETCABLE_CM_CAP11)) == 0)
			||
			(tvb_memeql(tvb, optoff, (const guint8*)PACKETCABLE_CM_CAP20,
				(int)strlen(PACKETCABLE_CM_CAP20)) == 0 ))
		{
			dissect_docsis_cm_cap(v_tree, tvb, optoff, optlen, FALSE);
		} else
			if (tvb_memeql(tvb, optoff, (const guint8*)PACKETCABLE_CM_CAP30,
				(int)strlen(PACKETCABLE_CM_CAP30)) == 0 )
		{
			proto_tree_add_item(v_tree, hf_bootp_option_vendor_class_data, tvb, optoff, optlen, ENC_ASCII|ENC_NA);
		} else
			if (tvb_memeql(tvb, optoff, (const guint8*)PACKETCABLE_BSDPD,
				(int)strlen(PACKETCABLE_BSDPD)) == 0 )
		{
			proto_tree_add_item(v_tree, hf_bootp_option_vendor_class_data, tvb, optoff+(int)strlen(PACKETCABLE_BSDPD), optlen-(int)strlen(PACKETCABLE_BSDPD), ENC_ASCII|ENC_NA);
		}
		break;

	case 61:	/* Client Identifier */
		if (optlen > 0)
			byte = tvb_get_guint8(tvb, optoff);
		else
			byte = 0;

		/* We *MAY* use hwtype/hwaddr. If we have 7 bytes, I'll
		   guess that the first is the hwtype, and the last 6
		   are the hw addr */
		/* See http://www.iana.org/assignments/arp-parameters */
		/* RFC2132 9.14 Client-identifier has the following to say:
		   A hardware type of 0 (zero) should be used when the value
		   field contains an identifier other than a hardware address
		   (e.g. a fully qualified domain name). */

		if (optlen == 7 && byte > 0 && byte < 48) {
			proto_tree_add_item(v_tree,
					hf_bootp_hw_type, tvb, optoff, 1,
					ENC_NA);

			if (byte == ARPHRD_ETHER || byte == ARPHRD_IEEE802)
				proto_tree_add_item(v_tree,
					hf_bootp_hw_ether_addr, tvb, optoff+1, 6,
					ENC_NA);
			else
				proto_tree_add_string(v_tree, hf_bootp_client_hardware_address, tvb, optoff+1, 6,
					tvb_arphrdaddr_to_str(tvb, optoff+1, 6, byte));
		} else if (optlen == 17 && byte == 0) {
			/* Identifier is a UUID */
			proto_tree_add_item(v_tree, hf_bootp_client_identifier_uuid, tvb, optoff + 1, 16, bootp_uuid_endian);

		/* From RFC 4361 paragraph 6.1 DHCPv4 Client Behavior:
			To send an RFC 3315-style binding identifier in a DHCPv4 'client
			identifier' option, the type of the 'client identifier' option is set
			to 255.	*/
		} else if (byte == 255) {
			guint16	duidtype;
			guint16	hwtype;

			/*	The type field is immediately followed by the IAID, which is
				an opaque 32-bit quantity	*/
			proto_tree_add_string(v_tree, hf_bootp_client_id_iaid, tvb, optoff+1, 4,
				tvb_arphrdaddr_to_str(tvb, optoff+1, 4, byte));
			optoff = optoff + 5;
			duidtype = tvb_get_ntohs(tvb, optoff);
			proto_tree_add_item(v_tree, hf_bootp_client_id_duid_type, tvb, optoff, 2, ENC_BIG_ENDIAN);
			switch (duidtype) {
			case DUID_LLT:
				if (optlen < 8) {
					expert_add_info(pinfo, vti, &ei_bootp_mal_duid);
					break;
				}
				hwtype=tvb_get_ntohs(tvb, optoff + 2);
				proto_tree_add_item(v_tree, hf_bootp_client_identifier_duid_llt_hw_type,
						tvb, optoff + 2, 2, ENC_BIG_ENDIAN);

				/* XXX seconds since Jan 1 2000 */
				proto_tree_add_item(v_tree, hf_bootp_client_identifier_time, tvb, optoff + 4, 4, ENC_BIG_ENDIAN);
				if (optlen > 8) {
					proto_tree_add_string(v_tree, hf_bootp_client_identifier_link_layer_address, tvb, optoff + 8,
						optlen - 13, tvb_arphrdaddr_to_str(tvb, optoff+8, optlen-13, hwtype));
				}
				break;
			case DUID_EN:
				if (optlen < 6) {
					expert_add_info(pinfo, vti, &ei_bootp_mal_duid);
					break;
				}
				proto_tree_add_item(v_tree, hf_bootp_client_identifier_enterprise_num, tvb, optoff + 2, 4, ENC_BIG_ENDIAN);
				if (optlen > 6) {
					proto_tree_add_item(v_tree, hf_bootp_client_identifier, tvb, optoff + 6, optlen - 11, ENC_NA);
				}
				break;
			case DUID_LL:
				if (optlen < 4) {
					expert_add_info(pinfo, vti, &ei_bootp_mal_duid);
					break;
				}
				hwtype=tvb_get_ntohs(tvb, optoff + 2);
				proto_tree_add_item(v_tree, hf_bootp_client_identifier_duid_ll_hw_type,
						tvb, optoff + 2, 2, ENC_BIG_ENDIAN);

				if (optlen > 4) {
					proto_tree_add_string(v_tree, hf_bootp_client_identifier_link_layer_address, tvb, optoff + 4,
						optlen - 9, tvb_arphrdaddr_to_str(tvb, optoff+4, optlen-9, hwtype));
				}
				break;
			}
		} else if (byte == 0 && optlen > 1) {
			/* identifier other than a hardware address (e.g. a fully qualified domain name) */
			proto_tree_add_item(v_tree, hf_bootp_client_identifier_type, tvb, optoff, 1, ENC_NA);
			proto_tree_add_item(v_tree, hf_bootp_client_identifier_undef, tvb, optoff+1, optlen-1, ENC_ASCII|ENC_NA);
		} else {
			/* otherwise, it's opaque data */
		}
		break;
	case 77: {	/* User Class Information RFC 3004 */
		guchar user_class_instance_index;
		proto_item *vtix;
		proto_tree *o77_v_tree;
		if (optlen < 2) {
			expert_add_info_format(pinfo, v_tree, &ei_bootp_bad_length, "length isn't >= 2");
			break;
		}
		optleft = optlen;
		for (user_class_instance_index = 0, i = 0, byte = tvb_get_guint8(tvb, optoff); i < optlen; byte = tvb_get_guint8(tvb, optoff + i), user_class_instance_index++) {
			/* Create subtree for instance of User Class. */
			vtix = proto_tree_add_uint_format_value(v_tree, hf_bootp_option77_user_class,
					tvb, optoff + i, byte + 1, user_class_instance_index, "[%d]", user_class_instance_index);
			o77_v_tree = proto_item_add_subtree(vtix, ett_bootp_option77_instance);

			/* Add length for instance of User Class. */
			proto_tree_add_item(o77_v_tree, hf_bootp_option77_user_class_length,
					tvb, optoff + i, 1, ENC_BIG_ENDIAN);

			if (byte == 0) {
				expert_add_info_format(pinfo, vtix, &ei_bootp_bad_length, "UC_Len_%u isn't >= 1 (UC_Len_%u = 0)", user_class_instance_index, user_class_instance_index);
				break;
			}
			optleft -= byte + 1;
			if (optleft < 0) {
				expert_add_info(pinfo, vtix, &ei_bootp_option77_user_class_malformed);
				break;
			}

			/* Add data for instance of User Class. */
			proto_tree_add_item(o77_v_tree, hf_bootp_option77_user_class_data,
					tvb, optoff + i + 1, byte, ENC_NA);

			/* Slide to next instance of User Class if any. */
			i += byte + 1;
		}
		break;
	}
	case 97:	/* Client Identifier (UUID) */
		if (optlen > 0)
			byte = tvb_get_guint8(tvb, optoff);
		else
			byte = 0;

		/* We *MAY* use hwtype/hwaddr. If we have 7 bytes, I'll
		   guess that the first is the hwtype, and the last 6
		   are the hw addr */
		/* See http://www.iana.org/assignments/arp-parameters */
		/* RFC2132 9.14 Client-identifier has the following to say:
		   A hardware type of 0 (zero) should be used when the value
		   field contains an identifier other than a hardware address
		   (e.g. a fully qualified domain name). */

		if (optlen == 7 && byte > 0 && byte < 48) {
			proto_tree_add_item(v_tree,
					hf_bootp_hw_type, tvb, optoff, 1,
					ENC_NA);
			if (byte == ARPHRD_ETHER || byte == ARPHRD_IEEE802)
				proto_tree_add_item(v_tree,
					hf_bootp_hw_ether_addr, tvb, optoff+1, 6,
					ENC_NA);
			else
				proto_tree_add_string(v_tree, hf_bootp_client_hardware_address, tvb, optoff+1, 6,
					tvb_arphrdaddr_to_str(tvb, optoff+1, 6, byte));
		} else if (optlen == 17 && byte == 0) {
			/* Identifier is a UUID */
			proto_tree_add_item(v_tree, hf_bootp_client_identifier_uuid, tvb, optoff + 1, 16, bootp_uuid_endian);
		} else {
			/* otherwise, it's opaque data */
		}
		break;

	case 63:	/* NetWare/IP options (RFC 2242) */

		optend = optoff + optlen;
		while (optoff < optend)
			optoff = dissect_netware_ip_suboption(pinfo, vti, v_tree, tvb, optoff, optend);
		break;

	case 78:	/* SLP Directory Agent Option RFC2610 Added by Greg Morris (gmorris@novell.com)*/
		if (optlen < 1) {
			expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "length isn't >= 1");
			break;
		}
		optleft = optlen;
		byte = tvb_get_guint8(tvb, optoff);
		proto_tree_add_item(v_tree, hf_bootp_option_slp_directory_agent_value, tvb, optoff, 1, ENC_BIG_ENDIAN);

		optoff++;
		optleft--;
		if (byte == 0x80) {
			if (optleft == 0)
				break;
			optoff++;
			optleft--;
		}
		for (i = optoff; optleft > 0; i += 4, optleft -= 4) {
			if (optleft < 4) {
				expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "Option length isn't a multiple of 4");
				break;
			}

			proto_tree_add_item(v_tree, hf_bootp_option_slp_directory_agent_slpda_address, tvb, i, 4, ENC_BIG_ENDIAN);
		}
		break;

	case 79:	/* SLP Service Scope Option RFC2610 Added by Greg Morris (gmorris@novell.com)*/
		proto_tree_add_item(v_tree, hf_bootp_option_slp_service_scope_value, tvb, optoff, 1, ENC_BIG_ENDIAN);

		optoff++;
		optleft = optlen - 1;
		proto_tree_add_item(v_tree, hf_bootp_option_slp_service_scope_string, tvb, optoff, optleft, ENC_ASCII|ENC_NA);
		break;

	case 81:	/* Client Fully Qualified Domain Name */
		{
		static const int * fqdn_hf_flags[] = {
			&hf_bootp_fqdn_mbz,
			&hf_bootp_fqdn_n,
			&hf_bootp_fqdn_e,
			&hf_bootp_fqdn_o,
			&hf_bootp_fqdn_s,
			NULL
		};

		if (optlen < 3) {
			expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "length isn't >= 3");
			break;
		}

		fqdn_flags = tvb_get_guint8(tvb, optoff);
		proto_tree_add_bitmask(v_tree, tvb, optoff, hf_bootp_fqdn_flags,
					ett_bootp_fqdn_flags, fqdn_hf_flags, ENC_BIG_ENDIAN);

		/* XXX: use code from packet-dns for return code decoding */
		proto_tree_add_item(v_tree, hf_bootp_fqdn_rcode1, tvb, optoff+1, 1, ENC_BIG_ENDIAN);
		/* XXX: use code from packet-dns for return code decoding */
		proto_tree_add_item(v_tree, hf_bootp_fqdn_rcode2, tvb, optoff+2, 1, ENC_BIG_ENDIAN);
		if (optlen > 3) {
			if (fqdn_flags & F_FQDN_E) {
				get_dns_name(tvb, optoff+3, optlen-3, optoff+3, &dns_name);
				proto_tree_add_string(v_tree, hf_bootp_fqdn_name,
				    tvb, optoff+3, optlen-3, dns_name);
			} else {
				proto_tree_add_item(v_tree, hf_bootp_fqdn_asciiname,
				    tvb, optoff+3, optlen-3, ENC_ASCII|ENC_NA);
			}
		}
		}
		break;

	case 82:	/* Relay Agent Information Option */
		optend = optoff + optlen;
		while (optoff < optend)
			optoff = bootp_dhcp_decode_agent_info(pinfo, vti, v_tree, tvb, optoff, optend);
		break;

	case 83:	/* iSNS Option (RFC 4174) */
		optoff = dissect_isns(pinfo, vti, v_tree, tvb, optoff, optlen);
		break;

	case 85:	/* Novell Servers (RFC 2241) */
		/* Option 85 can be sent as a string */
		/* Added by Greg Morris (gmorris[AT]novell.com) */
		if (novell_string) {
			proto_tree_add_item(v_tree, hf_bootp_option_novell_dss_string, tvb, optoff, optlen, ENC_ASCII|ENC_NA);
		} else{
			/* IP addresses */
			for (i = optoff, optleft = optlen; optleft > 0;
				i += 4, optleft -= 4) {
				if (optleft < 4) {
					expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "Option length isn't a multiple of 4");
					break;
				}

				proto_tree_add_item(v_tree, hf_bootp_option_novell_dss_ip, tvb, i, 4, ENC_BIG_ENDIAN);
			}
		}
		break;

	case 94: {	/* Client network interface identifier */
		guint8 id_type;

		id_type = tvb_get_guint8(tvb, optoff);

		if (id_type == 0x01) {
			proto_tree_add_item(v_tree, hf_bootp_option_client_network_id_major_ver,
								tvb, optoff + 1, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(v_tree, hf_bootp_option_client_network_id_minor_ver,
								tvb, optoff + 2, 1, ENC_LITTLE_ENDIAN);
		}

		break;
	}

	case 90:	/* DHCP Authentication */
		if (optlen < 11) {
			expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "length isn't >= 11");
			break;
		}
		optleft = optlen;
		protocol = tvb_get_guint8(tvb, optoff);

		proto_tree_add_item(v_tree, hf_bootp_option_dhcp_authentication_protocol, tvb, optoff, 1, ENC_BIG_ENDIAN);
		optoff++;
		optleft--;

		algorithm = tvb_get_guint8(tvb, optoff);
		switch (protocol) {

		case AUTHEN_PROTO_DELAYED_AUTHEN:
			proto_tree_add_item(v_tree, hf_bootp_option_dhcp_authentication_alg_delay, tvb, optoff, 1, ENC_BIG_ENDIAN);
			break;

		default:
			proto_tree_add_item(v_tree, hf_bootp_option_dhcp_authentication_algorithm, tvb, optoff, 1, ENC_BIG_ENDIAN);
			break;
		}
		optoff++;
		optleft--;

		rdm = tvb_get_guint8(tvb, optoff);
		proto_tree_add_item(v_tree, hf_bootp_option_dhcp_authentication_rdm, tvb, optoff, 1, ENC_BIG_ENDIAN);
		optoff++;
		optleft--;

		switch (rdm) {

		case AUTHEN_RDM_MONOTONIC_COUNTER:
			proto_tree_add_item(v_tree, hf_bootp_option_dhcp_authentication_rdm_replay_detection, tvb, optoff, 8, ENC_BIG_ENDIAN);
			break;

		default:
			proto_tree_add_item(v_tree, hf_bootp_option_dhcp_authentication_rdm_rdv, tvb, optoff, 8, ENC_ASCII|ENC_NA);
			break;
		}
		optoff += 8;
		optleft -= 8;

		switch (protocol) {

		case AUTHEN_PROTO_DELAYED_AUTHEN:
			switch (algorithm) {

			case AUTHEN_DELAYED_ALGO_HMAC_MD5:
				if (*dhcp_type_p && !strcmp(*dhcp_type_p, OPT53_DISCOVER)) {
					/* Discover has no Secret ID nor HMAC MD5 Hash */
					break;
				} else {
					if (optlen < 31) {
						expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "length isn't >= 31");
						break;
					}

					proto_tree_add_item(v_tree, hf_bootp_option_dhcp_authentication_secret_id, tvb, optoff, 4, ENC_BIG_ENDIAN);
					optoff += 4;
					/*optleft -= 4;*/
					proto_tree_add_item(v_tree, hf_bootp_option_dhcp_authentication_hmac_md5_hash, tvb, optoff, 16, ENC_ASCII|ENC_NA);
					break;
				}

			default:
				if (optleft == 0)
					break;

				proto_tree_add_item(v_tree, hf_bootp_option_dhcp_authentication_information, tvb, optoff, optleft, ENC_ASCII|ENC_NA);
				break;
			}
			break;

		default:
			if (optleft == 0)
				break;

			proto_tree_add_item(v_tree, hf_bootp_option_dhcp_authentication_information, tvb, optoff, optleft, ENC_ASCII|ENC_NA);
			break;
		}
		break;

	case 99: /* civic location (RFC 4776) */

		optleft = optlen;
		if (optleft >= 3)
		{
			proto_tree_add_item(v_tree, hf_bootp_option_civic_location_what, tvb, optoff, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(v_tree, hf_bootp_option_civic_location_country, tvb, optoff+1, 2, ENC_ASCII|ENC_NA);
			optleft = optleft - 3;
			optoff = optoff + 3;

			while (optleft >= 2)
			{
				int calength = tvb_get_guint8(tvb, optoff+1);
				proto_tree_add_item(v_tree, hf_bootp_option_civic_location_ca_type, tvb, optoff, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(v_tree, hf_bootp_option_civic_location_ca_length, tvb, optoff+1, 1, ENC_BIG_ENDIAN);

				optoff += 2;
				optleft -= 2;

				if (calength == 0)
					continue;

				if (optleft >= calength)
				{
					proto_tree_add_item(v_tree, hf_bootp_option_civic_location_ca_value, tvb, optoff, calength, ENC_ASCII|ENC_NA);

					optoff = optoff + calength;
					optleft = optleft - calength;
				}
				else
				{
					optleft = 0;
					expert_add_info(pinfo, vti, &ei_bootp_option_civic_location_bad_cattype);
				}
			}
		}
		break;

	case 117:   /* The Name Service Search Option for DHCP (RFC 2937) */
		if (optlen < 2) {
			expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "length isn't >= 2");
		} else if (optlen & 1) {
			expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "length (%u) isn't even number", optlen);
		} else {
			guint16 ns;
			for (i = 0, ns = tvb_get_ntohs(tvb, optoff); i < optlen; i += 2, ns = tvb_get_ntohs(tvb, optoff + i)) {
				switch (ns) {
				case RFC2937_LOCAL_NAMING_INFORMATION:
					proto_tree_add_string(v_tree, hf_bootp_option_dhcp_name_service_search_option, tvb, optoff + i, 2, "Local naming information (e.g., an /etc/hosts file on a UNIX machine) (0)");
					break;
				case RFC2937_DOMAIN_NAME_SERVER_OPTION:
					proto_tree_add_string(v_tree, hf_bootp_option_dhcp_name_service_search_option, tvb, optoff + i, 2, "Domain Name Server Option (6)");
					break;
				case RFC2937_NETWORK_INFORMATION_SERVERS_OPTION:
					proto_tree_add_string(v_tree, hf_bootp_option_dhcp_name_service_search_option, tvb, optoff + i, 2, "Network Information Servers Option (41)");
					break;
				case RFC2937_NETBIOS_OVER_TCP_IP_NAME_SERVER_OPTION:
					proto_tree_add_string(v_tree, hf_bootp_option_dhcp_name_service_search_option, tvb, optoff + i, 2, "NetBIOS over TCP/IP Name Server Option (44)");
					break;
				case RFC2937_NETWORK_INFORMATION_SERVICE_PLUS_SERVERS_OPTION:
					proto_tree_add_string(v_tree, hf_bootp_option_dhcp_name_service_search_option, tvb, optoff + i, 2, "Network Information Service+ Servers Option (65)");
					break;
				default:
					expert_add_info_format(pinfo, vti, &ei_bootp_option_dhcp_name_service_invalid,
								"Invalid Name Service (%u). RFC 2937 defines only 0, 6, 41, 44, and 65 as possible values.", ns);
					break;
				}
			}
		}
		break;

	case 119: { /* Dynamic Host Configuration Protocol (DHCP) Domain Search Option (RFC 3397) */
		    /* Encoding Long Options in the Dynamic Host Configuration Protocol (DHCPv4) (RFC 3396) */
		    /* Domain Names - Implementation And Specification (RFC 1035) */
		char tmpChar[BOOTP_MAX_NO_CHAR];
		rfc3396_dns_domain_search_list.index_current_block++;
		if (rfc3396_dns_domain_search_list.total_number_of_block > 1) {
			g_snprintf(tmpChar, BOOTP_MAX_NO_CHAR, "%u/%u", rfc3396_dns_domain_search_list.index_current_block, rfc3396_dns_domain_search_list.total_number_of_block);
			proto_tree_add_string(v_tree, hf_bootp_option_dhcp_dns_domain_search_list_rfc_3396_detected, tvb, optoff, optlen, tmpChar);
			if (rfc3396_dns_domain_search_list.index_current_block != rfc3396_dns_domain_search_list.total_number_of_block) {
				g_snprintf(tmpChar, BOOTP_MAX_NO_CHAR, "%u/%u", rfc3396_dns_domain_search_list.total_number_of_block, rfc3396_dns_domain_search_list.total_number_of_block);
				proto_tree_add_string(v_tree, hf_bootp_option_dhcp_dns_domain_search_list_refer_last_option, tvb, optoff, optlen, tmpChar);
			}
		}

		if (rfc3396_dns_domain_search_list.tvb_composite == NULL && optlen) {
			/* We use composite tvb for managing RFC 3396 */
			rfc3396_dns_domain_search_list.tvb_composite = tvb_new_composite();
		}

		/* Concatenate the block before being interpreted for managing RFC 3396 */
		if (optlen)
			tvb_composite_append(rfc3396_dns_domain_search_list.tvb_composite, tvb_new_subset_length(tvb, optoff, optlen));

		if (rfc3396_dns_domain_search_list.index_current_block == rfc3396_dns_domain_search_list.total_number_of_block
		    && rfc3396_dns_domain_search_list.tvb_composite) {
			/* Here, we are into the last (or unique) option 119. */
			/* We will display the information about fqdn */
			unsigned int consumedx = 0;
			unsigned int offset = 0;
			tvb_composite_finalize(rfc3396_dns_domain_search_list.tvb_composite);

			while (offset < tvb_reported_length(rfc3396_dns_domain_search_list.tvb_composite)) {
				/* use the get_dns_name method that manages all techniques of RFC 1035 (compression pointer and so on) */
				consumedx = get_dns_name(rfc3396_dns_domain_search_list.tvb_composite, offset, tvb_reported_length(rfc3396_dns_domain_search_list.tvb_composite), 0, &dns_name);
				if (rfc3396_dns_domain_search_list.total_number_of_block == 1) {
					/* RFC 3396 is not used, so we can easily link the fqdn with v_tree. */
					proto_tree_add_string(v_tree, hf_bootp_option_dhcp_dns_domain_search_list_fqdn, tvb, optoff + offset, consumedx, dns_name);
				} else {
					/* RFC 3396 is used, so the option is split into several option 119. We don't link fqdn with v_tree. */
					proto_tree_add_string(v_tree, hf_bootp_option_dhcp_dns_domain_search_list_fqdn, tvb, 0, 0, dns_name);
				}
				offset += consumedx;
			}
			rfc3396_dns_domain_search_list.tvb_composite = NULL;
		}
		break;
	}
	case 120: { /* SIP Servers (RFC 3361) */
		    /* Encoding Long Options in the Dynamic Host Configuration Protocol (DHCPv4) (RFC 3396) */
		    /* Domain Names - Implementation And Specification (RFC 1035) */
		char tmpChar[BOOTP_MAX_NO_CHAR];
		rfc3396_sip_server.index_current_block++;
		if (rfc3396_sip_server.total_number_of_block > 1) {
			g_snprintf(tmpChar, BOOTP_MAX_NO_CHAR, "%u/%u", rfc3396_sip_server.index_current_block, rfc3396_sip_server.total_number_of_block);
			proto_tree_add_string(v_tree, hf_bootp_option_sip_server_rfc_3396_detected, tvb, optoff, optlen, tmpChar);
			if (rfc3396_sip_server.index_current_block != rfc3396_sip_server.total_number_of_block) {
				g_snprintf(tmpChar, BOOTP_MAX_NO_CHAR, "%u/%u", rfc3396_sip_server.total_number_of_block, rfc3396_sip_server.total_number_of_block);
				proto_tree_add_string(v_tree, hf_bootp_option_sip_server_refer_last_option, tvb, optoff, optlen, tmpChar);
			}
		}

		if (rfc3396_sip_server.tvb_composite == NULL && optlen) {
			/* We use composite tvb for managing RFC 3396 */
			rfc3396_sip_server.tvb_composite = tvb_new_composite();
		}

		/* Concatenate the block before being interpreted for managing RFC 3396 */
		if (optlen)
			tvb_composite_append(rfc3396_sip_server.tvb_composite, tvb_new_subset_length(tvb, optoff, optlen));

		if (rfc3396_sip_server.index_current_block == rfc3396_sip_server.total_number_of_block
		    && rfc3396_sip_server.tvb_composite) {
			/* Here, we are into the last (or unique) option 120. */
			/* We will display the information about SIP server */
			guint8 enc;
			unsigned int offset = 1; /* ignore enc */
			tvb_composite_finalize(rfc3396_sip_server.tvb_composite);

			enc = tvb_get_guint8(rfc3396_sip_server.tvb_composite, 0);
			if (rfc3396_sip_server.total_number_of_block == 1) {
				/* RFC 3396 is not used, so we can easily link the fqdn with v_tree. */
				proto_tree_add_uint(v_tree, hf_bootp_option_sip_server_enc, tvb, optoff, 1, enc);
			} else {
				/* RFC 3396 is used, so the option is split into several option 120. We don't link fqdn with v_tree. */
				proto_tree_add_uint(v_tree, hf_bootp_option_sip_server_enc, tvb, 0, 0, enc);
			}

			switch (enc) {
			case RFC_3361_ENC_FQDN: {
				unsigned int consumedx = 0;
				if (tvb_reported_length(rfc3396_sip_server.tvb_composite) < 3) {
					expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "length isn't >= 3 (len = %u)", tvb_reported_length(rfc3396_sip_server.tvb_composite));
					break;
				}

				while (offset < tvb_reported_length(rfc3396_sip_server.tvb_composite)) {
					/* use the get_dns_name method that manages all techniques of RFC 1035 (compression pointer and so on) */
					consumedx = get_dns_name(rfc3396_sip_server.tvb_composite, offset, tvb_reported_length(rfc3396_sip_server.tvb_composite), 1 /* ignore enc */, &dns_name);

					if (rfc3396_sip_server.total_number_of_block == 1) {
						/* RFC 3396 is not used, so we can easily link the fqdn with v_tree. */
						proto_tree_add_string(v_tree, hf_bootp_option_sip_server_name, tvb, optoff + offset, consumedx, dns_name);
					} else {
						/* RFC 3396 is used, so the option is split into several option 120. We don't link fqdn with v_tree. */
						proto_tree_add_string(v_tree, hf_bootp_option_sip_server_name, tvb, 0, 0, dns_name);
					}
					offset += consumedx;
				}
				rfc3396_sip_server.tvb_composite = NULL;
				break;
			}
			case RFC_3361_ENC_IPADDR:
				if (tvb_reported_length(rfc3396_sip_server.tvb_composite) < 5) {
					expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "length isn't >= 5 (len = %u)", tvb_reported_length(rfc3396_sip_server.tvb_composite));
					break;
				}
				/* x % 2^n == x & (2^n - 1) note : (assuming x is a positive integer) */
				if ((tvb_reported_length(rfc3396_sip_server.tvb_composite) - 1) & 3) {
					if (rfc3396_sip_server.total_number_of_block == 1)
						expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "length isn't a multiple of 4 plus 1 (len = %u).", tvb_reported_length(rfc3396_sip_server.tvb_composite));
					else
						expert_add_info_format(pinfo, vti, &ei_bootp_bad_length,
							"length isn't a multiple of 4 plus 1 (len = %u). For your information with RFC 3396, the length is the length sum of all options 120 into this BOOTP packet.",
							tvb_reported_length(rfc3396_sip_server.tvb_composite));
					break;
				}
				while (offset < tvb_reported_length(rfc3396_sip_server.tvb_composite)) {
					if (rfc3396_sip_server.total_number_of_block == 1) {
						/* RFC 3396 is not used, so we can easily link the fqdn with v_tree. */
						proto_tree_add_item(v_tree, hf_bootp_option_sip_server_address, rfc3396_sip_server.tvb_composite, offset, 4, ENC_BIG_ENDIAN);
					} else {
						/* RFC 3396 is used, so the option is split into several option 120. We don't link fqdn with v_tree. */
						/* Since we don't use the "numbered argument" as described by README.developer, we have to repeat the arguments :( */
						g_snprintf(tmpChar, BOOTP_MAX_NO_CHAR, "%u.%u.%u.%u (%u.%u.%u.%u)",
							   tvb_get_guint8(rfc3396_sip_server.tvb_composite, offset),
							   tvb_get_guint8(rfc3396_sip_server.tvb_composite, offset + 1),
							   tvb_get_guint8(rfc3396_sip_server.tvb_composite, offset + 2),
							   tvb_get_guint8(rfc3396_sip_server.tvb_composite, offset + 3),
							   tvb_get_guint8(rfc3396_sip_server.tvb_composite, offset),
							   tvb_get_guint8(rfc3396_sip_server.tvb_composite, offset + 1),
							   tvb_get_guint8(rfc3396_sip_server.tvb_composite, offset + 2),
							   tvb_get_guint8(rfc3396_sip_server.tvb_composite, offset + 3)
							   );
						proto_tree_add_string(v_tree, hf_bootp_option_sip_server_address_stringz, tvb, 0, 0, tmpChar);
					}
					offset += 4;
				}
				break;
			default:
				expert_add_info_format(pinfo, vti, &ei_bootp_option_sip_server_address_encoding, "RFC 3361 defines only 0 and 1 for Encoding byte (Encoding = %u).", enc);
				break;
			}
		}
		break;
	}
	case 121:	/* Classless Static Route */
	case 249: {	/* Classless Static Route (Microsoft) */
		int mask_width, significant_octets;
		optend = optoff + optlen;
		/* minimum length is 5 bytes */
		if (optlen < 5) {
			expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "length isn't >= 5");
			break;
		}
		while (optoff < optend) {
			mask_width = tvb_get_guint8(tvb, optoff);
			/* mask_width <= 32 */
			if (mask_width > 32) {
				expert_add_info_format(pinfo, vti, &ei_bootp_option_classless_static_route, "Mask width (%d) > 32", mask_width);
				break;
			}
			significant_octets = (mask_width + 7) / 8;
			vti = proto_tree_add_bytes_format(v_tree, hf_bootp_option_classless_static_route, tvb, optoff,
				1 + significant_octets + 4, NULL,
				" ");
			optoff++;
			/* significant octets + router(4) */
			if (optend < optoff + significant_octets + 4) {
				expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "Remaining length (%d) < %d bytes", optend - optoff, significant_octets + 4);
				break;
			}
			if(mask_width == 0)
				proto_item_append_text(vti, "default");
			else {
				for(i = 0 ; i < significant_octets ; i++) {
					if (i > 0)
						proto_item_append_text(vti, ".");
					byte = tvb_get_guint8(tvb, optoff++);
					proto_item_append_text(vti, "%d", byte);
				}
				for(i = significant_octets ; i < 4 ; i++)
					proto_item_append_text(vti, ".0");
				proto_item_append_text(vti, "/%d", mask_width);
			}
			proto_item_append_text(vti, "-%s", tvb_ip_to_str(tvb, optoff));
			optoff += 4;
		}
		break;
	}

	case 123: /* coordinate based location RFC 3825 or CableLabs DSS_ID  */
		if (optlen == 16) {
			int c;
			unsigned char lci[16];
			struct rfc3825_location_fixpoint_t location_fp;
			struct rfc3825_location_decimal_t location;

			for (c=0; c < 16;c++)
				lci[c] = (unsigned char) tvb_get_guint8(tvb, optoff + c);

			/* convert lci encoding into fixpoint location */
			rfc3825_lci_to_fixpoint(lci, &location_fp);

			/* convert location from decimal to fixpoint */
			i = rfc3825_fixpoint_to_decimal(&location_fp, &location);

			if (i != RFC3825_NOERROR) {
				ti = proto_tree_add_uint(v_tree, hf_bootp_option_rfc3825_error, tvb, optoff, 1, i);
			proto_item_set_len(ti, optlen);
			} else {
				proto_tree_add_double_format_value(v_tree, hf_bootp_option_rfc3825_latitude, tvb, optoff, 5, location.latitude, "%15.10f", location.latitude);
				proto_tree_add_double_format_value(v_tree, hf_bootp_option_rfc3825_longitude, tvb, optoff+5, 5, location.longitude, "%15.10f", location.longitude);
				proto_tree_add_double_format_value(v_tree, hf_bootp_option_rfc3825_latitude_res, tvb, optoff, 1, location.latitude_res, "%15.10f", location.latitude_res);
				proto_tree_add_double_format_value(v_tree, hf_bootp_option_rfc3825_longitude_res, tvb, optoff+5, 1, location.longitude_res, "%15.10f", location.longitude_res);
				proto_tree_add_double_format_value(v_tree, hf_bootp_option_rfc3825_altitude, tvb, optoff+12, 4, location.altitude, "%15.10f", location.altitude);
				proto_tree_add_double_format_value(v_tree, hf_bootp_option_rfc3825_altitide_res, tvb, optoff+10, 2, location.altitude_res, "%15.10f", location.altitude_res);
				proto_tree_add_uint(v_tree, hf_bootp_option_rfc3825_altitude_type, tvb, optoff+10, 1, location.altitude_type);
				proto_tree_add_uint(v_tree, hf_bootp_option_rfc3825_map_datum, tvb, optoff+15, 1, location.datum_type);
			}
		} else if (optlen < 69) { /* CableLabs DSS_ID */

			proto_tree_add_item(v_tree, hf_bootp_option_cl_dss_id_option, tvb, optoff, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(v_tree, hf_bootp_option_cl_dss_id_len, tvb, optoff+1, 1, ENC_BIG_ENDIAN);
			s_len = tvb_get_guint8(tvb, optoff+1);
			proto_tree_add_item(v_tree, hf_bootp_option_cl_dss_id, tvb, optoff+2, s_len, ENC_ASCII|ENC_NA);

			if (optlen > s_len+2) { /* Second DSS_ID*/

				proto_tree_add_item(v_tree, hf_bootp_option_cl_dss_id_option, tvb, optoff+2+s_len, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(v_tree, hf_bootp_option_cl_dss_id_len, tvb, optoff+1+2+s_len, 1, ENC_BIG_ENDIAN);
				s_len = tvb_get_guint8(tvb, optoff+1+2+s_len);
				proto_tree_add_item(v_tree, hf_bootp_option_cl_dss_id, tvb, optoff+2+2+s_len, s_len, ENC_ASCII|ENC_NA);
			}
		} else {
			expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "Invalid length of DHCP option!");
		}
		break;

	case 124: {	/* V-I Vendor Class (RFC 3925) */
		int data_len;

		if (optlen == 1) {
			/* CableLab specific */
			proto_tree_add_item(v_tree, hf_bootp_option_vi_class_cl_address_mode, tvb, optoff, optlen, ENC_BIG_ENDIAN);
			break;
		}

		optleft = optlen;

		while (optleft > 0) {

			if (optleft < 5) {
				expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "length < 5");
				break;
			}

			proto_tree_add_item(v_tree, hf_bootp_option_vi_class_enterprise, tvb, optoff, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(v_tree, hf_bootp_option_vi_class_data_length, tvb, optoff, 1, ENC_BIG_ENDIAN);
			data_len = tvb_get_guint8(tvb, optoff + 4);

			optoff += 5;
			optleft -= 5;

			proto_tree_add_item(v_tree, hf_bootp_option_vi_class_data, tvb, optoff, data_len, ENC_ASCII|ENC_NA);

			/* look for next enterprise number */
			optoff += data_len;
			optleft -= data_len;
		}
		break;
	}

	case 125: {	/* V-I Vendor-specific Information (RFC 3925) */
		int enterprise = 0;
		int s_end = 0;
		int option_data_len = 0;
		proto_tree *e_tree = 0;

		optend = optoff + optlen;
		optleft = optlen;

		while (optleft > 0) {

			if (optleft < 5) {
				expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "length < 5");
				break;
			}

			enterprise = tvb_get_ntohl(tvb, optoff);
			vti = proto_tree_add_item(v_tree, hf_bootp_option125_enterprise, tvb, optoff, 4, ENC_BIG_ENDIAN);
			e_tree = proto_item_add_subtree(vti, ett_bootp_option);

			optoff += 4;
			optleft -= 4;

			proto_tree_add_item_ret_uint(e_tree, hf_bootp_option125_length, tvb, optoff, 1, ENC_NA, &option_data_len);

			optoff += 1;
			optleft -= 1;

			s_end = optoff + option_data_len;
			if ( s_end > optend ) {
				expert_add_info_format(pinfo, vti, &ei_bootp_option125_enterprise_malformed, "no room left in option for enterprise %u data", enterprise);
				break;
			}

			while (optoff < s_end) {
				switch (enterprise) {

				case 3561: /* ADSL Forum */
					optoff = dissect_vendor_tr111_suboption(pinfo, vti, e_tree, tvb, optoff, s_end);
				break;

				case 4491: /* CableLab */
					optoff = dissect_vendor_cl_suboption(pinfo, vti, e_tree, tvb, optoff, s_end);
				break;

				default:
					optoff = dissect_vendor_generic_suboption(pinfo, vti, e_tree, tvb, optoff, s_end);
				break;
				}
			}
			optleft -= option_data_len;
		}
		break;
	}

	case 212: {	/* 6RD option (RFC 5969) */
		if (optlen < 22) {
			expert_add_info(pinfo, vti, &ei_bootp_option_6RD_malformed);
			break;
		}

		proto_tree_add_item(v_tree, hf_bootp_option_6RD_ipv4_mask_len, tvb, optoff, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(v_tree, hf_bootp_option_6RD_prefix_len, tvb, optoff+1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(v_tree, hf_bootp_option_6RD_prefix, tvb, optoff+2, 16, ENC_NA);
		proto_tree_add_item(v_tree, hf_bootp_option_6RD_border_relay_ip, tvb, optoff+18, 4, ENC_BIG_ENDIAN);

		/* More Border Relay IPv4 addresses included */
		if (optlen > 22) {
			optoff += 22;
			for (i = optoff, optleft = optlen - 22; optleft > 0; i += 4, optleft -= 4) {
				if (optleft < 4) {
					expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "Option length isn't a multiple of 4");
					break;
				}

				proto_tree_add_item(v_tree, hf_bootp_option_6RD_border_relay_ip, tvb, i, 4, ENC_BIG_ENDIAN);
			}
		}
		break;
	}

	case 242: {	/* Avaya IP Telephone */
		proto_tree *o242avaya_v_tree;
		proto_item *avaya_ti;
		const guint8 *avaya_option = NULL;
		gchar *field = NULL;
		wmem_strbuf_t *avaya_param_buf = NULL;

		/* minimum length is 5 bytes */
		if (optlen < 5) {
			expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "Avaya IP Telephone option length isn't >= 5");
			optoff += optlen;
			break;
		}
		avaya_ti = proto_tree_add_item_ret_string(v_tree, hf_bootp_option242_avaya, tvb, optoff, optlen, ENC_ASCII|ENC_NA, wmem_packet_scope(), &avaya_option);
		o242avaya_v_tree = proto_item_add_subtree(avaya_ti, ett_bootp_option242_suboption);
		avaya_param_buf = wmem_strbuf_new(wmem_packet_scope(), "");
		for ( field = strtok((char*)avaya_option, ","); field; field = strtok(NULL, ",") ) {
			if (!strchr(field, '=')) {
				if (wmem_strbuf_get_len(avaya_param_buf) == 0) {
					expert_add_info_format(pinfo, vti, &hf_bootp_subopt_unknown_type, "ERROR, Unknown parameter %s", field);
					optoff += (int)strlen(field);
					break;
				}
				wmem_strbuf_append_printf(avaya_param_buf,",%s", field);
			}
			else {
				if (wmem_strbuf_get_len(avaya_param_buf) > 0) {
					dissect_vendor_avaya_param(o242avaya_v_tree, pinfo, vti, tvb, optoff, avaya_param_buf);
					optoff += (int)wmem_strbuf_get_len(avaya_param_buf) + 1;
					wmem_strbuf_truncate(avaya_param_buf, 0);
				}
				wmem_strbuf_append(avaya_param_buf, field);
			}
		}
		if (wmem_strbuf_get_len(avaya_param_buf) > 0) {
			dissect_vendor_avaya_param(o242avaya_v_tree, pinfo, vti, tvb, optoff, avaya_param_buf);
		}
		break;
	}

	default:	/* not special */
		/* The PacketCable CCC option number can vary.	If this is a CCC option,
		   handle it as a special.
		 */
		if (code == pkt_ccc_option) {
			ftype = special;
			proto_item_append_text(vti,
				"CableLabs Client Configuration (%d bytes)",
				optlen);
			optend = optoff + optlen;
			while (optoff < optend) {
				switch (pkt_ccc_protocol_version) {

				case PACKETCABLE_CCC_I05:
					optoff = dissect_packetcable_i05_ccc(pinfo, vti, v_tree, tvb, optoff, optend);
					break;
				case PACKETCABLE_CCC_DRAFT5:
				case PACKETCABLE_CCC_RFC_3495:
					optoff = dissect_packetcable_ietf_ccc(pinfo, vti, v_tree, tvb, optoff, optend, pkt_ccc_protocol_version);
					break;
				default: /* XXX Should we do something here? */
					break;
				}
			}
		} else {
			option_handled = FALSE;
		}

		break;
	}

	basictype_consumed = bootp_handle_basic_types(pinfo, v_tree, vti, tvb, ftype,
						      optoff, optlen, opt->phf, &default_hfs);

	if ((basictype_consumed == 0) && (option_handled == FALSE) &&
	    (opt->phf == NULL) && (optlen > 0)) {
		proto_tree_add_item(v_tree, hf_bootp_option_value, tvb, voff+2, optlen, ENC_NA);
	}

	return consumed;
}

static const value_string option82_suboption_vals[] = {
	{  0, "Padding" },
	{  1, "Agent Circuit ID" },
	{  2, "Agent Remote ID" },
	{  3, "Reserved" },
	{  4, "DOCSIS Device Class" },
	{  5, "Link selection" },
	{  6, "Subscriber ID" },
	{  7, "RADIUS Attributes" },
	{  8, "Authentication" },
	{  9, "Vendor-Specific Information" },
	{ 10, "Flags" },
	{ 11, "Server ID Override" },
	{ 150, "Link selection (Cisco proprietary)" },
	{ 151, "VRF name/VPN ID" },
	{ 152, "Server ID Override (Cisco proprietary)" },
	{ 0, NULL }
};

static int
bootp_dhcp_decode_agent_info(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree, tvbuff_t *tvb, int optoff,
			     int optend)
{
	int	    suboptoff = optoff;
	guint8	    subopt, idx, vs_opt, vs_len;
	int	    subopt_len, subopt_end, datalen;
	guint32	    enterprise;
	proto_item *vti, *ti;
	proto_tree *o82_v_tree, *o82_sub_tree;
	guint8	    tag, tag_len;

	struct basic_types_hfs default_hfs = {
		&hf_bootp_option82_value,
		&hf_bootp_option82_value_ip_address,
		&hf_bootp_option82_value_ip_address,
		&hf_bootp_option82_value_stringz,
		NULL,
		&hf_bootp_option82_value_8,
		NULL,
		NULL,
		&hf_bootp_option82_value_32,
		NULL,
		NULL
	};

	struct opt82_info {
		int id;
		struct opt_info info;
	};
	static struct opt82_info o82_opt[]= {
		{0, {"nop", bytes, &hf_bootp_option82_padding}},	/* dummy */
		{1, {"Agent Circuit ID", bytes, &hf_bootp_option82_agent_circuit_id}}, /* [RFC3046] */
		{2, {"Agent Remote ID", bytes, &hf_bootp_option82_agent_remote_id}}, /* [RFC3046] */
		{3, {"Reserved", bytes, &hf_bootp_option82_reserved}},
		{4, {"DOCSIS Device Class", val_u_long, &hf_bootp_option82_docsis_device_class}}, /* [RFC3256] */
		{5, {"Link selection", ipv4, &hf_bootp_option82_link_selection}}, /* [RFC3527] */
		{6, {"Subscriber ID", string, &hf_bootp_option82_subscriber_id}},  /* [RFC3993] */ /***** CHECK STRING TYPE */
		{7, {"RADIUS Attributes", bytes, &hf_bootp_option82_radius_attributes}}, /* [RFC4014] */
		{8, {"Authentication", bytes, &hf_bootp_option82_authentication}}, /* [RFC4030] */
		{9, {"Vendor-Specific Information", special, &hf_bootp_option82_vi}}, /* [RFC 4243] */
		{10, {"Flags", val_u_byte, &hf_bootp_option82_flags}}, /* [RFC5010] */
		{11, {"Server ID Override", ipv4, &hf_bootp_option82_server_id_override}}, /* [RFC 5107] */
		{150, {"Link selection (Cisco proprietary)", ipv4, &hf_bootp_option82_link_selection_cisco}}, /* [RFC3527] */
		{151, {"VRF name/VPN ID", special, &hf_bootp_option82_vrf_name_vpn_id}}, /* [RFC2685] */
		{152, {"Server ID Override (Cisco proprietary)", ipv4, &hf_bootp_option82_server_id_override_cisco}} /* [RFC 5107] */
	};

	subopt = tvb_get_guint8(tvb, optoff);
	suboptoff++;

	if (suboptoff >= optend) {
		expert_add_info_format(pinfo, v_ti, &ei_bootp_missing_subopt_length,
									"Suboption %d: no room left in option for suboption length", subopt);
		return (optend);
	}

	subopt_len = tvb_get_guint8(tvb, suboptoff);
	vti = proto_tree_add_uint_format_value(v_tree, hf_bootp_option82_suboption,
		tvb, optoff, subopt_len+2, subopt, "(%d) %s", subopt, val_to_str_const(subopt, option82_suboption_vals, "Unknown"));

	o82_v_tree = proto_item_add_subtree(vti, ett_bootp_option82_suboption);
	proto_tree_add_item(o82_v_tree, hf_bootp_suboption_length, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
	suboptoff++;

	subopt_end = suboptoff+subopt_len;
	if (subopt_end > optend) {
		expert_add_info_format(pinfo, vti, &ei_bootp_missing_subopt_value,
						"Suboption %d: no room left in option for suboption value", subopt);
		return (optend);
	}

	for (idx = 0; idx < array_length(o82_opt); idx++) {
		if (o82_opt[idx].id == subopt) {
			break;
		}
	}

	ti = proto_tree_add_item(o82_v_tree, hf_bootp_option82_value, tvb, suboptoff, subopt_len, ENC_NA);

	if ( (idx >= 1 ) && (idx < array_length(o82_opt)) ) {
		PROTO_ITEM_SET_HIDDEN(ti);
		if (o82_opt[idx].info.ftype == special) {
			switch(subopt)
			{
			case 9:
				while (suboptoff < subopt_end) {
					enterprise = tvb_get_ntohl(tvb, suboptoff);
					vti = proto_tree_add_item(o82_v_tree, hf_bootp_option82_vi_enterprise, tvb, suboptoff, 4, ENC_BIG_ENDIAN);
					suboptoff += 4;

					o82_sub_tree = proto_item_add_subtree(vti, ett_bootp_option82_suboption9);
					datalen = tvb_get_guint8(tvb, suboptoff);
					proto_tree_add_item(o82_sub_tree, hf_bootp_option82_vi_data_length, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
					suboptoff++;

					switch (enterprise) {
					case 4491: /* CableLab */
						vs_opt = tvb_get_guint8(tvb, suboptoff);
						proto_tree_add_item(o82_sub_tree, hf_bootp_option82_vi_cl_option, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
						suboptoff++;
						vs_len = tvb_get_guint8(tvb, suboptoff);
						proto_tree_add_item(o82_sub_tree, hf_bootp_option82_vi_cl_length, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
						suboptoff++;

						switch (vs_opt) {

						case 1:
							if (vs_len == 4) {
								tag = tvb_get_guint8(tvb, suboptoff);
								proto_tree_add_item(o82_sub_tree, hf_bootp_option82_vi_cl_tag, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
								tag_len = tvb_get_guint8(tvb, suboptoff+1);
								proto_tree_add_item(o82_sub_tree, hf_bootp_option82_vi_cl_tag_length, tvb, suboptoff+1, 1, ENC_BIG_ENDIAN);
								suboptoff+=2;
								if (tag == 1) {
									proto_tree_add_uint_format_value(o82_sub_tree, hf_bootp_option82_vi_cl_docsis_version,
											  tvb, suboptoff, 2, 0, "%d.%d",
											  tvb_get_guint8(tvb, suboptoff), tvb_get_guint8(tvb, suboptoff+1));
									suboptoff+=2;
								} else {
									expert_add_info_format(pinfo, vti, &ei_bootp_option82_vi_cl_tag_unknown, "Unknown tag %d (%d bytes)", tag, tag_len);
									suboptoff += tag_len;
								}
							} else {
								suboptoff += vs_len;
							}
							break;

						default:
							expert_add_info_format(pinfo, vti, &ei_bootp_suboption_invalid, "Invalid suboption %d (%d bytes)", vs_opt, vs_len);
							suboptoff += vs_len;
							break;
						}
						break;
					default:
						proto_tree_add_item(o82_v_tree, hf_bootp_option82_value, tvb, suboptoff, datalen, ENC_NA);
						suboptoff += datalen;
						break;
					}
				}
				break;
			case 151:
				if (subopt_len == 1) {
					proto_tree_add_item(o82_v_tree, hf_bootp_option82_vrf_name_global, tvb, suboptoff, 1, ENC_NA);
				}
				else if (subopt_len != 7) {
					proto_tree_add_item(o82_v_tree, hf_bootp_option82_vrf_name, tvb, suboptoff, subopt_len, ENC_ASCII|ENC_NA);
				} else {
					proto_tree_add_item(o82_v_tree, hf_bootp_option82_vrf_name_vpn_id_oui, tvb, suboptoff, 3, ENC_BIG_ENDIAN);
					proto_tree_add_item(o82_v_tree, hf_bootp_option82_vrf_name_vpn_id_index, tvb, suboptoff+3, 4, ENC_BIG_ENDIAN);
				}
				break;
			default:
				if (o82_opt[idx].info.phf != NULL)
					proto_tree_add_item(o82_v_tree, *o82_opt[idx].info.phf, tvb, suboptoff, subopt_len, ENC_BIG_ENDIAN);
				else
					proto_tree_add_item(o82_v_tree, hf_bootp_option82_value, tvb, suboptoff, subopt_len, ENC_NA);
				break;
			}
		}
		else {
			if (bootp_handle_basic_types(pinfo, o82_v_tree, vti, tvb, o82_opt[idx].info.ftype,
						     suboptoff, subopt_len, o82_opt[idx].info.phf, &default_hfs) == 0) {
				expert_add_info_format(pinfo, vti, &hf_bootp_subopt_unknown_type, "ERROR, please report: Unknown subopt type handler %d", subopt);
			}
		}
	}

	optoff += (subopt_len + 2);
	return optoff;
}

static const value_string option43_pxeclient_suboption_vals[] = {
	{  0, "Padding" },
	{  1, "PXE mtftp IP" },
	{  2, "PXE mtftp client port" },
	{  3, "PXE mtftp server port" },
	{  4, "PXE mtftp timeout" },
	{  5, "PXE mtftp delay" },
	{  6, "PXE discovery control" },
	{  7, "PXE multicast address" },
	{  8, "PXE boot servers" },
	{  9, "PXE boot menu" },
	{ 10, "PXE menu prompt" },
	{ 11, "PXE multicast address alloc", },
	{ 12, "PXE credential types" },
	{ 71, "PXE boot item" },
	{ 255, "PXE End" },
	{ 0, NULL}
};

static int
dissect_vendor_pxeclient_suboption(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
				   tvbuff_t *tvb, int optoff, int optend)
{
	int	    suboptoff = optoff;
	guint8	    subopt;
	guint8	    subopt_len;
	proto_tree *o43pxeclient_v_tree;
	proto_item *vti, *ti;

	struct basic_types_hfs default_hfs = {
		NULL,
		&hf_bootp_option43_value_ip_address,
		&hf_bootp_option43_value_ip_address,
		NULL,
		NULL,
		&hf_bootp_option43_value_8,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	};

	static struct opt_info o43pxeclient_opt[]= {
		/* 0 */ {"nop", special, &hf_bootp_option43_pxeclient_padding},	/* dummy */
		/* 1 */ {"PXE mtftp IP", ipv4_list, &hf_bootp_option43_pxeclient_mtftp_ip},
		/* 2 */ {"PXE mtftp client port", val_u_le_short, &hf_bootp_option43_pxeclient_mtftp_client_port},
		/* 3 */ {"PXE mtftp server port",val_u_le_short, &hf_bootp_option43_pxeclient_mtftp_server_port},
		/* 4 */ {"PXE mtftp timeout", val_u_byte, &hf_bootp_option43_pxeclient_mtftp_timeout},
		/* 5 */ {"PXE mtftp delay", val_u_byte, &hf_bootp_option43_pxeclient_mtftp_delay},
		/* 6 */ {"PXE discovery control", val_u_byte, &hf_bootp_option43_pxeclient_discovery_control},
			/*
			 * Correct: b0 (lsb): disable broadcast discovery
			 *	b1: disable multicast discovery
			 *	b2: only use/accept servers in boot servers
			 *	b3: download bootfile without prompt/menu/disc
			 */
		/* 7 */ {"PXE multicast address", ipv4_list, &hf_bootp_option43_pxeclient_multicast_address},
		/* 8 */ {"PXE boot servers", special, &hf_bootp_option43_pxeclient_boot_servers},
		/* 9 */ {"PXE boot menu", special, &hf_bootp_option43_pxeclient_boot_menu},
		/* 10 */ {"PXE menu prompt", special, &hf_bootp_option43_pxeclient_menu_prompt},
		/* 11 */ {"PXE multicast address alloc", special, &hf_bootp_option43_pxeclient_multicast_address_alloc},
		/* 12 */ {"PXE credential types", special, &hf_bootp_option43_pxeclient_credential_types}
		/* 71 {"PXE boot item", bytes, &hf_bootp_option43_pxeclient_boot_item}, */
		/* 255 {"PXE end options", special, &hf_bootp_option43_pxeclient_end} */
	};

	subopt = tvb_get_guint8(tvb, optoff);
	suboptoff++;

	if (subopt == 0) {
		proto_tree_add_item(v_tree, hf_bootp_option43_pxeclient_padding, tvb, optoff, 1, ENC_BIG_ENDIAN);
		return (suboptoff);
	} else if (subopt == 255) {	/* End Option */
		proto_tree_add_item(v_tree, hf_bootp_option43_pxeclient_end, tvb, optoff, 1, ENC_BIG_ENDIAN);
		/* Make sure we skip any junk left this option */
		return (optend);
	}

	if (suboptoff >= optend) {
		expert_add_info_format(pinfo, v_ti, &ei_bootp_missing_subopt_length,
									"Suboption %d: no room left in option for suboption length", subopt);
		return (optend);
	}

	subopt_len = tvb_get_guint8(tvb, suboptoff);
	vti = proto_tree_add_uint_format_value(v_tree, hf_bootp_option43_pxeclient_suboption,
				tvb, optoff, subopt_len+2, subopt, "(%d) %s",
				subopt, val_to_str_const(subopt, option43_pxeclient_suboption_vals, "Unknown"));

	o43pxeclient_v_tree = proto_item_add_subtree(vti, ett_bootp_option43_suboption);
	proto_tree_add_item(o43pxeclient_v_tree, hf_bootp_suboption_length, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
	suboptoff++;

	ti = proto_tree_add_item(o43pxeclient_v_tree, hf_bootp_option43_value, tvb, suboptoff, subopt_len, ENC_NA);
	PROTO_ITEM_SET_HIDDEN(ti);

	if ( subopt == 71 ) {	/* 71 {"PXE boot item", special} */
		/* case special */
		/* I may need to decode that properly one day */
		proto_tree_add_item(o43pxeclient_v_tree, hf_bootp_option43_pxeclient_boot_item, tvb, suboptoff, subopt_len, ENC_NA);
	} else if ((subopt < 1) || (subopt >= array_length(o43pxeclient_opt))) {
		expert_add_info_format(pinfo, vti, &ei_bootp_suboption_invalid, "Unknown suboption %d (%d bytes)", subopt, subopt_len);
	} else if (o43pxeclient_opt[subopt].ftype == special) {
		/* I may need to decode that properly one day */
		if (o43pxeclient_opt[subopt].phf != NULL)
			proto_tree_add_item(o43pxeclient_v_tree, *o43pxeclient_opt[subopt].phf, tvb, suboptoff, subopt_len, ENC_BIG_ENDIAN);
		else
			proto_tree_add_item(o43pxeclient_v_tree, hf_bootp_option43_value, tvb, suboptoff, subopt_len, ENC_NA);
	} else {
		if (bootp_handle_basic_types(pinfo, o43pxeclient_v_tree, vti, tvb, o43pxeclient_opt[subopt].ftype,
							suboptoff, subopt_len, o43pxeclient_opt[subopt].phf, &default_hfs) == 0)
		{
			expert_add_info_format(pinfo, vti, &hf_bootp_subopt_unknown_type, "ERROR, please report: Unknown subopt type handler %d", subopt);
		}
	}

	optoff += (subopt_len + 2);
	return optoff;
}

static void
dissect_vendor_avaya_param(proto_tree *tree, packet_info *pinfo, proto_item *vti,
		tvbuff_t *tvb, int optoff, wmem_strbuf_t *avaya_param_buf)
{
	const gchar *field;
	int len;

	field = wmem_strbuf_get_str(avaya_param_buf);
	len = (int)wmem_strbuf_get_len(avaya_param_buf);

	if((strncmp(field, "TLSSRVR=", 8) == 0) && ( len > 8 )) {
		proto_tree_add_string(tree, hf_bootp_option242_avaya_tlssrvr, tvb, optoff, len, field + 8);
	}
	else if((strncmp(field, "HTTPSRVR=", 9) == 0) && ( len > 9)) {
		proto_tree_add_string(tree, hf_bootp_option242_avaya_httpsrvr, tvb, optoff, len, field + 9);
	}
	else if((strncmp(field, "HTTPDIR=", 8) == 0) && ( len > 8)) {
		proto_tree_add_string(tree, hf_bootp_option242_avaya_httpdir, tvb, optoff, len, field + 8);
	}
	else if((strncmp(field, "STATIC=", 7) == 0) && ( len > 7)) {
		proto_tree_add_string_format_value(tree, hf_bootp_option242_avaya_static, tvb, optoff, len, field + 7, "%s (%s)", field + 7, str_to_str(field + 7, option242_avaya_static_vals, "Unknown (%s)"));
	}
	else if((strncmp(field, "MCIPADD=", 8) == 0) && ( len > 8)) {
		proto_tree_add_string(tree, hf_bootp_option242_avaya_mcipadd, tvb, optoff, len, field + 8);
	}
	else if((strncmp(field, "DOT1X=", 6) == 0) && ( len > 6)) {
		proto_tree_add_string_format_value(tree, hf_bootp_option242_avaya_dot1x, tvb, optoff, len, field + 6, "%s (%s)", field + 6, str_to_str(field + 6, option242_avaya_dot1x_vals, "Unknown (%s)"));
	}
	else if((strncmp(field, "ICMPDU=", 7) == 0) && ( len > 7)) {
		proto_tree_add_string_format_value(tree, hf_bootp_option242_avaya_icmpdu, tvb, optoff, len, field + 7, "%s (%s)", field + 7, str_to_str(field + 7, option242_avaya_icmpdu_vals, "Unknown (%s)"));
	}
	else if((strncmp(field, "ICMPRED=", 8) == 0) && ( len > 8)) {
		proto_tree_add_string_format_value(tree, hf_bootp_option242_avaya_icmpred, tvb, optoff, len, field + 8, "%s (%s)", field + 8, str_to_str(field + 8, option242_avaya_icmpred_vals, "Unknown (%s)"));
	}
	else if((strncmp(field, "L2Q=", 4) == 0) && ( len > 4)) {
		proto_tree_add_string_format_value(tree, hf_bootp_option242_avaya_l2q, tvb, optoff, len, field + 4, "%s (%s)", field + 4, str_to_str(field + 4, option242_avaya_l2q_vals, "Unknown (%s)"));
	}
	else if((strncmp(field, "L2QVLAN=", 8) == 0) && ( len > 8)) {
		proto_tree_add_int(tree, hf_bootp_option242_avaya_l2qvlan, tvb, optoff, len, atoi(field +8));
	}
	else if((strncmp(field, "LOGLOCAL=", 9) == 0) && ( len > 9)) {
		proto_tree_add_string_format_value(tree, hf_bootp_option242_avaya_loglocal, tvb, optoff, len, field + 9, "%s (%s)", field + 9, str_to_str(field + 9, option242_avaya_loglocal_vals, "Unknown (%s)"));
	}
	else if((strncmp(field, "PHY1STAT=", 9) == 0) && ( len > 9)) {
		proto_tree_add_string_format_value(tree, hf_bootp_option242_avaya_phy1stat, tvb, optoff, len, field + 9, "%s (%s)", field + 9, str_to_str(field + 9, option242_avaya_phystat_vals, "Unknown (%s)"));
	}
	else if((strncmp(field, "PHY2STAT=", 9) == 0) && ( len > 9)) {
		proto_tree_add_string_format_value(tree, hf_bootp_option242_avaya_phy2stat, tvb, optoff, len, field + 9, "%s (%s)", field + 9, str_to_str(field + 9, option242_avaya_phystat_vals, "Unknown (%s)"));
	}
	else if((strncmp(field, "PROCPSWD=", 9) == 0) && ( len > 9)) {
		proto_tree_add_string(tree, hf_bootp_option242_avaya_procpswd, tvb, optoff, len, field + 9);
	}
	else if((strncmp(field, "PROCSTAT=", 9) == 0) && ( len > 9)) {
		proto_tree_add_string_format_value(tree, hf_bootp_option242_avaya_procstat, tvb, optoff, len, field + 9, "%s (%s)", field + 9, str_to_str(field + 9, option242_avaya_procstat_vals, "Unknown (%s)"));
	}
	else if((strncmp(field, "SNMPADD=", 8) == 0) && ( len > 8)) {
		proto_tree_add_string(tree, hf_bootp_option242_avaya_snmpadd, tvb, optoff, len, field + 8);
	}
	else if((strncmp(field, "SNMPSTRING=", 11) == 0) && ( len > 11)) {
		proto_tree_add_string(tree, hf_bootp_option242_avaya_snmpstring, tvb, optoff, len, field + 11);
	}
	else if((strncmp(field, "VLANTEST=", 9) == 0) && ( len > 9)) {
		proto_tree_add_int(tree, hf_bootp_option242_avaya_vlantest, tvb, optoff, len, atoi(field + 9));
	}
	else {
		expert_add_info_format(pinfo, vti, &hf_bootp_subopt_unknown_type, "ERROR, Unknown Avaya IP Telephone parameter %s", field);
	}
}

/* RFC3825Decoder: http://www.enum.at/rfc3825encoder.529.0.html */
static void
rfc3825_lci_to_fixpoint(const unsigned char lci[16], struct rfc3825_location_fixpoint_t *fixpoint)
{
	fixpoint->latitude_res = (lci[0]>>2) & 0x3F; /* make sure that right-shift does not copy sign bit */
	if (lci[0] & 2) { /* LSB<<1 contains the sign of the latitude */
		/* Latitude is negative, expand two's complement */
		fixpoint->latitude = (((gint64)lci[0] & 3)<<32) | ((gint64)lci[1]<<24) |
					   ((gint64)lci[2]<<16) | ((gint64)lci[3]<<8)  |
					    (gint64)lci[4]	| ((gint64)0x3FFFFFFF<<34);

	} else {
		/* Latitude is positive */
		fixpoint->latitude = (((gint64)lci[0] & 3)<<32) | ((gint64)lci[1]<<24) |
					   ((gint64)lci[2]<<16) | ((gint64)lci[3]<<8)  |
					    (gint64)lci[4];
	}
	fixpoint->longitude_res = (lci[5]>>2) & 0x3F;  /* make sure that right-shift does not copy sign bit */
	if (lci[5] & 2) { /* LSB<<1 contains the sign of the latitude */
		/* Longitude is negative, expand two's complement */
		fixpoint->longitude = (((gint64)lci[5] & 3)<<32) | ((gint64)lci[6]<<24) |
					    ((gint64)lci[7]<<16) | ((gint64)lci[8]<<8)	|
					     (gint64)lci[9]	 | ((gint64)0x3FFFFFFF<<34);

	} else {
		/* Longitude is positive */
		fixpoint->longitude = (((gint64)lci[5] & 3)<<32) | ((gint64)lci[6]<<24) |
					    ((gint64)lci[7]<<16) | ((gint64)lci[8]<<8)	|
					     (gint64)lci[9];
	}
	fixpoint->altitude_type = (lci[10]>>4) & 0x0F;	/* make sure that right-shift does not copy sign bit */
	fixpoint->altitude_res	= ((lci[10] & 0x0F) << 2) | ((lci[11]>>6) & 0x03);
	if (lci[11] & 0x20) { /* LSB<<1 contains the sign of the latitude */
		/* Altitude is negative, expand two's complement */
		fixpoint->altitude = (((gint32)lci[11] & 0x3F)<<24) | ((gint32)lci[12]<<16) |
				     ((gint32)lci[13]<<8) | ((gint32)lci[14]) |
				      ((gint32)0x03<<30);

	} else {
		/* Altitude is positive */
		fixpoint->altitude = (((gint32)lci[11] & 0x3F)<<24) | ((gint32)lci[12]<<16) |
				     ((gint32)lci[13]<<8) | ((gint32)lci[14]);
	}

	fixpoint->datum_type = lci[15];

}

/* RFC3825Decoder: http://www.enum.at/rfc3825encoder.529.0.html */
static int
rfc3825_fixpoint_to_decimal(struct rfc3825_location_fixpoint_t *fixpoint, struct rfc3825_location_decimal_t *decimal)
{
	/* Latitude */
	decimal->latitude = (double) fixpoint->latitude / (1 << 25);
	if ((decimal->latitude > 90) || (decimal->latitude < -90)) {
		return RFC3825_LATITUDE_OUTOFRANGE;
	}

	/* Latitude Uncertainty */
	if (fixpoint->latitude_res > 34) {
		return RFC3825_LATITUDE_UNCERTAINTY_OUTOFRANGE;
	}
	if (fixpoint->latitude_res > 8 ) {
		decimal->latitude_res = (double) 1  / (G_GUINT64_CONSTANT(1) << (fixpoint->latitude_res - 8));
	} else {
		decimal->latitude_res = (double) (G_GUINT64_CONSTANT(1) << (8 - fixpoint->latitude_res));
	}

	/* Longitude */
	decimal->longitude = (double) fixpoint->longitude / (1 << 25);
	if ((decimal->longitude > 180) || (decimal->longitude < -180)) {
		return RFC3825_LONGITUDE_OUTOFRANGE;
	}

	/* Longitude Uncertainty */
	if (fixpoint->longitude_res > 34) {
		return RFC3825_LONGITUDE_UNCERTAINTY_OUTOFRANGE;
	}
	if (fixpoint->longitude_res > 8 ) {
		decimal->longitude_res = (double) 1 / (G_GUINT64_CONSTANT(1) << (fixpoint->longitude_res - 8));
	} else {
		decimal->longitude_res = (double) (G_GUINT64_CONSTANT(1) << (8 - fixpoint->longitude_res));
	}

	/* Altitude Type */
	decimal->altitude_type = fixpoint->altitude_type;
	decimal->altitude = 0;
	decimal->altitude_res = 0;

	if (decimal->altitude_type == 0) { /* Unknown */
	} else if (decimal->altitude_type == 1) { /* Meters */
		/* Altitude */
		decimal->altitude = (double) fixpoint->altitude / (1 << 8);
		if ((decimal->altitude > ((gint32) 1<<21)-1) || (decimal->altitude < ((gint32) -(1<<21))))
			return RFC3825_ALTITUDE_OUTOFRANGE;

		/* Altitude Uncertainty */
		if (fixpoint->altitude_res > 30) {
			return RFC3825_ALTITUDE_UNCERTAINTY_OUTOFRANGE;
		}
		if (fixpoint->altitude_res > 21 ) {
			decimal->altitude_res = (double) 1 / (G_GUINT64_CONSTANT(1) << (fixpoint->altitude_res - 21));
		} else {
			decimal->altitude_res = (double) (G_GUINT64_CONSTANT(1) << (21 - fixpoint->altitude_res));
		}
	} else if (decimal->altitude_type == 2) { /* Floors */
		/* Altitude */
		if ((fixpoint->altitude_res != 30) && (fixpoint->altitude_res != 0)) {
			return RFC3825_ALTITUDE_UNCERTAINTY_OUTOFRANGE;
		}
		decimal->altitude = (double) fixpoint->altitude / (1 << 8);
	} else { /* invalid type */
		return RFC3825_ALTITUDE_TYPE_OUTOFRANGE;
	}

	/* Datum Type */
	decimal->datum_type = 0;
	if ((fixpoint->datum_type > 3) || (fixpoint->datum_type < 1)) {
		return RFC3825_DATUM_TYPE_OUTOFRANGE;
	}
	decimal->datum_type = fixpoint->datum_type;

	return RFC3825_NOERROR;
}

static int dissect_isns(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
			tvbuff_t *tvb, int optoff, int optlen)
{
	static const int *isns_functions_hf_flags[] = {
		&hf_bootp_option_isns_functions_enabled,
		&hf_bootp_option_isns_functions_dd_authorization,
		&hf_bootp_option_isns_functions_sec_policy_distibution,
		&hf_bootp_option_isns_functions_reserved,
		NULL
	};

	static const int *isns_dda_hf_flags[] = {
		&hf_bootp_option_isns_discovery_domain_access_enabled,
		&hf_bootp_option_isns_discovery_domain_access_control_node,
		&hf_bootp_option_isns_discovery_domain_access_iscsi_target,
		&hf_bootp_option_isns_discovery_domain_access_iscsi_inititator,
		&hf_bootp_option_isns_discovery_domain_access_ifcp_target_port,
		&hf_bootp_option_isns_discovery_domain_access_ifcp_initiator_port,
		&hf_bootp_option_isns_discovery_domain_access_reserved,
		NULL
	};

	static const int *isns_administrative_flags[] = {
		&hf_bootp_option_isns_administrative_flags_enabled,
		&hf_bootp_option_isns_administrative_flags_heartbeat,
		&hf_bootp_option_isns_administrative_flags_management_scns,
		&hf_bootp_option_isns_administrative_flags_default_dd,
		&hf_bootp_option_isns_administrative_flags_reserved,
		NULL
	};

	static const int *isns_server_security_flags[] = {
		&hf_bootp_option_isns_server_security_bitmap_enabled,
		&hf_bootp_option_isns_server_security_bitmap_ike_ipsec_enabled,
		&hf_bootp_option_isns_server_security_bitmap_main_mode,
		&hf_bootp_option_isns_server_security_bitmap_aggressive_mode,
		&hf_bootp_option_isns_server_security_bitmap_pfs,
		&hf_bootp_option_isns_server_security_bitmap_transport_mode,
		&hf_bootp_option_isns_server_security_bitmap_tunnel_mode,
		&hf_bootp_option_isns_server_security_bitmap_reserved,
		NULL
	};

	guint16 function_flags, dd_access_flags, administrative_flags;
	guint32 server_security_flags;
	proto_tree *tree;
	proto_item *item;
	int optend, heartbeat_set = 0;

	if (optlen < 14) {
		expert_add_info_format(pinfo, v_ti, &ei_bootp_bad_length, "length must be >= 14");
		return optoff;
	}
	optend = optoff + optlen;

	item = proto_tree_add_bitmask(v_tree, tvb, optoff, hf_bootp_option_isns_functions,
				      ett_bootp_isns_functions, isns_functions_hf_flags, ENC_BIG_ENDIAN);
	function_flags = tvb_get_ntohs(tvb, optoff);
	/* RFC 4174, section "2.1. iSNS Functions Field" specifies that if
	 * the field "Function Fields Enabled" is set to 0, then "the contents
	 * of all other iSNS Function fields MUST be ignored. We will display
	 * the fields but add an informational expert info. This goes for all
	 * the bitmasks: iSNS Functions, DD Access, Administrative Flags, iSNS
	 * Server Security Bitmap */
	if (ISNS_BITFIELD_NZ_MUST_BE_IGNORED(function_flags, F_ISNS_FUNCTIONS_ENABLED))
		expert_add_info(pinfo, item, &ei_bootp_option_isns_ignored_bitfield);

	optoff += 2;
	item = proto_tree_add_bitmask(v_tree, tvb, optoff, hf_bootp_option_isns_discovery_domain_access,
				      ett_bootp_isns_discovery_domain_access, isns_dda_hf_flags, ENC_BIG_ENDIAN);
	dd_access_flags = tvb_get_ntohs(tvb, optoff);
	if (ISNS_BITFIELD_NZ_MUST_BE_IGNORED(dd_access_flags, F_ISNS_DD_ACCESS_ENABLED))
		expert_add_info(pinfo, item, &ei_bootp_option_isns_ignored_bitfield);

	optoff += 2;
	administrative_flags = tvb_get_ntohs(tvb, optoff);
	if (administrative_flags & F_ISNS_ADMIN_FLAGS_ENABLED) {
		if ((administrative_flags & F_ISNS_ADMIN_FLAGS_HEARTBEAT)) {
			if (optlen < 18) {
				expert_add_info_format(pinfo, v_ti, &ei_bootp_bad_length, "length must be >= 18");
				return optoff;
			}
			heartbeat_set = 1;
		}
	}
	item = proto_tree_add_bitmask(v_tree, tvb, optoff, hf_bootp_option_isns_administrative_flags,
				      ett_bootp_isns_administrative_flags, isns_administrative_flags, ENC_BIG_ENDIAN);
	if (ISNS_BITFIELD_NZ_MUST_BE_IGNORED(administrative_flags, F_ISNS_ADMIN_FLAGS_ENABLED))
		expert_add_info(pinfo, item, &ei_bootp_option_isns_ignored_bitfield);

	optoff += 2;
	item = proto_tree_add_bitmask(v_tree, tvb, optoff, hf_bootp_option_isns_server_security_bitmap,
				      ett_bootp_isns_server_security_bitmap, isns_server_security_flags, ENC_BIG_ENDIAN);
	server_security_flags = tvb_get_ntohl(tvb, optoff);
	if (ISNS_BITFIELD_NZ_MUST_BE_IGNORED(server_security_flags, F_ISNS_SRV_SEC_BITMAP_ENABLED))
		expert_add_info(pinfo, item, &ei_bootp_option_isns_ignored_bitfield);

	optoff += 4;
	if (heartbeat_set) {
		proto_tree_add_item(v_tree, hf_bootp_option_isns_heartbeat_originator_addr,
				    tvb, optoff, 4, ENC_BIG_ENDIAN);
		optoff += 4;
	}

	proto_tree_add_item(v_tree, hf_bootp_option_isns_primary_server_addr,
			    tvb, optoff, 4, ENC_BIG_ENDIAN);

	optoff += 4;
	if (optoff < optend) {
		tree = proto_tree_add_subtree(v_tree, tvb, optoff, 0, ett_bootp_isns_secondary_server_addr,
						&item, "Secondary iSNS Servers");
		optoff += bootp_handle_basic_types(pinfo, tree, item, tvb, ipv4_list, optoff, optend - optoff,
						   &hf_bootp_option_isns_secondary_server_addr_list, NULL);
	}
	return optoff;
}

static const value_string option43_cl_suboption_vals[] = {
	{  0, "Padding" },
	{  1, "Suboption Request List" },
	{  2, "Device Type" },
	{  3, "eSAFE Types" },
	{  4, "Serial Number" },
	{  5, "Hardware Version" },
	{  6, "Software Version" },
	{  7, "Boot ROM version" },
	{  8, "Organizationally Unique Identifier" },
	{  9, "Model Number" },
	{ 10, "Vendor Name" },
	{ 11, "Address Realm" },
	{ 12, "CM/PS System Description" },
	{ 13, "CM/PS Firmware Revision" },
	{ 14, "Firewall Policy File Version" },
	{ 15, "eSafe Config File Devices" },
	{ 18, "Video Security Type" },
	{ 31, "MTA MAC Address" },
	{ 32, "Correlation ID" },
	{ 51, "Vendor Name" },
	{ 52, "CableCARD Capability" },
	{ 53, "Device Identification (CA)" },
	{ 54, "Device Identification (X.509)" },
	{ 255, "CL End" },
	{ 0, NULL}
};

static const value_string cablehome_subopt11_vals[] = {
	{ 1, "PS WAN-Man" },
	{ 2, "PS WAN-Data" },
	{ 0, NULL }
};

static int
dissect_vendor_cablelabs_suboption(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
				   tvbuff_t *tvb, int optoff, int optend)
{
	int	    suboptoff = optoff;
	guint8	    subopt;
	guint8	    subopt_len;
	proto_tree *o43cl_v_tree;
	proto_item *vti;

	struct basic_types_hfs default_hfs = {
		&hf_bootp_option43_value,
		NULL,
		NULL,
		&hf_bootp_option43_value_stringz,
		NULL,
		&hf_bootp_option43_value_8,
		NULL,
		NULL,
		&hf_bootp_option43_value_32,
		NULL,
		NULL
	};

	static struct opt_info o43cablelabs_opt[]= {
		/*  0 */ {"nop", special, &hf_bootp_option43_cl_padding},	/* dummy */
		/*  1 */ {"Suboption Request List", string, &hf_bootp_option43_cl_suboption_request_list},
		/*  2 */ {"Device Type", string, &hf_bootp_option43_cl_device_type},
		/*  3 */ {"eSAFE Types", string, &hf_bootp_option43_cl_esafe_type},
		/*  4 */ {"Serial Number", string, &hf_bootp_option43_cl_serial_number},
		/*  5 */ {"Hardware Version", string, &hf_bootp_option43_cl_hardware_version},
		/*  6 */ {"Software Version", string, &hf_bootp_option43_cl_software_version},
		/*  7 */ {"Boot ROM version", string, &hf_bootp_option43_cl_boot_rom_version},
		/*  8 */ {"Organizationally Unique Identifier", special, &hf_bootp_option43_cl_oui_bytes},
		/*  9 */ {"Model Number", string, &hf_bootp_option43_cl_model_number},
		/* 10 */ {"Vendor Name", string, &hf_bootp_option43_cl_vendor_name10},
		/* *** 11-30: CableHome *** */
		/* 11 */ {"Address Realm", val_u_byte, &hf_bootp_option43_cl_address_realm},
		/* 12 */ {"CM/PS System Description", string, &hf_bootp_option43_cl_cm_ps_system_desc},
		/* 13 */ {"CM/PS Firmware Revision", string, &hf_bootp_option43_cl_cm_ps_firmware_revision},
		/* 14 */ {"Firewall Policy File Version", string, &hf_bootp_option43_cl_firewall_policy_file_version},
		/* 15 */ {"eSafe Config File Devices", string, &hf_bootp_option43_cl_esafe_config_file_devices},
		/* 16 */ {"Unassigned (CableHome)", special, NULL},
		/* 17 */ {"Unassigned (CableHome)", special, NULL},
		/* 18 */ {"Video Security Type", string, &hf_bootp_option43_cl_video_security_tape},
		/* 19 */ {"Unassigned (CableHome)", special, NULL},
		/* 20 */ {"Unassigned (CableHome)", special, NULL},
		/* 21 */ {"Unassigned (CableHome)", special, NULL},
		/* 22 */ {"Unassigned (CableHome)", special, NULL},
		/* 23 */ {"Unassigned (CableHome)", special, NULL},
		/* 24 */ {"Unassigned (CableHome)", special, NULL},
		/* 25 */ {"Unassigned (CableHome)", special, NULL},
		/* 26 */ {"Unassigned (CableHome)", special, NULL},
		/* 27 */ {"Unassigned (CableHome)", special, NULL},
		/* 28 */ {"Unassigned (CableHome)", special, NULL},
		/* 29 */ {"Unassigned (CableHome)", special, NULL},
		/* 30 */ {"Unassigned (CableHome)", special, NULL},
		/* *** 31-50: PacketCable *** */
		/* 31 */ {"MTA MAC Address", special, &hf_bootp_option43_cl_mta_mac_address},
		/* 32 */ {"Correlation ID", val_u_long, &hf_bootp_option43_cl_correlation_ID},
		/* 33 */ {"Unassigned (PacketCable)", special, NULL},
		/* 34 */ {"Unassigned (PacketCable)", special, NULL},
		/* 35 */ {"Unassigned (PacketCable)", special, NULL},
		/* 36 */ {"Unassigned (PacketCable)", special, NULL},
		/* 37 */ {"Unassigned (PacketCable)", special, NULL},
		/* 38 */ {"Unassigned (PacketCable)", special, NULL},
		/* 39 */ {"Unassigned (PacketCable)", special, NULL},
		/* 40 */ {"Unassigned (PacketCable)", special, NULL},
		/* 41 */ {"Unassigned (PacketCable)", special, NULL},
		/* 42 */ {"Unassigned (PacketCable)", special, NULL},
		/* 43 */ {"Unassigned (PacketCable)", special, NULL},
		/* 44 */ {"Unassigned (PacketCable)", special, NULL},
		/* 45 */ {"Unassigned (PacketCable)", special, NULL},
		/* 46 */ {"Unassigned (PacketCable)", special, NULL},
		/* 47 */ {"Unassigned (PacketCable)", special, NULL},
		/* 48 */ {"Unassigned (PacketCable)", special, NULL},
		/* 49 */ {"Unassigned (PacketCable)", special, NULL},
		/* 50 */ {"Unassigned (PacketCable)", special, NULL},
		/* *** 51-127: CableLabs *** */
		/* 51 */ {"Vendor Name", string, &hf_bootp_option43_cl_vendor_name51},
		/* 52 */ {"CableCARD Capability", special, &hf_bootp_option43_cl_cablecard_capability},
		/* 53 */ {"Device Identification (CA)", special, &hf_bootp_option43_cl_device_id_ca},
		/* 54 */ {"Device Identification (X.509)", string, &hf_bootp_option43_cl_device_id_x509},
		/* 55 */ {"Unassigned (CableLabs)", special, NULL},
		/* *** 128-254: Vendors *** */
		/* 128-254 {"Unassigned (Vendors)", special, NULL}, */
		/* 255 {"end options", special, &hf_bootp_option43_cl_end} */
	};

	subopt = tvb_get_guint8(tvb, optoff);
	suboptoff++;

	if (subopt == 0) {
		proto_tree_add_item(v_tree, hf_bootp_option43_cl_padding, tvb, optoff, 1, ENC_BIG_ENDIAN);
		return (suboptoff);
	} else if (subopt == 255) {	/* End Option */
		proto_tree_add_item(v_tree, hf_bootp_option43_cl_end, tvb, optoff, 1, ENC_BIG_ENDIAN);
		/* Make sure we skip any junk left this option */
		return (optend);
	}

	if (suboptoff >= optend) {
		expert_add_info_format(pinfo, v_ti, &ei_bootp_missing_subopt_length,
									"Suboption %d: no room left in option for suboption length", subopt);
		return (optend);
	}

	subopt_len = tvb_get_guint8(tvb, suboptoff);
	vti = proto_tree_add_uint_format_value(v_tree, hf_bootp_option43_cl_suboption,
				tvb, optoff, subopt_len+2, subopt, "(%d) %s",
				subopt, val_to_str_const(subopt, option43_cl_suboption_vals, "Unknown"));

	o43cl_v_tree = proto_item_add_subtree(vti, ett_bootp_option43_suboption);
	proto_tree_add_item(o43cl_v_tree, hf_bootp_suboption_length, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
	suboptoff++;

	if (suboptoff+subopt_len > optend) {
		expert_add_info_format(pinfo, vti, &ei_bootp_missing_subopt_value,
						"Suboption %d: no room left in option for suboption value", subopt);
		return (optend);
	}

	if ( (subopt < 1 ) || (subopt >= array_length(o43cablelabs_opt)) ) {
		proto_tree_add_item(o43cl_v_tree, hf_bootp_option43_value, tvb, suboptoff, subopt_len, ENC_NA);
	} else if (o43cablelabs_opt[subopt].ftype == special) {
		switch(subopt)
		{
		case 8:/* OUI */
			/* CableLabs specs treat 43.8 inconsistently
			 * as either binary (3b) or string (6b) */
			if (subopt_len == 3) {
				proto_tree_add_bytes_format_value(o43cl_v_tree, hf_bootp_option43_cl_oui_bytes, tvb, suboptoff, subopt_len, NULL,
					"%02x:%02x:%02x", tvb_get_guint8(tvb, suboptoff), tvb_get_guint8(tvb, suboptoff+1), tvb_get_guint8(tvb, suboptoff+2));
			} else if (subopt_len == 6) {
				proto_tree_add_item(o43cl_v_tree, hf_bootp_option43_cl_oui_string, tvb, suboptoff, subopt_len, ENC_ASCII|ENC_NA);
			} else {
				expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "length isn't 3 or 6");
			}
			break;
		case 31: /* MTA MAC address */
			if (subopt_len != 6) {
				expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "length isn't 6");
				break;
			}

			proto_tree_add_item(o43cl_v_tree, hf_bootp_option43_cl_mta_mac_address, tvb, suboptoff, 6, ENC_NA);
			break;
		default:
			if (o43cablelabs_opt[subopt].phf != NULL)
				proto_tree_add_item(o43cl_v_tree, *o43cablelabs_opt[subopt].phf, tvb, suboptoff, subopt_len, ENC_BIG_ENDIAN);
			else
				proto_tree_add_item(o43cl_v_tree, hf_bootp_option43_value, tvb, suboptoff, subopt_len, ENC_NA);
		}
	}
	else {
		if (bootp_handle_basic_types(pinfo, o43cl_v_tree, vti, tvb, o43cablelabs_opt[subopt].ftype,
							suboptoff, subopt_len, o43cablelabs_opt[subopt].phf, &default_hfs) == 0) {
			expert_add_info_format(pinfo, vti, &hf_bootp_subopt_unknown_type, "ERROR, please report: Unknown subopt type handler %d", subopt);
		}
	}

	optoff += (subopt_len + 2);
	return optoff;
}

static const value_string option43_bsdp_suboption_vals[] = {
	{  1, "Message Type" },
	{  2, "Version" },
	{  3, "Server Identifier" },
	{  4, "Server Priority" },
	{  5, "Reply Port" },
	{  6, "Boot Image List Path" },
	{  7, "Default Boot Image" },
	{  8, "Selected Boot Image" },
	{  9, "Boot Image List" },
	{ 10, "NetBoot 1.0 Firmware" },
	{ 11, "Boot Image Attributes Filter List" },
	{ 12, "Maximum Message Size" },
	{ 0, NULL}
};

static void
dissect_vendor_bsdp_boot_image(proto_tree *v_tree, tvbuff_t *tvb, int optoff)
{
	static const int * bootp_o43_bsdp_attributes_flags[] = {
		&hf_bootp_option43_bsdp_boot_image_attribute_install,
		&hf_bootp_option43_bsdp_boot_image_attribute_kind,
		&hf_bootp_option43_bsdp_boot_image_attribute_reserved,
		NULL
	};

	proto_tree_add_bitmask(v_tree, tvb, optoff, hf_bootp_option43_bsdp_boot_image_attribute, ett_bootp_o43_bsdp_attributes_flags, bootp_o43_bsdp_attributes_flags, ENC_NA);
}

static int
dissect_vendor_bsdp_suboption(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
				   tvbuff_t *tvb, int optoff, int optend)
{
	int         suboptoff = optoff;
	int	    attributes_off;
	guint8      subopt, string_len;
	guint8      subopt_len, attributes_len;
	proto_tree *o43bsdp_v_tree, *o43bsdp_va_tree, *o43bsdp_vb_tree, *o43bsdp_vc_tree, *o43bsdp_vd_tree;
	proto_item *vti, *ti, *tj;

	subopt = tvb_get_guint8(tvb, optoff);
	suboptoff++;

	if (suboptoff >= optend) {
		expert_add_info_format(pinfo, v_ti, &ei_bootp_missing_subopt_length,
									"Suboption %d: no room left in option for suboption length", subopt);
		return (optend);
	}

	subopt_len = tvb_get_guint8(tvb, suboptoff);
	vti = proto_tree_add_uint_format_value(v_tree, hf_bootp_option43_bsdp_suboption,
				tvb, optoff, subopt_len+2, subopt, "(%d) %s",
				subopt, val_to_str_const(subopt, option43_bsdp_suboption_vals, "Unknown"));

	o43bsdp_v_tree = proto_item_add_subtree(vti, ett_bootp_option43_suboption);
	proto_tree_add_item(o43bsdp_v_tree, hf_bootp_suboption_length, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
	suboptoff++;

	if (suboptoff+subopt_len > optend) {
		expert_add_info_format(pinfo, vti, &ei_bootp_missing_subopt_value,
						"Suboption %d: no room left in option for suboption value", subopt);
		return (optend);
	}

	switch(subopt)
	{
		case 1:
			proto_tree_add_item(o43bsdp_v_tree, hf_bootp_option43_bsdp_message_type, tvb, suboptoff, subopt_len, ENC_ASCII|ENC_NA);
			break;
		case 2:
			proto_tree_add_item(o43bsdp_v_tree, hf_bootp_option43_bsdp_version, tvb, suboptoff, subopt_len, ENC_BIG_ENDIAN);
			break;
		case 3:
			proto_tree_add_item(o43bsdp_v_tree, hf_bootp_option43_bsdp_server_identifier, tvb, suboptoff, subopt_len, ENC_BIG_ENDIAN);
			break;
		case 4:
			proto_tree_add_item(o43bsdp_v_tree, hf_bootp_option43_bsdp_server_priority, tvb, suboptoff, subopt_len, ENC_BIG_ENDIAN);
			break;
		case 5:
			proto_tree_add_item(o43bsdp_v_tree, hf_bootp_option43_bsdp_reply_port, tvb, suboptoff, subopt_len, ENC_BIG_ENDIAN);
			break;
		case 6:
			proto_tree_add_item(o43bsdp_v_tree, hf_bootp_option43_bsdp_boot_image_list_path, tvb, suboptoff, subopt_len, ENC_ASCII|ENC_NA);
			break;
		case 7:
			ti = proto_tree_add_item(o43bsdp_v_tree, hf_bootp_option43_bsdp_default_boot_image_id, tvb, suboptoff, subopt_len, ENC_BIG_ENDIAN|ENC_NA);
			o43bsdp_va_tree = proto_item_add_subtree(ti, ett_bootp_o43_bsdp_boot_image);
			dissect_vendor_bsdp_boot_image(o43bsdp_va_tree, tvb, suboptoff);
			proto_tree_add_item(o43bsdp_va_tree, hf_bootp_option43_bsdp_boot_image_index, tvb, suboptoff+2, subopt_len-2, ENC_BIG_ENDIAN|ENC_NA);
			break;
		case 8:
			ti = proto_tree_add_item(o43bsdp_v_tree, hf_bootp_option43_bsdp_selected_boot_image_id, tvb, suboptoff, subopt_len, ENC_BIG_ENDIAN|ENC_NA);
			o43bsdp_vc_tree = proto_item_add_subtree(ti, ett_bootp_o43_bsdp_boot_image);
			dissect_vendor_bsdp_boot_image(o43bsdp_vc_tree, tvb, suboptoff);
			proto_tree_add_item(o43bsdp_vc_tree, hf_bootp_option43_bsdp_boot_image_index, tvb, suboptoff+2, subopt_len-2, ENC_BIG_ENDIAN|ENC_NA);
			break;
		case 9:
			ti = proto_tree_add_item(o43bsdp_v_tree, hf_bootp_option43_bsdp_boot_image_list, tvb, suboptoff, subopt_len, ENC_BIG_ENDIAN|ENC_NA);
			attributes_len = subopt_len;
			attributes_off = suboptoff;
			o43bsdp_vd_tree = proto_item_add_subtree(ti, ett_bootp_o43_bsdp_image_desc_list);
			while (attributes_len >= 5) {
				string_len = tvb_get_guint8(tvb, attributes_off+4);
				if (string_len > 0) {
					tj = proto_tree_add_item(o43bsdp_vd_tree, hf_bootp_option43_bsdp_image_desc, tvb, attributes_off, string_len+5, ENC_BIG_ENDIAN|ENC_NA);
					o43bsdp_vb_tree = proto_item_add_subtree(tj, ett_bootp_o43_bsdp_image_desc);
					dissect_vendor_bsdp_boot_image(o43bsdp_vb_tree, tvb, attributes_off);
					proto_tree_add_item(o43bsdp_vb_tree, hf_bootp_option43_bsdp_boot_image_index, tvb, attributes_off+2, 2, ENC_BIG_ENDIAN|ENC_NA);
					proto_tree_add_item(o43bsdp_vb_tree, hf_bootp_option43_bsdp_boot_image_name_len, tvb, attributes_off+4, 1, ENC_BIG_ENDIAN|ENC_NA);
					proto_tree_add_item(o43bsdp_vb_tree, hf_bootp_option43_bsdp_boot_image_name, tvb, attributes_off+5, string_len, ENC_UTF_8|ENC_NA);
				}
				attributes_off += 5 + string_len;
				attributes_len -= 5 + string_len;
			}
			break;
		case 10:
			proto_tree_add_item(o43bsdp_v_tree, hf_bootp_option43_bsdp_netboot_firmware, tvb, suboptoff, subopt_len, ENC_NA);
			break;
		case 11:
			ti = proto_tree_add_item(o43bsdp_v_tree, hf_bootp_option43_bsdp_attributes_filter_list, tvb, suboptoff, subopt_len, ENC_BIG_ENDIAN|ENC_NA);
			attributes_len = subopt_len;
			attributes_off = suboptoff;
			o43bsdp_va_tree = proto_item_add_subtree(ti, ett_bootp_o43_bsdp_attributes);
			while (attributes_len >= 2) {
				dissect_vendor_bsdp_boot_image(o43bsdp_va_tree, tvb, attributes_off);
				attributes_off+=2;
				attributes_len-=2;
			}
			break;
		case 12:
			proto_tree_add_item(o43bsdp_v_tree, hf_bootp_option43_bsdp_message_size, tvb, suboptoff, subopt_len, ENC_BIG_ENDIAN|ENC_NA);
			break;
	}

	optoff += (subopt_len + 2);
	return optoff;
}

static int
dissect_vendor_generic_suboption(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
				 tvbuff_t *tvb, int optoff, int optend)
{
	int	    suboptoff = optoff;
	guint8	subopt;
	int	    subopt_len;
	proto_item *item;
	proto_tree *sub_tree;

	item = proto_tree_add_item(v_tree, hf_bootp_vendor_unknown_suboption, tvb, optoff, 1, ENC_NA);
	subopt = tvb_get_guint8(tvb, optoff);

	suboptoff+=1;

	if (suboptoff >= optend) {
		expert_add_info_format(pinfo, v_ti, &ei_bootp_missing_subopt_length,
									"Suboption %d: no room left in option for suboption length", subopt);
		return (optend);
	}

	sub_tree = proto_item_add_subtree(item, ett_bootp_option125_suboption);
	proto_tree_add_item_ret_uint(sub_tree, hf_bootp_suboption_length, tvb, suboptoff, 1, ENC_NA, &subopt_len);
	suboptoff++;

	if (suboptoff+subopt_len > optend) {
		expert_add_info_format(pinfo, item, &ei_bootp_missing_subopt_value,
						"Suboption %d: no room left in option for suboption value", subopt);
		return (optend);
	}

	proto_tree_add_item(sub_tree, hf_bootp_suboption_data, tvb, suboptoff, subopt_len, ENC_NA);
	suboptoff+= subopt_len;

	return suboptoff;

}
static const value_string option43_alcatel_suboption_vals[] = {
	{  0, "Padding" },
	{ 58, "Voice VLAN ID" },
	{ 64, "Spatial Redundancy TFTP1" },
	{ 65, "Spatial Redundancy TFTP2" },
	{ 66, "Application Type" },
	{ 67, "SIP URL" },
	{ 255, "Alcatel-Lucent End" },
	{ 0, NULL}
};

static const value_string option43_alcatel_app_type_vals[] = {
	{ 0, "NOE" },
	{ 1, "SIP" },
	{ 0, NULL}
};

/* Look for 'encapsulated vendor-specific options' */
static gboolean
test_encapsulated_vendor_options(tvbuff_t *tvb, int optoff, int optend)
{
	guint8	subopt;
	guint8	subopt_len;

	while (optoff < optend) {
		subopt = tvb_get_guint8(tvb, optoff);
		optoff++;

		/* Skip padding */
		if (subopt == 0)
			continue;
		/* We are done, skip any remaining bytes */
		if (subopt == 255)
			break;

		/* We expect a length byte next */
		if (optoff >= optend)
			return FALSE;
		subopt_len = tvb_get_guint8(tvb, optoff);
		optoff++;

		/* Check remaining room for suboption in option */
		if (optoff + subopt_len > optend)
			return FALSE;
		optoff += subopt_len;
	}
	return TRUE;
}

static int
dissect_vendor_alcatel_suboption(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
				 tvbuff_t *tvb, int optoff, int optend)
{
	int	    suboptoff = optoff;
	guint8	    subopt;
	guint8	    subopt_len;
	proto_item *vti;
	proto_tree *o43alcatel_v_tree;

	subopt = tvb_get_guint8(tvb, optoff);
	suboptoff++;

	if (subopt == 0) {
		proto_tree_add_item(v_tree, hf_bootp_option43_alcatel_padding, tvb, optoff, 1, ENC_BIG_ENDIAN);
		return (suboptoff);
	} else if (subopt == 255) {	/* End Option */
		proto_tree_add_item(v_tree, hf_bootp_option43_alcatel_end, tvb, optoff, 1, ENC_BIG_ENDIAN);
		/* Make sure we skip any junk left this option */
		return (optend);
	}

	if (suboptoff >= optend) {
		expert_add_info_format(pinfo, v_ti, &ei_bootp_missing_subopt_length,
									"Suboption %d: no room left in option for suboption length", subopt);
		return (optend);
	}

	subopt_len = tvb_get_guint8(tvb, suboptoff);
	vti = proto_tree_add_uint_format_value(v_tree, hf_bootp_option43_alcatel_suboption,
				tvb, optoff, subopt_len+2, subopt, "(%d) %s",
				subopt, val_to_str_const(subopt, option43_alcatel_suboption_vals, "Unknown"));

	o43alcatel_v_tree = proto_item_add_subtree(vti, ett_bootp_option43_suboption);
	proto_tree_add_item(o43alcatel_v_tree, hf_bootp_suboption_length, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
	suboptoff++;

	if (suboptoff+subopt_len > optend) {
		expert_add_info_format(pinfo, vti, &ei_bootp_missing_subopt_value,
						"Suboption %d: no room left in option for suboption value", subopt);
		return (optend);
	}

	switch (subopt)
	{
	case 58: /* 0x3A - Alcatel-Lucent AVA VLAN Id */
		if (subopt_len != 2) {
			expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "length isn't 2");
			return (optend);
		}

		proto_tree_add_item(o43alcatel_v_tree, hf_bootp_option43_alcatel_vlan_id, tvb, suboptoff, 2, ENC_BIG_ENDIAN);
		break;
	case 64: /* 0x40 - Alcatel-Lucent TFTP1 */
		if (subopt_len != 4) {
			expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "length isn't 4");
			return (optend);
		}

		proto_tree_add_item(o43alcatel_v_tree, hf_bootp_option43_alcatel_tftp1, tvb, suboptoff, 4, ENC_BIG_ENDIAN);
		break;
	case 65: /* 0x41 - Alcatel-Lucent TFTP2 */
		if (subopt_len != 4) {
			expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "length isn't 4");
			return (optend);
		}

		proto_tree_add_item(o43alcatel_v_tree, hf_bootp_option43_alcatel_tftp2, tvb, suboptoff, 4, ENC_BIG_ENDIAN);
		break;
	case 66: /* 0x42 - Alcatel-Lucent APPLICATION TYPE */
		if (subopt_len != 1) {
			expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "length isn't 1");
			return (optend);
		}
		proto_tree_add_item(o43alcatel_v_tree, hf_bootp_option43_alcatel_app_type, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
		break;
	case 67: /* 0x43 - Alcatel-Lucent SIP URL */
		proto_tree_add_item(o43alcatel_v_tree, hf_bootp_option43_alcatel_sip_url, tvb, suboptoff, subopt_len, ENC_ASCII|ENC_NA);
		break;
	default:
		expert_add_info_format(pinfo, vti, &hf_bootp_subopt_unknown_type, "ERROR, please report: Unknown subopt type handler %d", subopt);
		return optend;
	}

	optoff += (subopt_len + 2);
	return optoff;
}

static const value_string option63_suboption_vals[] = {
	{ 1, "NWIP does not exist on subnet" },
	{ 2, "NWIP exists in options area" },
	{ 3, "NWIP exists in sname/file" },
	{ 4, "NWIP exists, but too big" },
	{ 5, "Broadcast for nearest Netware server" },
	{ 6, "Preferred DSS server" },
	{ 7, "Nearest NWIP server" },
	{ 8, "Autoretries" },
	{ 9, "Autoretry delay, secs" },
	{ 10, "Support NetWare/IP v1.1" },
	{ 11, "Primary DSS" },
	{ 0, NULL }
};

static int
dissect_netware_ip_suboption(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
			     tvbuff_t *tvb, int optoff, int optend)
{
	int	    suboptoff = optoff;
	guint8	    subopt, subopt_len;
	proto_tree *o63_v_tree;
	proto_item *vti, *ti;

	struct basic_types_hfs default_hfs = {
		NULL,
		&hf_bootp_option63_value_ip_address,
		&hf_bootp_option63_value_ip_address,
		NULL,
		&hf_bootp_option63_value_boolean,
		&hf_bootp_option63_value_8,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	};

	static struct opt_info o63_opt[]= {
		/* 0 */ {"",none,NULL},
		/* 1 */ {"NWIP does not exist on subnet",presence,NULL},
		/* 2 */ {"NWIP exists in options area",presence,NULL},
		/* 3 */ {"NWIP exists in sname/file",presence,NULL},
		/* 4 */ {"NWIP exists, but too big",presence,NULL},
		/* 5 */ {"Broadcast for nearest Netware server",val_boolean, &hf_bootp_option63_broadcast},
		/* 6 */ {"Preferred DSS server",ipv4_list,&hf_bootp_option63_preferred_dss_server},
		/* 7 */ {"Nearest NWIP server",ipv4_list,&hf_bootp_option63_nearest_nwip_server},
		/* 8 */ {"Autoretries",val_u_byte,&hf_bootp_option63_autoretries},
		/* 9 */ {"Autoretry delay, secs",val_u_byte,&hf_bootp_option63_autoretry_delay},
		/* 10*/ {"Support NetWare/IP v1.1",val_boolean,&hf_bootp_option63_support_netware_v1_1},
		/* 11*/ {"Primary DSS",ipv4,&hf_bootp_option63_primary_dss}
	};

	subopt = tvb_get_guint8(tvb, optoff);
	suboptoff++;

	if (suboptoff >= optend) {
		expert_add_info_format(pinfo, v_ti, &ei_bootp_missing_subopt_length,
									"Suboption %d: no room left in option for suboption length", subopt);
		return (optend);
	}

	subopt_len = tvb_get_guint8(tvb, suboptoff);
	vti = proto_tree_add_uint_format_value(v_tree, hf_bootp_option63_suboption,
				tvb, optoff, subopt_len+2, subopt, "(%d) %s",
				subopt, val_to_str_const(subopt, option63_suboption_vals, "Unknown"));

	o63_v_tree = proto_item_add_subtree(vti, ett_bootp_option63_suboption);
	proto_tree_add_item(o63_v_tree, hf_bootp_suboption_length, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
	suboptoff++;

	ti = proto_tree_add_item(o63_v_tree, hf_bootp_option63_value, tvb, suboptoff, subopt_len, ENC_NA);
	PROTO_ITEM_SET_HIDDEN(ti);

	if (subopt < array_length(o63_opt)) {
		if (bootp_handle_basic_types(pinfo, o63_v_tree, vti, tvb, o63_opt[subopt].ftype,
							suboptoff, subopt_len, o63_opt[subopt].phf, &default_hfs) == 0) {
			switch(o63_opt[subopt].ftype)
			{
			case presence:
				if (subopt_len != 0) {
					expert_add_info_format(pinfo, vti, &ei_bootp_bad_length, "length isn't 0");
				}
				break;
			default:
				if (o63_opt[subopt].phf == NULL)
					proto_tree_add_item(o63_v_tree, hf_bootp_option63_value, tvb, suboptoff, subopt_len, ENC_NA);
				break;
			}
		}
	}
	optoff += (subopt_len + 2);
	return optoff;
}

static const value_string option125_tr111_suboption_vals[] = {
	{ 1, "DeviceManufacturerOUI" },
	{ 2, "DeviceSerialNumber" },
	{ 3, "DeviceProductClass" },
	{ 4, "GatewayManufacturerOUI" },
	{ 5, "GatewaySerialNumber" },
	{ 6, "GatewayProductClass" },
	{ 0, NULL }
};

static int
dissect_vendor_tr111_suboption(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
			       tvbuff_t *tvb, int optoff, int optend)
{
	int	    suboptoff = optoff;
	proto_tree *o125_v_tree;
	proto_item *vti, *ti;
	guint8	    subopt, subopt_len;

	struct basic_types_hfs default_hfs = {
		NULL,
		NULL,
		NULL,
		&hf_bootp_option125_value_stringz,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	};

	/* Reference: TR-111 DHCP Option 125 Sub-Option Data Fields
	   Page 10.
	*/

	static struct opt_info o125_tr111_opt[]= {
		/* 0 */ {"nop", special, NULL},	/* dummy */
		/* 1 */ {"DeviceManufacturerOUI",  oui,    &hf_bootp_option125_tr111_device_manufacturer_oui},
		/* 2 */ {"DeviceSerialNumber",     string, &hf_bootp_option125_tr111_device_serial_number},
		/* 3 */ {"DeviceProductClass",     string, &hf_bootp_option125_tr111_device_product_class},
		/* 4 */ {"GatewayManufacturerOUI", string, &hf_bootp_option125_tr111_gateway_manufacturer_oui},
		/* 5 */ {"GatewaySerialNumber",    string, &hf_bootp_option125_tr111_gateway_serial_number},
		/* 6 */ {"GatewayProductClass",    string, &hf_bootp_option125_tr111_gateway_product_class},
	};

	subopt = tvb_get_guint8(tvb, optoff);
	suboptoff++;

	if (suboptoff >= optend) {
		expert_add_info_format(pinfo, v_ti, &ei_bootp_missing_subopt_length,
				       "Suboption %d: no room left in option for suboption length", subopt);
		return (optend);
	}

	subopt_len = tvb_get_guint8(tvb, suboptoff);
	vti = proto_tree_add_uint_format_value(v_tree, hf_bootp_option125_tr111_suboption,
				tvb, optoff, subopt_len+2, subopt, "(%d) %s",
				subopt, val_to_str_const(subopt, option125_tr111_suboption_vals, "Unknown"));

	o125_v_tree = proto_item_add_subtree(vti, ett_bootp_option125_tr111_suboption);
	proto_tree_add_item(o125_v_tree, hf_bootp_suboption_length, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
	suboptoff++;

	if (suboptoff+subopt_len > optend) {
		expert_add_info_format(pinfo, vti, &ei_bootp_missing_subopt_value,
						"Suboption %d: no room left in option for suboption value", subopt);
		return (optend);
	}

	ti = proto_tree_add_item(v_tree, hf_bootp_option125_value, tvb, suboptoff, subopt_len, ENC_NA);
	PROTO_ITEM_SET_HIDDEN(ti);

	if (subopt < array_length(o125_tr111_opt)) {
		if (bootp_handle_basic_types(pinfo, o125_v_tree, vti, tvb, o125_tr111_opt[subopt].ftype, suboptoff, subopt_len, o125_tr111_opt[subopt].phf, &default_hfs) == 0) {
			if (o125_tr111_opt[subopt].ftype == special) {
				if (o125_tr111_opt[subopt].phf != NULL)
				   proto_tree_add_item(v_tree, *o125_tr111_opt[subopt].phf, tvb, suboptoff, subopt_len, ENC_BIG_ENDIAN);
				else
				   proto_tree_add_item(v_tree, hf_bootp_option125_value, tvb, suboptoff, subopt_len, ENC_NA);
			}
			else if (o125_tr111_opt[subopt].ftype == oui) {
				/* Get hex string.  Expecting 6 characters. */
				gchar   *oui_string =  tvb_get_string_enc(wmem_packet_scope(), tvb, suboptoff, subopt_len, ENC_ASCII);
				/* Convert to OUI number.  Only 3 bytes so no data lost in downcast. */
				guint32 oui_number = (guint32)strtol(oui_string, NULL, 16);
				/* Add item using oui_vals */
				proto_tree_add_uint(v_tree, *o125_tr111_opt[subopt].phf, tvb, suboptoff, subopt_len, oui_number);
			} else if (o125_tr111_opt[subopt].phf == NULL)
				proto_tree_add_item(v_tree, hf_bootp_option125_value, tvb, suboptoff, subopt_len, ENC_NA);
		}
	}

	optoff += (subopt_len + 2);
	return optoff;
}

static const value_string option125_cl_suboption_vals[] = {
	{ 1, "Option Request" },
	{ 2, "TFTP Server Addresses" },
	{ 3, "eRouter Container Option" },
	{ 4, "MIB Environment Indicator Option" },
	{ 5, "Modem Capabilities" },
	{ 0, NULL }
};

static const value_string pkt_mib_env_ind_opt_vals[] = {
	{ 0x00, "Reserved" },
	{ 0x01, "CableLabs" },
	{ 0x02, "IETF" },
	{ 0x03, "EuroCableLabs" },
	{ 0, NULL }
};

static int
dissect_vendor_cl_suboption(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
			    tvbuff_t *tvb, int optoff, int optend)
{
	int	    suboptoff = optoff;
	guint8	    subopt, subopt_len;
	proto_tree *o125_v_tree;
	proto_item *vti;

	struct basic_types_hfs default_hfs = {
		&hf_bootp_option125_value,
		&hf_bootp_option125_value_ip_address,
		&hf_bootp_option125_value_ip_address,
		&hf_bootp_option125_value_stringz,
		NULL,
		&hf_bootp_option125_value_8,
		&hf_bootp_option125_value_16,
		NULL,
		NULL,
		NULL,
		NULL
	};

	static struct opt_info o125_cl_opt[]= {
		/* 0 */ {"nop", special, NULL},	/* dummy */
		/* 1 */ {"Option Request = ", bytes, &hf_bootp_option125_cl_option_request},
		/* 2 */ {"TFTP Server Addresses : ", ipv4_list, &hf_bootp_option125_cl_tftp_server_addresses},
		/* 3 */ {"eRouter Container Option : ", bytes, &hf_bootp_option125_cl_erouter_container_option},
		/* 4 */ {"MIB Environment Indicator Option = ", val_u_byte, &hf_bootp_option125_cl_mib_environment_indicator_option},
		/* 5 */ {"Modem Capabilities : ", special, &hf_bootp_option125_cl_modem_capabilities},
	};

	subopt = tvb_get_guint8(tvb, optoff);
	suboptoff++;

	if (suboptoff >= optend) {
		expert_add_info_format(pinfo, v_ti, &ei_bootp_missing_subopt_length,
									"Suboption %d: no room left in option for suboption length", subopt);
		return (optend);
	}

	subopt_len = tvb_get_guint8(tvb, suboptoff);
	vti = proto_tree_add_uint_format_value(v_tree, hf_bootp_option125_cl_suboption,
				tvb, optoff, subopt_len+2, subopt, "(%d) %s",
				subopt, val_to_str_const(subopt, option125_cl_suboption_vals, "Unknown"));

	o125_v_tree = proto_item_add_subtree(vti, ett_bootp_option125_cl_suboption);
	proto_tree_add_item(o125_v_tree, hf_bootp_suboption_length, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
	suboptoff++;

	if (suboptoff+subopt_len > optend) {
		expert_add_info_format(pinfo, vti, &ei_bootp_missing_subopt_value,
						"Suboption %d: no room left in option for suboption value", subopt);
		return (optend);
	}

	if (subopt < array_length(o125_cl_opt)) {
		if (bootp_handle_basic_types(pinfo, o125_v_tree, vti, tvb, o125_cl_opt[subopt].ftype,
							suboptoff, subopt_len, o125_cl_opt[subopt].phf, &default_hfs) == 0) {

			switch(o125_cl_opt[subopt].ftype) {
			case special:
				if (o125_cl_opt[subopt].phf != NULL)
				   proto_tree_add_item(o125_v_tree, *o125_cl_opt[subopt].phf, tvb, suboptoff, subopt_len, ENC_BIG_ENDIAN);
				else
				   proto_tree_add_item(o125_v_tree, hf_bootp_option125_value, tvb, suboptoff, subopt_len, ENC_NA);
				switch(subopt){
					case 5: /* Modem Capabilities */
						dissect_docsis_cm_cap(o125_v_tree, tvb, optoff, subopt_len+2, TRUE);
					break;
				}
				break;
			default:
				if (o125_cl_opt[subopt].phf == NULL)
				   proto_tree_add_item(o125_v_tree, hf_bootp_option125_value, tvb, suboptoff, subopt_len, ENC_NA);
				break;
			}
		}
	}

	optoff += (subopt_len + 2);
	return optoff;
}

/* PacketCable Multimedia Terminal Adapter device capabilities (option 60).
   Ref: PKT-SP-I05-021127 sections 8.2 and 10 */

#define PKT_MDC_TLV_OFF 10


/* These are ASCII-encoded hexadecimal digits.	We use the raw hex equivalent for
   convenience. */
#define PKT_MDC_VERSION			0x3031	/* "01" */
#define PKT_MDC_TEL_END			0x3032	/* "02" */
#define PKT_MDC_TGT			0x3033	/* "03" */
#define PKT_MDC_HTTP_ACC		0x3034	/* "04" */
#define PKT_MDC_SYSLOG			0x3035	/* "05" */
#define PKT_MDC_NCS			0x3036	/* "06" */
#define PKT_MDC_PRI_LINE		0x3037	/* "07" */
#define PKT_MDC_VENDOR_TLV		0x3038	/* "08" */
#define PKT_MDC_NVRAM_STOR		0x3039	/* "09" */
#define PKT_MDC_PROV_REP		0x3041	/* "0A" */
#define PKT_MDC_PROV_REP_LC		0x3061	/* "0a" */
#define PKT_MDC_SUPP_CODECS		0x3042	/* "0B" */
#define PKT_MDC_SUPP_CODECS_LC		0x3062	/* "0b" */
#define PKT_MDC_SILENCE			0x3043	/* "0C" */
#define PKT_MDC_SILENCE_LC		0x3063	/* "0c" */
#define PKT_MDC_ECHO_CANCEL		0x3044	/* "0D" */
#define PKT_MDC_ECHO_CANCEL_LC		0x3064	/* "0d" */
#define PKT_MDC_RSVP			0x3045	/* "0E" */
#define PKT_MDC_RSVP_LC			0x3065	/* "0e" */
#define PKT_MDC_UGS_AD			0x3046	/* "0F" */
#define PKT_MDC_UGS_AD_LC		0x3066	/* "0f" */
#define PKT_MDC_IF_INDEX		0x3130	/* "10" */
#define PKT_MDC_FLOW_LOG		0x3131	/* "11" */
#define PKT_MDC_PROV_FLOWS		0x3132	/* "12" */
/* PacketCable 1.5: */
#define PKT_MDC_T38_VERSION		0x3133	/* "13" */
#define	PKT_MDC_T38_EC			0x3134	/* "14" */
#define	PKT_MDC_RFC2833_DTMF		0x3135	/* "15" */
#define PKT_MDC_VOICE_METRICS		0x3136	/* "16" */
#define	PKT_MDC_MIBS			0x3137	/* "17" */
#define	PKT_MDC_MGPI			0x3138	/* "18" */
#define	PKT_MDC_V152			0x3139	/* "19" */
#define	PKT_MDC_CBS			0x3141	/* "1A" */
#define	PKT_MDC_CBS_LC			0x3161	/* "1a" */

static const value_string pkt_mdc_type_vals[] = {
	{ PKT_MDC_VERSION,		"PacketCable Version" },
	{ PKT_MDC_TEL_END,		"Number Of Telephony Endpoints" },
	{ PKT_MDC_TGT,			"TGT Support" },
	{ PKT_MDC_HTTP_ACC,		"HTTP Download File Access Method Support" },
	{ PKT_MDC_SYSLOG,		"MTA-24 Event SYSLOG Notification Support" },
	{ PKT_MDC_NCS,			"NCS Service Flow Support" },
	{ PKT_MDC_PRI_LINE,		"Primary Line Support" },
	{ PKT_MDC_VENDOR_TLV,		"Vendor Specific TLV Type(s)" },
	{ PKT_MDC_NVRAM_STOR,		"NVRAM Ticket/Session Keys Storage Support" },
	{ PKT_MDC_PROV_REP,		"Provisioning Event Reporting Support" },
	{ PKT_MDC_PROV_REP_LC,		"Provisioning Event Reporting Support" },
	{ PKT_MDC_SUPP_CODECS,		"Supported CODEC(s)" },
	{ PKT_MDC_SUPP_CODECS_LC,	"Supported CODEC(s)" },
	{ PKT_MDC_SILENCE,		"Silence Suppression Support" },
	{ PKT_MDC_SILENCE_LC,		"Silence Suppression Support" },
	{ PKT_MDC_ECHO_CANCEL,		"Echo Cancellation Support" },
	{ PKT_MDC_ECHO_CANCEL_LC,	"Echo Cancellation Support" },
	{ PKT_MDC_RSVP,			"RSVP Support/ Reserved" },
	{ PKT_MDC_RSVP_LC,		"RSVP Support/ Reserved" },
	{ PKT_MDC_UGS_AD,		"UGS-AD Support" },
	{ PKT_MDC_UGS_AD_LC,		"UGS-AD Support" },
	{ PKT_MDC_IF_INDEX,		"MTA's \"ifIndex\" starting number in \"ifTable\"" },
	{ PKT_MDC_FLOW_LOG,		"Provisioning Flow Logging Support" },
	{ PKT_MDC_PROV_FLOWS,		"Supported Provisioning Flows" },
	/* PacketCable 1.5: */
	{ PKT_MDC_T38_VERSION,		"T38 Version Support" },
	{ PKT_MDC_T38_EC,		"T38 Error Correction Support" },
	{ PKT_MDC_RFC2833_DTMF,		"RFC 2833 DTMF Support" },
	{ PKT_MDC_VOICE_METRICS,	"Voice Metrics Support" },
	{ PKT_MDC_MIBS,			"MIB Support" },
	{ PKT_MDC_MGPI,			"Multiple Grants Per Interval Support" },
	{ PKT_MDC_V152,			"V.152 Support" },
	/* PacketCable 2.0: */
	{ PKT_MDC_CBS,			"Certificate Bootstrapping Support" },
	{ PKT_MDC_CBS_LC,		"Certificate Bootstrapping Support" },
	{ 0,				NULL }
};

static const value_string pkt_mdc_version_vals[] = {
	{ 0x3030,	"PacketCable 1.0" },
	{ 0x3031,	"PacketCable 1.1/1.5" }, /* 1.5 replaces 1.1-1.3 */
	{ 0x3032,	"PacketCable 2.0" },
	{ 0,		NULL }
};

static const value_string pkt_mdc_boolean_vals[] = {
	{ 0x3030,	"No" },
	{ 0x3031,	"Yes" },
	{ 0,		NULL }
};

static const value_string pkt_mdc_codec_vals[] = {
	{ 0x3031,	"other" },	     /* "01" */
	{ 0x3032,	"unknown" },
	{ 0x3033,	"G.729" },
	{ 0x3034,	"reserved" },
	{ 0x3035,	"G.729E" },
	{ 0x3036,	"PCMU" },
	{ 0x3037,	"G.726-32" },
	{ 0x3038,	"G.728" },
	{ 0x3039,	"PCMA" },	     /* "09" */
	{ 0x3041,	"G.726-16" },	     /* "0A" */
	{ 0x3042,	"G.726-24" },
	{ 0x3043,	"G.726-40" },
	{ 0x3044,	"iLBC" },
	{ 0x3045,	"BV16" },
	{ 0x3046,	"telephone-event" }, /* "0F" */
	{ 0,		NULL }
};

static const value_string pkt_mdc_t38_version_vals[] = {
	{ 0x3030,	"Unsupported" },
	{ 0x3031,	"T.38 Version Zero" }, /* default */
	{ 0x3032,	"T.38 Version One" },
	{ 0x3033,	"T.38 Version Two" },
	{ 0x3035,	"T.38 Version Three" },
	{ 0,		NULL }
};

static const value_string pkt_mdc_t38_ec_vals[] = {
	{ 0x3030,	"None" },
	{ 0x3031,	"Redundancy" }, /* default */
	{ 0x3032,	"FEC" },
	{ 0,		NULL }
};

static const value_string pkt_mdc_mib_orgs[] = {
	{ 0x3030,	"CableLabs" },
	{ 0x3031,	"IETF" },
	{ 0x3032,	"EuroCableLabs" },
	{ 0x3033,	"Reserved" },
	{ 0x3034,	"Reserved" },
	{ 0x3035,	"Reserved" },
	{ 0x3036,	"Reserved" },
	{ 0x3037,	"Reserved" },
	{ 0x3038,	"Reserved" },
	{ 0x3039,	"Reserved" },
	{ 0,		NULL }
};

static int hf_bootp_pkt_mdc_supp_flow_secure = -1;
static int hf_bootp_pkt_mdc_supp_flow_hybrid = -1;
static int hf_bootp_pkt_mdc_supp_flow_basic = -1;

#define PKT_MDC_MIB_CL 0x3030
static int hf_bootp_pkt_mdc_mib_cl_mta = -1;
static int hf_bootp_pkt_mdc_mib_cl_signaling = -1;
static int hf_bootp_pkt_mdc_mib_cl_management_event = -1;
static int hf_bootp_pkt_mdc_mib_cl_mta_extension = -1;
static int hf_bootp_pkt_mdc_mib_cl_mta_signaling_extension = -1;
static int hf_bootp_pkt_mdc_mib_cl_mta_mem_extention = -1;
static int hf_bootp_pkt_mdc_mib_cl_reserved = -1;

#define PKT_MDC_MIB_IETF 0x3031
static int hf_bootp_pkt_mdc_mib_ietf_mta = -1;
static int hf_bootp_pkt_mdc_mib_ietf_signaling = -1;
static int hf_bootp_pkt_mdc_mib_ietf_management_event = -1;
static int hf_bootp_pkt_mdc_mib_ietf_reserved = -1;

#define PKT_MDC_MIB_EURO 0x3032
static int hf_bootp_pkt_mdc_mib_euro_mta = -1;
static int hf_bootp_pkt_mdc_mib_euro_signaling = -1;
static int hf_bootp_pkt_mdc_mib_euro_management_event = -1;
static int hf_bootp_pkt_mdc_mib_euro_mta_extension = -1;
static int hf_bootp_pkt_mdc_mib_euro_mta_signaling_extension = -1;
static int hf_bootp_pkt_mdc_mib_euro_mta_mem_extention = -1;
static int hf_bootp_pkt_mdc_mib_euro_reserved = -1;


static void
dissect_packetcable_mta_cap(proto_tree *v_tree, packet_info *pinfo, tvbuff_t *tvb, int voff, int len)
{
	guint16	       raw_val;
	guint32        flow_val	  = 0;
	int	           off	  = PKT_MDC_TLV_OFF + voff;
	int	           subopt_off, max_len;
	guint	       tlv_len, i, mib_val;
	guint8	       asc_val[3] = "  ", flow_val_str[5];
	proto_item    *ti, *mib_ti;
	proto_tree    *subtree, *subtree2;

	tvb_memcpy (tvb, asc_val, off, 2);
	if (sscanf((gchar*)asc_val, "%x", &tlv_len) != 1 || tlv_len > 0xff) {
		proto_tree_add_expert_format(v_tree, pinfo, &ei_bootp_bad_length, tvb, off, len - off,
			"Bogus length: %s", asc_val);
		return;
	} else {
		proto_tree_add_uint_format_value(v_tree, hf_bootp_pkt_mta_cap_len, tvb, off, 2,
				tlv_len, "%d", tlv_len);
		off += 2;

		while (off - voff < len) {
			/* Type */
			raw_val = tvb_get_ntohs (tvb, off);

			/* Length */
			tvb_memcpy(tvb, asc_val, off + 2, 2);
			if (sscanf((gchar*)asc_val, "%x", &tlv_len) != 1
			    || tlv_len < 1 || tlv_len > G_MAXUINT16) {
				proto_tree_add_expert_format(v_tree, pinfo, &ei_bootp_bad_length, tvb, off, len - off,
						    "Bogus length: %s", asc_val);
				return;
			} else {
				/* Value(s) */

				ti = proto_tree_add_uint_format(v_tree, hf_bootp_pkt_mta_cap_type,
				    tvb, off, 2, raw_val, "0x%s: %s = ",
				    tvb_format_text(tvb, off, 2),
				    val_to_str_const(raw_val, pkt_mdc_type_vals, "unknown"));
				proto_item_set_len(ti, (tlv_len * 2) + 4);
				switch (raw_val) {

				case PKT_MDC_VERSION:
					raw_val = tvb_get_ntohs(tvb, off + 4);
					proto_item_append_text(ti,
							       "%s (%s)",
							       val_to_str_const(raw_val, pkt_mdc_version_vals, "Reserved"),
							       tvb_format_stringzpad(tvb, off + 4, 2) );
					break;

				case PKT_MDC_TEL_END:
				case PKT_MDC_IF_INDEX:
					proto_item_append_text(ti,
							       "%s",
							       tvb_format_stringzpad(tvb, off + 4, 2) );
					break;

				case PKT_MDC_TGT:
				case PKT_MDC_HTTP_ACC:
				case PKT_MDC_SYSLOG:
				case PKT_MDC_NCS:
				case PKT_MDC_PRI_LINE:
				case PKT_MDC_NVRAM_STOR:
				case PKT_MDC_PROV_REP:
				case PKT_MDC_PROV_REP_LC:
				case PKT_MDC_SILENCE:
				case PKT_MDC_SILENCE_LC:
				case PKT_MDC_ECHO_CANCEL:
				case PKT_MDC_ECHO_CANCEL_LC:
				case PKT_MDC_RSVP:
				case PKT_MDC_RSVP_LC:
				case PKT_MDC_UGS_AD:
				case PKT_MDC_UGS_AD_LC:
				case PKT_MDC_FLOW_LOG:
				case PKT_MDC_RFC2833_DTMF:
				case PKT_MDC_VOICE_METRICS:
				case PKT_MDC_MGPI:
				case PKT_MDC_V152:
				case PKT_MDC_CBS:
				case PKT_MDC_CBS_LC:
					raw_val = tvb_get_ntohs(tvb, off + 4);
					proto_item_append_text(ti,
							       "%s (%s)",
							       val_to_str_const(raw_val, pkt_mdc_boolean_vals, "unknown"),
							       tvb_format_stringzpad(tvb, off + 4, 2) );
					break;

				case PKT_MDC_SUPP_CODECS:
				case PKT_MDC_SUPP_CODECS_LC:
					for (i = 0; i < tlv_len; i++) {
						raw_val = tvb_get_ntohs(tvb, off + 4 + (i * 2) );
						proto_item_append_text(ti,
								       "%s%s (%s)",
								       plurality(i + 1, "", ", "),
								       val_to_str_const(raw_val, pkt_mdc_codec_vals, "unknown"),
								       tvb_format_stringzpad(tvb, off + 4 + (i * 2), 2) );
					}
					break;

				case PKT_MDC_PROV_FLOWS:
					tvb_memcpy(tvb, flow_val_str, off + 4, 4);
					flow_val_str[4] = '\0';
					/* We are only reading 4 digits which should fit in 32 bits */
					flow_val = (guint32)strtoul((gchar*)flow_val_str, NULL, 16);
					proto_item_append_text(ti,
							       "0x%04x", flow_val);
					break;

				case PKT_MDC_T38_VERSION:
					raw_val = tvb_get_ntohs(tvb, off + 4);
					proto_item_append_text(ti,
							       "%s (%s)",
							       val_to_str_const(raw_val, pkt_mdc_t38_version_vals, "unknown"),
							       tvb_format_stringzpad(tvb, off + 4, 2) );
					break;

				case PKT_MDC_T38_EC:
					raw_val = tvb_get_ntohs(tvb, off + 4);
					proto_item_append_text(ti,
							       "%s (%s)",
							       val_to_str_const(raw_val, pkt_mdc_t38_ec_vals, "unknown"),
							       tvb_format_stringzpad(tvb, off + 4, 2) );
					break;

				case PKT_MDC_MIBS:
					break;

				case PKT_MDC_VENDOR_TLV:
				default:
					proto_item_append_text(ti,
							       "%s",
							       tvb_format_stringzpad(tvb, off + 4, tlv_len * 2) );
					break;
				}
			}
			subtree = proto_item_add_subtree(ti, ett_bootp_option);
			if (raw_val == PKT_MDC_PROV_FLOWS) {
				static const int * flows[] = {
					&hf_bootp_pkt_mdc_supp_flow_secure,
					&hf_bootp_pkt_mdc_supp_flow_hybrid,
					&hf_bootp_pkt_mdc_supp_flow_basic,
					NULL
				};

				proto_tree_add_bitmask_list_value(subtree, tvb, off + 4, 4, flows, flow_val);
			} else if (raw_val == PKT_MDC_MIBS) {
			/* 17 06 02 00 38 02 01 07 */
				subopt_off = off + 4;
				max_len = subopt_off + (tlv_len * 2);
				while (subopt_off < max_len) {
					raw_val = tvb_get_ntohs(tvb, subopt_off);
					if (raw_val != 0x3032) { /* We only know how to handle a length of 2 */
						tvb_memcpy(tvb, asc_val, subopt_off, 2);
						proto_tree_add_expert_format(subtree, pinfo, &ei_bootp_bad_length, tvb, subopt_off, 2,
									"Bogus length: %s", asc_val);
						return;
					}

					subopt_off += 2;
					raw_val = tvb_get_ntohs(tvb, subopt_off);
					tvb_memcpy(tvb, asc_val, subopt_off, 2);

					subtree2 = proto_tree_add_subtree_format(subtree, tvb, subopt_off, 2,
						ett_bootp_option, &mib_ti, "%s (%s)",
						val_to_str_const(raw_val, pkt_mdc_mib_orgs, "Unknown"), asc_val);
					if (subopt_off > off + 4 + 2) {
						proto_item_append_text(ti, ", ");
					}
					proto_item_append_text(ti, "%s", val_to_str_const(raw_val, pkt_mdc_mib_orgs, "Unknown"));

					subopt_off += 2;
					tvb_memcpy(tvb, asc_val, subopt_off, 2);
					if (sscanf((gchar*)asc_val, "%x", &mib_val) != 1) {
						proto_tree_add_expert_format(v_tree, pinfo, &ei_bootp_bad_bitfield, tvb, subopt_off, 2,
									"Bogus bitfield: %s", asc_val);
						return;
					}
					switch (raw_val) {

					case PKT_MDC_MIB_CL: {
						static const int * cl_flags[] = {
							&hf_bootp_pkt_mdc_mib_cl_mta,
							&hf_bootp_pkt_mdc_mib_cl_signaling,
							&hf_bootp_pkt_mdc_mib_cl_management_event,
							&hf_bootp_pkt_mdc_mib_cl_mta_extension,
							&hf_bootp_pkt_mdc_mib_cl_mta_signaling_extension,
							&hf_bootp_pkt_mdc_mib_cl_mta_mem_extention,
							&hf_bootp_pkt_mdc_mib_cl_reserved,
							NULL
						};

						proto_tree_add_bitmask_list_value(subtree2, tvb, subopt_off, 2, cl_flags, mib_val);
                        }
						break;

					case PKT_MDC_MIB_IETF: {
						static const int * ietf_flags[] = {
							&hf_bootp_pkt_mdc_mib_ietf_mta,
							&hf_bootp_pkt_mdc_mib_ietf_signaling,
							&hf_bootp_pkt_mdc_mib_ietf_management_event,
							&hf_bootp_pkt_mdc_mib_ietf_reserved,
							NULL
						};

						proto_tree_add_bitmask_list_value(subtree2, tvb, subopt_off, 2, ietf_flags, mib_val);
                        }
						break;

					case PKT_MDC_MIB_EURO: {
						static const int * euro_flags[] = {
							&hf_bootp_pkt_mdc_mib_euro_mta,
							&hf_bootp_pkt_mdc_mib_euro_signaling,
							&hf_bootp_pkt_mdc_mib_euro_management_event,
							&hf_bootp_pkt_mdc_mib_euro_mta_extension,
							&hf_bootp_pkt_mdc_mib_euro_mta_signaling_extension,
							&hf_bootp_pkt_mdc_mib_euro_mta_mem_extention,
							&hf_bootp_pkt_mdc_mib_euro_reserved,
							NULL
						};

						proto_tree_add_bitmask_list_value(subtree2, tvb, subopt_off, 2, euro_flags, mib_val);
                        }
						break;

					default:
						break;
					}
					subopt_off += 2;
				}

			}
			off += (tlv_len * 2) + 4;
		}
	}
}

/* DOCSIS Cable Modem device capabilities (option 60/option 125). */
#define DOCSIS_CM_CAP_TLV_OFF 12

#define DOCSIS_CM_CAP_CONCAT_SUP	0x01
#define DOCSIS_CM_CAP_DOCSIS_VER	0x02
#define DOCSIS_CM_CAP_FRAG_SUP		0x03
#define DOCSIS_CM_CAP_PHS_SUP		0x04
#define DOCSIS_CM_CAP_IGMP_SUP		0x05
#define DOCSIS_CM_CAP_PRIV_SUP		0x06
#define DOCSIS_CM_CAP_DSAID_SUP		0x07
#define DOCSIS_CM_CAP_USSF_SUP		0x08
#define DOCSIS_CM_CAP_FILT_SUP		0x09
#define DOCSIS_CM_CAP_TET_MI		0x0a
#define DOCSIS_CM_CAP_TET		0x0b
#define DOCSIS_CM_CAP_DCC_SUP		0x0c
#define DOCSIS_CM_CAP_IPFILT_SUP	0x0d
#define DOCSIS_CM_CAP_LLCFILT_SUP	0x0e
#define DOCSIS_CM_CAP_EXPUNI_SPACE	0x0f
#define DOCSIS_CM_CAP_RNGHLDOFF_SUP	0x10
#define DOCSIS_CM_CAP_L2VPN_SUP		0x11
#define DOCSIS_CM_CAP_L2VPN_HOST_SUP	0x12
#define DOCSIS_CM_CAP_DUTFILT_SUP	0x13
#define DOCSIS_CM_CAP_USFREQRNG_SUP	0x14
#define DOCSIS_CM_CAP_USSYMRATE_SUP	0x15
#define DOCSIS_CM_CAP_SACM2_SUP		0x16
#define DOCSIS_CM_CAP_SACM2HOP_SUP	0x17
#define DOCSIS_CM_CAP_MULTTXCHAN_SUP	0x18
#define DOCSIS_CM_CAP_512USTXCHAN_SUP	0x19
#define DOCSIS_CM_CAP_256USTXCHAN_SUP	0x1a
#define DOCSIS_CM_CAP_TOTALSIDCLU_SUP	0x1b
#define DOCSIS_CM_CAP_SIDCLUPERSF_SUP	0x1c
#define DOCSIS_CM_CAP_MULTRXCHAN_SUP	0x1d
#define DOCSIS_CM_CAP_TOTALDSID_SUP	0x1e
#define DOCSIS_CM_CAP_RESEQDSID_SUP	0x1f
#define DOCSIS_CM_CAP_MULTDSID_SUP	0x20
#define DOCSIS_CM_CAP_MULTDSIDFW_SUP	0x21
#define DOCSIS_CM_CAP_FCTF_SUP		0x22
#define DOCSIS_CM_CAP_DPV_SUP		0x23
#define DOCSIS_CM_CAP_UGSPERUSFLOW_SUP	0x24
#define DOCSIS_CM_CAP_MAPUCDRECEIPT_SUP	0x25
#define DOCSIS_CM_CAP_USDROPCLASSIF_SUP	0x26
#define DOCSIS_CM_CAP_IPV6_SUP		0x27
#define DOCSIS_CM_CAP_ExUsTrPow		0x28
#define DOCSIS_CM_CAP_Opt802MPLSSup		0x29
#define DOCSIS_CM_CAP_DounEnc		0x2a
#define DOCSIS_CM_CAP_EnrgMang		0x2c

static const value_string docsis_cm_cap_type_vals[] = {
	{ DOCSIS_CM_CAP_CONCAT_SUP,		"Concatenation Support" },
	{ DOCSIS_CM_CAP_DOCSIS_VER,		"DOCSIS Version" },
	{ DOCSIS_CM_CAP_FRAG_SUP,		"Fragmentation Support" },
	{ DOCSIS_CM_CAP_PHS_SUP,		"Payload Header Suppression Support" },
	{ DOCSIS_CM_CAP_IGMP_SUP,		"IGMP Support" },
	{ DOCSIS_CM_CAP_PRIV_SUP,		"Privacy Support" },
	{ DOCSIS_CM_CAP_DSAID_SUP,		"Downstream SAID Support" },
	{ DOCSIS_CM_CAP_USSF_SUP,		"Upstream Service Flow Support" },
	{ DOCSIS_CM_CAP_FILT_SUP,		"Optional Filtering Support" },
	{ DOCSIS_CM_CAP_TET_MI,			"Transmit Equalizer Taps per Modulation Interval" },
	{ DOCSIS_CM_CAP_TET,			"Number of Transmit Equalizer Taps" },
	{ DOCSIS_CM_CAP_DCC_SUP,		"DCC Support" },
	{ DOCSIS_CM_CAP_IPFILT_SUP,		"IP Filters Support" },
	{ DOCSIS_CM_CAP_LLCFILT_SUP,		"LLC Filters Support" },
	{ DOCSIS_CM_CAP_EXPUNI_SPACE,		"Expanded Unicast SID Space" },
	{ DOCSIS_CM_CAP_RNGHLDOFF_SUP,		"Ranging Hold-Off Support" },
	{ DOCSIS_CM_CAP_L2VPN_SUP,		"L2VPN Capability" },
	{ DOCSIS_CM_CAP_L2VPN_HOST_SUP,		"L2VPN eSAFE Host Capability" },
	{ DOCSIS_CM_CAP_DUTFILT_SUP,		"Downstream Unencrypted Traffic (DUT) Filtering" },
	{ DOCSIS_CM_CAP_USFREQRNG_SUP,		"Upstream Frequency Range Support" },
	{ DOCSIS_CM_CAP_USSYMRATE_SUP,		"Upstream Symbol Rate Support" },
	{ DOCSIS_CM_CAP_SACM2_SUP,		"Selectable Active Code Mode 2 Support" },
	{ DOCSIS_CM_CAP_SACM2HOP_SUP,		"Code Hopping Mode 2 Support" },
	{ DOCSIS_CM_CAP_MULTTXCHAN_SUP,		"Multiple Transmit Channel Support" },
	{ DOCSIS_CM_CAP_512USTXCHAN_SUP,	"5.12 Msps Upstream Transmit Channel Support" },
	{ DOCSIS_CM_CAP_256USTXCHAN_SUP,	"2.56 Msps Upstream Transmit Channel Support" },
	{ DOCSIS_CM_CAP_TOTALSIDCLU_SUP,	"Total SID Cluster Support" },
	{ DOCSIS_CM_CAP_SIDCLUPERSF_SUP,	"SID Clusters per Service Flow Support" },
	{ DOCSIS_CM_CAP_MULTRXCHAN_SUP,		"Multiple Receive Channel Support" },
	{ DOCSIS_CM_CAP_TOTALDSID_SUP,		"Total Downstream Service ID (DSID) Support" },
	{ DOCSIS_CM_CAP_RESEQDSID_SUP,		"Resequencing Downstream Service ID (DSID) Support" },
	{ DOCSIS_CM_CAP_MULTDSID_SUP,		"Multicast Downstream Service ID (DSID) Support" },
	{ DOCSIS_CM_CAP_MULTDSIDFW_SUP,		"Multicast DSID Forwarding" },
	{ DOCSIS_CM_CAP_FCTF_SUP,		"Frame Control Type Forwarding Capability" },
	{ DOCSIS_CM_CAP_DPV_SUP,		"DPV Capability" },
	{ DOCSIS_CM_CAP_UGSPERUSFLOW_SUP,	"Unsolicited Grant Service/Upstream Service Flow Support" },
	{ DOCSIS_CM_CAP_MAPUCDRECEIPT_SUP,	"MAP and UCD Receipt Support" },
	{ DOCSIS_CM_CAP_USDROPCLASSIF_SUP,	"Upstream Drop Classifier Support" },
	{ DOCSIS_CM_CAP_IPV6_SUP,		"IPv6 Support" },
	{ DOCSIS_CM_CAP_ExUsTrPow,		"Extended Upstream Transmit Power Capability (1/4 dB)" },
	{ DOCSIS_CM_CAP_Opt802MPLSSup,		"Optional 802.1ad, 802.1ah, MPLS Classification Support" },
	{ DOCSIS_CM_CAP_DounEnc,		"D-ONU Capabilities Encoding" },
	{ DOCSIS_CM_CAP_EnrgMang,		"Energy Management Capabilities" },
	{ 0, NULL }
};

static const value_string docsis_cm_cap_supported_vals[] = {
	{ 0x00,	"Not Support" },
	{ 0x01,	"Supported" },
	{ 0,		NULL }
};

static const value_string docsis_cm_cap_version_vals[] = {
	{ 0x00,	"DOCSIS 1.0" },
	{ 0x01,	"DOCSIS 1.1" },
	{ 0x02,	"DOCSIS 2.0" },
	{ 0x03,	"DOCSIS 3.0" },
	{ 0,		NULL }
};

static const value_string docsis_cm_cap_privacy_vals[] = {
	{ 0x00,	"BPI Support" },
	{ 0x01,	"BPI Plus Support" },
	{ 0,		NULL }
};

static int hf_bootp_docsis_cm_cap_ranging_hold_off_cm = -1;
static int hf_bootp_docsis_cm_cap_ranging_hold_off_eps = -1;
static int hf_bootp_docsis_cm_cap_ranging_hold_off_emta = -1;
static int hf_bootp_docsis_cm_cap_ranging_hold_off_dsg = -1;

static const value_string docsis_cm_cap_l2vpn_vals[] = {
	{ 0x00,	"CM not compliant with DOCSIS L2VPN Section 7 (default)" },
	{ 0x01,	"CM compliant with DOCSIS L2VPN Section 7" },
	{ 0,		NULL }
};

static const value_string docsis_cm_cap_filt_vals[] = {
	{ 0x00,	"802.1P Filtering" },
	{ 0x01,	"802.1Q Filtering" },
	{ 0,		NULL }
};

static int hf_bootp_docsis_cm_cap_mpls_stpid = -1;
static int hf_bootp_docsis_cm_cap_mpls_svid = -1;
static int hf_bootp_docsis_cm_cap_mpls_spcp = -1;
static int hf_bootp_docsis_cm_cap_mpls_sdei = -1;
static int hf_bootp_docsis_cm_cap_mpls_ctpid = -1;
static int hf_bootp_docsis_cm_cap_mpls_cvid = -1;
static int hf_bootp_docsis_cm_cap_mpls_cpcp = -1;
static int hf_bootp_docsis_cm_cap_mpls_ccfi = -1;
static int hf_bootp_docsis_cm_cap_mpls_stci = -1;
static int hf_bootp_docsis_cm_cap_mpls_ctci = -1;
static int hf_bootp_docsis_cm_cap_mpls_itpid = -1;
static int hf_bootp_docsis_cm_cap_mpls_isid = -1;
static int hf_bootp_docsis_cm_cap_mpls_itci = -1;
static int hf_bootp_docsis_cm_cap_mpls_ipcp = -1;
static int hf_bootp_docsis_cm_cap_mpls_idei = -1;
static int hf_bootp_docsis_cm_cap_mpls_iuca = -1;
static int hf_bootp_docsis_cm_cap_mpls_btpid = -1;
static int hf_bootp_docsis_cm_cap_mpls_btci = -1;
static int hf_bootp_docsis_cm_cap_mpls_bpcp = -1;
static int hf_bootp_docsis_cm_cap_mpls_bdei = -1;
static int hf_bootp_docsis_cm_cap_mpls_bvid = -1;
static int hf_bootp_docsis_cm_cap_mpls_bda = -1;
static int hf_bootp_docsis_cm_cap_mpls_bsa = -1;
static int hf_bootp_docsis_cm_cap_mpls_tc = -1;
static int hf_bootp_docsis_cm_cap_mpls_label = -1;

static const value_string docsis_cm_cap_enrgmang_vals[] = {
	{ 0x00,	"Energy Management 1x1 Feature" },
	{ 0,		NULL }
};

static const value_string docsis_cm_cap_usfreqrng_vals[] = {
	{ 0x00,	"Standard Upstream Frequency Range" },
	{ 0x01,	"Standard Upstream Frequency Range and Extended Upstream Frequency Range" },
	{ 0,		NULL }
};

static const value_string docsis_cm_cap_map_ucd_receipt_vals[] = {
	{ 0x00,	"CM cannot support the receipt of MAPs and UCDs on downstreams other than the Primary Downstream Channel" },
	{ 0x01,	"CM can support the receipt of MAPs and UCDs on downstreams other than the Primary Downstream Channel" },
	{ 0,		NULL }
};

static const value_string docsis_cm_cap_map_dpv_support_vals[] = {
	{ 0x00,	"U1 supported as a Start Reference Point for DPV per Path" },
	{ 0x01,	"U1 supported as a Start Reference Point for DPV per Packet" },
	{ 0,		NULL }
};

static const value_string docsis_cm_cap_map_multDsidForward_support_vals[] = {
	{ 0x00,	"No support for multicast DSID forwarding" },
	{ 0x01,	"Support for GMAC explicit multicast DSID forwarding" },
	{ 0x02,	"Support for GMAC promiscuous multicast DSID forwarding" },
	{ 0,		NULL }
};

static const value_string docsis_cm_cap_map_fctfc_support_vals[] = {
	{ 0x00,	"Isolation Packet PDU MAC Header (FC_Type of 10) is not forwarded" },
	{ 0x01,	"Isolation Packet PDU MAC Header (FC_Type of 10) is forwarded" },
	{ 0,		NULL }
};

static const value_string docsis_cm_cap_map_l2vpn_esafe_index_support_vals[] = {
	{ 0x01,	"ePs or eRouter" },
	{ 0x10,	"eMTA" },
	{ 0x11,	"eSTB-IP" },
	{ 0x12,	"eSTB-DSG" },
	{ 0x13,	"eTEA" },
	{ 0,		NULL }
};

static int hf_bootp_docsis_cm_cap_ussymrate_160 = -1;
static int hf_bootp_docsis_cm_cap_ussymrate_320 = -1;
static int hf_bootp_docsis_cm_cap_ussymrate_640 = -1;
static int hf_bootp_docsis_cm_cap_ussymrate_1280 = -1;
static int hf_bootp_docsis_cm_cap_ussymrate_2560 = -1;
static int hf_bootp_docsis_cm_cap_ussymrate_5120 = -1;

static void
display_uint_with_range_checking(proto_item *ti, guint8 val_byte, guint16 val_uint16, int min_value, int max_value)
{
	guint16 value;

	if (0 != val_byte)
	{
		value = val_byte;
	}
	else
	{
		value = val_uint16;
	}
	proto_item_append_text(ti, "%i", value);
	if ((value < min_value) ||
	    (value > max_value))
	{
		proto_item_append_text(ti, " (Value Out-of-Range [%i..%i])", min_value, max_value);
	}
}

static void get_opt125_tlv(tvbuff_t *tvb, guint off, guint8 *tlvtype, guint8 *tlvlen, guint8 **value)
{
	/* Type */
	*tlvtype = tvb_get_guint8(tvb, off);
	/* Length */
	*tlvlen	 = tvb_get_guint8(tvb, off+1);
	/* Value */
	*value = (guint8 *)tvb_memdup(wmem_packet_scope(), tvb, off + 2, *tlvlen);
}

static void get_opt60_tlv(tvbuff_t *tvb, guint off, guint8 *tlvtype, guint8 *tlvlen, guint8 **value)
{
	guint	i;
	guint8 *val_asc;

	val_asc = (guint8 *)wmem_alloc0(wmem_packet_scope(), 4);
	/* Type */
	tvb_memcpy(tvb, val_asc, off, 2);
	*tlvtype = (guint8)strtoul((gchar*)val_asc, NULL, 16);
	/* Length */
	tvb_memcpy(tvb, val_asc, off + 2, 2);
	*tlvlen = (guint8)strtoul((gchar*)val_asc, NULL, 16);
	/* Value */
	*value = (guint8 *)wmem_alloc0(wmem_packet_scope(), *tlvlen);
	for (i=0; i<*tlvlen; i++)
	{
		memset(val_asc, 0, 4);
		tvb_memcpy(tvb, val_asc, off + ((i*2) + 4), 2);
		(*value)[i] = (guint8)strtoul((gchar*)val_asc, NULL, 16);
	}
}

static void
dissect_docsis_cm_cap(proto_tree *v_tree, tvbuff_t *tvb, int voff, int len, gboolean opt125)
{
	guint8	   *asc_val;
	proto_item *ti;
	proto_tree *subtree;
	guint8	    tlv_type;
	guint8	    tlv_len;
	guint8	    val_byte   = 0;
	guint16	    val_uint16 = 0;
	guint8	   *val_other  = NULL;
	guint	    off	       = voff;

	asc_val = (guint8*)wmem_alloc0(wmem_packet_scope(), 4);

	if (opt125)
	{
		/* Option 125 is formatted as uint8's */
		/* Type */
		tlv_type = tvb_get_guint8(tvb, off);
		/* Length */
		tlv_len	 = tvb_get_guint8(tvb, off+1);
		proto_tree_add_uint_format_value(v_tree, hf_bootp_docsis_cm_cap_len, tvb, off+1, 1,
						 tlv_len, "%d", tlv_len);
	}
	else
	{
		/* Option 60 is formatted as an ASCII string.
		   Since the capabilities are the same for both options
		   I am converting the Option 60 values from ASCII to
		   uint8s to allow the same parser to work for both */
		off += DOCSIS_CM_CAP_TLV_OFF;
		tvb_memcpy (tvb, asc_val, off, 2);
		tlv_len = (guint8)strtoul((gchar*)asc_val, NULL, 16);
		proto_tree_add_uint_format_value(v_tree, hf_bootp_docsis_cm_cap_len, tvb, off+2, 2,
						 tlv_len, "%d", tlv_len);
	}

	off+=2;

	while (off - ((guint) voff) < ((guint) len))
	{
		tlv_type = 0;
		tlv_len = 0;
		val_byte = 0;
		val_uint16 = 0;

		if (opt125)
		{
			get_opt125_tlv(tvb, off, &tlv_type, &tlv_len, &val_other);
			ti =  proto_tree_add_uint_format(v_tree, hf_bootp_docsis_cm_cap_type, tvb, off,
							 tlv_len + 2,
							 tlv_type,
							 "0x%02x: %s = ",
							 tlv_type,
							 val_to_str_const(tlv_type, docsis_cm_cap_type_vals, "unknown"));
		}
		else
		{
			/* Option 60 is formatted as an ASCII string.  Since the capabilities
			   are the same for both options I am converting the Option 60 values
			   from ASCII to uint8s to allow the same parser to work for both */
			get_opt60_tlv(tvb, off, &tlv_type, &tlv_len, &val_other);
			ti =  proto_tree_add_uint_format(v_tree, hf_bootp_docsis_cm_cap_type, tvb, off,
							 (tlv_len * 2) + 4,
							 tlv_type,
							 "0x%02x: %s = ",
							 tlv_type,
							 val_to_str_const(tlv_type, docsis_cm_cap_type_vals, "unknown"));
		}

		if (tlv_len == 1)
		{
			/* The value refers to a byte. */
			val_byte = val_other[0];
		}
		else
		{
			if (tlv_len == 2)
			{
				/* The value refers to a uint16. */
				val_uint16 = (val_other[0] << 8) + val_other[1];
			}
		}

		switch (tlv_type)
		{
		case DOCSIS_CM_CAP_CONCAT_SUP:
		case DOCSIS_CM_CAP_FRAG_SUP:
		case DOCSIS_CM_CAP_PHS_SUP:
		case DOCSIS_CM_CAP_IGMP_SUP:
		case DOCSIS_CM_CAP_DCC_SUP:
		case DOCSIS_CM_CAP_EXPUNI_SPACE:
		case DOCSIS_CM_CAP_DUTFILT_SUP:
		case DOCSIS_CM_CAP_SACM2_SUP:
		case DOCSIS_CM_CAP_SACM2HOP_SUP:
		case DOCSIS_CM_CAP_IPV6_SUP:
			proto_item_append_text(ti,
					       "%s",
					       val_to_str_const(val_byte, docsis_cm_cap_supported_vals, "Reserved"));
			break;
		case DOCSIS_CM_CAP_DOCSIS_VER:
			proto_item_append_text(ti,
					       "%s",
					       val_to_str_const(val_byte, docsis_cm_cap_version_vals, "Reserved"));
			break;
		case DOCSIS_CM_CAP_PRIV_SUP:
			proto_item_append_text(ti,
					       "%s",
					       val_to_str_const(val_byte, docsis_cm_cap_privacy_vals, "Reserved"));
			break;
		case DOCSIS_CM_CAP_FILT_SUP:
			proto_item_append_text(ti,
					       "%s",
					       val_to_str_const(val_byte, docsis_cm_cap_filt_vals, "Reserved"));
			break;
		case DOCSIS_CM_CAP_L2VPN_SUP:
			proto_item_append_text(ti,
					       "%s",
					       val_to_str_const(val_byte, docsis_cm_cap_l2vpn_vals, "Reserved"));
			break;
		case DOCSIS_CM_CAP_L2VPN_HOST_SUP:
			if (tlv_len == 7) {
				proto_item_append_text(ti,
						       "eSAFE ifIndex %s (%i)/eSAFE MAC %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
						       val_to_str_const(val_other[0], docsis_cm_cap_map_l2vpn_esafe_index_support_vals, "Reserved"),
						       val_other[0],
						       val_other[1],
						       val_other[2],
						       val_other[3],
						       val_other[4],
						       val_other[5],
						       val_other[6]);
			} else {
				proto_item_append_text(ti,
						       "Invalid (length should be 7, is %d)",
						       tlv_len);
			}
			break;
		case DOCSIS_CM_CAP_USFREQRNG_SUP:
			proto_item_append_text(ti,
					       "%s",
					       val_to_str_const(val_byte, docsis_cm_cap_usfreqrng_vals, "Reserved"));
			break;
		case DOCSIS_CM_CAP_MAPUCDRECEIPT_SUP:
			proto_item_append_text(ti,
					       "%s",
					       val_to_str_const(val_byte, docsis_cm_cap_map_ucd_receipt_vals, "Reserved"));
			break;
		case DOCSIS_CM_CAP_DPV_SUP:
			proto_item_append_text(ti,
					       "%s",
					       val_to_str_const(val_byte, docsis_cm_cap_map_dpv_support_vals, "Reserved"));
			break;
		case DOCSIS_CM_CAP_DSAID_SUP:
		case DOCSIS_CM_CAP_MULTTXCHAN_SUP:
		case DOCSIS_CM_CAP_512USTXCHAN_SUP:
		case DOCSIS_CM_CAP_256USTXCHAN_SUP:
		case DOCSIS_CM_CAP_TOTALSIDCLU_SUP:
		case DOCSIS_CM_CAP_MULTRXCHAN_SUP:
		case DOCSIS_CM_CAP_UGSPERUSFLOW_SUP:
		case DOCSIS_CM_CAP_USSF_SUP:
			display_uint_with_range_checking(ti, val_byte, val_uint16, 0, 255);
			break;
		case DOCSIS_CM_CAP_RESEQDSID_SUP:
		case DOCSIS_CM_CAP_MULTDSID_SUP:
			display_uint_with_range_checking(ti, val_byte, val_uint16, 16, 255);
			break;
		case DOCSIS_CM_CAP_SIDCLUPERSF_SUP:
			display_uint_with_range_checking(ti, val_byte, val_uint16, 2, 8);
			break;
		case DOCSIS_CM_CAP_TOTALDSID_SUP:
			display_uint_with_range_checking(ti, val_byte, val_uint16, 32, 255);
			break;
		case DOCSIS_CM_CAP_TET:
			display_uint_with_range_checking(ti, val_byte, val_uint16, 8, 64);
			break;
		case DOCSIS_CM_CAP_TET_MI:
			if ((val_byte == 1) ||
			    (val_byte == 2) ||
			    (val_byte == 4))
			{
				proto_item_append_text(ti,
						       " %i",
						       val_byte);
			}
			else
			{
				proto_item_append_text(ti,
						       " (Invalid Value %i : Should be [1,2,4]",
						       val_byte);
			}
			break;
		case DOCSIS_CM_CAP_IPFILT_SUP:
		case DOCSIS_CM_CAP_USDROPCLASSIF_SUP:
			display_uint_with_range_checking(ti, val_byte, val_uint16, 64, 65535);
			break;
		case DOCSIS_CM_CAP_LLCFILT_SUP:
			display_uint_with_range_checking(ti, val_byte, val_uint16, 10, 65535);
			break;
		case DOCSIS_CM_CAP_ExUsTrPow:
			if (val_byte == 0)
			{
				proto_item_append_text(ti, "%i", val_byte);
			}
			else
			{
				display_uint_with_range_checking(ti, val_byte, val_uint16, 205, 244);
			}
			break;
		case DOCSIS_CM_CAP_Opt802MPLSSup:
			proto_item_append_text(ti,
					       "0x%02x", val_byte);
		case DOCSIS_CM_CAP_DounEnc:
			/* TODO: add D-ONU Capabilities Encoding according DPoE-SP-MULPIv1.0-I02-120607 */
			break;
		case DOCSIS_CM_CAP_EnrgMang:
			proto_item_append_text(ti,
					       "%s",
					       val_to_str_const(val_byte, docsis_cm_cap_enrgmang_vals, "Reserved"));
			break;
		case DOCSIS_CM_CAP_RNGHLDOFF_SUP:
			proto_item_append_text(ti,
					       "Ranging ID ");
			if (tlv_len == 4)
			{
				proto_item_append_text(ti,
						"(0x%04x)", (val_other[0] << sizeof(guint8)) + val_other[1]);
				proto_item_append_text(ti,
						" Component Bit Mask ");
				proto_item_append_text(ti,
						"(0x%04x)", (val_other[2] << sizeof(guint8)) + val_other[3]);
			}
			else
			{
				proto_item_append_text(ti,
						" (Invalid Length %u : Should be 4",
						tlv_len);
			}
			break;
		case DOCSIS_CM_CAP_USSYMRATE_SUP:
			proto_item_append_text(ti,
					       "0x%02x", val_byte);
			break;
		case DOCSIS_CM_CAP_FCTF_SUP:
			proto_item_append_text(ti,
					       "%s",
					       val_to_str_const(val_byte, docsis_cm_cap_map_fctfc_support_vals, "Reserved"));
			break;
		case DOCSIS_CM_CAP_MULTDSIDFW_SUP:
			proto_item_append_text(ti,
					       "%s",
					       val_to_str_const(val_byte, docsis_cm_cap_map_multDsidForward_support_vals, "Reserved"));
			break;
		}

		subtree = proto_item_add_subtree(ti, ett_bootp_option);
		if (tlv_type == DOCSIS_CM_CAP_RNGHLDOFF_SUP && tlv_len >= 4)
		{
			const int * flags[] = {
				&hf_bootp_docsis_cm_cap_ranging_hold_off_cm,
				&hf_bootp_docsis_cm_cap_ranging_hold_off_eps,
				&hf_bootp_docsis_cm_cap_ranging_hold_off_emta,
				&hf_bootp_docsis_cm_cap_ranging_hold_off_dsg,
				NULL
			};
			val_uint16 = (val_other[2] << sizeof(guint8)) + val_other[3];

			proto_tree_add_bitmask_list_value(subtree, tvb, off + 2, 4, flags, val_uint16);
		}
		if (tlv_type == DOCSIS_CM_CAP_USSYMRATE_SUP)
		{
			const int * flags[] = {
				&hf_bootp_docsis_cm_cap_ussymrate_160,
				&hf_bootp_docsis_cm_cap_ussymrate_320,
				&hf_bootp_docsis_cm_cap_ussymrate_640,
				&hf_bootp_docsis_cm_cap_ussymrate_1280,
				&hf_bootp_docsis_cm_cap_ussymrate_2560,
				&hf_bootp_docsis_cm_cap_ussymrate_5120,
				NULL
			};

			proto_tree_add_bitmask_list_value(subtree, tvb, off + 2, 1, flags, val_byte);
		}
		if (tlv_type == DOCSIS_CM_CAP_Opt802MPLSSup && tlv_len >= 4)
		{
			const int * flags[] = {
				&hf_bootp_docsis_cm_cap_mpls_stpid,
				&hf_bootp_docsis_cm_cap_mpls_svid,
				&hf_bootp_docsis_cm_cap_mpls_spcp,
				&hf_bootp_docsis_cm_cap_mpls_sdei,
				&hf_bootp_docsis_cm_cap_mpls_ctpid,
				&hf_bootp_docsis_cm_cap_mpls_cvid,
				&hf_bootp_docsis_cm_cap_mpls_cpcp,
				&hf_bootp_docsis_cm_cap_mpls_ccfi,
				&hf_bootp_docsis_cm_cap_mpls_stci,
				&hf_bootp_docsis_cm_cap_mpls_ctci,
				&hf_bootp_docsis_cm_cap_mpls_itpid,
				&hf_bootp_docsis_cm_cap_mpls_isid,
				&hf_bootp_docsis_cm_cap_mpls_itci,
				&hf_bootp_docsis_cm_cap_mpls_ipcp,
				&hf_bootp_docsis_cm_cap_mpls_idei,
				&hf_bootp_docsis_cm_cap_mpls_iuca,
				&hf_bootp_docsis_cm_cap_mpls_btpid,
				&hf_bootp_docsis_cm_cap_mpls_btci,
				&hf_bootp_docsis_cm_cap_mpls_bpcp,
				&hf_bootp_docsis_cm_cap_mpls_bdei,
				&hf_bootp_docsis_cm_cap_mpls_bvid,
				&hf_bootp_docsis_cm_cap_mpls_bda,
				&hf_bootp_docsis_cm_cap_mpls_bsa,
				&hf_bootp_docsis_cm_cap_mpls_tc,
				&hf_bootp_docsis_cm_cap_mpls_label,
				NULL
			};
			val_uint16 = (val_other[2] << sizeof(guint8)) + val_other[3];

			proto_tree_add_bitmask_list_value(subtree, tvb, off + 2, 4, flags, val_uint16);
		}
		if (opt125)
		{
			off += (tlv_len) + 2;
		}
		else
		{
			off += (tlv_len *2) + 4;
		}

	}
}

/* Definitions specific to PKT-SP-PROV-I05-021127 begin with "PKT_CCC_I05".
   Definitions specific to IETF draft 5 and RFC 3495 begin with "PKT_CCC_IETF".
   Shared definitions begin with "PKT_CCC".
 */
#define PKT_CCC_PRI_DHCP       1
#define PKT_CCC_SEC_DHCP       2
#define PKT_CCC_I05_SNMP       3
#define PKT_CCC_IETF_PROV_SRV  3
#define PKT_CCC_I05_PRI_DNS    4
#define PKT_CCC_IETF_AS_KRB    4
#define PKT_CCC_I05_SEC_DNS    5
#define PKT_CCC_IETF_AP_KRB    5
#define PKT_CCC_KRB_REALM      6
#define PKT_CCC_TGT_FLAG       7
#define PKT_CCC_PROV_TIMER     8
#define PKT_CCC_CMS_FQDN       9
#define PKT_CCC_IETF_SEC_TKT   9
#define PKT_CCC_AS_KRB	      10
#define PKT_CCC_AP_KRB	      11
#define PKT_CCC_MTA_KRB_CLEAR 12

static const value_string pkt_i05_ccc_opt_vals[] = {
	{ PKT_CCC_PRI_DHCP,		"Primary DHCP Server" },
	{ PKT_CCC_SEC_DHCP,		"Secondary DHCP Server" },
	{ PKT_CCC_I05_SNMP,		"SNMP Entity" },
	{ PKT_CCC_I05_PRI_DNS,		"Primary DNS Server" },
	{ PKT_CCC_I05_SEC_DNS,		"Secondary DNS Server" },
	{ PKT_CCC_KRB_REALM,		"Kerberos Realm" },
	{ PKT_CCC_TGT_FLAG,		"MTA should fetch TGT?" },
	{ PKT_CCC_PROV_TIMER,		"Provisioning Timer" },
	{ PKT_CCC_CMS_FQDN,		"CMS FQDN" },
	{ PKT_CCC_AS_KRB,		"AS-REQ/AS-REP Backoff and Retry" },
	{ PKT_CCC_AP_KRB,		"AP-REQ/AP-REP Backoff and Retry" },
	{ PKT_CCC_MTA_KRB_CLEAR,	"MTA should clear Kerberos tickets?" },
	{ 0, NULL },
};

static const value_string pkt_draft5_ccc_opt_vals[] = {
	{ PKT_CCC_PRI_DHCP,		"TSP's Primary DHCP Server" },
	{ PKT_CCC_SEC_DHCP,		"TSP's Secondary DHCP Server" },
	{ PKT_CCC_IETF_PROV_SRV,	"TSP's Provisioning Server" },
	{ PKT_CCC_IETF_AS_KRB,		"TSP's AS-REQ/AS-REP Backoff and Retry" },
	{ PKT_CCC_IETF_AP_KRB,		"TSP's AP-REQ/AP-REP Backoff and Retry" },
	{ PKT_CCC_KRB_REALM,		"TSP's Kerberos Realm Name" },
	{ PKT_CCC_TGT_FLAG,		"TSP's Ticket Granting Server Utilization" },
	{ PKT_CCC_PROV_TIMER,		"TSP's Provisioning Timer Value" },
	{ PKT_CCC_IETF_SEC_TKT,		"PacketCable Security Ticket Control" },
	{ 0, NULL },
};

static const value_string pkt_i05_ccc_ticket_ctl_vals[] = {
	{ 1, "Invalidate Provisioning Application Server's ticket" },
	{ 2, "Invalidate all CMS Application Server tickets" },
	{ 3, "Invalidate all Application Server tickets" },
	{ 0, NULL },
};

static int
dissect_packetcable_i05_ccc(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
			    tvbuff_t *tvb, int optoff, int optend)
{
	int	    suboptoff = optoff;
	guint8	    subopt, subopt_len, fetch_tgt, timer_val, ticket_ctl;
	proto_tree *pkt_s_tree;
	proto_item *vti;

	subopt = tvb_get_guint8(tvb, optoff);
	suboptoff++;

	if (suboptoff >= optend) {
		expert_add_info_format(pinfo, v_ti, &ei_bootp_missing_subopt_length,
									"Suboption %d: no room left in option for suboption length", subopt);
		return (optend);
	}

	subopt_len = tvb_get_guint8(tvb, optoff);
	suboptoff++;

	vti = proto_tree_add_uint(v_tree, hf_bootp_pc_i05_ccc_suboption, tvb, optoff, 1, subopt);
	proto_item_set_len(vti, subopt_len + 2);
	proto_item_append_text(vti, ": ");

	switch (subopt) {

	case PKT_CCC_PRI_DHCP:	/* String values */
	case PKT_CCC_SEC_DHCP:
	case PKT_CCC_I05_SNMP:
	case PKT_CCC_I05_PRI_DNS:
	case PKT_CCC_I05_SEC_DNS:
	case PKT_CCC_KRB_REALM:
	case PKT_CCC_CMS_FQDN:
		proto_item_append_text(vti, "%s (%u byte%s)",
				       tvb_format_stringzpad(tvb, suboptoff, subopt_len),
				       subopt_len,
				       plurality(subopt_len, "", "s") );
		suboptoff += subopt_len;
		break;

	case PKT_CCC_TGT_FLAG:
		if (suboptoff+1 > optend) {
			expert_add_info(pinfo, vti, &ei_bootp_missing_subopt_value);
			return (optend);
		}
		fetch_tgt = tvb_get_guint8(tvb, suboptoff);
		proto_item_append_text(vti, "%s (%u byte%s%s)",
				       fetch_tgt ? "Yes" : "No",
				       subopt_len,
				       plurality(subopt_len, "", "s"),
				       subopt_len != 1 ? " [Invalid]" : "");
		suboptoff += subopt_len;
		break;

	case PKT_CCC_PROV_TIMER:
		if (suboptoff+1 > optend) {
			expert_add_info(pinfo, vti, &ei_bootp_missing_subopt_value);
			return (optend);
		}
		timer_val = tvb_get_guint8(tvb, suboptoff);
		proto_item_append_text(vti, "%u%s (%u byte%s%s)", timer_val,
				       timer_val > 30 ? " [Invalid]" : "",
				       subopt_len,
				       plurality(subopt_len, "", "s"),
				       subopt_len != 1 ? " [Invalid]" : "");
		suboptoff += subopt_len;
		break;

	case PKT_CCC_AS_KRB:
		if (suboptoff+12 > optend) {
			expert_add_info(pinfo, vti, &ei_bootp_missing_subopt_value);
			return (optend);
		}
		proto_item_append_text(vti, "(%u byte%s%s)", subopt_len,
				       plurality(subopt_len, "", "s"),
				       subopt_len != 12 ? " [Invalid]" : "");
		if (subopt_len == 12) {
			pkt_s_tree = proto_item_add_subtree(vti, ett_bootp_option);
			proto_tree_add_item(pkt_s_tree, hf_bootp_cl_ietf_ccc_dev_realm_unc_key_nom_timeout, tvb, suboptoff, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(pkt_s_tree, hf_bootp_cl_ietf_ccc_dev_realm_unc_key_max_timeout, tvb, suboptoff + 4, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(pkt_s_tree, hf_bootp_cl_ietf_ccc_dev_realm_unc_key_max_retries, tvb, suboptoff + 8, 4, ENC_BIG_ENDIAN);
		}
		suboptoff += subopt_len;
		break;

	case PKT_CCC_AP_KRB:
		if (suboptoff+12 > optend) {
			expert_add_info(pinfo, vti, &ei_bootp_missing_subopt_value);
			return (optend);
		}
		proto_item_append_text(vti, "(%u byte%s%s)", subopt_len,
				       plurality(subopt_len, "", "s"),
				       subopt_len != 12 ? " [Invalid]" : "");
		if (subopt_len == 12) {
			pkt_s_tree = proto_item_add_subtree(vti, ett_bootp_option);
			proto_tree_add_item(pkt_s_tree, hf_bootp_cl_ietf_ccc_dev_prov_unc_key_nom_timeout, tvb, suboptoff + 8, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(pkt_s_tree, hf_bootp_cl_ietf_ccc_dev_prov_unc_key_max_timeout, tvb, suboptoff + 8, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(pkt_s_tree, hf_bootp_cl_ietf_ccc_dev_prov_unc_key_max_retries, tvb, suboptoff + 8, 4, ENC_BIG_ENDIAN);
		}
		suboptoff += subopt_len;
		break;

	case PKT_CCC_MTA_KRB_CLEAR:
		if (suboptoff+1 > optend) {
			expert_add_info(pinfo, vti, &ei_bootp_missing_subopt_value);
			return (optend);
		}
		ticket_ctl = tvb_get_guint8(tvb, suboptoff);
		proto_item_append_text(vti, "%s (%u) (%u byte%s%s)",
				       val_to_str_const (ticket_ctl, pkt_i05_ccc_ticket_ctl_vals, "unknown/invalid"),
				       ticket_ctl,
				       subopt_len,
				       plurality(subopt_len, "", "s"),
				       subopt_len != 1 ? " [Invalid]" : "");
		suboptoff += subopt_len;
		break;

	default:
		suboptoff += subopt_len;
		break;

	}
	return suboptoff;
}

static int hf_bootp_ccc_ietf_sec_tkt_pc_provision_server = -1;
static int hf_bootp_ccc_ietf_sec_tkt_all_pc_call_management = -1;

static int
dissect_packetcable_ietf_ccc(packet_info *pinfo, proto_item *v_ti, proto_tree *v_tree,
			     tvbuff_t *tvb, int optoff, int optend, int revision)
{
	int	      suboptoff	    = optoff;
	guint8	      subopt, subopt_len;
	guint8	      prov_type, fetch_tgt, timer_val;
	guint16	      sec_tcm;
	proto_tree   *pkt_s_tree;
	proto_item   *vti;
	int	      max_timer_val = 255;
	const guchar *dns_name;

	subopt = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	if (suboptoff >= optend) {
		expert_add_info_format(pinfo, v_ti, &ei_bootp_missing_subopt_length,
									"Suboption %d: no room left in option for suboption length", subopt);
		return (optend);
	}
	subopt_len = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	vti = proto_tree_add_uint(v_tree, hf_bootp_pc_ietf_ccc_suboption, tvb, optoff, 1, subopt);
	proto_item_set_len(vti, subopt_len + 2);
	proto_item_append_text(vti, ": ");

	switch (subopt) {

	case PKT_CCC_PRI_DHCP:	/* IPv4 values */
	case PKT_CCC_SEC_DHCP:
		if (suboptoff+4 > optend) {
			expert_add_info(pinfo, vti, &ei_bootp_missing_subopt_value);
			return (optend);
		}
		proto_item_append_text(vti, "%s (%u byte%s%s)",
				       tvb_ip_to_str(tvb, suboptoff),
				       subopt_len,
				       plurality(subopt_len, "", "s"),
				       subopt_len != 4 ? " [Invalid]" : "");
		suboptoff += subopt_len;
		break;

	case PKT_CCC_IETF_PROV_SRV:
		if (suboptoff+1 > optend) {
			expert_add_info(pinfo, vti, &ei_bootp_missing_subopt_value);
			return (optend);
		}
		prov_type = tvb_get_guint8(tvb, suboptoff);
		suboptoff += 1;
		switch (prov_type) {

		case 0:
			get_dns_name(tvb, suboptoff, subopt_len, suboptoff, &dns_name);
			proto_item_append_text(vti, "%s (%u byte%s)", dns_name,
					       subopt_len - 1, plurality(subopt_len, "", "s") );
			break;

		case 1:
			if (suboptoff+4 > optend) {
				expert_add_info(pinfo, vti, &ei_bootp_missing_subopt_value);
				return (optend);
			}
			proto_item_append_text(vti, "%s (%u byte%s%s)",
					       tvb_ip_to_str(tvb, suboptoff),
					       subopt_len,
					       plurality(subopt_len, "", "s"),
					       subopt_len != 5 ? " [Invalid]" : "");
			break;

		default:
			proto_item_append_text(vti, "Invalid type: %u (%u byte%s)",
					       prov_type,
					       subopt_len,
					       plurality(subopt_len, "", "s") );
			break;
		}
		suboptoff += subopt_len - 1;
		break;

	case PKT_CCC_IETF_AS_KRB:
		if (suboptoff+12 > optend) {
			expert_add_info(pinfo, vti, &ei_bootp_missing_subopt_value);
			return (optend);
		}
		proto_item_append_text(vti, "(%u byte%s%s)", subopt_len,
				       plurality(subopt_len, "", "s"),
				       subopt_len != 12 ? " [Invalid]" : "");
		if (subopt_len == 12) {
			pkt_s_tree = proto_item_add_subtree(vti, ett_bootp_option);
			proto_tree_add_item(pkt_s_tree, hf_bootp_cl_ietf_ccc_dev_realm_unc_key_nom_timeout, tvb, suboptoff, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(pkt_s_tree, hf_bootp_cl_ietf_ccc_dev_realm_unc_key_max_timeout, tvb, suboptoff + 4, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(pkt_s_tree, hf_bootp_cl_ietf_ccc_dev_realm_unc_key_max_retries, tvb, suboptoff + 8, 4, ENC_BIG_ENDIAN);
		}
		suboptoff += subopt_len;
		break;

	case PKT_CCC_IETF_AP_KRB:
		proto_item_append_text(vti, "(%u byte%s%s)", subopt_len,
				       plurality(subopt_len, "", "s"),
				       subopt_len != 12 ? " [Invalid]" : "");
		if (subopt_len == 12) {
			pkt_s_tree = proto_item_add_subtree(vti, ett_bootp_option);
			proto_tree_add_item(pkt_s_tree, hf_bootp_cl_ietf_ccc_dev_prov_unc_key_nom_timeout, tvb, suboptoff, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(pkt_s_tree, hf_bootp_cl_ietf_ccc_dev_prov_unc_key_max_timeout, tvb, suboptoff + 4, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(pkt_s_tree, hf_bootp_cl_ietf_ccc_dev_prov_unc_key_max_retries, tvb, suboptoff + 8, 4, ENC_BIG_ENDIAN);
		}
		suboptoff += subopt_len;
		break;

	case PKT_CCC_KRB_REALM: /* String values */
		get_dns_name(tvb, suboptoff, subopt_len, suboptoff, &dns_name);
		proto_item_append_text(vti, "%s (%u byte%s)", dns_name,
				       subopt_len, plurality(subopt_len, "", "s") );
		suboptoff += subopt_len;
		break;

	case PKT_CCC_TGT_FLAG:
		if (suboptoff+1 > optend) {
			expert_add_info(pinfo, vti, &ei_bootp_missing_subopt_value);
			return (optend);
		}
		fetch_tgt = tvb_get_guint8(tvb, suboptoff);
		proto_item_append_text(vti, "%s (%u byte%s%s)",
				       fetch_tgt ? "Yes" : "No",
				       subopt_len,
				       plurality(subopt_len, "", "s"),
				       subopt_len != 1 ? " [Invalid]" : "");
		suboptoff += 1;
		break;

	case PKT_CCC_PROV_TIMER:
		if (suboptoff+1 > optend) {
			expert_add_info(pinfo, vti, &ei_bootp_missing_subopt_value);
			return (optend);
		}
		if (revision == PACKETCABLE_CCC_DRAFT5)
			max_timer_val = 30;
		timer_val = tvb_get_guint8(tvb, suboptoff);
		proto_item_append_text(vti, "%u%s (%u byte%s%s)", timer_val,
				       timer_val > max_timer_val ? " [Invalid]" : "",
				       subopt_len,
				       plurality(subopt_len, "", "s"),
				       subopt_len != 1 ? " [Invalid]" : "");
		suboptoff += 1;
		break;

	case PKT_CCC_IETF_SEC_TKT:
		if (suboptoff+2 > optend) {
			expert_add_info(pinfo, vti, &ei_bootp_missing_subopt_value);
			return (optend);
		}
		sec_tcm = tvb_get_ntohs(tvb, suboptoff);
		proto_item_append_text(vti, "0x%04x (%u byte%s%s)", sec_tcm, subopt_len,
				       plurality(subopt_len, "", "s"),
				       subopt_len != 2 ? " [Invalid]" : "");
		if (subopt_len == 2) {
			pkt_s_tree = proto_item_add_subtree(vti, ett_bootp_option);
			proto_tree_add_boolean(pkt_s_tree, hf_bootp_ccc_ietf_sec_tkt_pc_provision_server, tvb, suboptoff, 2, sec_tcm);
			proto_tree_add_boolean(pkt_s_tree, hf_bootp_ccc_ietf_sec_tkt_all_pc_call_management, tvb, suboptoff, 2, sec_tcm);
		}
		suboptoff += subopt_len;
		break;

	default:
		suboptoff += subopt_len;
		break;
	}
	return suboptoff;
}

#define BOOTREQUEST	1
#define BOOTREPLY	2

static const value_string op_vals[] = {
	{ BOOTREQUEST,	"Boot Request" },
	{ BOOTREPLY,	"Boot Reply" },
	{ 0,		NULL }
};

static int
dissect_bootp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree   *bp_tree;
	proto_item   *bp_ti, *ti;
	proto_item   *fi, *hidden_item;
	guint8	      op;
	guint8	      htype, hlen;
	int	      voff, eoff, tmpvoff; /* vendor offset, end offset */
	guint32	      ip_addr;
	gboolean      at_end;
	const char   *dhcp_type				     = NULL;
	const guint8 *vendor_class_id			     = NULL;
	guint16	      flags, secs;
	int	      offset_delta;
	guint8	      overload				     = 0; /* DHCP option overload */
	static const int * bootp_flags[] = {
		&hf_bootp_flags_broadcast,
		&hf_bootp_flags_reserved,
		NULL
	};

	rfc3396_dns_domain_search_list.total_number_of_block = 0;
	rfc3396_dns_domain_search_list.tvb_composite	     = NULL;
	rfc3396_sip_server.total_number_of_block	     = 0;
	rfc3396_sip_server.tvb_composite		     = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BOOTP");
	/*
	 * In case we throw an exception fetching the opcode, etc.
	 */
	col_clear(pinfo->cinfo, COL_INFO);

	op = tvb_get_guint8(tvb, 0);
	htype = tvb_get_guint8(tvb, 1);
	hlen = tvb_get_guint8(tvb, 2);
	switch (op) {

	case BOOTREQUEST:
		if ((htype == ARPHRD_ETHER || htype == ARPHRD_IEEE802)
		    && hlen == 6) {
			col_add_fstr(pinfo->cinfo, COL_INFO, "Boot Request from %s (%s)",
				     tvb_arphrdaddr_to_str(tvb, 28, hlen, htype),
				     tvb_get_ether_name(tvb, 28));
		}
		else {
			col_add_fstr(pinfo->cinfo, COL_INFO, "Boot Request from %s",
				     tvb_arphrdaddr_to_str(tvb, 28, hlen, htype));
		}
		break;

	case BOOTREPLY:
		col_set_str(pinfo->cinfo, COL_INFO, "Boot Reply");
		break;

	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown BOOTP message type (%u)", op);
		break;
	}

	voff = VENDOR_INFO_OFFSET;

	/* rfc2132 says it SHOULD exist, not that it MUST exist */
	if (tvb_bytes_exist(tvb, voff, 4) &&
	    (tvb_get_ntohl(tvb, voff) == 0x63825363)) {
		voff += 4;
	} else {
		voff += 64;
	}
	eoff = tvb_reported_length(tvb);

	bp_ti = proto_tree_add_item(tree, proto_bootp, tvb, 0, -1, ENC_NA);
	bp_tree = proto_item_add_subtree(bp_ti, ett_bootp);

	/*
	 * In the first pass, we just look for the DHCP message type
	 * and Vendor class identifier options.
	 */
	tmpvoff = voff;
	at_end = FALSE;
	rfc3396_dns_domain_search_list.index_current_block = 0;
	rfc3396_sip_server.index_current_block = 0;
	while (tmpvoff < eoff && !at_end) {
		offset_delta = bootp_option(tvb, pinfo, NULL, NULL, tmpvoff, eoff, TRUE, &at_end,
		    &dhcp_type, &vendor_class_id, &overload);
		if (offset_delta <= 0) {
			proto_tree_add_expert(bp_tree, pinfo, &ei_bootp_option_parse_err,
					tvb, tmpvoff, eoff);
			return tmpvoff;
		}
		tmpvoff += offset_delta;
	}

	/*
	 * If there was a DHCP message type option, flag this packet
	 * as DHCP.
	 */
	if (dhcp_type != NULL) {
		/*
		 * Yes, this is a DHCP packet, and "dhcp_type" is the
		 * packet type.
		 */
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "DHCP");

		col_add_fstr(pinfo->cinfo, COL_INFO, "DHCP %-8s - Transaction ID 0x%x",
			     dhcp_type, tvb_get_ntohl(tvb, 4));
		tap_queue_packet( bootp_dhcp_tap, pinfo, dhcp_type);
	}

	/*
	 * OK, now populate the protocol tree.
	 */

	proto_tree_add_uint(bp_tree, hf_bootp_type, tvb,
				   0, 1,
				   op);
	proto_tree_add_item(bp_tree, hf_bootp_hw_type, tvb,
					 1, 1, ENC_BIG_ENDIAN);
	proto_tree_add_uint(bp_tree, hf_bootp_hw_len, tvb,
			    2, 1, hlen);
	proto_tree_add_item(bp_tree, hf_bootp_hops, tvb,
			    3, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(bp_tree, hf_bootp_id, tvb,
			    4, 4, ENC_BIG_ENDIAN);
	/*
	 * Windows (98, XP and Vista tested) sends the "secs" value on
	 * the wire formatted as little-endian. See if the LE value
	 * makes sense.
	 */
	secs = tvb_get_letohs(tvb, 8);
	if (secs > 0 && secs <= 0xff) {
		ti = proto_tree_add_uint_format_value(bp_tree, hf_bootp_secs, tvb,
			    8, 2, secs, "%u", secs);
		expert_add_info_format(pinfo, ti, &ei_bootp_secs_le, "Seconds elapsed appears to be encoded as little-endian");
	} else {
		proto_tree_add_item(bp_tree, hf_bootp_secs, tvb,
			    8, 2, ENC_BIG_ENDIAN);
	}
	flags = tvb_get_ntohs(tvb, 10);
	fi = proto_tree_add_bitmask(bp_tree, tvb, 10, hf_bootp_flags,
			       ett_bootp_flags, bootp_flags, ENC_NA);
	proto_item_append_text(fi, " (%s)",
	    (flags & BOOTP_BC) ? "Broadcast" : "Unicast");

	proto_tree_add_item(bp_tree, hf_bootp_ip_client, tvb,
			    12, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(bp_tree, hf_bootp_ip_your, tvb,
			    16, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(bp_tree, hf_bootp_ip_server, tvb,
			    20, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(bp_tree, hf_bootp_ip_relay, tvb,
			    24, 4, ENC_BIG_ENDIAN);

	if (hlen > 0 && hlen <= 16) {
		if ((htype == ARPHRD_ETHER || htype == ARPHRD_IEEE802)
		    && hlen == 6)
			proto_tree_add_item(bp_tree, hf_bootp_hw_ether_addr, tvb, 28, 6, ENC_NA);
		else
			/* The chaddr element is 16 bytes in length,
			   although only the first hlen bytes are used */
			proto_tree_add_bytes_format_value(bp_tree, hf_bootp_hw_addr, tvb, 28, 16,
					   NULL, "%s", tvb_arphrdaddr_to_str(tvb, 28, hlen, htype));
		if ((16 - hlen) > 0)
			proto_tree_add_item(bp_tree, hf_bootp_hw_addr_padding, tvb, 28+hlen, 16-hlen, ENC_NA);
	} else {
		proto_tree_add_expert(bp_tree, pinfo, &ei_bootp_client_address_not_given, tvb, 28, 16);
	}

	if (overload & OPT_OVERLOAD_SNAME) {
		proto_tree_add_expert(bp_tree, pinfo, &ei_bootp_server_name_overloaded_by_dhcp, tvb,
			SERVER_NAME_OFFSET, SERVER_NAME_LEN);
	} else {
		/* The server host name is optional */
		if (tvb_get_guint8(tvb, SERVER_NAME_OFFSET) != '\0') {
			proto_tree_add_item(bp_tree, hf_bootp_server, tvb,
					   SERVER_NAME_OFFSET,
					   SERVER_NAME_LEN, ENC_ASCII|ENC_NA);

		} else {
			proto_tree_add_string_format(bp_tree, hf_bootp_server, tvb,
						   SERVER_NAME_OFFSET,
						   SERVER_NAME_LEN,
						   "", "Server host name not given");
		}
	}

	if (overload & OPT_OVERLOAD_FILE) {
		proto_tree_add_expert(bp_tree, pinfo, &ei_bootp_boot_filename_overloaded_by_dhcp, tvb,
			FILE_NAME_OFFSET, FILE_NAME_LEN);
	} else {
		/* Boot file is optional */
		if (tvb_get_guint8(tvb, FILE_NAME_OFFSET) != '\0') {
			proto_tree_add_item(bp_tree, hf_bootp_file, tvb,
					   FILE_NAME_OFFSET,
					   FILE_NAME_LEN, ENC_ASCII|ENC_NA);
		} else {
			proto_tree_add_string_format(bp_tree, hf_bootp_file, tvb,
						   FILE_NAME_OFFSET,
						   FILE_NAME_LEN,
						   "", "Boot file name not given");
		}
	}

	voff = VENDOR_INFO_OFFSET;
	if (dhcp_type != NULL) {
		hidden_item = proto_tree_add_boolean(bp_tree, hf_bootp_dhcp, tvb, 0, 0, 1);
		PROTO_ITEM_SET_HIDDEN(hidden_item);
	}
	if (tvb_bytes_exist(tvb, voff, 4) &&
	    (tvb_get_ntohl(tvb, voff) == 0x63825363)) {
		ip_addr = tvb_get_ipv4(tvb, voff);
		proto_tree_add_ipv4_format_value(bp_tree, hf_bootp_cookie, tvb,
			voff, 4, ip_addr, "DHCP");
		voff += 4;
	} else {
		proto_tree_add_item(bp_tree, hf_bootp_vendor_specific_options, tvb,
			voff, 64, ENC_NA);
		voff += 64;
	}

	at_end = FALSE;
	rfc3396_dns_domain_search_list.index_current_block = 0;
	rfc3396_sip_server.index_current_block = 0;
	while (voff < eoff && !at_end) {
		offset_delta = bootp_option(tvb, pinfo, bp_tree, bp_ti, voff, eoff, FALSE, &at_end,
		    &dhcp_type, &vendor_class_id, &overload);
		if (offset_delta <= 0) {
			proto_tree_add_expert(bp_tree, pinfo, &ei_bootp_option_parse_err,
					tvb, voff, eoff);
			return voff;
		}
		voff += offset_delta;
	}
	if ((dhcp_type != NULL) && (!at_end))
	{
		expert_add_info(pinfo, bp_ti, &ei_bootp_end_option_missing);
	}
	if (voff < eoff) {
		/*
		 * Padding after the end option.
		 */
		proto_tree_add_item(bp_tree, hf_bootp_option_padding, tvb, voff, eoff - voff, ENC_NA);
	}

	return tvb_captured_length(tvb);
}

static void
bootp_init_protocol(void)
{
	guint i;

	/* first copy default_bootp_opt[] to bootp_opt[].  This resets all values to default */
	memcpy(bootp_opt, default_bootp_opt, sizeof(bootp_opt));

	/* Now apply the custom options */
	for (i = 0; i < num_bootp_records_uat; i++)
	{
		bootp_opt[uat_bootp_records[i].opt].text = wmem_strdup(wmem_file_scope(), uat_bootp_records[i].text);
		bootp_opt[uat_bootp_records[i].opt].ftype = uat_bootp_records[i].ftype;
		bootp_opt[uat_bootp_records[i].opt].phf = NULL;
	}
}

/* TAP STAT INFO */
typedef enum
{
	MESSAGE_TYPE_COLUMN = 0,
	PACKET_COLUMN
} bootp_stat_columns;

static stat_tap_table_item bootp_stat_fields[] = {{TABLE_ITEM_STRING, TAP_ALIGN_LEFT, "DHCP Message Type", "%-25s"}, {TABLE_ITEM_UINT, TAP_ALIGN_RIGHT, "Packets", "%d"}};

static void bootp_stat_init(stat_tap_table_ui* new_stat, new_stat_tap_gui_init_cb gui_callback, void* gui_data)
{
	int num_fields = sizeof(bootp_stat_fields)/sizeof(stat_tap_table_item);
	stat_tap_table* table = new_stat_tap_init_table("DHCP Statistics", num_fields, 0, NULL, gui_callback, gui_data);
	int i = 0;
	stat_tap_table_item_type items[sizeof(bootp_stat_fields)/sizeof(stat_tap_table_item)];

	new_stat_tap_add_table(new_stat, table);

	/* Add a row for each value type */
	while (opt53_text[i].strptr)
	{
		items[MESSAGE_TYPE_COLUMN].type = TABLE_ITEM_STRING;
		items[MESSAGE_TYPE_COLUMN].value.string_value = opt53_text[i].strptr;
		items[PACKET_COLUMN].type = TABLE_ITEM_UINT;
		items[PACKET_COLUMN].value.uint_value = 0;

		new_stat_tap_init_table_row(table, i, num_fields, items);
		i++;
	}
}

static gboolean
bootp_stat_packet(void *tapdata, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *data)
{
	new_stat_data_t* stat_data = (new_stat_data_t*)tapdata;
	const char* value = (const char*)data;
	stat_tap_table* table;
	stat_tap_table_item_type* msg_data;
	guint i = 0;
	gint idx;

	idx = str_to_val_idx(value, opt53_text);
	if (idx < 0)
		return FALSE;

	table = g_array_index(stat_data->stat_tap_data->tables, stat_tap_table*, i);
	msg_data = new_stat_tap_get_field_data(table, idx, PACKET_COLUMN);
	msg_data->value.uint_value++;
	new_stat_tap_set_field_data(table, idx, PACKET_COLUMN, msg_data);

	return TRUE;
}

static void
bootp_stat_reset(stat_tap_table* table)
{
	guint element;
	stat_tap_table_item_type* item_data;

	for (element = 0; element < table->num_elements; element++)
	{
		item_data = new_stat_tap_get_field_data(table, element, PACKET_COLUMN);
		item_data->value.uint_value = 0;
		new_stat_tap_set_field_data(table, element, PACKET_COLUMN, item_data);
	}
}

void
proto_register_bootp(void)
{
	static const value_string bootp_custom_type_vals[] = {
		{ ipv4,		    "IP Address"},
		{ ipv4_list,	    "IP Address List" },
		{ string,	    "string" },
		{ bytes,	    "bytes" },
		{ val_boolean,	    "boolean" },
		{ val_u_byte,	    "byte" },
		{ val_u_short,	    "unsigned short" },
		{ val_u_short_list, "unsigned short list" },
		{ val_u_long,	    "unsigned long" },
		{ time_in_s_secs,   "integer time in seconds" },
		{ time_in_u_secs,   "unsigned integer time in seconds" },
		{ 0x00, NULL }
	};

	static hf_register_info hf[] = {
		{ &hf_bootp_dhcp,
		  { "Frame is DHCP", "bootp.dhcp",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_type,
		  { "Message type", "bootp.type",
		    FT_UINT8, BASE_DEC, VALS(op_vals), 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_hw_type,
		  { "Hardware type", "bootp.hw.type",
		    FT_UINT8, BASE_HEX, VALS(arp_hrd_vals), 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_hw_len,
		  { "Hardware address length", "bootp.hw.len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_hops,
		  { "Hops", "bootp.hops",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_id,
		  { "Transaction ID", "bootp.id",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_secs,
		  { "Seconds elapsed", "bootp.secs",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_flags,
		  { "Bootp flags", "bootp.flags",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_flags_broadcast,
		  { "Broadcast flag", "bootp.flags.bc",
		    FT_BOOLEAN, 16, TFS(&flag_set_broadcast), BOOTP_BC,
		    NULL, HFILL }},

		{ &hf_bootp_flags_reserved,
		  { "Reserved flags", "bootp.flags.reserved",
		    FT_UINT16, BASE_HEX, NULL, BOOTP_MBZ,
		    NULL, HFILL }},

		{ &hf_bootp_ip_client,
		  { "Client IP address", "bootp.ip.client",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_ip_your,
		  { "Your (client) IP address", "bootp.ip.your",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_ip_server,
		  { "Next server IP address", "bootp.ip.server",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_ip_relay,
		  { "Relay agent IP address", "bootp.ip.relay",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_hw_addr,
		  { "Client hardware address", "bootp.hw.addr",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_hw_addr_padding,
		  { "Client hardware address padding", "bootp.hw.addr_padding",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_hw_ether_addr,
		  { "Client MAC address", "bootp.hw.mac_addr",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_server,
		  { "Server host name", "bootp.server",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_file,
		  { "Boot file name", "bootp.file",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_cookie,
		  { "Magic cookie", "bootp.cookie",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_vendor_specific_options,
		  { "Bootp vendor specific options", "bootp.vendor_specific_options",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_fqdn_s,
		  { "Server", "bootp.fqdn.s",
		    FT_BOOLEAN, 8, TFS(&tfs_fqdn_s), F_FQDN_S,
		    "If true, server should do DDNS update", HFILL }},

		{ &hf_bootp_fqdn_o,
		  { "Server overrides", "bootp.fqdn.o",
		    FT_BOOLEAN, 8, TFS(&tfs_fqdn_o), F_FQDN_O,
		    "If true, server insists on doing DDNS update", HFILL }},

		{ &hf_bootp_fqdn_e,
		  { "Encoding", "bootp.fqdn.e",
		    FT_BOOLEAN, 8, TFS(&tfs_fqdn_e), F_FQDN_E,
		    "If true, name is binary encoded", HFILL }},

		{ &hf_bootp_fqdn_n,
		  { "Server DDNS", "bootp.fqdn.n",
		    FT_BOOLEAN, 8, TFS(&tfs_fqdn_n), F_FQDN_N,
		    "If true, server should not do any DDNS updates", HFILL }},

		{ &hf_bootp_fqdn_flags,
		  { "Flags", "bootp.fqdn.flags",
		    FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }},

		{ &hf_bootp_fqdn_mbz,
		  { "Reserved flags", "bootp.fqdn.mbz",
		    FT_UINT8, BASE_HEX, NULL, F_FQDN_MBZ,
		    NULL, HFILL }},

		{ &hf_bootp_fqdn_rcode1,
		  { "A-RR result", "bootp.fqdn.rcode1",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Result code of A-RR update", HFILL }},

		{ &hf_bootp_fqdn_rcode2,
		  { "PTR-RR result", "bootp.fqdn.rcode2",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Result code of PTR-RR update", HFILL }},

		{ &hf_bootp_fqdn_name,
		  { "Client name", "bootp.fqdn.name",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Name to register via DDNS", HFILL }},

		{ &hf_bootp_fqdn_asciiname,
		  { "Client name", "bootp.fqdn.name",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Name to register via DDNS", HFILL }},

		{ &hf_bootp_pkt_mta_cap_len,
		  { "MTA DC Length", "bootp.vendor.pktc.mta_cap_len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "PacketCable MTA Device Capabilities Length", HFILL }},

		{ &hf_bootp_pkt_mta_cap_type,
		  { "Type", "bootp.vendor.pktc.mta_cap_type",
		    FT_UINT8, BASE_DEC, VALS(pkt_mdc_type_vals), 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_pkt_mdc_supp_flow_secure,
		  { "Secure Flow (Full Secure Provisioning Flow)", "bootp.vendor.pktc.mdc.supp_flow.secure",
		    FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x01,
		    NULL, HFILL }},

		{ &hf_bootp_pkt_mdc_supp_flow_hybrid,
		  { "Hybrid Flow", "bootp.vendor.pktc.mdc.supp_flow.hybrid",
		    FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x02,
		    NULL, HFILL }},

		{ &hf_bootp_pkt_mdc_supp_flow_basic,
		  { "Basic Flow", "bootp.vendor.pktc.mdc.supp_flow.basic",
		    FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x04,
		    NULL, HFILL }},

		{ &hf_bootp_pkt_mdc_mib_cl_mta,
		  { "PacketCable 1.5 MTA MIB", "bootp.vendor.pktc.mdc_cl.mib.mta",
		    FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
		    NULL, HFILL }},

		{ &hf_bootp_pkt_mdc_mib_cl_signaling,
		  { "PacketCable 1.5 Signaling MIB", "bootp.vendor.pktc.mdc_cl.mib.signaling",
		    FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
		    NULL, HFILL }},

		{ &hf_bootp_pkt_mdc_mib_cl_management_event,
		  { "PacketCable 1.5 Management Event MIB", "bootp.vendor.pktc.mdc_cl.mib.management_event",
		    FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
		    NULL, HFILL }},

		{ &hf_bootp_pkt_mdc_mib_cl_mta_extension,
		  { "PacketCable 1.5 MTA Extension MIB", "bootp.vendor.pktc.mdc_cl.mib.mta_extension",
		    FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x08,
		    NULL, HFILL }},

		{ &hf_bootp_pkt_mdc_mib_cl_mta_signaling_extension,
		  { "PacketCable 1.5 Signaling Extension MIB", "bootp.vendor.pktc.mdc_cl.mib.signaling_extension",
		    FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x10,
		    NULL, HFILL }},

		{ &hf_bootp_pkt_mdc_mib_cl_mta_mem_extention,
		  { "PacketCable 1.5 MEM Extension MIB", "bootp.vendor.pktc.mdc_cl.mib.mem_extention",
		    FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x20,
		    NULL, HFILL }},

		{ &hf_bootp_pkt_mdc_mib_cl_reserved,
		  { "Reserved", "bootp.vendor.pktc.mdc_cl.mib.reserved",
		    FT_UINT8, BASE_HEX, NULL, 0xC0,
		    NULL, HFILL }},

		{ &hf_bootp_pkt_mdc_mib_ietf_mta,
		  { "IETF MTA MIB", "bootp.vendor.pktc.mdc_ietf.mib.mta",
		    FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
		    NULL, HFILL }},

		{ &hf_bootp_pkt_mdc_mib_ietf_signaling,
		  { "IETF Signaling MIB", "bootp.vendor.pktc.mdc_ietf.mib.signaling",
		    FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
		    NULL, HFILL }},

		{ &hf_bootp_pkt_mdc_mib_ietf_management_event,
		  { "IETF Management Event MIB", "bootp.vendor.pktc.mdc_ietf.mib.management_event",
		    FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
		    NULL, HFILL }},

		{ &hf_bootp_pkt_mdc_mib_ietf_reserved,
		  { "Reserved", "bootp.vendor.pktc.mdc_ietf.mib.reserved",
		    FT_UINT8, BASE_HEX, NULL, 0xF8,
		    NULL, HFILL }},

		{ &hf_bootp_pkt_mdc_mib_euro_mta,
		  { "PacketCable 1.5 MTA MIB", "bootp.vendor.pktc.mdc_euro.mib.mta",
		    FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
		    NULL, HFILL }},

		{ &hf_bootp_pkt_mdc_mib_euro_signaling,
		  { "PacketCable 1.5 Signaling MIB", "bootp.vendor.pktc.mdc_euro.mib.signaling",
		    FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x02,
		    NULL, HFILL }},

		{ &hf_bootp_pkt_mdc_mib_euro_management_event,
		  { "PacketCable 1.5 Management Event MIB", "bootp.vendor.pktc.mdc_euro.mib.management_event",
		    FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04,
		    NULL, HFILL }},

		{ &hf_bootp_pkt_mdc_mib_euro_mta_extension,
		  { "PacketCable 1.5 MTA Extension MIB", "bootp.vendor.pktc.mdc_euro.mib.mta_extension",
		    FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x08,
		    NULL, HFILL }},

		{ &hf_bootp_pkt_mdc_mib_euro_mta_signaling_extension,
		  { "PacketCable 1.5 Signaling Extension MIB", "bootp.vendor.pktc.mdc_euro.mib.signaling_extension",
		    FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x10,
		    NULL, HFILL }},

		{ &hf_bootp_pkt_mdc_mib_euro_mta_mem_extention,
		  { "PacketCable 1.5 MEM Extension MIB", "bootp.vendor.pktc.mdc_euro.mib.mem_extention",
		    FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x20,
		    NULL, HFILL }},

		{ &hf_bootp_pkt_mdc_mib_euro_reserved,
		  { "Reserved", "bootp.vendor.pktc.mdc_euro.mib.reserved",
		    FT_UINT8, BASE_HEX, NULL, 0xC0,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_len,
		  { "CM DC Length", "bootp.vendor.docsis.cm_cap_len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "DOCSIS Cable Modem Device Capabilities Length", HFILL }},

		{ &hf_bootp_docsis_cm_cap_type,
		  { "CM DC Type", "bootp.docsis_cm_cap_type",
		    FT_UINT16, BASE_DEC, VALS(docsis_cm_cap_type_vals), 0x0,
		    "Docsis Cable Modem Device Capability type", HFILL }},

		{ &hf_bootp_docsis_cm_cap_ranging_hold_off_cm,
		  { "CM", "bootp.docsis_cm_cap.ranging_hold_off.cm",
		    FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x01,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_ranging_hold_off_eps,
		  { "ePS or eRouter", "bootp.docsis_cm_cap.ranging_hold_off.eps",
		    FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x02,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_ranging_hold_off_emta,
		  { "EMTA or EDVA", "bootp.docsis_cm_cap.ranging_hold_off.emta",
		    FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x04,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_ranging_hold_off_dsg,
		  { "DSG/eSTB", "bootp.docsis_cm_cap.ranging_hold_off.dsg",
		    FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x08,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_stpid,
		  { "[IEEE 802.1ad] S-TPID", "bootp.docsis_cm_cap.mpls.stpid",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x01,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_svid,
		  { "[IEEE 802.1ad] S-VID", "bootp.docsis_cm_cap.mpls.svid",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x02,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_spcp,
		  { "[IEEE 802.1ad] S-PCP", "bootp.docsis_cm_cap.mpls.spcp",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x04,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_sdei,
		  { "[IEEE 802.1ad] S-DEI", "bootp.docsis_cm_cap.mpls.sdei",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x08,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_ctpid,
		  { "[IEEE 802.1ad] C-TPID", "bootp.docsis_cm_cap.mpls.ctpid",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x10,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_cvid,
		  { "[IEEE 802.1ad] C-VID", "bootp.docsis_cm_cap.mpls.cvid",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x20,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_cpcp,
		  { "[IEEE 802.1ad] C-PCP", "bootp.docsis_cm_cap.mpls.cpcp",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x40,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_ccfi,
		  { "[IEEE 802.1ad] C-CFI", "bootp.docsis_cm_cap.mpls.ccfi",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x80,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_stci,
		  { "[IEEE 802.1ad] S-TCI", "bootp.docsis_cm_cap.mpls.stci",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x100,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_ctci,
		  { "[IEEE 802.1ad] C-TCI", "bootp.docsis_cm_cap.mpls.ctci",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x200,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_itpid,
		  { "[IEEE 802.1ad] I-TPID", "bootp.docsis_cm_cap.mpls.itpid",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x400,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_isid,
		  { "[IEEE 802.1ad] I-SID", "bootp.docsis_cm_cap.mpls.isid",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x800,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_itci,
		  { "[IEEE 802.1ad] I-TCI", "bootp.docsis_cm_cap.mpls.itci",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x1000,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_ipcp,
		  { "[IEEE 802.1ad] I-PCP", "bootp.docsis_cm_cap.mpls.ipcp",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x2000,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_idei,
		  { "[IEEE 802.1ad] I-DEI", "bootp.docsis_cm_cap.mpls.idei",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x4000,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_iuca,
		  { "[IEEE 802.1ad] I-UCA", "bootp.docsis_cm_cap.mpls.iuca",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x8000,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_btpid,
		  { "[IEEE 802.1ad] B-TPID", "bootp.docsis_cm_cap.mpls.btpid",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x10000,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_btci,
		  { "[IEEE 802.1ad] B-TCI", "bootp.docsis_cm_cap.mpls.btci",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x20000,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_bpcp,
		  { "[IEEE 802.1ad] B-PCP", "bootp.docsis_cm_cap.mpls.bpcp",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x40000,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_bdei,
		  { "[IEEE 802.1ad] B-DEI", "bootp.docsis_cm_cap.mpls.bdei",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x80000,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_bvid,
		  { "[IEEE 802.1ad] B-VID", "bootp.docsis_cm_cap.mpls.bvid",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x100000,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_bda,
		  { "[IEEE 802.1ad] B-DA", "bootp.docsis_cm_cap.mpls.bda",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x200000,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_bsa,
		  { "[IEEE 802.1ad] B-SA", "bootp.docsis_cm_cap.mpls.bsa",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x200000,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_tc,
		  { "MPLS TC", "bootp.docsis_cm_cap.mpls.tc",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x200000,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_mpls_label,
		  { "MPLS Label", "bootp.docsis_cm_cap.mpls.label",
		    FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x200000,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_ussymrate_160,
		  { "160 ksps symbol rate", "bootp.docsis_cm_cap.ussymrate.160",
		    FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_ussymrate_320,
		  { "320 ksps symbol rate", "bootp.docsis_cm_cap.ussymrate.320",
		    FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_ussymrate_640,
		  { "640 ksps symbol rate", "bootp.docsis_cm_cap.ussymrate.640",
		    FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_ussymrate_1280,
		  { "1280 ksps symbol rate", "bootp.docsis_cm_cap.ussymrate.1280",
		    FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_ussymrate_2560,
		  { "2560 ksps symbol rate", "bootp.docsis_cm_cap.ussymrate.2560",
		    FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
		    NULL, HFILL }},

		{ &hf_bootp_docsis_cm_cap_ussymrate_5120,
		  { "5120 ksps symbol rate", "bootp.docsis_cm_cap.ussymrate.5120",
		    FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
		    NULL, HFILL }},

		{ &hf_bootp_client_identifier_uuid,
		  { "Client Identifier (UUID)", "bootp.client_id.uuid",
		    FT_GUID, BASE_NONE, NULL, 0x0,
		    "Client Machine Identifier (UUID)", HFILL }},

		{ &hf_bootp_client_hardware_address,
		  { "Client hardware address", "bootp.client_hardware_address",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_client_id_iaid,
		  { "IAID", "bootp.client_id.iaid",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_client_id_duid_type,
		  { "DUID Type", "bootp.client_id.duid_type",
		    FT_UINT16, BASE_DEC, VALS(duidtype_vals), 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_client_identifier_duid_llt_hw_type,
		  { "Hardware type", "bootp.client_id.duid_llt_hw_type",
		    FT_UINT16, BASE_DEC, VALS(arp_hrd_vals), 0x0,
		    "Client Identifier DUID LLT Hardware type", HFILL }},

		{ &hf_bootp_client_identifier_duid_ll_hw_type,
		  { "Hardware type", "bootp.client_id.duid_ll_hw_type",
		    FT_UINT16, BASE_DEC, VALS(arp_hrd_vals), 0x0,
		    "Client Identifier DUID LL Hardware type", HFILL }},

		{ &hf_bootp_client_identifier_time,
		  { "Time", "bootp.client_id.time",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_client_identifier_link_layer_address,
		  { "Link layer address", "bootp.client_id.link_layer_address",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_client_identifier_enterprise_num,
		  { "Enterprise-number", "bootp.client_id.enterprise_num",
		    FT_UINT32, BASE_DEC|BASE_EXT_STRING, &sminmpec_values_ext, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_client_identifier,
		  { "Identifier", "bootp.client_id",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_client_identifier_type,
		  { "Type", "bootp.client_id.type",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_client_identifier_undef,
		  { "Client Identifier", "bootp.client_id.undef",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_option_type,
		  { "Option", "bootp.option.type",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Bootp/Dhcp option type", HFILL }},

		{ &hf_bootp_option_length,
		  { "Length", "bootp.option.length",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Bootp/Dhcp option length", HFILL }},

		{ &hf_bootp_suboption_length,
		  { "Length", "bootp.option.suboption_length",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Suboption length", HFILL }},

		{ &hf_bootp_option_value,
		  { "Value", "bootp.option.value",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Bootp/Dhcp option value", HFILL }},

		{ &hf_bootp_option_value_8,
		  { "Value", "bootp.option.value.uint",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "8-bit Bootp/Dhcp option value", HFILL }},

		{ &hf_bootp_option_value_16,
		  { "Value", "bootp.option.value.uint",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "16-bit Bootp/Dhcp option value", HFILL }},

		{ &hf_bootp_option_value_u32,
		  { "Value", "bootp.option.value.uint",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "32-bit Bootp/Dhcp option value", HFILL }},

		{ &hf_bootp_option_value_i32,
		  { "Value", "bootp.option.value.int",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    "32-bit Bootp/Dhcp option value", HFILL }},

		{ &hf_bootp_option_value_stringz,
		  { "Value", "bootp.option.value.string",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Z-String Bootp/Dhcp option value", HFILL }},

		{ &hf_bootp_option_value_ip_address,
		  { "Value", "bootp.option.value.address",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "IP address Bootp/Dhcp option value", HFILL }},

		{ &hf_bootp_option_value_boolean,
		  { "Value", "bootp.option.value.bool",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_true_false), 0x00,
		    "Boolean Bootp/Dhcp option value", HFILL }},

		{ &hf_bootp_option_padding,
		  { "Padding", "bootp.option.padding",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 0: Padding", HFILL }},

		{ &hf_bootp_option_subnet_mask,
		  { "Subnet Mask", "bootp.option.subnet_mask",
		    FT_IPv4, BASE_NETMASK, NULL, 0x00,
		    "Option 1: Subnet Mask", HFILL }},

		{ &hf_bootp_option_time_offset,
		  { "Time Offset", "bootp.option.time_offset",
		    FT_INT32, BASE_DEC, NULL, 0x00,
		    "Option 2: Time Offset", HFILL }},

		{ &hf_bootp_option_router,
		  { "Router", "bootp.option.router",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 3: Router", HFILL }},

		{ &hf_bootp_option_time_server,
		  { "Time Server", "bootp.option.time_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 4: Time Server", HFILL }},

		{ &hf_bootp_option_name_server,
		  { "Name Server", "bootp.option.name_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 5: Name Server", HFILL }},

		{ &hf_bootp_option_domain_name_server,
		  { "Domain Name Server", "bootp.option.domain_name_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 6: Domain Name Server", HFILL }},

		{ &hf_bootp_option_log_server,
		  { "Log Server", "bootp.option.log_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 7: Log Server", HFILL }},

		{ &hf_bootp_option_quotes_server,
		  { "Quotes Server", "bootp.option.quotes_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 8: Quotes Server", HFILL }},

		{ &hf_bootp_option_lpr_server,
		  { "LPR Server", "bootp.option.lpr_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 9: LPR Server", HFILL }},

		{ &hf_bootp_option_impress_server,
		  { "Impress Server", "bootp.option.impress_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 10: Impress Server", HFILL }},

		{ &hf_bootp_option_resource_location_server,
		  { "Resource Location Server", "bootp.option.resource_location_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 11: Resource Location Server", HFILL }},

		{ &hf_bootp_option_hostname,
		  { "Host Name", "bootp.option.hostname",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 12: Host Name", HFILL }},

		{ &hf_bootp_option_boot_file_size,
		  { "Boot File Size", "bootp.option.boot_file_size",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Option 13: Boot File Size", HFILL }},

		{ &hf_bootp_option_merit_dump_file,
		  { "Merit Dump File", "bootp.option.merit_dump_file",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 14: Merit Dump File", HFILL }},

		{ &hf_bootp_option_domain_name,
		  { "Domain Name", "bootp.option.domain_name",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 15: Domain Name", HFILL }},

		{ &hf_bootp_option_swap_server,
		  { "Swap Server", "bootp.option.swap_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 16: Swap Server", HFILL }},

		{ &hf_bootp_option_root_path,
		  { "Root Path", "bootp.option.root_path",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 17: Root Path", HFILL }},

		{ &hf_bootp_option_extension_path,
		  { "Extensions Path", "bootp.option.extension_path",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 18: Extensions Path", HFILL }},

		{ &hf_bootp_option_ip_forwarding,
		  { "IP Forwarding", "bootp.option.ip_forwarding",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_enabled_disabled), 0x00,
		    "Option 19: IP Forwarding", HFILL }},

		{ &hf_bootp_option_policy_filter_ip,
		  { "IP Address", "bootp.option.policy_filter.ip",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 21: IP address", HFILL }},

		{ &hf_bootp_option_policy_filter_subnet_mask,
		  { "Subnet Mask", "bootp.option.policy_filter.subnet_mask",
		    FT_IPv4, BASE_NETMASK, NULL, 0x00,
		    "Option 21: Subnet Mask", HFILL }},

		{ &hf_bootp_option_non_local_source_routing,
		  { "Non-Local Source Routing", "bootp.option.non_local_source_routing",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_enabled_disabled), 0x00,
		    "Option 20: Non-Local Source Routing", HFILL }},

		{ &hf_bootp_option_max_datagram_reassembly_size,
		  { "Maximum Datagram Reassembly Size", "bootp.option.max_datagram_reassembly_size",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Option 22: Maximum Datagram Reassembly Size", HFILL }},

		{ &hf_bootp_option_default_ip_ttl,
		  { "Default IP Time-to-Live", "bootp.option.default_ip_ttl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 23: Default IP Time-to-Live", HFILL }},

		{ &hf_bootp_option_path_mtu_aging_timeout,
		  { "Path MTU Aging Timeout", "bootp.option.path_mtu_aging_timeout",
		    FT_UINT32, BASE_DEC, NULL, 0x00,
		    "Option 24: Path MTU Aging Timeout", HFILL }},

		{ &hf_bootp_option_path_mtu_plateau_table_item,
		  { "Path MTU Plateau Table Item", "bootp.option.path_mtu_plateau_table_item",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Option 25: Path MTU Plateau Table Item", HFILL }},

		{ &hf_bootp_option_interface_mtu,
		  { "Interface MTU", "bootp.option.interface_mtu",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Option 26: Interface MTU", HFILL }},

		{ &hf_bootp_option_all_subnets_are_local,
		  { "All Subnets are Local", "bootp.option.all_subnets_are_local",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x00,
		    "Option 27: All Subnets are Local", HFILL }},

		{ &hf_bootp_option_broadcast_address,
		  { "Broadcast Address", "bootp.option.broadcast_address",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 28: Broadcast Address", HFILL }},

		{ &hf_bootp_option_perform_mask_discovery,
		  { "Perform Mask Discovery", "bootp.option.perform_mask_discovery",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_enabled_disabled), 0x00,
		    "Option 29: Perform Mask Discovery", HFILL }},

		{ &hf_bootp_option_mask_supplier,
		  { "Mask Supplier", "bootp.option.mask_supplier",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x00,
		    "Option 30: Mask Supplier", HFILL }},

		{ &hf_bootp_option_perform_router_discover,
		  { "Perform Router Discover", "bootp.option.perform_router_discover",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_enabled_disabled), 0x00,
		    "Option 31: Perform Router Discover", HFILL }},

		{ &hf_bootp_option_router_solicitation_address,
		  { "Router Solicitation Address", "bootp.option.router_solicitation_address",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 32: Router Solicitation Address", HFILL }},

		{ &hf_bootp_option_static_route_ip,
		  { "Destination IP Address", "bootp.option.static_route.ip",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 33: Destination IP address", HFILL }},

		{ &hf_bootp_option_static_route_router,
		  { "Destination Router", "bootp.option.static_route.router",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 33: Destination Router", HFILL }},

		{ &hf_bootp_option_trailer_encapsulation,
		  { "Trailer Encapsulation", "bootp.option.trailer_encapsulation",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_enabled_disabled), 0x00,
		    "Option 34: Trailer Encapsulation", HFILL }},

		{ &hf_bootp_option_arp_cache_timeout,
		  { "ARP Cache Timeout", "bootp.option.arp_cache_timeout",
		    FT_UINT32, BASE_DEC, NULL, 0x00,
		    "Option 35: ARP Cache Timeout", HFILL }},

		{ &hf_bootp_option_ethernet_encapsulation,
		  { "Ethernet Encapsulation", "bootp.option.ethernet_encapsulation",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_enabled_disabled), 0x00,
		    "Option 36: Ethernet Encapsulation", HFILL }},

		{ &hf_bootp_option_tcp_default_ttl,
		  { "TCP Default TTL", "bootp.option.tcp_default_ttl",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 37: TCP Default TTL", HFILL }},

		{ &hf_bootp_option_tcp_keepalive_interval,
		  { "TCP Keepalive Interval", "bootp.option.tcp_keepalive_interval",
		    FT_UINT32, BASE_DEC, NULL, 0x00,
		    "Option 38: TCP Keepalive Interval", HFILL }},

		{ &hf_bootp_option_tcp_keepalive_garbage,
		  { "TCP Keepalive Garbage", "bootp.option.tcp_keepalive_garbage",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_enabled_disabled), 0x00,
		    "Option 39: TCP Keepalive Garbage", HFILL }},

		{ &hf_bootp_option_nis_domain,
		  { "Network Information Service Domain", "bootp.option.nis_domain",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 40: Network Information Service Domain", HFILL }},

		{ &hf_bootp_option_nis_server,
		  { "Network Information Service Server", "bootp.option.nis_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 41: Network Information Service Server", HFILL }},

		{ &hf_bootp_option_ntp_server,
		  { "Network Time Protocol Server", "bootp.option.ntp_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 42: Network Time Protocol Server", HFILL }},


		{ &hf_bootp_option43_value,
		  { "Value", "bootp.option.vendor.value",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 43: Suboption value", HFILL }},

		{ &hf_bootp_option43_value_8,
		  { "Value", "bootp.option.vendor.value.uint",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 43: Suboption 8-bit value", HFILL }},

		{ &hf_bootp_option43_value_32,
		  { "Value", "bootp.option.vendor.value.uint",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Option 43: Suboption 32-bit value", HFILL }},

		{ &hf_bootp_option43_value_stringz,
		  { "Value", "bootp.option.vendor.value.string",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 43: Suboption Z-String value", HFILL }},

		{ &hf_bootp_option43_value_ip_address,
		  { "Value", "bootp.option.vendor.value.address",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 43: Suboption IP address", HFILL }},


		{ &hf_bootp_option43_pxeclient_suboption,
		  { "Option 43 Suboption", "bootp.option.vendor.pxeclient.suboption",
		    FT_UINT8, BASE_DEC, VALS(option43_pxeclient_suboption_vals), 0x0,
		    "Option 43:PXE Client Suboption", HFILL }},

		{ &hf_bootp_option43_pxeclient_padding,
		  { "Padding", "bootp.option.vendor.pxeclient.padding",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 43:PXE Client 0 Padding", HFILL }},

		{ &hf_bootp_option43_pxeclient_mtftp_ip,
		  { "mtftp IP", "bootp.option.vendor.pxeclient.mtftp_ip",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 43:PXE Client 1 mtftp IP", HFILL }},

		{ &hf_bootp_option43_pxeclient_mtftp_client_port,
		  { "mtftp IP", "bootp.option.vendor.pxeclient.mtftp_client_port",
		    FT_UINT16, BASE_DEC, NULL, 0x00,
		    "Option 43:PXE Client 2 mtftp client port", HFILL }},

		{ &hf_bootp_option43_pxeclient_mtftp_server_port,
		  { "mtftp IP", "bootp.option.vendor.pxeclient.mtftp_server_port",
		    FT_UINT16, BASE_DEC, NULL, 0x00,
		    "Option 43:PXE Client 3 mtftp server port", HFILL }},

		{ &hf_bootp_option43_pxeclient_mtftp_timeout,
		  { "mtftp timeout", "bootp.option.vendor.pxeclient.mtftp_timeout",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 43:PXE Client 4 mtftp timeout", HFILL }},

		{ &hf_bootp_option43_pxeclient_mtftp_delay,
		  { "mtftp delay", "bootp.option.vendor.pxeclient.mtftp_delay",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 43:PXE Client 5 mtftp delay", HFILL }},

		{ &hf_bootp_option43_pxeclient_discovery_control,
		  { "discovery control", "bootp.option.vendor.pxeclient.discovery_control",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    "Option 43:PXE Client 6 discovery control", HFILL }},

		{ &hf_bootp_option43_pxeclient_multicast_address,
		  { "multicast address", "bootp.option.vendor.pxeclient.multicast_address",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 43:PXE Client 7 multicast address", HFILL }},

		{ &hf_bootp_option43_pxeclient_boot_servers,
		  { "boot servers", "bootp.option.vendor.pxeclient.boot_servers",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 43:PXE Client 8 boot servers", HFILL }},

		{ &hf_bootp_option43_pxeclient_boot_menu,
		  { "boot menu", "bootp.option.vendor.pxeclient.boot_menu",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 43:PXE Client 9 boot menu", HFILL }},

		{ &hf_bootp_option43_pxeclient_menu_prompt,
		  { "menu prompt", "bootp.option.vendor.pxeclient.menu_prompt",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 43:PXE Client 10 menu prompt", HFILL }},

		{ &hf_bootp_option43_pxeclient_multicast_address_alloc,
		  { "multicast address alloc", "bootp.option.vendor.pxeclient.multicast_address_alloc",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 43:PXE Client 11 multicast address alloc", HFILL }},

		{ &hf_bootp_option43_pxeclient_credential_types,
		  { "credential types", "bootp.option.vendor.pxeclient.credential_types",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 43:PXE Client 12 credential types", HFILL }},

		{ &hf_bootp_option43_pxeclient_boot_item,
		  { "boot item", "bootp.option.vendor.pxeclient.boot_item",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 43:PXE Client 71 boot item", HFILL }},

		{ &hf_bootp_option43_pxeclient_end,
		  { "PXE Client End", "bootp.option.vendor.pxeclient.end",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 43:PXE Client 255 End", HFILL }},


		{ &hf_bootp_option43_cl_suboption,
		  { "Option 43 Suboption", "bootp.option.vendor.cl.suboption",
		    FT_UINT8, BASE_DEC, VALS(option43_cl_suboption_vals), 0x0,
		    "Option 43:CL Suboption", HFILL }},

		{ &hf_bootp_option43_cl_padding,
		  { "Padding", "bootp.option.vendor.cl.padding",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 43:CL 0 Padding", HFILL }},

		{ &hf_bootp_option43_cl_suboption_request_list,
		  { "Suboption Request List", "bootp.option.vendor.cl.suboption_request_list",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 43:CL 1 Suboption Request List", HFILL }},

		{ &hf_bootp_option43_cl_device_type,
		  { "Device Type", "bootp.option.vendor.cl.device_type",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 43:CL 2 Device Type", HFILL }},

		{ &hf_bootp_option43_cl_esafe_type,
		  { "eSAFE Types", "bootp.option.vendor.cl.esafe_type",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 43:CL 3 eSAFE Types", HFILL }},

		{ &hf_bootp_option43_cl_serial_number,
		  { "Serial Number", "bootp.option.vendor.cl.serial_number",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 43:CL 4 Serial Number", HFILL }},

		{ &hf_bootp_option43_cl_hardware_version,
		  { "Hardware Version", "bootp.option.vendor.cl.hardware_version",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 43:CL 5 Hardware Version", HFILL }},

		{ &hf_bootp_option43_cl_software_version,
		  { "Software Version", "bootp.option.vendor.cl.software_version",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 43:CL 6 Software Version", HFILL }},

		{ &hf_bootp_option43_cl_boot_rom_version,
		  { "Boot ROM version", "bootp.option.vendor.cl.boot_rom_version",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 43:CL 7 Boot ROM version", HFILL }},

		{ &hf_bootp_option43_cl_oui_string,
		  { "Organizationally Unique Identifier", "bootp.option.vendor.cl.oui_string",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 43:CL 8 Organizationally Unique Identifier", HFILL }},

		{ &hf_bootp_option43_cl_oui_bytes,
		  { "Organizationally Unique Identifier", "bootp.option.vendor.cl.oui_bytes",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 43:CL 8 Organizationally Unique Identifier", HFILL }},

		{ &hf_bootp_option43_cl_model_number,
		  { "Model Number", "bootp.option.vendor.cl.model_number",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 43:CL 9 Model Number", HFILL }},

		{ &hf_bootp_option43_cl_vendor_name10,
		  { "Vendor Name", "bootp.option.vendor.cl.vendor_name10",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 43:CL 10 Vendor Name", HFILL }},

		{ &hf_bootp_option43_cl_address_realm,
		  { "Address Realm", "bootp.option.vendor.cl.address_realm",
		    FT_UINT8, BASE_DEC, VALS(cablehome_subopt11_vals), 0x0,
		    "Option 43:CL 11 Address Realm", HFILL }},

		{ &hf_bootp_option43_cl_cm_ps_system_desc,
		  { "CM/PS System Description", "bootp.option.vendor.cl.cm_ps_system_desc",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 43:CL 12 CM/PS System Description", HFILL }},

		{ &hf_bootp_option43_cl_cm_ps_firmware_revision,
		  { "CM/PS Firmware Revision", "bootp.option.vendor.cl.cm_ps_firmware_revision",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 43:CL 13 CM/PS Firmware Revision", HFILL }},

		{ &hf_bootp_option43_cl_firewall_policy_file_version,
		  { "Firewall Policy File Version", "bootp.option.vendor.cl.firewall_policy_file_version",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 43:CL 14 Firewall Policy File Version", HFILL }},

		{ &hf_bootp_option43_cl_esafe_config_file_devices,
		  { "eSafe Config File Devices", "bootp.option.vendor.cl.esafe_config_file_devices",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 43:CL 15 eSafe Config File Devices", HFILL }},

		{ &hf_bootp_option43_cl_video_security_tape,
		  { "Video Security Type", "bootp.option.vendor.cl.video_security_tape",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 43:CL 18 Video Security Type", HFILL }},

		{ &hf_bootp_option43_cl_mta_mac_address,
		  { "MTA MAC Address", "bootp.option.vendor.cl.mta_mac_address",
		    FT_ETHER, BASE_NONE, NULL, 0x0,
		    "Option 43:CL 31 MTA MAC Address", HFILL }},

		{ &hf_bootp_option43_cl_correlation_ID,
		  { "Correlation ID", "bootp.option.vendor.cl.correlation_ID",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Option 43: CL 32 Correlation ID", HFILL }},

		{ &hf_bootp_option43_cl_vendor_name51,
		  { "Vendor Name", "bootp.option.vendor.cl.vendor_name51",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 43:CL 51 Vendor Name", HFILL }},

		{ &hf_bootp_option43_cl_cablecard_capability,
		  { "CableCARD Capability", "bootp.option.vendor.cl.cablecard_capability",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 43:CL 52 CableCARD Capability", HFILL }},

		{ &hf_bootp_option43_cl_device_id_ca,
		  { "Device Identification (CA)", "bootp.option.vendor.cl.device_id_ca",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 43:CL 53 Device Identification (CA)", HFILL }},

		{ &hf_bootp_option43_cl_device_id_x509,
		  { "Device Identification (X.509)", "bootp.option.vendor.cl.device_id_x509",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 43:CL 54 Device Identification (X.509)", HFILL }},

		{ &hf_bootp_option43_cl_end,
		  { "CL End", "bootp.option.vendor.cl.end",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 43:CL 255 End", HFILL }},


		{ &hf_bootp_option43_alcatel_suboption,
		  { "Option 43 Suboption", "bootp.option.vendor.alu.suboption",
		    FT_UINT8, BASE_DEC, VALS(option43_alcatel_suboption_vals), 0x0,
		    "Option 43:Alcatel Suboption", HFILL }},

		{ &hf_bootp_option43_alcatel_padding,
		  { "Padding", "bootp.option.vendor.alu.padding",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 43:Alcatel 0 Padding", HFILL }},

		{ &hf_bootp_option43_alcatel_vlan_id,
		  { "Voice VLAN ID", "bootp.option.vendor.alu.vid",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Option 43:Alcatel 58 Voice VLAN ID", HFILL }},

		{ &hf_bootp_option43_alcatel_tftp1,
		  { "Spatial Redundancy TFTP1", "bootp.option.vendor.alu.tftp1",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    "Option 43:Alcatel 64 Spatial Redundancy TFTP1", HFILL }},

		{ &hf_bootp_option43_alcatel_tftp2,
		  { "Spatial Redundancy TFTP2", "bootp.option.vendor.alu.tftp2",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    "Option 43:Alcatel 65 Spatial Redundancy TFTP2", HFILL }},

		{ &hf_bootp_option43_alcatel_app_type,
		  { "Application Type", "bootp.option.vendor.alu.app_type",
		    FT_UINT8, BASE_DEC, VALS(option43_alcatel_app_type_vals), 0x0,
		    "Option 43:Alcatel 66 Application Type", HFILL }},

		{ &hf_bootp_option43_alcatel_sip_url,
		  { "SIP URL", "bootp.option.vendor.alu.sip_url",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Option 43:Alcatel 67 SIP URL", HFILL }},

		{ &hf_bootp_option43_alcatel_end,
		  { "Alcatel End", "bootp.option.vendor.alu.end",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 43:Alcatel 255 End", HFILL }},

		{ &hf_bootp_option43_arubaap_controllerip,
		  { "Aruba Controller IP", "bootp.option.vendor.arubaap.controllerip",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Address IP of Aruba controller", HFILL }},

		{ &hf_bootp_option43_arubaiap,
		  { "Aruba Instant AP", "bootp.option.vendor.arubaiap",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "nameorg,amp-ip-address,password", HFILL }},

		{ &hf_bootp_option43_arubaiap_nameorg,
		  { "Name Organisation", "bootp.option.vendor.arubaiap.name_org",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_option43_arubaiap_ampip,
		  { "AMP IP Address", "bootp.option.vendor.arubaiap.amp_ip",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Address IP of Airwave server (AMP)", HFILL }},

		{ &hf_bootp_option43_arubaiap_password,
		  { "Password", "bootp.option.vendor.arubaiap.password",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Password for Instant AP Airwave server (AMP)", HFILL }},


		{ &hf_bootp_option43_bsdp_suboption,
		  { "Option 43 Suboption", "bootp.option.vendor.bsdp.suboption",
		    FT_UINT8, BASE_DEC, VALS(option43_cl_suboption_vals), 0x0,
		    "Option 43:BSDP Suboption", HFILL }},

		{ &hf_bootp_option43_bsdp_message_type,
		  { "Message Type", "bootp.option.vendor.bsdp.message_type",
		    FT_UINT8, BASE_DEC, VALS(o43_bsdp_message_type_vals), 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_option43_bsdp_version,
		  { "Version", "bootp.option.vendor.bsdp.version",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_option43_bsdp_server_identifier,
		  { "Server Identifier", "bootp.option.vendor.bsdp.server_identifier",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_option43_bsdp_server_priority,
		  { "Server Priority", "bootp.option.vendor.bsdp.server_priority",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_option43_bsdp_reply_port,
		  { "Reply Port", "bootp.option.vendor.bsdp.reply_port",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_option43_bsdp_boot_image_list_path,
		  { "Boot Image List Path", "bootp.option.vendor.bsdp.boot_image_list_path",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_option43_bsdp_boot_image_index,
		  { "Boot Image Index", "bootp.option.vendor.bsdp.boot_image.index",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_option43_bsdp_default_boot_image_id,
		  { "Default Boot Image ID", "bootp.option.vendor.bsdp.default_boot_image_id",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_option43_bsdp_selected_boot_image_id,
		  { "Selected Boot Image ID", "bootp.option.vendor.bsdp.selected_boot_image_id",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_option43_bsdp_boot_image_list,
		  { "Boot Image List", "bootp.option.vendor.bsdp.boot_image_list",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_option43_bsdp_image_desc,
		  { "Boot Image Description", "bootp.option.vendor.bsdp.boot_image.desc",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_option43_bsdp_boot_image_name_len,
		  { "Boot Image Name Length", "bootp.option.vendor.bsdp.boot_image.name_len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_option43_bsdp_boot_image_name,
		  { "Boot Image Name", "bootp.option.vendor.bsdp.boot_image.name",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_option43_bsdp_netboot_firmware,
		  { "NetBoot 1.0 Firmware", "bootp.option.vendor.bsdp.netboot_firmware",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_option43_bsdp_attributes_filter_list,
		  { "Boot Image Attributes Filter List", "bootp.option.vendor.bsdp.attributes_filter_list",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_option43_bsdp_boot_image_attribute,
		  { "Boot Image Attribute", "bootp.option.vendor.bsdp.boot_image.attribute",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_option43_bsdp_boot_image_attribute_install,
		  { "Install", "bootp.option.vendor.bsdp.boot_image.attribute.install",
		    FT_UINT16, BASE_HEX, VALS(o43_bsdp_boot_image_install_vals), 0x8000,
		    "Boot Image Attribute Install", HFILL }},

		{ &hf_bootp_option43_bsdp_boot_image_attribute_kind,
		  { "Kind", "bootp.option.vendor.bsdp.boot_image.attribute.kind",
		    FT_UINT16, BASE_HEX, VALS(o43_bsdp_boot_image_kind_vals), 0x7f00,
		    "Boot Image Attribute Kind", HFILL }},

		{ &hf_bootp_option43_bsdp_boot_image_attribute_reserved,
		  { "Reserved", "bootp.option.vendor.bsdp.boot_image.attribute.reserved",
		    FT_UINT16, BASE_HEX, NULL, 0x00ff,
		    "Boot Image Attribute Reserved", HFILL }},

		{ &hf_bootp_option43_bsdp_message_size,
		  { "Message Size", "bootp.option.vendor.bsdp.message_size",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},


		{ &hf_bootp_option_netbios_over_tcpip_name_server,
		  { "NetBIOS over TCP/IP Name Server", "bootp.option.netbios_over_tcpip_name_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 44: NetBIOS over TCP/IP Name Server", HFILL }},

		{ &hf_bootp_option_netbios_over_tcpip_dd_name_server,
		  { "NetBIOS over TCP/IP Datagram Distribution Name Server", "bootp.option.netbios_over_tcpip_dd_name_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 45: NetBIOS over TCP/IP Datagram Distribution Name Server", HFILL }},

		{ &hf_bootp_option_netbios_over_tcpip_node_type,
		  { "NetBIOS over TCP/IP Node Type", "bootp.option.netbios_over_tcpip_node_type",
		    FT_UINT8, BASE_DEC, VALS(bootp_nbnt_vals), 0x0,
		    "Option 46: NetBIOS over TCP/IP Node Type", HFILL }},

		{ &hf_bootp_option_netbios_over_tcpip_scope,
		  { "NetBIOS over TCP/IP Scope", "bootp.option.netbios_over_tcpip_scope",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 47: NetBIOS over TCP/IP Scope", HFILL }},

		{ &hf_bootp_option_xwindows_system_font_server,
		  { "X Window System Font Server", "bootp.option.xwindows_system_font_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 48: X Window System Font Server", HFILL }},

		{ &hf_bootp_option_xwindows_system_display_manager,
		  { "X Window System Display Manager", "bootp.option.xwindows_system_display_manager",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 49: X Window System Display Manager", HFILL }},

		{ &hf_bootp_option_requested_ip_address,
		  { "Requested IP Address", "bootp.option.requested_ip_address",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 50: Requested IP Address", HFILL }},

		{ &hf_bootp_option_ip_address_lease_time,
		  { "IP Address Lease Time", "bootp.option.ip_address_lease_time",
		    FT_UINT32, BASE_DEC, NULL, 0x00,
		    "Option 51: IP Address Lease Time", HFILL }},

		{ &hf_bootp_option_option_overload,
		  { "Option Overload", "bootp.option.option_overload",
		    FT_UINT8, BASE_DEC, VALS(opt_overload_vals), 0x0,
		    "Option 52: Option Overload", HFILL }},

		{ &hf_bootp_option_dhcp,
		  { "DHCP", "bootp.option.dhcp",
		    FT_UINT8, BASE_DEC, VALS(opt53_text), 0x0,
		    "Option 53: DHCP option", HFILL }},

		{ &hf_bootp_option_dhcp_server_id,
		  { "DHCP Server Identifier", "bootp.option.dhcp_server_id",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 54: DHCP Server Identifier", HFILL }},

		{ &hf_bootp_option_parameter_request_list_item,
		  { "Parameter Request List Item", "bootp.option.request_list_item",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 55: Parameter Request List Item", HFILL }},

		{ &hf_bootp_option_message,
		  { "Message", "bootp.option.message",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 56: Option message", HFILL }},

		{ &hf_bootp_option_dhcp_max_message_size,
		  { "Maximum DHCP Message Size", "bootp.option.dhcp_max_message_size",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Option 57: Maximum DHCP Message Size", HFILL }},

		{ &hf_bootp_option_renewal_time_value,
		  { "Renewal Time Value", "bootp.option.renewal_time_value",
		    FT_UINT32, BASE_DEC, NULL, 0x00,
		    "Option 58: Renewal Time Value", HFILL }},

		{ &hf_bootp_option_rebinding_time_value,
		  { "Rebinding Time Value", "bootp.option.rebinding_time_value",
		    FT_UINT32, BASE_DEC, NULL, 0x00,
		    "Option 59: Rebinding Time Value", HFILL }},

		{ &hf_bootp_option_vendor_class_id,
		  { "Vendor class identifier", "bootp.option.vendor_class_id",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 60: Vendor class identifier", HFILL }},

		{ &hf_bootp_option_vendor_class_data,
		  { "vendor-class-data", "bootp.option.vendor_class_data",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 60: Vendor class data", HFILL }},

		{ &hf_bootp_option_novell_netware_ip_domain,
		  { "Novell/Netware IP domain", "bootp.option.novell_netware_ip_domain",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 62: Novell/Netware IP domain", HFILL }},

		{ &hf_bootp_option63_suboption,
		  { "Option 63 Suboption", "bootp.option.novell_options.suboption",
		    FT_UINT8, BASE_DEC, VALS(option63_suboption_vals), 0x0,
		    "Option 63: Suboption", HFILL }},

		{ &hf_bootp_option63_value,
		  { "Value", "bootp.option.novell_options.value",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 63: Suboption value", HFILL }},

		{ &hf_bootp_option63_value_8,
		  { "Value", "bootp.option.novell_options.value.uint",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 63: Suboption 8-bit value", HFILL }},

		{ &hf_bootp_option63_value_ip_address,
		  { "Value", "bootp.option.novell_options.value.address",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 63: Suboption IP address", HFILL }},

		{ &hf_bootp_option63_value_boolean,
		  { "Value", "bootp.option.novell_options.value.bool",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_true_false), 0x00,
		    "Option 63: Suboption Boolean value", HFILL }},

		{ &hf_bootp_option63_broadcast,
		  { "Broadcast for nearest Netware server", "bootp.option.novell_options.broadcast",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x00,
		    "Option 63:5 Broadcast for nearest Netware server", HFILL }},

		{ &hf_bootp_option63_preferred_dss_server,
		  { "Preferred DSS server", "bootp.option.novell_options.preferred_dss_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 63:6 Preferred DSS server", HFILL }},

		{ &hf_bootp_option63_nearest_nwip_server,
		  { "Nearest NWIP server", "bootp.option.novell_options.nearest_nwip_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 63:7 Nearest NWIP server", HFILL }},

		{ &hf_bootp_option63_autoretries,
		  { "Autoretries", "bootp.option.novell_options.autoretries",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 63:8 Autoretries", HFILL }},

		{ &hf_bootp_option63_autoretry_delay,
		  { "Autoretry delay, sec",
		    "bootp.option.novell_options.autoretry_delay", FT_UINT8, BASE_DEC, NULL,
		    0x0, "Option 63:9 Autoretry delay, sec", HFILL }},

		{ &hf_bootp_option63_support_netware_v1_1,
		  { "Broadcast for nearest Netware server", "bootp.option.novell_options.support_netware_v1_1",
		    FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x00,
		    "Option 63:10 Broadcast for nearest Netware server", HFILL }},

		{ &hf_bootp_option63_primary_dss,
		  { "Primary DSS", "bootp.option.novell_options.primary_dss",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 63:11 Primary DSS", HFILL }},


		{ &hf_bootp_option_nis_plus_domain,
		  { "Network Information Service+ Domain", "bootp.option.nis_plus_domain",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 64: Network Information Service+ Domain", HFILL }},

		{ &hf_bootp_option_nis_plus_server,
		  { "Network Information Service+ Server", "bootp.option.nis_plus_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 65: Network Information Service+ Server", HFILL }},

		{ &hf_bootp_option_tftp_server_name,
		  { "TFTP Server Name", "bootp.option.tftp_server_name",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 66: TFTP Server Name", HFILL }},

		{ &hf_bootp_option_bootfile_name,
		  { "Bootfile name", "bootp.option.bootfile_name",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 67: Bootfile name", HFILL }},

		{ &hf_bootp_option_mobile_ip_home_agent,
		  { "Mobile IP Home Agent", "bootp.option.mobile_ip_home_agent",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 68: Mobile IP Home Agent", HFILL }},

		{ &hf_bootp_option_smtp_server,
		  { "SMTP Server", "bootp.option.smtp_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 69: SMTP Server", HFILL }},

		{ &hf_bootp_option_pop3_server,
		  { "POP3 Server", "bootp.option.pop3_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 70: POP3 Server", HFILL }},

		{ &hf_bootp_option_nntp_server,
		  { "NNTP Server", "bootp.option.nntp_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 71: NNTP Server", HFILL }},

		{ &hf_bootp_option_default_www_server,
		  { "Default WWW Server", "bootp.option.default_www_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 72: Default WWW Server", HFILL }},

		{ &hf_bootp_option_default_finger_server,
		  { "Default Finger Server", "bootp.option.default_finger_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 73: Default Finger Server", HFILL }},

		{ &hf_bootp_option_default_irc_server,
		  { "Default IRC Server", "bootp.option.default_irc_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 74: Default IRC Server", HFILL }},

		{ &hf_bootp_option_streettalk_server,
		  { "StreetTalk Server", "bootp.option.streettalk_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 75: StreetTalk Server", HFILL }},

		{ &hf_bootp_option_streettalk_da_server,
		  { "StreetTalk Directory Assistance Server", "bootp.option.streettalk_da_server",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 76: StreetTalk Directory Assistance Server", HFILL }},

		{ &hf_bootp_option77_user_class,
		  { "Instance of User Class", "bootp.option.user_class",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_option77_user_class_length,
		  { "User Class Length", "bootp.option.user_class.length",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Length of User Class Instance", HFILL }},

		{ &hf_bootp_option77_user_class_data,
		  { "User Class Data", "bootp.option.user_class.data",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Data of User Class Instance", HFILL }},

		{ &hf_bootp_option_slp_directory_agent_value,
		  { "Value", "bootp.option.slp_directory_agent.value",
		    FT_UINT8, BASE_DEC, VALS(slpda_vals), 0x0,
		    "Option 78: SLPDA Value", HFILL }},

		{ &hf_bootp_option_slp_directory_agent_slpda_address,
		  { "IP Address", "bootp.option.slp_directory_agent.slpda_address",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 78: SLPDA Address", HFILL }},

		{ &hf_bootp_option_slp_service_scope_value,
		  { "Value", "bootp.option.slp_service_scope.value",
		    FT_UINT8, BASE_DEC, VALS(slp_scope_vals), 0x0,
		    "Option 79: SLP Service Scope Value", HFILL }},

		{ &hf_bootp_option_slp_service_scope_string,
		  { "SLP Service Scope", "bootp.option.slp_service_scope.string",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 79: SLP Service Scope", HFILL }},


		{ &hf_bootp_option82_suboption,
		  { "Option 82 Suboption", "bootp.option.agent_information_option.suboption",
		    FT_UINT8, BASE_DEC, VALS(option82_suboption_vals), 0x0,
		    "Option 82: Suboption", HFILL }},

		{ &hf_bootp_option82_value,
		  { "Value", "bootp.option.agent_information_option.value",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 82: Suboption value", HFILL }},

		{ &hf_bootp_option82_value_8,
		  { "Value", "bootp.option.agent_information_option.value.uint",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 82: Suboption 8-bit value", HFILL }},

		{ &hf_bootp_option82_value_32,
		  { "Value", "bootp.option.agent_information_option.value.uint",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Option 82: Suboption 32-bit value", HFILL }},

		{ &hf_bootp_option82_value_ip_address,
		  { "Value", "bootp.option.agent_information_option.value.address",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 82: Suboption IP address", HFILL }},

		{ &hf_bootp_option82_value_stringz,
		  { "Value", "bootp.option.agent_information_option.value.string",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 82: Suboption Z-String value", HFILL }},

		{ &hf_bootp_option82_padding,
		  { "Padding", "bootp.option.agent_information_option.padding",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 82:0 Padding", HFILL }},

		{ &hf_bootp_option82_agent_circuit_id,
		  { "Agent Circuit ID", "bootp.option.agent_information_option.agent_circuit_id",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 82:1 Agent Circuit ID", HFILL }},

		{ &hf_bootp_option82_agent_remote_id,
		  { "Agent Remote ID", "bootp.option.agent_information_option.agent_remote_id",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 82:2 Agent Remote ID", HFILL }},

		{ &hf_bootp_option82_reserved,
		  { "Reserved", "bootp.option.agent_information_option.reserved",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 82:3 Reserved", HFILL }},

		{ &hf_bootp_option82_docsis_device_class,
		  { "DOCSIS Device Class", "bootp.option.agent_information_option.docsis_device_class",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "Option 82:4 DOCSIS Device Class", HFILL }},

		{ &hf_bootp_option82_link_selection,
		  { "Link selection", "bootp.option.agent_information_option.link_selection",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 82:5 Link selection", HFILL }},

		{ &hf_bootp_option82_subscriber_id,
		  { "Subscriber ID", "bootp.option.agent_information_option.subscriber_id",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 82:6 Subscriber ID", HFILL }},

		{ &hf_bootp_option82_radius_attributes,
		  { "RADIUS Attributes", "bootp.option.agent_information_option.radius_attributes",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 82:7 RADIUS Attributes", HFILL }},

		{ &hf_bootp_option82_authentication,
		  { "Authentication", "bootp.option.agent_information_option.authentication",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 82:8 Authentication", HFILL }},

		{ &hf_bootp_option82_vi,
		  { "Vendor-Specific Information", "bootp.option.agent_information_option.vi",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 82:9 Vendor-Specific Information", HFILL }},

		{ &hf_bootp_option82_vi_enterprise,
		  { "Enterprise", "bootp.option.agent_information_option.vi.enterprise",
		    FT_UINT32, BASE_DEC|BASE_EXT_STRING, &sminmpec_values_ext, 0x0,
		    "Option 82:9 VI Enterprise", HFILL }},

		{ &hf_bootp_option82_vi_data_length,
		  { "Data Length", "bootp.option.agent_information_option.vi.data_length",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 82:9 VI Data Length", HFILL }},

		{ &hf_bootp_option82_vi_cl_option,
		  { "Option", "bootp.option.agent_information_option.vi.cl.option",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 82:9 VI CL Option", HFILL }},

		{ &hf_bootp_option82_vi_cl_length,
		  { "Length", "bootp.option.agent_information_option.vi.cl.length",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 82:9 VI CL Length", HFILL }},

		{ &hf_bootp_option82_vi_cl_tag,
		  { "Tag", "bootp.option.agent_information_option.vi.cl.tag",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 82:9 VI CL Tag", HFILL }},

		{ &hf_bootp_option82_vi_cl_tag_length,
		  { "Tag Length", "bootp.option.agent_information_option.vi.cl.tag_length",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 82:9 VI CL Tag Length", HFILL }},

		{ &hf_bootp_option82_vi_cl_docsis_version,
		  { "DOCSIS Version Number", "bootp.option.agent_information_option.vi.cl.docsis_version",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    "Option 82:9 VI CL DOCSIS Version Number", HFILL }},

		{ &hf_bootp_option82_flags,
		  { "Flags", "bootp.option.agent_information_option.flags",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    "Option 82:10 Flags", HFILL }},

		{ &hf_bootp_option82_server_id_override,
		  { "Server ID Override", "bootp.option.agent_information_option.server_id_override",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 82:11 Server ID Override", HFILL }},

		{ &hf_bootp_option82_link_selection_cisco,
		  { "Link selection (Cisco proprietary)", "bootp.option.agent_information_option.link_selection_cisco",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 82:150 Link selection (Cisco proprietary)", HFILL }},

		{ &hf_bootp_option82_vrf_name_vpn_id,
		  { "VRF name/VPN ID", "bootp.option.agent_information_option.vrf_name.vpn_id",
		    FT_BYTES, BASE_NONE, NULL, 0x00,
		    "Option 82:151 VRF name/VPN ID", HFILL }},

		{ &hf_bootp_option82_vrf_name_global,
		  { "Global, default VPN", "bootp.option.agent_information_option.vrf_name.global",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "Option 82:151 Global, default VPN", HFILL }},

		{ &hf_bootp_option82_vrf_name,
		  { "VRF name", "bootp.option.agent_information_option.vrf_name",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    "Option 82:151 VRF name", HFILL }},

		{ &hf_bootp_option82_vrf_name_vpn_id_oui,
		  { "VRF name/VPN ID OUI", "bootp.option.agent_information_option.vrf_name.vpn_id.oui",
		    FT_UINT24, BASE_HEX, NULL, 0x00,
		    "Option 82:151 VRF name/VPN ID OUI", HFILL }},

		{ &hf_bootp_option82_vrf_name_vpn_id_index,
		  { "VRF name/VPN ID Index", "bootp.option.agent_information_option.vrf_name.vpn_id.index",
		    FT_UINT32, BASE_HEX, NULL, 0x00,
		    "Option 82:151 VRF name/VPN ID Index", HFILL }},

		{ &hf_bootp_option82_server_id_override_cisco,
		  { "Server ID Override (Cisco proprietary)", "bootp.option.agent_information_option.server_id_override_cisco",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 82:152 Server ID Override (Cisco proprietary)", HFILL }},


		{ &hf_bootp_option_isns_functions,
		  { "iSNS Functions", "bootp.option.isns.functions",
		    FT_UINT16, BASE_HEX, NULL, 0x00,
		    "iSNS: the functions supported by the iSNS servers", HFILL }},

		{ &hf_bootp_option_isns_functions_enabled,
		  { "Function Fields Enabled", "bootp.option.isns.functions.enabled",
		    FT_BOOLEAN, 16, TFS(&tfs_yes_no), F_ISNS_FUNCTIONS_ENABLED,
		    "If set to zero, then the contents of all other iSNS Function fields MUST be ignored", HFILL }},

		{ &hf_bootp_option_isns_functions_dd_authorization,
		  { "Discovery Domain based Authorization", "bootp.option.isns.functions.dd_base_authorization",
		    FT_BOOLEAN, 16, TFS(&tfs_isns_function_dd_based_auth), F_ISNS_FUNCTIONS_DD_AUTH,
		    "If set to zero, then access authorization must be explicitly performed by each device", HFILL }},

		{ &hf_bootp_option_isns_functions_sec_policy_distibution,
		  { "Security Policy Distribution", "bootp.option.isns.functions.sec_policy_distribution",
		    FT_BOOLEAN, 16, TFS(&tfs_isns_functions_sec_distrib), F_ISNS_FUNCTIONS_SEC_POLICY,
		    NULL, HFILL }},

		{ &hf_bootp_option_isns_functions_reserved,
		  { "Reserved flags", "bootp.option.isns.functions.reserved",
		    FT_UINT16, BASE_HEX, NULL, F_ISNS_FUNCTIONS_RESERVED,
		    NULL, HFILL }},

		{ &hf_bootp_option_isns_discovery_domain_access,
		  { "Discovery Domain Access flags", "bootp.option.isns.discovery_domain_access",
		    FT_UINT16, BASE_HEX, NULL, 0x00,
		    "iSNS: the types of iSNS clients that are allowed to modify Discovery Domains", HFILL }},

		{ &hf_bootp_option_isns_discovery_domain_access_enabled,
		  { "Discovery Domain Enabled", "bootp.option.isns.discovery_domain_access.enabled",
		    FT_BOOLEAN, 16, TFS(&tfs_yes_no), F_ISNS_DD_ACCESS_ENABLED,
		    "If set to zero, then the contents of the remainder of this field MUST be ignored", HFILL }},

		{ &hf_bootp_option_isns_discovery_domain_access_control_node,
		  { "Control Node", "bootp.option.isns.discovery_domain_access_control.node",
		    FT_BOOLEAN, 16, TFS(&tfs_yes_no), F_ISNS_DD_ACCESS_CTRL_NODE,
		    NULL, HFILL }},

		{ &hf_bootp_option_isns_discovery_domain_access_iscsi_target,
		  { "iSCSI Target", "bootp.option.isns.discovery_domain_access.iscsi_target",
		    FT_BOOLEAN, 16, TFS(&tfs_yes_no), F_ISNS_DD_ACCESS_ISCSI_TARGET,
		    NULL, HFILL }},

		{ &hf_bootp_option_isns_discovery_domain_access_iscsi_inititator,
		  { "iSCSI Initiator", "bootp.option.isns.discovery_domain_access.iscsi_initiator",
		    FT_BOOLEAN, 16, TFS(&tfs_yes_no), F_ISNS_DD_ACCESS_ISCSI_INITIATOR,
		    NULL, HFILL }},

		{ &hf_bootp_option_isns_discovery_domain_access_ifcp_target_port,
		  { "iFCP Target Port", "bootp.option.isns.discovery_domain_access.ifcp_target_port",
		    FT_BOOLEAN, 16, TFS(&tfs_yes_no), F_ISNS_DD_ACCESS_IFCP_TARGET_PORT,
		    NULL, HFILL }},

		{ &hf_bootp_option_isns_discovery_domain_access_ifcp_initiator_port,
		  { "iFCP Initiator Port", "bootp.option.isns.discovery_domain_access.initiator_target_port",
		    FT_BOOLEAN, 16, TFS(&tfs_yes_no), F_ISNS_DD_ACCESS_IFCP_INITIATOR_PORT,
		    NULL, HFILL }},

		{ &hf_bootp_option_isns_discovery_domain_access_reserved,
		  { "Reserved Flags", "bootp.option.isns.discovery_domain_access.reserved",
		    FT_UINT16, BASE_HEX, NULL, F_ISNS_DD_ACCESS_RESERVED,
		    NULL, HFILL }},

		{ &hf_bootp_option_isns_administrative_flags,
		  { "Administrative Flags", "bootp.option.isns.administrative_flags",
		    FT_UINT16, BASE_HEX, NULL, 0x00,
		    "iSNS: administrative settings for the iSNS servers discovered through the DHCP query", HFILL }},

		{ &hf_bootp_option_isns_administrative_flags_enabled,
		  { "Administrative Flags Enabled", "bootp.option.isns.administrative_flags.enabled",
		    FT_BOOLEAN, 16, TFS(&tfs_yes_no), F_ISNS_ADMIN_FLAGS_ENABLED,
		    NULL, HFILL }},

		{ &hf_bootp_option_isns_administrative_flags_heartbeat,
		  { "Heartbeat", "bootp.option.isns.administrative_flags.heartbeat",
		    FT_BOOLEAN, 16, TFS(&tfs_yes_no), F_ISNS_ADMIN_FLAGS_HEARTBEAT,
		    NULL, HFILL }},

		{ &hf_bootp_option_isns_administrative_flags_management_scns,
		  { "Management SCNs", "bootp.option.isns.administrative_flags.management_scns",
		    FT_BOOLEAN, 16, TFS(&tfs_yes_no), F_ISNS_ADMIN_FLAGS_MANAGEMENT_SCNS,
		    NULL, HFILL }},

		{ &hf_bootp_option_isns_administrative_flags_default_dd,
		  { "Default Discovery Domain", "bootp.option.isns.administrative_flags.default_discovery_domain",
		    FT_BOOLEAN, 16, TFS(&tfs_yes_no), F_ISNS_ADMIN_FLAGS_DEFAULT_DD,
		    NULL, HFILL }},

		{ &hf_bootp_option_isns_administrative_flags_reserved,
		  { "Reserved Flags", "bootp.option.isns.administrative_flags.reserved",
		    FT_UINT16, BASE_HEX, NULL, F_ISNS_ADMIN_FLAGS_RESERVED,
		    NULL, HFILL }},

		{ &hf_bootp_option_isns_server_security_bitmap,
		  { "iSNS Server Security Bitmap", "bootp.option.isns.server_security_bitmap",
		    FT_UINT32, BASE_HEX, NULL, 0x00,
		    "iSNS: server security settings", HFILL }},

		{ &hf_bootp_option_isns_server_security_bitmap_enabled,
		  { "Server Security Bitmap Enabled", "bootp.option.isns.server_security_bitmap.enabled",
		    FT_BOOLEAN, 16, TFS(&tfs_yes_no), F_ISNS_SRV_SEC_BITMAP_ENABLED,
		    NULL, HFILL }},

		{ &hf_bootp_option_isns_server_security_bitmap_ike_ipsec_enabled,
		  { "IKE/IPSec", "bootp.option.isns.server_security_bitmap.ike_ipsec_enabled",
		    FT_BOOLEAN, 16, TFS(&tfs_enabled_disabled), F_ISNS_SRV_SEC_BITMAP_IKE_IPSEC,
		    NULL, HFILL }},

		{ &hf_bootp_option_isns_server_security_bitmap_main_mode,
		  { "Main Mode", "bootp.option.isns.server_security_bitmap.main_mode",
		    FT_BOOLEAN, 16, TFS(&tfs_enabled_disabled), F_ISNS_SRV_SEC_BITMAP_MAIN_MODE,
		    NULL, HFILL }},

		{ &hf_bootp_option_isns_server_security_bitmap_aggressive_mode,
		  { "Aggresive Mode", "bootp.option.isns.server_security_bitmap.aggressive_mode",
		    FT_BOOLEAN, 16, TFS(&tfs_enabled_disabled), F_ISNS_SRV_SEC_BITMAP_AGGRESSIVE,
		    NULL, HFILL }},

		{ &hf_bootp_option_isns_server_security_bitmap_pfs,
		  { "PFS", "bootp.option.isns.server_security_bitmap.pfs",
		    FT_BOOLEAN, 16, TFS(&tfs_enabled_disabled), F_ISNS_SRV_SEC_BITMAP_PFS,
		    NULL, HFILL }},

		{ &hf_bootp_option_isns_server_security_bitmap_transport_mode,
		  { "Transport Mode", "bootp.option.isns.server_security_bitmap.transport_mode",
		    FT_BOOLEAN, 16, TFS(&tfs_preferred_no_preference), F_ISNS_SRV_SEC_BITMAP_TRASPORT_MODE,
		    NULL, HFILL }},

		{ &hf_bootp_option_isns_server_security_bitmap_tunnel_mode,
		  { "Tunnel Mode", "bootp.option.isns.server_security_bitmap.tunnel_mode",
		    FT_BOOLEAN, 16, TFS(&tfs_preferred_no_preference), F_ISNS_SRV_SEC_BITMAP_TUNNEL_MODE,
		    NULL, HFILL }},

		{ &hf_bootp_option_isns_server_security_bitmap_reserved,
		  { "Reserved Flags", "bootp.option.isns.server_security_bitmap.reserved",
		    FT_UINT16, BASE_HEX, NULL, F_ISNS_SRV_SEC_BITMAP_RESERVED,
		    NULL, HFILL }},

		{ &hf_bootp_option_isns_primary_server_addr,
		  { "Primary Server Address", "bootp.option.isns.primary_server_addr",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "iSNS: IP address of the primary server", HFILL }},

		{ &hf_bootp_option_isns_heartbeat_originator_addr,
		  { "Heartbeat Originator Address", "bootp.option.isns.heartbeat_originator_addr",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "iSNS: IP address from which the iSNS heartbeat originates", HFILL }},

		{ &hf_bootp_option_isns_secondary_server_addr_list,
		  { "Secondary Server Address", "bootp.option.isns.secondary_server_addr",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "iSNS: a list of IP addresses of the secondary iSNS servers", HFILL }},


		{ &hf_bootp_option_novell_dss_string,
		  { "Novell Directory Services Servers String", "bootp.option.novell_dss.string",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 85: Novell Directory Services Servers String", HFILL }},

		{ &hf_bootp_option_novell_dss_ip,
		  { "IP Address", "bootp.option.novell_dss.ip",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 85: Novell Directory Services Servers IP Address", HFILL }},

		{ &hf_bootp_option_novell_ds_tree_name,
		  { "Novell Directory Services Tree Name", "bootp.option.novell_ds_tree_name",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 86: Novell Directory Services Tree Name", HFILL }},

		{ &hf_bootp_option_novell_ds_context,
		  { "Novell Directory Services Context", "bootp.option.novell_ds_context",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 87: Novell Directory Services Context", HFILL }},

		{ &hf_bootp_option_dhcp_authentication_protocol,
		  { "Protocol", "bootp.option.dhcp_authentication.protocol",
		    FT_UINT8, BASE_DEC, VALS(authen_protocol_vals), 0x0,
		    "Option 90: Authentication Protocol", HFILL }},

		{ &hf_bootp_option_dhcp_authentication_alg_delay,
		  { "Delay Algorithm", "bootp.option.dhcp_authentication.alg_delay",
		    FT_UINT8, BASE_DEC, VALS(authen_da_algo_vals), 0x0,
		    "Option 90: Delayed Authentication Algorithm", HFILL }},

		{ &hf_bootp_option_dhcp_authentication_algorithm,
		  { "Algorithm", "bootp.option.dhcp_authentication.algorithm",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 90: Authentication Algorithm", HFILL }},

		{ &hf_bootp_option_dhcp_authentication_rdm,
		  { "Replay Detection Method", "bootp.option.dhcp_authentication.rdm",
		    FT_UINT8, BASE_DEC, VALS(authen_rdm_vals), 0x0,
		    "Option 90: Replay Detection Method", HFILL }},

		{ &hf_bootp_option_dhcp_authentication_rdm_replay_detection,
		  { "RDM Replay Detection Value", "bootp.option.dhcp_authentication.rdm_replay_detection",
		    FT_UINT64, BASE_HEX, NULL, 0x0,
		    "Option 90: RDM Replay Detection Value", HFILL }},

		{ &hf_bootp_option_dhcp_authentication_rdm_rdv,
		  { "Replay Detection Value", "bootp.option.dhcp_authentication.rdm_rdv",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 90: Replay Detection Value", HFILL }},

		{ &hf_bootp_option_dhcp_authentication_secret_id,
		  { "Secret ID", "bootp.option.dhcp_authentication.secret_id",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "Option 90: Secret ID", HFILL }},

		{ &hf_bootp_option_dhcp_authentication_hmac_md5_hash,
		  { "HMAC MD5 Hash", "bootp.option.dhcp_authentication.hmac_md5_hash",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 90: HMAC MD5 Hash", HFILL }},

		{ &hf_bootp_option_dhcp_authentication_information,
		  { "Authentication Information", "bootp.option.dhcp_authentication.information",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 90: Authentication Information", HFILL }},

		{ &hf_bootp_option_client_last_transaction_time,
		  { "Client last transaction time", "bootp.option.client_last_transaction_time",
		    FT_UINT32, BASE_DEC, NULL, 0x00,
		    "Option 91: Client last transaction time", HFILL }},

		{ &hf_bootp_option_associated_ip_option,
		  { "Associated IP option", "bootp.option.associated_ip_option",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 92: Associated IP option", HFILL }},

		{ &hf_bootp_option_client_system_architecture,
		  { "Client System Architecture", "bootp.option.client_system_architecture",
		    FT_UINT16, BASE_DEC, VALS(bootp_client_arch), 0x0,
		    "Option 93: Client System Architecture", HFILL }},

		{ &hf_bootp_option_client_network_id_major_ver,
		  { "Major Version", "bootp.client_network_id_major",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 94: Major Version", HFILL }},

		{ &hf_bootp_option_client_network_id_minor_ver,
		  { "Minor Version", "bootp.client_network_id_minor",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 94: Minor Version", HFILL }},

		{ &hf_bootp_option_civic_location_what,
		  { "What", "bootp.option.civic_location.what",
		    FT_UINT8, BASE_DEC, VALS(civic_address_what_values), 0x0,
		    "Option 99: What", HFILL }},

		{ &hf_bootp_option_civic_location_country,
		  { "Country", "bootp.option.civic_location.country",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 99: Country", HFILL }},

		{ &hf_bootp_option_civic_location_ca_type,
		  { "CA Type", "bootp.option.civic_location.ca_type",
		    FT_UINT8, BASE_DEC, VALS(civic_address_type_values), 0x0,
		    "Option 99: CA Type", HFILL }},

		{ &hf_bootp_option_civic_location_ca_length,
		  { "CA Length", "bootp.option.civic_location.ca_length",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 99: CA Length", HFILL }},

		{ &hf_bootp_option_civic_location_ca_value,
		  { "CA Value", "bootp.option.civic_location.ca_value",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 99: CA Value", HFILL }},

		{ &hf_bootp_option_netinfo_parent_server_address,
		  { "NetInfo Parent Server Address", "bootp.option.netinfo_parent_server_address",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 112: NetInfo Parent Server Address", HFILL }},

		{ &hf_bootp_option_netinfo_parent_server_tag,
		  { "NetInfo Parent Server Tag", "bootp.option.netinfo_parent_server_tag",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 113: NetInfo Parent Server Tag", HFILL }},

		{ &hf_bootp_option_dhcp_auto_configuration,
		  { "DHCP Auto-Configuration", "bootp.option.dhcp_auto_configuration",
		    FT_UINT8, BASE_DEC, VALS(dhcp_autoconfig), 0x0,
		    "Option 116: DHCP Auto-Configuration", HFILL }},

		{ &hf_bootp_option_dhcp_name_service_search_option,
		  { "Name Service", "bootp.option.dhcp_name_service_search_option",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 117: Name Service", HFILL }},

		{ &hf_bootp_option_dhcp_dns_domain_search_list_rfc_3396_detected,
		  { "Encoding Long Options detected (RFC 3396)", "bootp.option.dhcp_dns_domain_search_list_rfc_3396_detected",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 119: Encoding Long Options detected (RFC 3396)", HFILL }},

		{ &hf_bootp_option_dhcp_dns_domain_search_list_refer_last_option,
		  { "For the data, please refer to last option 119", "bootp.option.dhcp_dns_domain_search_list_refer_last_option",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 119: For the data, please refer to last option 119", HFILL }},

		{ &hf_bootp_option_dhcp_dns_domain_search_list_fqdn,
		  { "FQDN", "bootp.option.dhcp_dns_domain_search_list_fqdn",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 119: FQDN", HFILL }},

		{ &hf_bootp_option_sip_server_rfc_3396_detected,
		  { "Encoding Long Options detected (RFC 3396)", "bootp.option.sip_server.rfc_3396_detected",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 120: Encoding Long Options detected (RFC 3396)", HFILL }},

		{ &hf_bootp_option_sip_server_refer_last_option,
		  { "For the data, please refer to last option 120", "bootp.option.sip_server.refer_last_option",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 120: For the data, please refer to last option 120", HFILL }},

		{ &hf_bootp_option_sip_server_enc,
		  { "SIP Server Encoding", "bootp.option.sip_server.encoding",
		    FT_UINT8, BASE_DEC, VALS(sip_server_enc_vals), 0x0,
		    "Option 120: SIP Server encoding", HFILL }},

		{ &hf_bootp_option_sip_server_name,
		  { "SIP Server Name", "bootp.option.sip_server.name",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 120: SIP Server Name", HFILL }},

		{ &hf_bootp_option_sip_server_address,
		  { "SIP Server Address", "bootp.option.sip_server.address",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    "Option 120: SIP Server Address", HFILL }},

		{ &hf_bootp_option_sip_server_address_stringz,
		  { "SIP Server Address", "bootp.option.sip_server.address.stringz",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 120: SIP Server Address", HFILL }},

		{ &hf_bootp_option_classless_static_route,
		  { "Subnet/MaskWidth-Router", "bootp.option.classless_static_route.",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 121: Subnet/MaskWidth-Router", HFILL }},

		{ &hf_bootp_option_rfc3825_error,
		  { "Error", "bootp.option.rfc3825.error",
		    FT_UINT8, BASE_DEC, VALS(rfc3825_error_types), 0x0,
		    "Option 123: Error", HFILL }},

		{ &hf_bootp_option_rfc3825_latitude,
		  { "Latitude", "bootp.option.rfc3825.latitude",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0,
		    "Option 123: Latitude", HFILL }},

		{ &hf_bootp_option_rfc3825_longitude,
		  { "Longitude", "bootp.option.rfc3825.longitude",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0,
		    "Option 123: Longitude", HFILL }},

		{ &hf_bootp_option_rfc3825_latitude_res,
		  { "Latitude resolution", "bootp.option.rfc3825.latitude_res",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0,
		    "Option 123: Latitude resolution", HFILL }},

		{ &hf_bootp_option_rfc3825_longitude_res,
		  { "Longitude resolution", "bootp.option.rfc3825.longitude_res",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0,
		    "Option 123: Longitude resolution", HFILL }},

		{ &hf_bootp_option_rfc3825_altitude,
		  { "Altitude", "bootp.option.rfc3825.altitude",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0,
		    "Option 123: Altitude", HFILL }},

		{ &hf_bootp_option_rfc3825_altitide_res,
		  { "Altitude resolution", "bootp.option.rfc3825.altitide_res",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0,
		    "Option 123: Altitude resolution", HFILL }},

		{ &hf_bootp_option_rfc3825_altitude_type,
		  { "Altitude type", "bootp.option.rfc3825.altitude_type",
		    FT_UINT8, BASE_DEC, VALS(altitude_type_values), 0x0,
		    "Option 123: Altitude type", HFILL }},

		{ &hf_bootp_option_rfc3825_map_datum,
		  { "Map Datum", "bootp.option.cl_dss_id.option",
		    FT_UINT8, BASE_DEC, VALS(map_datum_type_values), 0x0,
		    "Option 123: Map Datum", HFILL }},

		{ &hf_bootp_option_cl_dss_id_option,
		  { "DSS_ID Type", "bootp.option.cl_dss_id.option",
		    FT_UINT8, BASE_DEC, VALS(cl_dss_id_type_vals), 0x0,
		    "Option 123:CL DSS_ID Type", HFILL }},

		{ &hf_bootp_option_cl_dss_id_len,
		  { "DSS_ID Length", "bootp.option.cl_dss_id.len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 123:CL DSS_ID Length", HFILL }},

		{ &hf_bootp_option_cl_dss_id,
		  { "Country", "bootp.option.cl_dss_id",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 123:CL DSS_ID", HFILL }},

		{ &hf_bootp_option_vi_class_cl_address_mode,
		  { "CableLab Address Mode", "bootp.option.vi_class.cl_address_mode",
		    FT_UINT8, BASE_DEC, VALS(cablelab_ipaddr_mode_vals), 0x0,
		    "Option 124: CableLab Address Mode", HFILL }},

		{ &hf_bootp_option_vi_class_enterprise,
		  { "Enterprise", "bootp.option.vi_class.enterprise",
		    FT_UINT32, BASE_DEC|BASE_EXT_STRING, &sminmpec_values_ext, 0x00,
		    "Option 124: Enterprise", HFILL }},

		{ &hf_bootp_option_vi_class_data_length,
		  { "CableLab Address Mode", "bootp.option.vi_class.length",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 124: Length", HFILL }},

		{ &hf_bootp_option_vi_class_data,
		  { "NetInfo Parent Server Tag", "bootp.option.vi_class.data",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 124: Data", HFILL }},

		{ &hf_bootp_option125_enterprise,
		  { "Enterprise", "bootp.option.vi.enterprise",
		    FT_UINT32, BASE_DEC|BASE_EXT_STRING, &sminmpec_values_ext, 0x00,
		    "Option 125: Enterprise", HFILL }},

		{ &hf_bootp_option125_length,
		  { "Length", "bootp.option.vi.length",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "Option 125: Length", HFILL }},

		{ &hf_bootp_option125_value,
		  { "Value", "bootp.option.vi.value",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 125: Suboption value", HFILL }},

		{ &hf_bootp_option125_value_8,
		  { "Value", "bootp.option.vi.value.uint",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 125: Suboption 8-bit value", HFILL }},

		{ &hf_bootp_option125_value_16,
		  { "Value", "bootp.option.vi.value.uint",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Option 125: Suboption 16-bit value", HFILL }},

		{ &hf_bootp_option125_value_ip_address,
		  { "Value", "bootp.option.vi.value.address",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 125: Suboption IP address value", HFILL }},

		{ &hf_bootp_option125_value_stringz,
		  { "Value", "bootp.option.vi.value.string",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 125: Suboption Z-String value", HFILL }},

		{ &hf_bootp_option125_tr111_suboption,
		  { "Option 125 Suboption", "bootp.option.vi.tr111.suboption",
		    FT_UINT8, BASE_DEC, VALS(option125_tr111_suboption_vals), 0x0,
		    "Option 125:TR 111 Suboption", HFILL }},

		{ &hf_bootp_option125_tr111_device_manufacturer_oui,
		  { "DeviceManufacturerOUI", "bootp.option.vi.tr111.device_manufacturer_oui",
		    FT_UINT24, BASE_HEX, VALS(oui_vals), 0x0,
		    "Option 125:TR 111 1 DeviceManufacturerOUI", HFILL }},

		{ &hf_bootp_option125_tr111_device_serial_number,
		  { "DeviceSerialNumber", "bootp.option.vi.tr111.device_serial_number",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 125:TR 111 2 DeviceSerialNumber", HFILL }},

		{ &hf_bootp_option125_tr111_device_product_class,
		  { "DeviceProductClass", "bootp.option.vi.tr111.device_product_class",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 125:TR 111 3 DeviceProductClass", HFILL }},

		{ &hf_bootp_option125_tr111_gateway_manufacturer_oui,
		  { "GatewayManufacturerOUI", "bootp.option.vi.tr111.gateway_manufacturer_oui",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 125:TR 111 4 GatewayManufacturerOUI", HFILL }},

		{ &hf_bootp_option125_tr111_gateway_serial_number,
		  { "GatewaySerialNumber", "bootp.option.vi.tr111.gateway_serial_number",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 125:TR 111 5 GatewaySerialNumber", HFILL }},

		{ &hf_bootp_option125_tr111_gateway_product_class,
		  { "GatewayProductClass", "bootp.option.vi.tr111.gateway_product_class",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 125:TR 111 6 GatewayProductClass", HFILL }},

		{ &hf_bootp_option125_cl_suboption,
		  { "Option 125 Suboption", "bootp.option.vi.cl.suboption",
		    FT_UINT8, BASE_DEC, VALS(option125_cl_suboption_vals), 0x0,
		    "Option 125:CL Suboption", HFILL }},

		{ &hf_bootp_option125_cl_option_request,
		  { "Option Request", "bootp.option.vi.cl.option_request",
		    FT_BYTES, SEP_SPACE, NULL, 0x0,
		    "Option 125:CL 1 Option Request", HFILL }},

		{ &hf_bootp_option125_cl_tftp_server_addresses,
		  { "TFTP Server Addresses", "bootp.option.vi.cl.tftp_server_addresses",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 125:CL 2 TFTP Server Addresses", HFILL }},

		{ &hf_bootp_option125_cl_erouter_container_option,
		  { "eRouter Container Option", "bootp.option.vi.cl.erouter_container_option",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 125:CL 3 eRouter Container Option", HFILL }},

		{ &hf_bootp_option125_cl_mib_environment_indicator_option,
		  { "MIB Environment Indicator Option", "bootp.option.vi.cl.suboption",
		    FT_UINT8, BASE_DEC, VALS(pkt_mib_env_ind_opt_vals), 0x0,
		    "Option 125:CL 4 MIB Environment Indicator Option", HFILL }},

		{ &hf_bootp_option125_cl_modem_capabilities,
		  { "Modem Capabilities", "bootp.option.vi.cl.modem_capabilities",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Option 125:CL 5 Modem Capabilities", HFILL }},

		{ &hf_bootp_option_subnet_selection_option,
		  { "Subnet Selection Option", "bootp.option.subnet_selection_option",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 118: Subnet Selection Option", HFILL }},

		{ &hf_bootp_option_lost_server_domain_name,
		  { "LoST Server Domain Name", "bootp.option.lost_server_domain_name",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 137: LoST Server Domain Name", HFILL }},

		{ &hf_bootp_option_capwap_access_controller,
		  { "CAPWAP Access Controllers", "bootp.option.capwap_access_controller",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 138: CAPWAP Access Controllers", HFILL }},

		{ &hf_bootp_option_tftp_server_address,
		  { "TFTP Server Address", "bootp.option.tftp_server_address",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 150: TFTP Server Address", HFILL }},

		{ &hf_bootp_option_pxe_config_file,
		  { "PXELINUX configuration file", "bootp.option.pxe_config_file",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Option 209: PXE Configuration File", HFILL }},

		{ &hf_bootp_option_pxe_path_prefix,
		  { "PXELINUX path prefix", "bootp.option.pxe_path_prefix",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Option 210: PXE Path Prefix", HFILL }},

		{ &hf_bootp_option_6RD_ipv4_mask_len,
		  { "6RD IPv4 Mask Length", "bootp.option.6RD.ipv4_mask_len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 212: 6RD IPv4 Mask Length", HFILL }},

		{ &hf_bootp_option_6RD_prefix_len,
		  { "6RD Prefix Length", "bootp.option.6RD.prefix_len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 212: 6RD Prefix Length", HFILL }},

		{ &hf_bootp_option_6RD_prefix,
		  { "6RD Prefix", "bootp.option.6RD.prefix",
		    FT_IPv6, BASE_NONE, NULL, 0x00,
		    "Option 212: 6RD Prefix", HFILL }},

		{ &hf_bootp_option_6RD_border_relay_ip,
		  { "Border Relay IP", "bootp.option.6RD.border_relay_ip",
		    FT_IPv4, BASE_NONE, NULL, 0x00,
		    "Option 212: Border Relay IP", HFILL }},

		{ &hf_bootp_option_private_proxy_autodiscovery,
		  { "Private/Proxy autodiscovery", "bootp.option.private_proxy_autodiscovery",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 252: Private/Proxy autodiscovery", HFILL }},

		{ &hf_bootp_option_end,
		  { "Option End", "bootp.option.end",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 255: End", HFILL }},

		{ &hf_bootp_option_end_overload,
		  { "Option End (Overload)", "bootp.option.end",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Option 255: End (Overload)", HFILL }},

		{ &hf_bootp_vendor_unknown_suboption,
		  { "Option 125 Suboption", "bootp.vendor.suboption",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_suboption_data,
		  { "Data", "bootp.vendor.data",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_pc_ietf_ccc_suboption,
		  { "Suboption", "bootp.vendor.pc.ietf_ccc.suboption",
		    FT_UINT8, BASE_DEC, VALS(pkt_draft5_ccc_opt_vals), 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_pc_i05_ccc_suboption,
		  { "Suboption", "bootp.vendor.pc.i05_ccc.suboption",
		    FT_UINT8, BASE_DEC, VALS(pkt_i05_ccc_opt_vals), 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_cl_ietf_ccc_dev_realm_unc_key_nom_timeout,
		  { "pktcMtaDevRealmUnsolicitedKeyNomTimeout", "bootp.cl.ietf_ccc.dev_realm_unc_key_nom_timeout",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_cl_ietf_ccc_dev_realm_unc_key_max_timeout,
		  { "pktcMtaDevRealmUnsolicitedKeyMaxTimeout", "bootp.cl.ietf_ccc.dev_realm_unc_key_max_timeout",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_cl_ietf_ccc_dev_realm_unc_key_max_retries,
		  { "pktcMtaDevRealmUnsolicitedKeyMaxRetries", "bootp.cl.ietf_ccc.dev_realm_unc_key_max_retries",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_cl_ietf_ccc_dev_prov_unc_key_nom_timeout,
		  { "pktcMtaDevProvUnsolicitedKeyNomTimeout", "bootp.cl.ietf_ccc.dev_prov_unc_key_nom_timeout",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_cl_ietf_ccc_dev_prov_unc_key_max_timeout,
		  { "pktcMtaDevProvUnsolicitedKeyMaxTimeout", "bootp.cl.ietf_ccc.dev_prov_unc_key_max_timeout",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_cl_ietf_ccc_dev_prov_unc_key_max_retries,
		  { "pktcMtaDevProvUnsolicitedKeyMaxRetries", "bootp.cl.ietf_ccc.dev_prov_unc_key_max_retries",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_ccc_ietf_sec_tkt_pc_provision_server,
		  { "Invalidate PacketCable Provisioning Server", "bootp.ccc.ietf.sec_tkt.pc_provision_server",
		    FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x01,
		    NULL, HFILL }},

		{ &hf_bootp_ccc_ietf_sec_tkt_all_pc_call_management,
		  { "Invalidate All PacketCable Call Management Servers", "bootp.ccc.ietf.sec_tkt.all_pc_call_management",
		    FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x02,
		    NULL, HFILL }},

		{ &hf_bootp_option242_avaya,
		  { "Private/Avaya IP Telephone",  "bootp.option.vendor.avaya",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 242: Private/Avaya IP Telephone", HFILL }},

		{ &hf_bootp_option242_avaya_tlssrvr,
		  { "TLSSRVR",  "bootp.option.vendor.avaya.tlssrvr",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 242: TLSSRVR (HTTPS server(s) to download configuration)", HFILL }},

		{ &hf_bootp_option242_avaya_httpsrvr,
		  { "HTTPSRVR",  "bootp.option.vendor.avaya.httpsrvr",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 242: HTTPSRVR (HTTP server(s) to download configuration)", HFILL }},

		{ &hf_bootp_option242_avaya_httpdir,
		  { "HTTPDIR",  "bootp.option.vendor.avaya.httpdir",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 242: HTTPDIR (Path to configuration files)", HFILL }},

		{ &hf_bootp_option242_avaya_static,
		  { "STATIC",  "bootp.option.vendor.avaya.static",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 242: STATIC (Static programming override flag)", HFILL }},

		{ &hf_bootp_option242_avaya_mcipadd,
		  { "MCIPADD",  "bootp.option.vendor.avaya.mcipadd",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 242: MCIPADD (List of CM server(s))", HFILL }},

		{ &hf_bootp_option242_avaya_dot1x,
		  { "DOT1X",  "bootp.option.vendor.avaya.dot1x",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 242: DOT1X (802.1X Supplicant operation mode)", HFILL }},

		{ &hf_bootp_option242_avaya_icmpdu,
		  { "ICMPDU",  "bootp.option.vendor.avaya.icmpdu",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 242: ICMPDU (ICMP Destination Unreachable processing)", HFILL }},

		{ &hf_bootp_option242_avaya_icmpred,
		  { "ICMPRED",  "bootp.option.vendor.avaya.icmpred",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 242: ICMPRED (ICMP Redirect handling)", HFILL }},

		{ &hf_bootp_option242_avaya_l2q,
		  { "L2Q",  "bootp.option.vendor.avaya.l2q",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 242: L2Q (Controls 802.1Q tagging)", HFILL }},

		{ &hf_bootp_option242_avaya_l2qvlan,
		  { "L2QVLAN",  "bootp.option.vendor.avaya.l2qvlan",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    "Option 242: L2QVLAN (VLAN ID)", HFILL }},

		{ &hf_bootp_option242_avaya_loglocal,
		  { "LOGLOCAL",  "bootp.option.vendor.avaya.loglocal",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 242: LOGLOCAL (Log level)", HFILL }},

		{ &hf_bootp_option242_avaya_phy1stat,
		  { "PHY1STAT",  "bootp.option.vendor.avaya.phy1stat",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 242: PHY1STAT (Interface configuration)", HFILL }},

		{ &hf_bootp_option242_avaya_phy2stat,
		  { "PHY2STAT",  "bootp.option.vendor.avaya.phy2stat",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 242: PHY2STAT (Interface configuration)", HFILL }},

		{ &hf_bootp_option242_avaya_procpswd,
		  { "PROCPSWD",  "bootp.option.vendor.avaya.procpswd",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 242: PROCPSWD (Security string used to access local procedures)", HFILL }},

		{ &hf_bootp_option242_avaya_procstat,
		  { "PROCSTAT",  "bootp.option.vendor.avaya.procstat",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 242: PROCSTAT (Local (dialpad) Administrative access)", HFILL }},

		{ &hf_bootp_option242_avaya_snmpadd,
		  { "SNMPADD",  "bootp.option.vendor.avaya.snmpadd",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 242: SNMPADD (Allowable source IP Address(es) for SNMP queries)", HFILL }},

		{ &hf_bootp_option242_avaya_snmpstring,
		  { "SNMPSTRING",  "bootp.option.vendor.avaya.snmpstring",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    "Option 242: SNMPSTRING (SNMP community string)", HFILL }},

		{ &hf_bootp_option242_avaya_vlantest,
		  { "VLANTEST",  "bootp.option.vendor.avaya.vlantest",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    "Option 242: VLANTEST (Timeout in seconds)", HFILL }},
	};

	static uat_field_t bootp_uat_flds[] = {
		UAT_FLD_DEC(uat_bootp_records, opt, "Option number", "Custom Option Number"),
		UAT_FLD_CSTRING(uat_bootp_records, text, "Option Name", "Custom Option Name"),
		UAT_FLD_VS(uat_bootp_records, ftype, "Option type", bootp_custom_type_vals, "Option datatype"),
		UAT_END_FIELDS
	};

	static gint *ett[] = {
		&ett_bootp,
		&ett_bootp_flags,
		&ett_bootp_option,
		&ett_bootp_option43_suboption,
		&ett_bootp_option63_suboption,
		&ett_bootp_option77_instance,
		&ett_bootp_option82_suboption,
		&ett_bootp_option82_suboption9,
		&ett_bootp_option125_suboption,
		&ett_bootp_option125_tr111_suboption,
		&ett_bootp_option125_cl_suboption,
		&ett_bootp_option242_suboption,
		&ett_bootp_fqdn,
		&ett_bootp_filename_option,
		&ett_bootp_server_hostname,
		&ett_bootp_fqdn_flags,
		&ett_bootp_isns_functions,
		&ett_bootp_isns_discovery_domain_access,
		&ett_bootp_isns_administrative_flags,
		&ett_bootp_isns_server_security_bitmap,
		&ett_bootp_isns_secondary_server_addr,
		&ett_bootp_o43_bsdp_boot_image,
		&ett_bootp_o43_bsdp_attributes,
		&ett_bootp_o43_bsdp_image_desc_list,
		&ett_bootp_o43_bsdp_image_desc,
		&ett_bootp_o43_bsdp_attributes_flags,
	};

	static ei_register_info ei[] = {
		{ &ei_bootp_bad_length, { "bootp.bad_length", PI_PROTOCOL, PI_ERROR, "length isn't 0", EXPFILL }},
		{ &ei_bootp_bad_bitfield, { "bootp.bad_bitfield", PI_PROTOCOL, PI_ERROR, "Bogus bitfield", EXPFILL }},
		{ &ei_bootp_missing_subopt_length, { "bootp.missing_subopt_length", PI_PROTOCOL, PI_ERROR, "no room left in option for suboption length", EXPFILL }},
		{ &ei_bootp_missing_subopt_value, { "bootp.missing_subopt_value", PI_PROTOCOL, PI_ERROR, "no room left in option for suboption value", EXPFILL }},
		{ &ei_bootp_mal_duid, { "bootp.malformed.duid", PI_PROTOCOL, PI_ERROR, "DUID: malformed option", EXPFILL }},
		{ &hf_bootp_opt_overload_file_end_missing, { "bootp.option.option_overload.file_end_missing", PI_PROTOCOL, PI_ERROR, "file overload end option missing", EXPFILL }},
		{ &hf_bootp_opt_overload_sname_end_missing, { "bootp.option.option_overload.sname_end_missing", PI_PROTOCOL, PI_ERROR, "sname overload end option missing", EXPFILL }},
		{ &hf_bootp_subopt_unknown_type, { "bootp.subopt.unknown_type", PI_PROTOCOL, PI_ERROR, "ERROR, please report: Unknown subopt type handler", EXPFILL }},
		{ &ei_bootp_option77_user_class_malformed, { "bootp.option.user_class.malformed", PI_PROTOCOL, PI_ERROR, "User Class Information: malformed option", EXPFILL }},
		{ &ei_bootp_option_civic_location_bad_cattype, { "bootp.option.civic_location.bad_cattype", PI_PROTOCOL, PI_ERROR, "Error with CAType", EXPFILL }},
		{ &ei_bootp_option_dhcp_name_service_invalid, { "bootp.option.dhcp_name_service.invalid", PI_PROTOCOL, PI_ERROR, "Invalid Name Service", EXPFILL }},
		{ &ei_bootp_option_sip_server_address_encoding, { "bootp.option.sip_server_address.encoding", PI_PROTOCOL, PI_ERROR, "RFC 3361 defines only 0 and 1 for Encoding byte", EXPFILL }},
		{ &ei_bootp_option_classless_static_route, { "bootp.option.classless_static.route", PI_PROTOCOL, PI_ERROR, "Mask width > 32", EXPFILL }},
		{ &ei_bootp_option125_enterprise_malformed, { "bootp.option.enterprise.malformed", PI_PROTOCOL, PI_ERROR, "no room left in option for enterprise data", EXPFILL }},
		{ &ei_bootp_option_6RD_malformed, { "bootp.option.6RD.malformed", PI_PROTOCOL, PI_ERROR, "6RD: malformed option", EXPFILL }},
		{ &ei_bootp_option82_vi_cl_tag_unknown, { "bootp.option.option.vi.cl.tag_unknown", PI_PROTOCOL, PI_ERROR, "Unknown tag", EXPFILL }},
		{ &ei_bootp_option_parse_err, { "bootp.option.parse_err", PI_PROTOCOL, PI_ERROR, "Parse error", EXPFILL }},
		{ &ei_bootp_suboption_invalid, { "bootp.suboption_invalid", PI_PROTOCOL, PI_ERROR, "Invalid suboption", EXPFILL }},
		{ &ei_bootp_secs_le, { "bootp.secs_le", PI_PROTOCOL, PI_NOTE, "Seconds elapsed appears to be encoded as little-endian", EXPFILL }},
		{ &ei_bootp_end_option_missing, { "bootp.end_option_missing", PI_PROTOCOL, PI_ERROR, "End option missing", EXPFILL }},
		{ &ei_bootp_client_address_not_given, { "bootp.client_address_not_given", PI_PROTOCOL, PI_NOTE, "Client address not given", EXPFILL }},
		{ &ei_bootp_server_name_overloaded_by_dhcp, { "bootp.server_name_overloaded_by_dhcp", PI_PROTOCOL, PI_NOTE, "Server name option overloaded by DHCP", EXPFILL }},
		{ &ei_bootp_boot_filename_overloaded_by_dhcp, { "bootp.boot_filename_overloaded_by_dhcp", PI_PROTOCOL, PI_NOTE, "Boot file name option overloaded by DHCP", EXPFILL }},
		{ &ei_bootp_option_isns_ignored_bitfield, { "bootp.option.isns.ignored_bitfield", PI_PROTOCOL, PI_NOTE, "Enabled field is not set - non-zero bitmask ignored", EXPFILL }},
	};

	static tap_param bootp_stat_params[] = {
		{ PARAM_FILTER, "filter", "Filter", NULL, TRUE }
	};

	static stat_tap_table_ui bootp_stat_table = {
		REGISTER_STAT_GROUP_UNSORTED,
		"DHCP (BOOTP) Statistics",
		"bootp",
		"bootp,stat",
		bootp_stat_init,
		bootp_stat_packet,
		bootp_stat_reset,
		NULL,
		NULL,
		sizeof(bootp_stat_fields)/sizeof(stat_tap_table_item), bootp_stat_fields,
		sizeof(bootp_stat_params)/sizeof(tap_param), bootp_stat_params,
		NULL,
		0
	};

	module_t *bootp_module;
	expert_module_t* expert_bootp;

	proto_bootp = proto_register_protocol("Bootstrap Protocol", "BOOTP/DHCP",
					      "bootp");
	proto_register_field_array(proto_bootp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	bootp_dhcp_tap = register_tap("bootp");

	expert_bootp = expert_register_protocol(proto_bootp);
	expert_register_field_array(expert_bootp, ei, array_length(ei));

	/* register init routine to setup the custom bootp options */
	register_init_routine(&bootp_init_protocol);

	/* Allow dissector to find be found by name. */
	bootp_handle = register_dissector("bootp", dissect_bootp, proto_bootp);

	bootp_module = prefs_register_protocol(proto_bootp, NULL);

	prefs_register_bool_preference(bootp_module, "novellserverstring",
				       "Decode Option 85 as String",
				       "Novell Servers option 85 can be configured as a string instead of address",
				       &novell_string);

	prefs_register_enum_preference(bootp_module, "pkt.ccc.protocol_version",
				       "PacketCable CCC protocol version",
				       "The PacketCable CCC protocol version",
				       &pkt_ccc_protocol_version,
				       pkt_ccc_protocol_versions,
				       FALSE);

	prefs_register_uint_preference(bootp_module, "pkt.ccc.option",
				       "PacketCable CCC option",
				       "Option Number for PacketCable CableLabs Client Configuration",
				       10,
				       &pkt_ccc_option);

	prefs_register_enum_preference(bootp_module, "uuid.endian",
				       "Endianness of UUID",
				       "Endianness applied to UUID fields",
				       &bootp_uuid_endian,
				       bootp_uuid_endian_vals,
				       FALSE);

	prefs_register_obsolete_preference(bootp_module, "displayasstring");

	bootp_uat = uat_new("Custom BootP/DHCP Options (Excl. suboptions)",
			sizeof(uat_bootp_record_t), /* record size	     */
			"custom_bootp",		    /* filename		     */
			TRUE,			    /* from_profile	     */
			&uat_bootp_records,	    /* data_ptr		     */
			&num_bootp_records_uat,	    /* numitems_ptr	     */
			UAT_AFFECTS_DISSECTION,	    /* affects dissection of packets, but not set of named fields */
			NULL,			    /* help		     */
			uat_bootp_record_copy_cb,   /* copy callback	     */
			uat_bootp_record_update_cb, /* update callback	     */
			uat_bootp_record_free_cb,   /* free callback	     */
			NULL,			    /* post update callback  */
			bootp_uat_flds);	    /* UAT field definitions */

	prefs_register_uat_preference(bootp_module,
				      "custom_bootp_table",
				      "Custom BootP/DHCP Options (Excl. suboptions)",
				      "Custom BootP/DHCP Options (Excl. suboptions)",
				      bootp_uat);

	register_stat_tap_table_ui(&bootp_stat_table);
}

void
proto_reg_handoff_bootp(void)
{
	dissector_add_uint("udp.port", UDP_PORT_BOOTPS, bootp_handle);
	dissector_add_uint("udp.port", UDP_PORT_BOOTPC, bootp_handle);
}

/*
 * Editor modelines  -	http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
