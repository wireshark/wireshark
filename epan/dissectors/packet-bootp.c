/* packet-bootp.c
 * Routines for BOOTP/DHCP packet disassembly
 * Copyright 1998, Gilbert Ramirez <gram@alumni.rice.edu>
 * Copyright 2004, Thomas Anders <thomas.anders [AT] blue-cable.de>
 *
 * $Id$
 *
 * The information used comes from:
 * RFC  951: Bootstrap Protocol
 * RFC 1497: BOOTP extensions
 * RFC 1542: Clarifications and Extensions for the Bootstrap Protocol
 * RFC 2131: Dynamic Host Configuration Protocol
 * RFC 2132: DHCP Options and BOOTP Vendor Extensions
 * RFC 2241: DHCP Options for Novell Directory Services
 * RFC 2242: NetWare/IP Domain Name and Information
 * RFC 2489: Procedure for Defining New DHCP Options
 * RFC 2610: DHCP Options for Service Location Protocol
 * RFC 3046: DHCP Relay Agent Information Option
 * RFC 3118: Authentication for DHCP Messages
 * RFC 3203: DHCP reconfigure extension
 * RFC 3315: Dynamic Host Configuration Protocol for IPv6 (DHCPv6)
 * RFC 3495: DHCP Option (122) for CableLabs Client Configuration
 * RFC 3594: PacketCable Security Ticket Control Sub-Option (122.9)
 * RFC 3442: Classless Static Route Option for DHCP version 4
 * RFC 3825: Dynamic Host Configuration Protocol Option for Coordinate-based Location Configuration Information
 * RFC 3925: Vendor-Identifying Vendor Options for Dynamic Host Configuration Protocol version 4 (DHCPv4)
 * RFC 3942: Reclassifying DHCPv4 Options
 * RFC 4243: Vendor-Specific Information Suboption for the Dynamic Host Configuration Protocol (DHCP) Relay Agent Option
 * RFC 4361: Node-specific Client Identifiers for Dynamic Host Configuration Protocol Version Four (DHCPv4)
 * RFC 4388: Dynamic Host Configuration Protocol (DHCP) Leasequery
 * RFC 4578: Dynamic Host Configuration Protocol (DHCP) Options for PXE
 * RFC 4776: Dynamic Host Configuration Protocol (DHCPv4 and DHCPv6) Option for Civic Addresses Configuration Information
 * RFC 5223: Discovering Location-to-Service Translation (LoST) Servers Using the Dynamic Host Configuration Protocol (DHCP)
 * RFC 5417: CAPWAP Access Controller DHCP Option
 * RFC 5969: IPv6 Rapid Deployment on IPv4 Infrastructures (6rd)
 * draft-ietf-dhc-fqdn-option-07.txt
 * TFTP Server Address Option for DHCPv4 [draft-raj-dhc-tftp-addr-option-06.txt: http://tools.ietf.org/html/draft-raj-dhc-tftp-addr-option-06]
 * BOOTP and DHCP Parameters
 *     http://www.iana.org/assignments/bootp-dhcp-parameters
 * DOCSIS(TM) 2.0 Radio Frequency Interface Specification
 *     http://www.cablelabs.com/specifications/CM-SP-RFI2.0-I11-060602.pdf
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

/*
 * Some of the development of the BOOTP/DHCP protocol decoder was sponsored by
 * Cable Television Laboratories, Inc. ("CableLabs") based upon proprietary
 * CableLabs' specifications. Your license and use of this protocol decoder
 * does not mean that you are licensed to use the CableLabs'
 * specifications.  If you have questions about this protocol, contact
 * jf.mule [AT] cablelabs.com or c.stuart [AT] cablelabs.com for additional
 * information.
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include "packet-arp.h"
#include "packet-dns.h"				/* for get_dns_name() */
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/strutil.h>
#include <epan/arptypes.h>
#include <epan/sminmpec.h>
#include <epan/expert.h>


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
static int hf_bootp_vendor = -1;
static int hf_bootp_dhcp = -1;
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
static int hf_bootp_docsis_cm_cap_type = -1;
static int hf_bootp_docsis_cm_cap_len = -1;
static int hf_bootp_alu_vid = -1;
static int hf_bootp_alu_tftp1 = -1;
static int hf_bootp_alu_tftp2 = -1;
static int hf_bootp_alu_app_type = -1;
static int hf_bootp_alu_sip_url = -1;
static int hf_bootp_client_identifier_uuid = -1;
static int hf_bootp_client_network_id_major_ver = -1;
static int hf_bootp_client_network_id_minor_ver = -1;
static int hf_bootp_option_type = -1;
static int hf_bootp_option_length = -1;
static int hf_bootp_option_value = -1;

static gint ett_bootp = -1;
static gint ett_bootp_flags = -1;
static gint ett_bootp_option = -1;
static gint ett_bootp_fqdn = -1;

static const char *pref_optionstring = "";

/* RFC3825decoder error codes of the conversion function */
#define RFC3825_NOERROR                           0
#define RFC3825_LATITUDE_OUTOFRANGE               1
#define RFC3825_LATITUDE_UNCERTAINTY_OUTOFRANGE   2
#define RFC3825_LONGITUDE_OUTOFRANGE              3
#define RFC3825_LONGITUDE_UNCERTAINTY_OUTOFRANGE  4
#define RFC3825_ALTITUDE_OUTOFRANGE               5
#define RFC3825_ALTITUDE_UNCERTAINTY_OUTOFRANGE   6
#define RFC3825_ALTITUDE_TYPE_OUTOFRANGE          7
#define RFC3825_DATUM_TYPE_OUTOFRANGE             8

#define	DUID_LLT		1
#define	DUID_EN			2
#define	DUID_LL			3

struct rfc3825_location_fixpoint_t {

	gint64 latitude;        /* latitude in degrees, allowed range from -90deg to 90deg.
				   Fixpoint A(8,25) with 34 bits */
	guint8 latitude_res;    /* the resolution of the latitude in bits, allowed range is from 0 to 34.
				   6 bits. */
	gint64 longitude;       /* longitude in degrees, range from -180deg to 180deg.
				   Fixpoint A(8,25) with 34 bits */
	guint8 longitude_res;   /* the resolution of the longitude in bits, allowed range is from 0 to 34.
				   6 bits. */
	gint32 altitude;        /* the altitude, 30 bits.
				   Depending on alt_type this are meters or floors, no range limit.
				   altitude_type==1: A(13,8) with 22 bits
				   altitude_type==2: A(13,8) with 22 bits */
	guint8 altitude_res;    /* the resolution of the altitude in bits, allowed range is from 0 to 30.
				   6 bits.
				   altitude_type==1: any value between 0 and 30
				   altitude_type==2: either 0 (floor unknown) or 30 */
	guint8 altitude_type;   /* the type of the altitude, 4 bits. allowed values are:
				   0: unknown
				   1: altitude in meters
				   2: altitude in floors */
	guint8 datum_type;      /* the map datum used for the coordinates. 8 bits.
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

	double latitude;        /* latitude in degrees, allowed range from -90deg to 90deg */
	double latitude_res;    /* the uncertainty of the latitude in grad, "0.01" means +-0.01deg
				   from the altitude. During conversion this will be rounded to
				   next smaller value which can be respresented in fixpoint arithmetic */
	double longitude;       /* longitude in degrees, range from -180deg to 180deg */
	double longitude_res;   /* the uncertainty of the longitude in grad, "0.01" means +-0.01deg
				   from the longitude. During conversion this will be rounded to
				   next smaller value which can be respresented in fixpoint arithmetic */
	double altitude;        /* the altitude, depending on alt_type this are meters or floors, no range limit */
	double altitude_res;    /* the uncertainty of the altitude in either:
				   - altitude-type=meters: "10" means 10 meters which means +-10 meters from the altitude
				   - altitude-type=floors: either 0 (unknown) or 30 (exact) */
	int altitude_type;      /* the type of the altitude, allowed values are
				   0: unknown
				   1: altitude in meters
				   2: altitude in floors */
	int datum_type;          /* the map datum used for the coordinates.
				    All values are allowed although currently only the
				    following ones are defined:
				    1: WGS84
				    2: NAD83/NAVD88
				    3: NAD83/MLLW */
};

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
	{0,	"DoNotAutoConfigure"},
	{1,	"AutoConfigure"},
	{0,	NULL }
};

/* Error Types for RFC 3825 coordinate location decoding */
static const value_string rfc3825_error_types[] = {
	{1,	"Latitude is out of range [-90,90]"},
	{2,	"Latitude Uncertainty is out of range [0,90]"},
	{3,	"Longitude is out of range [-180,180]"},
	{4,	"Longitude Uncertainty is out of range [0,180]"},
	{5,	"Altitude is out of range [-(2^21),(2^21)-1]"},
	{6,	"Altitude Uncertainty is out of range [0,2^20]"},
	{7,	"Altitude Type is out of range [0,2]"},
	{8,	"Datum is out of range [1,3]"},
	{0,	NULL }
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
	{ 0,	"Language" },
	{ 1,	"A1" },
	{ 2,	"A2" },
	{ 3,	"A3" },
	{ 4,	"A4" },
	{ 5,	"A5" },
	{ 6,	"A6" },
	{ 16,	"PRD (Leading street direction)" },
	{ 17,	"POD (Trailing street suffix)" },
	{ 18,	"STS (Street suffix)" },
	{ 19,	"HNO (House number)" },
	{ 20,	"HNS (House number suffix)" },
	{ 21,	"LMK (Landmark or vanity address)" },
	{ 22,	"LOC (Additional location information)" },
	{ 23,	"NAM" },
	{ 24, 	"PC (Postal/ZIP code)" },
	{ 25,	"BLD (Building)" },
	{ 26,	"UNIT" },
	{ 27,	"FLR (Floor)" },
	{ 28,	"ROOM" },
	{ 29,	"PLC (Place-type)" },
	{ 30,	"PCN (Postal community name)" },
	{ 31,   "POBOX" },
	{ 32,	"ADDCODE (Additional Code)" },
	{ 33,	"SEAT" },
	{ 34,	"RD (Primary road or street)" },
	{ 35,	"RDSEC (Road section)" },
	{ 36,	"RDBR (Road branch)" },
	{ 37,	"RDSUBBR (Road sub-branch)" },
	{ 38,	"PRM (Road pre-modifier)" },
	{ 39,	"POM (Road post-modifier" },
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

#define UDP_PORT_BOOTPS  67
#define UDP_PORT_BOOTPC  68

#define BOOTP_BC	0x8000
#define BOOTP_MBZ	0x7FFF

/* FQDN stuff */
#define F_FQDN_S	0x01
#define F_FQDN_O	0x02
#define F_FQDN_E	0x04
#define F_FQDN_N	0x08
#define F_FQDN_MBZ	0xf0

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
	ipv4_or_fqdn
};

struct opt_info {
	const char	*text;
	enum field_type ftype;
	const void	*data;
};

static const true_false_string flag_set_broadcast = {
	"Broadcast",
	"Unicast"
};


/* PacketCable/DOCSIS definitions */
#define PACKETCABLE_MTA_CAP10 "pktc1.0:"
#define PACKETCABLE_MTA_CAP15 "pktc1.5:"
#define PACKETCABLE_MTA_CAP20 "pktc2.0:"
#define PACKETCABLE_CM_CAP11  "docsis1.1:"
#define PACKETCABLE_CM_CAP20  "docsis2.0:"
#define PACKETCABLE_CM_CAP30  "docsis3.0:"

#define PACKETCABLE_CCC_I05      1
#define PACKETCABLE_CCC_DRAFT5   2
#define PACKETCABLE_CCC_RFC_3495 3

static enum_val_t pkt_ccc_protocol_versions[] = {
	{ "ccc_i05",     "PKT-SP-PROV-I05-021127", PACKETCABLE_CCC_I05 },
	{ "ccc_draft_5", "IETF Draft 5",           PACKETCABLE_CCC_DRAFT5 },
	{ "rfc_3495",    "RFC 3495",               PACKETCABLE_CCC_RFC_3495 },
	{ NULL, NULL, 0 }
};

static gint pkt_ccc_protocol_version = PACKETCABLE_CCC_RFC_3495;
static guint pkt_ccc_option = 122;


static int dissect_vendor_pxeclient_suboption(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend);
static int dissect_vendor_cablelabs_suboption(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend);
static int dissect_vendor_alcatel_suboption(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend);
static int dissect_netware_ip_suboption(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend);
static int dissect_vendor_tr111_suboption(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend);
static int bootp_dhcp_decode_agent_info(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend);
static void dissect_packetcable_mta_cap(proto_tree *v_tree, tvbuff_t *tvb,
       int voff, int len);
static void dissect_docsis_cm_cap(proto_tree *v_tree, tvbuff_t *tvb,
       int voff, int len, gboolean opt125);
static int dissect_packetcable_i05_ccc(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend);
static int dissect_packetcable_ietf_ccc(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend, int revision);
static int dissect_vendor_cl_suboption(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend);

#define OPT53_DISCOVER "Discover"
/* http://www.iana.org/assignments/bootp-dhcp-parameters */
static const value_string opt53_text[] = {
	{ 1,	OPT53_DISCOVER },
	{ 2,	"Offer" },
	{ 3,	"Request" },
	{ 4,	"Decline" },
	{ 5,	"ACK" },
	{ 6,	"NAK" },
	{ 7,	"Release" },
	{ 8,	"Inform" },
	{ 9,	"Force Renew" },
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
#define SERVER_NAME_LEN 		64
#define FILE_NAME_OFFSET		108
#define FILE_NAME_LEN			128
#define VENDOR_INFO_OFFSET		236

static const value_string bootp_nbnt_vals[] = {
	{0x1,   "B-node" },
	{0x2,   "P-node" },
	{0x4,   "M-node" },
	{0x8,   "H-node" },
	{0,     NULL     }
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
	{ 0,      NULL }
};

/* bootp options administration */
#define BOOTP_OPT_NUM   256

/* Re-define structure.  Values to be upated by bootp_init_protocol */
static struct opt_info bootp_opt[BOOTP_OPT_NUM];

static struct opt_info default_bootp_opt[BOOTP_OPT_NUM] = {
/*   0 */ { "Padding",					none, NULL },
/*   1 */ { "Subnet Mask",				ipv4, NULL },
/*   2 */ { "Time Offset",				time_in_s_secs, NULL },
/*   3 */ { "Router",					ipv4_list, NULL },
/*   4 */ { "Time Server",				ipv4_list, NULL },
/*   5 */ { "Name Server",				ipv4_list, NULL },
/*   6 */ { "Domain Name Server",			ipv4_list, NULL },
/*   7 */ { "Log Server",				ipv4_list, NULL },
/*   8 */ { "Quotes Server",				ipv4_list, NULL },
/*   9 */ { "LPR Server",				ipv4_list, NULL },
/*  10 */ { "Impress Server",				ipv4_list, NULL },
/*  11 */ { "Resource Location Server",			ipv4_list, NULL },
/*  12 */ { "Host Name",				string, NULL },
/*  13 */ { "Boot File Size",				val_u_short, NULL },
/*  14 */ { "Merit Dump File",				string, NULL },
/*  15 */ { "Domain Name",				string, NULL },
/*  16 */ { "Swap Server",				ipv4, NULL },
/*  17 */ { "Root Path",				string, NULL },
/*  18 */ { "Extensions Path",				string, NULL },
/*  19 */ { "IP Forwarding",				val_boolean, TFS(&tfs_enabled_disabled) },
/*  20 */ { "Non-Local Source Routing",			val_boolean, TFS(&tfs_enabled_disabled) },
/*  21 */ { "Policy Filter",				special, NULL },
/*  22 */ { "Maximum Datagram Reassembly Size",		val_u_short, NULL },
/*  23 */ { "Default IP Time-to-Live",			val_u_byte, NULL },
/*  24 */ { "Path MTU Aging Timeout",			time_in_u_secs, NULL },
/*  25 */ { "Path MTU Plateau Table",			val_u_short_list, NULL },
/*  26 */ { "Interface MTU",				val_u_short, NULL },
/*  27 */ { "All Subnets are Local",			val_boolean, TFS(&tfs_yes_no) },
/*  28 */ { "Broadcast Address",			ipv4, NULL },
/*  29 */ { "Perform Mask Discovery",			val_boolean, TFS(&tfs_enabled_disabled) },
/*  30 */ { "Mask Supplier",				val_boolean, TFS(&tfs_yes_no) },
/*  31 */ { "Perform Router Discover",			val_boolean, TFS(&tfs_enabled_disabled) },
/*  32 */ { "Router Solicitation Address",		ipv4, NULL },
/*  33 */ { "Static Route",				special, NULL },
/*  34 */ { "Trailer Encapsulation",			val_boolean, TFS(&tfs_enabled_disabled) },
/*  35 */ { "ARP Cache Timeout",			time_in_u_secs, NULL },
/*  36 */ { "Ethernet Encapsulation",			val_boolean, TFS(&tfs_enabled_disabled) },
/*  37 */ { "TCP Default TTL", 				val_u_byte, NULL },
/*  38 */ { "TCP Keepalive Interval",			time_in_u_secs, NULL },
/*  39 */ { "TCP Keepalive Garbage",			val_boolean, TFS(&tfs_enabled_disabled) },
/*  40 */ { "Network Information Service Domain",	string, NULL },
/*  41 */ { "Network Information Service Servers",	ipv4_list, NULL },
/*  42 */ { "Network Time Protocol Servers",		ipv4_list, NULL },
/*  43 */ { "Vendor-Specific Information",		special, NULL },
/*  44 */ { "NetBIOS over TCP/IP Name Server",		ipv4_list, NULL },
/*  45 */ { "NetBIOS over TCP/IP Datagram Distribution Name Server", ipv4_list, NULL },
/*  46 */ { "NetBIOS over TCP/IP Node Type",		val_u_byte, VALS(bootp_nbnt_vals) },
/*  47 */ { "NetBIOS over TCP/IP Scope",		string, NULL },
/*  48 */ { "X Window System Font Server",		ipv4_list, NULL },
/*  49 */ { "X Window System Display Manager",		ipv4_list, NULL },
/*  50 */ { "Requested IP Address",			ipv4, NULL },
/*  51 */ { "IP Address Lease Time",			time_in_u_secs, NULL },
/*  52 */ { "Option Overload",				special, NULL },
/*  53 */ { "DHCP Message Type",			special, NULL },
/*  54 */ { "DHCP Server Identifier",			ipv4, NULL },
/*  55 */ { "Parameter Request List",			special, NULL },
/*  56 */ { "Message",					string, NULL },
/*  57 */ { "Maximum DHCP Message Size",		val_u_short, NULL },
/*  58 */ { "Renewal Time Value",			time_in_u_secs, NULL },
/*  59 */ { "Rebinding Time Value",			time_in_u_secs, NULL },
/*  60 */ { "Vendor class identifier",			special, NULL },
/*  61 */ { "Client identifier",			special, NULL },
/*  62 */ { "Novell/Netware IP domain",			string, NULL },
/*  63 */ { "Novell Options",				special, NULL },
/*  64 */ { "Network Information Service+ Domain",	string, NULL },
/*  65 */ { "Network Information Service+ Servers",	ipv4_list, NULL },
/*  66 */ { "TFTP Server Name",				string, NULL },
/*  67 */ { "Bootfile name",				string, NULL },
/*  68 */ { "Mobile IP Home Agent",			ipv4_list, NULL },
/*  69 */ { "SMTP Server",				ipv4_list, NULL },
/*  70 */ { "POP3 Server",				ipv4_list, NULL },
/*  71 */ { "NNTP Server",				ipv4_list, NULL },
/*  72 */ { "Default WWW Server",			ipv4_list, NULL },
/*  73 */ { "Default Finger Server",			ipv4_list, NULL },
/*  74 */ { "Default IRC Server",			ipv4_list, NULL },
/*  75 */ { "StreetTalk Server",			ipv4_list, NULL },
/*  76 */ { "StreetTalk Directory Assistance Server",	ipv4_list, NULL },
/*  77 */ { "User Class Information",			opaque, NULL },
/*  78 */ { "Directory Agent Information",		special, NULL },
/*  79 */ { "Service Location Agent Scope",		special, NULL },
/*  80 */ { "Rapid commit",				opaque, NULL },
/*  81 */ { "Client Fully Qualified Domain Name",	special, NULL },
/*  82 */ { "Agent Information Option",                 special, NULL },
/*  83 */ { "iSNS [TODO:RFC4174]",			opaque, NULL },
/*  84 */ { "Removed/Unassigned",			opaque, NULL },
/*  85 */ { "Novell Directory Services Servers",	special, NULL },
/*  86 */ { "Novell Directory Services Tree Name",	string, NULL },
/*  87 */ { "Novell Directory Services Context",	string, NULL },
/*  88 */ { "BCMCS Controller Domain Name [TODO:RFC4280]",	opaque, NULL },
/*  89 */ { "BCMCS Controller IPv4 address [TODO:RFC4280]",	opaque, NULL },
/*  90 */ { "Authentication",				special, NULL },
/*  91 */ { "Client last transaction time",		time_in_u_secs, NULL },
/*  92 */ { "Associated IP option",			ipv4_list, NULL },
/*  93 */ { "Client System Architecture",		val_u_short, VALS(bootp_client_arch) },
/*  94 */ { "Client Network Device Interface",		special, NULL },
/*  95 */ { "LDAP [TODO:RFC3679]",			opaque, NULL },
/*  96 */ { "Removed/Unassigend",			opaque, NULL },
/*  97 */ { "UUID/GUID-based Client Identifier",	special, NULL },
/*  98 */ { "Open Group's User Authentication [TODO:RFC2485]",	opaque, NULL },
/*  99 */ { "Civic Addresses Configuration",		special, NULL },
/* 100 */ { "PCode [TODO:RFC4833]",			opaque, NULL },
/* 101 */ { "TCode [TODO:RFC4833]",			opaque, NULL },
/* 102 */ { "Removed/unassigned",			opaque, NULL },
/* 103 */ { "Removed/unassigned",			opaque, NULL },
/* 104 */ { "Removed/unassigned",			opaque, NULL },
/* 105 */ { "Removed/unassigned",			opaque, NULL },
/* 106 */ { "Removed/unassigned",			opaque, NULL },
/* 107 */ { "Removed/unassigned",			opaque, NULL },
/* 108 */ { "Removed/Unassigend",			opaque, NULL },
/* 109 */ { "Unassigned",				opaque, NULL },
/* 110 */ { "Removed/Uassigend",			opaque, NULL },
/* 111 */ { "Unassigned",				opaque, NULL },
/* 112 */ { "NetInfo Parent Server Address",		ipv4_list, NULL },
/* 113 */ { "NetInfo Parent Server Tag",		string, NULL },
/* 114 */ { "URL [TODO:RFC3679]",			opaque, NULL },
/* 115 */ { "Removed/Unassigend",			opaque, NULL },
/* 116 */ { "DHCP Auto-Configuration",			val_u_byte, VALS(dhcp_autoconfig) },
/* 117 */ { "Name Service Search [TODO:RFC2937]",      	opaque, NULL },
/* 118 */ { "Subnet Selection Option",		       	ipv4_list, NULL },
/* 119 */ { "Domain Search [TODO:RFC3397]",		opaque, NULL },
/* 120 */ { "SIP Servers [TODO:RFC3361]",		opaque, NULL },
/* 121 */ { "Classless Static Route",		       	special, NULL },
/* 122 */ { "CableLabs Client Configuration [TODO:RFC3495]",	opaque, NULL },
/* 123 */ { "Coordinate-based Location Configuration",	special, NULL },
/* 124 */ { "V-I Vendor Class",				special, NULL },
/* 125 */ { "V-I Vendor-specific Information",		special, NULL },
/* 126 */ { "Removed/Unassigned",			opaque, NULL },
/* 127 */ { "Removed/Unassigend",			opaque, NULL },
/* 128 */ { "DOCSIS full security server IP [TODO]",	opaque, NULL },
/* 129 */ { "PXE - undefined (vendor specific)",	opaque, NULL },
/* 130 */ { "PXE - undefined (vendor specific)",	opaque, NULL },
/* 131 */ { "PXE - undefined (vendor specific)",	opaque, NULL },
/* 132 */ { "PXE - undefined (vendor specific)",	opaque, NULL },
/* 133 */ { "PXE - undefined (vendor specific)",	opaque, NULL },
/* 134 */ { "PXE - undefined (vendor specific)",	opaque, NULL },
/* 135 */ { "PXE - undefined (vendor specific)",	opaque, NULL },
/* 136 */ { "OPTION_PANA_AGENT [TODO:RFC5192]",		opaque, NULL },
/* 137 */ { "LoST Server Domain Name",			string, NULL },
/* 138 */ { "CAPWAP Access Controllers",		ipv4_list, NULL },
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
/* 150 */ { "TFTP Server Address",			ipv4_list, NULL },
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
/* 209 */ { "Configuration file",			opaque, NULL },
/* 210 */ { "Authentication",				special, NULL }, /* Path Prefix rfc5071 */
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
/* 242 */ { "Private",					opaque, NULL },
/* 243 */ { "Private",					opaque, NULL },
/* 244 */ { "Private",					opaque, NULL },
/* 245 */ { "Private",					opaque, NULL },
/* 246 */ { "Private",					opaque, NULL },
/* 247 */ { "Private",					opaque, NULL },
/* 248 */ { "Private",					opaque, NULL },
/* 249 */ { "Private/Classless Static Route (Microsoft)",	special, NULL },
/* 250 */ { "Private",					opaque, NULL },
/* 251 */ { "Private",					opaque, NULL },
/* 252 */ { "Private/Proxy autodiscovery",			string, NULL },
/* 253 */ { "Private",					opaque, NULL },
/* 254 */ { "Private",					opaque, NULL },
/* 255 */ { "End",					opaque, NULL }
};

static const char *
bootp_get_opt_text(unsigned int idx)
{
	if(idx>=BOOTP_OPT_NUM)
		return "unknown";
	return bootp_opt[idx].text;
}

static const void *
bootp_get_opt_data(unsigned int idx)
{
	if(idx>=BOOTP_OPT_NUM)
		return NULL;
	return bootp_opt[idx].data;
}

static enum field_type
bootp_get_opt_ftype(unsigned int idx)
{
	if(idx>=BOOTP_OPT_NUM)
		return none;
	return bootp_opt[idx].ftype;
}


/* Returns the number of bytes consumed by this option. */
static int
bootp_option(tvbuff_t *tvb, packet_info *pinfo, proto_tree *bp_tree, int voff,
    int eoff, gboolean first_pass, gboolean *at_end, const char **dhcp_type_p,
    const guint8 **vendor_class_id_p, guint8 *overload_p)
{
	const char		*text;
	enum field_type		ftype;
	guchar			code = tvb_get_guint8(tvb, voff);
	int			optlen;
	const struct true_false_string *tfs;
	const value_string	*vs;
	guchar			byte;
	int			i, consumed;
	int			optoff, optleft, optend;
	guint32			time_u_secs;
	gint32			time_s_secs;
	proto_tree		*v_tree;
	proto_item		*vti;
	guint8			protocol;
	guint8			algorithm;
	guint8			rdm;
	guint8			fqdn_flags;
	int			o52voff, o52eoff;
	gboolean		o52at_end;
	guint8			s_option;
	guint8			s_len;
	const guchar		*dns_name;


	static const value_string slpda_vals[] = {
		{0x00,   "Dynamic Discovery" },
		{0x01,   "Static Discovery" },
		{0x80,   "Backwards compatibility" },
		{0,     NULL     } };

	static const value_string slp_scope_vals[] = {
		{0x00,   "Preferred Scope" },
		{0x01,   "Mandatory Scope" },
		{0,     NULL     } };

	static const value_string authen_protocol_vals[] = {
		{AUTHEN_PROTO_CONFIG_TOKEN,   "configuration token" },
		{AUTHEN_PROTO_DELAYED_AUTHEN, "delayed authentication" },
		{0,                           NULL     } };

	static const value_string authen_da_algo_vals[] = {
		{AUTHEN_DELAYED_ALGO_HMAC_MD5, "HMAC_MD5" },
		{0,                            NULL     } };

	static const value_string authen_rdm_vals[] = {
		{AUTHEN_RDM_MONOTONIC_COUNTER, "Monotonically-increasing counter" },
		{0,                            NULL     } };

	static const value_string opt_overload_vals[] = {
		{ OPT_OVERLOAD_FILE,  "Boot file name holds options",                },
		{ OPT_OVERLOAD_SNAME, "Server host name holds options",              },
		{ OPT_OVERLOAD_BOTH,  "Boot file and server host names hold options" },
		{ 0,                  NULL                                           } };

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
				proto_tree_add_text(bp_tree, tvb, voff, i,
				    "Padding (%d byte%s)", i, plurality(i, "", "s"));
			}
		}
		consumed = i;
		return consumed;

	case 255:	/* End Option */
		if (!first_pass) {
			if (bp_tree != NULL) {
				proto_tree_add_text(bp_tree, tvb, voff, 1,
				    "End Option%s", *overload_p?" (overload)":"");
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
			}
		}

		/*
		 * We don't do anything else here.
		 */
		return consumed;
	}

	/* Normal cases */
	text = bootp_get_opt_text(code);
	ftype = bootp_get_opt_ftype(code);

	optoff = voff+2;

	vti = proto_tree_add_text(bp_tree, tvb, voff, consumed,
	    "Option: (t=%d,l=%d) %s", code, optlen, text);
	v_tree = proto_item_add_subtree(vti, ett_bootp_option);
	proto_tree_add_uint_format_value(v_tree, hf_bootp_option_type,
		tvb, voff, 1, code, "(%d) %s", code, text);
	proto_tree_add_item(v_tree, hf_bootp_option_length, tvb, voff+1, 1, FALSE);
	if (optlen > 0) {
		proto_tree_add_item(v_tree, hf_bootp_option_value, tvb, voff+2, optlen, FALSE);
	}

	/* Special cases */
	switch (code) {

	case 21:	/* Policy Filter */
		if (optlen == 8) {
			/* one IP address pair */
			proto_item_append_text(vti, " = %s/%s",
				tvb_ip_to_str(tvb, optoff),
				tvb_ip_to_str(tvb, optoff+4));
		} else {
			/* > 1 IP address pair. Let's make a sub-tree */
			for (i = optoff, optleft = optlen;
			    optleft > 0; i += 8, optleft -= 8) {
				if (optleft < 8) {
					proto_tree_add_text(v_tree, tvb, i, optleft,
					    "Option length isn't a multiple of 8");
					break;
				}
				proto_tree_add_text(v_tree, tvb, i, 8, "IP Address/Mask: %s/%s",
					tvb_ip_to_str(tvb, i),
					tvb_ip_to_str(tvb, i+4));
			}
		}
		break;

	case 33:	/* Static Route */
		if (optlen == 8) {
			/* one IP address pair */
			proto_item_append_text(vti, " = %s/%s",
				tvb_ip_to_str(tvb, optoff),
				tvb_ip_to_str(tvb, optoff+4));
		} else {
			/* > 1 IP address pair. Let's make a sub-tree */
			for (i = optoff, optleft = optlen; optleft > 0;
			    i += 8, optleft -= 8) {
				if (optleft < 8) {
					proto_tree_add_text(v_tree, tvb, i, optleft,
					    "Option length isn't a multiple of 8");
					break;
				}
				proto_tree_add_text(v_tree, tvb, i, 8,
					"Destination IP Address/Router: %s/%s",
					tvb_ip_to_str(tvb, i),
					tvb_ip_to_str(tvb, i+4));
			}
		}
		break;

	case 43:	/* Vendor-Specific Info */
		s_option = tvb_get_guint8(tvb, optoff);

		/* PXE protocol 2.1 as described in the intel specs */
		if (*vendor_class_id_p != NULL &&
		    strncmp((const gchar*)*vendor_class_id_p, "PXEClient", strlen("PXEClient")) == 0) {
			proto_item_append_text(vti, " (PXEClient)");
			v_tree = proto_item_add_subtree(vti, ett_bootp_option);

			optend = optoff + optlen;
			while (optoff < optend) {
				optoff = dissect_vendor_pxeclient_suboption(v_tree,
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
				optoff = dissect_vendor_cablelabs_suboption(v_tree,
					tvb, optoff, optend);
			}
		} else if (s_option==58 || s_option==64 || s_option==65
			|| s_option==66 || s_option==67) {
			/* Note that this is a rather weak (permissive) heuristic, */
			/* but since it comes last, i guess this is ok. */
			/* Add any stronger (less permissive) heuristics before this! */
			/* Alcatel-Lucent DHCP Extensions */
			proto_item_append_text(vti, " (Alcatel-Lucent)");
			optend = optoff + optlen;
			while (optoff < optend) {
				optoff = dissect_vendor_alcatel_suboption(v_tree,
					tvb, optoff, optend);
			}
		}
		break;

	case 52:	/* Option Overload */
		if (optlen < 1) {
			proto_item_append_text(vti, " length isn't >= 1");
			break;
		}
		byte = tvb_get_guint8(tvb, optoff);
		proto_item_append_text(vti, " = %s",
			val_to_str(byte, opt_overload_vals,
			    "Unknown (0x%02x)"));

		/* Just in case we find an option 52 in sname or file */
		if (voff > VENDOR_INFO_OFFSET && byte >= 1 && byte <= 3) {
			if (byte & OPT_OVERLOAD_FILE) {
				proto_item *oti;
				oti = proto_tree_add_text (bp_tree, tvb,
					FILE_NAME_OFFSET, FILE_NAME_LEN,
					"Boot file name option overload");
				o52voff = FILE_NAME_OFFSET;
				o52eoff = FILE_NAME_OFFSET + FILE_NAME_LEN;
				o52at_end = FALSE;
				while (o52voff < o52eoff && !o52at_end) {
					o52voff += bootp_option(tvb, pinfo, bp_tree, o52voff,
						o52eoff, FALSE, &o52at_end,
						dhcp_type_p, vendor_class_id_p,
						overload_p);
				}
				if (!o52at_end)
				{
					expert_add_info_format(pinfo, oti, PI_PROTOCOL,
						PI_ERROR, "file overload end option missing");
				}
			}
			if (byte & OPT_OVERLOAD_SNAME) {
				proto_item *oti;
				oti = proto_tree_add_text (bp_tree, tvb,
					SERVER_NAME_OFFSET, SERVER_NAME_LEN,
					"Server host name option overload");
				o52voff = SERVER_NAME_OFFSET;
				o52eoff = SERVER_NAME_OFFSET + SERVER_NAME_LEN;
				o52at_end = FALSE;
				while (o52voff < o52eoff && !o52at_end) {
					o52voff += bootp_option(tvb, pinfo, bp_tree, o52voff,
						o52eoff, FALSE, &o52at_end,
						dhcp_type_p, vendor_class_id_p,
						overload_p);
				}
				if (!o52at_end)
				{
					expert_add_info_format(pinfo, oti, PI_PROTOCOL,
						PI_ERROR, "sname overload end option missing");
				}
			}
			/* The final end option is not in overload */
			*overload_p = 0;
		}
		break;

	case 53:	/* DHCP Message Type */
		if (optlen != 1) {
			proto_item_append_text(vti, " length isn't 1");
			break;
		}
		proto_item_append_text(vti, " = DHCP %s",
			val_to_str(tvb_get_guint8(tvb, optoff),
				opt53_text,
				"Unknown Message Type (0x%02x)"));
		break;

	case 55:	/* Parameter Request List */
		for (i = 0; i < optlen; i++) {
			byte = tvb_get_guint8(tvb, optoff+i);
			proto_tree_add_text(v_tree, tvb, optoff+i, 1, "%d = %s",
					byte, bootp_get_opt_text(byte));
		}
		break;

	case 60:	/* Vendor class identifier */
		/*
		 * XXX - RFC 2132 says this is a string of octets;
		 * should we check for non-printables?
		 */
		proto_item_append_text(vti, " = \"%s\"",
			tvb_format_stringzpad(tvb, optoff, consumed-2));
		if ((tvb_memeql(tvb, optoff, (const guint8*)PACKETCABLE_MTA_CAP10,
				      (int)strlen(PACKETCABLE_MTA_CAP10)) == 0)
		    ||
		    (tvb_memeql(tvb, optoff, (const guint8*)PACKETCABLE_MTA_CAP15,
				      (int)strlen(PACKETCABLE_MTA_CAP15)) == 0)
			||
			(tvb_memeql(tvb, optoff, (const guint8*)PACKETCABLE_MTA_CAP20,
				      (int)strlen(PACKETCABLE_MTA_CAP20)) == 0))
		{
			dissect_packetcable_mta_cap(v_tree, tvb, optoff, optlen);
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
			proto_tree_add_text(v_tree, tvb, optoff, optlen,
				"vendor-class-data: \"%s\"", tvb_format_stringzpad(tvb, optoff, optlen));
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
			proto_tree_add_text(v_tree, tvb, optoff, 1,
				"Hardware type: %s",
				arphrdtype_to_str(byte,
					"Unknown (0x%02x)"));
			if (byte == ARPHRD_ETHER || byte == ARPHRD_IEEE802)
				proto_tree_add_item(v_tree,
				    hf_bootp_hw_ether_addr, tvb, optoff+1, 6,
				    FALSE);
			else
				proto_tree_add_text(v_tree, tvb, optoff+1, 6,
					"Client hardware address: %s",
					tvb_arphrdaddr_to_str(tvb, optoff+1, 6, byte));
		} else if (optlen == 17 && byte == 0) {
			/* Identifier is a UUID */
			proto_tree_add_item(v_tree, hf_bootp_client_identifier_uuid,
					    tvb, optoff + 1, 16, TRUE);
		/* From RFC 4631 paragraph 6.1 DHCPv4 Client Behavior:
			To send an RFC 3315-style binding identifier in a DHCPv4 'client
			identifier' option, the type of the 'client identifier' option is set
			to 255.	*/
		} else if (byte == 255) {
			guint16	duidtype;
			guint16	hwtype;
			guint8	*buf;
			int	enterprise;

			/*	The type field is immediately followed by the IAID, which is
				an opaque 32-bit quantity	*/
			proto_tree_add_text(v_tree, tvb, optoff+1, 4,
				"IAID: %s",
				tvb_arphrdaddr_to_str(tvb, optoff+1, 4, byte));
			optoff = optoff + 5;
			duidtype = tvb_get_ntohs(tvb, optoff);
			proto_tree_add_text(v_tree, tvb, optoff, 2,
				"DUID type: %s (%u)",
						val_to_str(duidtype,
							   duidtype_vals, "Unknown"),
						duidtype);
			switch (duidtype) {
			case DUID_LLT:
				if (optlen < 8) {
					proto_tree_add_text(v_tree, tvb, optoff,
						optlen, "DUID: malformed option");
					break;
				}
				hwtype=tvb_get_ntohs(tvb, optoff + 2);
				proto_tree_add_text(v_tree, tvb, optoff + 2, 2,
					"Hardware type: %s (%u)", arphrdtype_to_str(hwtype, "Unknown"),
					hwtype);
				/* XXX seconds since Jan 1 2000 */
				proto_tree_add_text(v_tree, tvb, optoff + 4, 4,
					"Time: %u", tvb_get_ntohl(tvb, optoff + 4));
				if (optlen > 8) {
					proto_tree_add_text(v_tree, tvb, optoff + 8,
						optlen - 13, "Link-layer address: %s",
						tvb_arphrdaddr_to_str(tvb, optoff+8, optlen-13, hwtype));
				}
				break;
			case DUID_EN:
				if (optlen < 6) {
					proto_tree_add_text(v_tree, tvb, optoff,
						optlen, "DUID: malformed option");
					break;
				}
				enterprise = tvb_get_ntohl(tvb, optoff+2);
				proto_tree_add_text(v_tree, tvb, optoff + 2, 4,
					    "Enterprise-number: %s (%u)",
					    val_to_str_ext_const( enterprise, &sminmpec_values_ext, "Unknown"),
					    enterprise);
				if (optlen > 6) {
						buf = tvb_bytes_to_str(tvb, optoff + 6, optlen - 11);
					proto_tree_add_text(v_tree, tvb, optoff + 6,
						optlen - 11, "identifier: %s", buf);
				}
				break;
			case DUID_LL:
				if (optlen < 4) {
					proto_tree_add_text(v_tree, tvb, optoff,
						optlen, "DUID: malformed option");
					break;
				}
				hwtype=tvb_get_ntohs(tvb, optoff + 2);
				proto_tree_add_text(v_tree, tvb, optoff + 2, 2,
					"Hardware type: %s (%u)",
					arphrdtype_to_str(hwtype, "Unknown"),
					hwtype);
				if (optlen > 4) {
					proto_tree_add_text(v_tree, tvb, optoff + 4,
						optlen - 9, "Link-layer address: %s",
						tvb_arphrdaddr_to_str(tvb, optoff+4, optlen-9, hwtype));
				}
				break;
			}
		} else {
			/* otherwise, it's opaque data */
		}
		break;

	case 97:        /* Client Identifier (UUID) */
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
			proto_tree_add_text(v_tree, tvb, optoff, 1,
				"Hardware type: %s",
				arphrdtype_to_str(byte,
					"Unknown (0x%02x)"));
			if (byte == ARPHRD_ETHER || byte == ARPHRD_IEEE802)
				proto_tree_add_item(v_tree,
				    hf_bootp_hw_ether_addr, tvb, optoff+1, 6,
				    FALSE);
			else
				proto_tree_add_text(v_tree, tvb, optoff+1, 6,
					"Client hardware address: %s",
					tvb_arphrdaddr_to_str(tvb, optoff+1, 6, byte));
		} else if (optlen == 17 && byte == 0) {
			/* Identifier is a UUID */
			proto_tree_add_item(v_tree, hf_bootp_client_identifier_uuid,
					    tvb, optoff + 1, 16, TRUE);
		} else {
			/* otherwise, it's opaque data */
		}
		break;

	case 63:	/* NetWare/IP options (RFC 2242) */

		optend = optoff + optlen;
		while (optoff < optend)
			optoff = dissect_netware_ip_suboption(v_tree, tvb, optoff, optend);
		break;

	case 78:	/* SLP Directory Agent Option RFC2610 Added by Greg Morris (gmorris@novell.com)*/
		if (optlen < 1) {
			proto_item_append_text(vti, " length isn't >= 1");
			break;
		}
		optleft = optlen;
		byte = tvb_get_guint8(tvb, optoff);
		proto_item_append_text(vti, " = %s",
				val_to_str(byte, slpda_vals,
					"Unknown (0x%02x)"));
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
				proto_tree_add_text(v_tree, tvb, i, optleft,
				    "Option length isn't a multiple of 4");
				break;
			}
			proto_tree_add_text(v_tree, tvb, i, 4, "SLPDA Address: %s",
			    tvb_ip_to_str(tvb, i));
		}
		break;

	case 79:	/* SLP Service Scope Option RFC2610 Added by Greg Morris (gmorris@novell.com)*/
		byte = tvb_get_guint8(tvb, optoff);
		proto_item_append_text(vti, " = %s",
				val_to_str(byte, slp_scope_vals,
				    "Unknown (0x%02x)"));
		optoff++;
		optleft = optlen - 1;
		proto_tree_add_text(v_tree, tvb, optoff, optleft,
		    "%s = \"%s\"", text,
		    tvb_format_stringzpad(tvb, optoff, optleft));
		break;

	case 81:	/* Client Fully Qualified Domain Name */
		if (optlen < 3) {
			proto_item_append_text(vti, " length isn't >= 3");
			break;
		}
		fqdn_flags = tvb_get_guint8(tvb, optoff);
		proto_tree_add_text(v_tree, tvb, optoff, 1, "Flags: 0x%02x", fqdn_flags);
		proto_tree_add_item(v_tree, hf_bootp_fqdn_mbz, tvb, optoff, 1, FALSE);
		proto_tree_add_item(v_tree, hf_bootp_fqdn_n, tvb, optoff, 1, FALSE);
		proto_tree_add_item(v_tree, hf_bootp_fqdn_e, tvb, optoff, 1, FALSE);
		proto_tree_add_item(v_tree, hf_bootp_fqdn_o, tvb, optoff, 1, FALSE);
		proto_tree_add_item(v_tree, hf_bootp_fqdn_s, tvb, optoff, 1, FALSE);
		/* XXX: use code from packet-dns for return code decoding */
		proto_tree_add_item(v_tree, hf_bootp_fqdn_rcode1, tvb, optoff+1, 1, FALSE);
		/* XXX: use code from packet-dns for return code decoding */
		proto_tree_add_item(v_tree, hf_bootp_fqdn_rcode2, tvb, optoff+2, 1, FALSE);
		if (optlen > 3) {
			if (fqdn_flags & F_FQDN_E) {
				get_dns_name(tvb, optoff+3, optlen-3, optoff+3, &dns_name);
				proto_tree_add_string(v_tree, hf_bootp_fqdn_name,
				    tvb, optoff+3, optlen-3, dns_name);
			} else {
				proto_tree_add_item(v_tree, hf_bootp_fqdn_asciiname,
				    tvb, optoff+3, optlen-3, FALSE);
			}
		}
		break;

	case 82:        /* Relay Agent Information Option */
		optend = optoff + optlen;
		while (optoff < optend)
			optoff = bootp_dhcp_decode_agent_info(v_tree, tvb, optoff, optend);
		break;

	case 85:        /* Novell Servers (RFC 2241) */
		/* Option 85 can be sent as a string */
		/* Added by Greg Morris (gmorris[AT]novell.com) */
		if (novell_string) {
			proto_item_append_text(vti, " = \"%s\"",
			    tvb_format_stringzpad(tvb, optoff, optlen));
		} else {
			if (optlen == 4) {
				/* one IP address */
				proto_item_append_text(vti, " = %s",
					tvb_ip_to_str(tvb, optoff));
			} else {
				/* > 1 IP addresses. Let's make a sub-tree */
				for (i = optoff, optleft = optlen; optleft > 0;
				    i += 4, optleft -= 4) {
					if (optleft < 4) {
						proto_tree_add_text(v_tree, tvb, i, optleft,
						    "Option length isn't a multiple of 4");
						break;
					}
					proto_tree_add_text(v_tree, tvb, i, 4, "IP Address: %s",
						tvb_ip_to_str(tvb, i));
				}
			}
		}
	        break;

	case 94: {	/* Client network interface identifier */
		guint8 id_type;

		id_type = tvb_get_guint8(tvb, optoff);

		if (id_type == 0x01) {
			proto_tree_add_item(v_tree, hf_bootp_client_network_id_major_ver,
					    tvb, optoff + 1, 1, TRUE);
			proto_tree_add_item(v_tree, hf_bootp_client_network_id_minor_ver,
					    tvb, optoff + 2, 1, TRUE);
		}

		break;
	}

	case 90:	/* DHCP Authentication */
	case 210:	/* Was this used for authentication at one time? */
		if (optlen < 11) {
			proto_item_append_text(vti, " length isn't >= 11");
			break;
		}
		optleft = optlen;
		protocol = tvb_get_guint8(tvb, optoff);
		proto_tree_add_text(v_tree, tvb, optoff, 1, "Protocol: %s (%u)",
				    val_to_str(protocol, authen_protocol_vals, "Unknown"),
				    protocol);
		optoff++;
		optleft--;

		algorithm = tvb_get_guint8(tvb, optoff);
		switch (protocol) {

		case AUTHEN_PROTO_DELAYED_AUTHEN:
			proto_tree_add_text(v_tree, tvb, optoff, 1,
				    "Algorithm: %s (%u)",
				    val_to_str(algorithm, authen_da_algo_vals, "Unknown"),
				    algorithm);
			break;

		default:
			proto_tree_add_text(v_tree, tvb, optoff, 1,
				    "Algorithm: %u", algorithm);
			break;
		}
		optoff++;
		optleft--;

		rdm = tvb_get_guint8(tvb, optoff);
		proto_tree_add_text(v_tree, tvb, optoff, 1,
				    "Replay Detection Method: %s (%u)",
				    val_to_str(rdm, authen_rdm_vals, "Unknown"),
				    rdm);
		optoff++;
		optleft--;

		switch (rdm) {

		case AUTHEN_RDM_MONOTONIC_COUNTER:
			proto_tree_add_text(v_tree, tvb, optoff, 8,
				    "RDM Replay Detection Value: %" G_GINT64_MODIFIER "x",
				    tvb_get_ntoh64(tvb, optoff));
			break;

		default:
			proto_tree_add_text(v_tree, tvb, optoff, 8,
				    "Replay Detection Value: %s",
				    tvb_bytes_to_str(tvb, optoff, 8));
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
						proto_item_append_text(vti,
							" length isn't >= 31");
						break;
					}
					proto_tree_add_text(v_tree, tvb, optoff, 4,
						"Secret ID: 0x%08x",
						tvb_get_ntohl(tvb, optoff));
					optoff += 4;
					optleft -= 4;
					proto_tree_add_text(v_tree, tvb, optoff, 16,
						"HMAC MD5 Hash: %s",
						tvb_bytes_to_str(tvb, optoff, 16));
					break;
				}

			default:
				if (optleft == 0)
					break;
				proto_tree_add_text(v_tree, tvb, optoff, optleft,
					"Authentication Information: %s",
					tvb_bytes_to_str(tvb, optoff, optleft));
				break;
			}
			break;

		default:
			if (optleft == 0)
				break;
			proto_tree_add_text(v_tree, tvb, optoff, optleft,
				"Authentication Information: %s",
				tvb_bytes_to_str(tvb, optoff, optleft));
			break;
		}
		break;

	case 99: /* civic location (RFC 4776) */

		optleft = optlen;
		if (optleft >= 3)
		{
			proto_tree_add_text(v_tree, tvb, optoff, 1, "What: %d (%s)",
				tvb_get_guint8(tvb, optoff), val_to_str(tvb_get_guint8(tvb, optoff),
				civic_address_what_values, "Unknown") );
			proto_tree_add_text(v_tree, tvb, optoff + 1, 2, "Country: \"%s\"",
				tvb_format_text(tvb, optoff + 1, 2) );
			optleft = optleft - 3;
			optoff = optoff + 3;

			while (optleft >= 2)
			{
				int catype = tvb_get_guint8(tvb, optoff);
				optoff++;
				optleft--;
				s_option = tvb_get_guint8(tvb, optoff);
				optoff++;
				optleft--;

				if (s_option == 0)
				{
					proto_tree_add_text(v_tree, tvb, optoff, s_option,
						"CAType %d [%s] (l=%d): EMTPY", catype,
						val_to_str(catype, civic_address_type_values,
						"Unknown"), s_option);
					continue;
				}

				if (optleft >= s_option)
				{
					proto_tree_add_text(v_tree, tvb, optoff, s_option,
						"CAType %d [%s] (l=%d): \"%s\"", catype,
						val_to_str(catype, civic_address_type_values,
						"Unknown"), s_option,
						tvb_format_text(tvb, optoff, s_option));
					optoff = optoff + s_option;
					optleft = optleft - s_option;
				}
				else
				{
					optleft = 0;
					proto_tree_add_text(v_tree, tvb, optoff, s_option,
						"Error with CAType");
				}
			}
		}

		break;

	case 121:	/* Classless Static Route */
	case 249: {	/* Classless Static Route (Microsoft) */
		int mask_width, significant_octets;
		optend = optoff + optlen;
		/* minimum length is 5 bytes */
		if (optlen < 5) {
			proto_item_append_text(vti, " [ERROR: Option length < 5 bytes]");
			break;
		}
		while (optoff < optend) {
			mask_width = tvb_get_guint8(tvb, optoff);
			/* mask_width <= 32 */
			if (mask_width > 32) {
				proto_tree_add_text(v_tree, tvb, optoff,
					optend - optoff,
					"Subnet/MaskWidth-Router: [ERROR: Mask width (%d) > 32]",
					mask_width);
				break;
			}
			significant_octets = (mask_width + 7) / 8;
			vti = proto_tree_add_text(v_tree, tvb, optoff,
				1 + significant_octets + 4,
				"Subnet/MaskWidth-Router: ");
			optoff++;
			/* significant octets + router(4) */
			if (optend < optoff + significant_octets + 4) {
				proto_item_append_text(vti, "[ERROR: Remaining length (%d) < %d bytes]",
					optend - optoff, significant_octets + 4);
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
				proto_tree_add_text(v_tree, tvb, optoff, optlen, "Error: %s", val_to_str(i, rfc3825_error_types, "Unknown"));
			} else {
				proto_tree_add_text(v_tree, tvb, optoff, 5, "Latitude: %15.10f", location.latitude);
				proto_tree_add_text(v_tree, tvb, optoff+5, 5, "Longitude: %15.10f", location.longitude);
				proto_tree_add_text(v_tree, tvb, optoff, 1, "Latitude resolution: %15.10f", location.latitude_res);
				proto_tree_add_text(v_tree, tvb, optoff+5, 1, "Longitude resolution: %15.10f", location.longitude_res);
				proto_tree_add_text(v_tree, tvb, optoff+12, 4, "Altitude: %15.10f", location.altitude);
				proto_tree_add_text(v_tree, tvb, optoff+10, 2, "Altitude resolution: %15.10f", location.altitude_res);
				proto_tree_add_text(v_tree, tvb, optoff+10, 1, "Altitude type: %s (%d)", val_to_str(location.altitude_type, altitude_type_values, "Unknown"), location.altitude_type);
				proto_tree_add_text(v_tree, tvb, optoff+15, 1, "Map Datum: %s (%d)", val_to_str(location.datum_type, map_datum_type_values, "Unknown"), location.datum_type);
			}
		} else if ((optlen < 69)) { /* CableLabs DSS_ID */
			s_option = tvb_get_guint8(tvb, optoff);
			s_len = tvb_get_guint8(tvb, optoff+1);

			if (s_option == 1) { /*First DSS_ID*/
				proto_tree_add_text(v_tree, tvb, optoff+2, s_len, "Suboption 1: Primary DSS_ID = \"%s\"",
					tvb_format_stringzpad(tvb, optoff+2, s_len));
			} else if (s_option == 2) {
				proto_tree_add_text(v_tree, tvb, optoff+2, s_len, "Suboption 2: Secondary DSS_ID = \"%s\"",
					tvb_format_stringzpad(tvb, optoff+2, s_len));
			} else {
				proto_tree_add_text(v_tree, tvb, optoff, s_len, "Unknown");
			}

			if (optlen > s_len+2) { /* Second DSS_ID*/
				s_option = tvb_get_guint8(tvb, optoff+2+s_len);
				s_len = tvb_get_guint8(tvb, optoff+1+2+s_len);
				if (s_option == 1) {
					proto_tree_add_text(v_tree, tvb, optoff+2+s_len+2, s_len, "Suboption 1: Primary DSS_ID = \"%s\"",
						tvb_format_stringzpad(tvb, optoff+2+s_len+2, s_len));
				} else if (s_option == 2) {
					proto_tree_add_text(v_tree, tvb, optoff+2+s_len+2, s_len, "Suboption 2: Secondary DSS_ID = \"%s\"",
						tvb_format_stringzpad(tvb, optoff+2+s_len+2, s_len));
				} else {
					proto_tree_add_text(v_tree, tvb, optoff+s_len+2, s_len, "Unknown");
				}
			}
		} else {
			proto_tree_add_text(v_tree, tvb, optoff, optlen, "Error: Invalid length of DHCP option!");
		}
		break;

	case 124: { 	/* V-I Vendor Class */
	        int enterprise = 0;
		int data_len;

		if (optlen == 1) {
			/* CableLab specific */
			s_option = tvb_get_guint8(tvb, optoff);
			proto_tree_add_text(v_tree, tvb, optoff, optlen,
					    "CableLabs IP addressing mode preference: %s",
					    val_to_str (s_option, cablelab_ipaddr_mode_vals, "Unknown"));
			break;
		}

		optend = optoff + optlen;
	        optleft = optlen;

		while (optleft > 0) {

		  if (optleft < 5) {
		    proto_tree_add_text(v_tree, tvb, optoff,
					optleft, "Vendor Class: malformed option");
		    break;
		  }

		  enterprise = tvb_get_ntohl(tvb, optoff);

		  vti = proto_tree_add_text(v_tree, tvb, optoff, 4,
					    "Enterprise-number: %s (%u)",
					    val_to_str_ext_const(enterprise, &sminmpec_values_ext, "Unknown"),
					    enterprise);

		  data_len = tvb_get_guint8(tvb, optoff + 4);

		  proto_tree_add_text(v_tree, tvb, optoff + 4, 1,
				      "Data len: %d", data_len);
		  optoff += 5;
		  optleft -= 5;

		  proto_tree_add_text(v_tree, tvb, optoff, data_len,
				      "Vendor Class data: %s",
				      tvb_bytes_to_str(tvb, optoff, data_len));

		  /* look for next enterprise number */
		  optoff += data_len;
		  optleft -= data_len;
		}
		break;
	}

	case 125: { 	/* V-I Vendor-specific Information */
	        int enterprise = 0;
		int s_end = 0;
		int s_option_len = 0;
		proto_tree *e_tree = 0;

		optend = optoff + optlen;

	        optleft = optlen;

		while (optleft > 0) {

		  if (optleft < 5) {
		    proto_tree_add_text(v_tree, tvb, optoff,
					optleft, "Vendor-specific Information: malformed option");
		    break;
		  }

		  enterprise = tvb_get_ntohl(tvb, optoff);

		  vti = proto_tree_add_text(v_tree, tvb, optoff, 4,
					    "Enterprise-number: %s (%u)",
					    val_to_str_ext_const( enterprise, &sminmpec_values_ext, "Unknown"),
					    enterprise);

		  s_option_len = tvb_get_guint8(tvb, optoff + 4);

		  optoff += 5;
		  optleft -= 5;

		  /* Handle DSL Forum TR-111 Option 125 */
		  switch (enterprise) {

		  case 3561: /* ADSL Forum */
		    s_end = optoff + s_option_len;
		    if ( s_end > optend ) {
		      proto_tree_add_text(v_tree, tvb, optoff, 1,
					  "no room left in option for enterprise %u data", enterprise);
		      break;
		    }


		    e_tree = proto_item_add_subtree(vti, ett_bootp_option);
		    while (optoff < s_end) {

		      optoff = dissect_vendor_tr111_suboption(e_tree,
								 tvb, optoff, s_end);
		    }

		  case 4491: /* CableLab */
		    s_end = optoff + s_option_len;
		    if ( s_end > optend ) {
		      proto_tree_add_text(v_tree, tvb, optoff, 1,
					  "no room left in option for enterprise %u data", enterprise);
		      break;
		    }

		    e_tree = proto_item_add_subtree(vti, ett_bootp_option);
		    while (optoff < s_end) {
		      optoff = dissect_vendor_cl_suboption(e_tree,
								 tvb, optoff, s_end);
		    }

		  default:
		    /* skip over the data and look for next enterprise number */
		    optoff += s_option_len;
		  }

		  optleft -= s_option_len;

		}
		break;
	}

	case 212: {	/* 6RD option (RFC 5969) */
		struct e_in6_addr prefix;
		if (optlen >= 22) {

			/* IPv4 Mask Len */
			byte = tvb_get_guint8(tvb, optoff);
			proto_tree_add_text(v_tree, tvb, optoff, 1,
				"IPv4 Mask Len: %u", byte);

			/* 6RD Prefix Len */
			byte = tvb_get_guint8(tvb, optoff + 1);
			proto_tree_add_text(v_tree, tvb, optoff + 1, 1,
				"6RD Prefix Len: %u", byte);

			/* 6RD Prefix */
			memset(&prefix, 0, sizeof(prefix));
			tvb_get_ipv6(tvb, optoff + 2, &prefix);
			proto_tree_add_text(v_tree, tvb, optoff + 2, 16,
				"6RD Prefix: %s", ip6_to_str(&prefix));

			/* Add first Border Relay IPv4 address */
			proto_tree_add_text(v_tree, tvb, optoff + 18, 4,
				"Border Relay Address: %s", tvb_ip_to_str(tvb, optoff + 18 ));

			/* More Border Relay IPv4 addresses included */
			if (optlen > 22) {
				optoff += 22;
				for (i = optoff, optleft = optlen - 22; optleft > 0; i += 4, optleft -= 4) {
					if (optleft < 4) {
						proto_tree_add_text(v_tree, tvb, i, voff + consumed - i,
							"Border Relay length isn't a multiple of 4");
						break;
					}
					proto_tree_add_text(v_tree, tvb, i, 4, "Border Relay Address: %s",
						tvb_ip_to_str(tvb, i));
				}
			}
		} else {
			proto_tree_add_text(v_tree, tvb, optoff,
				optlen, "6RD: malformed option");
		}
		break;
	}

	default:	/* not special */
		/* The PacketCable CCC option number can vary.  If this is a CCC option,
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
					optoff = dissect_packetcable_i05_ccc(v_tree, tvb, optoff, optend);
					break;
				case PACKETCABLE_CCC_DRAFT5:
				case PACKETCABLE_CCC_RFC_3495:
					optoff = dissect_packetcable_ietf_ccc(v_tree, tvb, optoff, optend, pkt_ccc_protocol_version);
					break;
				default: /* XXX Should we do something here? */
					break;
				}
			}
		}

		break;
	}

	switch (ftype) {

	case ipv4:
		if (optlen != 4) {
			proto_item_append_text(vti,
			    " - length isn't 4");
			break;
		}
		proto_item_append_text(vti, " = %s", tvb_ip_to_str(tvb, optoff));
		break;

	case ipv4_list:
		if (optlen == 4) {
			/* one IP address */
			proto_item_append_text(vti, " = %s", tvb_ip_to_str(tvb, optoff));
		} else {
			/* > 1 IP addresses. Let's make a sub-tree */
			for (i = optoff, optleft = optlen; optleft > 0;
			    i += 4, optleft -= 4) {
				if (optleft < 4) {
					proto_tree_add_text(v_tree, tvb, i, voff + consumed - i,
					    "Option length isn't a multiple of 4");
					break;
				}
				proto_tree_add_text(v_tree, tvb, i, 4, "IP Address: %s",
					tvb_ip_to_str(tvb, i));
			}
		}
		break;

	case string:
		/* Fix for non null-terminated string supplied by
		 * John Lines <John.Lines[AT]aeat.co.uk>
		 */
		proto_item_append_text(vti, " = \"%s\"",
				tvb_format_stringzpad(tvb, optoff, consumed-2));
		break;

	case val_boolean:
		if (optlen != 1) {
			proto_item_append_text(vti,
			    " - length isn't 1");
			break;
		}
		tfs = (const struct true_false_string *) bootp_get_opt_data(code);
		if(tfs){
			i = tvb_get_guint8(tvb, optoff);
			if (i != 0 && i != 1) {
				proto_item_append_text(vti,
				    " = Invalid Value %d", i);
			} else {
				proto_item_append_text(vti, " = %s",
			    		i == 0 ? tfs->false_string : tfs->true_string);
			}
		}
		break;

	case val_u_byte:
		if (optlen != 1) {
			proto_item_append_text(vti,
			    " - length isn't 1");
			break;
		}
		vs = (const value_string *) bootp_get_opt_data(code);
		byte = tvb_get_guint8(tvb, optoff);
		if (vs != NULL) {
			proto_item_append_text(vti, " = %s",
			    val_to_str(byte, vs, "Unknown (%u)"));
		} else
			proto_item_append_text(vti, " = %u", byte);
		break;

	case val_u_short: {
		gushort vd;

		if (optlen != 2) {
			proto_item_append_text(vti,
			    " - length isn't 2");
			break;
		}

		vs = (const value_string *) bootp_get_opt_data(code);
		vd = tvb_get_ntohs(tvb, optoff);

		if (vs != NULL) {
			proto_item_append_text(vti, " = %s",
					       val_to_str(vd, vs, "Unknown (%u)"));
		} else
			proto_item_append_text(vti, " = %u", vd);

		break;
	}

	case val_u_short_list:
		if (optlen == 2) {
			/* one gushort */
			proto_item_append_text(vti, " = %u",
			    tvb_get_ntohs(tvb, optoff));
		} else {
			/* > 1 gushort */
			for (i = optoff, optleft = optlen; optleft > 0;
			    i += 2, optleft -= 2) {
				if (optleft < 2) {
					proto_tree_add_text(v_tree, tvb, i, voff + consumed - i,
					    "Option length isn't a multiple of 2");
					break;
				}
				proto_tree_add_text(v_tree, tvb, i, 4, "Value: %u",
					tvb_get_ntohs(tvb, i));
			}
		}
		break;

	case val_u_long:
		if (optlen != 4) {
			proto_item_append_text(vti,
			    " - length isn't 4");
			break;
		}
		proto_item_append_text(vti, " = %u",
		    tvb_get_ntohl(tvb, optoff));
		break;

	case time_in_s_secs:
		if (optlen != 4) {
			proto_item_append_text(vti,
			    " - length isn't 4");
			break;
		}
		time_s_secs = (gint32) tvb_get_ntohl(tvb, optoff);
		proto_item_append_text(vti, " = %s",
		      time_secs_to_str(time_s_secs));
		break;

	case time_in_u_secs:
		if (optlen != 4) {
			proto_item_append_text(vti,
			    " - length isn't 4");
			break;
		}
		time_u_secs = tvb_get_ntohl(tvb, optoff);
		proto_item_append_text(vti, " = %s",
		    ((time_u_secs == 0xffffffff) ?
		      "infinity" :
		      time_secs_to_str_unsigned(time_u_secs)));
		break;

	default:
		break;
	}

	return consumed;
}

static int
bootp_dhcp_decode_agent_info(proto_tree *v_tree, tvbuff_t *tvb, int optoff,
    int optend)
{
	int suboptoff = optoff;
	guint8 subopt, vs_opt, vs_len;
	int subopt_len, datalen;
	guint32 enterprise;
	proto_item *vti;
	proto_tree *subtree = 0;
	guint8 tag, tag_len;

	subopt = tvb_get_guint8(tvb, optoff);
	suboptoff++;

	if (suboptoff >= optend) {
		proto_tree_add_text(v_tree, tvb, optoff, 1,
			"Suboption %d: no room left in option for suboption length",
	 		subopt);
	 	return (optend);
	}
	subopt_len = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	if (suboptoff+subopt_len > optend) {
		proto_tree_add_text(v_tree, tvb, optoff, optend-optoff,
			"Suboption %d: no room left in option for suboption value",
	 		subopt);
	 	return (optend);
	}
	switch (subopt) {

	case 1: /* 1   Agent Circuit ID Sub-option            [RFC3046] */
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
				    "Agent Circuit ID: %s",
				    tvb_bytes_to_str(tvb, suboptoff, subopt_len));
		break;

	case 2: /* 2   Agent Remote ID Sub-option             [RFC3046] */
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
				    "Agent Remote ID: %s",
				    tvb_bytes_to_str(tvb, suboptoff, subopt_len));
		break;

	case 3:
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
				    "Reserved: %s",
				    tvb_bytes_to_str(tvb, suboptoff, subopt_len));
		break;

	case 4: /* 4   DOCSIS Device Class Suboption          [RFC3256] */
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
				    "DOCSIS Device Class: %s",
				    tvb_bytes_to_str(tvb, suboptoff, subopt_len));
		break;

	case 5: /* 5   Link selection Sub-option              [RFC3527] */
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
				    "Link selection: %s",
				     tvb_ip_to_str(tvb, suboptoff));
		break;

	case 6: /*Subscriber-ID Suboption                [RFC3993] */
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
					"Subscriber ID: %s",
					tvb_bytes_to_str(tvb, suboptoff, subopt_len));
		break;

	case 7: /* 7   RADIUS Attributes Sub-option           [RFC4014] */
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
					"RADIUS Attributes: %s",
					tvb_bytes_to_str(tvb, suboptoff, subopt_len));
		break;

	case 8: /* 8   Authentication Suboption               [RFC4030]  */
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
					"Authentication: %s",
					tvb_bytes_to_str(tvb, suboptoff, subopt_len));
		break;

	case 9: /* Vendor-Specific Information Suboption    [RFC 4243] */
		while (suboptoff < optend) {
			enterprise = tvb_get_ntohl(tvb, suboptoff);
			datalen = tvb_get_guint8(tvb, suboptoff+4);
			vti = proto_tree_add_text(v_tree, tvb, suboptoff, 4 + datalen + 1,
					    "Enterprise-number: %s (%u)",
					    val_to_str_ext_const( enterprise, &sminmpec_values_ext, "Unknown"),
					    enterprise);
			suboptoff += 4;

			subtree = proto_item_add_subtree(vti, ett_bootp_option);
			proto_tree_add_text(subtree, tvb, suboptoff, 1,
					    "Data Length: %u", datalen);
			suboptoff++;

			switch (enterprise) {
			case 4491: /* CableLab */
				vs_opt = tvb_get_guint8(tvb, suboptoff);
				suboptoff++;
				vs_len = tvb_get_guint8(tvb, suboptoff);
				suboptoff++;

				switch (vs_opt) {

				case 1:
					if (vs_len == 4) {
						tag = tvb_get_guint8(tvb, suboptoff);
						tag_len = tvb_get_guint8(tvb, suboptoff+1);
						suboptoff+=2;
						if (tag == 1) {
							proto_tree_add_text(subtree, tvb, suboptoff, tag_len,
							    "DOCSIS Version Number %d.%d",
							    tvb_get_guint8(tvb, suboptoff),
							    tvb_get_guint8(tvb, suboptoff+1));
							suboptoff+=2;
						} else {
							proto_tree_add_text(subtree, tvb, suboptoff, tag_len,
							    "Unknown tag=%u %s (%d byte%s)", tag,
							    tvb_bytes_to_str(tvb, suboptoff, tag_len),
							    tag_len, plurality(tag_len, "", "s"));
							suboptoff += tag_len;
						}
					} else {
						suboptoff += vs_len;
					}
					break;

				default:
					proto_tree_add_text(subtree, tvb, suboptoff, vs_len,
					    "Invalid suboption %d (%d byte%s)",
					    vs_opt, vs_len, plurality(vs_len, "", "s"));
					suboptoff += vs_len;
					break;
				}
				break;
			default:
		     		proto_tree_add_text(subtree, tvb, suboptoff, datalen,
				    "Suboption Data: %s", tvb_bytes_to_str(tvb, suboptoff, datalen));
		     		suboptoff += datalen;
				break;
			}
		}
		break;

	case 10: /* 10   Relay Agent Flags                      [RFC5010] */
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
					"Flags: %s",
					tvb_bytes_to_str(tvb, suboptoff, subopt_len));
		break;

	case 11: /* Server Identifier Override Suboption     [RFC 5107] */
		if (subopt_len == 4) {
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
				"Server ID Override: %s",
				tvb_ip_to_str(tvb, suboptoff));
		} else {
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
				"Server ID Override: Invalid length (%d instead of 4)",
				subopt_len);
		}
		break;

	default:
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
				    "Unknown agent suboption %d (%d bytes)",
				    subopt, subopt_len);
		break;
	}
	optoff += (subopt_len + 2);
	return optoff;
}

static int
dissect_vendor_pxeclient_suboption(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend)
{
	int suboptoff = optoff;
	guint8 subopt;
	guint8 subopt_len;
	int suboptleft;
	proto_tree *o43pxeclient_v_tree;
	proto_item *vti;

	static struct opt_info o43pxeclient_opt[]= {
		/* 0 */ {"nop", special, NULL},	/* dummy */
		/* 1 */ {"PXE mtftp IP", ipv4_list, NULL},
		/* 2 */ {"PXE mtftp client port", val_u_le_short, NULL},
		/* 3 */ {"PXE mtftp server port",val_u_le_short, NULL},
		/* 4 */ {"PXE mtftp timeout", val_u_byte, NULL},
		/* 5 */ {"PXE mtftp delay", val_u_byte, NULL},
		/* 6 */ {"PXE discovery control", val_u_byte, NULL},
			/*
			 * Correct: b0 (lsb): disable broadcast discovery
			 *	b1: disable multicast discovery
			 *	b2: only use/accept servers in boot servers
			 *	b3: download bootfile without prompt/menu/disc
			 */
		/* 7 */ {"PXE multicast address", ipv4_list, NULL},
		/* 8 */ {"PXE boot servers", special, NULL},
		/* 9 */ {"PXE boot menu", special, NULL},
		/* 10 */ {"PXE menu prompt", special, NULL},
		/* 11 */ {"PXE multicast address alloc", special, NULL},
		/* 12 */ {"PXE credential types", special, NULL},
		/* 71 {"PXE boot item", special, NULL}, */
		/* 255 {"PXE end options", special, NULL} */
	};

	subopt = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	if (subopt == 0) {
		proto_tree_add_text(v_tree, tvb, optoff, 1, "Padding");
		return (suboptoff);
	} else if (subopt == 255) {	/* End Option */
		proto_tree_add_text(v_tree, tvb, optoff, 1, "End PXEClient option");
		/* Make sure we skip any junk left this option */
		return (optend);
	}

	if (suboptoff >= optend) {
		proto_tree_add_text(v_tree, tvb, optoff, 1,
			"Suboption %d: no room left in option for suboption length",
	 		subopt);
	 	return (optend);
	}
	subopt_len = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	if (suboptoff+subopt_len > optend) {
		proto_tree_add_text(v_tree, tvb, optoff, optend-optoff,
			"Suboption %d: no room left in option for suboption value",
	 		subopt);
	 	return (optend);
	}
	if ( subopt == 71 ) {	/* 71 {"PXE boot item", special} */
		/* case special */
		/* I may need to decode that properly one day */
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
			"Suboption %d: %s (%d byte%s)" ,
	 		subopt, "PXE boot item",
			subopt_len, plurality(subopt_len, "", "s"));
	} else if ((subopt < 1) || (subopt >= array_length(o43pxeclient_opt))) {
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
			"Unknown suboption %d (%d byte%s)", subopt, subopt_len,
			plurality(subopt_len, "", "s"));
	} else {
		switch (o43pxeclient_opt[subopt].ftype) {

		case special:
			/* I may need to decode that properly one day */
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
				"Suboption %d: %s (%d byte%s)",
		 		subopt, o43pxeclient_opt[subopt].text,
				subopt_len, plurality(subopt_len, "", "s"));
			break;

		case ipv4_list:
			if (subopt_len == 4) {
				/* one IP address */
				proto_tree_add_text(v_tree, tvb, optoff, 6,
				    "Suboption %d : %s = %s",
				    subopt, o43pxeclient_opt[subopt].text,
				    tvb_ip_to_str(tvb, suboptoff));
			} else {
				/* > 1 IP addresses. Let's make a sub-tree */
				vti = proto_tree_add_text(v_tree, tvb, optoff,
				    subopt_len+2, "Suboption %d: %s",
				    subopt, o43pxeclient_opt[subopt].text);
				o43pxeclient_v_tree = proto_item_add_subtree(vti, ett_bootp_option);
				for (suboptleft = subopt_len; suboptleft > 0;
				    suboptoff += 4, suboptleft -= 4) {
					if (suboptleft < 4) {
						proto_tree_add_text(o43pxeclient_v_tree,
						    tvb, suboptoff, suboptleft,
						    "Suboption length isn't a multiple of 4");
						break;
					}
					proto_tree_add_text(o43pxeclient_v_tree,
					    tvb, suboptoff, 4, "IP Address: %s",
					    tvb_ip_to_str(tvb, suboptoff));
				}
			}
			break;

#if 0 /* XXX */
		case string:
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
				"Suboption %d: %s", subopt, o43pxeclient_opt[subopt].text);
			break;
#endif /*  XXX */

		case val_u_byte:
			if (subopt_len != 1) {
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
					"Suboption %d: suboption length isn't 1", subopt);
				break;
			}
			proto_tree_add_text(v_tree, tvb, optoff, 3, "Suboption %d: %s = %u",
			    subopt, o43pxeclient_opt[subopt].text,
			    tvb_get_guint8(tvb, suboptoff));
			break;

		case val_u_le_short:
			if (subopt_len != 2) {
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
					"Suboption %d: suboption length isn't 2", subopt);
				break;
			}
			proto_tree_add_text(v_tree, tvb, optoff, 4, "Suboption %d: %s = %u",
			    subopt, o43pxeclient_opt[subopt].text,
			    tvb_get_letohs(tvb, suboptoff));
			break;

		default:
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,"ERROR, please report: Unknown subopt type handler %d", subopt);
			break;
		}
	}
	optoff += (subopt_len + 2);
	return optoff;
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
		                            (gint64)lci[4]      | ((gint64)0x3FFFFFFF<<34);

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
		                            ((gint64)lci[7]<<16) | ((gint64)lci[8]<<8)  |
		                             (gint64)lci[9]      | ((gint64)0x3FFFFFFF<<34);

	} else {
		/* Longitude is positive */
		fixpoint->longitude = (((gint64)lci[5] & 3)<<32) | ((gint64)lci[6]<<24) |
		                            ((gint64)lci[7]<<16) | ((gint64)lci[8]<<8)  |
		                             (gint64)lci[9];
	}
	fixpoint->altitude_type = (lci[10]>>4) & 0x0F;  /* make sure that right-shift does not copy sign bit */
	fixpoint->altitude_res  = ((lci[10] & 0x0F) << 2) | ((lci[11]>>6) & 0x03);
	if (lci[11] & 0x20) { /* LSB<<1 contains the sign of the latitude */
		/* Altitude is negative, expand two's complement */
		fixpoint->altitude = (((gint32)lci[11] & 0x3F)<<24) | ((gint32)lci[12]<<16) |
		                     ((gint32)lci[13]<<8) | ((gint32)lci[14]) |
		                      ((gint32)0x03<<30);

	} else {
		/* Altitudee is positive */
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
		decimal->latitude_res = (double) 1  / (1 << (fixpoint->latitude_res - 8));
	} else {
		decimal->latitude_res = 1 << (8 - fixpoint->latitude_res);
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
		decimal->longitude_res = (double) 1 / (1 << (fixpoint->longitude_res - 8));
	} else {
		decimal->longitude_res = 1 << (8 - fixpoint->longitude_res);
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
			decimal->altitude_res = (double) 1 / (1 << (fixpoint->altitude_res - 21));
		} else {
			decimal->altitude_res = 1 << (21 - fixpoint->altitude_res);
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


static int
dissect_vendor_cablelabs_suboption(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend)
{
	int suboptoff = optoff;
	guint8 subopt, byte_val;
	guint8 subopt_len;

	static struct opt_info o43cablelabs_opt[]= {
		/*  0 */ {"nop", special, NULL},	/* dummy */
		/*  1 */ {"Suboption Request List", string, NULL},
		/*  2 */ {"Device Type", string, NULL},
		/*  3 */ {"eSAFE Types", string, NULL},
		/*  4 */ {"Serial Number", string, NULL},
		/*  5 */ {"Hardware Version", string, NULL},
		/*  6 */ {"Software Version", string, NULL},
		/*  7 */ {"Boot ROM version", string, NULL},
		/*  8 */ {"Organizationally Unique Identifier", special, NULL},
		/*  9 */ {"Model Number", string, NULL},
		/* 10 */ {"Vendor Name", string, NULL},
		/* *** 11-30: CableHome *** */
		/* 11 */ {"Address Realm", special, NULL},
		/* 12 */ {"CM/PS System Description", string, NULL},
		/* 13 */ {"CM/PS Firmware Revision", string, NULL},
		/* 14 */ {"Firewall Policy File Version", string, NULL},
		/* 15 */ {"eSafe Config File Devices", string, NULL},
		/* 16 */ {"Unassigned (CableHome)", special, NULL},
		/* 17 */ {"Unassigned (CableHome)", special, NULL},
		/* 18 */ {"Video Security Type", string, NULL},
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
		/* 31 */ {"MTA MAC Address", special, NULL},
		/* 32 */ {"Correlation ID", val_u_long, NULL},
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
		/* 51 */ {"Vendor Name", string, NULL},
		/* 52 */ {"CableCARD Capability", special, NULL},
		/* 53 */ {"Device Identification (CA)", special, NULL},
		/* 54 */ {"Device Identification (X.509)", string, NULL},
		/* 55 */ {"Unassigned (CableLabs)", special, NULL},
		/* *** 128-254: Vendors *** */
		/* 128-254 {"Unassigned (Vendors)", special, NULL}, */
		/* 255 {"end options", special, NULL} */
	};

	static const value_string cablehome_subopt11_vals[] = {
		{ 1, "PS WAN-Man" },
		{ 2, "PS WAN-Data" },
		{ 0, NULL }
	};

	subopt = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	if (subopt == 0) {
		proto_tree_add_text(v_tree, tvb, optoff, 1, "Padding");
		return (suboptoff);
	} else if (subopt == 255) {	/* End Option */
		proto_tree_add_text(v_tree, tvb, optoff, 1, "End CableLabs option");
		/* Make sure we skip any junk left this option */
		return (optend);
	}

	if (suboptoff >= optend) {
		proto_tree_add_text(v_tree, tvb, optoff, 1,
			"Suboption %d: no room left in option for suboption length",
	 		subopt);
	 	return (optend);
	}
	subopt_len = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	if (suboptoff+subopt_len > optend) {
		proto_tree_add_text(v_tree, tvb, optoff, optend-optoff,
			"Suboption %d: no room left in option for suboption value",
	 		subopt);
	 	return (optend);
	}
	if ( (subopt < 1 ) || (subopt >= array_length(o43cablelabs_opt)) ) {
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
			"Suboption %d: Unassigned (%d byte%s)", subopt, subopt_len,
			plurality(subopt_len, "", "s"));
	} else {
		switch (o43cablelabs_opt[subopt].ftype) {

		case special:
			if ( subopt == 8 ) {	/* OUI */
				/* CableLabs specs treat 43.8 inconsistently
				 * as either binary (3b) or string (6b) */
				if (subopt_len == 3) {
					proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
						"Suboption %d: Organization Unique Identifier = %s", subopt,
						tvb_bytes_to_str_punct(tvb, suboptoff, 3, ':'));
				} else if (subopt_len == 6) {
					proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
						"Suboption %d: Organization Unique Identifier =  \"%s\"", subopt,
						tvb_format_stringzpad(tvb, suboptoff, subopt_len));
				} else {
					proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
						"Suboption %d: suboption length isn't 3 or 6", subopt);
				}
				break;
			} else if ( subopt == 11 ) { /* Address Realm */
				if (subopt_len != 1) {
					proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
						"Suboption %d: suboption length isn't 1", subopt);
					break;
				}
				byte_val = tvb_get_guint8(tvb, suboptoff);
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
					"Suboption %d: %s = %s (0x%02x)",
					subopt, o43cablelabs_opt[subopt].text,
					val_to_str(byte_val, cablehome_subopt11_vals, "Unknown"), byte_val);
			} else if ( subopt == 31 ) { /* MTA MAC address */
				if (subopt_len != 6) {
					proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
						"Suboption %d: suboption length isn't 6", subopt);
					break;
				}
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
					"Suboption %d: %s = %s",
					subopt,  o43cablelabs_opt[subopt].text,
					tvb_bytes_to_str_punct(tvb, suboptoff, 6, ':'));
			} else {
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
					"Suboption %d: %s (%d byte%s)" ,
					subopt, o43cablelabs_opt[subopt].text,
					subopt_len, plurality(subopt_len, "", "s"));
			}
			break;

		case string:
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
				"Suboption %d: %s = \"%s\"", subopt,
				o43cablelabs_opt[subopt].text,
				tvb_format_stringzpad(tvb, suboptoff, subopt_len));
			break;

		case bytes:
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
				"Suboption %d: %s = 0x%s", subopt,
				o43cablelabs_opt[subopt].text,
				tvb_bytes_to_str(tvb, suboptoff, subopt_len));
			break;

		case val_u_long:
			if (subopt_len != 4) {
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
					"Suboption %d: suboption length isn't 4", subopt);
				break;
			}
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
				"Suboption %d: %s = %u", subopt,
				o43cablelabs_opt[subopt].text,
				tvb_get_ntohl(tvb, suboptoff));
			break;

		default:
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,"ERROR, please report: Unknown subopt type handler %d", subopt);
			break;
		}
	}
	optoff += (subopt_len + 2);
	return optoff;
}


static int
dissect_vendor_alcatel_suboption(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend)
{
	int suboptoff = optoff;
	guint8 subopt;
	guint8 subopt_len;
	proto_tree *subtree;
	proto_item *vti;

	subopt = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	if (subopt == 0) {
		proto_tree_add_text(v_tree, tvb, optoff, 1, "Padding");
		return (suboptoff);
	} else if (subopt == 255) { /* End Option */
		proto_tree_add_text(v_tree, tvb, optoff, 1, "End Alcatel-Lucent option");
		/* Make sure we skip any junk left this option */
		return (optend);
	}

	if (suboptoff >= optend) {
		proto_tree_add_text(v_tree, tvb, optoff, 1,
			"Suboption %d: no room left in option for suboption length",
			subopt);
		return (optend);
	}
	subopt_len = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	if (suboptoff+subopt_len > optend) {
		proto_tree_add_text(v_tree, tvb, optoff, optend-optoff,
			"Suboption %d: no room left in option for suboption value",
			subopt);
		return (optend);
	}
	if ( subopt == 58 ) { /* 0x3A - Alcatel-Lucent AVA VLAN Id */
		if (subopt_len != 2) {
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
				"Suboption %d: Bad suboption length!", subopt);
			return (optend);
		}
		vti = proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
		    "Alcatel-Lucent-Specific Suboption %d: %s = %u",
		    subopt, "VLAN Id",
		    tvb_get_ntohs(tvb, optoff+2));
		subtree = proto_item_add_subtree(vti, ett_bootp_option);
		proto_tree_add_uint(subtree, hf_bootp_alu_vid, tvb, optoff+2, 2,
			tvb_get_ntohs(tvb, optoff+2));
	} else if ( subopt == 64 ) { /* 0x40 - Alcatel-Lucent TFTP1 */
		if (subopt_len != 4) {
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
				"Suboption %d: Bad suboption length!", subopt);
			return (optend);
		}
		vti = proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
		    "Alcatel-Lucent-Specific Suboption %d: %s = %s",
		    subopt, "Spatial Redundancy TFTP1",
		    tvb_ip_to_str(tvb, optoff+2));
		subtree = proto_item_add_subtree(vti, ett_bootp_option);
		proto_tree_add_ipv4(subtree, hf_bootp_alu_tftp1, tvb, optoff+2, 4,
			tvb_get_ipv4(tvb, optoff+2));
	} else if ( subopt == 65 ) { /* 0x41 - Alcatel-Lucent TFTP2 */
		if (subopt_len != 4) {
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
				"Suboption %d: Bad suboption length!", subopt);
			return (optend);
		}
		vti = proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
		    "Alcatel-Lucent-Specific Suboption %d: %s = %s",
		    subopt, "Spatial Redundancy TFTP2",
		    tvb_ip_to_str(tvb, optoff+2));
		subtree = proto_item_add_subtree(vti, ett_bootp_option);
		proto_tree_add_ipv4(subtree, hf_bootp_alu_tftp2, tvb, optoff+2, 4,
			tvb_get_ipv4(tvb, optoff+2));
	} else if ( subopt == 66 ) { /* 0x42 - Alcatel-Lucent APPLICATION TYPE */
		if (subopt_len != 1) {
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
				"Suboption %d: Bad suboption length!", subopt);
			return (optend);
		}
		vti = proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
			"Alcatel-Lucent-Specific Suboption %d: %s = %u",
			subopt, "Application Type (0=NOE, 1=SIP)",
			tvb_get_guint8(tvb, optoff+2));
		subtree = proto_item_add_subtree(vti, ett_bootp_option);
		proto_tree_add_uint(subtree, hf_bootp_alu_app_type, tvb, optoff+2, 1,
			tvb_get_guint8(tvb, optoff+2));
	} else if ( subopt == 67 ) { /* 0x43 - Alcatel-Lucent SIP URL */
		vti = proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
			"Alcatel-Lucent-Specific Suboption %d: %s = \"%s\"",
			subopt, "SIP URL",
			tvb_format_stringzpad(tvb, optoff+2, subopt_len));
		subtree = proto_item_add_subtree(vti, ett_bootp_option);
		proto_tree_add_item(subtree, hf_bootp_alu_sip_url, tvb, optoff+2, subopt_len,
			0);
	} else {
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
			"ERROR, please report: Unknown subopt type handler %d", subopt);
		return optend;
	}
	optoff += (subopt_len + 2);
	return optoff;
}


static int
dissect_netware_ip_suboption(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend)
{
	int suboptoff = optoff;
	guint8 subopt;
	guint8 subopt_len;
	int suboptleft;
	const struct true_false_string *tfs;
	int i;
	proto_tree *o63_v_tree;
	proto_item *vti;

	static struct opt_info o63_opt[]= {
		/* 0 */ {"",none,NULL},
		/* 1 */ {"NWIP does not exist on subnet",presence,NULL},
		/* 2 */ {"NWIP exists in options area",presence,NULL},
		/* 3 */ {"NWIP exists in sname/file",presence,NULL},
		/* 4 */ {"NWIP exists, but too big",presence,NULL},
		/* 5 */ {"Broadcast for nearest Netware server",val_boolean,TFS(&tfs_yes_no)},
		/* 6 */ {"Preferred DSS server",ipv4_list,NULL},
		/* 7 */ {"Nearest NWIP server",ipv4_list,NULL},
		/* 8 */ {"Autoretries",val_u_byte,NULL},
		/* 9 */ {"Autoretry delay, secs",val_u_byte,NULL},
		/* 10*/ {"Support NetWare/IP v1.1",val_boolean,TFS(&tfs_yes_no)},
		/* 11*/ {"Primary DSS",ipv4,NULL}
	};

	subopt = tvb_get_guint8(tvb, optoff);
	suboptoff++;

	if (suboptoff >= optend) {
		proto_tree_add_text(v_tree, tvb, optoff, 1,
			"Suboption %d: no room left in option for suboption length",
	 		subopt);
	 	return (optend);
	}
	subopt_len = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	if (subopt >= array_length(o63_opt)) {
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2, "Unknown suboption %d", subopt);
	} else {
		switch (o63_opt[subopt].ftype) {

		case presence:
			if (subopt_len != 0) {
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
					"Suboption %d: length isn't 0", subopt);
				break;
			}
			proto_tree_add_text(v_tree, tvb, optoff, 2, "Suboption %d: %s", subopt, o63_opt[subopt].text);
			break;

		case ipv4:
			if (subopt_len != 4) {
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
					"Suboption %d: length isn't 4", subopt);
				break;
			}
			if (suboptoff+4 > optend) {
				proto_tree_add_text(v_tree, tvb, optoff, optend-optoff,
				    "Suboption %d: no room left in option for suboption value",
				    subopt);
			 	return (optend);
			}
			proto_tree_add_text(v_tree, tvb, optoff, 6,
			    "Suboption %d: %s = %s" ,
			    subopt, o63_opt[subopt].text,
			    tvb_ip_to_str(tvb, suboptoff));
			break;

		case ipv4_list:
			if (subopt_len == 4) {
				/* one IP address */
				proto_tree_add_text(v_tree, tvb, optoff, 6,
				    "Suboption %d : %s = %s",
				    subopt, o63_opt[subopt].text,
				    tvb_ip_to_str(tvb, suboptoff));
			} else {
				/* > 1 IP addresses. Let's make a sub-tree */
				vti = proto_tree_add_text(v_tree, tvb, optoff,
				    subopt_len+2, "Suboption %d: %s",
				    subopt, o63_opt[subopt].text);
				o63_v_tree = proto_item_add_subtree(vti, ett_bootp_option);
				for (suboptleft = subopt_len; suboptleft > 0;
				    suboptoff += 4, suboptleft -= 4) {
					if (suboptleft < 4) {
						proto_tree_add_text(o63_v_tree,
						    tvb, suboptoff, suboptleft,
						    "Suboption length isn't a multiple of 4");
						break;
					}
					proto_tree_add_text(o63_v_tree, tvb, suboptoff, 4, "IP Address: %s",
					    tvb_ip_to_str(tvb, suboptoff));
				}
			}
			break;

		case val_boolean:
			if (subopt_len != 1) {
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
					"Suboption %d: suboption length isn't 1", subopt);
				break;
			}
			if (suboptoff+1 > optend) {
				proto_tree_add_text(v_tree, tvb, optoff, optend-optoff,
				    "Suboption %d: no room left in option for suboption value",
				    subopt);
			 	return (optend);
			}
			tfs = (const struct true_false_string *) o63_opt[subopt].data;
			i = tvb_get_guint8(tvb, suboptoff);
			if (i != 0 && i != 1) {
				proto_tree_add_text(v_tree, tvb, optoff, 3,
				    "Suboption %d: %s = Invalid Value %d",
				    subopt, o63_opt[subopt].text, i);
			} else {
				proto_tree_add_text(v_tree, tvb, optoff, 3,
				    "Suboption %d: %s = %s", subopt,
				    o63_opt[subopt].text,
				    i == 0 ? tfs->false_string : tfs->true_string);
			}
			break;

		case val_u_byte:
			if (subopt_len != 1) {
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
					"Suboption %d: length isn't 1", subopt);
				break;
			}
			if (suboptoff+1 > optend) {
				proto_tree_add_text(v_tree, tvb, optoff, optend-optoff,
				    "Suboption %d: no room left in option for suboption value",
				    subopt);
			 	return (optend);
			}
			proto_tree_add_text(v_tree, tvb, optoff, 3, "Suboption %d: %s = %u",
			    subopt, o63_opt[subopt].text,
			    tvb_get_guint8(tvb, suboptoff));
			break;

		default:
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,"Unknown suboption %d", subopt);
			break;
		}
	}
	optoff += (subopt_len + 2);
	return optoff;
}



static int
dissect_vendor_tr111_suboption(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend)
{
	int suboptoff = optoff;
	guint8 subopt;
	guint8 subopt_len;

	/* Reference: TR-111 DHCP Option 125 Sub-Option Data Fields
	   Page 10.
	*/

	static struct opt_info o125_tr111_opt[]= {
		/* 0 */ {"nop", special, NULL},	/* dummy */
		/* 1 */ {"DeviceManufacturerOUI", string, NULL},
		/* 2 */ {"DeviceSerialNumber", string, NULL},
		/* 3 */ {"DeviceProductClass", string, NULL},
		/* 4 */ {"GatewayManufacturerOUI", string, NULL},
		/* 5 */ {"GatewaySerialNumber", string, NULL},
		/* 6 */ {"GatewayProductClass", string, NULL},
	};

	subopt = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	if (suboptoff >= optend) {
		proto_tree_add_text(v_tree, tvb, optoff, 1,
			"Suboption %d: no room left in option for suboption length",
	 		subopt);
	 	return (optend);
	}
	subopt_len = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	if (suboptoff+subopt_len > optend) {
		proto_tree_add_text(v_tree, tvb, optoff, optend-optoff,
			"Suboption %d: no room left in option for suboption value",
	 		subopt);
	 	return (optend);
	}


	if ((subopt < 1) || (subopt >= array_length(o125_tr111_opt))) {
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
			"Unknown suboption %d (%d byte%s)", subopt, subopt_len,
			plurality(subopt_len, "", "s"));
	} else {
		switch (o125_tr111_opt[subopt].ftype) {

		case special:
			/* I may need to decode that properly one day */
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
				"Suboption %d: %s (%d byte%s)",
		 		subopt, o125_tr111_opt[subopt].text,
				subopt_len, plurality(subopt_len, "", "s"));
			break;

		case string:
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
				"Suboption %d: %s = \"%s\"", subopt,
				o125_tr111_opt[subopt].text,
				tvb_format_stringzpad(tvb, suboptoff, subopt_len));
			break;

		default:
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,"ERROR, please report: Unknown subopt type handler %d", subopt);
			break;
		}
	}
	optoff += (subopt_len + 2);
	return optoff;
}

static int
dissect_vendor_cl_suboption(proto_tree *v_tree, tvbuff_t *tvb,
    int optoff, int optend)
{
	int suboptoff = optoff;
	guint8 subopt, val;
	guint8 subopt_len;
	proto_item *ti;
	proto_tree *subtree;
	int i;

	static struct opt_info o125_cl_opt[]= {
		/* 0 */ {"nop", special, NULL},	/* dummy */
		/* 1 */ {"Option Request = ", val_u_byte, NULL},
		/* 2 */ {"TFTP Server Addresses : ", ipv4_list, NULL},
		/* 3 */ {"eRouter Container Option : ", bytes, NULL},
		/* 4 */ {"MIB Environment Indicator Option = ", special, NULL},
		/* 5 */ {"Modem Capabilities : ", special, NULL},
	};

	static const value_string pkt_mib_env_ind_opt_vals[] = {
		{ 0x00, "Reserved" },
		{ 0x01, "CableLabs" },
		{ 0x02, "IETF" },
		{ 0x03, "EuroCableLabs" },
		{ 0, NULL }
	};

	subopt = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	if (suboptoff >= optend) {
		proto_tree_add_text(v_tree, tvb, optoff, 1,
			"Suboption %d: no room left in option for suboption length",
	 		subopt);
	 	return (optend);
	}
	subopt_len = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	if (suboptoff+subopt_len > optend) {
		proto_tree_add_text(v_tree, tvb, optoff, optend-optoff,
			"Suboption %d: no room left in option for suboption value",
	 		subopt);
	 	return (optend);
	}

	if ((subopt < 1) || (subopt >= array_length(o125_cl_opt))) {
		proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
			"Unknown suboption %d (%d byte%s)", subopt, subopt_len,
			plurality(subopt_len, "", "s"));
	} else {
		switch (o125_cl_opt[subopt].ftype) {

		case bytes:
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
				"Suboption %d: %s%s (%d byte%s)", subopt,
				o125_cl_opt[subopt].text,
				tvb_bytes_to_str(tvb, suboptoff, subopt_len),
				subopt_len, plurality(subopt_len, "", "s"));
			break;

		case ipv4_list:
			ti = proto_tree_add_text(v_tree, tvb, optoff, 2,
					"Suboption %d %s", subopt, o125_cl_opt[subopt].text);

			if ((subopt_len % 4) != 0) {
				proto_item_append_text(ti,
					"Invalid length for suboption %d (%d byte%s)", subopt, subopt_len,
					plurality(subopt_len, "", "s"));
			} else {
				subtree = proto_item_add_subtree(ti, ett_bootp_option);
				for (i = 0; i < subopt_len; i+=4) {
						proto_tree_add_text(subtree, tvb, suboptoff+i, 4, "IP Address: %s",
							tvb_ip_to_str(tvb, (suboptoff+i)));
				}
			}
			break;

		case special:
			if (subopt == 4) {
			  val = tvb_get_guint8(tvb, suboptoff);
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
					"Suboption %d: %s%s", subopt,
					o125_cl_opt[subopt].text,
					val_to_str(val, pkt_mib_env_ind_opt_vals, "unknown"));
			}
			else {
				proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
					"Suboption %d: %s%s (%d byte%s)",
		 			subopt, o125_cl_opt[subopt].text,
					tvb_bytes_to_str(tvb, suboptoff, subopt_len),
					subopt_len, plurality(subopt_len, "", "s"));
					dissect_docsis_cm_cap(v_tree, tvb, optoff, subopt_len+2, TRUE);
			}
			break;

		case string:
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
				"Suboption %d: %s\"%s\"", subopt,
				o125_cl_opt[subopt].text,
				tvb_format_stringzpad(tvb, suboptoff, subopt_len));
			break;

		case val_u_byte:
			val = tvb_get_guint8(tvb, suboptoff);
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
				"Suboption %d: %s\"%s\"", subopt,
				o125_cl_opt[subopt].text,
				tvb_bytes_to_str(tvb, suboptoff, subopt_len));
			break;

		case val_u_short:
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,
				"Suboption %d: %s%d", subopt,
				o125_cl_opt[subopt].text,
				tvb_get_ntohs(tvb, suboptoff));
			break;

		default:
			proto_tree_add_text(v_tree, tvb, optoff, subopt_len+2,"ERROR, please report: Unknown subopt type handler %d", subopt);
			break;
		}
	}
	optoff += (subopt_len + 2);
	return optoff;
}

/* PacketCable Multimedia Terminal Adapter device capabilities (option 60).
   Ref: PKT-SP-I05-021127 sections 8.2 and 10 */

#define PKT_MDC_TLV_OFF 10


/* These are ASCII-encoded hexadecimal digits.  We use the raw hex equivalent for
   convenience. */
#define PKT_MDC_VERSION			0x3031  /* "01" */
#define PKT_MDC_TEL_END			0x3032  /* "02" */
#define PKT_MDC_TGT			0x3033  /* "03" */
#define PKT_MDC_HTTP_ACC		0x3034  /* "04" */
#define PKT_MDC_SYSLOG			0x3035  /* "05" */
#define PKT_MDC_NCS			0x3036  /* "06" */
#define PKT_MDC_PRI_LINE		0x3037  /* "07" */
#define PKT_MDC_VENDOR_TLV		0x3038  /* "08" */
#define PKT_MDC_NVRAM_STOR		0x3039  /* "09" */
#define PKT_MDC_PROV_REP		0x3041  /* "0A" */
#define PKT_MDC_PROV_REP_LC		0x3061  /* "0a" */
#define PKT_MDC_SUPP_CODECS		0x3042  /* "0B" */
#define PKT_MDC_SUPP_CODECS_LC		0x3062  /* "0b" */
#define PKT_MDC_SILENCE			0x3043  /* "0C" */
#define PKT_MDC_SILENCE_LC		0x3063  /* "0c" */
#define PKT_MDC_ECHO_CANCEL		0x3044  /* "0D" */
#define PKT_MDC_ECHO_CANCEL_LC		0x3064  /* "0d" */
#define PKT_MDC_RSVP			0x3045  /* "0E" */
#define PKT_MDC_RSVP_LC			0x3065  /* "0e" */
#define PKT_MDC_UGS_AD			0x3046  /* "0F" */
#define PKT_MDC_UGS_AD_LC		0x3066  /* "0f" */
#define PKT_MDC_IF_INDEX		0x3130  /* "10" */
#define PKT_MDC_FLOW_LOG		0x3131  /* "11" */
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
	{ 0x3031,	"other" },           /* "01" */
	{ 0x3032,	"unknown" },
	{ 0x3033,	"G.729" },
	{ 0x3034,	"reserved" },
	{ 0x3035,	"G.729E" },
	{ 0x3036,	"PCMU" },
	{ 0x3037,	"G.726-32" },
	{ 0x3038,	"G.728" },
	{ 0x3039,	"PCMA" },            /* "09" */
	{ 0x3041,	"G.726-16" },        /* "0A" */
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

static const value_string pkt_mdc_supp_flow_vals[] = {
	{ 1 << 0, "Secure Flow (Full Secure Provisioning Flow)" },
	{ 1 << 1, "Hybrid Flow" },
	{ 1 << 2, "Basic Flow" },
	{ 0, NULL }
};

#define PKT_MDC_MIB_CL 0x3030
static const value_string pkt_mdc_cl_mib_vals[] = {
	{ 1 << 0, "PacketCable 1.5 MTA MIB" },
	{ 1 << 1, "PacketCable 1.5 Signaling MIB" },
	{ 1 << 2, "PacketCable 1.5 Management Event MIB" },
	{ 1 << 3, "PacketCable 1.5 MTA Extension MIB" },
	{ 1 << 4, "PacketCable 1.5 Signaling Extension MIB" },
	{ 1 << 5, "PacketCable 1.5 MEM Extension MIB" },
	{ 1 << 6, "Reserved" },
	{ 1 << 7, "Reserved" },
	{ 0, NULL }
};

#define PKT_MDC_MIB_IETF 0x3031
static const value_string pkt_mdc_ietf_mib_vals[] = {
	{ 1 << 0, "IETF MTA MIB" },
	{ 1 << 1, "IETF Signaling MIB" },
	{ 1 << 2, "IETF Management Event MIB" },
	{ 1 << 3, "Reserved" },
	{ 1 << 4, "Reserved" },
	{ 1 << 5, "Reserved" },
	{ 1 << 6, "Reserved" },
	{ 1 << 7, "Reserved" },
	{ 0, NULL }
};

#define PKT_MDC_MIB_EURO 0x3032
static const value_string pkt_mdc_euro_mib_vals[] = {
	{ 1 << 0, "PacketCable 1.5 MTA MIB" },
	{ 1 << 1, "PacketCable 1.5 Signaling MIB" },
	{ 1 << 2, "PacketCable 1.5 Management Event MIB" },
	{ 1 << 3, "PacketCable 1.5 MTA Extension MIB" },
	{ 1 << 4, "PacketCable 1.5 Signaling Extension MIB" },
	{ 1 << 5, "PacketCable 1.5 MEM Extension MIB" },
	{ 1 << 6, "Reserved" },
	{ 1 << 7, "Reserved" },
	{ 0, NULL }
};


static void
dissect_packetcable_mta_cap(proto_tree *v_tree, tvbuff_t *tvb, int voff, int len)
{
	guint16 raw_val;
	unsigned long flow_val = 0;
	int off = PKT_MDC_TLV_OFF + voff;
	int subopt_off, max_len;
	guint tlv_len, i, mib_val;
	guint8 asc_val[3] = "  ", flow_val_str[5];
	char bit_fld[64];
	proto_item *ti, *mib_ti;
	proto_tree *subtree, *subtree2;

	tvb_memcpy (tvb, asc_val, off, 2);
	if (sscanf((gchar*)asc_val, "%x", &tlv_len) != 1 || tlv_len > 0xff) {
		proto_tree_add_text(v_tree, tvb, off, len - off,
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
				proto_tree_add_text(v_tree, tvb, off, len - off,
						    "[Bogus length: %s]", asc_val);
				return;
			} else {
				/* Value(s) */

				ti = proto_tree_add_text(v_tree,
				    tvb, off, (tlv_len * 2) + 4,
				    "0x%s: %s = ",
				    tvb_format_text(tvb, off, 2),
				    val_to_str(raw_val, pkt_mdc_type_vals, "unknown"));
				switch (raw_val) {

				case PKT_MDC_VERSION:
					raw_val = tvb_get_ntohs(tvb, off + 4);
					proto_item_append_text(ti,
							       "%s (%s)",
							       val_to_str(raw_val, pkt_mdc_version_vals, "Reserved"),
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
							       val_to_str(raw_val, pkt_mdc_boolean_vals, "unknown"),
							       tvb_format_stringzpad(tvb, off + 4, 2) );
					break;

				case PKT_MDC_SUPP_CODECS:
				case PKT_MDC_SUPP_CODECS_LC:
					for (i = 0; i < tlv_len; i++) {
						raw_val = tvb_get_ntohs(tvb, off + 4 + (i * 2) );
						proto_item_append_text(ti,
								       "%s%s (%s)",
								       plurality(i + 1, "", ", "),
								       val_to_str(raw_val, pkt_mdc_codec_vals, "unknown"),
								       tvb_format_stringzpad(tvb, off + 4 + (i * 2), 2) );
					}
					break;

				case PKT_MDC_PROV_FLOWS:
					tvb_memcpy(tvb, flow_val_str, off + 4, 4);
					flow_val_str[4] = '\0';
					flow_val = strtoul((gchar*)flow_val_str, NULL, 16);
					proto_item_append_text(ti,
							       "0x%04lx", flow_val);
					break;

				case PKT_MDC_T38_VERSION:
					raw_val = tvb_get_ntohs(tvb, off + 4);
					proto_item_append_text(ti,
							       "%s (%s)",
							       val_to_str(raw_val, pkt_mdc_t38_version_vals, "unknown"),
							       tvb_format_stringzpad(tvb, off + 4, 2) );
					break;

				case PKT_MDC_T38_EC:
					raw_val = tvb_get_ntohs(tvb, off + 4);
					proto_item_append_text(ti,
							       "%s (%s)",
							       val_to_str(raw_val, pkt_mdc_t38_ec_vals, "unknown"),
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
				for (i = 0 ; i < 3; i++) {
					if (flow_val & pkt_mdc_supp_flow_vals[i].value) {
						decode_bitfield_value(bit_fld, flow_val, pkt_mdc_supp_flow_vals[i].value, 16);
						proto_tree_add_text(subtree, tvb, off + 4, 4, "%s%s",
							bit_fld, pkt_mdc_supp_flow_vals[i].strptr);
					}
				}
			} else if (raw_val == PKT_MDC_MIBS) {
			/* 17 06 02 00 38 02 01 07 */
				subopt_off = off + 4;
				max_len = subopt_off + (tlv_len * 2);
				while (subopt_off < max_len) {
					raw_val = tvb_get_ntohs(tvb, subopt_off);
					if (raw_val != 0x3032) { /* We only know how to handle a length of 2 */
						tvb_memcpy(tvb, asc_val, subopt_off, 2);
						proto_tree_add_text(subtree, tvb, subopt_off, 2,
									"[Bogus length: %s]", asc_val);
						return;
					}

					subopt_off += 2;
					raw_val = tvb_get_ntohs(tvb, subopt_off);
					tvb_memcpy(tvb, asc_val, subopt_off, 2);

					mib_ti = proto_tree_add_text(subtree, tvb, subopt_off, 2, "%s (%s)",
						val_to_str(raw_val, pkt_mdc_mib_orgs, "Unknown"), asc_val);
					if (subopt_off > off + 4 + 2) {
						proto_item_append_text(ti, ", ");
					}
					proto_item_append_text(ti, "%s", val_to_str(raw_val, pkt_mdc_mib_orgs, "Unknown"));

					subopt_off += 2;
					tvb_memcpy(tvb, asc_val, subopt_off, 2);
					if (sscanf((gchar*)asc_val, "%x", &mib_val) != 1) {
						proto_tree_add_text(v_tree, tvb, subopt_off, 2,
									"[Bogus bitfield: %s]", asc_val);
						return;
					}
					switch (raw_val) {

					case PKT_MDC_MIB_CL:
						subtree2 = proto_item_add_subtree(mib_ti, ett_bootp_option);

						for (i = 0; i < 8; i++) {
							if (mib_val & pkt_mdc_cl_mib_vals[i].value) {
								decode_bitfield_value(bit_fld, mib_val, pkt_mdc_cl_mib_vals[i].value, 8);
								proto_tree_add_text(subtree2, tvb, subopt_off, 2,
										    "%s%s", bit_fld, pkt_mdc_cl_mib_vals[i].strptr);
							}
						}
						break;

					case PKT_MDC_MIB_IETF:
						subtree2 = proto_item_add_subtree(mib_ti, ett_bootp_option);

						for (i = 0; i < 8; i++) {
							if (mib_val & pkt_mdc_ietf_mib_vals[i].value) {
								decode_bitfield_value(bit_fld, mib_val, pkt_mdc_ietf_mib_vals[i].value, 8);
								proto_tree_add_text(subtree2, tvb, subopt_off, 2,
										    "%s%s", bit_fld, pkt_mdc_ietf_mib_vals[i].strptr);
							}
						}
						break;

					case PKT_MDC_MIB_EURO:
						subtree2 = proto_item_add_subtree(mib_ti, ett_bootp_option);

						for (i = 0; i < 8; i++) {
							if (mib_val & pkt_mdc_euro_mib_vals[i].value) {
								decode_bitfield_value(bit_fld, mib_val, pkt_mdc_euro_mib_vals[i].value, 8);
								proto_tree_add_text(subtree2, tvb, subopt_off, 2,
										    "%s%s", bit_fld, pkt_mdc_euro_mib_vals[i].strptr);
							}
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
#define DOCSIS_CM_CAP_USID_SUP		0x08
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

static const value_string docsis_cm_cap_type_vals[] = {
	{ DOCSIS_CM_CAP_CONCAT_SUP,		"Concatenation Support" },
	{ DOCSIS_CM_CAP_DOCSIS_VER,		"DOCSIS Version" },
	{ DOCSIS_CM_CAP_FRAG_SUP,		"Fragmentation Support" },
	{ DOCSIS_CM_CAP_PHS_SUP,		"PHS Support" },
	{ DOCSIS_CM_CAP_IGMP_SUP,		"IGMP Support" },
	{ DOCSIS_CM_CAP_PRIV_SUP,		"Privacy Support" },
	{ DOCSIS_CM_CAP_DSAID_SUP,		"Downstream SAID Support" },
	{ DOCSIS_CM_CAP_USID_SUP,		"Upstream SID Support" },
	{ DOCSIS_CM_CAP_FILT_SUP,		"Optional Filtering Support" },
	{ DOCSIS_CM_CAP_TET_MI,			"Transmit Equalizer Taps per Modulation Interval" },
	{ DOCSIS_CM_CAP_TET,			"Number of Transmit Equalizer Taps" },
	{ DOCSIS_CM_CAP_DCC_SUP,		"DCC Support" },
	{ DOCSIS_CM_CAP_IPFILT_SUP,		"IP Filters Support" },
	{ DOCSIS_CM_CAP_LLCFILT_SUP,		"LLC Filters Support" },
	{ DOCSIS_CM_CAP_EXPUNI_SPACE,		"Expanded Unicast SID Space" },
	{ DOCSIS_CM_CAP_RNGHLDOFF_SUP, 		"Ranging Hold-Off Support" },
	{ DOCSIS_CM_CAP_L2VPN_SUP,		"L2VPN Capability" },
	{ DOCSIS_CM_CAP_L2VPN_HOST_SUP, 	"eSAFE Host Capability" },
	{ DOCSIS_CM_CAP_DUTFILT_SUP,		"DUT Filtering" },
	{ DOCSIS_CM_CAP_USFREQRNG_SUP, 		"Upstream Frequency Range Support" },
	{ DOCSIS_CM_CAP_USSYMRATE_SUP, 		"Upstream Symbol Rate Support" },
	{ DOCSIS_CM_CAP_SACM2_SUP,		"Selectable Active Code Mode 2 Support" },
	{ DOCSIS_CM_CAP_SACM2HOP_SUP,		"Code Hopping SAC Mode 2 is supported" },
	{ DOCSIS_CM_CAP_MULTTXCHAN_SUP, 	"Multiple Transmit Channel Support" },
	{ DOCSIS_CM_CAP_512USTXCHAN_SUP, 	"5.12 Msps Upstream Transmit Channel Support" },
	{ DOCSIS_CM_CAP_256USTXCHAN_SUP, 	"2.56 Msps Upstream Transmit Channel Support" },
	{ DOCSIS_CM_CAP_TOTALSIDCLU_SUP, 	"Total SID Cluster Support" },
	{ DOCSIS_CM_CAP_SIDCLUPERSF_SUP, 	"SID Clusters per Service Flow Support" },
	{ DOCSIS_CM_CAP_MULTRXCHAN_SUP, 	"Multiple Receive Channel Support" },
	{ DOCSIS_CM_CAP_TOTALDSID_SUP, 		"Total Downstream Service ID (DSID) Support" },
	{ DOCSIS_CM_CAP_RESEQDSID_SUP, 		"Resequencing Downstream Service ID (DSID) Support" },
	{ DOCSIS_CM_CAP_MULTDSID_SUP, 		"Multicast Downstream Service ID (DSID) Support" },
	{ DOCSIS_CM_CAP_MULTDSIDFW_SUP, 	"Multicast DSID Forwarding" },
	{ DOCSIS_CM_CAP_FCTF_SUP,		"Frame Control Type Forwarding Capability" },
	{ DOCSIS_CM_CAP_DPV_SUP,		"DPV Capability" },
	{ DOCSIS_CM_CAP_UGSPERUSFLOW_SUP, 	"Unsolicited Grant Service/Upstream Service Flow Support" },
	{ DOCSIS_CM_CAP_MAPUCDRECEIPT_SUP, 	"MAP and UCD Receipt Support" },
	{ DOCSIS_CM_CAP_USDROPCLASSIF_SUP, 	"Upstream Drop Classifier Support" },
	{ DOCSIS_CM_CAP_IPV6_SUP,		"IPv6 Support" },
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

static const value_string docsis_cm_cap_ranging_hold_off_vals[] = {
	{ 1 << 0, "CM" },
	{ 1 << 1, "ePS or eRouter" },
	{ 1 << 2, "EMTA or EDVA" },
	{ 1 << 3, "DSG/eSTB" },
	{ 0, NULL }
};

static const value_string docsis_cm_cap_l2vpn_vals[] = {
	{ 0x00,	"CM not compliant with DOCSIS L2VPN Section 7 (default)" },
	{ 0x01,	"CM compliant with DOCSIS L2VPN Section 7" },
	{ 0,		NULL }
};

static const value_string docsis_cm_cap_filt_vals[] = {
	{ 0x00,	"None" },
	{ 0x01,	"802.1p Filtering" },
	{ 0x01,	"802.1Q Filtering" },
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
	{ 0x01,	"U1 supported as a Start Reference Point for DPV per Path" },
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

static const value_string docsis_cm_cap_ussymrate_vals[] = {
	{ 1 << 0, "160  ksps symbol rate supported" },
	{ 1 << 1, "320  ksps symbol rate supported" },
	{ 1 << 2, "640  ksps symbol rate supported" },
	{ 1 << 3, "1280 ksps symbol rate supported" },
	{ 1 << 4, "2560 ksps symbol rate supported" },
	{ 1 << 5, "5120 ksps symbol rate supported" },
	{ 0, NULL }
};

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
	*tlvlen  = tvb_get_guint8(tvb, off+1);
	/* Value */
	*value = ep_tvb_memdup(tvb, off + 2, *tlvlen);
}

static void get_opt60_tlv(tvbuff_t *tvb, guint off, guint8 *tlvtype, guint8 *tlvlen, guint8 **value)
{
	guint  i;
	guint8  *val_asc;
	val_asc = (guint8 *)ep_alloc0(4);
	/* Type */
	tvb_memcpy(tvb, val_asc, off, 2);
	*tlvtype = (guint8)strtoul((gchar*)val_asc, NULL, 16);
	/* Length */
	tvb_memcpy(tvb, val_asc, off + 2, 2);
	*tlvlen = (guint8)strtoul((gchar*)val_asc, NULL, 16);
	/* Value */
	*value = (guint8 *)ep_alloc0(*tlvlen);
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
	guint8 *asc_val;
	guint i;
	proto_item *ti;
	proto_tree *subtree;
	char bit_fld[64];
	guint8 tlv_type;
	guint8 tlv_len;
	guint8 val_byte = 0;
	guint16 val_uint16 = 0;
	guint8 *val_other = NULL;
	guint off = voff;

	asc_val = ep_alloc0(4);

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
		/* Option 60 is formatted as an ascii string.
		   Since the capabilities are the same for both options
		   I am converting the Option 60 values from ascii to
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
                                                         val_to_str(tlv_type, docsis_cm_cap_type_vals, "unknown"));
		}
		else
		{
			/* Option 60 is formatted as an ascii string.  Since the capabilities
			   are the same for both options I am converting the Option 60 values
			   from ascii to uint8s to allow the same parser to work for both */
			get_opt60_tlv(tvb, off, &tlv_type, &tlv_len, &val_other);
			ti =  proto_tree_add_uint_format(v_tree, hf_bootp_docsis_cm_cap_type, tvb, off,
                                                         (tlv_len * 2) + 4,
                                                         tlv_type,
                                                         "0x%02x: %s = ",
                                                         tlv_type,
                                                         val_to_str(tlv_type, docsis_cm_cap_type_vals, "unknown"));
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
					       val_to_str(val_byte, docsis_cm_cap_supported_vals, "Reserved"));
			break;
		case DOCSIS_CM_CAP_DOCSIS_VER:
			proto_item_append_text(ti,
					       "%s",
					       val_to_str(val_byte, docsis_cm_cap_version_vals, "Reserved"));
			break;
		case DOCSIS_CM_CAP_PRIV_SUP:
			proto_item_append_text(ti,
					       "%s",
					       val_to_str(val_byte, docsis_cm_cap_privacy_vals, "Reserved"));
			break;
		case DOCSIS_CM_CAP_FILT_SUP:
			proto_item_append_text(ti,
					       "%s",
					       val_to_str(val_byte, docsis_cm_cap_filt_vals, "Reserved"));
			break;
		case DOCSIS_CM_CAP_L2VPN_SUP:
			proto_item_append_text(ti,
					       "%s",
					       val_to_str(val_byte, docsis_cm_cap_l2vpn_vals, "Reserved"));
			break;
		case DOCSIS_CM_CAP_L2VPN_HOST_SUP:
			if (tlv_len == 7) {
				proto_item_append_text(ti,
						       "eSAFE ifIndex %s (%i)/eSAFE MAC %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
						       val_to_str(val_other[0], docsis_cm_cap_map_l2vpn_esafe_index_support_vals, "Reserved"),
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
					       val_to_str(val_byte, docsis_cm_cap_usfreqrng_vals, "Reserved"));
			break;
		case DOCSIS_CM_CAP_MAPUCDRECEIPT_SUP:
			proto_item_append_text(ti,
					       "%s",
					       val_to_str(val_byte, docsis_cm_cap_map_ucd_receipt_vals, "Reserved"));
			break;
		case DOCSIS_CM_CAP_DPV_SUP:
			proto_item_append_text(ti,
					       "%s",
					       val_to_str(val_byte, docsis_cm_cap_map_dpv_support_vals, "Reserved"));
			break;
		case DOCSIS_CM_CAP_DSAID_SUP:
		case DOCSIS_CM_CAP_MULTTXCHAN_SUP:
		case DOCSIS_CM_CAP_512USTXCHAN_SUP:
		case DOCSIS_CM_CAP_256USTXCHAN_SUP:
		case DOCSIS_CM_CAP_TOTALSIDCLU_SUP:
		case DOCSIS_CM_CAP_MULTRXCHAN_SUP:
		case DOCSIS_CM_CAP_UGSPERUSFLOW_SUP:
			display_uint_with_range_checking(ti, val_byte, val_uint16, 0, 255);
			break;
		case DOCSIS_CM_CAP_USID_SUP:
			display_uint_with_range_checking(ti, val_byte, val_uint16,1, 255);
			break;
		case DOCSIS_CM_CAP_RESEQDSID_SUP:
		case DOCSIS_CM_CAP_MULTDSID_SUP:
			display_uint_with_range_checking(ti, val_byte, val_uint16, 16, 255);
			break;
		case DOCSIS_CM_CAP_SIDCLUPERSF_SUP:
			display_uint_with_range_checking(ti, val_byte, val_uint16, 2, 8);
			break;
		case DOCSIS_CM_CAP_TOTALDSID_SUP:
			display_uint_with_range_checking(ti, val_byte, val_uint16, 3, 255);
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
		case DOCSIS_CM_CAP_RNGHLDOFF_SUP:
			proto_item_append_text(ti,
					       "Ranging ID ");
			proto_item_append_text(ti,
					       "(0x%04x)", (val_other[0] << sizeof(guint8)) + val_other[1]);
			proto_item_append_text(ti,
					       " Component Bit Mask ");
			proto_item_append_text(ti,
					       "(0x%04x)", (val_other[2] << sizeof(guint8)) + val_other[3]);
			break;
		case DOCSIS_CM_CAP_USSYMRATE_SUP:
			proto_item_append_text(ti,
					       "0x%02x", val_byte);
			break;
		case DOCSIS_CM_CAP_FCTF_SUP:
			proto_item_append_text(ti,
					       "%s",
					       val_to_str(val_byte, docsis_cm_cap_map_fctfc_support_vals, "Reserved"));
			break;
		case DOCSIS_CM_CAP_MULTDSIDFW_SUP:
			proto_item_append_text(ti,
					       "%s",
					       val_to_str(val_byte, docsis_cm_cap_map_multDsidForward_support_vals, "Reserved"));
			break;
		}

		subtree = proto_item_add_subtree(ti, ett_bootp_option);
		if (tlv_type == DOCSIS_CM_CAP_RNGHLDOFF_SUP)
		{
			for (i = 0 ; i < 4; i++)
			{
				decode_bitfield_value(bit_fld,
						      (val_other[2] << sizeof(guint8)) + val_other[3],
						      docsis_cm_cap_ranging_hold_off_vals[i].value,
						      16);
				proto_tree_add_text(subtree, tvb, off + 1, 4, "%s%s",
						    bit_fld, docsis_cm_cap_ranging_hold_off_vals[i].strptr);
			}
		}
		if (tlv_type == DOCSIS_CM_CAP_USSYMRATE_SUP)
		{
			for (i = 0 ; i < 6; i++)
			{
				decode_bitfield_value(bit_fld, val_byte,docsis_cm_cap_ussymrate_vals[i].value, 16);
				proto_tree_add_text(subtree, tvb, off + 1, 4, "%s%s",
						    bit_fld, docsis_cm_cap_ussymrate_vals[i].strptr);

			}
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
#define PKT_CCC_AS_KRB        10
#define PKT_CCC_AP_KRB        11
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
dissect_packetcable_i05_ccc(proto_tree *v_tree, tvbuff_t *tvb, int optoff,
    int optend)
{
	int suboptoff = optoff;
	guint8 subopt, subopt_len, fetch_tgt, timer_val, ticket_ctl;
	proto_tree *pkt_s_tree;
	proto_item *vti;

	subopt = tvb_get_guint8(tvb, optoff);
	suboptoff++;

	if (suboptoff >= optend) {
		proto_tree_add_text(v_tree, tvb, optoff, 1,
			"Suboption %d: no room left in option for suboption length",
	 		subopt);
	 	return (optend);
	}
	subopt_len = tvb_get_guint8(tvb, optoff);
	suboptoff++;

	vti = proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
	    "Suboption %u: %s: ", subopt,
	    val_to_str(subopt, pkt_i05_ccc_opt_vals, "unknown/reserved") );

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
			proto_item_append_text(vti,
					       "no room left in option for suboption value");
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
			proto_item_append_text(vti,
					       "no room left in option for suboption value");
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
			proto_item_append_text(vti,
					       "no room left in option for suboption value");
			return (optend);
		}
		proto_item_append_text(vti, "(%u byte%s%s)", subopt_len,
				       plurality(subopt_len, "", "s"),
				       subopt_len != 12 ? " [Invalid]" : "");
		if (subopt_len == 12) {
			pkt_s_tree = proto_item_add_subtree(vti, ett_bootp_option);
			proto_tree_add_text(pkt_s_tree, tvb, suboptoff, 4,
					    "pktcMtaDevRealmUnsolicitedKeyNomTimeout: %u",
					    tvb_get_ntohl(tvb, suboptoff));
			proto_tree_add_text(pkt_s_tree, tvb, suboptoff + 4, 4,
					    "pktcMtaDevRealmUnsolicitedKeyMaxTimeout: %u",
					    tvb_get_ntohl(tvb, suboptoff + 4));
			proto_tree_add_text(pkt_s_tree, tvb, suboptoff + 8, 4,
					    "pktcMtaDevRealmUnsolicitedKeyMaxRetries: %u",
					    tvb_get_ntohl(tvb, suboptoff + 8));
		}
		suboptoff += subopt_len;
		break;

	case PKT_CCC_AP_KRB:
		if (suboptoff+12 > optend) {
			proto_item_append_text(vti,
					       "no room left in option for suboption value");
			return (optend);
		}
		proto_item_append_text(vti, "(%u byte%s%s)", subopt_len,
				       plurality(subopt_len, "", "s"),
				       subopt_len != 12 ? " [Invalid]" : "");
		if (subopt_len == 12) {
			pkt_s_tree = proto_item_add_subtree(vti, ett_bootp_option);
			proto_tree_add_text(pkt_s_tree, tvb, suboptoff, 4,
					    "pktcMtaDevProvUnsolicitedKeyNomTimeout: %u",
					    tvb_get_ntohl(tvb, suboptoff));
			proto_tree_add_text(pkt_s_tree, tvb, suboptoff + 4, 4,
					    "pktcMtaDevProvUnsolicitedKeyMaxTimeout: %u",
					    tvb_get_ntohl(tvb, suboptoff + 4));
			proto_tree_add_text(pkt_s_tree, tvb, suboptoff + 8, 4,
					    "pktcMtaDevProvUnsolicitedKeyMaxRetries: %u",
					    tvb_get_ntohl(tvb, suboptoff + 8));
		}
		suboptoff += subopt_len;
		break;

	case PKT_CCC_MTA_KRB_CLEAR:
		if (suboptoff+1 > optend) {
			proto_item_append_text(vti,
					       "no room left in option for suboption value");
			return (optend);
		}
		ticket_ctl = tvb_get_guint8(tvb, suboptoff);
		proto_item_append_text(vti, "%s (%u) (%u byte%s%s)",
				       val_to_str (ticket_ctl, pkt_i05_ccc_ticket_ctl_vals, "unknown/invalid"),
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


static const value_string sec_tcm_vals[] = {
	{ 1 << 0, "PacketCable Provisioning Server" },
	{ 1 << 1, "All PacketCable Call Management Servers" },
	{ 0, NULL }
};

static int
dissect_packetcable_ietf_ccc(proto_tree *v_tree, tvbuff_t *tvb, int optoff,
    int optend, int revision)
{
	int suboptoff = optoff;
	guint8 subopt, subopt_len;
	guint32 ipv4addr;
	guint8 prov_type, fetch_tgt, timer_val;
	guint16 sec_tcm;
	proto_tree *pkt_s_tree;
	proto_item *vti;
	int max_timer_val = 255, i;
	const guchar *dns_name;
	char bit_fld[24];

	subopt = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	if (suboptoff >= optend) {
		proto_tree_add_text(v_tree, tvb, optoff, 1,
			"Suboption %d: no room left in option for suboption length",
	 		subopt);
	 	return (optend);
	}
	subopt_len = tvb_get_guint8(tvb, suboptoff);
	suboptoff++;

	vti = proto_tree_add_text(v_tree, tvb, optoff, subopt_len + 2,
	    "Suboption %u: %s: ", subopt,
	    val_to_str(subopt, pkt_draft5_ccc_opt_vals, "unknown/reserved") );

	switch (subopt) {

	case PKT_CCC_PRI_DHCP:	/* IPv4 values */
	case PKT_CCC_SEC_DHCP:
		if (suboptoff+4 > optend) {
			proto_item_append_text(vti,
					       "no room left in option for suboption value");
			return (optend);
		}
		ipv4addr = tvb_get_ipv4(tvb, suboptoff);
		proto_item_append_text(vti, "%s (%u byte%s%s)",
				       ip_to_str((guint8 *)&ipv4addr),
				       subopt_len,
				       plurality(subopt_len, "", "s"),
				       subopt_len != 4 ? " [Invalid]" : "");
		suboptoff += subopt_len;
		break;

	case PKT_CCC_IETF_PROV_SRV:
		if (suboptoff+1 > optend) {
			proto_item_append_text(vti,
					       "no room left in option for suboption value");
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
				proto_item_append_text(vti,
						       "no room left in option for suboption value");
				return (optend);
			}
			ipv4addr = tvb_get_ipv4(tvb, suboptoff);
			proto_item_append_text(vti, "%s (%u byte%s%s)",
					       ip_to_str((guint8 *)&ipv4addr),
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
			proto_item_append_text(vti,
					       "no room left in option for suboption value");
			return (optend);
		}
		proto_item_append_text(vti, "(%u byte%s%s)", subopt_len,
				       plurality(subopt_len, "", "s"),
				       subopt_len != 12 ? " [Invalid]" : "");
		if (subopt_len == 12) {
			pkt_s_tree = proto_item_add_subtree(vti, ett_bootp_option);
			proto_tree_add_text(pkt_s_tree, tvb, suboptoff, 4,
					    "pktcMtaDevRealmUnsolicitedKeyNomTimeout: %u",
					    tvb_get_ntohl(tvb, suboptoff));
			proto_tree_add_text(pkt_s_tree, tvb, suboptoff + 4, 4,
					    "pktcMtaDevRealmUnsolicitedKeyMaxTimeout: %u",
					    tvb_get_ntohl(tvb, suboptoff + 4));
			proto_tree_add_text(pkt_s_tree, tvb, suboptoff + 8, 4,
					    "pktcMtaDevRealmUnsolicitedKeyMaxRetries: %u",
					    tvb_get_ntohl(tvb, suboptoff + 8));
		}
		suboptoff += subopt_len;
		break;

	case PKT_CCC_IETF_AP_KRB:
		proto_item_append_text(vti, "(%u byte%s%s)", subopt_len,
				       plurality(subopt_len, "", "s"),
				       subopt_len != 12 ? " [Invalid]" : "");
		if (subopt_len == 12) {
			pkt_s_tree = proto_item_add_subtree(vti, ett_bootp_option);
			proto_tree_add_text(pkt_s_tree, tvb, suboptoff, 4,
					    "pktcMtaDevProvUnsolicitedKeyNomTimeout: %u",
					    tvb_get_ntohl(tvb, suboptoff));
			proto_tree_add_text(pkt_s_tree, tvb, suboptoff + 4, 4,
					    "pktcMtaDevProvUnsolicitedKeyMaxTimeout: %u",
					    tvb_get_ntohl(tvb, suboptoff + 4));
			proto_tree_add_text(pkt_s_tree, tvb, suboptoff + 8, 4,
					    "pktcMtaDevProvUnsolicitedKeyMaxRetries: %u",
					    tvb_get_ntohl(tvb, suboptoff + 8));
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
			proto_item_append_text(vti,
					       "no room left in option for suboption value");
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
			proto_item_append_text(vti,
					       "no room left in option for suboption value");
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
			proto_item_append_text(vti,
					       "no room left in option for suboption value");
			return (optend);
		}
		sec_tcm = tvb_get_ntohs(tvb, suboptoff);
		proto_item_append_text(vti, "0x%04x (%u byte%s%s)", sec_tcm, subopt_len,
				       plurality(subopt_len, "", "s"),
				       subopt_len != 2 ? " [Invalid]" : "");
		if (subopt_len == 2) {
			pkt_s_tree = proto_item_add_subtree(vti, ett_bootp_option);
			for (i = 0; i < 2; i++) {
				if (sec_tcm & sec_tcm_vals[i].value) {
					decode_bitfield_value(bit_fld, sec_tcm, sec_tcm_vals[i].value, 16);
					proto_tree_add_text(pkt_s_tree, tvb, suboptoff, 2, "%sInvalidate %s",
							    bit_fld, sec_tcm_vals[i].strptr);
				}
			}
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

static void
dissect_bootp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*bp_tree;
	proto_item	*ti;
	proto_tree	*flag_tree;
	proto_item	*fi, *hidden_item;
	guint8		op;
	guint8		htype, hlen;
	int		voff, eoff, tmpvoff; /* vendor offset, end offset */
	guint32		ip_addr;
	gboolean	at_end;
	const char	*dhcp_type = NULL;
	const guint8	*vendor_class_id = NULL;
	guint16		flags, secs;
	int		offset_delta;
	guint8		overload = 0; /* DHCP option overload */

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
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_add_fstr(pinfo->cinfo, COL_INFO, "Boot Request from %s (%s)",
					     tvb_arphrdaddr_to_str(tvb, 28, hlen, htype),
					     get_ether_name(tvb_get_ptr(tvb, 28, hlen)));
			}
		}
		else {
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_add_fstr(pinfo->cinfo, COL_INFO, "Boot Request from %s",
					     tvb_arphrdaddr_to_str(tvb, 28, hlen, htype));
			}
		}
		break;

	case BOOTREPLY:
		col_set_str(pinfo->cinfo, COL_INFO, "Boot Reply");
		break;

	default:
		if (check_col(pinfo->cinfo, COL_INFO))
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

	/*
	 * In the first pass, we just look for the DHCP message type
	 * and Vendor class identifier options.
	 */
	tmpvoff = voff;
	at_end = FALSE;
	while (tmpvoff < eoff && !at_end) {
		offset_delta = bootp_option(tvb, pinfo, 0, tmpvoff, eoff, TRUE, &at_end,
		    &dhcp_type, &vendor_class_id, &overload);
		if (offset_delta <= 0) {
			THROW(ReportedBoundsError);
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
		if (check_col(pinfo->cinfo, COL_INFO))
			col_add_fstr(pinfo->cinfo, COL_INFO, "DHCP %-8s - Transaction ID 0x%x",
				     dhcp_type, tvb_get_ntohl(tvb, 4));
		tap_queue_packet( bootp_dhcp_tap, pinfo, dhcp_type);
	}

	/*
	 * OK, now build the protocol tree.
	 */

	ti = proto_tree_add_item(tree, proto_bootp, tvb, 0, -1, FALSE);
	bp_tree = proto_item_add_subtree(ti, ett_bootp);

	proto_tree_add_uint(bp_tree, hf_bootp_type, tvb,
				   0, 1,
				   op);
	proto_tree_add_uint_format_value(bp_tree, hf_bootp_hw_type, tvb,
					 1, 1,
					 htype,
					 "%s",
					 arphrdtype_to_str(htype,
						     "Unknown (0x%02x)"));
	proto_tree_add_uint(bp_tree, hf_bootp_hw_len, tvb,
			    2, 1, hlen);
	proto_tree_add_item(bp_tree, hf_bootp_hops, tvb,
			    3, 1, FALSE);
	proto_tree_add_item(bp_tree, hf_bootp_id, tvb,
			    4, 4, FALSE);
	/*
	 * Windows (98, XP and Vista tested) sends the "secs" value on
	 * the wire formatted as little-endian. See if the LE value
	 * makes sense.
	 */
	secs = tvb_get_letohs(tvb, 8);
	if (secs > 0 && secs <= 0xff) {
		ti = proto_tree_add_uint_format_value(bp_tree, hf_bootp_secs, tvb,
			    8, 2, secs, "%u", secs);
		expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_NOTE,
			    "Seconds elapsed (%u) appears to be encoded as little-endian", secs);
	} else {
		proto_tree_add_item(bp_tree, hf_bootp_secs, tvb,
			    8, 2, FALSE);
	}
	flags = tvb_get_ntohs(tvb, 10);
	fi = proto_tree_add_uint(bp_tree, hf_bootp_flags, tvb,
			    10, 2, flags);
	proto_item_append_text(fi, " (%s)",
	    (flags & BOOTP_BC) ? "Broadcast" : "Unicast");
	flag_tree = proto_item_add_subtree(fi, ett_bootp_flags);
	proto_tree_add_boolean(flag_tree, hf_bootp_flags_broadcast, tvb,
			    10, 2, flags);
	proto_tree_add_uint(flag_tree, hf_bootp_flags_reserved, tvb,
			    10, 2, flags);
	proto_tree_add_item(bp_tree, hf_bootp_ip_client, tvb,
			    12, 4, FALSE);
	proto_tree_add_item(bp_tree, hf_bootp_ip_your, tvb,
			    16, 4, FALSE);
	proto_tree_add_item(bp_tree, hf_bootp_ip_server, tvb,
			    20, 4, FALSE);
	proto_tree_add_item(bp_tree, hf_bootp_ip_relay, tvb,
			    24, 4, FALSE);

	if (hlen > 0 && hlen <= 16) {
		if ((htype == ARPHRD_ETHER || htype == ARPHRD_IEEE802)
		    && hlen == 6)
			proto_tree_add_item(bp_tree, hf_bootp_hw_ether_addr, tvb, 28, 6, FALSE);
		else
			/* The chaddr element is 16 bytes in length,
			   although only the first hlen bytes are used */
			proto_tree_add_bytes_format_value(bp_tree, hf_bootp_hw_addr, tvb, 28, 16,
					   NULL, "%s", tvb_arphrdaddr_to_str(tvb, 28, hlen, htype));
		if ((16 - hlen) > 0)
			proto_tree_add_item(bp_tree, hf_bootp_hw_addr_padding, tvb, 28+hlen, 16-hlen, FALSE);
	} else {
		proto_tree_add_text(bp_tree,  tvb,
					   28, 16, "Client address not given");
	}

	if (overload & OPT_OVERLOAD_SNAME) {
		proto_tree_add_text (bp_tree, tvb,
			SERVER_NAME_OFFSET, SERVER_NAME_LEN,
			"Server name option overloaded by DHCP");
	} else {
		/* The server host name is optional */
		if (tvb_get_guint8(tvb, SERVER_NAME_OFFSET) != '\0') {
			proto_tree_add_item(bp_tree, hf_bootp_server, tvb,
					   SERVER_NAME_OFFSET,
					   SERVER_NAME_LEN, FALSE);

		} else {
			proto_tree_add_string_format(bp_tree, hf_bootp_server, tvb,
						   SERVER_NAME_OFFSET,
						   SERVER_NAME_LEN,
						   "", "Server host name not given");
		}
	}

	if (overload & OPT_OVERLOAD_FILE) {
		proto_tree_add_text (bp_tree, tvb,
			FILE_NAME_OFFSET, FILE_NAME_LEN,
			"Boot file name option overloaded by DHCP");
	} else {
		/* Boot file is optional */
		if (tvb_get_guint8(tvb, FILE_NAME_OFFSET) != '\0') {
			proto_tree_add_item(bp_tree, hf_bootp_file, tvb,
					   FILE_NAME_OFFSET,
					   FILE_NAME_LEN, FALSE);
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
		proto_tree_add_text(bp_tree,  tvb,
			voff, 64, "Bootp vendor specific options");
		voff += 64;
	}

	at_end = FALSE;
	while (voff < eoff && !at_end) {
		offset_delta = bootp_option(tvb, pinfo, bp_tree, voff, eoff, FALSE, &at_end,
		    &dhcp_type, &vendor_class_id, &overload);
		if (offset_delta <= 0) {
			THROW(ReportedBoundsError);
		}
		voff += offset_delta;
	}
	if ((dhcp_type != NULL) && (!at_end))
	{
		expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_ERROR, "End option missing");
	}
	if (voff < eoff) {
		/*
		 * Padding after the end option.
		 */
		proto_tree_add_text(bp_tree, tvb, voff, eoff - voff, "Padding");
	}
}

static void
bootp_init_protocol(void)
{
	gchar **optionstrings = NULL;
	gchar **optiondetail = NULL;
	gchar *type = NULL;
	guint i, ii;

	/* first copy default_bootp_opt[] to bootp_opt[].  This resets all values to default */
	for(i=0; i<BOOTP_OPT_NUM; i++)
	{
		bootp_opt[i].text = default_bootp_opt[i].text;
		bootp_opt[i].ftype = default_bootp_opt[i].ftype;
		bootp_opt[i].data = default_bootp_opt[i].data;
	}

	/* now split semicolon seperated fields groups */
	optionstrings = ep_strsplit(pref_optionstring, ";", -1);
	for (i=0;optionstrings[i]!=NULL;i++)
	{
		/* input string should have 3 fields:
		   1 - bootp option - uint8 1-254, not being a special
		   2 - option name - string
		   3 - option type - defined in enum represented as a string
		*/

		/* now split field groups to usable data */
		optiondetail = ep_strsplit(optionstrings[i], ",",-1);
		/* verify array has 3 or more entries, any entries beyond 3 are ingnored */
		for(ii=0;(optiondetail[ii]!=NULL);ii++)
		{
			/* do nothing */
		}
		if (ii < 3) continue;                            /* not enough values.  Go again              */
		ii = atoi(optiondetail[0]);                      /* get the bootp option number               */
		if (ii==0 || ii>=BOOTP_OPT_NUM-1) continue;      /* not a number or out of range.  Go again   */
		if (bootp_opt[ii].ftype == special) continue;    /* don't mess with specials.  Go again       */
		bootp_opt[ii].text = se_strdup(optiondetail[1]); /* store a permanent ("seasonal") copy       */
		type = optiondetail[2];                          /* A string to be converted to an ftype enum */
		/* XXX This if statement could be extended to allow for additional types */
		if (g_ascii_strcasecmp(type,"string") == 0)
		{
			bootp_opt[ii].ftype = string;
		} else if (g_ascii_strcasecmp(type,"ipv4") == 0)
		{
			bootp_opt[ii].ftype = ipv4;
		} else if (g_ascii_strcasecmp(type,"bytes") == 0)
		{
			bootp_opt[ii].ftype = bytes;
		} else
		{
			bootp_opt[ii].ftype = opaque;
		}
	}
}

void
proto_register_bootp(void)
{
	static hf_register_info hf[] = {
		{ &hf_bootp_dhcp,
		  { "Frame is DHCP",            "bootp.dhcp",    FT_BOOLEAN,
		    BASE_NONE,			NULL,		 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_type,
		  { "Message type",		"bootp.type",	 FT_UINT8,
		    BASE_DEC, 			VALS(op_vals),   0x0,
		    NULL, HFILL }},

		{ &hf_bootp_hw_type,
		  { "Hardware type",	       	"bootp.hw.type", FT_UINT8,
		    BASE_HEX,			NULL,		 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_hw_len,
		  { "Hardware address length",	"bootp.hw.len",  FT_UINT8,
		    BASE_DEC,			NULL,		 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_hops,
		  { "Hops",		       	"bootp.hops",	 FT_UINT8,
		    BASE_DEC,			NULL,		 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_id,
		  { "Transaction ID",	       	"bootp.id",	 FT_UINT32,
		    BASE_HEX,			 NULL,		 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_secs,
		  { "Seconds elapsed",	       	"bootp.secs",	 FT_UINT16,
		    BASE_DEC,			 NULL,		 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_flags,
		  { "Bootp flags",	       	"bootp.flags",   FT_UINT16,
		    BASE_HEX,			NULL,		 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_flags_broadcast,
		  { "Broadcast flag",	       	"bootp.flags.bc", FT_BOOLEAN,
		    16,			TFS(&flag_set_broadcast), BOOTP_BC,
		    NULL, HFILL }},

		{ &hf_bootp_flags_reserved,
		  { "Reserved flags",	       	"bootp.flags.reserved", FT_UINT16,
		    BASE_HEX,			NULL,		BOOTP_MBZ,
		    NULL, HFILL }},

		{ &hf_bootp_ip_client,
		  { "Client IP address",	"bootp.ip.client",FT_IPv4,
		    BASE_NONE,			NULL,		  0x0,
		    NULL, HFILL }},

		{ &hf_bootp_ip_your,
		  { "Your (client) IP address",	"bootp.ip.your",  FT_IPv4,
		    BASE_NONE,			NULL,		  0x0,
		    NULL, HFILL }},

		{ &hf_bootp_ip_server,
		  { "Next server IP address",	"bootp.ip.server",FT_IPv4,
		    BASE_NONE,			NULL,		  0x0,
		    NULL, HFILL }},

		{ &hf_bootp_ip_relay,
		  { "Relay agent IP address",	"bootp.ip.relay", FT_IPv4,
		    BASE_NONE,			NULL,		  0x0,
		    NULL, HFILL }},

		{ &hf_bootp_hw_addr,
		  { "Client hardware address",	"bootp.hw.addr", FT_BYTES,
		    BASE_NONE,			NULL,		 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_hw_addr_padding,
		  { "Client hardware address padding",	"bootp.hw.addr_padding", FT_BYTES,
		    BASE_NONE,			NULL,		 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_hw_ether_addr,
		  { "Client MAC address",	"bootp.hw.mac_addr", FT_ETHER,
		    BASE_NONE,			NULL,		 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_server,
		  { "Server host name",		"bootp.server",  FT_STRING,
		    BASE_NONE,			NULL,		 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_file,
		  { "Boot file name",		"bootp.file",	 FT_STRING,
		    BASE_NONE,			NULL,		 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_cookie,
		  { "Magic cookie",		"bootp.cookie",	 FT_IPv4,
		    BASE_NONE,			NULL,		 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_vendor,
		  { "Bootp Vendor Options",	"bootp.vendor",  FT_BYTES,
		    BASE_NONE,			NULL,		 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_fqdn_s,
		  { "Server",			"bootp.fqdn.s",	 FT_BOOLEAN,
		    8,				TFS(&tfs_fqdn_s), F_FQDN_S,
		    "If true, server should do DDNS update", HFILL }},

		{ &hf_bootp_fqdn_o,
		  { "Server overrides",		"bootp.fqdn.o",  FT_BOOLEAN,
		    8,			      TFS(&tfs_fqdn_o),  F_FQDN_O,
		    "If true, server insists on doing DDNS update", HFILL }},

		{ &hf_bootp_fqdn_e,
		  { "Encoding",			"bootp.fqdn.e",  FT_BOOLEAN,
		    8,			      TFS(&tfs_fqdn_e),	 F_FQDN_E,
		    "If true, name is binary encoded", HFILL }},

		{ &hf_bootp_fqdn_n,
		  { "Server DDNS",		"bootp.fqdn.n",  FT_BOOLEAN,
		    8,			      TFS(&tfs_fqdn_n),  F_FQDN_N,
		    "If true, server should not do any DDNS updates", HFILL }},

		{ &hf_bootp_fqdn_mbz,
		  { "Reserved flags",		"bootp.fqdn.mbz",FT_UINT8,
		    BASE_HEX,			NULL,		 F_FQDN_MBZ,
		    NULL, HFILL }},

		{ &hf_bootp_fqdn_rcode1,
		  { "A-RR result",	       	"bootp.fqdn.rcode1", FT_UINT8,
		    BASE_DEC,			NULL,		 0x0,
		    "Result code of A-RR update", HFILL }},

		{ &hf_bootp_fqdn_rcode2,
		  { "PTR-RR result",       	"bootp.fqdn.rcode2", FT_UINT8,
		    BASE_DEC,			NULL,		 0x0,
		    "Result code of PTR-RR update", HFILL }},

		{ &hf_bootp_fqdn_name,
		  { "Client name",		"bootp.fqdn.name", FT_STRING,
		    BASE_NONE,			NULL,		 0x0,
		    "Name to register via DDNS", HFILL }},

		{ &hf_bootp_fqdn_asciiname,
		  { "Client name",		"bootp.fqdn.name", FT_STRING,
		    BASE_NONE,			NULL,		 0x0,
		    "Name to register via DDNS", HFILL }},

		{ &hf_bootp_pkt_mta_cap_len,
		  { "MTA DC Length",		"bootp.vendor.pktc.mta_cap_len", FT_UINT8,
		    BASE_DEC,			 NULL,		 0x0,
		    "PacketCable MTA Device Capabilities Length", HFILL }},

		{ &hf_bootp_docsis_cm_cap_len,
		  { "CM DC Length",		"bootp.vendor.docsis.cm_cap_len", FT_UINT8,
		    BASE_DEC,			NULL,		 0x0,
		    "DOCSIS Cable Modem Device Capabilities Length", HFILL }},

		{ &hf_bootp_docsis_cm_cap_type,
		  { "CM DC Type", "bootp.docsis_cm_cap_type", FT_UINT16,
		    BASE_DEC,			VALS(docsis_cm_cap_type_vals),	0x0,
		    "Docsis Cable Modem Device Capability type", HFILL }},

		{ &hf_bootp_alu_vid,
		  { "Voice VLAN ID",	"bootp.vendor.alu.vid", FT_UINT16,
		    BASE_DEC, 			NULL,		 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_alu_tftp1,
		  { "Spatial Redundancy TFTP1",	"bootp.vendor.alu.tftp1", FT_IPv4,
		    BASE_NONE,			NULL,		 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_alu_tftp2,
		  { "Spatial Redundancy TFTP2",	"bootp.vendor.alu.tftp2", FT_IPv4,
		    BASE_NONE,			NULL,		 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_alu_app_type,
		  { "Application Type",	"bootp.vendor.alu.app_type", FT_UINT8,
		    BASE_DEC,			NULL,		 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_alu_sip_url,
		  { "SIP URL",			"bootp.vendor.alu.sip_url", FT_STRING,
		    BASE_NONE,			NULL,		 0x0,
		    NULL, HFILL }},

		{ &hf_bootp_client_identifier_uuid,
		  { "Client Identifier (UUID)",	"bootp.client_id_uuid", FT_GUID,
		    BASE_NONE,			NULL,		 0x0,
		    "Client Machine Identifier (UUID)", HFILL }},

		{ &hf_bootp_client_network_id_major_ver,
		  { "Client Network ID Major Version", "bootp.client_network_id_major", FT_UINT8,
		    BASE_DEC, 			NULL,		 0x0,
		    "Client Machine Identifier, Major Version", HFILL }},

		{ &hf_bootp_client_network_id_minor_ver,
		  { "Client Network ID Minor Version", "bootp.client_network_id_minor", FT_UINT8,
		    BASE_DEC, 			NULL,		 0x0,
		    "Client Machine Identifier, Major Version", HFILL }},

		{ &hf_bootp_option_type,
		  { "Option",	"bootp.option.type", FT_UINT8,
		    BASE_DEC,			 NULL,		 0x0,
		    "Bootp/Dhcp option type", HFILL }},

		{ &hf_bootp_option_length,
		  { "Length",	"bootp.option.length", FT_UINT8,
		    BASE_DEC, 			NULL,		 0x0,
		    "Bootp/Dhcp option length", HFILL }},

		{ &hf_bootp_option_value,
		  { "Value",	"bootp.option.value", FT_BYTES,
		    BASE_NONE, 			NULL,		 0x0,
		    "Bootp/Dhcp option value", HFILL }},

	};

	static gint *ett[] = {
		&ett_bootp,
		&ett_bootp_flags,
		&ett_bootp_option,
		&ett_bootp_fqdn,
	};

	module_t *bootp_module;

	proto_bootp = proto_register_protocol("Bootstrap Protocol", "BOOTP/DHCP",
					      "bootp");
	proto_register_field_array(proto_bootp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	bootp_dhcp_tap = register_tap("bootp");

	/* register init routine to setup the custom bootp options */
	register_init_routine(&bootp_init_protocol);

	/* Allow dissector to find be found by name. */
	register_dissector("bootp", dissect_bootp, proto_bootp);

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

	prefs_register_string_preference(bootp_module, "displayasstring",
					 "Custom BootP/DHCP Options (Excl. suboptions)",
					 "Format: OptionNumber,OptionName,OptionType[;Format].\n"
					 "Example: 176,MyOption,string;242,NewOption,ipv4.\n"
					 "OptionNumbers: 1-254, but no special options. "
					 "OptionType: string, ipv4 and bytes",
					 &pref_optionstring );
}

void
proto_reg_handoff_bootp(void)
{
	dissector_handle_t bootp_handle;

	bootp_handle = create_dissector_handle(dissect_bootp, proto_bootp);
	dissector_add_uint("udp.port", UDP_PORT_BOOTPS, bootp_handle);
	dissector_add_uint("udp.port", UDP_PORT_BOOTPC, bootp_handle);
}
