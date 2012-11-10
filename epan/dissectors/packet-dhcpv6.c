/* packet-dhpcv6.c
 * Routines for DHCPv6 packet disassembly
 * Copyright 2004, Nicolas DICHTEL - 6WIND - <nicolas.dichtel@6wind.com>
 * Jun-ichiro itojun Hagino <itojun@iijlab.net>
 * IItom Tsutomu MIENO <iitom@utouto.com>
 * SHIRASAKI Yasuhiro <yasuhiro@gnome.gr.jp>
 * Tony Lindstrom <tony.lindstrom@ericsson.com>
 * Copyright 2012, Jerome LAFORGE <jerome.laforge@gmail.com>
 *
 * $Id$
 *
 * The information used comes from:
 * RFC3315.txt (DHCPv6)
 * RFC3319.txt (SIP options)
 * RFC3633.txt (Prefix options)
 * RFC3646.txt (DNS servers/domains)
 * RFC3898.txt (NIS options)
 * RFC4649.txt (Remote ID option)
 * RFC4704.txt (Client FQDN)
 * RFC5007.txt (DHCPv6 Leasequery)
 * RFC5417.txt (CAPWAP Access Controller DHCP Option)
 * RFC6334.txt (Dual-Stack Lite Option)
 * draft-ietf-dhc-dhcpv6-opt-timeconfig-03.txt
 * draft-ietf-dhc-dhcpv6-opt-lifetime-00.txt
 * CL-SP-CANN-DHCP-Reg-I06-110210.doc
 *
 * Note that protocol constants are still subject to change, based on IANA
 * assignment decisions.
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
#include <epan/sminmpec.h>
#include <epan/strutil.h>
#include <epan/arptypes.h>
#include <epan/expert.h>
#include "packet-arp.h"
#include "packet-dns.h"                         /* for get_dns_name() */

static int proto_dhcpv6 = -1;
static int hf_dhcpv6_msgtype = -1;
static int hf_dhcpv6_domain = -1;
static int hf_clientfqdn_reserved = -1;
static int hf_clientfqdn_n = -1;
static int hf_clientfqdn_o = -1;
static int hf_clientfqdn_s = -1;
static int hf_option_type = -1;
static int hf_option_length = -1;
static int hf_option_value = -1;
static int hf_remoteid_enterprise = -1;
static int hf_vendoropts_enterprise = -1;
static int hf_duid_bytes = -1;
static int hf_duid_type = -1;
static int hf_duidllt_time = -1;
static int hf_duidllt_link_layer_addr = -1;
static int hf_duidllt_hwtype = -1;
static int hf_duidll_hwtype = -1;
static int hf_duiden_enterprise = -1;
static int hf_duiden_identifier = -1;
static int hf_duidll_link_layer_addr = -1;
static int hf_iaid = -1;
static int hf_iaid_t1 = -1;
static int hf_iaid_t2 = -1;
static int hf_iata = -1;
static int hf_iaaddr_ip = -1;
static int hf_iaaddr_pref_lifetime = -1;
static int hf_iaaddr_valid_lifetime = -1;
static int hf_requested_option_code = -1;
static int hf_option_preference = -1;
static int hf_elapsed_time = -1;
static int hf_auth_protocol = -1;
static int hf_auth_algorithm = -1;
static int hf_auth_rdm = -1;
static int hf_auth_replay_detection = -1;
static int hf_auth_info = -1;
static int hf_opt_unicast = -1;
static int hf_opt_status_code = -1;
static int hf_opt_status_msg = -1;
static int hf_vendorclass_enterprise = -1;
static int hf_vendorclass_data = -1;
static int hf_vendoropts_enterprise_option_code = -1;
static int hf_vendoropts_enterprise_option_length = -1;
static int hf_vendoropts_enterprise_option_data = -1;
static int hf_interface_id = -1;
static int hf_interface_id_link_address = -1;
static int hf_reconf_msg = -1;
static int hf_sip_server_a = -1;
static int hf_dns_servers = -1;
static int hf_nis_servers = -1;
static int hf_nisp_servers = -1;
static int hf_sntp_servers = -1;
static int hf_opt_lifetime = -1;
static int hf_bcmcs_servers_a = -1;
static int hf_remoteid_enterprise_id = -1;
static int hf_subscriber_id = -1;
static int hf_pana_agent = -1;
static int hf_opt_timezone = -1;
static int hf_opt_tzdb = -1;
static int hf_lq_query = -1;
static int hf_lq_query_link_address = -1;
static int hf_clt_time = -1;
static int hf_lq_relay_data_peer_addr = -1;
static int hf_lq_relay_data_msg = -1;
static int hf_lq_client_link = -1;
static int hf_capwap_ac_v6 = -1;
static int hf_aftr_name = -1;
static int hf_iaprefix_pref_lifetime = -1;
static int hf_iaprefix_valid_lifetime = -1;
static int hf_iaprefix_pref_len = -1;
static int hf_iaprefix_pref_addr = -1;
static int hf_mip6_ha = -1;
static int hf_mip6_hoa = -1;
static int hf_nai = -1;
static int hf_dhcpv6_hopcount = -1;
static int hf_dhcpv6_xid = -1;
static int hf_dhcpv6_peeraddr = -1;
static int hf_dhcpv6_linkaddr = -1;
static int hf_packetcable_ccc_suboption = -1;
static int hf_packetcable_ccc_pri_dhcp = -1;
static int hf_packetcable_ccc_sec_dhcp = -1;
static int hf_packetcable_ccc_prov_srv_type = -1;
static int hf_packetcable_ccc_prov_srv_fqdn = -1;
static int hf_packetcable_ccc_prov_srv_ipv4 = -1;
static int hf_packetcable_ccc_as_krb_nominal_timeout = -1;
static int hf_packetcable_ccc_as_krb_max_timeout = -1;
static int hf_packetcable_ccc_as_krb_max_retry_count = -1;
static int hf_packetcable_ccc_ap_krb_nominal_timeout = -1;
static int hf_packetcable_ccc_ap_krb_max_timeout = -1;
static int hf_packetcable_ccc_ap_krb_max_retry_count = -1;
static int hf_packetcable_ccc_krb_realm = -1;
static int hf_packetcable_ccc_tgt_flag = -1;
static int hf_packetcable_ccc_tgt_flag_fetch = -1;
static int hf_packetcable_ccc_prov_timer = -1;
static int hf_packetcable_ccc_sec_tcm = -1;
static int hf_packetcable_ccc_sec_tcm_provisioning_server = -1;
static int hf_packetcable_ccc_sec_tcm_call_manager_server = -1;
static int hf_packetcable_cccV6_suboption = -1;
static int hf_packetcable_cccV6_pri_dss = -1;
static int hf_packetcable_cccV6_sec_dss = -1;
static int hf_packetcable_cccV6_prov_srv_type = -1;
static int hf_packetcable_cccV6_prov_srv_fqdn = -1;
static int hf_packetcable_cccV6_prov_srv_ipv6 = -1;
static int hf_packetcable_cccV6_as_krb_nominal_timeout = -1;
static int hf_packetcable_cccV6_as_krb_max_timeout = -1;
static int hf_packetcable_cccV6_as_krb_max_retry_count = -1;
static int hf_packetcable_cccV6_ap_krb_nominal_timeout = -1;
static int hf_packetcable_cccV6_ap_krb_max_timeout = -1;
static int hf_packetcable_cccV6_ap_krb_max_retry_count = -1;
static int hf_packetcable_cccV6_krb_realm = -1;
static int hf_packetcable_cccV6_tgt_flag = -1;
static int hf_packetcable_cccV6_tgt_flag_fetch = -1;
static int hf_packetcable_cccV6_prov_timer = -1;
static int hf_packetcable_cccV6_sec_tcm = -1;
static int hf_packetcable_cccV6_sec_tcm_provisioning_server = -1;
static int hf_packetcable_cccV6_sec_tcm_call_manager_server = -1;
static int hf_cablelabs_opts = -1;
static int hf_cablelabs_ipv6_server = -1;

static gint ett_dhcpv6 = -1;
static gint ett_dhcpv6_option = -1;
static gint ett_dhcpv6_option_vsoption = -1;
static gint ett_dhcpv6_vendor_option = -1;
static gint ett_dhcpv6_pkt_option = -1;

#define UDP_PORT_DHCPV6_DOWNSTREAM      546
#define UDP_PORT_DHCPV6_UPSTREAM        547

#define DHCPV6_LEASEDURATION_INFINITY   0xffffffff

#define SOLICIT                  1
#define ADVERTISE                2
#define REQUEST                  3
#define CONFIRM                  4
#define RENEW                    5
#define REBIND                   6
#define REPLY                    7
#define RELEASE                  8
#define DECLINE                  9
#define RECONFIGURE             10
#define INFORMATION_REQUEST     11
#define RELAY_FORW              12
#define RELAY_REPLY             13
#define LEASEQUERY              14
#define LEASEQUERY_REPLY        15

#define OPTION_CLIENTID          1
#define OPTION_SERVERID          2
#define OPTION_IA_NA             3
#define OPTION_IA_TA             4
#define OPTION_IAADDR            5
#define OPTION_ORO               6
#define OPTION_PREFERENCE        7
#define OPTION_ELAPSED_TIME      8
#define OPTION_RELAY_MSG         9
/* #define      OPTION_SERVER_MSG       10 */
#define OPTION_AUTH             11
#define OPTION_UNICAST          12
#define OPTION_STATUS_CODE      13
#define OPTION_RAPID_COMMIT     14
#define OPTION_USER_CLASS       15
#define OPTION_VENDOR_CLASS     16
#define OPTION_VENDOR_OPTS      17
#define OPTION_INTERFACE_ID     18
#define OPTION_RECONF_MSG       19
#define OPTION_RECONF_ACCEPT    20
#define OPTION_SIP_SERVER_D     21
#define OPTION_SIP_SERVER_A     22
#define OPTION_DNS_SERVERS      23
#define OPTION_DOMAIN_LIST      24
#define OPTION_IA_PD            25
#define OPTION_IAPREFIX         26
#define OPTION_NIS_SERVERS      27
#define OPTION_NISP_SERVERS     28
#define OPTION_NIS_DOMAIN_NAME  29
#define OPTION_NISP_DOMAIN_NAME 30
#define OPTION_SNTP_SERVERS     31
#define OPTION_LIFETIME         32
#define OPTION_BCMCS_SERVER_D   33
#define OPTION_BCMCS_SERVER_A   34
#define OPTION_GEOCONF_CIVIC    36
#define OPTION_REMOTE_ID        37
#define OPTION_SUBSCRIBER_ID    38
#define OPTION_CLIENT_FQDN      39
#define OPTION_PANA_AGENT       40
#define OPTION_TIME_ZONE        41
#define OPTION_TZDB             42
#define OPTION_ERO              43
#define OPTION_LQ_QUERY         44
#define OPTION_CLIENT_DATA      45
#define OPTION_CLT_TIME         46
#define OPTION_LQ_RELAY_DATA    47
#define OPTION_LQ_CLIENT_LINK   48
#define OPTION_CAPWAP_AC_V6     52
#define OPTION_AFTR_NAME        64

/* temporary value until defined by IETF */
#define OPTION_MIP6_HA          165
#define OPTION_MIP6_HOA         166
#define OPTION_NAI              167

#define DUID_LLT                1
#define DUID_EN                 2
#define DUID_LL                 3
#define DUID_LL_OLD             4

static const value_string msgtype_vals[] = {
    { SOLICIT,                 "Solicit" },
    { ADVERTISE,               "Advertise" },
    { REQUEST,                 "Request" },
    { CONFIRM,                 "Confirm" },
    { RENEW,                   "Renew" },
    { REBIND,                  "Rebind" },
    { REPLY,                   "Reply" },
    { RELEASE,                 "Release" },
    { DECLINE,                 "Decline" },
    { RECONFIGURE,             "Reconfigure" },
    { INFORMATION_REQUEST,     "Information-request" },
    { RELAY_FORW,              "Relay-forw" },
    { RELAY_REPLY,             "Relay-reply" },
    { LEASEQUERY,              "Leasequery" },
    { LEASEQUERY_REPLY,        "Leasequery-reply" },
    { 0, NULL }
};

static const value_string opttype_vals[] = {
    { OPTION_CLIENTID,         "Client Identifier" },
    { OPTION_SERVERID,         "Server Identifier" },
    { OPTION_IA_NA,            "Identity Association for Non-temporary Address" },
    { OPTION_IA_TA,            "Identity Association for Temporary Address" },
    { OPTION_IAADDR,           "IA Address" },
    { OPTION_ORO,              "Option Request" },
    { OPTION_PREFERENCE,       "Preference" },
    { OPTION_ELAPSED_TIME,     "Elapsed time" },
    { OPTION_RELAY_MSG,        "Relay Message" },
/*  { OPTION_SERVER_MSG,       "Server message" }, */
    { OPTION_AUTH,             "Authentication" },
    { OPTION_UNICAST,          "Server unicast" },
    { OPTION_STATUS_CODE,      "Status code" },
    { OPTION_RAPID_COMMIT,     "Rapid Commit" },
    { OPTION_USER_CLASS,       "User Class" },
    { OPTION_VENDOR_CLASS,     "Vendor Class" },
    { OPTION_VENDOR_OPTS,      "Vendor-specific Information" },
    { OPTION_INTERFACE_ID,     "Interface-Id" },
    { OPTION_RECONF_MSG,       "Reconfigure Message" },
    { OPTION_RECONF_ACCEPT,    "Reconfigure Accept" },
    { OPTION_SIP_SERVER_D,     "SIP Server Domain Name List" },
    { OPTION_SIP_SERVER_A,     "SIP Servers IPv6 Address List" },
    { OPTION_DNS_SERVERS,      "DNS recursive name server" },
    { OPTION_DOMAIN_LIST,      "Domain Search List" },
    { OPTION_IA_PD,            "Identity Association for Prefix Delegation" },
    { OPTION_IAPREFIX,         "IA Prefix" },
    { OPTION_NIS_SERVERS,      "Network Information Server" },
    { OPTION_NISP_SERVERS,     "Network Information Server V2" },
    { OPTION_NIS_DOMAIN_NAME,  "Network Information Server Domain Name" },
    { OPTION_NISP_DOMAIN_NAME, "Network Information Server V2 Domain Name" },
    { OPTION_SNTP_SERVERS,     "Simple Network Time Protocol Server" },
    { OPTION_LIFETIME,         "Lifetime" },
    { OPTION_BCMCS_SERVER_D,   "BCMCS Server Domain" },
    { OPTION_BCMCS_SERVER_A,   "BCMCS Servers IPv6 Address List" },
    { OPTION_GEOCONF_CIVIC,    "Geoconf Civic Address" },
    { OPTION_REMOTE_ID,        "Remote Identifier" },
    { OPTION_SUBSCRIBER_ID,    "Subscriber Identifier" },
    { OPTION_CLIENT_FQDN,      "Fully Qualified Domain Name" },
    { OPTION_PANA_AGENT,       "PANA Agents IPv6 Address List" },
    { OPTION_TIME_ZONE,        "Time Zone" },
    { OPTION_TZDB,             "Time Zone Database" },
    { OPTION_ERO,              "Echo Request Option" },
    { OPTION_LQ_QUERY,         "Leasequery Query" },
    { OPTION_CLIENT_DATA,      "Leasequery Client Data" },
    { OPTION_CLT_TIME,         "Client Last Transaction Time" },
    { OPTION_LQ_RELAY_DATA,    "Leasequery Relay Data" },
    { OPTION_LQ_CLIENT_LINK,   "Leasequery Client Link Address List" },
    { OPTION_CAPWAP_AC_V6,     "CAPWAP Access Controllers" },
    { OPTION_AFTR_NAME,        "Dual-Stack Lite AFTR Name" },
    { OPTION_MIP6_HA,          "Mobile IPv6 Home Agent" },
    { OPTION_MIP6_HOA,         "Mobile IPv6 Home Address" },
    { OPTION_NAI,              "Network Access Identifier" },
    { 0,        NULL }
};

static const value_string statuscode_vals[] =
{
    {0, "Success" },
    {1, "UnspecFail" },
    {2, "NoAddrAvail" },
    {3, "NoBinding" },
    {4, "NotOnLink" },
    {5, "UseMulticast" },
    {6, "NoPrefixAvail" },
    {7, "UnknownQueryType" },
    {8, "MalformedQuery" },
    {9, "NotConfigured" },
    {10, "NotAllowed" },
    {0, NULL }
};

static const value_string duidtype_vals[] =
{
    { DUID_LLT,    "link-layer address plus time" },
    { DUID_EN,     "assigned by vendor based on Enterprise number" },
    { DUID_LL,     "link-layer address" },
    { DUID_LL_OLD, "link-layer address (old)" },
    { 0, NULL }
};

static const true_false_string fqdn_n = {
    "Server should not perform DNS updates",
    "Server should perform DNS updates"
};

static const true_false_string fqdn_o = {
    "Server has overridden client's S bit preference",
    "Server has not overridden client's S bit preference"
};

static const true_false_string fqdn_s = {
    "Server should perform forward DNS updates",
    "Server should not perform forward DNS updates"
};

static const value_string lq_query_vals[] = {
    { 1, "by-address" },
    { 2, "by-clientID" },
    { 0, NULL },
};

/* CableLabs Common Vendor Specific Options */
#define CL_OPTION_ORO                     0x0001 /* 1 */
#define CL_OPTION_DEVICE_TYPE             0x0002 /* 2 */
#define CL_OPTION_EMBEDDED_COMPONENT_LIST 0x0003 /* 3 */
#define CL_OPTION_DEVICE_SERIAL_NUMBER    0x0004 /* 4 */
#define CL_OPTION_HARDWARE_VERSION_NUMBER 0x0005 /* 5 */
#define CL_OPTION_SOFTWARE_VERSION_NUMBER 0x0006 /* 6 */
#define CL_OPTION_BOOT_ROM_VERSION        0x0007 /* 7 */
#define CL_OPTION_VENDOR_OUI              0x0008 /* 8 */
#define CL_OPTION_MODEL_NUMBER            0x0009 /* 9 */
#define CL_OPTION_VENDOR_NAME             0x000a /* 10 */
/* 11-32 is currently reserved */
#define CL_OPTION_TFTP_SERVERS            0x0020 /* 32 */
#define CL_OPTION_CONFIG_FILE_NAME        0x0021 /* 33 */
#define CL_OPTION_SYSLOG_SERVERS          0x0022 /* 34 */
#define CL_OPTION_TLV5                    0x0023 /* 35 */
#define CL_OPTION_DEVICE_ID               0x0024 /* 36 */
#define CL_OPTION_RFC868_SERVERS          0x0025 /* 37 */
#define CL_OPTION_TIME_OFFSET             0x0026 /* 38 */
#define CL_OPTION_IP_PREF                 0x0027 /* 39 */

/** CableLabs DOCSIS Project Vendor Specific Options */
#define CL_OPTION_DOCS_CMTS_CAP 0x0401  /* 1025 */
#define CL_CM_MAC_ADDR 0x0402 /* 1026 */
#define CL_EROUTER_CONTAINER_OPTION 0x403 /* 1027 */

/** CableLabs PacketCable Project Vendor Specific Options **/
#define CL_OPTION_CCC 0x087a  /* 2170 */
#define CL_OPTION_CCCV6 0x087b  /* 2171 */
#define CL_OPTION_CORRELATION_ID 0x087c /*2172 */

/** CableLabs TLVs for DOCS_CMTS_CAP Vendor Option **/
#define CL_OPTION_DOCS_CMTS_TLV_VERS_NUM 0x01 /* 1 */

static const value_string cl_vendor_subopt_values[] = {
    /*    1 */ { CL_OPTION_ORO, "Option Request = " },
    /*    2 */ { CL_OPTION_DEVICE_TYPE, "Device Type = " },
    /*    3 */ { CL_OPTION_EMBEDDED_COMPONENT_LIST, "Embedded Components = " },
    /*    4 */ { CL_OPTION_DEVICE_SERIAL_NUMBER, "Serial Number = " },
    /*    5 */ { CL_OPTION_HARDWARE_VERSION_NUMBER, "Hardware Version = " },
    /*    6 */ { CL_OPTION_SOFTWARE_VERSION_NUMBER, "Software Version = " },
    /*    7 */ { CL_OPTION_BOOT_ROM_VERSION, "Boot ROM Version = " },
    /*    8 */ { CL_OPTION_VENDOR_OUI, "Organization Unique Identifier = " },
    /*    9 */ { CL_OPTION_MODEL_NUMBER, "Model Number = " },
    /*   10 */ { CL_OPTION_VENDOR_NAME, "Vendor Name = " },
    /*   32 */ { CL_OPTION_TFTP_SERVERS, "TFTP Server Addresses : " },
    /*   33 */ { CL_OPTION_CONFIG_FILE_NAME, "Configuration File Name = " },
    /*   34 */ { CL_OPTION_SYSLOG_SERVERS, "Syslog Servers : " },
    /*   35 */ { CL_OPTION_TLV5, "TLV5 = " },
    /*   36 */ { CL_OPTION_DEVICE_ID, "Device Identifier = " },
    /*   37 */ { CL_OPTION_RFC868_SERVERS, "Time Protocol Servers : " },
    /*   38 */ { CL_OPTION_TIME_OFFSET, "Time Offset = " },
    /*   39 */ { CL_OPTION_IP_PREF, "IP preference : " },
    /* 1025 */ { CL_OPTION_DOCS_CMTS_CAP, "CMTS Capabilities Option : " },
    /* 1026 */ { CL_CM_MAC_ADDR, "CM MAC Address Option = " },
    /* 1027 */ { CL_EROUTER_CONTAINER_OPTION, "eRouter Container Option : " },
    /* 2170 */ { CL_OPTION_CCC, "CableLabs Client Configuration : " },
    /* 2171 */ { CL_OPTION_CCCV6, "CableLabs Client Configuration IPv6 : " },
    /* 2172 */ { CL_OPTION_CORRELATION_ID, "CableLabs Correlation ID = " },
    { 0, NULL }
};

#define PKT_CCC_PRI_DHCP       0x0001
#define PKT_CCC_SEC_DHCP       0x0002
#define PKT_CCC_IETF_PROV_SRV  0x0003
#define PKT_CCC_IETF_AS_KRB    0x0004
#define PKT_CCC_IETF_AP_KRB    0x0005
#define PKT_CCC_KRB_REALM      0x0006
#define PKT_CCC_TGT_FLAG       0x0007
#define PKT_CCC_PROV_TIMER     0x0008
#define PKT_CCC_IETF_SEC_TKT   0x0009
/** 10 -255 Reserved for future extensions **/

#define PKT_CCCV6_PRI_DSS       0x0001
#define PKT_CCCV6_SEC_DSS       0x0002
#define PKT_CCCV6_IETF_PROV_SRV 0x0003
#define PKT_CCCV6_IETF_AS_KRB   0x0004
#define PKT_CCCV6_IETF_AP_KRB   0x0005
#define PKT_CCCV6_KRB_REALM     0x0006
#define PKT_CCCV6_TGT_FLAG      0x0007
#define PKT_CCCV6_PROV_TIMER    0x0008
#define PKT_CCCV6_IETF_SEC_TKT  0x0009
/** 10 -255 Reserved for future extensions **/

static const value_string pkt_ccc_opt_vals[] = {
    { PKT_CCC_PRI_DHCP,      "TSP's Primary DHCP Server" },
    { PKT_CCC_SEC_DHCP,      "TSP's Secondary DHCP Server" },
    { PKT_CCC_IETF_PROV_SRV, "TSP's Provisioning Server" },
    { PKT_CCC_IETF_AS_KRB,   "TSP's AS-REQ/AS-REP Backoff and Retry" },
    { PKT_CCC_IETF_AP_KRB,   "TSP's AP-REQ/AP-REP Backoff and Retry" },
    { PKT_CCC_KRB_REALM,     "TSP's Kerberos Realm Name" },
    { PKT_CCC_TGT_FLAG,      "TSP's Ticket Granting Server Utilization" },
    { PKT_CCC_PROV_TIMER,    "TSP's Provisioning Timer Value" },
    { PKT_CCC_IETF_SEC_TKT,  "PacketCable Security Ticket Control" },
    { 0, NULL },
};

static const value_string pkt_ccc_prov_srv_type_vals[] = {
    { 0,      "FQDN" },
    { 1,      "IPv4" },
    { 0, NULL },
};

static const value_string pkt_cccV6_prov_srv_type_vals[] = {
    { 0,      "FQDN" },
    { 1,      "IPv6" },
    { 0, NULL },
};

static const value_string pkt_cccV6_opt_vals[] = {
    { PKT_CCCV6_PRI_DSS,        "TSP's Primary DHCPv6 Server Selector ID" },
    { PKT_CCCV6_SEC_DSS,        "TSP's Secondary DHCPv6 Server Selector ID " },
    { PKT_CCCV6_IETF_PROV_SRV,  "TSP's Provisioning Server" },
    { PKT_CCCV6_IETF_AS_KRB,    "TSP's AS-REQ/AS-REP Backoff and Retry" },
    { PKT_CCCV6_IETF_AP_KRB,    "TSP's AP-REQ/AP-REP Backoff and Retry" },
    { PKT_CCCV6_KRB_REALM,      "TSP's Kerberos Realm Name" },
    { PKT_CCCV6_TGT_FLAG,       "TSP's Ticket Granting Server Utilization" },
    { PKT_CCCV6_PROV_TIMER,     "TSP's Provisioning Timer Value" },
    { PKT_CCCV6_IETF_SEC_TKT,   "PacketCable Security Ticket Control" },
    { 0, NULL }
};

static const value_string sec_tcm_vals[] = {
    { 1 << 0, "PacketCable Provisioning Server" },
    { 1 << 1, "PacketCable Call Manager Servers" },
    { 0, NULL },
};

/* May be called recursively */
static void
dissect_dhcpv6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               gboolean downstream, int off, int eoff);

static int
dissect_packetcable_ccc_option(proto_tree *v_tree, proto_item *v_item, packet_info *pinfo, tvbuff_t *tvb, int optoff,
                               int optend)
{
    /** THE ENCODING OF THIS SUBOPTION HAS CHANGED FROM DHCPv4
        the code and length fields have grown from a single octet to
        two octets each. **/
    int suboptoff = optoff;
    guint16 subopt, subopt_len;
    guint8 type;
    proto_item *vti, *ti;
    proto_tree *pkt_s_tree;
    guchar kr_name;       /** A character in the kerberos realm name option */
    guint8 kr_value;      /* The integer value of the character currently being tested */
    int kr_fail_flag = 0; /* Flag indicating an invalid character was found */
    int kr_pos = 0;       /* The position of the first invalid character */
    int i = 0;

    subopt = tvb_get_ntohs(tvb, optoff);
    suboptoff += 2;

    subopt_len = tvb_get_ntohs(tvb, suboptoff);
    suboptoff += 2;

    /* There must be at least five octets left to be a valid sub element */
    if (optend <= 0) {
        expert_add_info_format(pinfo, v_item, PI_PROTOCOL, PI_WARN, "Sub element %d: no room left in option for suboption length", subopt);
        return (optend);
    }
    /* g_print("dissect packetcable ccc option subopt_len=%d optend=%d\n\n", subopt_len, optend); */

    vti = proto_tree_add_item(v_tree, hf_packetcable_ccc_suboption, tvb, optoff, subopt_len + 4, ENC_BIG_ENDIAN);
    pkt_s_tree = proto_item_add_subtree(vti, ett_dhcpv6_pkt_option);

    switch (subopt) {
    case PKT_CCC_PRI_DHCP:      /* IPv4 address values */
        if (subopt_len == 4) {
            proto_tree_add_item(pkt_s_tree, hf_packetcable_ccc_pri_dhcp, tvb, suboptoff, 4, ENC_BIG_ENDIAN);
        }
        else {
            expert_add_info_format(pinfo, vti, PI_MALFORMED, PI_ERROR, "Bogus length: %d", subopt_len);
        }

        suboptoff += subopt_len;
        break;
    case PKT_CCC_SEC_DHCP:
        if (subopt_len == 4) {
            proto_tree_add_item(pkt_s_tree, hf_packetcable_ccc_sec_dhcp, tvb, suboptoff, 4, ENC_BIG_ENDIAN);
        }
        else {
            expert_add_info_format(pinfo, vti, PI_MALFORMED, PI_ERROR, "Bogus length: %d", subopt_len);
        }

        suboptoff += subopt_len;
        break;
    case PKT_CCC_IETF_PROV_SRV :
        proto_tree_add_item(pkt_s_tree, hf_packetcable_ccc_prov_srv_type, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
        type = tvb_get_guint8(tvb, suboptoff);

        /** Type 0 is FQDN **/
        if (type == 0) {
            proto_tree_add_item(pkt_s_tree, hf_packetcable_ccc_prov_srv_fqdn, tvb, suboptoff+1, subopt_len-1, ENC_ASCII|ENC_NA);
        }
        /** Type 1 is IPv4 **/
        else if (type == 1) {
            if (subopt_len == 5) {
                proto_tree_add_item(pkt_s_tree, hf_packetcable_ccc_prov_srv_ipv4, tvb, suboptoff+1, 4, ENC_BIG_ENDIAN);
            }
            else {
                expert_add_info_format(pinfo, vti, PI_MALFORMED, PI_ERROR, "Bogus length: %d", subopt_len);
            }
        }
        else {
            expert_add_info_format(pinfo, vti, PI_PROTOCOL, PI_WARN, "Invalid type: %u (%u byte%s)",
                type, subopt_len, plurality(subopt_len, "", "s"));
        }
        suboptoff += subopt_len;
        break;

    case PKT_CCC_IETF_AS_KRB :
        if (subopt_len == 12) {
            proto_tree_add_item(pkt_s_tree, hf_packetcable_ccc_as_krb_nominal_timeout, tvb, suboptoff, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(pkt_s_tree, hf_packetcable_ccc_as_krb_max_timeout, tvb, suboptoff+4, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(pkt_s_tree, hf_packetcable_ccc_as_krb_max_retry_count, tvb, suboptoff+8, 4, ENC_BIG_ENDIAN);
        }
        else {
            expert_add_info_format(pinfo, vti, PI_MALFORMED, PI_ERROR, "Bogus length: %d", subopt_len);
        }
        suboptoff += subopt_len;
        break;
    case PKT_CCC_IETF_AP_KRB :
        if (subopt_len == 12) {
            proto_tree_add_item(pkt_s_tree, hf_packetcable_ccc_ap_krb_nominal_timeout, tvb, suboptoff, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(pkt_s_tree, hf_packetcable_ccc_ap_krb_max_timeout, tvb, suboptoff+4, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(pkt_s_tree, hf_packetcable_ccc_ap_krb_max_retry_count, tvb, suboptoff+8, 4, ENC_BIG_ENDIAN);
        }
        else {
            expert_add_info_format(pinfo, vti, PI_MALFORMED, PI_ERROR, "Bogus length: %d", subopt_len);
        }
        suboptoff += subopt_len;
        break;
    case PKT_CCC_KRB_REALM:
        if (subopt_len > 0) {
            /** The only allowable characters are
                A-Z (upper case only) 65-90
                '.', 46
                '/', 47
                '\', 92
                '=', 61
                '"', 34
                ',', 44
                and
                ':' 58
                so loop through and
                make sure it conforms to the expected syntax.
            **/
            for (i=0; i < subopt_len; i++) {
                kr_name = tvb_get_guint8(tvb, suboptoff + i);
                kr_value = (int)kr_name;
                if ((kr_value >= 65 && kr_value <= 90) ||
                    kr_value == 34 ||
                    kr_value == 44 ||
                    kr_value == 46 ||
                    kr_value == 47 ||
                    kr_value == 58 ||
                    kr_value == 61 ||
                    kr_value == 92)   {
                }
                else if (!kr_fail_flag) {
                    kr_pos = i;
                    kr_fail_flag = 1;
                }
            }

            ti = proto_tree_add_item(pkt_s_tree, hf_packetcable_ccc_krb_realm, tvb, suboptoff, subopt_len, ENC_ASCII|ENC_NA);
            if (kr_fail_flag)
                expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN, "Invalid at byte=%d", kr_pos);
        }
        suboptoff += subopt_len;
        break;

    case PKT_CCC_TGT_FLAG:
        if (subopt_len == 1) {
            proto_tree_add_item(pkt_s_tree, hf_packetcable_ccc_tgt_flag, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(pkt_s_tree, hf_packetcable_ccc_tgt_flag_fetch, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
        }
        else {
            expert_add_info_format(pinfo, vti, PI_MALFORMED, PI_ERROR, "Bogus length: %d", subopt_len);
        }
        suboptoff += subopt_len;
        break;

    case PKT_CCC_PROV_TIMER:
        if (subopt_len == 1) {
            ti = proto_tree_add_item(pkt_s_tree, hf_packetcable_ccc_prov_timer, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
            if (tvb_get_guint8(tvb, suboptoff ) > 30)
                expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN, "Invalid time value");
        }
        else {
            expert_add_info_format(pinfo, vti, PI_MALFORMED, PI_ERROR, "Bogus length: %d", subopt_len);
        }
        suboptoff += subopt_len;
        break;

    case PKT_CCC_IETF_SEC_TKT :
        proto_tree_add_item(pkt_s_tree, hf_packetcable_ccc_sec_tcm, tvb, suboptoff, 2, ENC_BIG_ENDIAN);
        if (subopt_len == 2) {
            proto_tree_add_item(pkt_s_tree, hf_packetcable_ccc_sec_tcm_provisioning_server, tvb, suboptoff, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(pkt_s_tree, hf_packetcable_ccc_sec_tcm_call_manager_server, tvb, suboptoff, 2, ENC_BIG_ENDIAN);
        } else {
            expert_add_info_format(pinfo, vti, PI_MALFORMED, PI_ERROR, "Bogus length: %d", subopt_len);
        }
        suboptoff += subopt_len;
        break;


    default:
        suboptoff += subopt_len;
        break;

    }

    /** Return the number of bytes processed **/
    return (suboptoff - optoff);
}

static int
dissect_packetcable_cccV6_option(proto_tree *v_tree, proto_item *v_item, packet_info *pinfo, tvbuff_t *tvb, int optoff,
    int optend)
{
    int suboptoff = optoff;
    guint16 subopt, subopt_len;
    guint8 type;
    proto_item *vti, *ti;
    proto_tree *pkt_s_tree;
    guchar kr_name;         /* A character in the kerberos realm name option */
    guint8 kr_value;        /* The integer value of the character currently being tested */
    int kr_fail_flag = 0;   /* Flag indicating an invalid character was found */
    int kr_pos = 0;         /* The position of the first invalid character */
    int i = 0;

    subopt = tvb_get_ntohs(tvb, optoff);
    suboptoff += 2;

    subopt_len = tvb_get_ntohs(tvb, suboptoff);
    suboptoff += 2;

    /* There must be at least five octets left to be a valid sub element */
    if (optend <= 0) {
        expert_add_info_format(pinfo, v_item, PI_PROTOCOL, PI_WARN, "Sub element %d: no room left in option for suboption length", subopt);
        return (optend);
    }

    vti = proto_tree_add_item(v_tree, hf_packetcable_cccV6_suboption, tvb, optoff, subopt_len + 4, ENC_BIG_ENDIAN);
    pkt_s_tree = proto_item_add_subtree(vti, ett_dhcpv6_pkt_option);

    switch (subopt) {
        case PKT_CCCV6_PRI_DSS:
            if (subopt_len < 35) {
                proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_pri_dss, tvb, suboptoff, subopt_len, ENC_ASCII|ENC_NA);
            } else {
                expert_add_info_format(pinfo, vti, PI_MALFORMED, PI_ERROR, "Bogus length: %d", subopt_len);
            }
            suboptoff += subopt_len;
            break;
        case PKT_CCCV6_SEC_DSS:
            if (subopt_len < 35) {
                proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_sec_dss, tvb, suboptoff, subopt_len, ENC_ASCII|ENC_NA);
            } else {
                expert_add_info_format(pinfo, vti, PI_MALFORMED, PI_ERROR, "Bogus length: %d", subopt_len);
            }
            suboptoff += subopt_len;
            break;

        case PKT_CCCV6_IETF_PROV_SRV:
            proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_prov_srv_type, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
            type = tvb_get_guint8(tvb, suboptoff);
            /** Type 0 is FQDN **/
            if (type == 0) {
                proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_prov_srv_fqdn, tvb, suboptoff+1, subopt_len-1, ENC_ASCII|ENC_NA);
            /** Type 1 is IPv6 **/
            } else if (type == 1) {
                if ((subopt_len % 16) == 0) {
                    for (i = 0; i < subopt_len/16; i++) {
                        proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_prov_srv_ipv6, tvb, suboptoff+1, 4, ENC_BIG_ENDIAN);
                        suboptoff += 16;
                    }
                }
            } else {
                expert_add_info_format(pinfo, vti, PI_PROTOCOL, PI_WARN, "Invalid type: %u (%u byte%s)",
                    type, subopt_len, plurality(subopt_len, "", "s"));
            }
            suboptoff += subopt_len;
            break;

        case PKT_CCCV6_IETF_AS_KRB:
            if (subopt_len == 12) {
                proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_as_krb_nominal_timeout, tvb, suboptoff, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_as_krb_max_timeout, tvb, suboptoff+4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_as_krb_max_retry_count, tvb, suboptoff+8, 4, ENC_BIG_ENDIAN);
            } else {
                proto_item_append_text(vti, "Bogus length: %d", subopt_len);
            }
            suboptoff += subopt_len;
            break;

        case PKT_CCCV6_IETF_AP_KRB:
            if (subopt_len == 12) {
                proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_ap_krb_nominal_timeout, tvb, suboptoff, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_ap_krb_max_timeout, tvb, suboptoff+4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_ap_krb_max_retry_count, tvb, suboptoff+8, 4, ENC_BIG_ENDIAN);
            } else {
                proto_item_append_text(vti, "Bogus length: %d", subopt_len);
            }
            suboptoff += subopt_len;
            break;

        case PKT_CCCV6_KRB_REALM:
            if (subopt_len > 0) {
                for (i=0; i < subopt_len; i++) {
                    kr_name = tvb_get_guint8(tvb, suboptoff + i);
                    kr_value = (int)kr_name;
                    if ((kr_value >= 65 && kr_value <= 90) ||
                        kr_value == 34 ||
                        kr_value == 44 ||
                        kr_value == 46 ||
                        kr_value == 47 ||
                        kr_value == 58 ||
                        kr_value == 61 ||
                        kr_value == 92) {
                    } else if (!kr_fail_flag) {
                        kr_pos = i;
                        kr_fail_flag = 1;
                    }
                }

                ti = proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_krb_realm, tvb, suboptoff, subopt_len, ENC_ASCII|ENC_NA);
                if (kr_fail_flag)
                    expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN, "Invalid at byte=%d", kr_pos);
            }
            suboptoff += subopt_len;
            break;

        case PKT_CCCV6_TGT_FLAG:
            if (subopt_len == 1) {
                proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_tgt_flag, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_tgt_flag_fetch, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
            }
            else {
                expert_add_info_format(pinfo, vti, PI_MALFORMED, PI_ERROR, "Bogus length: %d", subopt_len);
            }
            suboptoff += subopt_len;
            break;

        case PKT_CCCV6_PROV_TIMER:
            if (subopt_len == 1) {
                ti = proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_prov_timer, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
                if (tvb_get_guint8(tvb, suboptoff ) > 30)
                    expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN, "Invalid time value");
            }
            else {
                expert_add_info_format(pinfo, vti, PI_MALFORMED, PI_ERROR, "Bogus length: %d", subopt_len);
            }
            suboptoff += subopt_len;
            break;

        case PKT_CCCV6_IETF_SEC_TKT:
            proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_sec_tcm, tvb, suboptoff, 2, ENC_BIG_ENDIAN);
            if (subopt_len == 2) {
                proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_sec_tcm_provisioning_server, tvb, suboptoff, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_sec_tcm_call_manager_server, tvb, suboptoff, 2, ENC_BIG_ENDIAN);
            } else {
                expert_add_info_format(pinfo, vti, PI_MALFORMED, PI_ERROR, "Bogus length: %d", subopt_len);
            }
            suboptoff += subopt_len;
            break;

        default:
            suboptoff += subopt_len;
            break;
    }

    /** Return the number of bytes processed **/
    return (suboptoff - optoff);
}

static void
dissect_cablelabs_specific_opts(proto_tree *v_tree, proto_item *v_item, packet_info *pinfo, tvbuff_t *tvb, int voff, int len)
{
    guint16 type,
            tlv_len, /* holds the number of elements in the tlv */
            opt_len, /* holds the length of the suboption */
            sub_value;
    proto_item *ti;
    proto_tree *subtree;
    int off = voff,
        sub_off, /** The offset for the sub-option */
        i, 
        field_len, /* holds the length of one occurrence of a field */
        field_value;

    if (len > 4) {
        while (off - voff < len) {

            /* Type */
            type = tvb_get_ntohs(tvb, off);
            ti = proto_tree_add_item(v_tree, hf_cablelabs_opts, tvb, off, 2, ENC_BIG_ENDIAN);
            /* Length */
            tlv_len = tvb_get_ntohs(tvb, off+2);

            /* Values */
            sub_off = off + 4;

            switch(type) {
                /* String types */
            case CL_OPTION_DEVICE_TYPE :
            case CL_OPTION_DEVICE_SERIAL_NUMBER :
            case CL_OPTION_HARDWARE_VERSION_NUMBER :
            case CL_OPTION_SOFTWARE_VERSION_NUMBER :
            case CL_OPTION_BOOT_ROM_VERSION :
            case CL_OPTION_MODEL_NUMBER :
            case CL_OPTION_VENDOR_NAME :
            case CL_OPTION_CONFIG_FILE_NAME :
            case CL_OPTION_EMBEDDED_COMPONENT_LIST :
                opt_len = tlv_len;
                field_len = tlv_len;
                proto_item_append_text(ti, "\"%s\"",
                                       tvb_format_stringzpad(tvb, sub_off, field_len));
                break;

            case CL_OPTION_VENDOR_OUI :
                /* CableLabs specs treat 17.8 inconsistently
                 * as either binary (3b) or string (6b) */
                opt_len = tlv_len;
                if (tlv_len == 3) {
                    proto_item_append_text(ti, "%s",
                        tvb_bytes_to_str_punct(tvb, sub_off, 3, ':'));
                } else if (tlv_len == 6) {
                    proto_item_append_text(ti, "\"%s\"", tvb_format_stringzpad(tvb, sub_off, tlv_len));
                } else {
                    expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR, "Suboption %d: suboption length isn't 3 or 6", type);
                }
                break;

            case CL_OPTION_ORO :
                field_len = 2;
                opt_len = tlv_len;
                if (opt_len > 0) {
                    for (i = 0; i < tlv_len; i += field_len) {
                        sub_value = tvb_get_ntohs(tvb, sub_off);
                        proto_item_append_text(ti, " %d", sub_value);
                        sub_off += field_len;
                    }
                }
                break;

                /* List of IPv6 Address */
            case CL_OPTION_TFTP_SERVERS :
            case CL_OPTION_SYSLOG_SERVERS :
            case CL_OPTION_RFC868_SERVERS :
                field_len = 16;
                opt_len = tlv_len;
                subtree = proto_item_add_subtree(ti, ett_dhcpv6_vendor_option);

                if ((tlv_len % field_len) == 0) {
                    for (i = 0; i < tlv_len/field_len; i++) {
                        proto_tree_add_item(subtree, hf_cablelabs_ipv6_server, tvb, sub_off, 16, ENC_BIG_ENDIAN);
                        sub_off += field_len;
                    }
                }
                break;

            case CL_OPTION_DEVICE_ID :
                opt_len = tlv_len;
                field_len = tlv_len;
                if (tlv_len != 6) {
                    expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR, "Bogus length: %d", tlv_len);
                }
                else {
                    proto_item_append_text(ti, "%s",
                                           tvb_bytes_to_str(tvb, sub_off, field_len));
                }
                break;

            case CL_OPTION_TLV5 :
                opt_len = tlv_len;
                field_len = tlv_len;
                proto_item_append_text(ti, "%s",
                                       tvb_bytes_to_str(tvb, sub_off, field_len));
                break;

            case CL_OPTION_TIME_OFFSET :
                opt_len = tlv_len;
                proto_item_append_text(ti, "%d", tvb_get_ntohl(tvb, sub_off));
                break;

            case CL_OPTION_IP_PREF :
                opt_len = tlv_len;
                field_value = tvb_get_guint8(tvb, sub_off);
                if (field_value == 1) {
                    proto_item_append_text(ti, "%s", "IPv4");
                } else if (field_value == 2) {
                    proto_item_append_text(ti, "%s", "IPv6");
                } else {
                    proto_item_append_text(ti, "%s", "Unknown");
                }
                break;

            case CL_OPTION_DOCS_CMTS_CAP :
                opt_len = tlv_len;
                field_len = 0;
                subtree = proto_item_add_subtree(ti, ett_dhcpv6_vendor_option);

                /* tlv_len contains the total length of all the TLVs for this
                   option */
                if (tlv_len > 0) {
                    for (i = 0; field_len < opt_len; i++) {
                        int tagLen = 0;
                        int tag = 0;
                        tag = tvb_get_guint8(tvb, sub_off);
                        sub_off++;
                        tagLen = tvb_get_guint8(tvb, sub_off);
                        sub_off++;
                        if (tag == CL_OPTION_DOCS_CMTS_TLV_VERS_NUM &&
                            tagLen == 2) {
                            int major = 0;
                            int minor = 0;
                            major = tvb_get_guint8(tvb, sub_off);
                            sub_off++;
                            minor = tvb_get_guint8(tvb, sub_off);
                            sub_off++;
                            proto_tree_add_text(subtree, tvb, sub_off-2,
                                2, "DOCSIS Version Number %d.%d",
                                                major, minor);
                        }
                        else
                            sub_off += tagLen;

                        field_len += tagLen + 2;
                    }
                }
                else
                    proto_tree_add_text(subtree, tvb, sub_off, 0, "empty");
                break;

            case CL_CM_MAC_ADDR :
                opt_len = tlv_len;
                if (tlv_len != 6) {
                    expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR, "Bogus length: %d", tlv_len);
                }
                else {
                    /*proto_item_append_text(ti, "CM MAC Address Option = %s", */
                    proto_item_append_text(ti, "%s", tvb_bytes_to_str_punct(tvb, sub_off, opt_len, ':'));
                    /* tvb_bytes_to_str(tvb, sub_off, opt_len)); */
                }
                break;

            case CL_EROUTER_CONTAINER_OPTION :
                opt_len = tlv_len;
                proto_item_append_text(ti, " %s (len=%d)",
                                       tvb_bytes_to_str(tvb, sub_off, opt_len), tlv_len);
                break;

            case CL_OPTION_CCC :
                opt_len = tlv_len;
                field_len = 0;
                subtree = proto_item_add_subtree(ti, ett_dhcpv6_vendor_option);
                proto_item_append_text(ti, " (%d bytes)", opt_len);
                while (field_len < opt_len) {
                    sub_value = dissect_packetcable_ccc_option(subtree, ti, pinfo, tvb,
                                                               sub_off, (opt_len - field_len));
                    sub_off += sub_value;
                    field_len += sub_value;
                }
                break;

            case CL_OPTION_CCCV6 :
                opt_len = tlv_len;
                field_len = 0;
                subtree = proto_item_add_subtree(ti, ett_dhcpv6_vendor_option);
                proto_item_append_text(ti, " (%d bytes)", opt_len);
                while (field_len < opt_len) {
                    sub_value = dissect_packetcable_cccV6_option(subtree, ti, pinfo, tvb,
                        sub_off, (opt_len - field_len));
                    sub_off += sub_value;
                    field_len += sub_value;
                }
                break;

            case CL_OPTION_CORRELATION_ID :
                opt_len = tlv_len;
                 if (tlv_len != 4) {
                    proto_item_append_text(ti, "Bogus value length=%d",
                                           tlv_len);
                }
                else {
                    proto_item_append_text(ti, "%d", tvb_get_ntohl(tvb, sub_off));
                }
                break;

            default:
                opt_len = tlv_len;
                break;
            }
            off += (opt_len + 4);

        }
    }
    else {
        expert_add_info_format(pinfo, v_item, PI_PROTOCOL, PI_WARN, "Bogus length: %d", len);
    }
}

/* Adds domain */
static void
dhcpv6_domain(proto_tree * subtree, proto_item *v_item, packet_info *pinfo, tvbuff_t *tvb, int offset, guint16 optlen)
{
    int start_offset=offset;
    char domain[256];
    int pos;
    guint8 len;

    pos=0;
    while(optlen){
        /* this is the start of the domain name */
        if(!pos){
            start_offset=offset;
        }
        domain[pos]=0;

        /* read length of the next substring */
        len = tvb_get_guint8(tvb, offset);
        /* Microsoft dhcpv6 clients aren't currently RFC 4704 conformant: They send an
         * ASCII string instead of a DNS record encoded domain name. Catch that case
         * to allow us to continue after such a malformed record.
         */
        if ( optlen < len ) {
            expert_add_info_format(pinfo, v_item, PI_PROTOCOL, PI_WARN, "Malformed DNS name record (MS Vista client?)");
            return;
        }
        offset++;
        optlen--;
        /* if len==0 and pos>0 we have read an entire domain string */
        if(!len){
            if(!pos){
                /* empty string, this must be an error? */
                expert_add_info_format(pinfo, v_item, PI_MALFORMED, PI_ERROR, "Malformed option");
                return;
            } else {
                proto_tree_add_string(subtree, hf_dhcpv6_domain, tvb, start_offset, offset-start_offset, domain);
                pos=0;
                continue;
            }
        }

        /* add the substring to domain */
        if(pos){
            domain[pos]='.';
            pos++;
        }
        if(pos+len>254){
            /* too long string, this must be an error? */
            expert_add_info_format(pinfo, v_item, PI_MALFORMED, PI_ERROR, "Malformed option");
            return;
        }
        tvb_memcpy(tvb, domain+pos, offset, len);
        pos+=len;
        offset+=len;
        optlen-=len;
    }

    if(pos){
        domain[pos]=0;
        proto_tree_add_string(subtree, hf_dhcpv6_domain, tvb, start_offset, offset-start_offset, domain);
    }
}

/* Returns the number of bytes consumed by this option. */
static int
dhcpv6_option(tvbuff_t *tvb, packet_info *pinfo, proto_tree *bp_tree,
              gboolean downstream, int off, int eoff, gboolean *at_end)
{
    guint16     opttype, optlen, hwtype;
    guint16     temp_optlen = 0;
    proto_item *ti, *option_item;
    proto_tree *subtree;
    proto_tree *subtree_2;
    int i;
    guint16 duidtype;
    guint32 enterprise_no;

    /* option type and length must be present */
    if (eoff - off < 4) {
        *at_end = TRUE;
        return 0;
    }

    opttype = tvb_get_ntohs(tvb, off);
    optlen = tvb_get_ntohs(tvb, off + 2);

    /* all option data must be present */
    if (eoff - off < 4 + optlen) {
        *at_end = TRUE;
        return 0;
    }

    option_item = proto_tree_add_text(bp_tree, tvb, off, 4 + optlen,
                             "%s", val_to_str(opttype, opttype_vals, "DHCP option %u"));

    subtree = proto_item_add_subtree(option_item, ett_dhcpv6_option);
    proto_tree_add_item(subtree, hf_option_type, tvb, off, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_option_length, tvb, off + 2, 2, ENC_BIG_ENDIAN);
    off += 4;
    /* Right now, none of the options can be filtered at, so provide a hex
       array for minimalistic filtering */
    if (optlen)
        proto_tree_add_item(subtree, hf_option_value, tvb, off, optlen, ENC_NA);

    switch (opttype) {
    case OPTION_CLIENTID:
        col_append_fstr(pinfo->cinfo, COL_INFO, "CID: %s ", tvb_bytes_to_str(tvb, off, optlen));
        /* Fall through */
    case OPTION_SERVERID:
        if (optlen < 2) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "DUID: malformed option");
            break;
        }

        proto_tree_add_item(subtree, hf_duid_bytes, tvb, off, optlen, ENC_NA);
        duidtype = tvb_get_ntohs(tvb, off);
        proto_tree_add_item(subtree, hf_duid_type, tvb, off, 2, ENC_BIG_ENDIAN);
        switch (duidtype) {
        case DUID_LLT:
        {
            nstime_t llt_time;

            if (optlen < 8) {
                expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "DUID: malformed option");
                break;
            }
			proto_tree_add_item(subtree, hf_duidllt_hwtype, tvb, off + 2, 2, ENC_BIG_ENDIAN);

            /* Packet specifies seconds since Jan 1 2000, so add 946684800U (30 years) to get back to epoch */
            llt_time.secs = tvb_get_ntohl(tvb, off + 4)+946684800U;
            llt_time.nsecs = 0;

            proto_tree_add_time(subtree, hf_duidllt_time, tvb, off + 4, 4, &llt_time);
            if (optlen > 8) {
                hwtype=tvb_get_ntohs(tvb, off + 2);
                proto_tree_add_string(subtree, hf_duidllt_link_layer_addr, tvb, off + 8,
                                    optlen - 8, tvb_arphrdaddr_to_str(tvb, off+8, optlen-8, hwtype));
            }
        }
        break;
        case DUID_EN:
            if (optlen < 6) {
                expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "DUID: malformed option");
                break;
            }
            proto_tree_add_item(subtree, hf_duiden_enterprise, tvb, off + 2, 4, ENC_BIG_ENDIAN);
            if (optlen > 6) {
                proto_tree_add_item(subtree, hf_duiden_identifier, tvb, off + 6, optlen - 6, ENC_NA);
            }
            break;
        case DUID_LL:
        case DUID_LL_OLD:
            if (optlen < 4) {
                expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "DUID: malformed option");
                break;
            }
            proto_tree_add_item(subtree, hf_duidll_hwtype, tvb, off + 2, 2, ENC_BIG_ENDIAN);
            if (optlen > 4) {
                hwtype=tvb_get_ntohs(tvb, off + 2);
                proto_tree_add_string(subtree, hf_duidll_link_layer_addr, tvb, off + 4,
                                    optlen - 4, tvb_arphrdaddr_to_str(tvb, off+4, optlen-4, hwtype));
            }
            break;
        }
        break;
    case OPTION_IA_NA:
    case OPTION_IA_PD:
        if (optlen < 12) {
            if (opttype == OPTION_IA_NA)
                expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "IA_NA: malformed option");
            else
                expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "IA_PD: malformed option");
            break;
        }
        proto_tree_add_string(subtree, hf_iaid, tvb, off,
                                    4, tvb_arphrdaddr_to_str(tvb, off, 4, opttype));
        if (tvb_get_ntohl(tvb, off+4) == DHCPV6_LEASEDURATION_INFINITY) {
            proto_tree_add_uint_format(subtree, hf_iaid_t1, tvb, off+4,
                                    4, DHCPV6_LEASEDURATION_INFINITY, "T1: infinity");
        } else {
            proto_tree_add_item(subtree, hf_iaid_t1, tvb, off+4,
                                    4, ENC_BIG_ENDIAN);
        }

        if (tvb_get_ntohl(tvb, off+8) == DHCPV6_LEASEDURATION_INFINITY) {
            proto_tree_add_uint_format(subtree, hf_iaid_t2, tvb, off+8,
                                    4, DHCPV6_LEASEDURATION_INFINITY, "T2: infinity");
        } else {
            proto_tree_add_item(subtree, hf_iaid_t2, tvb, off+8,
                                    4, ENC_BIG_ENDIAN);
        }

        temp_optlen = 12;
        while ((optlen - temp_optlen) > 0) {
            temp_optlen += dhcpv6_option(tvb, pinfo, subtree, downstream,
                                         off+temp_optlen, off + optlen, at_end);
            if (*at_end) {
                /* Bad option - just skip to the end */
                temp_optlen = optlen;
            }
        }
        break;
    case OPTION_IA_TA:
        if (optlen < 4) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "IA_TA: malformed option");
            break;
        }
        proto_tree_add_string(subtree, hf_iata, tvb, off,
                                    4, tvb_arphrdaddr_to_str(tvb, off, 4, opttype));
        temp_optlen = 4;
        while ((optlen - temp_optlen) > 0) {
            temp_optlen += dhcpv6_option(tvb, pinfo, subtree, downstream,
                                         off+temp_optlen, off + optlen, at_end);
            if (*at_end) {
                /* Bad option - just skip to the end */
                temp_optlen = optlen;
            }
        }
        break;
    case OPTION_IAADDR:
    {
        guint32 preferred_lifetime, valid_lifetime;

        if (optlen < 24) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "IA_TA: malformed option");
            break;
        }

        proto_tree_add_item(subtree, hf_iaaddr_ip, tvb, off, 16, ENC_BIG_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, "IAA: %s ", tvb_ip6_to_str(tvb, off));

        preferred_lifetime = tvb_get_ntohl(tvb, off + 16);
        valid_lifetime = tvb_get_ntohl(tvb, off + 20);

        if (preferred_lifetime == DHCPV6_LEASEDURATION_INFINITY) {
            proto_tree_add_uint_format(subtree, hf_iaaddr_pref_lifetime, tvb, off+16,
                                    4, DHCPV6_LEASEDURATION_INFINITY, "Preferred lifetime: infinity");
        } else {
            proto_tree_add_item(subtree, hf_iaaddr_pref_lifetime, tvb, off+16,
                                    4, ENC_BIG_ENDIAN);
        }
        if (valid_lifetime == DHCPV6_LEASEDURATION_INFINITY) {
            proto_tree_add_uint_format(subtree, hf_iaaddr_valid_lifetime, tvb, off+20,
                                    4, DHCPV6_LEASEDURATION_INFINITY, "Preferred lifetime: infinity");
        } else {
            proto_tree_add_item(subtree, hf_iaaddr_valid_lifetime, tvb, off+20,
                                    4, ENC_BIG_ENDIAN);
        }

        temp_optlen = 24;
        while ((optlen - temp_optlen) > 0) {
            temp_optlen += dhcpv6_option(tvb, pinfo, subtree, downstream,
                                         off+temp_optlen, off + optlen, at_end);
            if (*at_end) {
                /* Bad option - just skip to the end */
                temp_optlen = optlen;
            }
        }
    }
    break;
    case OPTION_ORO:
    case OPTION_ERO:
        for (i = 0; i < optlen; i += 2) {
            proto_tree_add_item(subtree, hf_requested_option_code, tvb, off+i,
                                    2, ENC_BIG_ENDIAN);
        }
        break;
    case OPTION_PREFERENCE:
        if (optlen != 1) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "PREFERENCE: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_option_preference, tvb, off, 1, ENC_BIG_ENDIAN);
        break;
    case OPTION_ELAPSED_TIME:
        if (optlen != 2) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "ELAPSED-TIME: malformed option");
            break;
        }

        temp_optlen = tvb_get_ntohs(tvb, off);
        proto_tree_add_uint_format(subtree, hf_elapsed_time, tvb, off,
                                    2, temp_optlen*10, "Elapsed-time: %u ms", temp_optlen*10);
        break;
    case OPTION_RELAY_MSG:
        if (optlen == 0) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "RELAY-MSG: malformed option");
        } else {
            /* here, we should dissect a full DHCP message */
            dissect_dhcpv6(tvb, pinfo, subtree, downstream, off, off + optlen);
        }
        break;
    case OPTION_AUTH:
        if (optlen < 11) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "AUTH: malformed option");
            break;
        }

        proto_tree_add_item(subtree, hf_auth_protocol, tvb, off, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_auth_algorithm, tvb, off+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_auth_rdm, tvb, off+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_auth_replay_detection, tvb, off+3, 8, ENC_NA);
        if (optlen != 11)
            proto_tree_add_item(subtree, hf_auth_info, tvb, off+11, optlen-11, ENC_NA);
        break;
    case OPTION_UNICAST:
        if (optlen != 16) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "UNICAST: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_opt_unicast, tvb, off, 16, ENC_BIG_ENDIAN);
        break;
    case OPTION_STATUS_CODE:
        proto_tree_add_item(subtree, hf_opt_status_code, tvb, off, 2, ENC_BIG_ENDIAN);
        if (optlen > 2)
            proto_tree_add_item(subtree, hf_opt_status_msg, tvb, off+2, optlen - 2, ENC_ASCII|ENC_NA);
        break;
    case OPTION_VENDOR_CLASS:
        if (optlen < 4) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "VENDOR_CLASS: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_vendorclass_enterprise, tvb, off, 4, ENC_BIG_ENDIAN);
        if (optlen > 4)
            proto_tree_add_item(subtree, hf_vendorclass_data, tvb, off+6, optlen-6, ENC_NA);
        break;
    case OPTION_VENDOR_OPTS:
        if (optlen < 4) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "VENDOR_OPTS: malformed option");
            break;
        }

        enterprise_no = tvb_get_ntohl(tvb, off);
        ti = proto_tree_add_item(subtree, hf_vendoropts_enterprise, tvb, off, 4, ENC_BIG_ENDIAN);

        if (optlen >= 4) {
            if (enterprise_no == 4491) {
                dissect_cablelabs_specific_opts(subtree, ti, pinfo, tvb, off+4, optlen-4);
            } else {
                int optoffset = 0;

                while((optlen - 4 - optoffset) > 0)  {
                    int olen = tvb_get_ntohs(tvb, off + optoffset + 6);
                    ti = proto_tree_add_text(subtree, tvb, off + optoffset + 4,
                                             4 + olen, "option");
                    subtree_2 = proto_item_add_subtree(ti, ett_dhcpv6_option_vsoption);
                    proto_tree_add_item(subtree_2, hf_vendoropts_enterprise_option_code, tvb, off + optoffset + 4, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(subtree_2, hf_vendoropts_enterprise_option_length, tvb, off + optoffset + 6, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(subtree_2, hf_vendoropts_enterprise_option_data, tvb, off + optoffset + 8, olen, ENC_NA);
                    optoffset += (4 + olen);
                }
            }
        }
        break;
    case OPTION_INTERFACE_ID:
    {
        gint namelen;

        if (optlen == 0) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "INTERFACE_ID: malformed option");
            break;
        }

        namelen = tvb_strnlen(tvb, off, optlen)+1;
        if (namelen == 0) {
            proto_tree_add_item(subtree, hf_interface_id, tvb, off, optlen, ENC_ASCII|ENC_NA);
        } else {
            proto_tree_add_item(subtree, hf_interface_id, tvb, off, namelen-1, ENC_ASCII|ENC_NA);

            temp_optlen = optlen - namelen;
            off += namelen;
            if (temp_optlen >= 6)
                proto_tree_add_string(subtree, hf_interface_id_link_address, tvb, off, temp_optlen, tvb_arphrdaddr_to_str(tvb, off, 6, ARPHRD_ETHER));
        }
    }
    break;
    case OPTION_RECONF_MSG:
        if (optlen != 1) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "RECONF_MSG: malformed option");
            break;
        }

        proto_tree_add_item(subtree, hf_reconf_msg, tvb, off, 1, ENC_BIG_ENDIAN);
        break;
    case OPTION_RECONF_ACCEPT:
        if (optlen)
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "RECONF_ACCEPT: malformed option");
        break;
    case OPTION_SIP_SERVER_D:
        if (optlen > 0) {
            ti = proto_tree_add_text(subtree, tvb, off, optlen, "SIP Servers Domain Search List");
            dhcpv6_domain(subtree, ti, pinfo, tvb, off, optlen);
        }
        break;
    case OPTION_SIP_SERVER_A:
        if (optlen % 16) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "SIP servers address: malformed option");
            break;
        }

        for (i = 0; i < optlen; i += 16)
            proto_tree_add_item(subtree, hf_sip_server_a, tvb, off + i, 16, ENC_BIG_ENDIAN);
        break;
    case OPTION_DNS_SERVERS:
        if (optlen % 16) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "DNS servers address: malformed option");
            break;
        }

        for (i = 0; i < optlen; i += 16)
            proto_tree_add_item(subtree, hf_dns_servers, tvb, off + i, 16, ENC_BIG_ENDIAN);
        break;
    case OPTION_DOMAIN_LIST:
        if (optlen > 0) {
            ti = proto_tree_add_text(subtree, tvb, off, optlen, "DNS Domain Search List");
            dhcpv6_domain(subtree, ti, pinfo, tvb, off, optlen);
        }        
        break;
    case OPTION_NIS_SERVERS:
        if (optlen % 16) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "NIS servers address: malformed option");
            break;
        }
        for (i = 0; i < optlen; i += 16)
            proto_tree_add_item(subtree, hf_nis_servers, tvb, off + i, 16, ENC_BIG_ENDIAN);
        break;
    case OPTION_NISP_SERVERS:
        if (optlen % 16) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "NISP servers address: malformed option");
            break;
        }
        for (i = 0; i < optlen; i += 16)
            proto_tree_add_item(subtree, hf_nisp_servers, tvb, off + i, 16, ENC_BIG_ENDIAN);
        break;
    case OPTION_NIS_DOMAIN_NAME:
        if (optlen > 0) {
            ti = proto_tree_add_text(subtree, tvb, off, optlen, "nis-domain-name");
            dhcpv6_domain(subtree, ti, pinfo, tvb, off, optlen);
        }        
        break;
    case OPTION_NISP_DOMAIN_NAME:
        if (optlen > 0) {
            ti = proto_tree_add_text(subtree, tvb, off, optlen, "nisp-domain-name");
            dhcpv6_domain(subtree, ti, pinfo, tvb, off, optlen);
        }        
        break;
    case OPTION_SNTP_SERVERS:
        if (optlen % 16) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "SNTP servers address: malformed option");
            break;
        }
        for (i = 0; i < optlen; i += 16)
            proto_tree_add_item(subtree, hf_sntp_servers, tvb, off + i, 16, ENC_BIG_ENDIAN);
        break;
    case OPTION_LIFETIME:
        if (optlen != 4) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "LIFETIME: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_opt_lifetime, tvb, off, 4, ENC_BIG_ENDIAN);
        break;
    case OPTION_BCMCS_SERVER_D:
        if (optlen > 0) {
            ti = proto_tree_add_text(subtree, tvb, off, optlen, "BCMCS Servers Domain Search List");
            dhcpv6_domain(subtree, ti, pinfo, tvb, off, optlen);
        }        
        break;
    case OPTION_BCMCS_SERVER_A:
        if (optlen % 16) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "BCMCS servers address: malformed option");
            break;
        }
        for (i = 0; i < optlen; i += 16)
            proto_tree_add_item(subtree, hf_bcmcs_servers_a, tvb, off + i, 16, ENC_BIG_ENDIAN);
        break;
    case OPTION_REMOTE_ID:
        if (optlen < 4) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "REMOTE_ID: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_remoteid_enterprise, tvb, off, 4, ENC_BIG_ENDIAN);
        off += 4;
        proto_tree_add_item(subtree, hf_remoteid_enterprise_id, tvb, off, optlen - 4, ENC_ASCII|ENC_NA);
        break;
    case OPTION_SUBSCRIBER_ID:
        if (optlen == 0) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "SUBSCRIBER_ID: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_subscriber_id, tvb, off, optlen, ENC_ASCII|ENC_NA);
        break;
    case OPTION_CLIENT_FQDN:
        if (optlen < 1) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "FQDN: malformed option");
        } else {
            /*
             * +-----+-+-+-+
             * | MBZ |N|O|S|
             * +-----+-+-+-+
             */
            proto_tree_add_item(subtree, hf_clientfqdn_reserved, tvb, off, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_clientfqdn_n, tvb, off, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_clientfqdn_o, tvb, off, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_clientfqdn_s, tvb, off, 1, ENC_BIG_ENDIAN);

            dhcpv6_domain(subtree, option_item, pinfo, tvb, off+1, optlen-1);
        }
        break;
    case OPTION_PANA_AGENT:
        if (optlen % 16) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "PANA agent address: malformed option");
            break;
        }
        for (i = 0; i < optlen; i += 16)
            proto_tree_add_item(subtree, hf_pana_agent, tvb, off + i, 16, ENC_BIG_ENDIAN);
        break;
    case OPTION_TIME_ZONE:
        if (optlen > 0)
            proto_tree_add_item(subtree, hf_opt_timezone, tvb, off, optlen, ENC_ASCII|ENC_NA);
        break;
    case OPTION_TZDB:
        if (optlen > 0)
            proto_tree_add_item(subtree, hf_opt_tzdb, tvb, off, optlen, ENC_ASCII|ENC_NA);
        break;
    case OPTION_LQ_QUERY:
        if (optlen < 17) {
            expert_add_info_format(pinfo, option_item, PI_PROTOCOL, PI_ERROR, "LQ-QUERY: malformed option");
            break;
        }

        proto_tree_add_item(subtree, hf_lq_query, tvb, off, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_lq_query_link_address, tvb, off+1, 16, ENC_BIG_ENDIAN);
        temp_optlen = 17;
        while ((optlen - temp_optlen) > 0) {
            temp_optlen += dhcpv6_option(tvb, pinfo, subtree,
                                         downstream, off + temp_optlen,
                                         off + optlen, at_end);
            if (*at_end) {
                /* Bad option - just skip to the end */
                temp_optlen = optlen;
            }
        }
        break;
    case OPTION_CLIENT_DATA:
        temp_optlen = 0;
        while ((optlen - temp_optlen) > 0) {
            temp_optlen += dhcpv6_option(tvb, pinfo, subtree,
                                         downstream, off + temp_optlen,
                                         off + optlen, at_end);
            if (*at_end) {
                /* Bad option - just skip to the end */
                temp_optlen = optlen;
            }
        }
        break;
    case OPTION_CLT_TIME:
        if (optlen != 4) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "CLT_TIME: malformed option");
            break;
        }

        proto_tree_add_item(subtree, hf_clt_time, tvb, off, 4, ENC_BIG_ENDIAN);
        break;
    case OPTION_LQ_RELAY_DATA:
        if (optlen < 16) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "LQ_RELAY_DATA: malformed option");
            break;
        }

        proto_tree_add_item(subtree, hf_lq_relay_data_peer_addr, tvb, off, 16, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_lq_relay_data_msg, tvb, off+16, optlen - 16, ENC_ASCII|ENC_NA);
        break;
    case OPTION_LQ_CLIENT_LINK:
        if (optlen % 16) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "LQ client links address: malformed option");
            break;
        }
        for (i = 0; i < optlen; i += 16)
            proto_tree_add_item(subtree, hf_lq_client_link, tvb, off + i, 16, ENC_BIG_ENDIAN);
        break;
    case OPTION_CAPWAP_AC_V6:
        if (optlen % 16) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "CAPWAP Access Controllers address: malformed option");
            break;
        }
        for (i = 0; i < optlen; i += 16)
            proto_tree_add_item(subtree, hf_capwap_ac_v6, tvb, off + i, 16, ENC_BIG_ENDIAN);
        break;
    case OPTION_AFTR_NAME:
    {
        const guchar *dns_name;
        get_dns_name(tvb, off, optlen, off, &dns_name);
        proto_tree_add_string(subtree, hf_aftr_name, tvb, off, optlen, dns_name);
        break;
    }
    case OPTION_IAPREFIX:
        if (optlen < 25) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "IAPREFIX: malformed option");
            break;
        }

        if (tvb_get_ntohl(tvb, off) == DHCPV6_LEASEDURATION_INFINITY) {
            proto_tree_add_uint_format(subtree, hf_iaprefix_pref_lifetime, tvb, off,
                                    4, DHCPV6_LEASEDURATION_INFINITY, "Preferred lifetime: infinity");
        } else {
            proto_tree_add_item(subtree, hf_iaprefix_pref_lifetime, tvb, off,
                                    4, ENC_BIG_ENDIAN);
        }
        if (tvb_get_ntohl(tvb, off + 4) == DHCPV6_LEASEDURATION_INFINITY) {
            proto_tree_add_uint_format(subtree, hf_iaprefix_valid_lifetime, tvb, off+4,
                                    4, DHCPV6_LEASEDURATION_INFINITY, "Valid lifetime: infinity");
        } else {
            proto_tree_add_item(subtree, hf_iaprefix_valid_lifetime, tvb, off+4,
                                    4, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(subtree, hf_iaprefix_pref_len, tvb, off+8, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_iaprefix_pref_addr, tvb, off+9, 16, ENC_BIG_ENDIAN);
        temp_optlen = 25;
        while ((optlen - temp_optlen) > 0) {
            temp_optlen += dhcpv6_option(tvb, pinfo, subtree, downstream,
                                         off+temp_optlen, off + optlen, at_end);
            if (*at_end) {
                /* Bad option - just skip to the end */
                temp_optlen = optlen;
            }
        }
        break;
    case OPTION_MIP6_HA:
        if (optlen != 16) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "MIP6_HA: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_mip6_ha, tvb, off, 16, ENC_BIG_ENDIAN);
        break;
    case OPTION_MIP6_HOA:
        if (optlen != 16) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "MIP6_HOA: malformed option");
            break;
        }

        proto_tree_add_item(subtree, hf_mip6_hoa, tvb, off, 16, ENC_BIG_ENDIAN);
        break;
    case OPTION_NAI:
        if (optlen < 4) {
            expert_add_info_format(pinfo, option_item, PI_MALFORMED, PI_ERROR, "NAI: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_nai, tvb, off, optlen - 2, ENC_ASCII|ENC_NA);
        break;
    }

    return 4 + optlen;
}


static void
dissect_dhcpv6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               gboolean downstream, int off, int eoff)
{
    proto_tree *bp_tree = NULL;
    proto_item *ti;
    guint8 msgtype;
    gboolean at_end;
    struct e_in6_addr in6;

    msgtype = tvb_get_guint8(tvb, off);

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(msgtype, msgtype_vals, "Message Type %u"));

    if (tree) {
        ti = proto_tree_add_item(tree, proto_dhcpv6, tvb, off, eoff - off, ENC_NA);
        bp_tree = proto_item_add_subtree(ti, ett_dhcpv6);
    }


    if (msgtype == RELAY_FORW || msgtype == RELAY_REPLY) {
        if (tree) {
            proto_tree_add_item(bp_tree, hf_dhcpv6_msgtype, tvb, off, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(bp_tree, hf_dhcpv6_hopcount, tvb, off + 1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(bp_tree, hf_dhcpv6_linkaddr, tvb, off + 2, 16, ENC_NA);
            tvb_get_ipv6(tvb, off + 2, &in6);
            col_append_fstr(pinfo->cinfo, COL_INFO, "L: %s ", ip6_to_str(&in6));
            proto_tree_add_item(bp_tree, hf_dhcpv6_peeraddr, tvb, off + 18, 16, ENC_NA);
        }
        off += 34;
    } else {
        if (tree) {
            proto_tree_add_item(bp_tree, hf_dhcpv6_msgtype, tvb, off, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(bp_tree, hf_dhcpv6_xid, tvb, off + 1, 3, ENC_BIG_ENDIAN);
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, "XID: 0x%x ", tvb_get_ntoh24(tvb, off + 1));
        off += 4;
    }

    at_end = FALSE;
    while (off < eoff && !at_end)
        off += dhcpv6_option(tvb, pinfo, bp_tree, downstream, off, eoff, &at_end);
}

static void
dissect_dhcpv6_downstream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DHCPv6");
    col_clear(pinfo->cinfo, COL_INFO);
    dissect_dhcpv6(tvb, pinfo, tree, TRUE, 0, tvb_reported_length(tvb));
}

static void
dissect_dhcpv6_upstream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DHCPv6");
    col_clear(pinfo->cinfo, COL_INFO);
    dissect_dhcpv6(tvb, pinfo, tree, FALSE, 0, tvb_reported_length(tvb));
}


void
proto_register_dhcpv6(void)
{
    static hf_register_info hf[] = {

        /* DHCPv6 header */
        { &hf_dhcpv6_msgtype,
          { "Message type", "dhcpv6.msgtype", FT_UINT8, BASE_DEC, VALS(msgtype_vals), 0x0, NULL, HFILL }},
        { &hf_dhcpv6_domain,
          { "Domain", "dhcpv6.domain", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_dhcpv6_hopcount,
          { "Hopcount", "dhcpv6.hopcount", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_dhcpv6_xid,
          { "Transaction ID", "dhcpv6.xid", FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL}},
        { &hf_dhcpv6_linkaddr,
          { "Link address", "dhcpv6.linkaddr", FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL}},
        { &hf_dhcpv6_peeraddr,
          { "Peer address", "dhcpv6.peeraddr", FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL}},
        /* Generic option stuff */
        { &hf_option_type,
          { "Option", "dhcpv6.option.type", FT_UINT16, BASE_DEC, VALS(opttype_vals), 0x0, NULL, HFILL}},
        { &hf_option_length,
          { "Length", "dhcpv6.option.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        { &hf_option_value,
          { "Value", "dhcpv6.option.value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        /* Individual options */
        { &hf_clientfqdn_reserved,
          { "Reserved", "dhcpv6.clientfqdn.reserved", FT_UINT8, BASE_HEX, NULL, 0xF8, NULL, HFILL}},
        { &hf_clientfqdn_n,
          { "N bit", "dhcpv6.clientfqdn.n", FT_BOOLEAN, 8, TFS(&fqdn_n), 0x4, "Whether the server SHOULD NOT perform any DNS updates", HFILL}},
        { &hf_clientfqdn_o,
          { "O bit", "dhcpv6.clientfqdn.o", FT_BOOLEAN, 8, TFS(&fqdn_o), 0x2, "Whether the server has overridden the client's preference for the S bit.  Must be 0 when sent from client", HFILL}},
        { &hf_clientfqdn_s,
          { "S bit", "dhcpv6.clientfqdn.s", FT_BOOLEAN, 8, TFS(&fqdn_s), 0x1, "Whether the server SHOULD or SHOULD NOT perform the AAAA RR (FQDN-to-address) DNS updates", HFILL}},
        { &hf_remoteid_enterprise,
          { "Enterprise ID", "dhcpv6.remoteid.enterprise", FT_UINT32, BASE_DEC|BASE_EXT_STRING,  &sminmpec_values_ext, 0, "RemoteID Enterprise Number", HFILL }},
        { &hf_duid_bytes,
          { "DUID", "dhcpv6.duid.bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_duid_type,
          { "DUID Type", "dhcpv6.duid.type", FT_UINT16, BASE_DEC, VALS(duidtype_vals), 0x0, NULL, HFILL}},
        { &hf_duidllt_time,
          { "DUID Time", "dhcpv6.duidllt.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL}},
        { &hf_duidllt_link_layer_addr,
          { "Link-layer address", "dhcpv6.duidllt.link_layer_addr", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_duidllt_hwtype,
          { "Hardware type", "dhcpv6.duidllt.hwtype", FT_UINT16, BASE_DEC, VALS(arp_hrd_vals), 0, "DUID LLT Hardware Type", HFILL }},
        { &hf_duidll_hwtype,
          { "Hardware type", "dhcpv6.duidll.hwtype", FT_UINT16, BASE_DEC, VALS(arp_hrd_vals), 0, "DUID LL Hardware Type", HFILL }},
        { &hf_duiden_enterprise,
          { "Enterprise ID", "dhcpv6.duiden.enterprise", FT_UINT32, BASE_DEC|BASE_EXT_STRING,  &sminmpec_values_ext, 0, "DUID EN Enterprise Number", HFILL }},
        { &hf_duiden_identifier,
          { "Identifier", "dhcpv6.duiden.identifier", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_duidll_link_layer_addr,
          { "Link-layer address", "dhcpv6.duidll.link_layer_addr", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_iaid,
          { "IAID", "dhcpv6.iaid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_iaid_t1,
          { "T1", "dhcpv6.iaid.t1", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_iaid_t2,
          { "T2", "dhcpv6.iaid.t2", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_iata,
          { "IATA", "dhcpv6.iata", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_iaaddr_ip,
          { "IPv6 address", "dhcpv6.iaaddr.ip", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_iaaddr_pref_lifetime,
          { "Preferred lifetime", "dhcpv6.iaaddr.pref_lifetime", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_iaaddr_valid_lifetime,
          { "Valid lifetime", "dhcpv6.iaaddr.valid_lifetime", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_requested_option_code,
          { "Requested Option code", "dhcpv6.requested_option_code", FT_UINT16, BASE_DEC, VALS(opttype_vals), 0, NULL, HFILL }},
        { &hf_option_preference,
          { "Pref-value", "dhcpv6.option_preference", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_elapsed_time,
          { "Elapsed time", "dhcpv6.elapsed_time", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_auth_protocol,
          { "Protocol", "dhcpv6.auth.protocol", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_auth_algorithm,
          { "Algorithm", "dhcpv6.auth.algorithm", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_auth_rdm,
          { "RDM", "dhcpv6.auth.rdm", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_auth_replay_detection,
          { "Replay Detection", "dhcpv6.auth.replay_detection", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_auth_info,
          { "Authentication Information", "dhcpv6.auth.info", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_opt_unicast,
          { "IPv6 address", "dhcpv6.unicast", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_opt_status_code,
          { "Status Code", "dhcpv6.status_code", FT_UINT16, BASE_DEC, VALS(statuscode_vals), 0, NULL, HFILL }},
        { &hf_opt_status_msg,
          { "Status Message", "dhcpv6.status_msg", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_vendorclass_enterprise,
          { "Enterprise ID", "dhcpv6.vendorclass.enterprise", FT_UINT32, BASE_DEC|BASE_EXT_STRING,  &sminmpec_values_ext, 0, "Vendor Class Enterprise Number", HFILL }},
        { &hf_vendorclass_data,
          { "vendor-class-data", "dhcpv6.vendorclass.data", FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_vendoropts_enterprise,
          { "Enterprise ID", "dhcpv6.vendoropts.enterprise", FT_UINT32, BASE_DEC|BASE_EXT_STRING,  &sminmpec_values_ext, 0, "Vendor opts Enterprise Number", HFILL }},
        { &hf_vendoropts_enterprise_option_code,
          { "Option code", "dhcpv6.vendoropts.enterprise.option_code", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_vendoropts_enterprise_option_length,
          { "Option length", "dhcpv6.vendoropts.enterprise.option_length", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_vendoropts_enterprise_option_data,
          { "Option data", "dhcpv6.vendoropts.enterprise.option_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_interface_id,
          { "Interface-ID", "dhcpv6.interface_id", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_interface_id_link_address,
          { "Link Address", "dhcpv6.interface_id_link_address", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_reconf_msg,
          { "Reconfigure message type", "dhcpv6.reconf_msg", FT_UINT8, BASE_DEC, VALS(msgtype_vals), 0, NULL, HFILL }},
        { &hf_sip_server_a,
          { "SIP server address", "dhcpv6.sip_server_a", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_dns_servers,
          { "DNS server address", "dhcpv6.dns_server", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_nis_servers,
          { "NIS server address", "dhcpv6.nis_server", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_nisp_servers,
          { "NISP server address", "dhcpv6.nisp_server", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_sntp_servers,
          { "SNTP server address", "dhcpv6.sntp_server", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_opt_lifetime,
          { "Lifetime", "dhcpv6.lifetime", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_bcmcs_servers_a,
          { "BCMCS server address", "dhcpv6.bcmcs_server_a", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_remoteid_enterprise_id,
          { "Remote-ID", "dhcpv6.remoteid_enterprise_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_subscriber_id,
          { "Subscriber-ID", "dhcpv6.subscriber_id", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_pana_agent,
          { "PANA agents address", "dhcpv6.pana_agent", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_opt_timezone,
          { "Time-zone", "dhcpv6.timezone", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_opt_tzdb,
          { "TZ-database", "dhcpv6.tzdb", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lq_query,
          { "Query-type", "dhcpv6.lq_query", FT_UINT8, BASE_DEC, VALS(lq_query_vals), 0, NULL, HFILL }},
        { &hf_lq_query_link_address,
          { "Link address", "dhcpv6.lq_query_link_address", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_clt_time,
          { "Clt_time", "dhcpv6.clt_time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_lq_relay_data_peer_addr,
          { "Peer address", "dhcpv6.lq_relay_data_peer_addr", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_lq_relay_data_msg,
          { "DHCPv6 relay message", "dhcpv6.lq_relay_data_msg", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_lq_client_link,
          { "LQ client links address", "dhcpv6.lq_client_link", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_capwap_ac_v6,
          { "CAPWAP Access Controllers address", "dhcpv6.capwap_ac_v6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_aftr_name,
          { "DS-Lite AFTR Name", "dhcpv6.aftr_name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_iaprefix_pref_lifetime,
          { "Preferred lifetime", "dhcpv6.iaprefix.pref_lifetime", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_iaprefix_valid_lifetime,
          { "Valid lifetime", "dhcpv6.iaprefix.valid_lifetime", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_iaprefix_pref_len,
          { "Prefix length", "dhcpv6.iaprefix.pref_len", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_iaprefix_pref_addr,
          { "Prefix address", "dhcpv6.iaprefix.pref_addr", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_mip6_ha,
          { "Home Agent", "dhcpv6.mip6_home_agent", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_mip6_hoa,
          { "Home Address", "dhcpv6.mip6_home_address", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_nai,
          { "NAI", "dhcpv6.nai", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_ccc_suboption,
          { "Sub element", "dhcpv6.packetcable.ccc.suboption", FT_UINT16, BASE_DEC, VALS(pkt_ccc_opt_vals), 0, NULL, HFILL }},
        { &hf_packetcable_ccc_pri_dhcp,
          { "Primary DHCP", "dhcpv6.packetcable.ccc.pri_dhcp", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_ccc_sec_dhcp,
          { "Secondary DHCP", "dhcpv6.packetcable.ccc.sec_dhcp", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_ccc_prov_srv_type,
          { "Type", "dhcpv6.packetcable.ccc.prov_srv.type", FT_UINT8, BASE_DEC, VALS(pkt_ccc_prov_srv_type_vals), 0, NULL, HFILL }},
        { &hf_packetcable_ccc_prov_srv_fqdn,
          { "FQDN", "dhcpv6.packetcable.ccc.prov_srv.fqdn", FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_ccc_prov_srv_ipv4,
          { "IPv4 address", "dhcpv6.packetcable.ccc.prov_srv.ipv4", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_ccc_as_krb_nominal_timeout,
          { "Nominal Timeout", "dhcpv6.packetcable.ccc.as_krb.nominal_timeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_ccc_as_krb_max_timeout,
          { "Maximum Timeout", "dhcpv6.packetcable.ccc.as_krb.max_timeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_ccc_as_krb_max_retry_count,
          { "Maximum Retry Count", "dhcpv6.packetcable.ccc.as_krb.max_retry_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_ccc_ap_krb_nominal_timeout,
          { "Nominal Timeout", "dhcpv6.packetcable.ccc.ap_krb.nominal_timeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_ccc_ap_krb_max_timeout,
          { "Maximum Timeout", "dhcpv6.packetcable.ccc.ap_krb.max_timeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_ccc_ap_krb_max_retry_count,
          { "Maximum Retry Count", "dhcpv6.packetcable.ccc.ap_krb.max_retry_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_ccc_krb_realm,
          { "KRB Realm", "dhcpv6.packetcable.ccc.krb_realm", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_ccc_tgt_flag,
          { "TGT Flags", "dhcpv6.packetcable.ccc.tgt_flag", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_ccc_tgt_flag_fetch,
          { "Fetch TGT", "dhcpv6.packetcable.ccc.tgt_flag.fetch", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x01, NULL, HFILL }},
        { &hf_packetcable_ccc_prov_timer,
          { "Provisioning timer", "dhcpv6.packetcable.ccc.prov_timer", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_ccc_sec_tcm,
          { "SEC TCM Flags", "dhcpv6.packetcable.ccc.sec_tcm", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_ccc_sec_tcm_provisioning_server,
          { "Provisioning Server", "dhcpv6.packetcable.ccc.sec_tcm.provisioning_server", FT_BOOLEAN, 16, TFS(&tfs_on_off), 0x01, NULL, HFILL }},
        { &hf_packetcable_ccc_sec_tcm_call_manager_server,
          { "Call Manager Servers", "dhcpv6.packetcable.ccc.tgt_flag.call_manager_server", FT_BOOLEAN, 16, TFS(&tfs_on_off), 0x02, NULL, HFILL }},
        { &hf_packetcable_cccV6_suboption,
          { "Sub element", "dhcpv6.packetcable.cccV6.suboption", FT_UINT16, BASE_DEC, VALS(pkt_cccV6_opt_vals), 0, NULL, HFILL }},
        { &hf_packetcable_cccV6_pri_dss,
          { "Primary DHCP", "dhcpv6.packetcable.cccV6.pri_dss", FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_cccV6_sec_dss,
          { "Secondary DHCP", "dhcpv6.packetcable.cccV6.sec_dss", FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_cccV6_prov_srv_type,
          { "Type", "dhcpv6.packetcable.cccV6.prov_srv.type", FT_UINT8, BASE_DEC, VALS(pkt_cccV6_prov_srv_type_vals), 0, NULL, HFILL }},
        { &hf_packetcable_cccV6_prov_srv_fqdn,
          { "FQDN", "dhcpv6.packetcable.cccV6.prov_srv.fqdn", FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_cccV6_prov_srv_ipv6,
          { "IPv6 address", "dhcpv6.packetcable.cccV6.prov_srv.ipv6", FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_cccV6_as_krb_nominal_timeout,
          { "Nominal Timeout", "dhcpv6.packetcable.cccV6.as_krb.nominal_timeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_cccV6_as_krb_max_timeout,
          { "Maximum Timeout", "dhcpv6.packetcable.cccV6.as_krb.max_timeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_cccV6_as_krb_max_retry_count,
          { "Maximum Retry Count", "dhcpv6.packetcable.cccV6.as_krb.max_retry_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_cccV6_ap_krb_nominal_timeout,
          { "Nominal Timeout", "dhcpv6.packetcable.cccV6.ap_krb.nominal_timeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_cccV6_ap_krb_max_timeout,
          { "Maximum Timeout", "dhcpv6.packetcable.cccV6.ap_krb.max_timeout", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_cccV6_ap_krb_max_retry_count,
          { "Maximum Retry Count", "dhcpv6.packetcable.cccV6.ap_krb.max_retry_count", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_cccV6_krb_realm,
          { "KRB Realm", "dhcpv6.packetcable.cccV6.krb_realm", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_cccV6_tgt_flag,
          { "TGT Flags", "dhcpv6.packetcable.cccV6.tgt_flag", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_cccV6_tgt_flag_fetch,
          { "Fetch TGT", "dhcpv6.packetcable.cccV6.tgt_flag.fetch", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x01, NULL, HFILL }},
        { &hf_packetcable_cccV6_prov_timer,
          { "Provisioning timer", "dhcpv6.packetcable.cccV6.prov_timer", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_cccV6_sec_tcm,
          { "SEC TCM Flags", "dhcpv6.packetcable.cccV6.sec_tcm", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_cccV6_sec_tcm_provisioning_server,
          { "Provisioning Server", "dhcpv6.packetcable.cccV6.sec_tcm.provisioning_server", FT_BOOLEAN, 16, TFS(&tfs_on_off), 0x01, NULL, HFILL }},
        { &hf_packetcable_cccV6_sec_tcm_call_manager_server,
          { "Call Manager Servers", "dhcpv6.packetcable.cccV6.tgt_flag.call_manager_server", FT_BOOLEAN, 16, TFS(&tfs_on_off), 0x02, NULL, HFILL }},
        { &hf_cablelabs_opts,
          { "Suboption", "dhcpv6.cablelabs.opt", FT_UINT16, BASE_DEC, VALS(cl_vendor_subopt_values), 0, NULL, HFILL }},
        { &hf_cablelabs_ipv6_server,
          { "IPv6 address", "dhcpv6.cablelabs.ipv6_server", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    };

    static gint *ett[] = {
        &ett_dhcpv6,
        &ett_dhcpv6_option,
        &ett_dhcpv6_option_vsoption,
        &ett_dhcpv6_vendor_option,
        &ett_dhcpv6_pkt_option,
    };

    proto_dhcpv6 = proto_register_protocol("DHCPv6", "DHCPv6", "dhcpv6");
    proto_register_field_array(proto_dhcpv6, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Allow other dissectors to find this one by name.
       Just choose upstream version for now as they are identical. */
    register_dissector("dhcpv6", dissect_dhcpv6_upstream, proto_dhcpv6);
}

void
proto_reg_handoff_dhcpv6(void)
{
    dissector_handle_t dhcpv6_handle;

    dhcpv6_handle = create_dissector_handle(dissect_dhcpv6_downstream,
                                            proto_dhcpv6);
    dissector_add_uint("udp.port", UDP_PORT_DHCPV6_DOWNSTREAM, dhcpv6_handle);
    dhcpv6_handle = create_dissector_handle(dissect_dhcpv6_upstream,
                                            proto_dhcpv6);
    dissector_add_uint("udp.port", UDP_PORT_DHCPV6_UPSTREAM, dhcpv6_handle);
}

