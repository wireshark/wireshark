/* packet-dhcpv6.c
 * Routines for DHCPv6 packet disassembly
 * Copyright 2004, Nicolas DICHTEL - 6WIND - <nicolas.dichtel@6wind.com>
 * Jun-ichiro itojun Hagino <itojun@iijlab.net>
 * IItom Tsutomu MIENO <iitom@utouto.com>
 * SHIRASAKI Yasuhiro <yasuhiro@gnome.gr.jp>
 * Tony Lindstrom <tony.lindstrom@ericsson.com>
 * Copyright 2012, Jerome LAFORGE <jerome.laforge@gmail.com>
 *
 * The information used comes from:
 * RFC1034 (DOMAIN NAMES - CONCEPTS AND FACILITIES)
 * RFC1035 (DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION)
 * RFC1535 (A Security Problem with DNS) [clear definition of Partial names]
 * RFC2181 (Clarifications to the DNS Specification)
 * RFC3319 (SIP options)
 * RFC3633 (Prefix options) replaces draft-ietf-dhc-dhcpv6-opt-lifetime-00
 * RFC3646 (DNS Configuration options for DHCP for IPv6 (DHCPv6))
 * RFC3898 (NIS options)
 * RFC4075 (SNTP - Configuration Option for DHCPv6)
                 - replaces "draft-ietf-dhc-dhcpv6-opt-timeconfig-03"
 * RFC4242 (Information Refresh Time Option)
 * RFC4280 (Broadcast and Multicast Control Servers Options)
 * RFC4649 (Remote ID option)
 * RFC4704 (DHCPv6 Client FQDN Option)
 * RFC5007 (DHCPv6 Leasequery)
 * RFC5417 (CAPWAP Access Controller DHCP Option)
 * RFC5460 (DHCPv6 Bulk Leasequery)
 * RFC5908 (Network Time Protocol (NTP) Server Option)
 * RFC6334 (Dual-Stack Lite Option)
 * RFC6603 (Prefix Exclude Option)
 * RFC7598 (Configuration of Softwire Address and Port-Mapped Clients)
 * RFC8415 (Dynamic Host Configuration Protocol for IPv6 (DHCPv6))
 * RFC8520 (Manufacturer Usage Descriptions) replaces "draft-ietf-opsawg-mud-02"
 * CL-SP-CANN-DHCP-Reg-I15-180509 (CableLabs' DHCP Options Registry) latest
 *
 * Note that protocol constants are still subject to change, based on IANA
 * assignment decisions.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/arptypes.h>
#include <epan/strutil.h>
#include "packet-tcp.h"
#include "packet-arp.h"
#include "packet-dns.h"

void proto_register_dhcpv6(void);
void proto_reg_handoff_dhcpv6(void);

static gboolean dhcpv6_bulk_leasequery_desegment  = TRUE;
static gboolean cablelabs_interface_id = FALSE;

static int proto_dhcpv6 = -1;
static int proto_dhcpv6_bulk_leasequery = -1;
static int hf_dhcpv6_msgtype = -1;
static int hf_clientfqdn_bad_msgtype = -1;
static int hf_clientfqdn_flags = -1;
static int hf_clientfqdn_client_n = -1;
static int hf_clientfqdn_client_s = -1;
static int hf_clientfqdn_server_n = -1;
static int hf_clientfqdn_server_o = -1;
static int hf_clientfqdn_server_s = -1;
static int hf_option_type_str=-1;
static int hf_option_type_num = -1;
static int hf_option_length = -1;
static int hf_empty_domain_name = -1;
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
static int hf_duiduuid_bytes = -1;
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
static int hf_auth_realm = -1;
static int hf_auth_key_id = -1;
static int hf_auth_md5_data = -1;
static int hf_opt_unicast = -1;
static int hf_opt_status_code = -1;
static int hf_opt_status_msg = -1;
static int hf_vendorclass_enterprise = -1;
static int hf_vendorclass_data = -1;
static int hf_vendoropts_enterprise_option_code = -1;
static int hf_vendoropts_enterprise_option_length = -1;
static int hf_vendoropts_enterprise_option_data = -1;
static int hf_interface_id = -1;
static int hf_reconf_msg = -1;
static int hf_sip_server_domain_search_fqdn = -1;
static int hf_sip_server_a = -1;
static int hf_dns_servers = -1;
static int hf_domain_search_list_entry = -1;
static int hf_nis_servers = -1;
static int hf_nisp_servers = -1;
static int hf_nis_fqdn = -1;
static int hf_nisp_fqdn = -1;
static int hf_sntp_servers = -1;
static int hf_opt_lifetime = -1;
static int hf_bcmcs_servers_fqdn = -1;
static int hf_bcmcs_servers_a = -1;
static int hf_remoteid_enterprise_id = -1;
static int hf_subscriber_id = -1;
static int hf_client_fqdn = -1;
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
static int hf_pd_exclude_pref_len = -1;
static int hf_pd_exclude_subnet_id = -1;
static int hf_option_captive_portal = -1;
static int hf_option_s46_option_code = -1;
static int hf_option_failover_binding_status = -1;
static int hf_option_failover_connect_flags = -1;
static int hf_option_failover_connect_reserved_flag = -1;
static int hf_option_failover_connect_f_flag = -1;
static int hf_option_failover_dns_hostname = -1;
static int hf_option_failover_dns_zonename = -1;
static int hf_option_failover_dns_flags = -1;
static int hf_option_failover_dns_reserved_flag = -1;
static int hf_option_failover_dns_u_flag = -1;
static int hf_option_failover_dns_s_flag = -1;
static int hf_option_failover_dns_r_flag = -1;
static int hf_option_failover_dns_f_flag = -1;
static int hf_option_failover_expiration_time = -1;
static int hf_option_failover_max_unacked_bndupd = -1;
static int hf_option_failover_mclt = -1;
static int hf_option_failover_partner_lifetime = -1;
static int hf_option_failover_partner_lifetime_sent = -1;
static int hf_option_failover_partner_downtime = -1;
static int hf_option_failover_partner_raw_clt_time = -1;
static int hf_option_failover_major_version = -1;
static int hf_option_failover_minor_version = -1;
static int hf_option_failover_keepalive_time = -1;
static int hf_option_failover_reconfigure_time = -1;
static int hf_option_failover_reconfigure_key = -1;
static int hf_option_failover_relationship_name = -1;
static int hf_option_failover_server_flags = -1;
static int hf_option_failover_server_reserved_flag = -1;
static int hf_option_failover_server_a_flag = -1;
static int hf_option_failover_server_s_flag = -1;
static int hf_option_failover_server_c_flag = -1;
static int hf_option_failover_server_state = -1;
static int hf_option_failover_start_time_of_state = -1;
static int hf_option_failover_state_expiration_time = -1;
static int hf_option_relay_port = -1;
static int hf_dhcpv6_hopcount = -1;
static int hf_dhcpv6_xid = -1;
static int hf_dhcpv6_peeraddr = -1;
static int hf_dhcpv6_linkaddr = -1;
static int hf_opt_mudurl = -1;
static int hf_option_ntpserver_type = -1;
static int hf_option_ntpserver_length = -1;
static int hf_option_ntpserver_addr = -1;
static int hf_option_ntpserver_mc_addr = -1;
static int hf_option_ntpserver_fqdn = -1;
static int hf_packetcable_ccc_suboption = -1;
static int hf_packetcable_ccc_pri_dhcp = -1;
static int hf_packetcable_ccc_sec_dhcp = -1;
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
static int hf_modem_capabilities_encoding_type = -1;
static int hf_eue_capabilities_encoding_type = -1;
static int hf_capabilities_encoding_length = -1;
static int hf_capabilities_encoding_bytes = -1;
static int hf_capabilities_encoding_number = -1;
static int hf_cablelabs_ipv6_server = -1;
static int hf_cablelabs_docsis_version_number = -1;
static int hf_cablelabs_interface_id = -1;
static int hf_cablelabs_interface_id_link_address = -1;
static int hf_option_s46_rule_flags = -1;
static int hf_option_s46_rule_reserved_flag = -1;
static int hf_option_s46_rule_fmr_flag = -1;
static int hf_option_s46_rule_ea_len = -1;
static int hf_option_s46_rule_ipv4_pref_len = -1;
static int hf_option_s46_rule_ipv4_prefix = -1;
static int hf_option_s46_rule_ipv6_pref_len = -1;
static int hf_option_s46_rule_ipv6_prefix = -1;
static int hf_option_s46_br_address = -1;
static int hf_option_s46_dmr_pref_len = -1;
static int hf_option_s46_dmr_prefix = -1;
static int hf_option_s46_v4v6bind_ipv4_address = -1;
static int hf_option_s46_v4v6bind_ipv6_pref_len = -1;
static int hf_option_s46_v4v6bind_ipv6_prefix = -1;
static int hf_option_s46_portparam_offset = -1;
static int hf_option_s46_portparam_psid_len = -1;
static int hf_option_s46_portparam_psid = -1;

static int hf_dhcpv6_non_dns_encoded_name = -1;
static int hf_dhcpv6_domain_field_len_exceeded = -1;
static int hf_dhcpv6_decoded_portion = -1;
static int hf_dhcpv6_encoded_fqdn_len_gt_255 = -1;
static int hf_dhcpv6_root_only_domain_name = -1;
static int hf_dhcpv6_tld = -1;
static int hf_dhcpv6_partial_name_preceded_by_fqdn = -1;

static gint ett_dhcpv6 = -1;
static gint ett_dhcpv6_option = -1;
static gint ett_dhcpv6_option_vsoption = -1;
static gint ett_dhcpv6_vendor_option = -1;
static gint ett_dhcpv6_pkt_option = -1;
static gint ett_dhcpv6_netserver_option = -1;
static gint ett_dhcpv6_tlv5_type = -1;
static gint ett_dhcpv6_sip_server_domain_search_list_option = -1;
static gint ett_dhcpv6_dns_domain_search_list_option = -1;
static gint ett_dhcpv6_nis_domain_name_option = -1;
static gint ett_dhcpv6_nisp_domain_name_option = -1;
static gint ett_dhcpv6_bcmcs_servers_domain_search_list_option = -1;
static gint ett_dhcpv6_s46_rule_flags = -1;
static gint ett_dhcpv6_failover_connect_flags = -1;
static gint ett_dhcpv6_failover_dns_flags = -1;
static gint ett_dhcpv6_failover_server_flags = -1;
static gint ett_clientfqdn_flags = -1;
static gint ett_clientfqdn_expert = -1;

/* Expert fields relating to domain names */
static expert_field ei_dhcpv6_non_dns_encoded_name=EI_INIT;
static expert_field ei_dhcpv6_domain_field_len_exceeded=EI_INIT;
static expert_field ei_dhcpv6_encoded_fqdn_len_gt_255=EI_INIT;
static expert_field ei_dhcpv6_root_only_domain_name=EI_INIT;
static expert_field ei_dhcpv6_tld_lookup=EI_INIT;
static expert_field ei_dhcpv6_partial_name_preceded_by_fqdn=EI_INIT;
/*
 * Expert fields triggered in dhcpv6_option() and others */
static expert_field ei_dhcpv6_bogus_length = EI_INIT;
static expert_field ei_dhcpv6_malformed_option = EI_INIT;
static expert_field ei_dhcpv6_no_suboption_len = EI_INIT;
static expert_field ei_dhcpv6_invalid_time_value = EI_INIT;
static expert_field ei_dhcpv6_invalid_type = EI_INIT;
static expert_field ei_dhcpv6_error_hopcount = EI_INIT;
static expert_field ei_dhcpv6_clientfqdn_bad_msgtype=EI_INIT;
static expert_field ei_dhcpv6_s_bit_should_be_zero=EI_INIT;


static int hf_dhcpv6_bulk_leasequery_size = -1;
static int hf_dhcpv6_bulk_leasequery_msgtype = -1;
static int hf_dhcpv6_bulk_leasequery_reserved = -1;
static int hf_dhcpv6_bulk_leasequery_trans_id = -1;

static gint ett_dhcpv6_bulk_leasequery = -1;
static gint ett_dhcpv6_bulk_leasequery_options = -1;

static expert_field ei_dhcpv6_bulk_leasequery_bad_query_type = EI_INIT;
static expert_field ei_dhcpv6_bulk_leasequery_bad_msg_type = EI_INIT;

static dissector_handle_t dhcpv6_handle;

#define TCP_PORT_DHCPV6_UPSTREAM        547
#define UDP_PORT_DHCPV6_RANGE      "546-547" /* Downstream + Upstream */

#define DHCPV6_LEASEDURATION_INFINITY   0xffffffff
#define HOP_COUNT_LIMIT                 32

/********************************************************************************************/
/********************************** MESSAGE TYPES *******************************************/
/********************************************************************************************/
/*                                     SENT BY                                              */
/*                                     -------                                              */
#define SOLICIT                  1  /* CLIENT                                               */
#define ADVERTISE                2  /* SERVER(S)                                            */
#define REQUEST                  3  /* CLIENT                                               */
#define CONFIRM                  4  /* CLIENT                                               */
#define RENEW                    5  /* CLIENT                                               */
#define REBIND                   6  /* CLIENT                                               */
#define REPLY                    7  /* SERVER(S)                                            */
#define RELEASE                  8  /* CLIENT                                               */
#define DECLINE                  9  /* CLIENT                                               */
#define RECONFIGURE             10  /* SERVER(S)  (see 18-19)                               */
#define INFORMATION_REQUEST     11  /* CLIENT                                               */
#define RELAY_FORW              12  /* relay agents                                         */
#define RELAY_REPLY             13  /* relay agents                                         */
#define LEASEQUERY              14  /*                                                      */
#define LEASEQUERY_REPLY        15  /*                                                      */
#define LEASEQUERY_DONE         16  /*                                                      */
#define LEASEQUERY_DATA         17  /*                                                      */
#define RECONFIGURE_REQUEST     18  /* SERVER  (Server requests client to send requests)    */
#define RECONFIGURE_REPLY       19  /* CLIENT  (Client replies with the requested requests) */

/* TODO: add support the following message types
#define DHCPV4-QUERY            20  [RFC7341]
#define DHCPV4-RESPONSE         21  [RFC7341]
#define ACTIVELEASEQUERY        22  [RFC7653]
#define STARTTLS                23  [RFC7653]
#define BNDUPD                  24  [RFC8156]
#define BNDREPLY                25  [RFC8156]
#define POOLREQ                 26  [RFC8156]
#define POOLRESP                27  [RFC8156]
#define UPDREQ                  28  [RFC8156]
#define UPDREQALL               29  [RFC8156]
#define UPDDONE                 30  [RFC8156]
#define CONNECT                 31  [RFC8156]
#define CONNECTREPLY            32  [RFC8156]
#define DISCONNECT              33  [RFC8156]
#define STATE                   34  [RFC8156]
#define CONTACT                 35  [RFC8156]
                                36-255 Unassigned
*********************************************************************************************/

/********************************************************************************************/
/**************************************** OPTIONS *******************************************/
/********************************************************************************************/
#define OPTION_CLIENTID                1
#define OPTION_SERVERID                2
#define OPTION_IA_NA                   3
#define OPTION_IA_TA                   4
#define OPTION_IAADDR                  5
#define OPTION_ORO                     6
#define OPTION_PREFERENCE              7
#define OPTION_ELAPSED_TIME            8
#define OPTION_RELAY_MSG               9
/* #define      OPTION_SERVER_MSG     10 */
#define OPTION_AUTH                   11
#define OPTION_UNICAST                12
#define OPTION_STATUS_CODE            13
#define OPTION_RAPID_COMMIT           14
#define OPTION_USER_CLASS             15
#define OPTION_VENDOR_CLASS           16
#define OPTION_VENDOR_OPTS            17
#define OPTION_INTERFACE_ID           18
#define OPTION_RECONF_MSG             19
#define OPTION_RECONF_ACCEPT          20
#define OPTION_SIP_SERVER_D           21 /* RFC 3319 */
#define OPTION_SIP_SERVER_A           22 /* RFC 3319 */
#define OPTION_DNS_SERVERS            23 /* RFC 3646 */
#define OPTION_DOMAIN_LIST            24 /* RFC 3646 */
#define OPTION_IA_PD                  25 /* RFC 3633 */
#define OPTION_IAPREFIX               26 /* RFC 3633 */
#define OPTION_NIS_SERVERS            27 /* RFC 3898 */
#define OPTION_NISP_SERVERS           28 /* RFC 3898 */
#define OPTION_NIS_DOMAIN_NAME        29 /* RFC 3898 */
#define OPTION_NISP_DOMAIN_NAME       30 /* RFC 3898 */
#define OPTION_SNTP_SERVERS           31 /* RFC 4075 */
#define OPTION_LIFETIME               32 /* RFC 4242: OPTION_INFORMATION_REFRESH_TIME */
#define OPTION_BCMCS_SERVER_D         33 /* RFC 4280 */
#define OPTION_BCMCS_SERVER_A         34 /* RFC 4280 */
/* 35 - Unassigned */
#define OPTION_GEOCONF_CIVIC          36 /* RFC 4776 */
#define OPTION_REMOTE_ID              37 /* RFC 4649 */
#define OPTION_SUBSCRIBER_ID          38 /* RFC 4580 */
#define OPTION_CLIENT_FQDN            39 /* RFC 4704 */
#define OPTION_PANA_AGENT             40 /* RFC 5192 */
#define OPTION_TIME_ZONE              41 /* RFC 4833: OPTION_NEW_POSIX_TIMEZONE */
#define OPTION_TZDB                   42 /* RFC 4833: OPTION_NEW_TZDB_TIMEZONE */
#define OPTION_ERO                    43 /* RFC 4994 */
#define OPTION_LQ_QUERY               44 /* RFC 5007 */
#define OPTION_CLIENT_DATA            45 /* RFC 5007 */
#define OPTION_CLT_TIME               46 /* RFC 5007 */
#define OPTION_LQ_RELAY_DATA          47 /* RFC 5007 */
#define OPTION_LQ_CLIENT_LINK         48 /* RFC 5007 */
#define OPTION_MIP6_HNIDF             49 /* RFC 6610 */
#define OPTION_MIP6_VDINF             50 /* RFC 6610 */
#define OPTION_V6_LOST                51 /* RFC 5223 */
#define OPTION_CAPWAP_AC_V6           52 /* RFC 5417 */
#define OPTION_RELAYID                53 /* RFC 5460 */
#define OPTION_IPV6_ADDRESS_MOS       54 /* RFC 5678: OPTION-IPv6_Address-MoS */
#define OPTION_IPV6_FQDN_MOS          55 /* RFC 5678: OPTION-IPv6_FQDN-MoS */
#define OPTION_NTP_SERVER             56 /* RFC 5908 */
#define OPTION_V6_ACCESS_DOMAIN       57 /* RFC 5986 */
#define OPTION_SIP_UA_CS_LIST         58 /* RFC 6011 */
#define OPTION_BOOTFILE_URL           59 /* RFC 5970: OPT_BOOTFILE_URL */
#define OPTION_BOOTFILE_PARAM         60 /* RFC 5970: OPT_BOOTFILE_PARAM */
#define OPTION_CLIENT_ARCH_TYPE       61 /* RFC 5970 */
#define OPTION_NII                    62 /* RFC 5970 */
#define OPTION_GEOLOCATION            63 /* RFC 6225 */
#define OPTION_AFTR_NAME              64 /* RFC 6334 */
#define OPTION_ERP_LOCAL_DOMAIN_NAME  65 /* RFC 6440 */
#define OPTION_RSOO                   66 /* RFC 6422 */
#define OPTION_PD_EXCLUDE             67 /* RFC 6603 */
#define OPTION_VSS                    68 /* RFC 6607 */
#define OPTION_MIP6_IDINF             69 /* RFC 6610 */
#define OPTION_MIP6_UDINF             70 /* RFC 6610 */
#define OPTION_MIP6_HNP               71 /* RFC 6610 */
#define OPTION_MIP6_HAA               72 /* RFC 6610 */
#define OPTION_MIP6_HAF               73 /* RFC 6610 */
#define OPTION_RDNSS_SELECTION        74 /* RFC 6731 */
#define OPTION_KRB_PRINCIPAL_NAME     75 /* RFC 6784 */
#define OPTION_KRB_REALM_NAME         76 /* RFC 6784 */
#define OPTION_KRB_DEFAULT_REALM_NAME 77 /* RFC 6784 */
#define OPTION_KRB_KDC                78 /* RFC 6784 */
#define OPTION_CLIENT_LINKLAYER_ADDR  79 /* RFC 6939 */
#define OPTION_LINK_ADDRESS           80 /* RFC 6977 */
#define OPTION_RADIUS                 81 /* RFC 7037 */
#define OPTION_SOL_MAX_RT             82 /* RFC 7083 */
#define OPTION_INF_MAX_RT             83 /* RFC 7083 */
#define OPTION_ADDRSEL                84 /* RFC 7078 */
#define OPTION_ADDRSEL_TABLE          85 /* RFC 7078 */
#define OPTION_V6_PCP_SERVER          86 /* RFC 7291 */
#define OPTION_DHCPV4_MSG             87 /* RFC 7341 */
#define OPTION_DHCP4_O_DHCP6_SERVER   88 /* RFC 7341 */
#define OPTION_S46_RULE               89 /* RFC 7598 */
#define OPTION_S46_BR                 90 /* RFC 7598 */
#define OPTION_S46_DMR                91 /* RFC 7598 */
#define OPTION_S46_V4V6BIND           92 /* RFC 7598 */
#define OPTION_S46_PORTPARAMS         93 /* RFC 7598 */
#define OPTION_S46_CONT_MAPE          94 /* RFC 7598 */
#define OPTION_S46_CONT_MAPT          95 /* RFC 7598 */
#define OPTION_S46_CONT_LW            96 /* RFC 7598 */
#define OPTION_4RD                    97 /* RFC 7600 */
#define OPTION_4RD_MAP_RULE           98 /* RFC 7600 */
#define OPTION_4RD_NON_MAP_RULE       99 /* RFC 7600 */
#define OPTION_LQ_BASE_TIME          100 /* RFC 7653 */
#define OPTION_LQ_START_TIME         101 /* RFC 7653 */
#define OPTION_LQ_END_TIME           102 /* RFC 7653 */
#define OPTION_CAPTIVE_PORTAL        103 /* RFC 7710: DHCP Captive-Portal */
#define OPTION_MPL_PARAMETERS        104 /* RFC 7774 */
#define OPTION_ANI_ATT               105 /* RFC 7839 */
#define OPTION_ANI_NETWORK_NAME      106 /* RFC 7839 */
#define OPTION_ANI_AP_NAME           107 /* RFC 7839 */
#define OPTION_ANI_AP_BSSID          108 /* RFC 7839 */
#define OPTION_ANI_OPERATOR_ID       109 /* RFC 7839 */
#define OPTION_ANI_OPERATOR_REALM    110 /* RFC 7839 */
#define OPTION_S46_PRIORITY          111 /* RFC 8026 */
#define OPTION_MUDURL                112 /* MUDURL */
#define OPTION_V6_PREFIX64           113 /* RFC 8115 */
#define OPTION_F_BINDING_STATUS      114 /* RFC 8156 */
#define OPTION_F_CONNECT_FLAGS       115 /* RFC 8156 */
#define OPTION_F_DNS_REMOVAL_INFO    116 /* RFC 8156 */
#define OPTION_F_DNS_HOST_NAME       117 /* RFC 8156 */
#define OPTION_F_DNS_ZONE_NAME       118 /* RFC 8156 */
#define OPTION_F_DNS_FLAGS           119 /* RFC 8156 */
#define OPTION_F_EXPIRATION_TIME     120 /* RFC 8156 */
#define OPTION_F_MAX_UNACKED_BNDUPD  121 /* RFC 8156 */
#define OPTION_F_MCLT                  122  /* RFC 8156 */
#define OPTION_F_PARTNER_LIFETIME      123  /* RFC 8156 */
#define OPTION_F_PARTNER_LIFETIME_SENT 124  /* RFC 8156 */
#define OPTION_F_PARTNER_DOWN_TIME     125  /* RFC 8156 */
#define OPTION_F_PARTNER_RAW_CLT_TIME  126  /* RFC 8156 */
#define OPTION_F_PROTOCOL_VERSION      127  /* RFC 8156 */
#define OPTION_F_KEEPALIVE_TIME        128  /* RFC 8156 */
#define OPTION_F_RECONFIGURE_DATA      129  /* RFC 8156 */
#define OPTION_F_RELATIONSHIP_NAME     130  /* RFC 8156 */
#define OPTION_F_SERVER_FLAGS          131  /* RFC 8156 */
#define OPTION_F_SERVER_STATE          132  /* RFC 8156 */
#define OPTION_F_START_TIME_OF_STATE   133  /* RFC 8156 */
#define OPTION_F_STATE_EXPIRATION_TIME 134  /* RFC 8156 */
#define OPTION_RELAY_PORT              135  /* RFC 8357 */
#define OPTION_V6_SZTP_REDIRECT        136  /* RFC-ietf-netconf-zerotouch-29 */
#define OPTION_S46_BIND_IPV6_PREFIX    137  /* RFC 8539 */
#define OPTION_IPv6_ADDRESS_ANDSF      143  /* RFC 6153 */

/* temporary value until defined by IETF */
#define OPTION_MIP6_HA                 165
#define OPTION_MIP6_HOA                166
#define OPTION_NAI                     167
/********************************************************************************************/

#define DUID_LLT                1
#define DUID_EN                 2
#define DUID_LL                 3
#define DUID_UUID               4

static const value_string msgtype_vals[] = {
    { SOLICIT,                       "Solicit" },
    { ADVERTISE,                     "Advertise" },
    { REQUEST,                       "Request" },
    { CONFIRM,                       "Confirm" },
    { RENEW,                         "Renew" },
    { REBIND,                        "Rebind" },
    { REPLY,                         "Reply" },
    { RELEASE,                       "Release" },
    { DECLINE,                       "Decline" },
    { RECONFIGURE,                   "Reconfigure" },
    { INFORMATION_REQUEST,           "Information-request" },
    { RELAY_FORW,                    "Relay-forw" },
    { RELAY_REPLY,                   "Relay-reply" },
    { LEASEQUERY,                    "Leasequery" },
    { LEASEQUERY_REPLY,              "Leasequery-reply" },
    { LEASEQUERY_DONE,               "Leasequery-done" },
    { LEASEQUERY_DATA,               "Leasequery-data" },
    { RECONFIGURE_REQUEST,           "Reconfigure-request" },
    { RECONFIGURE_REPLY,             "Reconfigure-reply" },
    { 0, NULL }
};
static value_string_ext msgtype_vals_ext = VALUE_STRING_EXT_INIT(msgtype_vals);

static const value_string opttype_vals[] = {
    { OPTION_CLIENTID,               "Client Identifier" },
    { OPTION_SERVERID,               "Server Identifier" },
    { OPTION_IA_NA,                  "Identity Association for Non-temporary Address" },
    { OPTION_IA_TA,                  "Identity Association for Temporary Address" },
    { OPTION_IAADDR,                 "IA Address" },
    { OPTION_ORO,                    "Option Request" },
    { OPTION_PREFERENCE,             "Preference" },
    { OPTION_ELAPSED_TIME,           "Elapsed time" },
    { OPTION_RELAY_MSG,              "Relay Message" },
/*  { OPTION_SERVER_MSG,             "Server message" }, */
    { OPTION_AUTH,                   "Authentication" },
    { OPTION_UNICAST,                "Server unicast" },
    { OPTION_STATUS_CODE,            "Status code" },
    { OPTION_RAPID_COMMIT,           "Rapid Commit" },
    { OPTION_USER_CLASS,             "User Class" },
    { OPTION_VENDOR_CLASS,           "Vendor Class" },
    { OPTION_VENDOR_OPTS,            "Vendor-specific Information" },
    { OPTION_INTERFACE_ID,           "Interface-Id" },
    { OPTION_RECONF_MSG,             "Reconfigure Message" },
    { OPTION_RECONF_ACCEPT,          "Reconfigure Accept" },
    { OPTION_SIP_SERVER_D,           "SIP Server Domain Name List" },
    { OPTION_SIP_SERVER_A,           "SIP Servers IPv6 Address List" },
    { OPTION_DNS_SERVERS,            "DNS recursive name server" },
    { OPTION_DOMAIN_LIST,            "Domain Search List" },
    { OPTION_IA_PD,                  "Identity Association for Prefix Delegation" },
    { OPTION_IAPREFIX,               "IA Prefix" },
    { OPTION_NIS_SERVERS,            "Network Information Server" },
    { OPTION_NISP_SERVERS,           "Network Information Server V2" },
    { OPTION_NIS_DOMAIN_NAME,        "Network Information Server Domain Name" },
    { OPTION_NISP_DOMAIN_NAME,       "Network Information Server V2 Domain Name" },
    { OPTION_SNTP_SERVERS,           "Simple Network Time Protocol Server" },
    { OPTION_LIFETIME,               "Lifetime" },
    { OPTION_BCMCS_SERVER_D,         "BCMCS Server Domain" },
    { OPTION_BCMCS_SERVER_A,         "BCMCS Servers IPv6 Address List" },
    { OPTION_GEOCONF_CIVIC,          "Geoconf Civic Address" },
    { OPTION_REMOTE_ID,              "Remote Identifier" },
    { OPTION_SUBSCRIBER_ID,          "Subscriber Identifier" },
    { OPTION_CLIENT_FQDN,            "Client Fully Qualified Domain Name" },
    { OPTION_PANA_AGENT,             "PANA Agents IPv6 Address List" },
    { OPTION_TIME_ZONE,              "Time Zone" },
    { OPTION_TZDB,                   "Time Zone Database" },
    { OPTION_ERO,                    "Echo Request Option" },
    { OPTION_LQ_QUERY,               "Leasequery Query" },
    { OPTION_CLIENT_DATA,            "Leasequery Client Data" },
    { OPTION_CLT_TIME,               "Client Last Transaction Time" },
    { OPTION_LQ_RELAY_DATA,          "Leasequery Relay Data" },
    { OPTION_LQ_CLIENT_LINK,         "Leasequery Client Link Address List" },
    { OPTION_MIP6_HNIDF,             "Home Network Identifier FQDN" },
    { OPTION_MIP6_VDINF,             "Visited Home Network Information" },
    { OPTION_V6_LOST,                "LoST Server" },
    { OPTION_CAPWAP_AC_V6,           "CAPWAP Access Controllers" },
    { OPTION_RELAYID,                "Relay-ID" },
    { OPTION_IPV6_ADDRESS_MOS,       "MoS IPv6 Address" },
    { OPTION_IPV6_FQDN_MOS,          "MoS Domain Name List" },
    { OPTION_NTP_SERVER,             "NTP Server" },
    { OPTION_V6_ACCESS_DOMAIN,       "Access Network Domain Name" },
    { OPTION_SIP_UA_CS_LIST,         "SIP User Agent Configuration Service Domains" },
    { OPTION_BOOTFILE_URL,           "Boot File URL" },
    { OPTION_BOOTFILE_PARAM,         "Boot File Parameters" },
    { OPTION_CLIENT_ARCH_TYPE,       "Client System Architecture Type" },
    { OPTION_NII,                    "Client Network Interface Identifier" },
    { OPTION_GEOLOCATION,            "Geolocation" },
    { OPTION_AFTR_NAME,              "Dual-Stack Lite AFTR Name" },
    { OPTION_ERP_LOCAL_DOMAIN_NAME,  "ERP Local Domain Name" },
    { OPTION_RSOO,                   "Relay-Supplied Options" },
    { OPTION_PD_EXCLUDE,             "Prefix Exclude" },
    { OPTION_VSS,                    "Virtual Subnet Selection" },
    { OPTION_MIP6_IDINF,             "Identified Home Network Information" },
    { OPTION_MIP6_UDINF,             "Unrestricted Home Network Information" },
    { OPTION_MIP6_HNP,               "Home Network Prefix" },
    { OPTION_MIP6_HAA,               "Home Agent Address" },
    { OPTION_MIP6_HAF,               "Home Agent FQDN" },
    { OPTION_RDNSS_SELECTION,        "RDNSS Selection" },
    { OPTION_KRB_PRINCIPAL_NAME,     "Kerberos Principal Name" },
    { OPTION_KRB_REALM_NAME,         "Kerberos Realm Name" },
    { OPTION_KRB_DEFAULT_REALM_NAME, "Kerberos Default Realm Name" },
    { OPTION_KRB_KDC,                "Kerberos KDC" },
    { OPTION_CLIENT_LINKLAYER_ADDR,  "Client Link-Layer Address" },
    { OPTION_LINK_ADDRESS,           "Link Address" },
    { OPTION_RADIUS,                 "RADIUS" },
    { OPTION_SOL_MAX_RT,             "SOL_MAX_RT" },
    { OPTION_INF_MAX_RT,             "INF_MAX_RT" },
    { OPTION_ADDRSEL,                "Address Selection" },
    { OPTION_ADDRSEL_TABLE,          "Address Selection table" },
    { OPTION_V6_PCP_SERVER,          "PCP Server" },
    { OPTION_DHCPV4_MSG,             "DHCPv4 Message" },
    { OPTION_DHCP4_O_DHCP6_SERVER,   "DHCP 4o6 Servers Address" },
    { OPTION_S46_RULE,               "S46 Rule" },
    { OPTION_S46_BR,                 "S46 BR" },
    { OPTION_S46_DMR,                "S46 DMR" },
    { OPTION_S46_V4V6BIND,           "S46 IPv4/IPv6 Address Binding" },
    { OPTION_S46_PORTPARAMS,         "S46 Port Parameters" },
    { OPTION_S46_CONT_MAPE,          "S46 MAP-E Container" },
    { OPTION_S46_CONT_MAPT,          "S46 MAP-T Container" },
    { OPTION_S46_CONT_LW,            "S46 Lightweight 4over6 Container" },
    { OPTION_4RD,                    "4rd Options" },
    { OPTION_4RD_MAP_RULE,           "4rd Mapping Rule" },
    { OPTION_4RD_NON_MAP_RULE,       "4rd Non-Mapping Rule" },
    { OPTION_LQ_BASE_TIME,           "LQ Server Base Time" },
    { OPTION_LQ_START_TIME,          "LQ Server Query Start Time" },
    { OPTION_LQ_END_TIME,            "LQ Server Query End Time" },
    { OPTION_CAPTIVE_PORTAL,         "Captive Portal" },
    { OPTION_MPL_PARAMETERS,         "MPL Parameter Configuration" },
    { OPTION_ANI_ATT,                "Access Technology Type" },
    { OPTION_ANI_NETWORK_NAME,       "Access Network Name" },
    { OPTION_ANI_AP_NAME,            "Access Point Name" },
    { OPTION_ANI_AP_BSSID,           "Access Point BSSID" },
    { OPTION_ANI_OPERATOR_ID,        "Access Network Operator ID" },
    { OPTION_ANI_OPERATOR_REALM,     "Access Network Operator Realm" },
    { OPTION_S46_PRIORITY,           "S46 Priority" },
    { OPTION_MUDURL,                 "Manufacturer Usage Description" },
    { OPTION_V6_PREFIX64,            "IPv4/IPv6 Multicast Prefixes" },
    { OPTION_F_BINDING_STATUS,       "Failover Binding Status" },
    { OPTION_F_CONNECT_FLAGS,        "Failover Connect Flags" },
    { OPTION_F_DNS_REMOVAL_INFO,     "Failover DNS Removal Info" },
    { OPTION_F_DNS_HOST_NAME,        "Failover DNS Hostname" },
    { OPTION_F_DNS_ZONE_NAME,        "Failover DNS Zone Name" },
    { OPTION_F_DNS_FLAGS,            "Failover DNS Flags" },
    { OPTION_F_EXPIRATION_TIME,      "Failover Expiration Time" },
    { OPTION_F_MAX_UNACKED_BNDUPD,   "Failover Maximum Number Unacked BNDUPD Messages" },
    { OPTION_F_MCLT,                 "Failover Maximum Client Lead Time (MCLT)" },
    { OPTION_F_PARTNER_LIFETIME,     "Failover Partner Lifetime" },
    { OPTION_F_PARTNER_LIFETIME_SENT,"Failover Partner Lifetime Sent" },
    { OPTION_F_PARTNER_DOWN_TIME,    "Failover Partner Down Time" },
    { OPTION_F_PARTNER_RAW_CLT_TIME, "Failover Partner Raw Client Time" },
    { OPTION_F_PROTOCOL_VERSION,     "Failover Protocol Version" },
    { OPTION_F_KEEPALIVE_TIME,       "Failover Keepalive Time" },
    { OPTION_F_RECONFIGURE_DATA,     "Failover Reconfigure Data" },
    { OPTION_F_RELATIONSHIP_NAME,    "Failover Relationship Name" },
    { OPTION_F_SERVER_FLAGS,         "Failover Server Flags" },
    { OPTION_F_SERVER_STATE,         "Failover Server State" },
    { OPTION_F_START_TIME_OF_STATE,  "Failover Start Time of State" },
    { OPTION_F_STATE_EXPIRATION_TIME,"Failover State Expiration Time" },
    { OPTION_RELAY_PORT,             "Relay Source Port" },
    { OPTION_V6_SZTP_REDIRECT,       "SZTP Redirect" },
    { OPTION_S46_BIND_IPV6_PREFIX,   "Softwire Source Binding Prefix Hint" },
    { OPTION_IPv6_ADDRESS_ANDSF,     "ANDSF IPv6 Address" },
    { OPTION_MIP6_HA,                "Mobile IPv6 Home Agent" },
    { OPTION_MIP6_HOA,               "Mobile IPv6 Home Address" },
    { OPTION_NAI,                    "Network Access Identifier" },
    { 0,        NULL }
};
static value_string_ext opttype_vals_ext = VALUE_STRING_EXT_INIT(opttype_vals);

static const value_string statuscode_vals[] =
{
    { 0, "Success" },
    { 1, "UnspecFail" },
    { 2, "NoAddrAvail" },
    { 3, "NoBinding" },
    { 4, "NotOnLink" },
    { 5, "UseMulticast" },
    { 6, "NoPrefixAvail" },
    { 7, "UnknownQueryType" },
    { 8, "MalformedQuery" },
    { 9, "NotConfigured" },
    {10, "NotAllowed" },
    {11, "QueryTerminated" },
    {12, "DataMissing" },           /* RFC 7653 */
    {13, "CatchUpComplete" },       /* RFC 7653 */
    {14, "NotSupported" },          /* RFC 7653 */
    {15, "TLSConnectionRefused" },  /* RFC 7653 */
    {0, NULL }
};
static value_string_ext statuscode_vals_ext = VALUE_STRING_EXT_INIT(statuscode_vals);

static const value_string duidtype_vals[] =
{
    { DUID_LLT,  "link-layer address plus time" },
    { DUID_EN,   "assigned by vendor based on Enterprise number" },
    { DUID_LL,   "link-layer address" },
    { DUID_UUID, "Universally Unique IDentifier (UUID)" },
    { 0, NULL }
};

#define NTP_SUBOPTION_SRV_ADDR  1
#define NTP_SUBOPTION_MC_ADDR   2
#define NTP_SUBOPTION_SRV_FQDN  3

static const value_string ntp_server_opttype_vals[] =
{
    { NTP_SUBOPTION_SRV_ADDR,    "NTP Server Address" },
    { NTP_SUBOPTION_MC_ADDR,     "NTP Multicast Address" },
    { NTP_SUBOPTION_SRV_FQDN,    "NTP Server FQDN" },

    { 0, NULL }
};


static const true_false_string fqdn_n = {
    "Server SHOULD NOT perform PTR RR updates",
    "Server SHOULD perform PTR RR updates"
};

static const true_false_string fqdn_o = {
    "Server HAS overridden client's S bit preference",
    "Server HAS NOT overridden client's S bit preference"
};

static const true_false_string fqdn_s = {
    "Server SHOULD perform AAAA RR updates",
    "Server SHOULD NOT perform AAAA RR updates"
};

#define LQ_QUERY_ADDRESS        1
#define LQ_QUERY_CLIENTID       2
#define LQ_QUERY_RELAYID        3
#define LQ_QUERY_LINK_ADDRESS   4
#define LQ_QUERY_REMOTEID       5

static const value_string lq_query_vals[] = {
    { LQ_QUERY_ADDRESS,      "by-address" },
    { LQ_QUERY_CLIENTID,     "by-clientID" },
    { LQ_QUERY_RELAYID,      "by-relayID" },
    { LQ_QUERY_LINK_ADDRESS, "by-linkAddress" },
    { LQ_QUERY_REMOTEID,     "by-remoteID" },
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
/* 11-32 are currently reserved */
#define CL_OPTION_TFTP_SERVERS            0x0020 /* 32 */
#define CL_OPTION_CONFIG_FILE_NAME        0x0021 /* 33 */
#define CL_OPTION_SYSLOG_SERVERS          0x0022 /* 34 */
#define CL_OPTION_TLV5                    0x0023 /* 35 */
#define CL_OPTION_DEVICE_ID               0x0024 /* 36 */
#define CL_OPTION_RFC868_SERVERS          0x0025 /* 37 */
#define CL_OPTION_TIME_OFFSET             0x0026 /* 38 */
#define CL_OPTION_IP_PREF                 0x0027 /* 39 */
#define CL_OPTION_CCAP_CORES              0x003D /* 61 */

/** CableLabs DOCSIS Project Vendor Specific Options */
#define CL_OPTION_DOCS_CMTS_CAP 0x0401  /* 1025 */
#define CL_CM_MAC_ADDR 0x0402 /* 1026 */
#define CL_EROUTER_CONTAINER_OPTION 0x403 /* 1027 */

/** CableLabs PacketCable Project Vendor Specific Options **/
#define CL_OPTION_CCC            0x087a  /* 2170 */
#define CL_OPTION_CCCV6          0x087b  /* 2171 */
#define CL_OPTION_CORRELATION_ID 0x087c  /* 2172 */

/** CableLabs TLVs for DOCS_CMTS_CAP Vendor Option **/
#define CL_OPTION_DOCS_CMTS_TLV_VERS_NUM 0x01 /* 1 */

static const value_string cl_vendor_subopt_values[] = {
    /*    1 */ { CL_OPTION_ORO,                     "Option Request = " },
    /*    2 */ { CL_OPTION_DEVICE_TYPE,             "Device Type = " },
    /*    3 */ { CL_OPTION_EMBEDDED_COMPONENT_LIST, "Embedded Components = " },
    /*    4 */ { CL_OPTION_DEVICE_SERIAL_NUMBER,    "Serial Number = " },
    /*    5 */ { CL_OPTION_HARDWARE_VERSION_NUMBER, "Hardware Version = " },
    /*    6 */ { CL_OPTION_SOFTWARE_VERSION_NUMBER, "Software Version = " },
    /*    7 */ { CL_OPTION_BOOT_ROM_VERSION,        "Boot ROM Version = " },
    /*    8 */ { CL_OPTION_VENDOR_OUI,              "Organization Unique Identifier = " },
    /*    9 */ { CL_OPTION_MODEL_NUMBER,            "Model Number = " },
    /*   10 */ { CL_OPTION_VENDOR_NAME,             "Vendor Name = " },
    /*   32 */ { CL_OPTION_TFTP_SERVERS,            "TFTP Server Addresses : " },
    /*   33 */ { CL_OPTION_CONFIG_FILE_NAME,        "Configuration File Name = " },
    /*   34 */ { CL_OPTION_SYSLOG_SERVERS,          "Syslog Servers : " },
    /*   35 */ { CL_OPTION_TLV5,                    "TLV5 = " },
    /*   36 */ { CL_OPTION_DEVICE_ID,               "Device Identifier = " },
    /*   37 */ { CL_OPTION_RFC868_SERVERS,          "Time Protocol Servers : " },
    /*   38 */ { CL_OPTION_TIME_OFFSET,             "Time Offset = " },
    /*   39 */ { CL_OPTION_IP_PREF,                 "IP preference : " },
    /*   61 */ { CL_OPTION_CCAP_CORES,              "CCAP-CORES : " },
    /* 1025 */ { CL_OPTION_DOCS_CMTS_CAP,           "CMTS Capabilities Option : " },
    /* 1026 */ { CL_CM_MAC_ADDR,                    "CM MAC Address Option = " },
    /* 1027 */ { CL_EROUTER_CONTAINER_OPTION,       "eRouter Container Option : " },
    /* 2170 */ { CL_OPTION_CCC,                     "CableLabs Client Configuration : " },
    /* 2171 */ { CL_OPTION_CCCV6,                   "CableLabs Client Configuration IPv6 : " },
    /* 2172 */ { CL_OPTION_CORRELATION_ID,          "CableLabs Correlation ID = " },
    { 0, NULL }
};
static value_string_ext cl_vendor_subopt_values_ext = VALUE_STRING_EXT_INIT(cl_vendor_subopt_values);

/* 17:2170: CL_OPTION_CCC */
#define PKT_CCC_PRI_DHCP       0x0001
#define PKT_CCC_SEC_DHCP       0x0002

static const value_string pkt_ccc_opt_vals[] = {
    { PKT_CCC_PRI_DHCP,      "TSP's Primary DHCP Server" },
    { PKT_CCC_SEC_DHCP,      "TSP's Secondary DHCP Server" },
    { 0, NULL },
};

/* 17:2171: CL_OPTION_CCCV6 */
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
static value_string_ext pkt_cccV6_opt_vals_ext = VALUE_STRING_EXT_INIT(pkt_cccV6_opt_vals);

static const value_string pkt_cccV6_prov_srv_type_vals[] = {
    { 0,      "FQDN" },
    { 1,      "IPv6" },
    { 0, NULL },
};

#if 0
static const value_string sec_tcm_vals[] = {
    { 1 << 0, "PacketCable Provisioning Server" },
    { 1 << 1, "PacketCable Call Manager Servers" },
    { 0, NULL },
};
#endif

static const value_string modem_capabilities_encoding [] = {
    {  1,     "Concatenation Support" },
    {  2,     "DOCSIS Version" },
    {  3,     "Fragmentation Support" },
    {  4,     "Payload Header Suppression Support" },
    {  5,     "IGMP Support" },
    {  6,     "Privacy Support" },
    {  7,     "Downstream SAID Support" },
    {  8,     "Upstream Service Flow Support" },
    {  9,     "Optional Filtering Support" },
    { 10,      "Transmit Pre-Equalizer Taps per Modulation Interval" },
    { 11,      "Number of Transmit Equalizer Taps" },
    { 12,      "DCC Support" },
    { 13,      "IP Filters Support" },
    { 14,      "LLC Filters Support" },
    { 15,      "Expanded Unicast SID Space" },
    { 16,      "Ranging Hold-Off Support" },
    { 17,      "L2VPN Capability" },
    { 18,      "L2VPN eSAFE Host Capability" },
    { 19,      "Downstream Unencrypted Traffic (DUT) Filtering" },
    { 20,      "Upstream Frequency Range Support" },
    { 21,      "Upstream Symbol Rate Support" },
    { 22,      "Selectable Active Code Mode 2 Support" },
    { 23,      "Code Hopping Mode 2 Support" },
    { 24,      "Multiple Transmit Channel Support" },
    { 25,      "5.12 Msps UpstreamTransmit Channel Support" },
    { 26,      "2.56 Msps Upstream Transmit Channel Support" },
    { 27,      "Total SID Cluster Support" },
    { 28,      "SID Clusters per Service Flow Support" },
    { 29,      "Multiple Receive Channel Support" },
    { 30,      "Total Downstream Service ID (DSID) Support" },
    { 31,      "Resequencing Downstream Service ID (DSID) Support" },
    { 32,      "Multicast Downstream Service ID (DSID) Support" },
    { 33,      "Multicast DSID Forwarding" },
    { 34,      "Frame Control Type Forwarding Capability" },
    { 35,      "DPV Capability" },
    { 36,      "Unsolicited Grant Service/Upstream Service Flow Support" },
    { 37,      "MAP and UCD Receipt Support" },
    { 38,      "Upstream Drop Classifier Support" },
    { 39,      "IPv6 Support" },
    { 40,      "Extended Upstream Transmit Power Capability" },
    { 41,      "Optional 802.1ad, 802.1ah, MPLS Classification Support" },
    { 42,      "D-ONU Capabilities Encoding" },
    { 43,      "Reserved" },
    { 44,      "Energy Management Capabilities" },
/* Added TLV5.45-62 from CL-SP-CANN-I18-180509 */
    { 45,      "C-DOCSIS Capability Encoding" },
    { 46,      "CM-STATUS-ACK" },
    { 47,      "Energy Management Preferences" },
    { 48,      "Extended Packet Length Support Capability" },
    { 49,      "Multiple Receive OFDM Channel Support" },
    { 50,      "Multiple Transmit OFDMA Channel Support" },
    { 51,      "Downstream OFDM Profile Support" },
    { 52,      "Downstream OFDM channel subcarrier QAM modulation support" },
    { 53,      "Upstream OFDM channel subcarrier QAM modulation support" },
    { 54,      "Downstream Lower Band Edge Support" },
    { 55,      "Downstream Upper Band Edge Support" },
    { 56,      "Upstream Upper Band Edge Support" },
    { 57,      "DOCSIS Time Protocol Support" },
    { 58,      "DOCSIS Time Protocol Performance Support" },
    { 59,      "Pmax" },
    { 60,      "Diplexer Downstream Lower Band Edge" },
    { 61,      "Diplexer Downstream Upper Band Edge" },
    { 62,      "Diplexer Upstream Upper Band Edge" },
    { 0, NULL },
};
static value_string_ext modem_capabilities_encoding_ext = VALUE_STRING_EXT_INIT(modem_capabilities_encoding);

static const value_string eue_capabilities_encoding [] = {
    {  1,      "PacketCable Version" },
    {  2,      "Number Of Telephony Endpoints" },
    {  3,      "TGT Support" },
    {  4,      "HTTP Download File Access Method Support" },
    {  5,      "MTA-24 Event SYSLOG Notification Support" },
    {  6,      "NCS Service Flow Support" },
    {  7,      "Primary Line Support" },
    {  8,      "Vendor Specific TLV Type(s)" },
    {  9,      "NVRAM Ticket/Ticket Information Storage Support" },
    { 10,      "Provisioning Event Reporting Support" },
    { 11,      "Supported CODEC(s)" },
    { 12,      "Silence Suppression Support" },
    { 13,      "Echo Cancellation Support" },
    { 14,      "RSVP Support" },
    { 15,      "UGS-AD Support" },
    { 16,      "MTA's \"ifIndex\" starting number in \"ifTable\"" },
    { 17,      "Provisioning Flow Logging Support" },
    { 18,      "Supported Provisioning Flows" },
    { 19,      "T38 Version Support" },
    { 20,      "T38 Error Correction Support" },
    { 21,      "RFC2833 DTMF Support" },
    { 22,      "Voice Metrics Support" },
    { 23,      "Device MIB Support" },
    { 24,      "Multiple Grants Per Interval Support" },
    { 25,      "V.152 Support" },
    { 26,      "Certificate Bootstrapping Support" },
    { 38,      "IP Address Provisioning Capability" },
    { 0, NULL },
};
static value_string_ext eue_capabilities_encoding_ext = VALUE_STRING_EXT_INIT(eue_capabilities_encoding);

static const value_string s46_opt_code_vals[] = {
    { 64,      "DS-Lite" },
    { 88,      "DHCPv4 over DHCPv6" },
    { 94,      "MAP-E" },
    { 95,      "MAP-T" },
    { 96,      "Lightweight 4over6" },
    { 0, NULL },
};

static const value_string failover_binding_status_vals[] = {
    { 0,       "reserved" },
    { 1,       "ACTIVE" },
    { 2,       "EXPIRED" },
    { 3,       "RELEASED" },
    { 4,       "PENDING-FREE" },
    { 5,       "FREE" },
    { 6,       "FREE-BACKUP" },
    { 7,       "ABANDONED" },
    { 8,       "RESET" },
    { 0, NULL },
};

static const value_string failover_server_state_vals[] = {
    {  0,      "reserved" },
    {  1,      "Startup state (1)" },
    {  2,      "Normal state" },
    {  3,      "Communications interrupted" },
    {  4,      "Partner down" },
    {  5,      "Synchronizing" },
    {  6,      "Recovering bindings from partner" },
    {  7,      "Waiting out MCLT after RECOVER" },
    {  8,      "Interlock state prior to NORMAL" },
    {  9,      "Comm. failed during resolution" },
    { 10,      "Primary resolved its conflicts" },
    { 0, NULL },
};

static int * const dhcpv6_failover_connect_flags_fields[] = {
    &hf_option_failover_connect_reserved_flag,
    &hf_option_failover_connect_f_flag,
    NULL
};

static int * const dhcpv6_failover_dns_flags_fields[] = {
    &hf_option_failover_dns_reserved_flag,
    &hf_option_failover_dns_u_flag,
    &hf_option_failover_dns_s_flag,
    &hf_option_failover_dns_r_flag,
    &hf_option_failover_dns_f_flag,
    NULL
};

static int * const dhcpv6_failover_server_flags_fields[] = {
    &hf_option_failover_server_reserved_flag,
    &hf_option_failover_server_a_flag,
    &hf_option_failover_server_s_flag,
    &hf_option_failover_server_c_flag,
    NULL
};

typedef struct hopcount_info_t {
    guint8     hopcount;
    proto_item *pi;
    gboolean   relay_message_previously_detected;
} hopcount_info;

static int * const dhcpv6_s46_rule_flags_fields[] = {
    &hf_option_s46_rule_reserved_flag,
    &hf_option_s46_rule_fmr_flag,
    NULL
};


static void
initialize_hopount_info(hopcount_info *hpi) {
  memset(hpi, 0, sizeof(hopcount_info));
}

static void
dissect_dhcpv6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               int off, int eoff, hopcount_info hpi);

static int
dissect_dhcpv6_s46_ipv6_prefix(tvbuff_t *tvb, int hf, int offset, int prefix_length, proto_tree *tree);


static int
dissect_packetcable_ccc_option(proto_tree *v_tree, proto_item *v_item, packet_info *pinfo, tvbuff_t *tvb, int optoff,
                               int optend)
{
    /** THE ENCODING OF THIS SUBOPTION HAS CHANGED FROM DHCPv4
        the code and length fields have grown from a single octet to
        two octets each. **/
    int         suboptoff = optoff;
    guint16     subopt, subopt_len;
    proto_item *vti;
    proto_tree *pkt_s_tree;

    subopt = tvb_get_ntohs(tvb, optoff);
    suboptoff += 2;

    subopt_len = tvb_get_ntohs(tvb, suboptoff);
    suboptoff += 2;

    /* There must be at least five octets left to be a valid sub element */
    if (optend <= 0) {
        expert_add_info_format(pinfo, v_item, &ei_dhcpv6_no_suboption_len, "Sub element %d: no room left in option for suboption length", subopt);
        return (suboptoff - optoff);
    }
    /* g_print("dissect packetcable ccc option subopt_len=%d optend=%d\n\n", subopt_len, optend); */

    vti = proto_tree_add_item(v_tree, hf_packetcable_ccc_suboption, tvb, optoff, 2, ENC_BIG_ENDIAN);
    pkt_s_tree = proto_item_add_subtree(vti, ett_dhcpv6_pkt_option);

    switch (subopt) {
    case PKT_CCC_PRI_DHCP:      /* IPv4 address values */
        if (subopt_len == 4) {
            proto_tree_add_item(pkt_s_tree, hf_packetcable_ccc_pri_dhcp, tvb, suboptoff, 4, ENC_BIG_ENDIAN);
        }
        else {
            expert_add_info_format(pinfo, vti, &ei_dhcpv6_bogus_length, "Bogus length: %d", subopt_len);
        }

        suboptoff += subopt_len;
        break;
    case PKT_CCC_SEC_DHCP:
        if (subopt_len == 4) {
            proto_tree_add_item(pkt_s_tree, hf_packetcable_ccc_sec_dhcp, tvb, suboptoff, 4, ENC_BIG_ENDIAN);
        }
        else {
            expert_add_info_format(pinfo, vti, &ei_dhcpv6_bogus_length, "Bogus length: %d", subopt_len);
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


/** Dissect one or more domain names within an option's domain name field and verify conformance
 *  with RFCs 8415, 3646, 4704, 2181, 1535, 1035, and 1034. Sufficiently detailed info is provided
 *  as to the cause of each error.
 *
 * TERMINOLOGY:
 * field          An option's domain name field containing from 0-n domain names (DNs)
 * DN             Decoded FQDN or a partial (relative) name.
 * label          A DNS-encoded name consisting of length octet followed by a name of that many
 *                octets. Bits 7 and 8 of the length octet are 0 thus the maximum length of a
 *                name is 63 octets.
 * root           "the null length of the root". An encoded root label only consists of its length,
 *                [0] and decoded as a dot. The trailing dot of an FQDN should not be confused with
 *                dots within a DN which are used to delineate its names.
 * TLD or tld     A Top Level Domain name consisting of *two* encoded labels: name and root.
 *                For example, [3org0] are decoded as [org.]
 * FQDN:          Fully Qualified Domain Name: A "complete" or "absolute" domain name that consists
 *                of *three* or more labels the last of which is root [0].
 * partial name   One or more labels *not* terminated by root. Partial names consisting of two or
 *                more names are referred to as "multi-part partially qualified Domain Names"
 *                [RFC 1535 pg 4.]. They are also called "relative" names. "Relative names are either
 *                taken relative to a well known origin, or to a list of domains used as a search
 *                list." [RFC 1034 3.1]. A partial name must be the only DN in the field.
 *
 * TODO: Revise DNS routines such as dissect_dns_query(), get_dns_name(), and expand_dns_name()
 *       (a.) to be aware of relative/partial names
 *       (b.) to detect protocol violations per keywords "MUST" "REQUIRED" and "SHALL"
 */
static void
dhcpv6_domain(proto_tree *subtree, proto_item *v_item _U_, packet_info *pinfo, int hfindex,
              tvbuff_t *tvb, int dn_field_off, guint16 dn_field_len)
{
    int      final_field_off;        /* Last offset of in DN field */
    guint8   label_len;
    int      remlen;                 /* The number of remaining octets in a domain field */
    guint8   num_labels;
    int      first_lab_off;          /* Offset of the first label of a DN */
    char     decoded_name_str[320];  /* Array used to construct an FQDN or partial name. Although 255
                                        is the max allowed FQDN length, the array is longer in order
                                        to accommodate FQDNs greater than 255 for display in error
                                        messages.  */
    int      dpos;                   /* Current position within decoded_name_str[] */
    int      offset;
    gboolean fqdn_seen, inc;
    proto_item *exi;
    proto_tree *ex_subtree;

    /* Empty domain name
     * [RFC 4704 4.2.] "A client MAY also leave the Domain Name field empty if it desires the server
     * to provide a name." If the domain field is empty, dn_field_len = 0; however, if the field only
     * contains a root label(0), it consumes one octet so in that case dn_field_len = 1.
     * See [RFC 1034 3.1] for details.
     */
    if (dn_field_len == 0) {
        proto_tree_add_uint_format(subtree, hf_empty_domain_name, tvb, dn_field_off-3, 2, dn_field_len,
            "Empty domain field: the client requests the server to provide a domain name");
        return;
    }
    offset              = dn_field_off;
    first_lab_off       = dn_field_off;
    final_field_off     = dn_field_off + dn_field_len - 1;
    remlen              = dn_field_len;
    num_labels          = 0;
    dpos                = 0;
    decoded_name_str[0] = '\0';
    fqdn_seen           = FALSE;
    inc                 = TRUE;

    /* Decode one label of an FQDN or partial domain name per iteration. [RFC 1034 3.1] "labels are
     * separated by dots ('.'). Since a complete domain name ends with the root label, this leads to
     * a printed form which ends in a dot."
     */
    while (remlen) {
        label_len = tvb_get_guint8(tvb, offset);
        if (label_len > 63) {
            /*
             * Bits 7 and 8 of the label length octet are zero, so the max length of a label is 63
             * octets. If greater, it is likely the first char of a non-DNS-encoded name.
             */
            exi = proto_tree_add_uint_format(subtree, hf_dhcpv6_non_dns_encoded_name, tvb,
                    offset, 1, label_len,
                    "Label Length: %u\n"
                    "This is not a DNS record encoded domain name. The value in the first octet of\n"
                    "a label is the length of the name that follows and must be 63 octets or less.\n"
                    "However, in this case it is %u which typically means the name is not DNS encoded.\n",
                    label_len, label_len);
            ex_subtree = proto_item_add_subtree(exi, ett_clientfqdn_expert);

            if (num_labels) {
                decoded_name_str[dpos] = '\0';
                proto_tree_add_string_format(ex_subtree, hf_dhcpv6_decoded_portion, tvb,
                    first_lab_off, dpos, decoded_name_str,
                    "The decoded portion of this FQDN to this point is [%s]\n", decoded_name_str);
            }
            proto_tree_add_expert(ex_subtree, pinfo, &ei_dhcpv6_non_dns_encoded_name, tvb, offset, 1);
            return;
        }

        if(!dpos)
            first_lab_off = offset;
        decoded_name_str[dpos] = '\0';
        offset++;
        remlen--;

        if (label_len > remlen) {
            /*
             * FQDN len exceeds domain field len.
             */
            col_append_str(pinfo->cinfo, COL_INFO, " [DOMAIN FIELD LEN EXCEEDED]");

            exi = proto_tree_add_uint_format(subtree, hf_dhcpv6_domain_field_len_exceeded, tvb,
                    offset-1, 1, label_len,
                    "ERROR: The length of this name, %u, exceeds the remaining length, %d, in the\n"
                    "domain name field.\n", label_len, remlen);
            ex_subtree = proto_item_add_subtree(exi, ett_clientfqdn_expert);

            if (num_labels) {
                decoded_name_str[dpos] = '\0';
                proto_tree_add_string_format(ex_subtree, hf_dhcpv6_decoded_portion, tvb,
                    first_lab_off, dpos, decoded_name_str,
                    "The successfully decoded portion of this FQDN: [%s]\n", decoded_name_str);
            }
            proto_tree_add_expert(ex_subtree, pinfo, &ei_dhcpv6_domain_field_len_exceeded, tvb,
                dn_field_off, dn_field_len);
            return;
        }

        if (dpos + label_len + 2 > 255) {
            /*
             * RFC 1034 Section 3.1: "To simplify implementations, the total number of octets that
             * represent a domain name (i.e., the sum of all label octets and label lengths) is
             * limited to 255."
             */
            col_append_str(pinfo->cinfo, COL_INFO, " [FQDN > 255]");
            /*
             * Since label_len is valid (<=63 and the name has not been truncated (i.e., its length
             * is <= remlen), display this oversized FQDN.
             */
            decoded_name_str[dpos] = '.';
            dpos++;
            tvb_memcpy(tvb, decoded_name_str + dpos, offset, label_len);
            offset += label_len;
            dpos   += label_len;
            if (tvb_get_guint8(tvb, offset) == 0) {
                decoded_name_str[dpos]   = '.';
                dpos++;
                offset++;
                inc = FALSE;
            }
            decoded_name_str[dpos] = '\0';
            exi = proto_tree_add_uint_format(subtree, hf_dhcpv6_encoded_fqdn_len_gt_255, tvb,
                      first_lab_off, dpos-1, dpos,
                "FQDN: %s%s\n"
                "ERROR: The total length of DNS-encoded names of this FQDN, %d, exceeds 255,\n"
                "the maximum allowed.", decoded_name_str, (inc ? "<incomplete>" : " "), dpos);
            ex_subtree = proto_item_add_subtree(exi, ett_clientfqdn_expert);
            proto_tree_add_expert(ex_subtree, pinfo, &ei_dhcpv6_encoded_fqdn_len_gt_255, tvb,
               first_lab_off, dpos-1);
            return;
        }

        if (label_len==0) {
            decoded_name_str[dpos] = '.';
            dpos++;
            decoded_name_str[dpos] = '\0';

            if (num_labels == 0) {
                /*
                 * This a standalone root label thus the client has request the resolver to return
                 * the IP address of root.
                 */
                col_append_str(pinfo->cinfo, COL_INFO, " [ROOT-ONLY DOMAIN NAME]");
                exi = proto_tree_add_string(subtree, hf_dhcpv6_root_only_domain_name, tvb,
                    offset-1, 1, "['.' (0)]");
                ex_subtree = proto_item_add_subtree(exi, ett_clientfqdn_expert);
                proto_tree_add_expert(ex_subtree, pinfo, &ei_dhcpv6_root_only_domain_name, tvb,
                    offset-1, 1);
                return;
            }
            else if (num_labels == 1) {
                /*
                 * TLDs consist of one DNS encoded label and a root label(0) (e.g., [com.] is
                 * encoded as [03 64 6F 6D 00]).
                 */
                exi = proto_tree_add_string_format(subtree, hf_dhcpv6_tld, tvb, first_lab_off, dpos+1,
                    decoded_name_str, "Top Level Domain name (TLD): %s", decoded_name_str);
                ex_subtree = proto_item_add_subtree(exi, ett_clientfqdn_expert);
                proto_tree_add_expert(ex_subtree, pinfo, &ei_dhcpv6_tld_lookup, tvb, first_lab_off, dpos+1);

                num_labels = 0;
                dpos = 0;
                fqdn_seen = TRUE;
                continue;   /* This was only a COMMENT/WARNING so continue */
            }

            /* This is a fully decoded FQDN. Add it to the tree with a trailing dot for root to
             * indicate that the domain name is in fact an FQDN and not a multi-part partially
             * qualified domain name.
             */
            proto_tree_add_string(subtree, hfindex, tvb, first_lab_off, dpos+1, decoded_name_str);
            num_labels = 0;
            dpos = 0;
            fqdn_seen = TRUE;
            continue;   /* Decode the next FQDN, if any */
        }
        /**************** End of label_len==0 (root) ****************/

        /* If a DN's last offset equals final_field_off, this marks the end of a partial name. Due
         * to the fact that they are root-terminated, only one partial name or 'multi-part partially
         * qualified domain name' is permitted per option field; otherwise, the labels of a
         * subsequent DN would be appended to it.
         *
         * If a client with a domain name suffix search list configured manually, via GPO, or
         * OPTION_DOMAIN_LIST response, appends each of the (rooted) list entries and queries the
         * DNS server for each. If a search list is unavailable, the client sends a partial name to
         * the server which will use its own search list. According to RFC 1535 Pg 4, "where a '.'
         * exists in a specified name it should be assumed to be a fully qualified domain name (FQDN)
         * and SHOULD be tried as a rooted name first." Some client implementations, most notably MS
         * Windows, do the opposite; the client issues several superfluous (silly-named) queries all
         * of which fail, followed by a successful rooted name query. See RFCs 1034 3.1 and 4704 4.2
         * for more info.
         */
        if (offset + label_len - 1 == final_field_off) {
            tvb_memcpy(tvb, decoded_name_str + dpos, first_lab_off + 1, label_len);
            dpos += label_len;
            decoded_name_str[dpos] = '\0';
            num_labels++;

            if (fqdn_seen) {
                /*
                 * An FQDN precedes this partial name. Partial names must be the only DN in the
                 * domain field.
                 */
                col_append_str(pinfo->cinfo, COL_INFO, " [PROTOCOL VIOLATION]");

                exi = proto_tree_add_string_format(subtree, hf_dhcpv6_partial_name_preceded_by_fqdn,
                        tvb, first_lab_off, label_len, decoded_name_str,
                        "Partial name: %s\n"
                        "ERROR: A single or multi-part partial name must be the only name in "
                        "the domain field", decoded_name_str);
                ex_subtree = proto_item_add_subtree(exi, ett_clientfqdn_expert);
                proto_tree_add_expert(ex_subtree, pinfo, &ei_dhcpv6_partial_name_preceded_by_fqdn,
                    tvb, first_lab_off, label_len);
                return;
            }

            /* A conformant partial name
             */
            if (num_labels==1) {
                proto_tree_add_string_format(subtree, hfindex, tvb, first_lab_off, dpos+1,
                    decoded_name_str, "Partial domain name: %s", decoded_name_str);
            }
            else {
                proto_tree_add_string_format(subtree, hfindex, tvb, first_lab_off, dpos+1,
                    decoded_name_str, "Multi-part partially qualified Domain Name: %s",
                    decoded_name_str);
            }
            return;
        }

        /* Add this name it to the array. Prepend it with a dot unless it's the first name of the DN.
         * Dots are only used to separate (delineate) the decoded names of a DN; however, an FQDN's
         * trailing root label (0) is decoded as a dot. This is handled above.
         */
        if (num_labels) {
            decoded_name_str[dpos] = '.';
            dpos++;
        }
        tvb_memcpy(tvb, decoded_name_str + dpos, offset, label_len);
        offset += label_len;
        remlen -= label_len;
        dpos   += label_len;
        decoded_name_str[dpos] = '\0';
        num_labels++;
    }
    /* End of while() loop */
}


static int
dissect_packetcable_cccV6_option(proto_tree *v_tree, proto_item *v_item, packet_info *pinfo, tvbuff_t *tvb, int optoff,
    int optend)
{
    int         suboptoff = optoff;
    guint16     subopt, subopt_len;
    guint8      type;
    proto_item *vti, *ti;
    proto_tree *pkt_s_tree;
    int         i;

    subopt = tvb_get_ntohs(tvb, optoff);
    suboptoff += 2;

    subopt_len = tvb_get_ntohs(tvb, suboptoff);
    suboptoff += 2;

    /* There must be at least five octets left to be a valid sub element */
    if (optend <= 0) {
        expert_add_info_format(pinfo, v_item, &ei_dhcpv6_no_suboption_len, "Sub element %d: no room left in option for suboption length", subopt);
        return (suboptoff - optoff);
    }

    vti = proto_tree_add_item(v_tree, hf_packetcable_cccV6_suboption, tvb, optoff, 2, ENC_BIG_ENDIAN);
    pkt_s_tree = proto_item_add_subtree(vti, ett_dhcpv6_pkt_option);

    switch (subopt) {
    case PKT_CCCV6_PRI_DSS:
        if (subopt_len < 35) {
            proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_pri_dss, tvb, suboptoff, subopt_len, ENC_ASCII|ENC_NA);
        } else {
            expert_add_info_format(pinfo, vti, &ei_dhcpv6_bogus_length, "Bogus length: %d", subopt_len);
        }
        suboptoff += subopt_len;
        break;
    case PKT_CCCV6_SEC_DSS:
        if (subopt_len < 35) {
            proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_sec_dss, tvb, suboptoff, subopt_len, ENC_ASCII|ENC_NA);
        } else {
            expert_add_info_format(pinfo, vti, &ei_dhcpv6_bogus_length, "Bogus length: %d", subopt_len);
        }
        suboptoff += subopt_len;
        break;
    case PKT_CCCV6_IETF_PROV_SRV:
        proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_prov_srv_type, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
        type = tvb_get_guint8(tvb, suboptoff);

        /** Type 0 is FQDN **/
        if (type == 0) {
            dhcpv6_domain(pkt_s_tree, vti, pinfo, hf_packetcable_cccV6_prov_srv_fqdn, tvb, suboptoff+1, subopt_len-1);

            /** Type 1 is IPv6 **/
        } else if (type == 1) {
            if ((subopt_len % 16) == 0) {
                for (i = 0; i < subopt_len/16; i++) {
                    proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_prov_srv_ipv6, tvb, suboptoff+1, 4, ENC_NA);
                    suboptoff += 16;
                }
            }
        } else {
            expert_add_info_format(pinfo, vti, &ei_dhcpv6_invalid_type, "Invalid type: %u (%u byte%s)",
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
            dhcpv6_domain(pkt_s_tree, vti, pinfo, hf_packetcable_cccV6_krb_realm, tvb, suboptoff, subopt_len);
        }
        suboptoff += subopt_len;
        break;
    case PKT_CCCV6_TGT_FLAG:
        if (subopt_len == 1) {
            proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_tgt_flag, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_tgt_flag_fetch, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
        }
        else {
            expert_add_info_format(pinfo, vti, &ei_dhcpv6_bogus_length, "Bogus length: %d", subopt_len);
        }
        suboptoff += subopt_len;
        break;
    case PKT_CCCV6_PROV_TIMER:
        if (subopt_len == 1) {
            ti = proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_prov_timer, tvb, suboptoff, 1, ENC_BIG_ENDIAN);
            if (tvb_get_guint8(tvb, suboptoff) > 30)
                expert_add_info(pinfo, ti, &ei_dhcpv6_invalid_time_value);
        }
        else {
            expert_add_info_format(pinfo, vti, &ei_dhcpv6_bogus_length, "Bogus length: %d", subopt_len);
        }
        suboptoff += subopt_len;
        break;
    case PKT_CCCV6_IETF_SEC_TKT:
        proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_sec_tcm, tvb, suboptoff, 2, ENC_BIG_ENDIAN);
        if (subopt_len == 2) {
            proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_sec_tcm_provisioning_server, tvb, suboptoff, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(pkt_s_tree, hf_packetcable_cccV6_sec_tcm_call_manager_server, tvb, suboptoff, 2, ENC_BIG_ENDIAN);
        } else {
            expert_add_info_format(pinfo, vti, &ei_dhcpv6_bogus_length, "Bogus length: %d", subopt_len);
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

/* ToDo: review latest CL docs for updates */
static void
dissect_cablelabs_specific_opts(proto_tree *v_tree, proto_item *v_item, packet_info *pinfo, tvbuff_t *tvb, int voff, int len)
{
    guint type,
          sub_value;
    proto_item *ti;
    proto_item *ti2;
    proto_tree *subtree;
    proto_tree *subtree2;
    int tlv5_cap_index,
        tlv5_counter,
        tlv5_cap_len;
    int off = voff,
        sub_off, /** The offset for the sub-option */
        i,
        tlv_len, /* holds the number of elements in the tlv */
        field_len, /* holds the length of one occurrence of a field */
        opt_len, /* holds the length of the suboption */
        field_value;
    gchar *device_type = NULL;

    if (len > 4) {
        while (off - voff < len) {

            /* Type */
            type = tvb_get_ntohs(tvb, off);
            ti = proto_tree_add_item(v_tree, hf_cablelabs_opts, tvb, off, 2, ENC_BIG_ENDIAN);
            /* Length */
            tlv_len = tvb_get_ntohs(tvb, off+2);

            /* Values */
            sub_off = off + 4;

            switch (type) {
                /* String types */
            case CL_OPTION_DEVICE_TYPE:
                opt_len = tlv_len;
                field_len = tlv_len;

                device_type = tvb_get_string_enc(wmem_packet_scope(), tvb, sub_off, field_len, ENC_ASCII);

                if ((device_type == NULL) || (strlen(device_type) == 0)) {
                    proto_item_append_text(ti, "Packet does not contain Device Type.");
                } else {
                    proto_item_append_text(ti, "\"%s\"", device_type);
                }
                break;
            case CL_OPTION_DEVICE_SERIAL_NUMBER:
            case CL_OPTION_HARDWARE_VERSION_NUMBER:
            case CL_OPTION_SOFTWARE_VERSION_NUMBER:
            case CL_OPTION_BOOT_ROM_VERSION:
            case CL_OPTION_MODEL_NUMBER:
            case CL_OPTION_VENDOR_NAME:
            case CL_OPTION_CONFIG_FILE_NAME:
            case CL_OPTION_EMBEDDED_COMPONENT_LIST:
                opt_len = tlv_len;
                field_len = tlv_len;
                proto_item_append_text(ti, "\"%s\"",
                                       tvb_format_stringzpad(tvb, sub_off, field_len));
                break;
            case CL_OPTION_VENDOR_OUI:
                /* CableLabs specs treat 17.8 inconsistently
                 * as either binary (3b) or string (6b) */
                opt_len = tlv_len;
                if (tlv_len == 3) {
                    proto_item_append_text(ti, "%s",
                        tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, sub_off, 3, ':'));
                } else if (tlv_len == 6) {
                    proto_item_append_text(ti, "\"%s\"", tvb_format_stringzpad(tvb, sub_off, tlv_len));
                } else {
                    expert_add_info_format(pinfo, ti, &ei_dhcpv6_bogus_length, "Suboption %d: suboption length isn't 3 or 6", type);
                }
                break;
            case CL_OPTION_ORO:
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
            case CL_OPTION_TFTP_SERVERS:
            case CL_OPTION_SYSLOG_SERVERS:
            case CL_OPTION_RFC868_SERVERS:
            case CL_OPTION_CCAP_CORES:
                field_len = 16;
                opt_len = tlv_len;
                subtree = proto_item_add_subtree(ti, ett_dhcpv6_vendor_option);

                if ((tlv_len % field_len) == 0) {
                    for (i = 0; i < tlv_len/field_len; i++) {
                        ti = proto_tree_add_item(subtree, hf_cablelabs_ipv6_server, tvb, sub_off, 16, ENC_NA);
                        proto_item_prepend_text(ti, " %d ", i + 1);
                        sub_off += field_len;
                    }
                }
                break;
            case CL_OPTION_DEVICE_ID:
                opt_len = tlv_len;
                field_len = tlv_len;
                if (tlv_len != 6) {
                    expert_add_info_format(pinfo, ti, &ei_dhcpv6_bogus_length, "Bogus length: %d", tlv_len);
                }
                else {
                    proto_item_append_text(ti, "%s",
                                           tvb_bytes_to_str(wmem_packet_scope(), tvb, sub_off, field_len));
                }
                break;
            case CL_OPTION_TLV5:
                /* ToDo: review latest CL docs for updates */
                opt_len = tlv_len;


                tlv5_counter = 0;
                tlv5_cap_index = sub_off;

                subtree = proto_item_add_subtree(ti, ett_dhcpv6_tlv5_type);

                while (tlv5_counter < tlv_len) {
                    /*Device type is not mandatory for CM (see par 10.2.5.2.3 "Obtain IPv6 Management Address and Other Configuration Parameters" in  CM-SP-MULPIv3.1-114-180130*/
                    if (device_type == NULL || !g_ascii_strncasecmp(device_type, "ecm", 3)) {
                        ti2 = proto_tree_add_item(subtree, hf_modem_capabilities_encoding_type, tvb, tlv5_cap_index, 1, ENC_BIG_ENDIAN);
                    } else if (!g_ascii_strncasecmp(device_type, "edva", 3)) {
                        ti2 = proto_tree_add_item(subtree, hf_eue_capabilities_encoding_type, tvb, tlv5_cap_index, 1, ENC_BIG_ENDIAN);
                    } else {
                        break;
                    }

                    tlv5_cap_index++;
                    tlv5_counter++;

                    /* Why make another subtree (subtree2) below?
                       The addition of a subtree is not needed for the display.
                       However, when parsing the PDML, each Type 'contains' it's Length and Value.
                    */
                    subtree2 = proto_item_add_subtree(ti2, ett_dhcpv6_tlv5_type);

                    proto_tree_add_item(subtree2, hf_capabilities_encoding_length, tvb, tlv5_cap_index, 1, ENC_BIG_ENDIAN);
                    tlv5_cap_len = (guint8) tvb_get_guint8(tvb, tlv5_cap_index);

                    tlv5_cap_index++;
                    tlv5_counter += tlv5_cap_len;

                    /* In cases where the TLV length is greater than 2, the value fields should be displayed
                       according to the encoding of the values as described in the CL-SP-CANN-DHCP-Reg specification.
                       Below, these values are simply displayed as hex.
                    */
                    if (tlv5_cap_len > 2) {
                            proto_tree_add_item(subtree2, hf_capabilities_encoding_bytes, tvb, tlv5_cap_index, tlv5_cap_len, ENC_NA);
                    } else {
                            proto_tree_add_item(subtree2, hf_capabilities_encoding_number, tvb, tlv5_cap_index, tlv5_cap_len, ENC_BIG_ENDIAN);
                    }

                    tlv5_cap_index += tlv5_cap_len;
                    tlv5_counter++;
                }
                break;
            case CL_OPTION_TIME_OFFSET:
                opt_len = tlv_len;
                proto_item_append_text(ti, "%d", tvb_get_ntohl(tvb, sub_off));
                break;
            case CL_OPTION_IP_PREF:
                opt_len = tlv_len;
                field_value = tvb_get_guint8(tvb, sub_off);
                if (field_value == 1) {
                    proto_item_append_text(ti, "%s", "IPv4");
                } else if (field_value == 2) {
                    proto_item_append_text(ti, "%s", "IPv6");
                } else if (field_value == 6) {
                    proto_item_append_text(ti, "%s", "Dual Stack");
                } else {
                    proto_item_append_text(ti, "%s%d", "Invalid IP Preference value ", field_value);
                }
                break;
            case CL_OPTION_DOCS_CMTS_CAP:
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
                        if ((tag == CL_OPTION_DOCS_CMTS_TLV_VERS_NUM) && (tagLen == 2)) {
                            proto_tree_add_item(subtree, hf_cablelabs_docsis_version_number, tvb, sub_off,
                                2, ENC_BIG_ENDIAN);
                            sub_off += 2;
                        }
                        else
                            sub_off += tagLen;

                        field_len += tagLen + 2;
                    }
                }
                else
                    proto_item_append_text(ti, " (empty)");
                break;
            case CL_CM_MAC_ADDR:
                opt_len = tlv_len;
                if (tlv_len != 6) {
                    expert_add_info_format(pinfo, ti, &ei_dhcpv6_bogus_length, "Bogus length: %d", tlv_len);
                }
                else {
                    /*proto_item_append_text(ti, "CM MAC Address Option = %s", */
                    proto_item_append_text(ti, "%s", tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, sub_off, opt_len, ':'));
                    /* tvb_bytes_to_str(wmem_packet_scope(), tvb, sub_off, opt_len)); */
                }
                break;
            case CL_EROUTER_CONTAINER_OPTION:
                opt_len = tlv_len;
                proto_item_append_text(ti, " %s (len=%d)",
                                       tvb_bytes_to_str(wmem_packet_scope(), tvb, sub_off, opt_len), tlv_len);
                break;
            case CL_OPTION_CCC:
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
            case CL_OPTION_CCCV6:
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
            case CL_OPTION_CORRELATION_ID:
                opt_len = tlv_len;
                 if (tlv_len != 4) {
                    proto_item_append_text(ti, "Bogus value length=%d",
                                           tlv_len);
                }
                else {
                    proto_item_append_text(ti, "%u", tvb_get_ntohl(tvb, sub_off));
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
        expert_add_info_format(pinfo, v_item, &ei_dhcpv6_bogus_length, "Bogus length: %d", len);
    }
}

static void
cablelabs_fmt_docsis_version( gchar *result, guint32 revision )
{
   g_snprintf( result, ITEM_LABEL_LENGTH, "%d.%02d", (guint8)(( revision & 0xFF00 ) >> 8), (guint8)(revision & 0xFF) );
}


/* Returns the number of bytes consumed by this option. */
static int
dhcpv6_option(tvbuff_t *tvb, packet_info *pinfo, proto_tree *bp_tree,
              int off, int eoff, gboolean *at_end, int protocol, hopcount_info hpi, guint8 msgtype)
{
    guint16     opttype, hwtype, subopt_type;
    int         temp_optlen, optlen, subopt_len; /* 16-bit values that need 16-bit rollover protection */
    proto_item *ti = NULL, *option_item;
    proto_tree *subtree;
    proto_tree *subtree_2;
    int         i;
    guint16     duidtype;
    guint32     enterprise_no;
    guint       algorithm;

    /* option type and length must be present */
    if ((eoff - off) < 4) {
        *at_end = TRUE;
        return 0;
    }

    opttype = tvb_get_ntohs(tvb, off);
    optlen  = tvb_get_ntohs(tvb, off + 2);

    /* all option data must be present */
    if ((eoff - off) < (4 + optlen)) {
        *at_end = TRUE;
        return 0;
    }

    /* Replace "Text item" option header with a filterable field which in turn eliminates the need
     * for the "Value:" raw data field. */
    option_item = proto_tree_add_string_format(bp_tree, hf_option_type_str, tvb, off, 4 + optlen,
                    val_to_str_ext(opttype, &opttype_vals_ext, "DHCP option %u"),
                    "%s", val_to_str_ext(opttype, &opttype_vals_ext, "DHCP option %u"));

    subtree = proto_item_add_subtree(option_item, ett_dhcpv6_option);

    proto_tree_add_item(subtree, hf_option_type_num, tvb, off, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_option_length, tvb, off + 2, 2, ENC_BIG_ENDIAN);
    off += 4;

    switch (opttype) {
    case OPTION_CLIENTID:
        col_append_fstr(pinfo->cinfo, COL_INFO, "CID: %s ", tvb_bytes_to_str(wmem_packet_scope(), tvb, off, optlen));
        /* Fall through */
    case OPTION_SERVERID:
    case OPTION_RELAYID:
        if (optlen < 2) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "DUID: malformed option");
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
                expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "DUID: malformed option");
                break;
            }
            proto_tree_add_item(subtree, hf_duidllt_hwtype, tvb, off + 2, 2, ENC_BIG_ENDIAN);

            /* Packet specifies seconds since Jan 1 2000, so add 946684800U (30 years) to get back to epoch */
            llt_time.secs = tvb_get_ntohl(tvb, off + 4) + 946684800U;
            llt_time.nsecs = 0;

            proto_tree_add_time(subtree, hf_duidllt_time, tvb, off + 4, 4, &llt_time);
            if (optlen > 8) {
                hwtype = tvb_get_ntohs(tvb, off + 2);
                proto_tree_add_string(subtree, hf_duidllt_link_layer_addr, tvb, off + 8,
                                    optlen - 8, tvb_arphrdaddr_to_str(tvb, off+8, optlen-8, hwtype));
            }
        }
        break;
        case DUID_EN:
            if (optlen < 6) {
                expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "DUID: malformed option");
                break;
            }
            proto_tree_add_item(subtree, hf_duiden_enterprise, tvb, off + 2, 4, ENC_BIG_ENDIAN);
            if (optlen > 6) {
                proto_tree_add_item(subtree, hf_duiden_identifier, tvb, off + 6, optlen - 6, ENC_NA);
            }
            break;
        case DUID_LL:
            if (optlen < 4) {
                expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "DUID: malformed option");
                break;
            }
            proto_tree_add_item(subtree, hf_duidll_hwtype, tvb, off + 2, 2, ENC_BIG_ENDIAN);
            if (optlen > 4) {
                hwtype = tvb_get_ntohs(tvb, off + 2);
                proto_tree_add_string(subtree, hf_duidll_link_layer_addr, tvb, off + 4,
                                    optlen - 4, tvb_arphrdaddr_to_str(tvb, off+4, optlen-4, hwtype));
            }
            break;
        case DUID_UUID:
            if (optlen != 18) {
                expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "DUID: malformed option");
                break;
            }
            proto_tree_add_item(subtree, hf_duiduuid_bytes, tvb, off + 2, 16, ENC_NA);
            break;
        }
        break;
    case OPTION_NTP_SERVER:
        if (optlen < 4) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "NTP Server: malformed option");
            break;
        }
        temp_optlen = 0;
        while (optlen > temp_optlen) {
            subopt_type = tvb_get_ntohs(tvb, off + temp_optlen);
            subopt_len = tvb_get_ntohs(tvb,  off + 2 + temp_optlen);
            if (subopt_len > optlen - temp_optlen) {
                expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "NFS Server: suboption too long");
                break;
            }
            subtree_2 = proto_tree_add_subtree(subtree, tvb, off+temp_optlen, 4 + subopt_len, ett_dhcpv6_netserver_option, &ti,
                                     val_to_str(subopt_type, ntp_server_opttype_vals, "NTP Server suboption %u"));
            proto_tree_add_item(subtree_2, hf_option_ntpserver_type,   tvb, off + temp_optlen,     2, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree_2, hf_option_ntpserver_length, tvb, off + temp_optlen + 2, 2, ENC_BIG_ENDIAN);
            temp_optlen += 4;
            switch (subopt_type) {
            case NTP_SUBOPTION_SRV_ADDR:
                proto_tree_add_item(subtree_2, hf_option_ntpserver_addr,    tvb, off + temp_optlen, 16, ENC_NA);
                break;
            case NTP_SUBOPTION_MC_ADDR:
                proto_tree_add_item(subtree_2, hf_option_ntpserver_mc_addr, tvb, off + temp_optlen, 16, ENC_NA);
                break;
            case NTP_SUBOPTION_SRV_FQDN:
                /* RFC 5906: section 4.3: "Internationalized domain names are not allowed ..." */
                dhcpv6_domain(subtree_2, ti, pinfo, hf_option_ntpserver_fqdn, tvb, off + temp_optlen, subopt_len);
                break;
            }

            temp_optlen += subopt_len;
        }
        break;
    case OPTION_S46_RULE:
    {
        guint8 ipv4_pref_len, ipv6_pref_len;
        int ipv6_pref_len_bytes;

        if (optlen < 8) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "S46_RULE: malformed option");
            break;
        }

        /*  0 1 2 3 4 5 6 7
         * +-+-+-+-+-+-+-+-+
         * |Reserved     |F|
         * +-+-+-+-+-+-+-+-+
         */
        proto_tree_add_bitmask(subtree, tvb, off, hf_option_s46_rule_flags, ett_dhcpv6_s46_rule_flags, dhcpv6_s46_rule_flags_fields, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_option_s46_rule_ea_len, tvb, off + 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_option_s46_rule_ipv4_pref_len, tvb, off + 2, 1, ENC_BIG_ENDIAN);
        ipv4_pref_len = tvb_get_guint8(tvb, off + 2);

        if (ipv4_pref_len > 32) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "S46_RULE: malformed option");
            break;
        }

        proto_tree_add_item(subtree, hf_option_s46_rule_ipv4_prefix, tvb, off + 3, 4, ENC_NA);
        proto_tree_add_item(subtree, hf_option_s46_rule_ipv6_pref_len, tvb, off + 7, 1, ENC_BIG_ENDIAN);
        ipv6_pref_len = tvb_get_guint8(tvb, off + 7);

        if (ipv6_pref_len > 128) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "S46_RULE: malformed option");
            break;
        }

        ipv6_pref_len_bytes =
            dissect_dhcpv6_s46_ipv6_prefix(tvb, hf_option_s46_rule_ipv6_prefix, off + 8, ipv6_pref_len, subtree);

        temp_optlen = 8 + ipv6_pref_len_bytes;
        while ((optlen - temp_optlen) > 0) {
            temp_optlen += dhcpv6_option(tvb, pinfo, subtree,
                                         off+temp_optlen, off + optlen, at_end, protocol, hpi, msgtype);
            if (*at_end) {
                /* Bad option - just skip to the end */
                temp_optlen = optlen;
            }
        }
    }
    break;
    case OPTION_S46_BR:
        if (optlen != 16) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "S46_BR: malformed option");
            break;
        }

        proto_tree_add_item(subtree, hf_option_s46_br_address, tvb, off, 16, ENC_NA);
        break;
    case OPTION_S46_DMR:
    {
        guint8 dmr_pref_len;

        if (optlen < 1 || optlen > 17) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "S46_DMR: malformed option");
            break;
        }

        proto_tree_add_item(subtree, hf_option_s46_dmr_pref_len, tvb, off, 1, ENC_BIG_ENDIAN);
        dmr_pref_len = tvb_get_guint8(tvb, off);

        if (dmr_pref_len > 128) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "S46_DMR: malformed option");
            break;
        }

        dissect_dhcpv6_s46_ipv6_prefix(tvb, hf_option_s46_dmr_prefix, off + 1, dmr_pref_len, subtree);
    }
    break;
    case OPTION_S46_V4V6BIND:
    {
        guint8 ipv6_pref_len;
        int ipv6_pref_len_bytes;

        if (optlen < 5) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "S46_V4V6BIND: malformed option");
            break;
        }

        proto_tree_add_item(subtree, hf_option_s46_v4v6bind_ipv4_address, tvb, off, 4, ENC_NA);
        proto_tree_add_item(subtree, hf_option_s46_v4v6bind_ipv6_pref_len, tvb, off + 4, 1, ENC_BIG_ENDIAN);
        ipv6_pref_len = tvb_get_guint8(tvb, off + 4);

        if (ipv6_pref_len > 128) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "S46_V4V6BIND: malformed option");
            break;
        }

        ipv6_pref_len_bytes =
            dissect_dhcpv6_s46_ipv6_prefix(tvb, hf_option_s46_v4v6bind_ipv6_prefix, off + 5, ipv6_pref_len, subtree);

        temp_optlen = 5 + ipv6_pref_len_bytes;
        while ((optlen - temp_optlen) > 0) {
            temp_optlen += dhcpv6_option(tvb, pinfo, subtree,
                                         off+temp_optlen, off + optlen, at_end, protocol, hpi, msgtype);
            if (*at_end) {
                /* Bad option - just skip to the end */
                temp_optlen = optlen;
            }
        }
    }
    break;
    case OPTION_S46_PORTPARAMS:
    {
        guint16 psid;
        guint8 offset, psid_len;

        if (optlen != 4) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "S46_PORTPARAMS: malformed option");
            break;
        }

        proto_tree_add_item(subtree, hf_option_s46_portparam_offset, tvb, off, 1, ENC_BIG_ENDIAN);
        offset = tvb_get_guint8(tvb, off);

        if (offset > 15) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "S46_PORTPARAMS: malformed option");
            break;
        }

        proto_tree_add_item(subtree, hf_option_s46_portparam_psid_len, tvb, off + 1, 1, ENC_BIG_ENDIAN);
        psid_len = tvb_get_guint8(tvb, off + 1);

        if (psid_len > 16) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "S46_PORTPARAMS: malformed option");
            break;
        }

        psid = tvb_get_ntohs(tvb, off + 2);
        proto_tree_add_uint(subtree, hf_option_s46_portparam_psid, tvb, off + 2, 2, psid >> (16 - psid_len));
    }
    break;
    case OPTION_S46_CONT_MAPE:
    case OPTION_S46_CONT_MAPT:
    case OPTION_S46_CONT_LW:
        temp_optlen = 0;
        while ((optlen - temp_optlen) > 0) {
            temp_optlen += dhcpv6_option(tvb, pinfo, subtree,
                                         off+temp_optlen, off + optlen, at_end, protocol, hpi, msgtype);
            if (*at_end) {
                /* Bad option - just skip to the end */
                temp_optlen = optlen;
            }
        }
        break;
    case OPTION_IA_NA:
    case OPTION_IA_PD:
        if (optlen < 12) {
            if (opttype == OPTION_IA_NA)
                expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "IA_NA: malformed option");
            else
                expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "IA_PD: malformed option");
            break;
        }
        proto_tree_add_string(subtree, hf_iaid, tvb, off,
                                    4, tvb_arphrdaddr_to_str(tvb, off, 4, opttype));  /* XXX: IAID is opaque ? review ... */
        if (tvb_get_ntohl(tvb, off+4) == DHCPV6_LEASEDURATION_INFINITY) {
            proto_tree_add_uint_format_value(subtree, hf_iaid_t1, tvb, off+4,
                                    4, DHCPV6_LEASEDURATION_INFINITY, "infinity");
        } else {
            proto_tree_add_item(subtree, hf_iaid_t1, tvb, off+4,
                                    4, ENC_BIG_ENDIAN);
        }

        if (tvb_get_ntohl(tvb, off+8) == DHCPV6_LEASEDURATION_INFINITY) {
            proto_tree_add_uint_format_value(subtree, hf_iaid_t2, tvb, off+8,
                                    4, DHCPV6_LEASEDURATION_INFINITY, "infinity");
        } else {
            proto_tree_add_item(subtree, hf_iaid_t2, tvb, off+8,
                                    4, ENC_BIG_ENDIAN);
        }

        temp_optlen = 12;
        while ((optlen - temp_optlen) > 0) {
            temp_optlen += dhcpv6_option(tvb, pinfo, subtree,
                                         off+temp_optlen, off + optlen, at_end, protocol, hpi, msgtype);
            if (*at_end) {
                /* Bad option - just skip to the end */
                temp_optlen = optlen;
            }
        }
        break;
    case OPTION_IA_TA:
        if (optlen < 4) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "IA_TA: malformed option");
            break;
        }
        proto_tree_add_string(subtree, hf_iata, tvb, off,
                                    4, tvb_arphrdaddr_to_str(tvb, off, 4, opttype));  /* XXX: IAID is opaque ? review ... */
        temp_optlen = 4;
        while ((optlen - temp_optlen) > 0) {
            temp_optlen += dhcpv6_option(tvb, pinfo, subtree,
                                         off+temp_optlen, off + optlen, at_end, protocol, hpi, msgtype);
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
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "IA_TA: malformed option");
            break;
        }

        proto_tree_add_item(subtree, hf_iaaddr_ip, tvb, off, 16, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, "IAA: %s ", tvb_ip6_to_str(tvb, off));

        preferred_lifetime = tvb_get_ntohl(tvb, off + 16);
        valid_lifetime = tvb_get_ntohl(tvb, off + 20);

        if (preferred_lifetime == DHCPV6_LEASEDURATION_INFINITY) {
            proto_tree_add_uint_format_value(subtree, hf_iaaddr_pref_lifetime, tvb, off+16,
                                    4, DHCPV6_LEASEDURATION_INFINITY, "infinity");
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
            temp_optlen += dhcpv6_option(tvb, pinfo, subtree,
                                         off+temp_optlen, off + optlen, at_end, protocol, hpi, msgtype);
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
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "PREFERENCE: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_option_preference, tvb, off, 1, ENC_BIG_ENDIAN);
        break;
    case OPTION_ELAPSED_TIME:
        if (optlen != 2) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "ELAPSED-TIME: malformed option");
            break;
        }

        temp_optlen = tvb_get_ntohs(tvb, off);
        proto_tree_add_uint(subtree, hf_elapsed_time, tvb, off, 2, temp_optlen*10);
        break;
    case OPTION_RELAY_MSG:
        if (optlen == 0) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "RELAY-MSG: malformed option");
        } else {
            /* here, we should dissect a full DHCP message */
            dissect_dhcpv6(tvb, pinfo, subtree, off, off + optlen, hpi);
        }
        break;
    case OPTION_AUTH:
        if (optlen < 11) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "AUTH: malformed option");
            break;
        }

        proto_tree_add_item(subtree, hf_auth_protocol, tvb, off, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item_ret_uint(subtree, hf_auth_algorithm, tvb, off+1, 1, ENC_BIG_ENDIAN, &algorithm);
        proto_tree_add_item(subtree, hf_auth_rdm, tvb, off+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_auth_replay_detection, tvb, off+3, 8, ENC_NA);
        if (optlen > 11+20 && algorithm == 1) {  // RFC 3315, HMAC-MD5 (16) + Key ID (4) => 20 bytes
            if (optlen-11-20 < 256) {
                proto_tree_add_item(subtree, hf_auth_realm, tvb, off+11, optlen-11-20, ENC_ASCII|ENC_NA);
            } else {
                expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "DHCP realm: probably malformed option");
            }
            proto_tree_add_item(subtree, hf_auth_key_id, tvb, off+optlen-16-4, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(subtree, hf_auth_md5_data, tvb, off+optlen-16, 16, ENC_NA);
        } else {
            proto_tree_add_item(subtree, hf_auth_info, tvb, off+11, optlen-11, ENC_NA);
        }
        break;
    case OPTION_UNICAST:
        if (optlen != 16) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "UNICAST: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_opt_unicast, tvb, off, 16, ENC_NA);
        break;
    case OPTION_STATUS_CODE:
        proto_tree_add_item(subtree, hf_opt_status_code, tvb, off, 2, ENC_BIG_ENDIAN);
        if (optlen > 2)
            proto_tree_add_item(subtree, hf_opt_status_msg, tvb, off+2, optlen - 2, ENC_ASCII|ENC_NA);
        break;
    case OPTION_VENDOR_CLASS:
        if (optlen < 4) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "VENDOR_CLASS: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_vendorclass_enterprise, tvb, off, 4, ENC_BIG_ENDIAN);
        if (optlen > 4)
            proto_tree_add_item(subtree, hf_vendorclass_data, tvb, off+6, optlen-6, ENC_ASCII|ENC_NA);
        break;
    case OPTION_VENDOR_OPTS:
        if (optlen < 4) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "VENDOR_OPTS: malformed option");
            break;
        }

        enterprise_no = tvb_get_ntohl(tvb, off);
        ti = proto_tree_add_item(subtree, hf_vendoropts_enterprise, tvb, off, 4, ENC_BIG_ENDIAN);

        if (enterprise_no == 4491) {
            dissect_cablelabs_specific_opts(subtree, ti, pinfo, tvb, off+4, optlen-4);
        } else {
            int optoffset = 0;

            while ((optlen - 4 - optoffset) > 0) {
                int olen = tvb_get_ntohs(tvb, off + optoffset + 6);
                subtree_2 = proto_tree_add_subtree(subtree, tvb, off + optoffset + 4,
                                         4 + olen, ett_dhcpv6_option_vsoption, NULL, "option");
                proto_tree_add_item(subtree_2, hf_vendoropts_enterprise_option_code, tvb, off + optoffset + 4, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree_2, hf_vendoropts_enterprise_option_length, tvb, off + optoffset + 6, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree_2, hf_vendoropts_enterprise_option_data, tvb, off + optoffset + 8, olen, ENC_NA);
                optoffset += (4 + olen);
            }
        }
        break;
    case OPTION_INTERFACE_ID:
    {
        if (optlen == 0) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "INTERFACE_ID: malformed option");
            break;
        }

        if (cablelabs_interface_id) {
            gint namelen = tvb_strnlen(tvb, off, optlen)+1;
            if (namelen == 0) {
                proto_tree_add_item(subtree, hf_cablelabs_interface_id, tvb, off, optlen, ENC_ASCII|ENC_NA);
            } else {
                proto_tree_add_item(subtree, hf_cablelabs_interface_id, tvb, off, namelen-1, ENC_ASCII|ENC_NA);

                temp_optlen = optlen - namelen;
                off += namelen;
                if (temp_optlen >= 6)
                    proto_tree_add_string(subtree, hf_cablelabs_interface_id_link_address, tvb, off, temp_optlen, tvb_arphrdaddr_to_str(tvb, off, 6, ARPHRD_ETHER));
            }
        } else {
            proto_tree_add_item(subtree, hf_interface_id, tvb, off, optlen, ENC_NA);
        }
    }
    break;
    case OPTION_RECONF_MSG:
        if (optlen != 1) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "RECONF_MSG: malformed option");
            break;
        }

        proto_tree_add_item(subtree, hf_reconf_msg, tvb, off, 1, ENC_BIG_ENDIAN);
        break;
    case OPTION_RECONF_ACCEPT:
        if (optlen)
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "RECONF_ACCEPT: malformed option");
        break;
    case OPTION_SIP_SERVER_D:
        if (optlen > 0) {
            subtree_2 = proto_tree_add_subtree(subtree, tvb, off, optlen, ett_dhcpv6_sip_server_domain_search_list_option, &ti, "SIP Servers Domain Search List");
            dhcpv6_domain(subtree_2, ti, pinfo, hf_sip_server_domain_search_fqdn, tvb, off, optlen);
        }
        break;
    case OPTION_SIP_SERVER_A:
        if (optlen % 16) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "SIP servers address: malformed option");
            break;
        }

        for (i = 0; i < optlen; i += 16)
            proto_tree_add_item(subtree, hf_sip_server_a, tvb, off + i, 16, ENC_NA);
        break;
    case OPTION_DNS_SERVERS:
        if (optlen % 16) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "DNS servers address: malformed option");
            break;
        }

        for (i = 0; i < optlen; i += 16) {
            ti = proto_tree_add_item(subtree, hf_dns_servers, tvb, off + i, 16, ENC_NA);
            proto_item_prepend_text(ti, " %d ", i/16 + 1);
        }
        break;

    case OPTION_DOMAIN_LIST:
        if (optlen > 0) {
            subtree_2 = proto_tree_add_subtree(subtree, tvb, off, optlen, ett_dhcpv6_dns_domain_search_list_option, &ti,
                            "Domain name suffix search list");
            dhcpv6_domain(subtree_2, ti, pinfo, hf_domain_search_list_entry, tvb, off, optlen);
        }
        break;

    /* NIS...: RFC 3898 */
    case OPTION_NIS_SERVERS:
        if (optlen % 16) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "NIS servers address: malformed option");
            break;
        }
        for (i = 0; i < optlen; i += 16)
            proto_tree_add_item(subtree, hf_nis_servers, tvb, off + i, 16, ENC_NA);
        break;
    case OPTION_NISP_SERVERS:
        if (optlen % 16) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "NISP servers address: malformed option");
            break;
        }
        for (i = 0; i < optlen; i += 16)
            proto_tree_add_item(subtree, hf_nisp_servers, tvb, off + i, 16, ENC_NA);
        break;
    case OPTION_NIS_DOMAIN_NAME:
        if (optlen > 0) {
            subtree_2 = proto_tree_add_subtree(subtree, tvb, off, optlen, ett_dhcpv6_nis_domain_name_option, &ti, "nis-domain-name");
            dhcpv6_domain(subtree_2, ti, pinfo, hf_nis_fqdn, tvb, off, optlen);
        }
        break;
    case OPTION_NISP_DOMAIN_NAME:
        if (optlen > 0) {
            subtree_2 = proto_tree_add_subtree(subtree, tvb, off, optlen, ett_dhcpv6_nisp_domain_name_option, &ti, "nisp-domain-name");
            dhcpv6_domain(subtree_2, ti, pinfo, hf_nisp_fqdn, tvb, off, optlen);
        }
        break;

    case OPTION_SNTP_SERVERS:
        /* Deprecated as of RFC 5908 */
        if (optlen % 16) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "SNTP servers address: malformed option");
            break;
        }
        for (i = 0; i < optlen; i += 16){
            ti = proto_tree_add_item(subtree, hf_sntp_servers, tvb, off + i, 16, ENC_NA);
            proto_item_prepend_text(ti, " %d ", i/16 + 1);
        }
        break;
    case OPTION_LIFETIME:
        if (optlen != 4) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "LIFETIME: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_opt_lifetime, tvb, off, 4, ENC_BIG_ENDIAN);
        break;

    /* BCMCS...: RFC 4280 */
    case OPTION_BCMCS_SERVER_D:
        if (optlen > 0) {
            subtree_2 = proto_tree_add_subtree(subtree, tvb, off, optlen, ett_dhcpv6_bcmcs_servers_domain_search_list_option, &ti, "BCMCS Servers Domain Search List");
            dhcpv6_domain(subtree_2, ti, pinfo, hf_bcmcs_servers_fqdn, tvb, off, optlen);
        }
        break;
    case OPTION_BCMCS_SERVER_A:
        if (optlen % 16) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "BCMCS servers address: malformed option");
            break;
        }
        for (i = 0; i < optlen; i += 16)
            proto_tree_add_item(subtree, hf_bcmcs_servers_a, tvb, off + i, 16, ENC_NA);
        break;

    case OPTION_REMOTE_ID:
        if (optlen < 4) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "REMOTE_ID: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_remoteid_enterprise, tvb, off, 4, ENC_BIG_ENDIAN);
        off += 4;
        proto_tree_add_item(subtree, hf_remoteid_enterprise_id, tvb, off, optlen - 4, ENC_NA);
        break;
    case OPTION_SUBSCRIBER_ID:
        if (optlen == 0) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "SUBSCRIBER_ID: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_subscriber_id, tvb, off, optlen, ENC_ASCII|ENC_NA);
        break;
    case OPTION_CLIENT_FQDN:
        if (optlen < 1) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "FQDN: malformed option");
        } else {
            guint8      flags;
            proto_item *fi = NULL;
            proto_tree *flags_tree = NULL;
            char       *flags_str, *suffix;
            gboolean    is_client;
            proto_item *exi;
            proto_tree *ex_subtree;

            /*
             * A client MUST only include the OPTION_CLIENT_FQDN in SOLICIT, REQUEST, RENEW, or REBIND messages.
             * [RFC 4704 Section 5.]
             * Servers MUST only include a OPTION_CLIENT_FQDN in ADVERTISE and REPLY messages.
             * [RFC 4704 Section 6.]
             */
            if (msgtype == SOLICIT || msgtype == REQUEST || msgtype == RENEW || msgtype == REBIND)
                is_client = TRUE;
            else if (msgtype == ADVERTISE || msgtype == REPLY)
                is_client = FALSE;
            else {
                exi = proto_tree_add_uint_format(subtree, hf_clientfqdn_bad_msgtype, tvb, off-4, 1,
                        msgtype,
                        "Only the following message types are permitted to use OPTION_CLIENT_FQDN:\n"
                        "SOLICIT, REQUEST, RENEW, REBIND, ADVERTISE, and REPLY");
                ex_subtree = proto_item_add_subtree(exi, ett_clientfqdn_expert);
                proto_tree_add_expert(ex_subtree, pinfo, &ei_dhcpv6_clientfqdn_bad_msgtype, tvb, off-4, 1);
                break;
            }
            /*
             * +-----+-+-+-+
             * | MBZ |N|O|S|
             * +-----+-+-+-+
             *
             * [RFC4704 Section 4.1]
             * "The 'S' bit indicates whether the server SHOULD or SHOULD NOT perform the AAAA RR (FQDN-to-address)
             * DNS updates. A client sets the bit to 0 to indicate that the server SHOULD NOT perform the updates
             * and 1 to indicate that the server SHOULD perform the updates. The state of the bit in the reply from
             * the server indicates the action to be taken by the server; if it is 1 the server has taken
             * responsibility for AAAA RR updates for the FQDN.
             *
             * The 'O' bit indicates whether the server has overridden the client's preference for the 'S' bit.
             * A client MUST set this bit to 0. A server MUST set this bit to 1 if the "S" bit in its reply to the
             * client does not match the 'S' bit received from the client.
             *
             * The 'N' bit indicates whether the server SHOULD NOT perform any DNS updates. A client sets this bit to
             * 0 to request that the server SHOULD perform updates (the PTR RR and possibly the AAAA RR based on the
             * 'S' bit) 1 to request that the server SHOULD NOT perform any DNS updates. A server sets the 'N' bit to
             * indicate whether the server SHALL (0) or SHALL NOT (1) perform DNS updates. If the 'N' bit is 1, the
             * 'S' bit MUST be 0."
             */
            flags = tvb_get_guint8(tvb, off);
            suffix = "]";

            if (is_client) {
                /*CLIENT*/
                if ((flags & 0x5)==0) flags_str = "[CLIENT wants to update its AAAA RRs and SERVER to update its PTR RRs";
                if ((flags & 0x5)==1) flags_str = "[CLIENT wants SERVER to update both its AAAA and PTR RRs";
                if ((flags & 0x5)==4) flags_str = "[CLIENT prefers that the server not perform *any* DNS updates";
                if ((flags & 0x5)==5) flags_str = "[ERROR: CLIENT prefers that the server not perform *any* DNS updates\n"
                                                  "        In which case the 'S' bit MUST be 0";
                /* The client MUST set this bit to 0 (in that it is meaningless). */
            }
            else {
                /*SERVER*/
                if ((flags & 0x5)==0) flags_str = "[CLIENT SHALL update AAAA RRs; SERVER SHALL update PTR RRs";
                if ((flags & 0x5)==1) flags_str = "[SERVER SHALL update both AAAA and PTR RRs";
                if ((flags & 0x5)==4) flags_str = "[CLIENT SHALL update AAAA RRs; SERVER SHALL NOT perform any DNS updates";
                if ((flags & 0x5)==5) flags_str = "[ERROR: SERVER SHALL NOT perform *any* DNS updates in which case "
                                                  "        the 'S' bit MUST be 0";
                if ((flags & 0x2)==2
                && ((flags & 0x5)==0 || (flags & 0x5)==1))
                    suffix = "]\n[Server has overridden the client's S bit]";
            }
            fi = proto_tree_add_uint_format(subtree, hf_clientfqdn_flags, tvb, off, 1, flags,
                    "Flags: 0x%02x  %s%s", flags, flags_str, suffix);
            flags_tree = proto_item_add_subtree(fi, ett_clientfqdn_flags);

        if (is_client) {
                proto_tree_add_item(flags_tree, hf_clientfqdn_client_n, tvb, off, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flags_tree, hf_clientfqdn_client_s, tvb, off, 1, ENC_BIG_ENDIAN);
            }
            else {
                proto_tree_add_item(flags_tree, hf_clientfqdn_server_n, tvb, off, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flags_tree, hf_clientfqdn_server_o, tvb, off, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flags_tree, hf_clientfqdn_server_s, tvb, off, 1, ENC_BIG_ENDIAN);
            }
            if ((flags & 0x5)==5)
                proto_tree_add_expert(subtree, pinfo, &ei_dhcpv6_s_bit_should_be_zero, tvb, off, 1);

            dhcpv6_domain(subtree, option_item, pinfo, hf_client_fqdn, tvb, off+1, optlen-1);
        }
        break;
    case OPTION_PANA_AGENT:
        if (optlen % 16) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "PANA agent address: malformed option");
            break;
        }
        for (i = 0; i < optlen; i += 16)
            proto_tree_add_item(subtree, hf_pana_agent, tvb, off + i, 16, ENC_NA);
        break;
    case OPTION_TIME_ZONE:
        if (optlen > 0)
            proto_tree_add_item(subtree, hf_opt_timezone, tvb, off, optlen, ENC_ASCII|ENC_NA);
        break;
    case OPTION_TZDB:
        if (optlen > 0)
            proto_tree_add_item(subtree, hf_opt_tzdb, tvb, off, optlen, ENC_ASCII|ENC_NA);
        break;

    case OPTION_MUDURL:
        if (optlen > 0)
            proto_tree_add_item(subtree, hf_opt_mudurl, tvb, off, optlen, ENC_ASCII|ENC_NA);
        break;

    case OPTION_LQ_QUERY:
    {
        guint8 query_type;
        if (optlen < 17) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "LQ-QUERY: malformed option");
            break;
        }
        query_type = tvb_get_guint8(tvb, off);
        ti = proto_tree_add_item(subtree, hf_lq_query, tvb, off, 1, ENC_BIG_ENDIAN);
        if ((protocol == proto_dhcpv6)           &&
            ((query_type == LQ_QUERY_RELAYID)      ||
             (query_type == LQ_QUERY_LINK_ADDRESS) ||
             (query_type == LQ_QUERY_REMOTEID))) {
            expert_add_info(pinfo, ti, &ei_dhcpv6_bulk_leasequery_bad_query_type);
        }

        proto_tree_add_item(subtree, hf_lq_query_link_address, tvb, off+1, 16, ENC_NA);
        temp_optlen = 17;
        while ((optlen - temp_optlen) > 0) {
            temp_optlen += dhcpv6_option(tvb, pinfo, subtree,
                                         off + temp_optlen,
                                         off + optlen, at_end, protocol, hpi, msgtype);
            if (*at_end) {
                /* Bad option - just skip to the end */
                temp_optlen = optlen;
            }
        }
    }
    break;
    case OPTION_CLIENT_DATA:
        temp_optlen = 0;
        while ((optlen - temp_optlen) > 0) {
            temp_optlen += dhcpv6_option(tvb, pinfo, subtree,
                                         off + temp_optlen,
                                         off + optlen, at_end, protocol, hpi, msgtype);
            if (*at_end) {
                /* Bad option - just skip to the end */
                temp_optlen = optlen;
            }
        }
        break;
    case OPTION_CLT_TIME:
        if (optlen != 4) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "CLT_TIME: malformed option");
            break;
        }

        proto_tree_add_item(subtree, hf_clt_time, tvb, off, 4, ENC_BIG_ENDIAN);
        break;
    case OPTION_LQ_RELAY_DATA:
        if (optlen < 16) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "LQ_RELAY_DATA: malformed option");
            break;
        }

        proto_tree_add_item(subtree, hf_lq_relay_data_peer_addr, tvb, off, 16, ENC_NA);
        proto_tree_add_item(subtree, hf_lq_relay_data_msg, tvb, off+16, optlen - 16, ENC_ASCII|ENC_NA);
        break;
    case OPTION_LQ_CLIENT_LINK:
        if (optlen % 16) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "LQ client links address: malformed option");
            break;
        }
        for (i = 0; i < optlen; i += 16)
            proto_tree_add_item(subtree, hf_lq_client_link, tvb, off + i, 16, ENC_NA);
        break;
    case OPTION_CAPWAP_AC_V6:
        if (optlen % 16) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "CAPWAP Access Controllers address: malformed option");
            break;
        }
        for (i = 0; i < optlen; i += 16)
            proto_tree_add_item(subtree, hf_capwap_ac_v6, tvb, off + i, 16, ENC_NA);
        break;

    case OPTION_AFTR_NAME:
        dhcpv6_domain(subtree, option_item, pinfo, hf_aftr_name, tvb, off, optlen);
        break;
    case OPTION_IAPREFIX:
        if (optlen < 25) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "IAPREFIX: malformed option");
            break;
        }

        if (tvb_get_ntohl(tvb, off) == DHCPV6_LEASEDURATION_INFINITY) {
            proto_tree_add_uint_format_value(subtree, hf_iaprefix_pref_lifetime, tvb, off,
                                    4, DHCPV6_LEASEDURATION_INFINITY, "infinity");
        } else {
            proto_tree_add_item(subtree, hf_iaprefix_pref_lifetime, tvb, off,
                                    4, ENC_BIG_ENDIAN);
        }
        if (tvb_get_ntohl(tvb, off + 4) == DHCPV6_LEASEDURATION_INFINITY) {
            proto_tree_add_uint_format_value(subtree, hf_iaprefix_valid_lifetime, tvb, off+4,
                                    4, DHCPV6_LEASEDURATION_INFINITY, "infinity");
        } else {
            proto_tree_add_item(subtree, hf_iaprefix_valid_lifetime, tvb, off+4,
                                    4, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(subtree, hf_iaprefix_pref_len, tvb, off+8, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_iaprefix_pref_addr, tvb, off+9, 16, ENC_NA);
        temp_optlen = 25;
        while ((optlen - temp_optlen) > 0) {
            temp_optlen += dhcpv6_option(tvb, pinfo, subtree,
                                         off+temp_optlen, off + optlen, at_end, protocol, hpi, msgtype);
            if (*at_end) {
                /* Bad option - just skip to the end */
                temp_optlen = optlen;
            }
        }
        break;
    case OPTION_MIP6_HA:
        if (optlen != 16) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "MIP6_HA: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_mip6_ha, tvb, off, 16, ENC_NA);
        break;
    case OPTION_MIP6_HOA:
        if (optlen != 16) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "MIP6_HOA: malformed option");
            break;
        }

        proto_tree_add_item(subtree, hf_mip6_hoa, tvb, off, 16, ENC_NA);
        break;
    case OPTION_NAI:
        if (optlen < 4) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "NAI: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_nai, tvb, off, optlen - 2, ENC_ASCII|ENC_NA);
        break;
    case OPTION_PD_EXCLUDE:
        if ((optlen < 2) || (optlen > 17)) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "PD_EXCLUDE: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_pd_exclude_pref_len, tvb, off, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_pd_exclude_subnet_id , tvb, off+1, optlen-1, ENC_NA);
        break;
    case OPTION_CAPTIVE_PORTAL:{
        proto_item *ti_cp;
        ti_cp = proto_tree_add_item(subtree, hf_option_captive_portal, tvb, off, optlen, ENC_ASCII|ENC_NA);
        proto_item_set_url(ti_cp);
        break;
        }
    case OPTION_S46_PRIORITY:
        temp_optlen = optlen;
        while (temp_optlen >= 2) {
            proto_tree_add_item(subtree, hf_option_s46_option_code, tvb, off, 2, ENC_BIG_ENDIAN);
            temp_optlen -= 2;
            off += 2;
        }
        break;
    case OPTION_F_BINDING_STATUS:
        if (optlen != 1) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "Failover: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_option_failover_binding_status, tvb, off, 1, ENC_BIG_ENDIAN);
        break;
    case OPTION_F_CONNECT_FLAGS:
        if (optlen != 2) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "Failover: malformed option");
            break;
        }
        proto_tree_add_bitmask(subtree, tvb, off, hf_option_failover_connect_flags, ett_dhcpv6_failover_connect_flags, dhcpv6_failover_connect_flags_fields, ENC_BIG_ENDIAN);
        break;
    case OPTION_F_DNS_HOST_NAME:
        {
        const gchar *dns_name;
        gint dns_name_len;

        get_dns_name(tvb, off, optlen, off, &dns_name, &dns_name_len);
        proto_tree_add_string(subtree, hf_option_failover_dns_hostname, tvb, off, optlen, format_text(wmem_packet_scope(), dns_name, dns_name_len));
        break;
        }
    case OPTION_F_DNS_ZONE_NAME:
        {
        const gchar *dns_name;
        gint dns_name_len;

        get_dns_name(tvb, off, optlen, off, &dns_name, &dns_name_len);
        proto_tree_add_string(subtree, hf_option_failover_dns_zonename, tvb, off, optlen, format_text(wmem_packet_scope(), dns_name, dns_name_len));
        break;
        }
    case OPTION_F_DNS_FLAGS:
        if (optlen != 2) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "Failover: malformed option");
            break;
        }
        proto_tree_add_bitmask(subtree, tvb, off, hf_option_failover_dns_flags, ett_dhcpv6_failover_dns_flags, dhcpv6_failover_dns_flags_fields, ENC_BIG_ENDIAN);
        break;
    case OPTION_F_EXPIRATION_TIME:
        if (optlen != 4) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "Failover: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_option_failover_expiration_time, tvb, off, 4, ENC_BIG_ENDIAN);
        break;
    case OPTION_F_MAX_UNACKED_BNDUPD:
        if (optlen != 4) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "Failover: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_option_failover_max_unacked_bndupd, tvb, off, 4, ENC_BIG_ENDIAN);
        break;
    case OPTION_F_MCLT:
        if (optlen != 4) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "Failover: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_option_failover_mclt, tvb, off, 4, ENC_BIG_ENDIAN);
        break;
    case OPTION_F_PARTNER_LIFETIME:
        if (optlen != 4) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "Failover: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_option_failover_partner_lifetime, tvb, off, 4, ENC_BIG_ENDIAN);
        break;
    case OPTION_F_PARTNER_LIFETIME_SENT:
        if (optlen != 4) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "Failover: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_option_failover_partner_lifetime_sent, tvb, off, 4, ENC_BIG_ENDIAN);
        break;
    case OPTION_F_PARTNER_DOWN_TIME:
        if (optlen != 4) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "Failover: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_option_failover_partner_downtime, tvb, off, 4, ENC_BIG_ENDIAN);
        break;
    case OPTION_F_PARTNER_RAW_CLT_TIME:
        if (optlen != 4) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "Failover: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_option_failover_partner_raw_clt_time, tvb, off, 4, ENC_BIG_ENDIAN);
        break;
    case OPTION_F_PROTOCOL_VERSION:
        if (optlen != 4) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "Failover: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_option_failover_major_version, tvb, off, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_option_failover_minor_version, tvb, off+2, 2, ENC_BIG_ENDIAN);
        break;
    case OPTION_F_KEEPALIVE_TIME:
        if (optlen != 4) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "Failover: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_option_failover_keepalive_time, tvb, off, 4, ENC_BIG_ENDIAN);
        break;
    case OPTION_F_RECONFIGURE_DATA:
        if (optlen < 4) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "Failover: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_option_failover_reconfigure_time, tvb, off, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_option_failover_reconfigure_key, tvb, off+4, optlen-4, ENC_NA);
        break;
    case OPTION_F_RELATIONSHIP_NAME:
        proto_tree_add_item(subtree, hf_option_failover_relationship_name, tvb, off, optlen, ENC_UTF_8|ENC_NA);
        break;
    case OPTION_F_SERVER_FLAGS:
        if (optlen != 1) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "Failover: malformed option");
            break;
        }
        proto_tree_add_bitmask(subtree, tvb, off, hf_option_failover_server_flags, ett_dhcpv6_failover_server_flags, dhcpv6_failover_server_flags_fields, ENC_BIG_ENDIAN);
        break;
    case OPTION_F_SERVER_STATE:
        if (optlen != 1) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "Failover: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_option_failover_server_state, tvb, off, 1, ENC_BIG_ENDIAN);
        break;
    case OPTION_F_START_TIME_OF_STATE:
        if (optlen != 4) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "Failover: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_option_failover_start_time_of_state, tvb, off, 4, ENC_BIG_ENDIAN);
        break;
    case OPTION_F_STATE_EXPIRATION_TIME:
        if (optlen != 4) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "Failover: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_option_failover_state_expiration_time, tvb, off, 4, ENC_BIG_ENDIAN);
        break;
    case OPTION_RELAY_PORT:
        if (optlen != 2) {
            expert_add_info_format(pinfo, option_item, &ei_dhcpv6_malformed_option, "Relay Port: malformed option");
            break;
        }
        proto_tree_add_item(subtree, hf_option_relay_port, tvb, off, 2, ENC_BIG_ENDIAN);
        break;
    }

    return 4 + optlen;
}


/* May be called recursively */
static void
dissect_dhcpv6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               int off, int eoff, hopcount_info hpi)
{
    proto_tree        *bp_tree = NULL;
    proto_item        *ti;
    gboolean           at_end;
    guint8             msgtype;
    msgtype = tvb_get_guint8(tvb, off);

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str_ext(msgtype, &msgtype_vals_ext, "Message Type %u"));

    if (tree) {
        ti = proto_tree_add_item(tree, proto_dhcpv6, tvb, off, eoff - off, ENC_NA);
        bp_tree = proto_item_add_subtree(ti, ett_dhcpv6);
    }


    if ((msgtype == RELAY_FORW) || (msgtype == RELAY_REPLY)) {
        const guint8 previous_hopcount = hpi.hopcount;
        proto_item *previous_pi = hpi.pi;
        if (tree) {
            proto_tree_add_item(bp_tree, hf_dhcpv6_msgtype,  tvb, off,       1, ENC_BIG_ENDIAN);
            hpi.pi = proto_tree_add_item(bp_tree, hf_dhcpv6_hopcount, tvb, off + 1,   1, ENC_BIG_ENDIAN);
            proto_tree_add_item(bp_tree, hf_dhcpv6_linkaddr, tvb, off + 2,  16, ENC_NA);
            proto_tree_add_item(bp_tree, hf_dhcpv6_peeraddr, tvb, off + 18, 16, ENC_NA);

        }
        /* Check the hopcount not exceed the HOP_COUNT_LIMIT */
        hpi.hopcount = tvb_get_guint8(tvb, off + 1);
        if (hpi.hopcount > HOP_COUNT_LIMIT) {
          expert_add_info_format(pinfo, hpi.pi, &ei_dhcpv6_error_hopcount, "Hopcount (%d) exceeds the maximum limit HOP_COUNT_LIMIT (%d)", hpi.hopcount, HOP_COUNT_LIMIT);
        }
        /* Check hopcount is correctly incremented by 1 */
        if (hpi.relay_message_previously_detected && hpi.hopcount != previous_hopcount - 1) {
          expert_add_info_format(pinfo, previous_pi, &ei_dhcpv6_error_hopcount, "hopcount is not correctly incremented by 1 (expected : %d, actual : %d)", hpi.hopcount + 1, previous_hopcount);
        }
        hpi.relay_message_previously_detected = TRUE;
        col_append_fstr(pinfo->cinfo, COL_INFO, "L: %s ", tvb_ip6_to_str(tvb, off + 2));
        off += 34;
    } else {
        /* Check the inner hopcount equals 0 */
        if (hpi.hopcount) {
            expert_add_info_format(pinfo, hpi.pi, &ei_dhcpv6_error_hopcount, "Hopcount of most inner message has to equal 0 instead of %d", hpi.hopcount);
        }
        if (tree) {
            proto_tree_add_item(bp_tree, hf_dhcpv6_msgtype, tvb, off, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(bp_tree, hf_dhcpv6_xid, tvb, off + 1, 3, ENC_BIG_ENDIAN);
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, "XID: 0x%06x ", tvb_get_ntoh24(tvb, off + 1));
        off += 4;
    }

    at_end = FALSE;
    while ((off < eoff) && !at_end)
        off += dhcpv6_option(tvb, pinfo, bp_tree, off, eoff, &at_end, proto_dhcpv6, hpi, msgtype);
}

static int
dissect_dhcpv6_stream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    hopcount_info hpi;
    initialize_hopount_info(&hpi);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DHCPv6");
    col_clear(pinfo->cinfo, COL_INFO);
    dissect_dhcpv6(tvb, pinfo, tree, 0, tvb_reported_length(tvb), hpi);
    return tvb_captured_length(tvb);
}

static guint
get_dhcpv6_bulk_leasequery_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                                   int offset, void *data _U_)
{
    return (tvb_get_ntohs(tvb, offset)+2);
}

static int
dissect_dhcpv6_bulk_leasequery_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *bulk_tree, *option_tree;
    gint        offset = 0, end;
    guint16     size, trans_id;
    guint8      msg_type;
    gboolean    at_end = FALSE;
    hopcount_info hpi;
    initialize_hopount_info(&hpi);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DHCPv6 BulkLease");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_dhcpv6_bulk_leasequery, tvb, 0, -1, ENC_NA );
    bulk_tree = proto_item_add_subtree(ti, ett_dhcpv6_bulk_leasequery);

    size = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(bulk_tree, hf_dhcpv6_bulk_leasequery_size, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    msg_type = tvb_get_guint8( tvb, offset );
    ti = proto_tree_add_item(bulk_tree, hf_dhcpv6_bulk_leasequery_msgtype, tvb, offset, 1, ENC_BIG_ENDIAN);
    if ((msg_type != LEASEQUERY)       &&
        (msg_type != LEASEQUERY_REPLY) &&
        (msg_type != LEASEQUERY_DONE)  &&
        (msg_type != LEASEQUERY_DATA))
        expert_add_info_format(pinfo, ti, &ei_dhcpv6_bulk_leasequery_bad_msg_type,
            "Message Type %d not allowed by DHCPv6 Bulk Leasequery", msg_type);

    offset += 1;
    proto_tree_add_item(bulk_tree, hf_dhcpv6_bulk_leasequery_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    trans_id = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(bulk_tree, hf_dhcpv6_bulk_leasequery_trans_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s, Transaction ID: %5u",
                      val_to_str_ext_const(msg_type, &msgtype_vals_ext, "Unknown"), trans_id);

    option_tree = proto_tree_add_subtree(bulk_tree, tvb, offset, -1, ett_dhcpv6_bulk_leasequery_options, NULL, "DHCPv6 Options");
    end = size + 2;
    while ((offset < end) && !at_end)
        offset += dhcpv6_option(tvb, pinfo, option_tree, offset,
                                end, &at_end, proto_dhcpv6_bulk_leasequery, hpi, msg_type);

    return tvb_reported_length(tvb);
}

static int
dissect_dhcpv6_bulk_leasequery(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, dhcpv6_bulk_leasequery_desegment, 2,
                    get_dhcpv6_bulk_leasequery_pdu_len, dissect_dhcpv6_bulk_leasequery_pdu, data);
    return tvb_reported_length(tvb);
}

static int dissect_dhcpv6_s46_ipv6_prefix(tvbuff_t *tvb, int hf, int offset, int prefix_length, proto_tree *tree)
{

    int bytes_to_process;
    ws_in6_addr prefix;

    bytes_to_process = (((prefix_length + 7) & 0xf8) >> 3);

    memset(prefix.bytes, 0, sizeof prefix.bytes);
    if (bytes_to_process != 0) {
        tvb_memcpy(tvb, prefix.bytes, offset, bytes_to_process);
    }
    proto_tree_add_ipv6(tree, hf, tvb, offset, bytes_to_process, &prefix);

    return bytes_to_process;
}

void
proto_register_dhcpv6(void)
{
    module_t *bulkquery_module;
    module_t *dhcpv6_module;

    static hf_register_info hf[] = {

        /* DHCPv6 header */
        { &hf_dhcpv6_msgtype,
          { "Message type", "dhcpv6.msgtype", FT_UINT8, BASE_DEC | BASE_EXT_STRING, &msgtype_vals_ext, 0x0, NULL, HFILL }},
        { &hf_dhcpv6_hopcount,
          { "Hopcount", "dhcpv6.hopcount", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_dhcpv6_xid,
          { "Transaction ID", "dhcpv6.xid", FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL}},
        { &hf_dhcpv6_linkaddr,
          { "Link address", "dhcpv6.linkaddr", FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL}},
        { &hf_dhcpv6_peeraddr,
          { "Peer address", "dhcpv6.peeraddr", FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL}},
        /* Generic option stuff */
        { &hf_option_type_num,
          { "Option", "dhcpv6.option.type", FT_UINT16, BASE_DEC | BASE_EXT_STRING, &opttype_vals_ext, 0x0, NULL, HFILL}},
        { &hf_option_length,
          { "Length", "dhcpv6.option.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        { &hf_option_type_str,
          { "Option", "dhcpv6.option.type_str", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        /* OPTION_CLIENT_FQDN */
        { &hf_clientfqdn_bad_msgtype,
          { "Illegal Message Type", "dhcpv6.clientfqdn.bad_msgtype", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &msgtype_vals_ext, 0x0, NULL, HFILL }},
        { &hf_clientfqdn_flags,
          { "Flags", "dhcpv6.client_fqdn_flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        /* Client's preferences */
        { &hf_clientfqdn_client_s,
          { "S bit", "dhcpv6.clientfqdn.client.s", FT_BOOLEAN, 8, TFS(&fqdn_s), 0x1,
            "Whether or not the client prefers to perform AAAA RR (FQDN-to-address) updates", HFILL}},
        { &hf_clientfqdn_client_n,
          { "N bit", "dhcpv6.clientfqdn.client.n", FT_BOOLEAN, 8, TFS(&fqdn_n), 0x4,
            "Whether or not the client prefers to perform PTR RR (address-to-FQDN) updates", HFILL}},
        /* Server's decision to reject or accept the client's preferences */
        { &hf_clientfqdn_server_s,
          { "S bit", "dhcpv6.clientfqdn.server.s", FT_BOOLEAN, 8, TFS(&fqdn_s), 0x1,
            "Whether or not the server SHALL perform AAAA RR (FQDN-to-address) updates", HFILL}},
        { &hf_clientfqdn_server_o,
          { "O bit", "dhcpv6.clientfqdn.server.o", FT_BOOLEAN, 8, TFS(&fqdn_o), 0x2,
              "Whether or not the server has overridden the client's S-bit preference", HFILL}},
        { &hf_clientfqdn_server_n,
          { "N bit", "dhcpv6.clientfqdn.server.n", FT_BOOLEAN, 8, TFS(&fqdn_n), 0x4,
            "Whether or not the server SHALL perform PTR RR (address-to-FQDN) updates", HFILL}},

        /* Headers used in dhcpv6_domain(). */
        { &hf_empty_domain_name,
          { "Empty domain name - field length", "dhcpv6.domain_field_len", FT_UINT16, BASE_DEC, NULL, 0,
            "Indicates that the client requests the server to provide an FQDN name", HFILL}},
        { &hf_dhcpv6_non_dns_encoded_name,
          { "Non-DNS encoded name. Label length exceeds 63", "dhcpv6.bogus_label_length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_dhcpv6_domain_field_len_exceeded,
          { "Remaining length in the domain name field exceeded", "dhcpv6.domain_field_len_exceeded", FT_UINT8, BASE_DEC,
            NULL, 0, NULL, HFILL }},
        { &hf_dhcpv6_decoded_portion,
          { "Portion successfully decoded", "dhcpv6.decoded_portion", FT_STRING, STR_ASCII, NULL, 0, NULL, HFILL}},
        { &hf_dhcpv6_encoded_fqdn_len_gt_255,
          { "DNS-encoded labels of FQDN exceed 255 octets", "dhcpv6.encoded_fqdn_gt_255", FT_UINT16, BASE_DEC, NULL, 0,
            "Encoded length is greater than 255 [RFC 1035 3.1.]", HFILL}},
        { &hf_dhcpv6_root_only_domain_name,
          { "Root only domain name", "dhcpv6.root_only_domain_name", FT_STRING, BASE_NONE, NULL, 0,
            "The root domain cannot be resolved", HFILL}},
        { &hf_dhcpv6_tld,
          { "Top Level Domain name", "dhcpv6.tld", FT_STRING, STR_ASCII, NULL, 0,
            "Likely to fail because most TLDs do not have an IP address", HFILL}},
        { &hf_dhcpv6_partial_name_preceded_by_fqdn,
          { "Partial name preceded by FQDN", "dhcpv6.partial_name_preceded_by_fqdn", FT_STRING, STR_ASCII, NULL, 0,
            "Partial domain names must be the only name in the domain field", HFILL}},

        { &hf_remoteid_enterprise,
          { "Enterprise ID", "dhcpv6.remoteid.enterprise", FT_UINT32, BASE_ENTERPRISES, STRINGS_ENTERPRISES, 0, "RemoteID Enterprise Number", HFILL }},
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
          { "Enterprise ID", "dhcpv6.duiden.enterprise", FT_UINT32, BASE_ENTERPRISES, STRINGS_ENTERPRISES, 0, "DUID EN Enterprise Number", HFILL }},
        { &hf_duiden_identifier,
          { "Identifier", "dhcpv6.duiden.identifier", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_duidll_link_layer_addr,
          { "Link-layer address", "dhcpv6.duidll.link_layer_addr", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_duiduuid_bytes,
          { "UUID", "dhcpv6.duiduuid.bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
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
          { "Requested Option code", "dhcpv6.requested_option_code", FT_UINT16, BASE_DEC | BASE_EXT_STRING, &opttype_vals_ext, 0, NULL, HFILL }},
        { &hf_option_preference,
          { "Pref-value", "dhcpv6.option_preference", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_elapsed_time,
          { "Elapsed time", "dhcpv6.elapsed_time", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0, NULL, HFILL}},
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
        { &hf_auth_realm,
          { "DHCP realm", "dhcpv6.auth.realm", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_auth_key_id,
          {"Key ID", "dhcpv6.auth.key_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        { &hf_auth_md5_data,
          {"HMAC-MD5 data", "dhcpv6.auth.md5_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_opt_unicast,
          { "IPv6 address", "dhcpv6.unicast", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_opt_status_code,
          { "Status Code", "dhcpv6.status_code", FT_UINT16, BASE_DEC | BASE_EXT_STRING, &statuscode_vals_ext, 0, NULL, HFILL }},
        { &hf_opt_status_msg,
          { "Status Message", "dhcpv6.status_msg", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_vendorclass_enterprise,
          { "Enterprise ID", "dhcpv6.vendorclass.enterprise", FT_UINT32, BASE_ENTERPRISES, STRINGS_ENTERPRISES, 0, "Vendor Class Enterprise Number", HFILL }},
        { &hf_vendorclass_data,
          { "vendor-class-data", "dhcpv6.vendorclass.data", FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_vendoropts_enterprise,
          { "Enterprise ID", "dhcpv6.vendoropts.enterprise", FT_UINT32, BASE_ENTERPRISES, STRINGS_ENTERPRISES, 0, "Vendor opts Enterprise Number", HFILL }},
        { &hf_vendoropts_enterprise_option_code,
          { "Option code", "dhcpv6.vendoropts.enterprise.option_code", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_vendoropts_enterprise_option_length,
          { "Option length", "dhcpv6.vendoropts.enterprise.option_length", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_vendoropts_enterprise_option_data,
          { "Option data", "dhcpv6.vendoropts.enterprise.option_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_interface_id,
          { "Interface-ID", "dhcpv6.interface_id", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_reconf_msg,
          { "Reconfigure message type", "dhcpv6.reconf_msg", FT_UINT8, BASE_DEC | BASE_EXT_STRING, &msgtype_vals_ext, 0, NULL, HFILL }},
        { &hf_sip_server_domain_search_fqdn,
          { "SIP Server Domain Search FQDN", "dhcpv6.sip_server_domain_search_fqdn", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_sip_server_a,
          { "SIP server address", "dhcpv6.sip_server_a", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_dns_servers,
          { "DNS server address", "dhcpv6.dns_server", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_domain_search_list_entry,
          { "List entry", "dhcpv6.search_list_entry", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_nis_servers,
          { "NIS server address", "dhcpv6.nis_server", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_nisp_servers,
          { "NISP server address", "dhcpv6.nisp_server", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_nis_fqdn,
          { "NIS FQDN", "dhcpv6.nis_fqdn", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_nisp_fqdn,
          { "NISP FQDN", "dhcpv6.nisp_fqdn", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_sntp_servers,
          { "SNTP server address", "dhcpv6.sntp_server", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_opt_lifetime,
          { "Lifetime", "dhcpv6.lifetime", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_bcmcs_servers_fqdn,
          { "BCMCS server FQDN", "dhcpv6.bcmcs_server_fqdn", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_bcmcs_servers_a,
          { "BCMCS server address", "dhcpv6.bcmcs_server_a", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_remoteid_enterprise_id,
          { "Remote-ID", "dhcpv6.remoteid_enterprise_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_subscriber_id,
          { "Subscriber-ID", "dhcpv6.subscriber_id", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_client_fqdn,
          { "Client Domain Name", "dhcpv6.client_domain", FT_STRING, STR_ASCII, NULL, 0x0, NULL, HFILL } },
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
        { &hf_pd_exclude_pref_len,
          { "Prefix length", "dhcpv6.pd_exclude.pref_len", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_pd_exclude_subnet_id,
          { "IPv6 subnet ID", "dhcpv6.pd_exclude.subnet_id", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_option_ntpserver_type,
          { "Suboption", "dhcpv6.ntpserver.option.type", FT_UINT16, BASE_DEC, VALS(ntp_server_opttype_vals), 0x0, NULL, HFILL}},
        { &hf_option_ntpserver_length,
          { "Length", "dhcpv6.ntpserver.option.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        { &hf_option_ntpserver_addr,
          { "NTP Server Address", "dhcpv6.ntpserver.addr", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_option_ntpserver_mc_addr,
          { "NTP Multicast Address", "dhcpv6.ntpserver.mc_addr", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_option_captive_portal,
          { "Captive Portal", "dhcpv6.captive_portal", FT_STRING, BASE_NONE, NULL, 0x0, "The contact URI for the captive portal that the user should connect to", HFILL }},
        { &hf_option_s46_option_code,
          { "S46 Option code", "dhcpv6.option_code", FT_UINT16, BASE_HEX, VALS(s46_opt_code_vals), 0x0, NULL, HFILL }},
        { &hf_option_failover_binding_status,
          { "Failover Binding Status", "dhcpv6.failover.binding_status", FT_UINT8, BASE_DEC, VALS(failover_binding_status_vals), 0x0, NULL, HFILL }},
        { &hf_option_failover_connect_flags,
          { "Flags", "dhcpv6.failover.connect.flags", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_option_failover_connect_reserved_flag,
          { "Reserved", "dhcpv6.failover.connect.flags.reserved", FT_BOOLEAN, 16, TFS(&tfs_true_false), 0xfffe, NULL, HFILL }},
        { &hf_option_failover_connect_f_flag,
          { "Fixed PD Length (F)", "dhcpv6.failover.connect.flags.f", FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x0001, NULL, HFILL }},
        { &hf_option_failover_dns_hostname,
          { "DNS Hostname", "dhcpv6.failover.dns_hostname", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_option_failover_dns_zonename,
          { "DNS Zone Name", "dhcpv6.failover.dns_zonename", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_option_failover_dns_flags,
          { "Flags", "dhcpv6.failover.dns.flags", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_option_failover_dns_reserved_flag,
          { "Reserved", "dhcpv6.failover.dns.flags.reserved", FT_BOOLEAN, 16, TFS(&tfs_true_false), 0xfff0, NULL, HFILL }},
        { &hf_option_failover_dns_u_flag,
          { "Using Requested FQDN (U)", "dhcpv6.failover.dns.flags.u", FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x0008, NULL, HFILL }},
        { &hf_option_failover_dns_s_flag,
          { "Synthesized Name (S)", "dhcpv6.failover.dns.flags.s", FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x0004, NULL, HFILL }},
        { &hf_option_failover_dns_r_flag,
          { "Rev Uptodate (R)", "dhcpv6.failover.dns.flags.r", FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x0002, NULL, HFILL }},
        { &hf_option_failover_dns_f_flag,
          { "Fwd Uptodate (F)", "dhcpv6.failover.dns.flags.f", FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x0001, NULL, HFILL }},
        { &hf_option_failover_expiration_time,
          { "Expiration Time", "dhcpv6.failover.expiration_time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_option_failover_max_unacked_bndupd,
          { "Max number of unacked BNDUPD messages", "dhcpv6.failover.max_unacked_bndupd", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_option_failover_mclt,
          { "Maximum Client Lead Time (MCLT)", "dhcpv6.failover.mclt", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_option_failover_partner_lifetime,
          { "Partner Lifetime", "dhcpv6.failover.partner_lifetime", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_option_failover_partner_lifetime_sent,
          { "Partner Lifetime Sent", "dhcpv6.failover.partner_lifetime_sent", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_option_failover_partner_downtime,
          { "Partner Down Time", "dhcpv6.failover.partner_down_time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_option_failover_partner_raw_clt_time,
          { "Partner Raw Client Time", "dhcpv6.failover.partner_raw_clt_time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_option_failover_major_version,
          { "Protocol Major Version", "dhcpv6.failover.protocol.major_version", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_option_failover_minor_version,
          { "Protocol Minor Version", "dhcpv6.failover.protocol.minor_version", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_option_failover_keepalive_time,
          { "Keepalive Time", "dhcpv6.failover.keepalive_time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_option_failover_reconfigure_time,
          { "Reconfigure Time", "dhcpv6.failover.reconfigure_time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_option_failover_reconfigure_key,
          { "Reconfigure Key", "dhcpv6.failover.reconfigure_key", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_option_failover_relationship_name,
          { "Relationship Name", "dhcpv6.failover.relationship_name", FT_STRING, STR_UNICODE, NULL, 0, NULL, HFILL }},
        { &hf_option_failover_server_flags,
          { "Flags", "dhcpv6.failover.server.flags", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_option_failover_server_reserved_flag,
          { "Reserved", "dhcpv6.failover.server.flags.reserved", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0xf8, NULL, HFILL }},
        { &hf_option_failover_server_a_flag,
          { "Ack Startup (A)", "dhcpv6.failover.server.flags.a", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x04, NULL, HFILL }},
        { &hf_option_failover_server_s_flag,
          { "Startup (S)", "dhcpv6.failover.server.flags.s", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x02, NULL, HFILL }},
        { &hf_option_failover_server_c_flag,
          { "Communicated (C)", "dhcpv6.failover.server.flags.c", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x01, NULL, HFILL }},
        { &hf_option_failover_server_state,
          { "Server State", "dhcpv6.failover.server_state", FT_UINT8, BASE_DEC, VALS(failover_server_state_vals), 0, NULL, HFILL }},
        { &hf_option_failover_start_time_of_state,
          { "Start Time of State", "dhcpv6.failover.start_time_of_state", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_option_failover_state_expiration_time,
          { "State Expiration Time", "dhcpv6.failover.state_expiration_time", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_option_relay_port,
          { "Downstream Source Port", "dhcpv6.relay_port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_option_ntpserver_fqdn,
          { "NTP Server FQDN", "dhcpv6.ntpserver.fqdn", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_packetcable_ccc_suboption,
          { "Sub element", "dhcpv6.packetcable.ccc.suboption", FT_UINT16, BASE_DEC, VALS(pkt_ccc_opt_vals), 0, NULL, HFILL }},
        { &hf_packetcable_ccc_pri_dhcp,
          { "Primary DHCP", "dhcpv6.packetcable.ccc.pri_dhcp", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_ccc_sec_dhcp,
          { "Secondary DHCP", "dhcpv6.packetcable.ccc.sec_dhcp", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_cccV6_suboption,
          { "Sub element", "dhcpv6.packetcable.cccV6.suboption", FT_UINT16, BASE_DEC | BASE_EXT_STRING, &pkt_cccV6_opt_vals_ext, 0, NULL, HFILL }},
        { &hf_modem_capabilities_encoding_type,
          { "Type", "dhcpv6.docsis.cccV6.tlv5.suboption", FT_UINT16, BASE_DEC | BASE_EXT_STRING, &modem_capabilities_encoding_ext, 0, NULL, HFILL }},
        { &hf_eue_capabilities_encoding_type,
          { "Type", "dhcpv6.packetcable.cccV6.tlv5.suboption", FT_UINT16, BASE_DEC | BASE_EXT_STRING, &eue_capabilities_encoding_ext, 0, NULL, HFILL }},
        { &hf_capabilities_encoding_length,
          { "Length", "dhcpv6.cccV6.tlv5.suboption.length", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_capabilities_encoding_bytes,
          { "Value", "dhcpv6.cccV6.tlv5.suboption.value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_capabilities_encoding_number,
          { "Value", "dhcpv6.cccV6.tlv5.suboption.value_number", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_cccV6_pri_dss,
          { "Primary SSID", "dhcpv6.packetcable.cccV6.pri_dss", FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_cccV6_sec_dss,
          { "Secondary SSID", "dhcpv6.packetcable.cccV6.sec_dss", FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_packetcable_cccV6_prov_srv_type,
          { "Type", "dhcpv6.packetcable.cccV6.prov_srv.type", FT_UINT8, BASE_DEC, VALS(pkt_cccV6_prov_srv_type_vals), 0, NULL, HFILL }},
        { &hf_packetcable_cccV6_prov_srv_fqdn,
          { "FQDN", "dhcpv6.packetcable.cccV6.prov_srv.fqdn", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
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
          { "Suboption", "dhcpv6.cablelabs.opt", FT_UINT16, BASE_DEC | BASE_EXT_STRING, &cl_vendor_subopt_values_ext, 0, NULL, HFILL }},
        { &hf_cablelabs_ipv6_server,
          { "IPv6 address", "dhcpv6.cablelabs.ipv6_server", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        { &hf_cablelabs_docsis_version_number,
          { "DOCSIS Version Number", "dhcpv6.cablelabs.docsis_version_number", FT_UINT16, BASE_CUSTOM, CF_FUNC(cablelabs_fmt_docsis_version), 0x0, NULL, HFILL}},
        { &hf_cablelabs_interface_id,
          { "Interface-ID", "dhcpv6.cablelabs.interface_id", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_cablelabs_interface_id_link_address,
          { "Link Address", "dhcpv6.cablelabs.interface_id_link_address", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_option_s46_rule_flags,
          { "Flags", "dhcpv6.s46_rule.flags", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
        { &hf_option_s46_rule_reserved_flag,
          { "Reserved", "dhcpv6.s46_rule.flags.reserved", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0xfe, NULL, HFILL }},
        { &hf_option_s46_rule_fmr_flag,
          { "Forwarding Mapping Rule", "dhcpv6.s46_rule.flags.fmr", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x01, NULL, HFILL }},
        { &hf_option_s46_rule_ea_len,
          { "EA-bit length", "dhcpv6.s46_rule.ea_len", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_option_s46_rule_ipv4_pref_len,
          { "IPv4 prefix length", "dhcpv6.s46_rule.ipv4_pref_len", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_option_s46_rule_ipv4_prefix,
          { "IPv4 prefix", "dhcpv6.s46_rule.ipv4_prefix", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_option_s46_rule_ipv6_pref_len,
          { "IPv6 prefix length", "dhcpv6.s46_rule.ipv6_prefix_len", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_option_s46_rule_ipv6_prefix,
          { "IPv6 prefix", "dhcpv6.s46_rule.ipv6_prefix", FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_option_s46_br_address,
          { "BR address", "dhcpv6.s46_br.address", FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_option_s46_dmr_pref_len,
          { "IPv6 prefix length", "dhcpv6.s46_dmr.dmr_pref_len", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_option_s46_dmr_prefix,
          { "IPv6 prefix", "dhcpv6.s46_dmr.dmr_prefix", FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_option_s46_v4v6bind_ipv4_address,
          { "IPv4 Address", "dhcpv6.s46_v4v6bind.ipv4_address", FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_option_s46_v4v6bind_ipv6_pref_len,
          { "IPv6 prefix length", "dhcpv6.s46_v4v6bind.ipv6_pref_len", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_option_s46_v4v6bind_ipv6_prefix,
          { "IPv6 prefix", "dhcpv6.s46_v4v6bind.ipv6_prefix", FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_option_s46_portparam_offset,
          { "Offset", "dhcpv6.s46_portparam.offset", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_option_s46_portparam_psid_len,
          { "PSID length", "dhcpv6.s46_portparam.psid_len", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_option_s46_portparam_psid,
          { "PSID", "dhcpv6.s46_portparam.psid", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_opt_mudurl,
          { "MUDURL", "dhcpv6.mudurl", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_dhcpv6,
        &ett_dhcpv6_option,
        &ett_dhcpv6_option_vsoption,
        &ett_dhcpv6_vendor_option,
        &ett_dhcpv6_pkt_option,
        &ett_dhcpv6_netserver_option,
        &ett_dhcpv6_tlv5_type,
        &ett_dhcpv6_sip_server_domain_search_list_option,
        &ett_dhcpv6_dns_domain_search_list_option,
        &ett_dhcpv6_nis_domain_name_option,
        &ett_dhcpv6_nisp_domain_name_option,
        &ett_dhcpv6_bcmcs_servers_domain_search_list_option,
        &ett_dhcpv6_s46_rule_flags,
        &ett_dhcpv6_failover_connect_flags,
        &ett_dhcpv6_failover_dns_flags,
        &ett_dhcpv6_failover_server_flags,
        &ett_clientfqdn_flags,
        &ett_clientfqdn_expert
    };

    static ei_register_info ei[] = {
        { &ei_dhcpv6_bogus_length, { "dhcpv6.bogus_length", PI_MALFORMED, PI_ERROR, "Bogus length", EXPFILL }},
        { &ei_dhcpv6_malformed_option, { "dhcpv6.malformed_option", PI_MALFORMED, PI_ERROR, "Malformed option", EXPFILL }},
        { &ei_dhcpv6_no_suboption_len, { "dhcpv6.no_suboption_len", PI_PROTOCOL, PI_WARN,
                                         "no room left in option for suboption length", EXPFILL }},
        { &ei_dhcpv6_invalid_time_value, { "dhcpv6.invalid_time_value", PI_PROTOCOL, PI_WARN, "Invalid time value", EXPFILL }},
        { &ei_dhcpv6_invalid_type, { "dhcpv6.invalid_type", PI_PROTOCOL, PI_WARN, "Invalid type", EXPFILL }},
        { &ei_dhcpv6_error_hopcount, { "dhcpv6.error_hopcount", PI_PROTOCOL, PI_WARN, "Detected error on hop-count", EXPFILL }},
        { &ei_dhcpv6_clientfqdn_bad_msgtype, { "dhcpv6.bad_msgtype", PI_PROTOCOL, PI_ERROR,
                                    "This message type is not permitted to use OPTION_CLIENT_FQDN", EXPFILL }},
        { &ei_dhcpv6_s_bit_should_be_zero, { "dhcpv6.s_bit_should_be_zero", PI_PROTOCOL, PI_ERROR,
                                    "ERROR: When the N-bit is set, the S-bit must be reset", EXPFILL }},
        /*
         * FQDN-related errors in dhcpv6_domain() */
        { &ei_dhcpv6_non_dns_encoded_name, { "dhcpv6.expert.name_not_dns_encoded", PI_PROTOCOL, PI_ERROR,
                                    "ERROR: This name is not a DNS record encoded", EXPFILL }},
        { &ei_dhcpv6_domain_field_len_exceeded, { "dhcpv6.expert.domain_field_length_exceeded", PI_MALFORMED, PI_ERROR,
                                    "ERROR: FQDN exceeds length of the domain name field", EXPFILL }},
        { &ei_dhcpv6_encoded_fqdn_len_gt_255, { "dhcpv6.expert.encoded_fqdn_gt_255", PI_MALFORMED, PI_ERROR,
                                    "ERROR: FQDN's *encoded* length exceeds 255 octets [RFC 1035 3.1.]", EXPFILL }},
        { &ei_dhcpv6_root_only_domain_name, { "dhcpv6.expert.root_only_domain_name", PI_PROTOCOL, PI_ERROR,
                                    "ERROR: A root-only domain name cannot be resolved.", EXPFILL }},
        { &ei_dhcpv6_tld_lookup, { "dhcpv6.expert.tld_lookup", PI_COMMENTS_GROUP, PI_WARN,
                                    "WARNING: TLDs are rarely resolvable ", EXPFILL }},
        { &ei_dhcpv6_partial_name_preceded_by_fqdn, { "dhcpv6.expert.partial_name_preceded_by_fqdn", PI_PROTOCOL, PI_ERROR,
                                    "ERROR: Partial name is preceded by an FQDN", EXPFILL }},
    };

    static hf_register_info bulk_leasequery_hf[] = {
        { &hf_dhcpv6_bulk_leasequery_size,
          { "Message size", "dhcpv6.bulk_leasequery.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dhcpv6_bulk_leasequery_msgtype,
          { "Message type", "dhcpv6.bulk_leasequery.msgtype", FT_UINT8, BASE_DEC | BASE_EXT_STRING, &msgtype_vals_ext, 0x0, NULL, HFILL }},
        { &hf_dhcpv6_bulk_leasequery_reserved,
          { "Reserved", "dhcpv6.bulk_leasequery.reserved", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_dhcpv6_bulk_leasequery_trans_id,
          { "Transaction ID", "dhcpv6.bulk_leasequery.trans_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    };

    static gint *ett_bulk_leasequery[] = {
        &ett_dhcpv6_bulk_leasequery,
        &ett_dhcpv6_bulk_leasequery_options
    };

    static ei_register_info ei_bulk_leasequery[] = {
        { &ei_dhcpv6_bulk_leasequery_bad_query_type, { "dhcpv6.bulk_leasequery.bad_query_type", PI_MALFORMED, PI_WARN, "LQ-QUERY: Query types only supported by Bulk Leasequery", EXPFILL }},
        { &ei_dhcpv6_bulk_leasequery_bad_msg_type, { "dhcpv6.bulk_leasequery.bad_msg_type", PI_MALFORMED, PI_WARN, "Message Type %d not allowed by DHCPv6 Bulk Leasequery", EXPFILL }},
    };

    expert_module_t *expert_dhcpv6;
    expert_module_t *expert_dhcpv6_bulk_leasequery;

    proto_dhcpv6 = proto_register_protocol("DHCPv6", "DHCPv6", "dhcpv6");
    proto_register_field_array(proto_dhcpv6, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_dhcpv6 = expert_register_protocol(proto_dhcpv6);
    expert_register_field_array(expert_dhcpv6, ei, array_length(ei));

    proto_dhcpv6_bulk_leasequery = proto_register_protocol("DHCPv6 Bulk Leasequery", "DHCPv6 Bulk Leasequery", "dhcpv6.bulk_leasequery");
    proto_register_field_array(proto_dhcpv6_bulk_leasequery, bulk_leasequery_hf, array_length(bulk_leasequery_hf));
    proto_register_subtree_array(ett_bulk_leasequery, array_length(ett_bulk_leasequery));

    expert_dhcpv6_bulk_leasequery = expert_register_protocol(proto_dhcpv6_bulk_leasequery);
    expert_register_field_array(expert_dhcpv6_bulk_leasequery, ei_bulk_leasequery, array_length(ei_bulk_leasequery));

    /* Allow other dissectors to find this one by name. */
    dhcpv6_handle = register_dissector("dhcpv6", dissect_dhcpv6_stream, proto_dhcpv6);

    dhcpv6_module = prefs_register_protocol(proto_dhcpv6, NULL);
    prefs_register_bool_preference(dhcpv6_module, "cablelabs_interface_id",
                                    "Dissect Option 18 (Interface-Id) as CableLab option",
                                    "Whether Option 18 is dissected as CableLab or RFC 3315",
                                    &cablelabs_interface_id);

    bulkquery_module = prefs_register_protocol(proto_dhcpv6_bulk_leasequery, NULL);
    prefs_register_bool_preference(bulkquery_module, "desegment",
                                    "Desegment all Bulk Leasequery messages spanning multiple TCP segments",
                                    "Whether the Bulk Leasequery dissector should desegment all messages spanning multiple TCP segments",
                                    &dhcpv6_bulk_leasequery_desegment);
}

void
proto_reg_handoff_dhcpv6(void)
{
    dissector_handle_t dhcpv6_bulkquery_handle;

    dissector_add_uint_range_with_preference("udp.port", UDP_PORT_DHCPV6_RANGE, dhcpv6_handle);

    dhcpv6_bulkquery_handle = create_dissector_handle(dissect_dhcpv6_bulk_leasequery,
                                            proto_dhcpv6_bulk_leasequery);
    dissector_add_uint_with_preference("tcp.port", TCP_PORT_DHCPV6_UPSTREAM, dhcpv6_bulkquery_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
