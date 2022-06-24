/* packet-dns.c
 * Routines for DNS packet disassembly
 * Copyright 2004, Nicolas DICHTEL - 6WIND - <nicolas.dichtel@6wind.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * RFC 1034, RFC 1035
 * RFC 2136 for dynamic DNS
 * https://datatracker.ietf.org/doc/draft-cheshire-dnsext-multicastdns/
 *  for multicast DNS
 * RFC 4795 for link-local multicast name resolution (LLMNR)
 *
 * For the TTL field, see also:
 *
 *  RFC 1035 erratum 2130:
 *
 *      https://www.rfc-editor.org/errata/eid2130
 *
 *  RFC 2181, section 8:
 *
 *      https://tools.ietf.org/html/rfc2181#section-8
 *
 * RFC 1035 said, in section 3.2.1, that the TTL is "a 32 bit signed
 * integer" but said, in section 4.1.3, that it's "a 32 bit unsigned
 * integer"; the erratum notes this
 *
 * RFC 2181 says of this:
 *
 *      The definition of values appropriate to the TTL field in STD 13 is
 *      not as clear as it could be, with respect to how many significant
 *      bits exist, and whether the value is signed or unsigned.  It is
 *      hereby specified that a TTL value is an unsigned number, with a
 *      minimum value of 0, and a maximum value of 2147483647.  That is, a
 *      maximum of 2^31 - 1.  When transmitted, this value shall be encoded
 *      in the less significant 31 bits of the 32 bit TTL field, with the
 *      most significant, or sign, bit set to zero.
 *
 *      Implementations should treat TTL values received with the most
 *      significant bit set as if the entire value received was zero.
 *
 *      Implementations are always free to place an upper bound on any TTL
 *      received, and treat any larger values as if they were that upper
 *      bound.  The TTL specifies a maximum time to live, not a mandatory
 *      time to live.
 *
 * so its resolution is 1) it's unsigned but 2) don't use the uppermost
 * bit, presumably to avoid problems with implementations that were based
 * on section 3.2.1 of RFC 1035 rather than on section 4.1.3 of RFC 1035.
 */

#include "config.h"


#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/ipproto.h>
#include <epan/addr_resolv.h>
#include "packet-dns.h"
#include "packet-tcp.h"
#include "packet-ip.h"
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/expert.h>
#include <epan/afn.h>
#include <epan/tap.h>
#include <epan/stats_tree.h>
#include <wsutil/utf8_entities.h>
#include "packet-tls.h"
#include "packet-dtls.h"
#include "packet-http2.h"

void proto_register_dns(void);
void proto_reg_handoff_dns(void);

struct DnsTap {
    guint packet_qr;
    guint packet_qtype;
    gint packet_qclass;
    guint packet_rcode;
    guint packet_opcode;
    guint payload_size;
    guint qname_len;
    guint qname_labels;
    guint nquestions;
    guint nanswers;
    guint nauthorities;
    guint nadditionals;
    gboolean unsolicited;
    gboolean retransmission;
    nstime_t rrt;
};

static int dns_tap = -1;

static const gchar* st_str_packets = "Total Packets";
static const gchar* st_str_packet_qr = "Query/Response";
static const gchar* st_str_packet_qtypes = "Query Type";
static const gchar* st_str_packet_qclasses = "Class";
static const gchar* st_str_packet_rcodes = "rcode";
static const gchar* st_str_packet_opcodes = "opcodes";
static const gchar* st_str_packets_avg_size = "Payload size";
static const gchar* st_str_query_stats = "Query Stats";
static const gchar* st_str_query_qname_len = "Qname Len";
static const gchar* st_str_query_domains = "Label Stats";
static const gchar* st_str_query_domains_l1 = "1st Level";
static const gchar* st_str_query_domains_l2 = "2nd Level";
static const gchar* st_str_query_domains_l3 = "3rd Level";
static const gchar* st_str_query_domains_lmore = "4th Level or more";
static const gchar* st_str_response_stats = "Response Stats";
static const gchar* st_str_response_nquestions = "no. of questions";
static const gchar* st_str_response_nanswers = "no. of answers";
static const gchar* st_str_response_nauthorities = "no. of authorities";
static const gchar* st_str_response_nadditionals = "no. of additionals";
static const gchar* st_str_service_stats = "Service Stats";
static const gchar* st_str_service_unsolicited = "no. of unsolicited responses";
static const gchar* st_str_service_retransmission = "no. of retransmissions";
static const gchar* st_str_service_rrt = "request-response time (msec)";

static int st_node_packets = -1;
static int st_node_packet_qr = -1;
static int st_node_packet_qtypes = -1;
static int st_node_packet_qclasses = -1;
static int st_node_packet_rcodes = -1;
static int st_node_packet_opcodes = -1;
static int st_node_packets_avg_size = -1;
static int st_node_query_stats = -1;
static int st_node_query_qname_len = -1;
static int st_node_query_domains = -1;
static int st_node_query_domains_l1 = -1;
static int st_node_query_domains_l2 = -1;
static int st_node_query_domains_l3 = -1;
static int st_node_query_domains_lmore = -1;
static int st_node_response_stats = -1;
static int st_node_response_nquestions = -1;
static int st_node_response_nanswers = -1;
static int st_node_response_nauthorities = -1;
static int st_node_response_nadditionals = -1;
static int st_node_service_stats = -1;
static int st_node_service_unsolicited = -1;
static int st_node_service_retransmission = -1;
static int st_node_service_rrt = -1;

static int proto_dns = -1;
static int proto_mdns = -1;
static int proto_llmnr = -1;
static int hf_dns_length = -1;
static int hf_dns_flags = -1;
static int hf_dns_flags_response = -1;
static int hf_dns_flags_opcode = -1;
static int hf_dns_flags_authoritative = -1;
static int hf_dns_flags_conflict_query = -1;
static int hf_dns_flags_conflict_response = -1;
static int hf_dns_flags_truncated = -1;
static int hf_dns_flags_recdesired = -1;
static int hf_dns_flags_tentative = -1;
static int hf_dns_flags_recavail = -1;
static int hf_dns_flags_z = -1;
static int hf_dns_flags_authenticated = -1;
static int hf_dns_flags_ad = -1;
static int hf_dns_flags_checkdisable = -1;
static int hf_dns_flags_rcode = -1;
static int hf_dns_transaction_id = -1;
static int hf_dns_count_questions = -1;
static int hf_dns_count_zones = -1;
static int hf_dns_count_answers = -1;
static int hf_dns_count_prerequisites = -1;
static int hf_dns_count_updates = -1;
static int hf_dns_count_auth_rr = -1;
static int hf_dns_count_add_rr = -1;
static int hf_dns_qry_name = -1;
static int hf_dns_qry_name_len = -1;
static int hf_dns_count_labels = -1;
static int hf_dns_qry_type = -1;
static int hf_dns_qry_class = -1;
static int hf_dns_qry_class_mdns = -1;
static int hf_dns_qry_qu = -1;
static int hf_dns_srv_service = -1;
static int hf_dns_srv_proto = -1;
static int hf_dns_srv_name = -1;
static int hf_dns_srv_priority = -1;
static int hf_dns_srv_weight = -1;
static int hf_dns_srv_port = -1;
static int hf_dns_srv_target = -1;
static int hf_dns_naptr_order = -1;
static int hf_dns_naptr_preference = -1;
static int hf_dns_naptr_flags_length = -1;
static int hf_dns_naptr_flags = -1;
static int hf_dns_naptr_service_length = -1;
static int hf_dns_naptr_service = -1;
static int hf_dns_naptr_regex_length = -1;
static int hf_dns_naptr_regex = -1;
static int hf_dns_naptr_replacement_length = -1;
static int hf_dns_naptr_replacement = -1;
static int hf_dns_rr_name = -1;
static int hf_dns_rr_type = -1;
static int hf_dns_rr_class = -1;
static int hf_dns_rr_class_mdns = -1;
static int hf_dns_rr_cache_flush = -1;
static int hf_dns_rr_ext_rcode = -1;
static int hf_dns_rr_edns0_version = -1;
static int hf_dns_rr_z = -1;
static int hf_dns_rr_z_do = -1;
static int hf_dns_rr_z_reserved = -1;
static int hf_dns_rr_ttl = -1;
static int hf_dns_rr_len = -1;
static int hf_dns_a = -1;
static int hf_dns_md = -1;
static int hf_dns_mf = -1;
static int hf_dns_mb = -1;
static int hf_dns_mg = -1;
static int hf_dns_mr = -1;
static int hf_dns_null = -1;
static int hf_dns_aaaa = -1;
static int hf_dns_cname = -1;
static int hf_dns_rr_udp_payload_size = -1;
static int hf_dns_rr_udp_payload_size_mdns = -1;
static int hf_dns_soa_mname = -1;
static int hf_dns_soa_rname = -1;
static int hf_dns_soa_serial_number = -1;
static int hf_dns_soa_refresh_interval = -1;
static int hf_dns_soa_retry_interval = -1;
static int hf_dns_soa_expire_limit = -1;
static int hf_dns_soa_minimum_ttl = -1;
static int hf_dns_ptr_domain_name = -1;
static int hf_dns_wks_address = -1;
static int hf_dns_wks_protocol = -1;
static int hf_dns_wks_bits = -1;
static int hf_dns_hinfo_cpu_length = -1;
static int hf_dns_hinfo_cpu = -1;
static int hf_dns_hinfo_os_length = -1;
static int hf_dns_hinfo_os = -1;
static int hf_dns_minfo_r_mailbox = -1;
static int hf_dns_minfo_e_mailbox = -1;
static int hf_dns_mx_preference = -1;
static int hf_dns_mx_mail_exchange = -1;
static int hf_dns_txt_length = -1;
static int hf_dns_txt = -1;
static int hf_dns_csync_soa = -1;
static int hf_dns_csync_flags = -1;
static int hf_dns_csync_flags_immediate = -1;
static int hf_dns_csync_flags_soaminimum = -1;
static int hf_dns_csync_type_bitmap = -1;
static int hf_dns_zonemd_serial = -1;
static int hf_dns_zonemd_scheme = -1;
static int hf_dns_zonemd_hash_algo = -1;
static int hf_dns_zonemd_digest = -1;
static int hf_dns_svcb_priority = -1;
static int hf_dns_svcb_target = -1;
static int hf_dns_svcb_param_key = -1;
static int hf_dns_svcb_param_length = -1;
static int hf_dns_svcb_param_value = -1;
static int hf_dns_svcb_param = -1;
static int hf_dns_svcb_param_mandatory_key = -1;
static int hf_dns_svcb_param_alpn_length = -1;
static int hf_dns_svcb_param_alpn = -1;
static int hf_dns_svcb_param_port = -1;
static int hf_dns_svcb_param_ipv4hint_ip = -1;
static int hf_dns_svcb_param_echconfig = -1;
static int hf_dns_svcb_param_ipv6hint_ip = -1;
static int hf_dns_svcb_param_odohconfig = -1;
static int hf_dns_openpgpkey = -1;
static int hf_dns_spf_length = -1;
static int hf_dns_spf = -1;
static int hf_dns_ilnp_nodeid_preference = -1;
static int hf_dns_ilnp_nodeid = -1;
static int hf_dns_ilnp_locator32_preference = -1;
static int hf_dns_ilnp_locator32 = -1;
static int hf_dns_ilnp_locator64_preference = -1;
static int hf_dns_ilnp_locator64 = -1;
static int hf_dns_ilnp_locatorfqdn_preference = -1;
static int hf_dns_ilnp_locatorfqdn = -1;
static int hf_dns_eui48 = -1;
static int hf_dns_eui64 = -1;
static int hf_dns_rrsig_type_covered = -1;
static int hf_dns_rrsig_algorithm = -1;
static int hf_dns_rrsig_labels = -1;
static int hf_dns_rrsig_original_ttl = -1;
static int hf_dns_rrsig_signature_expiration = -1;
static int hf_dns_rrsig_signature_inception = -1;
static int hf_dns_rrsig_key_tag = -1;
static int hf_dns_rrsig_signers_name = -1;
static int hf_dns_rrsig_signature = -1;
static int hf_dns_dnskey_flags = -1;
static int hf_dns_dnskey_flags_zone_key = -1;
static int hf_dns_dnskey_flags_key_revoked = -1;
static int hf_dns_dnskey_flags_secure_entry_point = -1;
static int hf_dns_dnskey_flags_reserved = -1;
static int hf_dns_dnskey_protocol = -1;
static int hf_dns_dnskey_algorithm = -1;
static int hf_dns_dnskey_key_id = -1;
static int hf_dns_dnskey_public_key = -1;
static int hf_dns_key_flags = -1;
static int hf_dns_key_flags_authentication = -1;
static int hf_dns_key_flags_confidentiality = -1;
static int hf_dns_key_flags_key_required = -1;
static int hf_dns_key_flags_associated_user = -1;
static int hf_dns_key_flags_associated_named_entity = -1;
static int hf_dns_key_flags_ipsec = -1;
static int hf_dns_key_flags_mime = -1;
static int hf_dns_key_flags_signatory = -1;
static int hf_dns_key_protocol = -1;
static int hf_dns_key_algorithm = -1;
static int hf_dns_key_key_id = -1;
static int hf_dns_key_public_key = -1;
static int hf_dns_px_preference = -1;
static int hf_dns_px_map822 = -1;
static int hf_dns_px_mapx400 = -1;
static int hf_dns_tkey_algo_name = -1;
static int hf_dns_tkey_signature_expiration = -1;
static int hf_dns_tkey_signature_inception = -1;
static int hf_dns_tkey_mode = -1;
static int hf_dns_tkey_error = -1;
static int hf_dns_tkey_key_size = -1;
static int hf_dns_tkey_key_data = -1;
static int hf_dns_tkey_other_size = -1;
static int hf_dns_tkey_other_data = -1;
static int hf_dns_ipseckey_gateway_precedence = -1;
static int hf_dns_ipseckey_gateway_type = -1;
static int hf_dns_ipseckey_gateway_algorithm = -1;
static int hf_dns_ipseckey_gateway_ipv4 = -1;
static int hf_dns_ipseckey_gateway_ipv6 = -1;
static int hf_dns_ipseckey_gateway_dns = -1;
static int hf_dns_ipseckey_public_key = -1;
static int hf_dns_xpf_ip_version = -1;
static int hf_dns_xpf_protocol = -1;
static int hf_dns_xpf_source_ipv4 = -1;
static int hf_dns_xpf_destination_ipv4 = -1;
static int hf_dns_xpf_source_ipv6 = -1;
static int hf_dns_xpf_destination_ipv6 = -1;
static int hf_dns_xpf_sport = -1;
static int hf_dns_xpf_dport = -1;
static int hf_dns_a6_prefix_len = -1;
static int hf_dns_a6_address_suffix = -1;
static int hf_dns_a6_prefix_name = -1;
static int hf_dns_dname = -1;
static int hf_dns_loc_version = -1;
static int hf_dns_loc_size = -1;
static int hf_dns_loc_horizontal_precision = -1;
static int hf_dns_loc_vertical_precision = -1;
static int hf_dns_loc_latitude = -1;
static int hf_dns_loc_longitude = -1;
static int hf_dns_loc_altitude = -1;
static int hf_dns_loc_unknown_data = -1;
static int hf_dns_nxt_next_domain_name = -1;
static int hf_dns_kx_preference = -1;
static int hf_dns_kx_key_exchange = -1;
static int hf_dns_cert_type = -1;
static int hf_dns_cert_key_tag = -1;
static int hf_dns_cert_algorithm = -1;
static int hf_dns_cert_certificate = -1;
static int hf_dns_nsec_next_domain_name = -1;
static int hf_dns_ns = -1;
static int hf_dns_opt = -1;
static int hf_dns_opt_code = -1;
static int hf_dns_opt_len = -1;
static int hf_dns_opt_data = -1;
static int hf_dns_opt_dau = -1;
static int hf_dns_opt_dhu = -1;
static int hf_dns_opt_n3u = -1;
static int hf_dns_opt_client_family = -1;
static int hf_dns_opt_client_netmask = -1;
static int hf_dns_opt_client_scope = -1;
static int hf_dns_opt_client_addr = -1;
static int hf_dns_opt_client_addr4 = -1;
static int hf_dns_opt_client_addr6 = -1;
static int hf_dns_opt_cookie_client = -1;
static int hf_dns_opt_cookie_server = -1;
static int hf_dns_opt_edns_tcp_keepalive_timeout = -1;
static int hf_dns_opt_padding = -1;
static int hf_dns_opt_chain_fqdn = -1;
static int hf_dns_opt_ext_error_info_code = -1;
static int hf_dns_opt_ext_error_extra_text = -1;
static int hf_dns_nsec3_algo = -1;
static int hf_dns_nsec3_flags = -1;
static int hf_dns_nsec3_flag_optout = -1;
static int hf_dns_nsec3_iterations = -1;
static int hf_dns_nsec3_salt_length = -1;
static int hf_dns_nsec3_salt_value = -1;
static int hf_dns_nsec3_hash_length = -1;
static int hf_dns_nsec3_hash_value = -1;
static int hf_dns_tlsa_certificate_usage = -1;
static int hf_dns_tlsa_selector = -1;
static int hf_dns_tlsa_matching_type = -1;
static int hf_dns_tlsa_certificate_association_data = -1;
static int hf_dns_tsig_algorithm_name = -1;
static int hf_dns_tsig_time_signed = -1;
static int hf_dns_tsig_error = -1;
static int hf_dns_tsig_fudge = -1;
static int hf_dns_tsig_mac_size = -1;
static int hf_dns_tsig_mac = -1;
static int hf_dns_tsig_original_id = -1;
static int hf_dns_tsig_other_len = -1;
static int hf_dns_tsig_other_data = -1;
static int hf_dns_response_in = -1;
static int hf_dns_response_to = -1;
static int hf_dns_retransmission = -1;
static int hf_dns_retransmit_request_in = -1;
static int hf_dns_retransmit_response_in = -1;
static int hf_dns_time = -1;
static int hf_dns_unsolicited = -1;
static int hf_dns_sshfp_algorithm = -1;
static int hf_dns_sshfp_fingerprint_type = -1;
static int hf_dns_sshfp_fingerprint = -1;
static int hf_dns_hip_hit_length = -1;
static int hf_dns_hip_pk_algo = -1;
static int hf_dns_hip_pk_length = -1;
static int hf_dns_hip_hit = -1;
static int hf_dns_hip_pk = -1;
static int hf_dns_hip_rendezvous_server = -1;
static int hf_dns_dhcid_rdata = -1;
static int hf_dns_ds_key_id = -1;
static int hf_dns_ds_algorithm = -1;
static int hf_dns_apl_coded_prefix = -1;
static int hf_dns_ds_digest_type = -1;
static int hf_dns_ds_digest = -1;
static int hf_dns_apl_address_family = -1;
static int hf_dns_apl_negation = -1;
static int hf_dns_apl_afdlength = -1;
static int hf_dns_apl_afdpart_ipv4 = -1;
static int hf_dns_apl_afdpart_ipv6 = -1;
static int hf_dns_apl_afdpart_data = -1;
static int hf_dns_gpos_longitude_length = -1;
static int hf_dns_gpos_longitude = -1;
static int hf_dns_gpos_latitude_length = -1;
static int hf_dns_gpos_latitude = -1;
static int hf_dns_gpos_altitude_length = -1;
static int hf_dns_gpos_altitude = -1;
static int hf_dns_rp_mailbox = -1;
static int hf_dns_rp_txt_rr = -1;
static int hf_dns_afsdb_subtype = -1;
static int hf_dns_afsdb_hostname = -1;
static int hf_dns_x25_length = -1;
static int hf_dns_x25_psdn_address = -1;
static int hf_dns_isdn_length = -1;
static int hf_dns_isdn_address = -1;
static int hf_dns_isdn_sa_length = -1;
static int hf_dns_isdn_sa = -1;
static int hf_dns_rt_preference = -1;
static int hf_dns_rt_intermediate_host = -1;
static int hf_dns_nsap_rdata = -1;
static int hf_dns_nsap_ptr_owner = -1;
static int hf_dns_caa_flags = -1;
static int hf_dns_caa_flag_issuer_critical = -1;
static int hf_dns_caa_issue = -1;
static int hf_dns_caa_issuewild = -1;
static int hf_dns_caa_iodef = -1;
static int hf_dns_caa_unknown = -1;
static int hf_dns_caa_tag_length = -1;
static int hf_dns_caa_tag = -1;
static int hf_dns_caa_value = -1;
static int hf_dns_extraneous_data = -1;
static int hf_dns_extraneous_length = -1;

static int hf_dns_wins_local_flag = -1;
static int hf_dns_wins_lookup_timeout = -1;
static int hf_dns_wins_cache_timeout = -1;
static int hf_dns_wins_nb_wins_servers = -1;
static int hf_dns_wins_server = -1;

static int hf_dns_winsr_local_flag = -1;
static int hf_dns_winsr_lookup_timeout = -1;
static int hf_dns_winsr_cache_timeout = -1;
static int hf_dns_winsr_name_result_domain = -1;

static int hf_dns_data = -1;

static int hf_dns_dso = -1;
static int hf_dns_dso_tlv = -1;
static int hf_dns_dso_tlv_type = -1;
static int hf_dns_dso_tlv_length = -1;
static int hf_dns_dso_tlv_data = -1;
static int hf_dns_dso_tlv_keepalive_inactivity = -1;
static int hf_dns_dso_tlv_keepalive_interval = -1;
static int hf_dns_dso_tlv_retrydelay_retrydelay = -1;
static int hf_dns_dso_tlv_encpad_padding = -1;

static gint ett_dns = -1;
static gint ett_dns_qd = -1;
static gint ett_dns_rr = -1;
static gint ett_dns_qry = -1;
static gint ett_dns_ans = -1;
static gint ett_dns_flags = -1;
static gint ett_dns_opts = -1;
static gint ett_nsec3_flags = -1;
static gint ett_key_flags = -1;
static gint ett_t_key = -1;
static gint ett_dns_mac = -1;
static gint ett_caa_flags = -1;
static gint ett_caa_data = -1;
static gint ett_dns_csdync_flags = -1;
static gint ett_dns_dso = -1;
static gint ett_dns_dso_tlv = -1;
static gint ett_dns_svcb = -1;
static gint ett_dns_extraneous = -1;

static expert_field ei_dns_opt_bad_length = EI_INIT;
static expert_field ei_dns_depr_opc = EI_INIT;
static expert_field ei_ttl_high_bit_set = EI_INIT;
static expert_field ei_dns_tsig_alg = EI_INIT;
static expert_field ei_dns_undecoded_option = EI_INIT;
static expert_field ei_dns_key_id_buffer_too_short = EI_INIT;
static expert_field ei_dns_retransmit_request = EI_INIT;
static expert_field ei_dns_retransmit_response = EI_INIT;
static expert_field ei_dns_extraneous_data = EI_INIT;

static dissector_table_t dns_tsig_dissector_table=NULL;

static dissector_handle_t dns_handle;

/* desegmentation of DNS over TCP */
static gboolean dns_desegment = TRUE;

/* Maximum number of elapsed seconds between messages with the same
 * transaction ID to be considered as a retransmission
 */
static guint32 retransmission_timer = 5;

/* Dissector handle for GSSAPI */
static dissector_handle_t gssapi_handle;
static dissector_handle_t ntlmssp_handle;

/* Transport protocol for DNS. */
enum DnsTransport {
  DNS_TRANSPORT_UDP,    /* includes compatible transports like SCTP */
  DNS_TRANSPORT_TCP,
  DNS_TRANSPORT_HTTP,
  DNS_TRANSPORT_QUIC
};

/* Structure containing transaction specific information */
typedef struct _dns_transaction_t {
  guint32 req_frame;
  guint32 rep_frame;
  nstime_t req_time;
  guint id;
  gboolean multiple_responds;
} dns_transaction_t;

/* Structure containing conversation specific information */
typedef struct _dns_conv_info_t {
  wmem_tree_t *pdus;
} dns_conv_info_t;

/* DNS structs and definitions */

/* Ports used for DNS. */
#define DEFAULT_DNS_PORT_RANGE   "53"
#define DEFAULT_DNS_TCP_PORT_RANGE   "53,5353" /* Includes mDNS */
#define SCTP_PORT_DNS             53
#define UDP_PORT_MDNS           5353
#define UDP_PORT_LLMNR          5355
#define TCP_PORT_DNS_TLS         853
#define UDP_PORT_DNS_DTLS        853
#if 0
/* PPID used for DNS/SCTP (will be changed when IANA assigned) */
#define DNS_PAYLOAD_PROTOCOL_ID 1000
#endif

/* Offsets of fields in the DNS header. */
#define DNS_ID           0
#define DNS_FLAGS        2
#define DNS_QUEST        4
#define DNS_ANS          6
#define DNS_AUTH         8
#define DNS_ADD         10

/* Length of DNS header. */
#define DNS_HDRLEN      12

/* type values  */
#define T_A              1              /* host address */
#define T_NS             2              /* authoritative name server */
#define T_MD             3              /* mail destination (obsolete) */
#define T_MF             4              /* mail forwarder (obsolete) */
#define T_CNAME          5              /* canonical name */
#define T_SOA            6              /* start of authority zone */
#define T_MB             7              /* mailbox domain name (experimental) */
#define T_MG             8              /* mail group member (experimental) */
#define T_MR             9              /* mail rename domain name (experimental) */
#define T_NULL          10              /* null RR (experimental) */
#define T_WKS           11              /* well known service */
#define T_PTR           12              /* domain name pointer */
#define T_HINFO         13              /* host information */
#define T_MINFO         14              /* mailbox or mail list information */
#define T_MX            15              /* mail routing information */
#define T_TXT           16              /* text strings */
#define T_RP            17              /* responsible person (RFC 1183) */
#define T_AFSDB         18              /* AFS data base location (RFC 1183) */
#define T_X25           19              /* X.25 address (RFC 1183) */
#define T_ISDN          20              /* ISDN address (RFC 1183) */
#define T_RT            21              /* route-through (RFC 1183) */
#define T_NSAP          22              /* OSI NSAP (RFC 1706) */
#define T_NSAP_PTR      23              /* PTR equivalent for OSI NSAP (RFC 1348 - obsolete) */
#define T_SIG           24              /* digital signature (RFC 2535) */
#define T_KEY           25              /* public key (RFC 2535) */
#define T_PX            26              /* pointer to X.400/RFC822 mapping info (RFC 1664) */
#define T_GPOS          27              /* geographical position (RFC 1712) */
#define T_AAAA          28              /* IPv6 address (RFC 1886) */
#define T_LOC           29              /* geographical location (RFC 1876) */
#define T_NXT           30              /* "next" name (RFC 2535) */
#define T_EID           31              /* Endpoint Identifier */
#define T_NIMLOC        32              /* Nimrod Locator */
#define T_SRV           33              /* service location (RFC 2052) */
#define T_ATMA          34              /* ATM Address */
#define T_NAPTR         35              /* naming authority pointer (RFC 3403) */
#define T_KX            36              /* Key Exchange (RFC 2230) */
#define T_CERT          37              /* Certificate (RFC 4398) */
#define T_A6            38              /* IPv6 address with indirection (RFC 2874 - obsolete) */
#define T_DNAME         39              /* Non-terminal DNS name redirection (RFC 2672) */
#define T_SINK          40              /* SINK */
#define T_OPT           41              /* OPT pseudo-RR (RFC 2671) */
#define T_APL           42              /* Lists of Address Prefixes (APL RR) (RFC 3123) */
#define T_DS            43              /* Delegation Signer (RFC 4034) */
#define T_SSHFP         44              /* Using DNS to Securely Publish SSH Key Fingerprints (RFC 4255) */
#define T_IPSECKEY      45              /* RFC 4025 */
#define T_RRSIG         46              /* RFC 4034 */
#define T_NSEC          47              /* RFC 4034 */
#define T_DNSKEY        48              /* RFC 4034 */
#define T_DHCID         49              /* DHCID RR (RFC 4701) */
#define T_NSEC3         50              /* Next secure hash (RFC 5155) */
#define T_NSEC3PARAM    51              /* NSEC3 parameters (RFC 5155) */
#define T_TLSA          52              /* TLSA (RFC 6698) */
#define T_HIP           55              /* Host Identity Protocol (HIP) RR (RFC 5205) */
#define T_NINFO         56              /* NINFO */
#define T_RKEY          57              /* RKEY */
#define T_TALINK        58              /* Trust Anchor LINK */
#define T_CDS           59              /* Child DS (RFC7344)*/
#define T_CDNSKEY       60              /* DNSKEY(s) the Child wants reflected in DS ( [RFC7344])*/
#define T_OPENPGPKEY    61              /* OPENPGPKEY draft-ietf-dane-openpgpkey-00 */
#define T_CSYNC         62              /* Child To Parent Synchronization (RFC7477) */
#define T_ZONEMD        63              /* Message Digest for DNS Zones (RFC8976) */
#define T_SVCB          64              /* draft-ietf-dnsop-svcb-https-01 */
#define T_HTTPS         65              /* draft-ietf-dnsop-svcb-https-01 */
#define T_SPF           99              /* SPF RR (RFC 4408) section 3 */
#define T_UINFO        100              /* [IANA-Reserved] */
#define T_UID          101              /* [IANA-Reserved] */
#define T_GID          102              /* [IANA-Reserved] */
#define T_UNSPEC       103              /* [IANA-Reserved] */
#define T_NID          104              /* ILNP [RFC6742] */
#define T_L32          105              /* ILNP [RFC6742] */
#define T_L64          106              /* ILNP [RFC6742] */
#define T_LP           107              /* ILNP [RFC6742] */
#define T_EUI48        108              /* EUI 48 Address (RFC7043) */
#define T_EUI64        109              /* EUI 64 Address (RFC7043) */
#define T_TKEY         249              /* Transaction Key (RFC 2930) */
#define T_TSIG         250              /* Transaction Signature (RFC 2845) */
#define T_IXFR         251              /* incremental transfer (RFC 1995) */
#define T_AXFR         252              /* transfer of an entire zone (RFC 5936) */
#define T_MAILB        253              /* mailbox-related RRs (MB, MG or MR) (RFC 1035) */
#define T_MAILA        254              /* mail agent RRs (OBSOLETE - see MX) (RFC 1035) */
#define T_ANY          255              /* A request for all records (RFC 1035) */
#define T_URI          256              /* URI */
#define T_CAA          257              /* Certification Authority Authorization (RFC 6844) */
#define T_TA         32768              /* DNSSEC Trust Authorities */
#define T_DLV        32769              /* DNSSEC Lookaside Validation (DLV) DNS Resource Record (RFC 4431) */
#define T_WINS       65281              /* Microsoft's WINS RR */
#define T_WINS_R     65282              /* Microsoft's WINS-R RR */
#define T_XPF        65422              /* XPF draft-bellis-dnsop-xpf */

/* Class values */
#define C_IN             1              /* the Internet */
#define C_CS             2              /* CSNET (obsolete) */
#define C_CH             3              /* CHAOS */
#define C_HS             4              /* Hesiod */
#define C_NONE         254              /* none */
#define C_ANY          255              /* any */

#define C_QU            (1<<15)         /* High bit is set in queries for unicast queries */
#define C_FLUSH         (1<<15)         /* High bit is set for MDNS cache flush */

/* Bit fields in the flags */
#define F_RESPONSE      (1<<15)         /* packet is response */
#define F_OPCODE        (0xF<<11)       /* query opcode */
#define OPCODE_SHIFT    11
#define F_AUTHORITATIVE (1<<10)         /* response is authoritative */
#define F_CONFLICT      (1<<10)         /* conflict detected */
#define F_TRUNCATED     (1<<9)          /* response is truncated */
#define F_RECDESIRED    (1<<8)          /* recursion desired */
#define F_TENTATIVE     (1<<8)          /* response is tentative */
#define F_RECAVAIL      (1<<7)          /* recursion available */
#define F_Z             (1<<6)          /* Z */
#define F_AUTHENTIC     (1<<5)          /* authentic data (RFC2535) */
#define F_CHECKDISABLE  (1<<4)          /* checking disabled (RFC2535) */
#define F_RCODE         (0xF<<0)        /* reply code */

/* Optcode values for EDNS0 options (RFC 2671) */
#define O_LLQ            1              /* Long-lived query (on-hold, draft-sekar-dns-llq) */
#define O_UL             2              /* Update lease (on-hold, draft-sekar-dns-ul) */
#define O_NSID           3              /* Name Server Identifier (RFC 5001) */
#define O_OWNER          4              /* Owner, reserved (draft-cheshire-edns0-owner-option) */
#define O_DAU            5              /* DNSSEC Algorithm Understood (RFC6975) */
#define O_DHU            6              /* DS Hash Understood (RFC6975) */
#define O_N3U            7              /* NSEC3 Hash Understood (RFC6975) */
#define O_CLIENT_SUBNET  8              /* Client subnet as assigned by IANA */
#define O_EDNS_EXPIRE    9              /* EDNS Expire (RFC7314) */
#define O_CLIENT_SUBNET_EXP 0x50fa      /* Client subnet (placeholder value, draft-vandergaast-edns-client-subnet) */
#define O_COOKIE        10              /* Cookies (RFC7873) */
#define O_EDNS_TCP_KA   11              /* edns-tcp-keepalive EDNS0 Option (RFC7828) */
#define O_PADDING       12              /* EDNS(0) Padding Option (RFC7830) */
#define O_CHAIN         13              /* draft-ietf-dnsop-edns-chain-query */
#define O_EXT_ERROR     15              /* Extended DNS Errors (RFC8914) */

#define MIN_DNAME_LEN    2              /* minimum domain name length */

static const true_false_string tfs_flags_response = {
  "Message is a response",
  "Message is a query"
};

static const true_false_string tfs_flags_authoritative = {
  "Server is an authority for domain",
  "Server is not an authority for domain"
};

static const true_false_string tfs_flags_conflict_query = {
  "The sender received multiple responses",
  "None"
};

static const true_false_string tfs_flags_conflict_response = {
  "The name is not considered unique",
  "The name is considered unique"
};

static const true_false_string tfs_flags_truncated = {
  "Message is truncated",
  "Message is not truncated"
};

static const true_false_string tfs_flags_recdesired = {
  "Do query recursively",
  "Don't do query recursively"
};

static const true_false_string tfs_flags_tentative = {
  "Tentative",
  "Not tentative"
};

static const true_false_string tfs_flags_recavail = {
  "Server can do recursive queries",
  "Server can't do recursive queries"
};

static const true_false_string tfs_flags_z = {
  "reserved - incorrect!",
  "reserved (0)"
};

static const true_false_string tfs_flags_authenticated = {
  "Answer/authority portion was authenticated by the server",
  "Answer/authority portion was not authenticated by the server"
};

static const true_false_string tfs_flags_checkdisable = {
  "Acceptable",
  "Unacceptable"
};

static const true_false_string tfs_dns_rr_z_do = {
  "Accepts DNSSEC security RRs",
  "Cannot handle DNSSEC security RRs"
};

/* Opcodes */
#define OPCODE_QUERY    0         /* standard query */
#define OPCODE_IQUERY   1         /* inverse query */
#define OPCODE_STATUS   2         /* server status request */
#define OPCODE_NOTIFY   4         /* zone change notification */
#define OPCODE_UPDATE   5         /* dynamic update */
#define OPCODE_DSO      6         /* DNS stateful operations */

static const value_string opcode_vals[] = {
  { OPCODE_QUERY,  "Standard query"                },
  { OPCODE_IQUERY, "Inverse query"                 },
  { OPCODE_STATUS, "Server status request"         },
  { OPCODE_NOTIFY, "Zone change notification"      },
  { OPCODE_UPDATE, "Dynamic update"                },
  { OPCODE_DSO,    "DNS Stateful operations (DSO)" },
  { 0,              NULL                           } };

/* Reply codes */
#define RCODE_NOERROR    0
#define RCODE_FORMERR    1
#define RCODE_SERVFAIL   2
#define RCODE_NXDOMAIN   3
#define RCODE_NOTIMPL    4
#define RCODE_REFUSED    5
#define RCODE_YXDOMAIN   6
#define RCODE_YXRRSET    7
#define RCODE_NXRRSET    8
#define RCODE_NOTAUTH    9
#define RCODE_NOTZONE   10
#define RCODE_DSOTYPENI 11

#define RCODE_BAD       16
#define RCODE_BADKEY    17
#define RCODE_BADTIME   18
#define RCODE_BADMODE   19
#define RCODE_BADNAME   20
#define RCODE_BADALG    21
#define RCODE_BADTRUNC  22
#define RCODE_BADCOOKIE 23

static const value_string rcode_vals[] = {
  { RCODE_NOERROR,    "No error"                 },
  { RCODE_FORMERR,    "Format error"             },
  { RCODE_SERVFAIL,   "Server failure"           },
  { RCODE_NXDOMAIN,   "No such name"             },
  { RCODE_NOTIMPL,    "Not implemented"          },
  { RCODE_REFUSED,    "Refused"                  },
  { RCODE_YXDOMAIN,   "Name exists"              },
  { RCODE_YXRRSET,    "RRset exists"             },
  { RCODE_NXRRSET,    "RRset does not exist"     },
  { RCODE_NOTAUTH,    "Not authoritative"        },
  { RCODE_NOTZONE,    "Name out of zone"         },
  { RCODE_DSOTYPENI,  "DSO-Type not implemented" },
  /* 12-15            Unassigned */
  { RCODE_BAD,        "Bad OPT Version or TSIG Signature Failure" },
  { RCODE_BADKEY,     "Key not recognized" },
  { RCODE_BADTIME,    "Signature out of time window" },
  { RCODE_BADMODE,    "Bad TKEY Mode" },
  { RCODE_BADNAME,    "Duplicate key name" },
  { RCODE_BADALG,     "Algorithm not supported" },
  { RCODE_BADTRUNC,   "Bad Truncation" },
  { RCODE_BADCOOKIE,  "Bad/missing Server Cookie" },
  { 0,                NULL }
 };

#define NSEC3_HASH_RESERVED  0
#define NSEC3_HASH_SHA1      1

#define NSEC3_FLAG_OPTOUT    1

static const value_string hash_algorithms[] = {
  { NSEC3_HASH_RESERVED,  "Reserved"        },
  { NSEC3_HASH_SHA1,      "SHA-1"           },
  { 0,                    NULL              } };

static const true_false_string tfs_flags_nsec3_optout = {
  "Additional insecure delegations allowed",
  "Additional insecure delegations forbidden"
};
static const true_false_string tfs_required_experimental = { "Experimental or optional", "Required" };

#define TKEYMODE_SERVERASSIGNED             (1)
#define TKEYMODE_DIFFIEHELLMAN              (2)
#define TKEYMODE_GSSAPI                     (3)
#define TKEYMODE_RESOLVERASSIGNED           (4)
#define TKEYMODE_DELETE                     (5)

static const value_string tkey_mode_vals[] = {
  { TKEYMODE_SERVERASSIGNED,   "Server assigned"   },
  { TKEYMODE_DIFFIEHELLMAN,    "Diffie Hellman"    },
  { TKEYMODE_GSSAPI,           "GSSAPI"            },
  { TKEYMODE_RESOLVERASSIGNED, "Resolver assigned" },
  { TKEYMODE_DELETE,           "Delete"            },
  { 0,                         NULL                }
 };

/*
 * SSHFP (RFC 4255) algorithm number and fingerprint types
 */
#define TSSHFP_ALGO_RESERVED   (0)
#define TSSHFP_ALGO_RSA        (1)
#define TSSHFP_ALGO_DSA        (2)
#define TSSHFP_ALGO_ECDSA      (3)
#define TSSHFP_ALGO_ED25519    (4)
#define TSSHFP_ALGO_XMSS       (5)

#define TSSHFP_FTYPE_RESERVED  (0)
#define TSSHFP_FTYPE_SHA1      (1)
#define TSSHFP_FTYPE_SHA256    (2)

static const value_string sshfp_algo_vals[] = {
  { TSSHFP_ALGO_RESERVED, "Reserved" },
  { TSSHFP_ALGO_RSA,      "RSA" },
  { TSSHFP_ALGO_DSA,      "DSA" },
  { TSSHFP_ALGO_ECDSA,    "ECDSA" },
  { TSSHFP_ALGO_ED25519,  "Ed25519" },
  { TSSHFP_ALGO_XMSS,     "XMSS" },
  { 0, NULL }
};

static const value_string sshfp_fingertype_vals[] = {
  { TSSHFP_FTYPE_RESERVED,  "Reserved" },
  { TSSHFP_FTYPE_SHA1,      "SHA1" },
  { TSSHFP_FTYPE_SHA256,    "SHA256" },
  { 0, NULL }
};

/* HIP PK ALGO RFC 5205 */
#define THIP_ALGO_RESERVED     (0)
#define THIP_ALGO_DSA          (1)
#define THIP_ALGO_RSA          (2)


static const value_string hip_algo_vals[] = {
  { THIP_ALGO_DSA,       "DSA" },
  { THIP_ALGO_RSA,       "RSA" },
  { THIP_ALGO_RESERVED,  "Reserved" },
  { 0,                   NULL }
};

/* RFC 3123 */
#define DNS_APL_NEGATION       (1<<7)
#define DNS_APL_AFDLENGTH      (0x7F<<0)

static const true_false_string tfs_dns_apl_negation = {
  "Yes (!)",
  "No (0)"
};

static const value_string afamily_vals[] = {
  { AFNUM_INET,      "IPv4" },
  { AFNUM_INET6,     "IPv6" },
  { 0,               NULL  }
};

/* RFC 6844 */
#define CAA_FLAG_ISSUER_CRITICAL (1<<7)

/* See RFC 1035 for all RR types for which no RFC is listed, except for
   the ones with "???", and for the Microsoft WINS and WINS-R RRs, for
   which one should look at

http://www.windows.com/windows2000/en/server/help/sag_DNS_imp_UsingWinsLookup.htm

   and

http://www.microsoft.com/windows2000/library/resources/reskit/samplechapters/cncf/cncf_imp_wwaw.asp

   which discuss them to some extent. */
/* http://www.iana.org/assignments/dns-parameters (last updated 2015-07-26)*/

static const value_string dns_qr_vals[] = {
  { 0, "Query" },
  { 1, "Response" },
  { 0, NULL }
};
static const value_string dns_types_vals[] = {
  { 0,            "Unused"     },
  { T_A,          "A"          },
  { T_NS,         "NS"         },
  { T_MD,         "MD"         },
  { T_MF,         "MF"         },
  { T_CNAME,      "CNAME"      },
  { T_SOA,        "SOA"        },
  { T_MB,         "MB"         },
  { T_MG,         "MG"         },
  { T_MR,         "MR"         },
  { T_NULL,       "NULL"       },
  { T_WKS,        "WKS"        },
  { T_PTR,        "PTR"        },
  { T_HINFO,      "HINFO"      },
  { T_MINFO,      "MINFO"      },
  { T_MX,         "MX"         },
  { T_TXT,        "TXT"        },
  { T_RP,         "RP"         }, /* RFC 1183 */
  { T_AFSDB,      "AFSDB"      }, /* RFC 1183 */
  { T_X25,        "X25"        }, /* RFC 1183 */
  { T_ISDN,       "ISDN"       }, /* RFC 1183 */
  { T_RT,         "RT"         }, /* RFC 1183 */
  { T_NSAP,       "NSAP"       }, /* RFC 1706 */
  { T_NSAP_PTR,   "NSAP-PTR"   }, /* RFC 1348 */
  { T_SIG,        "SIG"        }, /* RFC 2535 */
  { T_KEY,        "KEY"        }, /* RFC 2535 */
  { T_PX,         "PX"         }, /* RFC 1664 */
  { T_GPOS,       "GPOS"       }, /* RFC 1712 */
  { T_AAAA,       "AAAA"       }, /* RFC 1886 */
  { T_LOC,        "LOC"        }, /* RFC 1886 */
  { T_NXT,        "NXT"        }, /* RFC 1876 */
  { T_EID,        "EID"        },
  { T_NIMLOC,     "NIMLOC"     },
  { T_SRV,        "SRV"        }, /* RFC 2052 */
  { T_ATMA,       "ATMA"       },
  { T_NAPTR,      "NAPTR"      }, /* RFC 3403 */
  { T_KX,         "KX"         }, /* RFC 2230 */
  { T_CERT,       "CERT"       }, /* RFC 4398 */
  { T_A6,         "A6"         }, /* RFC 2874 */
  { T_DNAME,      "DNAME"      }, /* RFC 2672 */
  { T_SINK,       "SINK"       },
  { T_OPT,        "OPT"        }, /* RFC 2671 */
  { T_APL,        "APL"        }, /* RFC 3123 */
  { T_DS,         "DS"         }, /* RFC 4034 */
  { T_SSHFP,      "SSHFP"      }, /* RFC 4255 */
  { T_IPSECKEY,   "IPSECKEY"   }, /* RFC 4025 */
  { T_RRSIG,      "RRSIG"      }, /* RFC 4034 */
  { T_NSEC,       "NSEC"       }, /* RFC 4034 */
  { T_DNSKEY,     "DNSKEY"     }, /* RFC 4034 */
  { T_DHCID,      "DHCID"      }, /* RFC 4701 */
  { T_NSEC3,      "NSEC3"      }, /* RFC 5155 */
  { T_NSEC3PARAM, "NSEC3PARAM" }, /* RFC 5155 */
  { T_TLSA,       "TLSA"       },
  { T_HIP,        "HIP"        }, /* RFC 5205 */
  { T_RKEY,       "RKEY"       },
  { T_TALINK,     "TALINK"     },
  { T_CDS,        "CDS"        }, /* RFC 7344 */
  { T_CDNSKEY,    "CDNSKEY"    }, /* RFC 7344*/
  { T_OPENPGPKEY, "OPENPGPKEY" }, /* draft-ietf-dane-openpgpkey */
  { T_CSYNC,      "CSYNC"      }, /* RFC 7477 */
  { T_ZONEMD,     "ZONEMD"     }, /* RFC 8976 */
  { T_SVCB,       "SVCB"       }, /* draft-ietf-dnsop-svcb-https-01 */
  { T_HTTPS,      "HTTPS"      }, /* draft-ietf-dnsop-svcb-https-01 */
  { T_SPF,        "SPF"        }, /* RFC 4408 */
  { T_UINFO,      "UINFO"      }, /* IANA reserved */
  { T_UID,        "UID"        }, /* IANA reserved */
  { T_GID,        "GID"        }, /* IANA reserved */
  { T_UNSPEC,     "UNSPEC"     }, /* IANA reserved */
  { T_NID,        "NID"        }, /* RFC 6742 */
  { T_L32,        "L32"        }, /* RFC 6742 */
  { T_L64,        "L64"        }, /* RFC 6742 */
  { T_LP,         "LP"         }, /* RFC 6742 */
  { T_EUI48,      "EUI48"      }, /* RFC 7043 */
  { T_EUI64,      "EUI64"      }, /* RFC 7043 */
  { T_TKEY,       "TKEY"       },
  { T_TSIG,       "TSIG"       },
  { T_IXFR,       "IXFR"       },
  { T_AXFR,       "AXFR"       },
  { T_MAILB,      "MAILA"      },
  { T_MAILA,      "MAILB"      },
  { T_ANY,        "ANY"        },
  { T_URI,        "URI"        },
  { T_CAA,        "CAA"        }, /* RFC 6844 */

  { T_TA,         "TA"         },
  { T_DLV,        "DLV"        }, /* RFC 4431 */

  { T_WINS,       "WINS"       },
  { T_WINS_R,     "WINS-R"     },
  { T_XPF,        "XPF"        }, /* draft-bellis-dnsop-xpf */

  {0,             NULL}
};

static value_string_ext dns_types_vals_ext = VALUE_STRING_EXT_INIT(dns_types_vals);

static const value_string dns_types_description_vals[] = {
  { 0,            "Unused" },
  { T_A,          "A (Host Address)" },
  { T_NS,         "NS (authoritative Name Server)" },
  { T_MD,         "MD (Mail Destination)" },
  { T_MF,         "MF (Mail Forwarder)" },
  { T_CNAME,      "CNAME (Canonical NAME for an alias)" },
  { T_SOA,        "SOA (Start Of a zone of Authority)" },
  { T_MB,         "MB (MailBox domain name)"},
  { T_MG,         "MG (Mail Group member)" },
  { T_MR,         "MR (Mail Rename domain)" },
  { T_NULL,       "NULL RR" },
  { T_WKS,        "WKS (Well Known Service)" },
  { T_PTR,        "PTR (domain name PoinTeR)" },
  { T_HINFO,      "HINFO (host information)" },
  { T_MINFO,      "MINFO (Mailbox or mail list information)" },
  { T_MX,         "MX (Mail eXchange)" },
  { T_TXT,        "TXT (Text strings)" },
  { T_RP,         "RP (Responsible Person)" }, /* RFC 1183 */
  { T_AFSDB,      "AFSDB (AFS Data Base location)" }, /* RFC 1183 */
  { T_X25,        "X25 (XX.25 PSDN address)" }, /* RFC 1183 */
  { T_ISDN,       "ISDN (ISDN address)" }, /* RFC 1183 */
  { T_RT,         "RT (Route Through)" }, /* RFC 1183 */
  { T_NSAP,       "NSAP (NSAP address)" },
  { T_NSAP_PTR,   "NSAP-PTR (NSAP domain name pointer)" },
  { T_SIG,        "SIG (security signature)" },
  { T_KEY,        "KEY (security key)" },
  { T_PX,         "PX (X.400 mail mapping information)" },
  { T_GPOS,       "GPOS (Geographical Position)" },
  { T_AAAA,       "AAAA (IPv6 Address)" },
  { T_LOC,        "LOC (Location Information)" },
  { T_NXT,        "NXT (Next Domain)" },
  { T_EID,        "EID (Endpoint Identifier)" },
  { T_NIMLOC,     "NIMLOC (Nimrod Locator)" },
  { T_SRV,        "SRV (Server Selection)" },
  { T_ATMA,       "ATMA (ATM Address)" },
  { T_NAPTR,      "NAPTR (Naming Authority Pointer)" },
  { T_KX,         "KX (Key Exchanger)" },
  { T_CERT,       "CERT" },
  { T_A6,         "A6 (OBSOLETE - use AAAA)" },
  { T_DNAME,      "DNAME" },
  { T_SINK,       "SINK" },
  { T_OPT,        "OPT" },
  { T_APL,        "APL" },
  { T_DS,         "DS (Delegation Signer)" },
  { T_SSHFP,      "SSHFP (SSH Key Fingerprint)" },
  { T_IPSECKEY,   "IPSECKEY" },
  { T_RRSIG,      "RRSIG (Resource Record Signature)" },
  { T_NSEC,       "NSEC (Next Secure)" },
  { T_DNSKEY,     "DNSKEY (DNS Public Key)" },
  { T_DHCID,      "DHCID" },
  { T_NSEC3,      "NSEC3" },
  { T_NSEC3PARAM, "NSEC3PARAM" },
  { T_TLSA,       "TLSA" },
  { T_HIP,        "HIP (Host Identity Protocol)" }, /* RFC 5205 */
  { T_RKEY,       "RKEY" },
  { T_TALINK,     "TALINK (Trust Anchor LINK)" },
  { T_CDS,        "CDS (Child DS)" }, /* RFC 7344 */
  { T_CDNSKEY,    "CDNSKEY (DNSKEY(s) the Child wants reflected in DS)" }, /* RFC 7344 */
  { T_OPENPGPKEY, "OPENPGPKEY (OpenPGP Key)" }, /* draft-ietf-dane-openpgpkey */
  { T_CSYNC,      "CSYNC (Child-to-Parent Synchronization)" }, /* RFC 7477 */
  { T_ZONEMD,     "ZONEMD" }, /* RFC 8976 */
  { T_SVCB,       "SVCB (General Purpose Service Endpoints)" }, /*  draft-ietf-dnsop-svcb-https*/
  { T_HTTPS,      "HTTPS (HTTPS Specific Service Endpoints)" }, /*  draft-ietf-dnsop-svcb-https*/
  { T_SPF,        "SPF" }, /* RFC 4408 */
  { T_UINFO,      "UINFO" }, /* IANA reserved */
  { T_UID,        "UID" }, /* IANA reserved */
  { T_GID,        "GID" }, /* IANA reserved */
  { T_UNSPEC,     "UNSPEC" }, /* IANA reserved */
  { T_NID,        "NID (NodeID)" },
  { T_L32,        "L32 (Locator32)" },
  { T_L64,        "L64 (Locator64)" },
  { T_LP,         "LP (Locator FQDN)" },
  { T_EUI48,      "EUI48" },
  { T_EUI64,      "EUI64" },

  { T_TKEY,       "TKEY (Transaction Key)"  },
  { T_TSIG,       "TSIG (Transaction Signature)" },
  { T_IXFR,       "IXFR (incremental transfer)" },
  { T_AXFR,       "AXFR (transfer of an entire zone)" },
  { T_MAILB,      "MAILB (mailbox-related RRs)" },
  { T_MAILA,      "MAILA (mail agent RRs)" },
  { T_ANY,        "* (A request for all records the server/cache has available)" },
  { T_URI,        "URI" },
  { T_CAA,        "CAA (Certification Authority Restriction)" }, /* RFC 6844 */
  { T_TA,         "TA (DNSSEC Trust Authorities)" },
  { T_DLV,        "DLV (DNSSEC Lookaside Validation)" }, /* RFC 4431 */

  { T_WINS,       "WINS" },
  { T_WINS_R,     "WINS-R" },
  { T_XPF,        "XPF" }, /* draft-bellis-dnsop-xpf */

  {0,             NULL}
};

static value_string_ext dns_types_description_vals_ext = VALUE_STRING_EXT_INIT(dns_types_description_vals);

static const value_string edns0_opt_code_vals[] = {
  {0,            "Reserved"},
  {O_LLQ,        "LLQ - Long-lived query"},
  {O_UL,         "UL - Update lease"},
  {O_NSID,       "NSID - Name Server Identifier"},
  {O_OWNER,      "Owner (reserved)"},
  {O_DAU,        "DAU - DNSSEC Algorithm Understood (RFC6975)"},
  {O_DHU,        "DHU - DS Hash Understood (RFC6975)"},
  {O_N3U,        "N3U - NSEC3 Hash Understood (RFC6975)"},
  {O_CLIENT_SUBNET_EXP, "Experimental - CSUBNET - Client subnet" },
  {O_CLIENT_SUBNET, "CSUBNET - Client subnet" },
  {O_EDNS_EXPIRE, "EDNS EXPIRE (RFC7314)"},
  {O_COOKIE,      "COOKIE"},
  {O_EDNS_TCP_KA, "EDNS TCP Keepalive"},
  {O_PADDING,     "PADDING"},
  {O_CHAIN,       "CHAIN"},
  {O_EXT_ERROR,   "Extended DNS Error"},
  {0,             NULL}
 };
/* DNS-Based Authentication of Named Entities (DANE) Parameters
   http://www.iana.org/assignments/dane-parameters (last updated 2014-04-23)
 */
/* TLSA Certificate Usages */
#define TLSA_CU_PKIX_TA 0
#define TLSA_CU_PKIX_EE 1
#define TLSA_CU_DANE_TA 2
#define TLSA_CU_DANE_EE 3

static const value_string tlsa_certificate_usage_vals[] = {
  {TLSA_CU_PKIX_TA, "CA constraint (PKIX-TA)"},
  {TLSA_CU_PKIX_EE, "Service certificate constraint (PKIX-EE)"},
  {TLSA_CU_DANE_TA, "Trust anchor assertion (DANE-TA)"},
  {TLSA_CU_DANE_EE, "Domain-issued certificate (DANE-EE)"},
  {0,            NULL}
};

/* TLSA Selectors */
#define TLSA_S_CERT 0
#define TLSA_S_SPKI 1

static const value_string tlsa_selector_vals[] = {
  {TLSA_S_CERT, "Full certificate (Cert)"},
  {TLSA_S_SPKI, "SubjectPublicKeyInfo (SPKI)"},
  {0,            NULL}
};

/* TLSA Matching Types */
#define TLSA_MT_FULL 0
#define TLSA_MT_SHA_256 1
#define TLSA_MT_SHA_512 2

static const value_string tlsa_matching_type_vals[] = {
  {TLSA_MT_FULL, "No Hash Used (Full)"},
  {TLSA_MT_SHA_256, "256 bit hash by SHA2 (SHA2-256)"},
  {TLSA_MT_SHA_512, "512 bit hash by SHA2 (SHA2-512)"},
  {0,            NULL}
};

/* IPSECKEY RFC4025 */
static const value_string gw_algo_vals[] = {
  { 1,     "DSA" },
  { 2,     "RSA" },
  { 0,      NULL }
};

static const value_string gw_type_vals[] = {
  { 0,     "No Gateway" },
  { 1,     "IPv4 Gateway" },
  { 2,     "IPv6 Gateway" },
  { 3,     "DNS Gateway" },
  { 0,      NULL }
};

const value_string dns_classes[] = {
  {C_IN,   "IN"},
  {C_CS,   "CS"},
  {C_CH,   "CH"},
  {C_HS,   "HS"},
  {C_NONE, "NONE"},
  {C_ANY,  "ANY"},
  {0,NULL}
};

/* DSO Type Opcodes RFC8490 */
#define DSO_TYPE_RES          0x0000         /* RFC8490 */
#define DSO_TYPE_KEEPALIVE    0x0001         /* RFC8490 */
#define DSO_TYPE_RETRYDELAY   0x0002         /* RFC8490 */
#define DSO_TYPE_ENCPAD       0x0003         /* RFC8490 */
#define DSO_TYPE_SUBSCRIBE    0x0040         /* RF8765 */
#define DSO_TYPE_PUSH         0x0041         /* RF8765 */
#define DSO_TYPE_UNSUBSCRIBE  0x0042         /* RF8765 */
#define DSO_TYPE_RECONFIRM    0x0043         /* RF8765 */

static const range_string dns_dso_type_rvals[] = {
  { DSO_TYPE_RES,         DSO_TYPE_RES,         "Reserved" },
  { DSO_TYPE_KEEPALIVE,   DSO_TYPE_KEEPALIVE,   "Keep Alive" },
  { DSO_TYPE_RETRYDELAY,  DSO_TYPE_RETRYDELAY,  "Retry Delay" },
  { DSO_TYPE_ENCPAD,      DSO_TYPE_ENCPAD,      "Encryption Padding" },
  { 0x0004,               0x003F,               "Unassigned, reserved for DSO session-management TLVs" },
  { DSO_TYPE_SUBSCRIBE,   DSO_TYPE_SUBSCRIBE,   "Subscribe" },
  { DSO_TYPE_PUSH,        DSO_TYPE_PUSH,        "Push" },
  { DSO_TYPE_UNSUBSCRIBE, DSO_TYPE_UNSUBSCRIBE, "Unsubscribe" },
  { DSO_TYPE_RECONFIRM,   DSO_TYPE_RECONFIRM,   "Reconfirm" },
  { 0x0044,               0xF7FF,               "Unassigned" },
  { 0xF800,               0xFBFF,               "Reserved for Experimental/Local Use" },
  { 0xFC00,               0xFFFF,               "Reserved for future expansion" },
  { 0, 0, NULL }
};

#define DNS_SVCB_KEY_MANDATORY        0
#define DNS_SVCB_KEY_ALPN             1
#define DNS_SVCB_KEY_NOALPN           2
#define DNS_SVCB_KEY_PORT             3
#define DNS_SVCB_KEY_IPV4HINT         4
#define DNS_SVCB_KEY_ECHCONFIG        5
#define DNS_SVCB_KEY_IPV6HINT         6
#define DNS_SVCB_KEY_ODOHCONFIG   32769 /* draft-pauly-dprive-oblivious-doh-02 */
#define DNS_SVCB_KEY_RESERVED     65535

/**
 * Service Binding (SVCB) Parameter Registry.
 * https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-01#section-12.3.2
 */
static const value_string dns_svcb_param_key_vals[] = {
  { DNS_SVCB_KEY_MANDATORY,     "mandatory" },
  { DNS_SVCB_KEY_ALPN,          "alpn" },
  { DNS_SVCB_KEY_NOALPN,        "no-default-alpn" },
  { DNS_SVCB_KEY_PORT,          "port" },
  { DNS_SVCB_KEY_IPV4HINT,      "ipv4hint" },
  { DNS_SVCB_KEY_ECHCONFIG,     "echconfig" },
  { DNS_SVCB_KEY_IPV6HINT,      "ipv6hint" },
  { DNS_SVCB_KEY_ODOHCONFIG,    "odohconfig" },
  { DNS_SVCB_KEY_RESERVED,      "key65535" },
  { 0,                          NULL }
};

static int * const dns_csync_flags[] = {
    &hf_dns_csync_flags_immediate,
    &hf_dns_csync_flags_soaminimum,
    NULL
};

#define DNS_ZONEMD_SCHEME_SIMPLE  1

static const range_string dns_zonemd_scheme[] = {
  {                        0,                         0, "Reserved"     },
  { DNS_ZONEMD_SCHEME_SIMPLE,  DNS_ZONEMD_SCHEME_SIMPLE, "SIMPLE"       },
  {                        2,                       239, "Unassigned"   },
  {                      240,                       254, "Private Use"  },
  {                      255,                       255, "Reserved"     },
  {                        0,                         0, NULL           } };

#define DNS_ZONEMD_HASH_SHA384  1
#define DNS_ZONEMD_HASH_SHA512  2

static const range_string dns_zonemd_hash_algo[] = {
  {                      0,                       0, "Reserved"     },
  { DNS_ZONEMD_HASH_SHA384,  DNS_ZONEMD_HASH_SHA384, "SHA-384"      },
  { DNS_ZONEMD_HASH_SHA512,  DNS_ZONEMD_HASH_SHA512, "SHA-512"      },
  {                      3,                     239, "Unassigned"   },
  {                    240,                     254, "Private Use"  },
  {                    255,                     255, "Reserved"     },
  {                      0,                       0, NULL           } };

static const range_string dns_ext_err_info_code[] = {
  {     0,     0, "Other Error"        },
  {     1,     1, "Unsupported DNSKEY Algorithm" },
  {     2,     2, "Unsupported DS Digest Type"   },
  {     3,     3, "Stale Answer"                 },
  {     4,     4, "Forged Answer"                },
  {     5,     5, "DNSSEC Indeterminate"         },
  {     6,     6, "DNSSEC Bogus"                 },
  {     7,     7, "Signature Expired"            },
  {     8,     8, "Signature Not Yet Valid"      },
  {     9,     9, "DNSKEY Missing"               },
  {    10,    10, "RRSIGs Missing"               },
  {    11,    11, "No Zone Key Bit Set"          },
  {    12,    12, "NSEC Missing"                 },
  {    13,    13, "Cached Error"                 },
  {    14,    14, "Not Ready"                    },
  {    15,    15, "Blocked"                      },
  {    16,    16, "Censored"                     },
  {    17,    17, "Filtered"                     },
  {    18,    18, "Prohibited"                   },
  {    19,    19, "Stale NXDomain Answer"        },
  {    20,    20, "Not Authoritative"            },
  {    21,    21, "Not Supported"                },
  {    22,    22, "No Reachable Authority"       },
  {    23,    23, "Network Error"                },
  {    24,    24, "Invalid Data"                 },
  {    25, 49151, "Unassigned"                   },
  { 49152, 65535, "Reserved for Private Use"     },
  {     0,     0, NULL                           } };


/* This function counts how many '.' are in the string, plus 1, in order to count the number
 * of labels
 */
static guint
qname_labels_count(const gchar* name, gint name_len)
{
    guint labels = 0;
    gint i;

    if (name_len > 1) {
        /* it was not a Zero-length name */
        for (i = 0; i < name_len; i++) {
            if (name[i] == '.')
                labels++;
        }
        labels++;
    }
    return labels;
}

/* This function returns the number of bytes consumed and the expanded string
 * in *name.
 * The string is allocated with wmem_packet_scope scope and does not need to be freed.
 * it will be automatically freed when the packet has been dissected.
 */
static int
expand_dns_name(tvbuff_t *tvb, int offset, int max_len, int dns_data_offset,
    const gchar **name, gint* name_len)
{
  int     start_offset    = offset;
  gchar  *np;
  int     len             = -1;
  int     pointers_count  = 0;
  int     component_len;
  int     indir_offset;
  int     maxname;

  const int min_len = 1;        /* Minimum length of encoded name (for root) */
        /* If we're about to return a value (probably negative) which is less
         * than the minimum length, we're looking at bad data and we're liable
         * to put the dissector into a loop.  Instead we throw an exception */

  maxname = MAX_DNAME_LEN;
  np=(gchar *)wmem_alloc(wmem_packet_scope(), maxname);
  *name=np;
  (*name_len) = 0;

  for (;;) {
    if (max_len && offset - start_offset > max_len - 1) {
      break;
    }
    component_len = tvb_get_guint8(tvb, offset);
    offset++;
    if (component_len == 0) {
      break;
    }
    switch (component_len & 0xc0) {

      case 0x00:
        /* Label */
        if (np != *name) {
          /* Not the first component - put in a '.'. */
          if (maxname > 0) {
            *np++ = '.';
            (*name_len)++;
            maxname--;
          }
        }
        else {
          maxname--;
        }
        while (component_len > 0) {
          if (max_len && offset - start_offset > max_len - 1) {
            THROW(ReportedBoundsError);
          }
          if (maxname > 0) {
            *np++ = tvb_get_guint8(tvb, offset);
            (*name_len)++;
            maxname--;
          }
          component_len--;
          offset++;
        }
        break;

      case 0x40:
        /* Extended label (RFC 2673) */
        switch (component_len & 0x3f) {

          case 0x01:
            /* Bitstring label */
          {
            int bit_count;
            int label_len;
            int print_len;

            bit_count = tvb_get_guint8(tvb, offset);
            offset++;
            label_len = (bit_count - 1) / 8 + 1;

            if (maxname > 0) {
              print_len = snprintf(np, maxname, "\\[x");
              if (print_len <= maxname) {
                np      += print_len;
                maxname -= print_len;
              } else {
                /* Nothing printed, as there's no room.
                   Suppress all subsequent printing. */
                maxname = 0;
              }
            }
            while (label_len--) {
              if (maxname > 0) {
                print_len = snprintf(np, maxname, "%02x",
                                       tvb_get_guint8(tvb, offset));
                if (print_len <= maxname) {
                  np      += print_len;
                  maxname -= print_len;
                } else {
                  /* Nothing printed, as there's no room.
                     Suppress all subsequent printing. */
                  maxname = 0;
                }
              }
              offset++;
            }
            if (maxname > 0) {
              print_len = snprintf(np, maxname, "/%d]", bit_count);
              if (print_len <= maxname) {
                np      += print_len;
                maxname -= print_len;
              } else {
                /* Nothing printed, as there's no room.
                   Suppress all subsequent printing. */
                maxname = 0;
              }
            }
          }
          break;

          default:
            *name="<Unknown extended label>";
            *name_len = (guint)strlen(*name);
            /* Parsing will probably fail from here on, since the */
            /* label length is unknown... */
            len = offset - start_offset;
            if (len < min_len) {
              THROW(ReportedBoundsError);
            }
            return len;
        }
        break;

      case 0x80:
        THROW(ReportedBoundsError);
        break;

      case 0xc0:
        /* Pointer. */
        indir_offset = dns_data_offset +
          (((component_len & ~0xc0) << 8) | tvb_get_guint8(tvb, offset));
        offset++;
        pointers_count++;

        /* If "len" is negative, we are still working on the original name,
           not something pointed to by a pointer, and so we should set "len"
           to the length of the original name. */
        if (len < 0) {
          len = offset - start_offset;
        }
        /*
         * If we find a pointer to itself, it is a trivial loop. Otherwise if we
         * processed a large number of pointers, assume an indirect loop.
         */
        if (indir_offset == offset + 2 || pointers_count > MAX_DNAME_LEN) {
          *name="<Name contains a pointer that loops>";
          *name_len = (guint)strlen(*name);
          if (len < min_len) {
            THROW(ReportedBoundsError);
          }
          return len;
        }

        offset = indir_offset;
        break;   /* now continue processing from there */
    }
  }

  // Do we have space for the terminating 0?
  if (maxname > 0) {
    *np = '\0';
  }
  else {
    *name="<Name too long>";
    *name_len = (guint)strlen(*name);
  }

  /* If "len" is negative, we haven't seen a pointer, and thus haven't
     set the length, so set it. */
  if (len < 0) {
    len = offset - start_offset;
  }

  return len;
}

/* return the bytes in the tvb consumed by the function. The converted string (that
   can contain null bytes, is written in name and its length in name_len. */
int
get_dns_name(tvbuff_t *tvb, int offset, int max_len, int dns_data_offset,
    const gchar **name, gint* name_len)
{
  int len;

  len = expand_dns_name(tvb, offset, max_len, dns_data_offset, name, name_len);

  /* Zero-length name means "root server" */
  if (**name == '\0' && len <= MIN_DNAME_LEN) {
    *name="<Root>";
    *name_len = (gint)strlen(*name);
    return len;
  }

  if ((len < MIN_DNAME_LEN) || (len > MIN_DNAME_LEN && *name_len == 0)) {
    THROW(ReportedBoundsError);
  }

  return len;
}

static int
get_dns_name_type_class(tvbuff_t *tvb, int offset, int dns_data_offset,
    const gchar **name, int *name_len, guint16 *type, guint16 *dns_class)
{
  int start_offset = offset;

  offset += get_dns_name(tvb, offset, 0, dns_data_offset, name, name_len);

  *type = tvb_get_ntohs(tvb, offset);
  offset += 2;

  *dns_class = tvb_get_ntohs(tvb, offset);
  offset += 2;

  return offset - start_offset;
}

static double
rfc1867_size(tvbuff_t *tvb, int offset)
{
  guint8  val;
  double  size;
  guint32 exponent;

  val = tvb_get_guint8(tvb, offset);
  size = (val & 0xF0) >> 4;
  exponent = (val & 0x0F);
  while (exponent != 0) {
    size *= 10;
    exponent--;
  }
  return size / 100;  /* return size in meters, not cm */
}

static char *
rfc1867_angle(tvbuff_t *tvb, int offset, gboolean longitude)
{
  guint32     angle;
  char        direction;
  guint32     degrees, minutes, secs, tsecs;
              /* "%u deg %u min %u.%03u sec %c" */
  static char buf[10+1+3+1 + 2+1+3+1 + 2+1+3+1+3+1 + 1 + 1];

  angle = tvb_get_ntohl(tvb, offset);

  if (angle < 0x80000000U) {
    angle = 0x80000000U - angle;
    direction = longitude ? 'W' : 'S';
  } else {
    angle = angle - 0x80000000U;
    direction = longitude ? 'E' : 'N';
  }

  if (longitude ? (angle > 648000000) : (angle > 324000000))
  {
    snprintf(buf, sizeof(buf), "Value out of range");
    return buf;
  }

  tsecs = angle % 1000;
  angle = angle / 1000;
  secs = angle % 60;
  angle = angle / 60;
  minutes = angle % 60;
  degrees = angle / 60;

  snprintf(buf, sizeof(buf), "%u deg %u min %u.%03u sec %c", degrees, minutes, secs,
             tsecs, direction);
  return buf;
}

static int
dissect_dns_query(tvbuff_t *tvb, int offset, int dns_data_offset,
  packet_info *pinfo, proto_tree *dns_tree, gboolean is_mdns,
  gboolean *is_multiple_responds)
{
  int           used_bytes;
  const gchar  *name;
  gchar        *name_out;
  int           name_len;
  guint16       type;
  guint16       dns_class;
  int           qu;
  const char   *type_name;
  int           data_start;
  guint16       labels;
  proto_tree   *q_tree;
  proto_item   *tq;

  data_start = offset;

  used_bytes = get_dns_name_type_class(tvb, offset, dns_data_offset, &name, &name_len,
    &type, &dns_class);

  if (is_mdns) {
    /* Split the QU flag and the class */
    qu = dns_class & C_QU;
    dns_class &= ~C_QU;
  } else {
    qu = 0;
  }

  if (type == T_AXFR || type == T_IXFR) {
    *is_multiple_responds = TRUE;
  }

  type_name = val_to_str_ext(type, &dns_types_vals_ext, "Unknown (%d)");

  /*
   * The name might contain octets that aren't printable characters,
   * format it for display.
   */
  name_out = format_text(wmem_packet_scope(), (const guchar *)name, name_len);

  col_append_fstr(pinfo->cinfo, COL_INFO, " %s %s", type_name, name_out);
  if (is_mdns) {
    col_append_fstr(pinfo->cinfo, COL_INFO, ", \"%s\" question", qu ? "QU" : "QM");
  }
  if (dns_tree != NULL) {
    q_tree = proto_tree_add_subtree_format(dns_tree, tvb, offset, used_bytes, ett_dns_qd, &tq, "%s: type %s, class %s",
                             name_out, type_name, val_to_str_const(dns_class, dns_classes, "Unknown"));
    if (is_mdns) {
      proto_item_append_text(tq, ", \"%s\" question", qu ? "QU" : "QM");
    }

    /* The number of used bytes for qname is the total used bytes minus 2 bytes for qtype and 2 bytes for qclass */
    proto_tree_add_string(q_tree, hf_dns_qry_name, tvb, offset, used_bytes - 4, name_out);

    tq = proto_tree_add_uint(q_tree, hf_dns_qry_name_len, tvb, offset, used_bytes - 4, name_len > 1 ? name_len : 0);
    proto_item_set_generated(tq);

    labels = qname_labels_count(name, name_len);
    tq = proto_tree_add_uint(q_tree, hf_dns_count_labels, tvb, offset, used_bytes - 4, labels);
    proto_item_set_generated(tq);

    offset += used_bytes - 4;

    proto_tree_add_item(q_tree, hf_dns_qry_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (is_mdns) {
      proto_tree_add_uint(q_tree, hf_dns_qry_class_mdns, tvb, offset, 2, dns_class);
      proto_tree_add_boolean(q_tree, hf_dns_qry_qu, tvb, offset, 2, qu);
    } else {
      proto_tree_add_uint(q_tree, hf_dns_qry_class, tvb, offset, 2, dns_class);
    }

    offset += 2;
  }

  if (data_start + used_bytes != offset) {
    /* Add expert info ? (about incorrect len...)*/
  }
  return used_bytes;
}


static void
add_rr_to_tree(proto_tree  *rr_tree, tvbuff_t *tvb, int offset,
  const gchar *name, int namelen, int type,
  packet_info *pinfo, gboolean is_mdns)
{
  guint32     ttl_value;
  proto_item *ttl_item;
  gchar      **srv_rr_info;

  if (type == T_SRV && name[0]) {
    srv_rr_info = wmem_strsplit(wmem_packet_scope(), name, ".", 3);

    proto_tree_add_string(rr_tree, hf_dns_srv_service, tvb, offset,
                          namelen, srv_rr_info[0]);

    if (srv_rr_info[1]) {
      proto_tree_add_string(rr_tree, hf_dns_srv_proto, tvb, offset,
                            namelen, srv_rr_info[1]);

      if (srv_rr_info[2]) {
        proto_tree_add_string(rr_tree, hf_dns_srv_name, tvb, offset,
                              namelen, srv_rr_info[2]);
      }
    }
  } else {
    proto_tree_add_string(rr_tree, hf_dns_rr_name, tvb, offset, namelen, name);
  }

  offset += namelen;

  proto_tree_add_item(rr_tree, hf_dns_rr_type, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  if (is_mdns) {
    proto_tree_add_item(rr_tree, hf_dns_rr_class_mdns, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(rr_tree, hf_dns_rr_cache_flush, tvb, offset, 2, ENC_BIG_ENDIAN);
  } else {
    proto_tree_add_item(rr_tree, hf_dns_rr_class, tvb, offset, 2, ENC_BIG_ENDIAN);
  }
  offset += 2;
  ttl_item = proto_tree_add_item_ret_uint(rr_tree, hf_dns_rr_ttl, tvb, offset, 4, ENC_BIG_ENDIAN, &ttl_value);
  proto_item_append_text(ttl_item, " (%s)", unsigned_time_secs_to_str(wmem_packet_scope(), ttl_value));
  if (ttl_value & 0x80000000) {
    expert_add_info(pinfo, ttl_item, &ei_ttl_high_bit_set);
  }

  offset += 4;
  proto_tree_add_item(rr_tree, hf_dns_rr_len, tvb, offset, 2, ENC_BIG_ENDIAN);
}


static void
add_opt_rr_to_tree(proto_tree  *rr_tree, tvbuff_t *tvb, int offset,
  const char *name, int namelen, gboolean is_mdns)
{
  proto_tree *Z_tree;
  proto_item *Z_item;

  proto_tree_add_string(rr_tree, hf_dns_rr_name, tvb, offset, namelen, name);
  offset += namelen;
  proto_tree_add_item(rr_tree, hf_dns_rr_type, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  if (is_mdns) {
    proto_tree_add_item(rr_tree, hf_dns_rr_udp_payload_size_mdns, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(rr_tree, hf_dns_rr_cache_flush, tvb, offset, 2, ENC_BIG_ENDIAN);
  } else {
    proto_tree_add_item(rr_tree, hf_dns_rr_udp_payload_size, tvb, offset, 2, ENC_BIG_ENDIAN);
  }
  offset += 2;
  proto_tree_add_item(rr_tree, hf_dns_rr_ext_rcode, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;
  proto_tree_add_item(rr_tree, hf_dns_rr_edns0_version, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;
  Z_item = proto_tree_add_item(rr_tree, hf_dns_rr_z, tvb, offset, 2, ENC_BIG_ENDIAN);
  Z_tree = proto_item_add_subtree(Z_item, ett_dns_rr);
  proto_tree_add_item(Z_tree, hf_dns_rr_z_do, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(Z_tree, hf_dns_rr_z_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(rr_tree, hf_dns_rr_len, tvb, offset, 2, ENC_BIG_ENDIAN);
}

static int
dissect_type_bitmap(proto_tree *rr_tree, tvbuff_t *tvb, int cur_offset, int rr_len)
{
  int    mask, blockbase, blocksize;
  int    i, initial_offset, rr_type;
  guint8 bits;

  initial_offset = cur_offset;
  while (rr_len != 0) {
    blockbase = tvb_get_guint8(tvb, cur_offset);
    blocksize = tvb_get_guint8(tvb, cur_offset + 1);
    cur_offset += 2;
    rr_len     -= 2;
    rr_type = blockbase * 256;
    for( ; blocksize; blocksize-- ) {
      bits = tvb_get_guint8(tvb, cur_offset);
      mask = 1<<7;
      for (i = 0; i < 8; i++) {
        if (bits & mask) {
          proto_tree_add_uint_format(rr_tree, hf_dns_rr_type, tvb, cur_offset, 1, rr_type,
            "RR type in bit map: %s",
            val_to_str_ext(rr_type, &dns_types_description_vals_ext, "Unknown (%d)"));
        }
        mask >>= 1;
        rr_type++;
      }
      cur_offset += 1;
      rr_len     -= 1;
    }
  }
  return(initial_offset - cur_offset);
}

static int
dissect_type_bitmap_nxt(proto_tree *rr_tree, tvbuff_t *tvb, int cur_offset, int rr_len)
{
  int    mask;
  int    i, initial_offset, rr_type;
  guint8 bits;

  initial_offset = cur_offset;
  rr_type = 0;
  while (rr_len != 0) {
    bits = tvb_get_guint8(tvb, cur_offset);
    mask = 1<<7;
    for (i = 0; i < 8; i++) {
      if (bits & mask) {
          proto_tree_add_uint_format(rr_tree, hf_dns_rr_type, tvb, cur_offset, 1, rr_type,
            "RR type in bit map: %s",
            val_to_str_ext(rr_type, &dns_types_description_vals_ext, "Unknown (%d)"));
        }
      mask >>= 1;
      rr_type++;
      }
    cur_offset += 1;
    rr_len     -= 1;
  }

  return(initial_offset - cur_offset);
}
/*
 * SIG, KEY, and CERT RR algorithms.
 * http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.txt (last updated 2017-01-09)
 */
#define DNS_ALGO_RSAMD5               1 /* RSA/MD5 */
#define DNS_ALGO_DH                   2 /* Diffie-Hellman */
#define DNS_ALGO_DSA                  3 /* DSA */
#define DNS_ALGO_ECC                  4 /* Elliptic curve crypto */
#define DNS_ALGO_RSASHA1              5 /* RSA/SHA1 */
#define DNS_ALGO_DSA_NSEC3_SHA1       6 /* DSA + NSEC3/SHA1 */
#define DNS_ALGO_RSASHA1_NSEC3_SHA1   7 /* RSA/SHA1 + NSEC3/SHA1 */
#define DNS_ALGO_RSASHA256            8 /* RSA/SHA-256 */
#define DNS_ALGO_RSASHA512           10 /* RSA/SHA-512 */
#define DNS_ALGO_ECCGOST             12 /* GOST R 34.10-2001 */
#define DNS_ALGO_ECDSAP256SHA256     13 /* ECDSA Curve P-256 with SHA-256 */
#define DNS_ALGO_ECDSAP386SHA386     14 /* ECDSA Curve P-386 with SHA-386 */
#define DNS_ALGO_ED25519             15 /* Ed25519 */
#define DNS_ALGO_ED448               16 /* Ed448 */
#define DNS_ALGO_HMACMD5            157 /* HMAC/MD5 */
#define DNS_ALGO_INDIRECT           252 /* Indirect key */
#define DNS_ALGO_PRIVATEDNS         253 /* Private, domain name  */
#define DNS_ALGO_PRIVATEOID         254 /* Private, OID */

static const value_string dnssec_algo_vals[] = {
  { DNS_ALGO_RSAMD5,            "RSA/MD5" },
  { DNS_ALGO_DH,                "Diffie-Hellman" },
  { DNS_ALGO_DSA,               "DSA" },
  { DNS_ALGO_ECC,               "Elliptic curve crypto" },
  { DNS_ALGO_RSASHA1,           "RSA/SHA1" },
  { DNS_ALGO_DSA_NSEC3_SHA1,    "DSA + NSEC3/SHA1" },
  { DNS_ALGO_RSASHA1_NSEC3_SHA1,"RSA/SHA1 + NSEC3/SHA1" },
  { DNS_ALGO_RSASHA256,         "RSA/SHA-256" },
  { DNS_ALGO_RSASHA512,         "RSA/SHA-512" },
  { DNS_ALGO_ECCGOST,           "GOST R 34.10-2001" },
  { DNS_ALGO_ECDSAP256SHA256,   "ECDSA Curve P-256 with SHA-256" },
  { DNS_ALGO_ECDSAP386SHA386,   "ECDSA Curve P-386 with SHA-386" },
  { DNS_ALGO_ED25519,           "Ed25519" },
  { DNS_ALGO_ED448,             "Ed448" },
  { DNS_ALGO_HMACMD5,           "HMAC/MD5" },
  { DNS_ALGO_INDIRECT,          "Indirect key" },
  { DNS_ALGO_PRIVATEDNS,        "Private, domain name" },
  { DNS_ALGO_PRIVATEOID,        "Private, OID" },
  { 0,                          NULL }
};

/*
Delegation Signer (DS) Resource Record (RR) Type Digest Algorithms
https://www.iana.org/assignments/ds-rr-types/ds-rr-types.txt (last-updated 2012-04-13)
*/
#define DS_DIGEST_RESERVED  0
#define DS_DIGEST_SHA1      1 /* MANDATORY [RFC3658] */
#define DS_DIGEST_SHA256    2 /* MANDATORY [RFC4509] */
#define DS_DIGEST_GOST      3 /* OPTIONAL  [RFC5933] */
#define DS_DIGEST_SHA384    4 /*OPTIONAL  [RFC6605] */

static const value_string dns_ds_digest_vals[] = {
  { DS_DIGEST_RESERVED, "Reserved digest" },
  { DS_DIGEST_SHA1,     "SHA-1" },
  { DS_DIGEST_SHA256,   "SHA-256" },
  { DS_DIGEST_GOST,     "GOST R 34.11-94" },
  { DS_DIGEST_SHA384,   "SHA-384" },
  { 0, NULL }
};
/* DNSKEY : RFC4034 */
#define DNSKEY_FLAGS_ZK 0x0100
#define DNSKEY_FLAGS_KR 0x0080
#define DNSKEY_FLAGS_SEP 0x0001
#define DNSKEY_FLAGS_RSV 0xFE7E

static const true_false_string dns_dnskey_zone_key_tfs = { "This is the zone key for specified zone", "This it not a zone key" };

/* See RFC 4398 */
#define DNS_CERT_PKIX             1     /* X509 certificate */
#define DNS_CERT_SPKI             2     /* Simple public key certificate */
#define DNS_CERT_PGP              3     /* OpenPGP packet */
#define DNS_CERT_IPKIX            4     /* Indirect PKIX */
#define DNS_CERT_ISPKI            5     /* Indirect SPKI */
#define DNS_CERT_IPGP             6     /* Indirect PGP */
#define DNS_CERT_ACPKIX           7     /* Attribute certificate */
#define DNS_CERT_IACPKIX          8     /* Indirect ACPKIX */
#define DNS_CERT_PRIVATEURI     253     /* Private, URI */
#define DNS_CERT_PRIVATEOID     254     /* Private, OID */

static const value_string dns_cert_type_vals[] = {
  { DNS_CERT_PKIX,       "PKIX" },
  { DNS_CERT_SPKI,       "SPKI" },
  { DNS_CERT_PGP,        "PGP" },
  { DNS_CERT_IPKIX,      "IPKIX" },
  { DNS_CERT_ISPKI,      "ISPKI" },
  { DNS_CERT_IPGP,       "IPGP" },
  { DNS_CERT_ACPKIX,     "ACPKIX" },
  { DNS_CERT_IACPKIX,    "IACPKIX" },
  { DNS_CERT_PRIVATEURI, "Private, URI" },
  { DNS_CERT_PRIVATEOID, "Private, OID" },
  { 0,                   NULL }
};

/**
 *   Compute the key id of a KEY RR depending of the algorithm used.
 */
static gboolean
compute_key_id(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int size, guint8 algo, guint16 *key_id)
{
  guint32 ac;
  guint8  c1, c2;

  if (size < 4) {
    proto_item *item;
    *key_id = 0;
    item = proto_tree_add_expert(tree, pinfo, &ei_dns_key_id_buffer_too_short, tvb, offset, size);
    proto_item_set_generated(item);
    return FALSE;
  }

  switch( algo ) {
     case DNS_ALGO_RSAMD5:
       *key_id = (guint16)(tvb_get_guint8(tvb, offset + size - 3) << 8) + tvb_get_guint8( tvb, offset + size - 2 );
       break;
     default:
       for (ac = 0; size > 1; size -= 2, offset += 2) {
         c1 = tvb_get_guint8( tvb, offset );
         c2 = tvb_get_guint8( tvb, offset + 1 );
         ac +=  (c1 << 8) + c2 ;
       }
       if (size > 0) {
         c1 = tvb_get_guint8( tvb, offset );
         ac += c1 << 8;
       }
       ac += (ac >> 16) & 0xffff;
       *key_id = (guint16)(ac & 0xffff);
       break;
  }
  return TRUE;
}

/* Dissect a SvbParam where the presentation format of the value is base64. */
static void
dissect_dns_svcparam_base64(proto_tree *param_tree, proto_item *param_item, int hf_id, tvbuff_t *tvb, int offset, guint length)
{
  gchar *str = g_base64_encode((guint8 *)tvb_memdup(wmem_packet_scope(), tvb, offset, length), length);
  proto_tree_add_bytes_format_value(param_tree, hf_id, tvb, offset, length, NULL, "%s", str);
  proto_item_append_text(param_item, "=%s", str);
  g_free(str);
}


static int
dissect_dns_answer(tvbuff_t *tvb, int offsetx, int dns_data_offset,
  proto_tree *dns_tree, packet_info *pinfo,
  gboolean is_mdns)
{
  const gchar  *name;
  gchar        *name_out;
  int           name_len;
  guint16       dns_type;
  guint16       dns_class;
  int           flush;
  const char   *class_name;
  const char   *type_name;
  int           data_offset;
  int           cur_offset;
  int           data_start;
  gushort       data_len;
  proto_tree   *rr_tree = NULL;
  proto_item   *trr     = NULL;
  guint         used_bytes;

  data_start = data_offset = offsetx;
  cur_offset = offsetx;

  used_bytes = get_dns_name_type_class(tvb, offsetx, dns_data_offset, &name, &name_len,
                                &dns_type, &dns_class);

  /* The offset if the total used bytes minus 2 bytes for qtype and 2 bytes for qclass */
  data_offset += used_bytes;
  cur_offset += used_bytes;
  if (is_mdns) {
    /* Split the FLUSH flag and the class */
    flush = dns_class & C_FLUSH;
    dns_class &= ~C_FLUSH;
  } else {
    flush = 0;
  }
  type_name = val_to_str_ext(dns_type, &dns_types_vals_ext, "Unknown (%d)");
  class_name = val_to_str_const(dns_class, dns_classes, "Unknown");

  data_offset += 4;
  cur_offset += 4;

  data_len = tvb_get_ntohs(tvb, data_offset);

  data_offset += 2;
  cur_offset  += 2;

  col_append_fstr(pinfo->cinfo, COL_INFO, " %s", type_name);
  if (is_mdns && flush) {
    col_append_str(pinfo->cinfo, COL_INFO, ", cache flush");
  }

  if (dns_tree != NULL) {
    /*
     * The name might contain octets that aren't printable characters,
     * format it for display.
     */
    name_out = format_text(wmem_packet_scope(), (const guchar*)name, name_len);
    if (dns_type != T_OPT) {
      rr_tree = proto_tree_add_subtree_format(dns_tree, tvb, offsetx,
                                (data_offset - data_start) + data_len,
                                ett_dns_rr, &trr, "%s: type %s, class %s",
                                name_out, type_name, class_name);
      add_rr_to_tree(rr_tree, tvb, offsetx, name_out, used_bytes - 4,
                               dns_type, pinfo, is_mdns);
    } else  {
      rr_tree = proto_tree_add_subtree_format(dns_tree, tvb, offsetx,
                                (data_offset - data_start) + data_len,
                                ett_dns_rr, &trr, "%s: type %s", name_out, type_name);
      add_opt_rr_to_tree(rr_tree, tvb, offsetx, name_out, used_bytes - 4, is_mdns);
    }
    if (is_mdns && flush) {
      proto_item_append_text(trr, ", cache flush");
    }
  }

  if (data_len == 0) {
    return data_offset - data_start;
  }

  switch (dns_type) {

    case T_A: /* a host Address (1) */
    {
      const char *addr;

      addr = tvb_ip_to_str(pinfo->pool, tvb, cur_offset);
      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", addr);

      proto_item_append_text(trr, ", addr %s", addr);
      proto_tree_add_item(rr_tree, hf_dns_a, tvb, cur_offset, 4, ENC_BIG_ENDIAN);

      if (gbl_resolv_flags.dns_pkt_addr_resolution && (dns_class & 0x7f) == C_IN &&
          !PINFO_FD_VISITED(pinfo)) {
        guint32 addr_int;
        tvb_memcpy(tvb, &addr_int, cur_offset, sizeof(addr_int));
        add_ipv4_name(addr_int, name);
      }
    }
    break;

    case T_NS: /* an authoritative Name Server (2) */
    {
      const gchar *ns_name;
      int ns_name_len;

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &ns_name, &ns_name_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)ns_name, ns_name_len);
      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name_out);
      proto_item_append_text(trr, ", ns %s", name_out);
      proto_tree_add_string(rr_tree, hf_dns_ns, tvb, cur_offset, used_bytes, name_out);

    }
    break;

    case T_MD: /* Mail Destination  (3) */
    {
      int           hostname_len;
      const gchar  *hostname_str;

      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &hostname_str, &hostname_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)hostname_str, hostname_len);
      proto_tree_add_string(rr_tree, hf_dns_md, tvb, cur_offset, used_bytes, name_out);
    }
    break;

    case T_MF: /* Mail Forwader  (4) */
    {
      int           hostname_len;
      const gchar  *hostname_str;

      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &hostname_str, &hostname_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)hostname_str, hostname_len);
      proto_tree_add_string(rr_tree, hf_dns_mf, tvb, cur_offset, used_bytes, name_out);
    }
    break;

    case T_CNAME: /* the Canonical NAME for an alias (5) */
    {
      const gchar *cname;
      int cname_len;

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &cname, &cname_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)cname, cname_len);
      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name_out);
      proto_item_append_text(trr, ", cname %s", name_out);
      proto_tree_add_string(rr_tree, hf_dns_cname, tvb, cur_offset, used_bytes, name_out);

    }
    break;

    case T_SOA: /* Start Of Authority zone (6) */
    {
      const gchar  *mname;
      int           mname_len;
      const gchar  *rname;
      int           rname_len;
      proto_item   *ti_soa;

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &mname, &mname_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)mname, mname_len);
      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name_out);
      proto_item_append_text(trr, ", mname %s", name_out);
      proto_tree_add_string(rr_tree, hf_dns_soa_mname, tvb, cur_offset, used_bytes, name_out);
      cur_offset += used_bytes;

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &rname, &rname_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)rname, rname_len);
      proto_tree_add_string(rr_tree, hf_dns_soa_rname, tvb, cur_offset, used_bytes, name_out);
      cur_offset += used_bytes;

      proto_tree_add_item(rr_tree, hf_dns_soa_serial_number, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
      cur_offset += 4;

      ti_soa = proto_tree_add_item(rr_tree, hf_dns_soa_refresh_interval, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
      proto_item_append_text(ti_soa, " (%s)", unsigned_time_secs_to_str(wmem_packet_scope(), tvb_get_ntohl(tvb, cur_offset)));
      cur_offset += 4;

      ti_soa = proto_tree_add_item(rr_tree, hf_dns_soa_retry_interval, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
      proto_item_append_text(ti_soa, " (%s)", unsigned_time_secs_to_str(wmem_packet_scope(), tvb_get_ntohl(tvb, cur_offset)));
      cur_offset += 4;

      ti_soa = proto_tree_add_item(rr_tree, hf_dns_soa_expire_limit, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
      proto_item_append_text(ti_soa, " (%s)", unsigned_time_secs_to_str(wmem_packet_scope(), tvb_get_ntohl(tvb, cur_offset)));
      cur_offset += 4;

      ti_soa = proto_tree_add_item(rr_tree, hf_dns_soa_minimum_ttl, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
      proto_item_append_text(ti_soa, " (%s)", unsigned_time_secs_to_str(wmem_packet_scope(), tvb_get_ntohl(tvb, cur_offset)));
    }
    break;

    case T_MB: /* MailBox domain (7) */
    {
      int           hostname_len;
      const gchar  *hostname_str;

      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &hostname_str, &hostname_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)hostname_str, hostname_len);
      proto_tree_add_string(rr_tree, hf_dns_mb, tvb, cur_offset, used_bytes, name_out);
    }
    break;

    case T_MG: /* Mail Group member (8) */
    {
      int           hostname_len;
      const gchar  *hostname_str;

      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &hostname_str, &hostname_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)hostname_str, hostname_len);
      proto_tree_add_string(rr_tree, hf_dns_mg, tvb, cur_offset, used_bytes, name_out);
    }
    break;

    case T_MR: /* Mail Rename domain (9) */
    {
      int           hostname_len;
      const gchar  *hostname_str;

      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &hostname_str, &hostname_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)hostname_str, hostname_len);
      proto_tree_add_string(rr_tree, hf_dns_mr, tvb, cur_offset, used_bytes, name_out);
    }
    break;

    case T_NULL: /* Null (10) */
    {
      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);
      proto_tree_add_item(rr_tree, hf_dns_null, tvb, cur_offset, data_len, ENC_NA);
    }
    break;

    case T_WKS: /* Well Known Service (11) */
    {
      int            rr_len   = data_len;
      const char    *wks_addr;
      guint8         protocol;
      guint8         bits;
      int            mask;
      int            port_num;
      int            i;
      proto_item     *ti_wks;
      wmem_strbuf_t *bitnames = wmem_strbuf_new_label(wmem_packet_scope());

      wks_addr = tvb_ip_to_str(pinfo->pool, tvb, cur_offset);
      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", wks_addr);
      proto_item_append_text(trr, ", addr %s", wks_addr);
      proto_tree_add_item(rr_tree, hf_dns_wks_address, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
      cur_offset += 4;
      rr_len     -= 4;

      proto_tree_add_item(rr_tree, hf_dns_wks_protocol, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      protocol = tvb_get_guint8(tvb, cur_offset);
      cur_offset += 1;
      rr_len     -= 1;

      port_num = 0;
      while (rr_len != 0) {
        bits = tvb_get_guint8(tvb, cur_offset);
        if (bits != 0) {
          mask = 1<<7;
          wmem_strbuf_truncate(bitnames, 0);
          for (i = 0; i < 8; i++) {
            if (bits & mask) {
              if (wmem_strbuf_get_len(bitnames) > 0) {
                wmem_strbuf_append(bitnames, ", ");
              }
              switch (protocol) {

                case IP_PROTO_TCP:
                  wmem_strbuf_append(bitnames, tcp_port_to_display(wmem_packet_scope(), port_num));
                  break;

                case IP_PROTO_UDP:
                  wmem_strbuf_append(bitnames, udp_port_to_display(wmem_packet_scope(), port_num));
                  break;

                default:
                  wmem_strbuf_append_printf(bitnames, "%u", port_num);
                  break;
              }
            }
            mask >>= 1;
            port_num++;
          }

          ti_wks = proto_tree_add_item(rr_tree, hf_dns_wks_bits, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
          proto_item_append_text(ti_wks, " (%s)", wmem_strbuf_get_str(bitnames));
        } else {
          port_num += 8;
        }
        cur_offset += 1;
        rr_len     -= 1;
      }
    }
    break;

    case T_PTR: /* Domain Name Pointer (12) */
    {
      const gchar  *pname;
      int           pname_len;

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &pname, &pname_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)pname, pname_len);
      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name_out);
      proto_item_append_text(trr, ", %s", name_out);
      proto_tree_add_string(rr_tree, hf_dns_ptr_domain_name, tvb, cur_offset, used_bytes, name_out);

    }
    break;

    case T_HINFO: /* Host Information (13) */
    {
      int         cpu_offset;
      int         cpu_len;
      const char *cpu;
      int         os_offset;
      int         os_len;
      const char *os;

      cpu_offset = cur_offset;
      cpu_len = tvb_get_guint8(tvb, cpu_offset);
      cpu = (const char* )tvb_get_string_enc(wmem_packet_scope(), tvb, cpu_offset + 1, cpu_len, ENC_ASCII|ENC_NA);
      os_offset = cpu_offset + 1 + cpu_len;
      os_len = tvb_get_guint8(tvb, os_offset);
      os = (const char*)tvb_get_string_enc(wmem_packet_scope(), tvb, os_offset + 1, os_len, ENC_ASCII|ENC_NA);
      col_append_fstr(pinfo->cinfo, COL_INFO, " %.*s %.*s", cpu_len, cpu, os_len, os);
      proto_item_append_text(trr, ", CPU %.*s, OS %.*s", cpu_len, cpu, os_len, os);

      proto_tree_add_item(rr_tree, hf_dns_hinfo_cpu_length, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset += 1;
      proto_tree_add_item(rr_tree, hf_dns_hinfo_cpu, tvb, cur_offset, cpu_len, ENC_ASCII);
      cur_offset += cpu_len;

      proto_tree_add_item(rr_tree, hf_dns_hinfo_os_length, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset += 1;
      proto_tree_add_item(rr_tree, hf_dns_hinfo_os, tvb, cur_offset, os_len, ENC_ASCII);
      /* cur_offset += os_len;*/
    }
    break;

    case T_MINFO: /* Mailbox or Mail list INFOrmation (14) */
    {
      int rmailbx_len, emailbx_len;
      const gchar *rmailbx_str, *emailbx_str;

      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &rmailbx_str, &rmailbx_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)rmailbx_str, rmailbx_len);
      proto_tree_add_string(rr_tree, hf_dns_minfo_r_mailbox, tvb, cur_offset, used_bytes, name_out);
      cur_offset += used_bytes;

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &emailbx_str, &emailbx_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)emailbx_str, emailbx_len);
      proto_tree_add_string(rr_tree, hf_dns_minfo_e_mailbox, tvb, cur_offset, used_bytes, name_out);
    }
    break;

    case T_MX: /* Mail eXchange (15) */
    {
      guint16       preference = 0;
      const gchar  *mx_name;
      int           mx_name_len;

      preference = tvb_get_ntohs(tvb, cur_offset);

      used_bytes = get_dns_name(tvb, cur_offset + 2, 0, dns_data_offset, &mx_name, &mx_name_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)mx_name, mx_name_len);
      col_append_fstr(pinfo->cinfo, COL_INFO, " %u %s", preference, name_out);
      proto_item_append_text(trr, ", preference %u, mx %s",
                             preference, name_out);
      proto_tree_add_item(rr_tree, hf_dns_mx_preference, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      cur_offset += 2;
      proto_tree_add_string(rr_tree, hf_dns_mx_mail_exchange, tvb, cur_offset, used_bytes, name_out);
      /* cur_offset += used_bytes; */
    }
    break;

    case T_TXT: /* TeXT strings (16) */
    {
      int rr_len = data_len;
      int txt_offset;
      int txt_len;

      txt_offset = cur_offset;
      while (rr_len != 0) {
        txt_len = tvb_get_guint8(tvb, txt_offset);
        proto_tree_add_item(rr_tree, hf_dns_txt_length, tvb, txt_offset, 1, ENC_BIG_ENDIAN);
        txt_offset += 1;
        rr_len     -= 1;
        proto_tree_add_item(rr_tree, hf_dns_txt, tvb, txt_offset, txt_len, is_mdns ? ENC_UTF_8|ENC_NA : ENC_ASCII|ENC_NA);
        txt_offset +=  txt_len;
        rr_len     -= txt_len;
      }
    }
    break;

    case T_RP: /* Responsible Person (17) */
    {
      int           mbox_dname_len, txt_dname_len;
      const gchar  *mbox_dname, *txt_dname;

      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &mbox_dname, &mbox_dname_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)mbox_dname, mbox_dname_len);
      proto_tree_add_string(rr_tree, hf_dns_rp_mailbox, tvb, cur_offset, used_bytes, name_out);
      cur_offset += used_bytes;

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &txt_dname, &txt_dname_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)txt_dname, txt_dname_len);
      proto_tree_add_string(rr_tree, hf_dns_rp_txt_rr, tvb, cur_offset, used_bytes, name_out);
    }
    break;

    case T_AFSDB: /* AFS data base location (18) */
    {
      const gchar  *host_name;
      int           host_name_len;

      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);

      used_bytes = get_dns_name(tvb, cur_offset + 2, 0, dns_data_offset, &host_name, &host_name_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)host_name, host_name_len);

      proto_tree_add_item(rr_tree, hf_dns_afsdb_subtype, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      cur_offset += 2;

      proto_tree_add_string(rr_tree, hf_dns_afsdb_hostname, tvb, cur_offset, used_bytes, name_out);
    }
    break;

    case T_X25: /* X.25 address (19) */
    {
      guint8 x25_len;

      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);

      proto_tree_add_item(rr_tree, hf_dns_x25_length, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      x25_len = tvb_get_guint8(tvb, cur_offset);
      cur_offset += 1;

      proto_tree_add_item(rr_tree, hf_dns_x25_psdn_address, tvb, cur_offset, x25_len, ENC_ASCII);
      /*cur_offset += x25_len;*/
    }
    break;

    case T_ISDN: /* ISDN address (20) */
    {
      guint8 isdn_address_len, isdn_sa_len;
      int    rr_len = data_len;

      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);

      proto_tree_add_item(rr_tree, hf_dns_isdn_length, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      isdn_address_len = tvb_get_guint8(tvb, cur_offset);
      cur_offset += 1;
      rr_len     -= 1;

      proto_tree_add_item(rr_tree, hf_dns_isdn_address, tvb, cur_offset, isdn_address_len, ENC_ASCII);
      cur_offset += isdn_address_len;
      rr_len     -= isdn_address_len;

      if (rr_len > 1)   /* ISDN SA is optional */ {
        proto_tree_add_item(rr_tree, hf_dns_isdn_sa_length, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
        isdn_sa_len = tvb_get_guint8(tvb, cur_offset);
        cur_offset += 1;

        proto_tree_add_item(rr_tree, hf_dns_isdn_sa, tvb, cur_offset, isdn_sa_len, ENC_ASCII);
      }
    }
    break;

    case T_RT: /* Route-Through (21) */
    {
      const gchar  *host_name;
      int           host_name_len;

      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);

      used_bytes = get_dns_name(tvb, cur_offset + 2, 0, dns_data_offset, &host_name, &host_name_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)host_name, host_name_len);

      proto_tree_add_item(rr_tree, hf_dns_rt_preference, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      cur_offset += 2;

      proto_tree_add_string(rr_tree, hf_dns_rt_intermediate_host, tvb, cur_offset, used_bytes, name_out);
    }
    break;

    case T_NSAP: /* for NSAP address, NSAP style A record (22) */
    {
      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);
      proto_tree_add_item(rr_tree, hf_dns_nsap_rdata, tvb, cur_offset, data_len, ENC_NA);
    }
    break;

    case T_NSAP_PTR: /* for domain name pointer, NSAP style (23) */
    {
      int           nsap_ptr_owner_len;
      const gchar  *nsap_ptr_owner;

      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &nsap_ptr_owner, &nsap_ptr_owner_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)nsap_ptr_owner, nsap_ptr_owner_len);
      proto_tree_add_string(rr_tree, hf_dns_nsap_ptr_owner, tvb, cur_offset, used_bytes, name_out);
    }
    break;


    case T_KEY: /* Public Key (25) */
    {
      int         rr_len = data_len;
      guint16     flags;
      proto_item *tf, *ti_gen;
      proto_tree *flags_tree;
      guint8      algo;
      guint16     key_id;

      tf = proto_tree_add_item(rr_tree, hf_dns_key_flags, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      flags_tree = proto_item_add_subtree(tf, ett_key_flags);
      flags = tvb_get_ntohs(tvb, cur_offset);

      proto_tree_add_item(flags_tree, hf_dns_key_flags_authentication, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(flags_tree, hf_dns_key_flags_confidentiality, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      if ((flags & 0xC000) != 0xC000) {
        /* We have a key */
        proto_tree_add_item(flags_tree, hf_dns_key_flags_key_required, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(flags_tree, hf_dns_key_flags_associated_user, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(flags_tree, hf_dns_key_flags_associated_named_entity, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(flags_tree, hf_dns_key_flags_ipsec, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(flags_tree, hf_dns_key_flags_mime, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(flags_tree, hf_dns_key_flags_signatory, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      }
      cur_offset += 2;
      rr_len     -= 2;

      proto_tree_add_item(rr_tree, hf_dns_key_protocol, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset += 1;
      rr_len     -= 1;

      proto_tree_add_item(rr_tree, hf_dns_key_algorithm, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      algo = tvb_get_guint8(tvb, cur_offset);
      cur_offset += 1;
      rr_len     -= 1;

      if (compute_key_id(rr_tree, pinfo, tvb, cur_offset-4, rr_len+4, algo, &key_id)) {
        ti_gen = proto_tree_add_uint(rr_tree, hf_dns_key_key_id, tvb, 0, 0, key_id);
        proto_item_set_generated(ti_gen);
      }

      if (rr_len != 0) {
        proto_tree_add_item(rr_tree, hf_dns_key_public_key, tvb, cur_offset, rr_len, ENC_NA);
      }
    }
    break;

    case T_PX: /* Pointer to X.400/RFC822 mapping info (26)*/
    {
      gint           px_map822_len, px_mapx400_len;
      const gchar *px_map822_dnsname, *px_mapx400_dnsname;

      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);
      proto_tree_add_item(rr_tree, hf_dns_px_preference, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      cur_offset += 2;

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &px_map822_dnsname, &px_map822_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)px_map822_dnsname, px_map822_len);
      proto_tree_add_string(rr_tree, hf_dns_px_map822, tvb, cur_offset, used_bytes, name_out);
      cur_offset += used_bytes;

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &px_mapx400_dnsname, &px_mapx400_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)px_mapx400_dnsname, px_mapx400_len);
      proto_tree_add_string(rr_tree, hf_dns_px_mapx400, tvb, cur_offset, used_bytes, name_out);
      /*cur_offset += used_bytes;*/
    }
    break;

    case T_GPOS: /* Geographical POSition (27) */
    {
      guint8 long_len, lat_len, alt_len;

      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);
      proto_tree_add_item(rr_tree, hf_dns_gpos_longitude_length, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      long_len = tvb_get_guint8(tvb, cur_offset);
      cur_offset += 1;

      proto_tree_add_item(rr_tree, hf_dns_gpos_longitude, tvb, cur_offset, long_len, ENC_ASCII);
      cur_offset += long_len;

      proto_tree_add_item(rr_tree, hf_dns_gpos_latitude_length, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      lat_len = tvb_get_guint8(tvb, cur_offset);
      cur_offset += 1;

      proto_tree_add_item(rr_tree, hf_dns_gpos_latitude, tvb, cur_offset, lat_len, ENC_ASCII);
      cur_offset += lat_len;

      proto_tree_add_item(rr_tree, hf_dns_gpos_altitude_length, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      alt_len = tvb_get_guint8(tvb, cur_offset);
      cur_offset += 1;

      proto_tree_add_item(rr_tree, hf_dns_gpos_altitude, tvb, cur_offset, alt_len, ENC_ASCII);
      /*cur_offset += alt_len;*/
    }
    break;

    case T_AAAA: /* IPv6 Address (28) */
    {
      const char        *addr6;

      addr6 = tvb_ip6_to_str(pinfo->pool, tvb, cur_offset);
      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", addr6);

      proto_item_append_text(trr, ", addr %s", addr6);
      proto_tree_add_item(rr_tree, hf_dns_aaaa, tvb, cur_offset, 16, ENC_NA);

      if (gbl_resolv_flags.dns_pkt_addr_resolution && (dns_class & 0x7f) == C_IN &&
          !PINFO_FD_VISITED(pinfo)) {
        ws_in6_addr  addr_in6;
        tvb_memcpy(tvb, &addr_in6, cur_offset, sizeof(addr_in6));
        add_ipv6_name(&addr_in6, name);
      }
    }
    break;

    case T_LOC: /* Geographical Location (29) */
    {
      guint8 version;
      proto_item *ti;

      version = tvb_get_guint8(tvb, cur_offset);
      proto_tree_add_item(rr_tree, hf_dns_loc_version, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      if (version == 0) {
        /* Version 0, the only version RFC 1876 discusses. */
        cur_offset++;

        ti = proto_tree_add_item(rr_tree, hf_dns_loc_size, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, " (%g m)", rfc1867_size(tvb, cur_offset));
        cur_offset++;

        ti = proto_tree_add_item(rr_tree, hf_dns_loc_horizontal_precision, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, " (%g m)", rfc1867_size(tvb, cur_offset));
        cur_offset++;

        ti = proto_tree_add_item(rr_tree, hf_dns_loc_vertical_precision, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, " (%g m)", rfc1867_size(tvb, cur_offset));
        cur_offset++;

        ti = proto_tree_add_item(rr_tree, hf_dns_loc_latitude, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, " (%s)", rfc1867_angle(tvb, cur_offset, FALSE));
        cur_offset += 4;

        ti = proto_tree_add_item(rr_tree, hf_dns_loc_longitude, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, " (%s)", rfc1867_angle(tvb, cur_offset, TRUE));
        cur_offset += 4;

        ti = proto_tree_add_item(rr_tree, hf_dns_loc_altitude, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, " (%g m)", (tvb_get_ntohil(tvb, cur_offset) - 10000000)/100.0);
      } else {
        proto_tree_add_item(rr_tree, hf_dns_loc_unknown_data, tvb, cur_offset, data_len, ENC_NA);
      }
    }
    break;

    case T_NXT: /* Next name (30) */
    {
      int           rr_len = data_len;
      const gchar  *next_domain_name;
      int           next_domain_name_len;

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset,
                                &next_domain_name, &next_domain_name_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)next_domain_name, next_domain_name_len);
      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name_out);
      proto_item_append_text(trr, ", next domain name %s", name_out);
      proto_tree_add_string(rr_tree, hf_dns_nxt_next_domain_name, tvb, cur_offset, used_bytes, name_out);
      cur_offset += used_bytes;
      rr_len     -= used_bytes;
      dissect_type_bitmap_nxt(rr_tree, tvb, cur_offset, rr_len);
    }
    break;

    case T_SRV: /* Service Location (33) */
    {
      guint16       priority = 0;
      guint16       weight   = 0;
      guint16       port     = 0;
      const gchar  *target;
      int           target_len;

      proto_tree_add_item(rr_tree, hf_dns_srv_priority, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      priority = tvb_get_ntohs(tvb, cur_offset);
      cur_offset += 2;

      proto_tree_add_item(rr_tree, hf_dns_srv_weight, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      weight = tvb_get_ntohs(tvb, cur_offset);
      cur_offset += 2;

      proto_tree_add_item(rr_tree, hf_dns_srv_port, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      port = tvb_get_ntohs(tvb, cur_offset);
      cur_offset += 2;

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &target, &target_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)target, target_len);

      proto_tree_add_string(rr_tree, hf_dns_srv_target, tvb, cur_offset, used_bytes, name_out);

      col_append_fstr(pinfo->cinfo, COL_INFO, " %u %u %u %s", priority, weight, port, name_out);
      proto_item_append_text(trr,
                             ", priority %u, weight %u, port %u, target %s",
                             priority, weight, port, name_out);
    }
    break;

    case T_NAPTR: /*  Naming Authority PoinTeR (35) */
    {
      proto_item    *ti_len;
      int           offset = cur_offset;
      guint16       order;
      guint16       preference;
      const guint8 *flags;
      guint8        flags_len;
      guint8        service_len;
      guint8        regex_len;
      const gchar  *replacement;
      int           replacement_len;

      /* Order */
      proto_tree_add_item(rr_tree, hf_dns_naptr_order, tvb, offset, 2, ENC_BIG_ENDIAN);
      order = tvb_get_ntohs(tvb, offset);
      offset += 2;

      /* Preference */
      proto_tree_add_item(rr_tree, hf_dns_naptr_preference, tvb, offset, 2, ENC_BIG_ENDIAN);
      preference = tvb_get_ntohs(tvb, offset);
      offset += 2;

       /* Flags */
      proto_tree_add_item(rr_tree, hf_dns_naptr_flags_length, tvb, offset, 1, ENC_BIG_ENDIAN);
      flags_len = tvb_get_guint8(tvb, offset);
      offset += 1;
      proto_tree_add_item_ret_string(rr_tree, hf_dns_naptr_flags, tvb, offset, flags_len, ENC_ASCII|ENC_NA, wmem_packet_scope(), &flags);
      offset += flags_len;

      /* Service */
      proto_tree_add_item(rr_tree, hf_dns_naptr_service_length, tvb, offset, 1, ENC_BIG_ENDIAN);
      service_len = tvb_get_guint8(tvb, offset);
      offset += 1;
      proto_tree_add_item(rr_tree, hf_dns_naptr_service, tvb, offset, service_len, ENC_ASCII);
      offset += service_len;

      /* Regex */
      proto_tree_add_item(rr_tree, hf_dns_naptr_regex_length, tvb, offset, 1, ENC_BIG_ENDIAN);
      regex_len = tvb_get_guint8(tvb, offset);
      offset += 1;
      proto_tree_add_item(rr_tree, hf_dns_naptr_regex, tvb, offset, regex_len, ENC_ASCII);
      offset += regex_len;

      /* Replacement */
      used_bytes = get_dns_name(tvb, offset, 0, dns_data_offset, &replacement, &replacement_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)replacement, replacement_len);
      ti_len = proto_tree_add_uint(rr_tree, hf_dns_naptr_replacement_length, tvb, offset, 0, replacement_len);
      proto_item_set_generated(ti_len);

      proto_tree_add_string(rr_tree, hf_dns_naptr_replacement, tvb, offset, used_bytes, name_out);

      col_append_fstr(pinfo->cinfo, COL_INFO, " %u %u %s", order, preference, flags);

      proto_item_append_text(trr, ", order %u, preference %u, flags %s",
                             order, preference, flags);
    }
    break;

    case T_KX: /* Key Exchange (36) */
    {
      const gchar  *kx_name;
      int           kx_name_len;

      used_bytes = get_dns_name(tvb, cur_offset + 2, 0, dns_data_offset, &kx_name, &kx_name_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)kx_name, kx_name_len);
      col_append_fstr(pinfo->cinfo, COL_INFO, " %u %s", tvb_get_ntohs(tvb, cur_offset), name_out);
      proto_item_append_text(trr, ", preference %u, kx %s",
                             tvb_get_ntohs(tvb, cur_offset), name_out);
      proto_tree_add_item(rr_tree, hf_dns_kx_preference, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      proto_tree_add_string(rr_tree, hf_dns_kx_key_exchange, tvb, cur_offset + 2, used_bytes, name_out);
    }
    break;

    case T_CERT: /* Certificate (37) */
    {
      int     rr_len = data_len;

      proto_tree_add_item(rr_tree, hf_dns_cert_type, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      cur_offset += 2;
      rr_len     -= 2;

      proto_tree_add_item(rr_tree, hf_dns_cert_key_tag, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      cur_offset += 2;
      rr_len     -= 2;

      proto_tree_add_item(rr_tree, hf_dns_cert_algorithm, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset += 1;
      rr_len     -= 1;

      if (rr_len != 0) {
        proto_tree_add_item(rr_tree, hf_dns_cert_certificate, tvb, cur_offset, rr_len, ENC_NA);
      }
    }
    break;

    case T_A6: /* IPv6 address with indirection (38) Obso */
    {
      unsigned short     pre_len;
      unsigned short     suf_len;
      unsigned short     suf_octet_count;
      const gchar       *pname;
      int                pname_len;
      int                a6_offset;
      int                suf_offset;
      ws_in6_addr  suffix;
      address            suffix_addr;

      a6_offset = cur_offset;
      pre_len = tvb_get_guint8(tvb, cur_offset);
      cur_offset++;
      suf_len = 128 - pre_len;
      suf_octet_count = suf_len ? (suf_len - 1) / 8 + 1 : 0;
      /* Pad prefix */
      for (suf_offset = 0; suf_offset < 16 - suf_octet_count; suf_offset++) {
        suffix.bytes[suf_offset] = 0;
      }
      for (; suf_offset < 16; suf_offset++) {
        suffix.bytes[suf_offset] = tvb_get_guint8(tvb, cur_offset);
        cur_offset++;
      }

      if (pre_len > 0) {
        used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset,
                                  &pname, &pname_len);
      } else {
        pname = "";
        pname_len = 0;
      }
      name_out = format_text(wmem_packet_scope(), (const guchar*)pname, pname_len);

      set_address(&suffix_addr, AT_IPv6, 16, suffix.bytes);
      col_append_fstr(pinfo->cinfo, COL_INFO, " %d %s %s",
                      pre_len,
                      address_to_str(wmem_packet_scope(), &suffix_addr),
                      name_out);

      proto_tree_add_item(rr_tree, hf_dns_a6_prefix_len,tvb, a6_offset, 1, ENC_BIG_ENDIAN);
      a6_offset++;
      if (suf_len) {
        proto_tree_add_ipv6(rr_tree, hf_dns_a6_address_suffix,tvb, a6_offset, suf_octet_count, &suffix);
        a6_offset += suf_octet_count;
      }
      if (pre_len > 0) {
        proto_tree_add_string(rr_tree, hf_dns_a6_prefix_name, tvb, a6_offset, used_bytes, name_out);
      }
      proto_item_append_text(trr, ", addr %d %s %s",
                             pre_len,
                             address_to_str(wmem_packet_scope(), &suffix_addr),
                             name_out);
    }
    break;

    case T_DNAME: /* Non-terminal DNS name redirection (39) */
    {
      const gchar  *dname;
      int           dname_len;

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset,
                               &dname, &dname_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)dname, dname_len);
      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name_out);
      proto_item_append_text(trr, ", dname %s", name_out);
      proto_tree_add_string(rr_tree, hf_dns_dname, tvb, cur_offset, used_bytes, name_out);
    }
    break;

    case T_OPT: /* Option (41) */
    {
      int rropt_len = data_len;
      guint16 optcode, optlen;
      proto_item *rropt, *rroptlen;
      proto_tree *rropt_tree;

      while (rropt_len > 0) {
        optcode = tvb_get_ntohs(tvb, cur_offset);
        rropt_len -= 2;

        optlen = tvb_get_ntohs(tvb, cur_offset + 2);
        rropt_len -= 2;

        rropt = proto_tree_add_item(rr_tree, hf_dns_opt, tvb, cur_offset, 4 + optlen, ENC_NA);
        proto_item_append_text(rropt, ": %s", val_to_str(optcode, edns0_opt_code_vals, "Unknown (%d)"));
        rropt_tree = proto_item_add_subtree(rropt, ett_dns_opts);
        rropt = proto_tree_add_item(rropt_tree, hf_dns_opt_code, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        cur_offset += 2;
        rroptlen = proto_tree_add_item(rropt_tree, hf_dns_opt_len, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        cur_offset += 2;

        proto_tree_add_item(rropt_tree, hf_dns_opt_data, tvb, cur_offset, optlen, ENC_NA);
        switch(optcode) {

          case O_DAU: /* DNSSEC Algorithm Understood (RFC6975) */
          {
            while (optlen != 0) {
              proto_tree_add_item(rropt_tree, hf_dns_opt_dau, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
              cur_offset += 1;
              rropt_len  -= 1;
              optlen -= 1;
            }
          }
          break;

          case O_DHU: /* DS Hash Understood (RFC6975) */
          {
            while (optlen != 0) {
              proto_tree_add_item(rropt_tree, hf_dns_opt_dhu, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
              cur_offset += 1;
              rropt_len  -= 1;
              optlen -= 1;
            }
          }
          break;

          case O_N3U: /* N3SEC Hash Understood (RFC6975) */
          {
            while (optlen != 0) {
              proto_tree_add_item(rropt_tree, hf_dns_opt_n3u, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
              cur_offset += 1;
              rropt_len  -= 1;
              optlen -= 1;
            }
          }
          break;

          case O_CLIENT_SUBNET_EXP: /* draft-vandergaast-edns-client-subnet */
             expert_add_info_format(pinfo, rropt, &ei_dns_depr_opc,
                "Deprecated opcode. Client subnet OPT assigned as %d.", O_CLIENT_SUBNET);
             /* Intentional fall-through */

          case O_CLIENT_SUBNET:
          {
            guint16 family;
            guint16 addr_len = optlen - 4;
            union {
              guint32 addr;
              guint8 bytes[16];
            } ip_addr = {0};

            family = tvb_get_ntohs(tvb, cur_offset);
            proto_tree_add_item(rropt_tree, hf_dns_opt_client_family, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
            cur_offset += 2;
            proto_tree_add_item(rropt_tree, hf_dns_opt_client_netmask, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
            cur_offset += 1;
            proto_tree_add_item(rropt_tree, hf_dns_opt_client_scope, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
            cur_offset += 1;

            if (addr_len > 16) {
              expert_add_info(pinfo, rroptlen, &ei_dns_opt_bad_length);
              /* Avoid stack-smashing which occurs otherwise with the
               * following tvb_memcpy. */
              addr_len = 16;
            }
            tvb_memcpy(tvb, ip_addr.bytes, cur_offset, addr_len);
            switch (family) {

              case AFNUM_INET:
              {
                proto_tree_add_ipv4(rropt_tree, hf_dns_opt_client_addr4, tvb,
                                    cur_offset, addr_len, ip_addr.addr);
              }
              break;

              case AFNUM_INET6:
              {
                proto_tree_add_ipv6(rropt_tree, hf_dns_opt_client_addr6, tvb,
                                    cur_offset, addr_len, (ws_in6_addr *)&ip_addr);
              }
              break;

              default:
              {
                proto_tree_add_item(rropt_tree, hf_dns_opt_client_addr, tvb, cur_offset, (optlen - 4),
                                    ENC_NA);
	      }
              break;
            }
            cur_offset += (optlen - 4);
            rropt_len  -= optlen;
          }
          break;

          case O_COOKIE:
          {
            proto_tree_add_item(rropt_tree, hf_dns_opt_cookie_client, tvb, cur_offset, 8, ENC_NA);
            cur_offset += 8;
            rropt_len  -= 8;
            optlen -= 8;
            proto_tree_add_item(rropt_tree, hf_dns_opt_cookie_server, tvb, cur_offset, optlen, ENC_NA);
            cur_offset += optlen;
            rropt_len  -= optlen;
          }
          break;

          case O_EDNS_TCP_KA:
          {
            if (optlen == 2) {
              proto_tree_add_item(rropt_tree, hf_dns_opt_edns_tcp_keepalive_timeout, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
            }
            cur_offset += optlen;
            rropt_len  -= optlen;
          }
          break;

          case O_PADDING:
          {
            proto_tree_add_item(rropt_tree, hf_dns_opt_padding, tvb, cur_offset, optlen, ENC_NA);
            cur_offset += optlen;
            rropt_len  -= optlen;
          }
          break;

          case O_CHAIN:
          {
            if (optlen) {
              proto_tree_add_item(rropt_tree, hf_dns_opt_chain_fqdn, tvb, cur_offset, optlen, ENC_ASCII);
            }
            cur_offset += optlen;
            rropt_len  -= optlen;
          }
          break;

          case O_EXT_ERROR:
          {
            if (optlen >= 2) {
              proto_tree_add_item(rropt_tree, hf_dns_opt_ext_error_info_code, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
              cur_offset += 2;
              rropt_len  -= 2;
              if (optlen > 2) {
                proto_tree_add_item(rropt_tree, hf_dns_opt_ext_error_extra_text, tvb, cur_offset, optlen - 2, ENC_UTF_8);
                cur_offset += (optlen - 2);
                rropt_len  -= (optlen - 2);
              }
            }
          }
          break;

          default:
          {
            cur_offset += optlen;
            rropt_len  -= optlen;
          }
          break;
        }
      }
    }
    break;

    case T_APL: /* Lists of Address Prefixes (42) */
    {
      int      rr_len = data_len;
      guint16  afamily;
      guint8   afdpart_len;

      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);

      while (rr_len > 1) {
        afamily = tvb_get_ntohs(tvb, cur_offset);
        proto_tree_add_item(rr_tree, hf_dns_apl_address_family, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        cur_offset += 2;
        rr_len     -= 2;

        proto_tree_add_item(rr_tree, hf_dns_apl_coded_prefix, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
        cur_offset += 1;
        rr_len     -= 1;

        afdpart_len = tvb_get_guint8(tvb, cur_offset) & DNS_APL_AFDLENGTH;
        proto_tree_add_item(rr_tree, hf_dns_apl_negation, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(rr_tree, hf_dns_apl_afdlength, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
        cur_offset += 1;
        rr_len     -= 1;

        if (afamily == AFNUM_INET && afdpart_len <= 4) {
          ws_in4_addr *addr4_copy;

          addr4_copy = (ws_in4_addr *)wmem_alloc0(wmem_packet_scope(), 4);
          tvb_memcpy(tvb, (void *)addr4_copy, cur_offset, afdpart_len);
          proto_tree_add_ipv4(rr_tree, hf_dns_apl_afdpart_ipv4, tvb, cur_offset, afdpart_len, *addr4_copy);
        } else if (afamily == AFNUM_INET6 && afdpart_len <= 16) {
          ws_in6_addr *addr6_copy;

          addr6_copy = (ws_in6_addr *)wmem_alloc0(wmem_packet_scope(), 16);
          tvb_memcpy(tvb, (void *)addr6_copy, cur_offset, afdpart_len);
          proto_tree_add_ipv6(rr_tree, hf_dns_apl_afdpart_ipv6, tvb, cur_offset, afdpart_len, addr6_copy);
        } else { /* Other... */
           proto_tree_add_item(rr_tree, hf_dns_apl_afdpart_data, tvb, cur_offset, afdpart_len, ENC_NA);
        }
        cur_offset += afdpart_len;
        rr_len     -= afdpart_len;
      }
    }
    break;

    case T_DS: /* Delegation Signature (43) */
    case T_CDS: /* Child DS (59) */
    case T_DLV:
    {
      int     rr_len = data_len;

      proto_tree_add_item(rr_tree, hf_dns_ds_key_id, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      cur_offset += 2;
      rr_len     -= 2;

      proto_tree_add_item(rr_tree,  hf_dns_ds_algorithm, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset += 1;
      rr_len     -= 1;

      proto_tree_add_item(rr_tree,  hf_dns_ds_digest_type, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset += 1;
      rr_len     -= 1;

      proto_tree_add_item(rr_tree,  hf_dns_ds_digest, tvb, cur_offset, rr_len, ENC_NA);
    }
    break;

    case T_SSHFP: /* Securely Publish SSH Key Fingerprints (44) */
    {
      int    rr_len = data_len;

      proto_tree_add_item(rr_tree, hf_dns_sshfp_algorithm, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset += 1;
      rr_len     -= 1;

      proto_tree_add_item(rr_tree, hf_dns_sshfp_fingerprint_type, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset += 1;
      rr_len     -= 1;


      if (rr_len != 0) {
        proto_tree_add_item(rr_tree, hf_dns_sshfp_fingerprint, tvb, cur_offset, rr_len, ENC_NA);
      }
    }
    break;

    case T_IPSECKEY: /* IPsec Key (45) */
    {
      int           rr_len = data_len;
      guint8        gw_type;
      const gchar  *gw;
      int           gw_name_len;

      proto_tree_add_item(rr_tree, hf_dns_ipseckey_gateway_precedence, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset += 1;
      rr_len     -= 1;

      proto_tree_add_item(rr_tree, hf_dns_ipseckey_gateway_type, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      gw_type = tvb_get_guint8(tvb, cur_offset);
      cur_offset += 1;
      rr_len     -= 1;

      proto_tree_add_item(rr_tree, hf_dns_ipseckey_gateway_algorithm, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset += 1;
      rr_len     -= 1;

      switch (gw_type) {

        case 0:
        {
          /* No Gateway */
        }
        break;

        case 1:
        {
          proto_tree_add_item(rr_tree, hf_dns_ipseckey_gateway_ipv4, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
          cur_offset += 4;
          rr_len     -= 4;
        }
        break;

        case 2:
        {
          proto_tree_add_item(rr_tree, hf_dns_ipseckey_gateway_ipv6, tvb, cur_offset, 16, ENC_NA);
          cur_offset += 16;
          rr_len     -= 16;
        }
        break;

        case 3:
        {
          used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &gw, &gw_name_len);
          name_out = format_text(wmem_packet_scope(), (const guchar*)gw, gw_name_len);
          proto_tree_add_string(rr_tree, hf_dns_ipseckey_gateway_dns, tvb, cur_offset, used_bytes, name_out);

          cur_offset += used_bytes;
          rr_len     -= used_bytes;
        }
        break;

        default:
        break;
      }
      if (rr_len != 0) {
        proto_tree_add_item(rr_tree, hf_dns_ipseckey_public_key, tvb, cur_offset, rr_len, ENC_NA);
      }
    }
    break;

    case T_RRSIG: /* RRSIG (46) */
    case T_SIG: /* Security SIgnature (24) */
    {
      int           rr_len = data_len;
      const gchar  *signer_name;
      int           signer_name_len;
      proto_item    *ti;

      proto_tree_add_item(rr_tree, hf_dns_rrsig_type_covered, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      cur_offset += 2;
      rr_len     -= 2;

      proto_tree_add_item(rr_tree, hf_dns_rrsig_algorithm, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset += 1;
      rr_len     -= 1;

      proto_tree_add_item(rr_tree, hf_dns_rrsig_labels, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset += 1;
      rr_len     -= 1;

      ti = proto_tree_add_item(rr_tree, hf_dns_rrsig_original_ttl, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
      proto_item_append_text(ti, " (%s)", unsigned_time_secs_to_str(wmem_packet_scope(), tvb_get_ntohl(tvb, cur_offset)));
      cur_offset += 4;
      rr_len     -= 4;

      proto_tree_add_item(rr_tree, hf_dns_rrsig_signature_expiration, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
      cur_offset += 4;
      rr_len     -= 4;

      proto_tree_add_item(rr_tree, hf_dns_rrsig_signature_inception, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
      cur_offset += 4;
      rr_len     -= 4;

      proto_tree_add_item(rr_tree, hf_dns_rrsig_key_tag, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      cur_offset += 2;
      rr_len     -= 2;

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &signer_name, &signer_name_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)signer_name, signer_name_len);
      proto_tree_add_string(rr_tree, hf_dns_rrsig_signers_name, tvb, cur_offset, used_bytes, name_out);
      cur_offset += used_bytes;
      rr_len     -= used_bytes;

      if (rr_len != 0) {
        proto_tree_add_item(rr_tree, hf_dns_rrsig_signature, tvb, cur_offset, rr_len, ENC_NA);
      }
    }
    break;

    case T_NSEC: /* NSEC (47) */
    {
      int           rr_len = data_len;
      const gchar  *next_domain_name;
      int           next_domain_name_len;

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset,
                                          &next_domain_name, &next_domain_name_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)next_domain_name, next_domain_name_len);
      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name_out);
      proto_item_append_text(trr, ", next domain name %s", name_out);
      proto_tree_add_string(rr_tree, hf_dns_nsec_next_domain_name, tvb, cur_offset, used_bytes, name_out);
      cur_offset += used_bytes;
      rr_len     -= used_bytes;

      dissect_type_bitmap(rr_tree, tvb, cur_offset, rr_len);
    }
    break;

    case T_DNSKEY: /* DNSKEY (48) */
    case T_CDNSKEY: /* CDNSKEY (60) */
    {
      int         rr_len = data_len;
      proto_item *tf, *ti_gen;
      proto_tree *flags_tree;
      guint16     key_id;
      guint8 algo;

      tf = proto_tree_add_item(rr_tree, hf_dns_dnskey_flags, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      flags_tree = proto_item_add_subtree(tf, ett_key_flags);
      proto_tree_add_item(flags_tree, hf_dns_dnskey_flags_zone_key, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(flags_tree, hf_dns_dnskey_flags_key_revoked, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(flags_tree, hf_dns_dnskey_flags_secure_entry_point, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(flags_tree, hf_dns_dnskey_flags_reserved, tvb, cur_offset, 2, ENC_BIG_ENDIAN);

      cur_offset += 2;
      rr_len     -= 2;

      /* Must have value 3, Add check ? */
      proto_tree_add_item(rr_tree, hf_dns_dnskey_protocol, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset += 1;
      rr_len     -= 1;

      proto_tree_add_item(rr_tree, hf_dns_dnskey_algorithm, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      algo = tvb_get_guint8(tvb, cur_offset);

      cur_offset += 1;
      rr_len     -= 1;

      if (compute_key_id(rr_tree, pinfo, tvb, cur_offset-4, rr_len+4, algo, &key_id)) {
        ti_gen = proto_tree_add_uint(rr_tree, hf_dns_dnskey_key_id, tvb, 0, 0, key_id);
        proto_item_set_generated(ti_gen);
      }

      proto_tree_add_item(rr_tree, hf_dns_dnskey_public_key, tvb, cur_offset, rr_len, ENC_NA);
    }
    break;

    case T_DHCID: /* DHCID (49) */
    {
      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);
      proto_tree_add_item(rr_tree, hf_dns_dhcid_rdata, tvb, cur_offset, data_len, ENC_NA);
    }
    break;

    case T_NSEC3: /* NSEC3 (50) */
    {
      int         rr_len, initial_offset = cur_offset;
      guint8      salt_len, hash_len;
      proto_item *flags_item, *hash_item;
      proto_tree *flags_tree;

      proto_tree_add_item(rr_tree, hf_dns_nsec3_algo, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset += 1;

      flags_item = proto_tree_add_item(rr_tree, hf_dns_nsec3_flags, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      flags_tree = proto_item_add_subtree(flags_item, ett_nsec3_flags);
      proto_tree_add_item(flags_tree, hf_dns_nsec3_flag_optout, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset += 1;

      proto_tree_add_item(rr_tree, hf_dns_nsec3_iterations, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      cur_offset += 2;

      proto_tree_add_item(rr_tree, hf_dns_nsec3_salt_length, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      salt_len = tvb_get_guint8(tvb, cur_offset);
      cur_offset += 1;

      proto_tree_add_item(rr_tree, hf_dns_nsec3_salt_value, tvb, cur_offset, salt_len, ENC_NA);
      cur_offset += salt_len;

      proto_tree_add_item(rr_tree, hf_dns_nsec3_hash_length, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      hash_len = tvb_get_guint8(tvb, cur_offset);
      cur_offset += 1;

      /*
       * The code below is optimized for simplicity as trailing padding
       * characters ("=") are not used in the NSEC3 specification (see RFC 5155
       * section 1.3).
       */
      if (hash_len) {
        /* Base 32 Encoding with Extended Hex Alphabet (see RFC 4648 section 7) */
        const char    *base32hex = "0123456789abcdefghijklmnopqrstuv";
        wmem_strbuf_t *hash_value_base32hex = wmem_strbuf_new(pinfo->pool, "");
        int            group, in_offset, out_offset;
        for (in_offset = 0, out_offset = 0;
            in_offset / 8 < hash_len;
            in_offset += 5, out_offset += 1) {
          group = tvb_get_bits8(tvb, cur_offset * 8 + in_offset, 5);
          wmem_strbuf_append_c(hash_value_base32hex, base32hex[group]);
        }
        hash_item = proto_tree_add_string(rr_tree, hf_dns_nsec3_hash_value, tvb, cur_offset, hash_len, wmem_strbuf_finalize(hash_value_base32hex));
        proto_item_set_generated(hash_item);
        cur_offset += hash_len;
      }

      rr_len = data_len - (cur_offset - initial_offset);
      dissect_type_bitmap(rr_tree, tvb, cur_offset, rr_len);
    }
    break;

    case T_NSEC3PARAM: /* NSEC3PARAM (51) */
    {
      int salt_len;
      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);

      proto_tree_add_item(rr_tree, hf_dns_nsec3_algo, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset +=1;

      proto_tree_add_item(rr_tree, hf_dns_nsec3_flags, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset +=1;

      proto_tree_add_item(rr_tree, hf_dns_nsec3_iterations, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      cur_offset += 2;

      proto_tree_add_item(rr_tree, hf_dns_nsec3_salt_length, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      salt_len = tvb_get_guint8(tvb, cur_offset);
      cur_offset +=1;

      proto_tree_add_item(rr_tree, hf_dns_nsec3_salt_value, tvb, cur_offset, salt_len, ENC_NA);
    }
    break;

    case T_TLSA: /* DNS-Based Authentication of Named Entities (52) */
    {
      int     rr_len = data_len;
      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);

      proto_tree_add_item(rr_tree, hf_dns_tlsa_certificate_usage, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset ++;
      rr_len --;

      proto_tree_add_item(rr_tree, hf_dns_tlsa_selector, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset ++;
      rr_len --;

      proto_tree_add_item(rr_tree, hf_dns_tlsa_matching_type, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset ++;
      rr_len --;

      proto_tree_add_item(rr_tree, hf_dns_tlsa_certificate_association_data, tvb, cur_offset, rr_len, ENC_NA);
    }
    break;

    case T_HIP: /* Host Identity Protocol (55) */
    {
      guint8        hit_len;
      guint16       pk_len;
      int           rr_len = data_len;
      int           rendezvous_len;
      const gchar  *rend_server_dns_name;

      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name);

      hit_len = tvb_get_guint8(tvb, cur_offset);
      proto_tree_add_item(rr_tree, hf_dns_hip_hit_length, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset += 1;
      rr_len     -= 1;

      proto_tree_add_item(rr_tree, hf_dns_hip_pk_algo, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset += 1;
      rr_len     -= 1;

      pk_len = tvb_get_ntohs(tvb, cur_offset);
      proto_tree_add_item(rr_tree, hf_dns_hip_pk_length, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      cur_offset += 2;
      rr_len     -= 2;

      proto_tree_add_item(rr_tree, hf_dns_hip_hit, tvb, cur_offset, hit_len, ENC_NA);
      cur_offset += hit_len;
      rr_len     -= hit_len;

      proto_tree_add_item(rr_tree, hf_dns_hip_pk, tvb, cur_offset, pk_len, ENC_NA);
      cur_offset += pk_len;
      rr_len     -= pk_len;

      while (rr_len > 1) {
        used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &rend_server_dns_name, &rendezvous_len);
        name_out = format_text(wmem_packet_scope(), (const guchar*)rend_server_dns_name, rendezvous_len);
        proto_tree_add_string(rr_tree, hf_dns_hip_rendezvous_server, tvb, cur_offset, used_bytes, name_out);
        cur_offset += used_bytes;
        rr_len     -= used_bytes;
      }
    }
    break;

    case T_OPENPGPKEY: /* OpenPGP Key (61) */
    {
      proto_tree_add_item(rr_tree, hf_dns_openpgpkey, tvb, cur_offset, data_len, ENC_ASCII);
    }
    break;

    case T_CSYNC: /* Child-to-Parent Synchronization (62) */
    {
      int         rr_len, initial_offset = cur_offset;

      proto_tree_add_item(rr_tree, hf_dns_csync_soa, tvb, cur_offset, 4, ENC_ASCII|ENC_NA);
      cur_offset += 4;

      proto_tree_add_bitmask_with_flags(rr_tree, tvb, cur_offset,
        hf_dns_csync_flags, ett_dns_csdync_flags, dns_csync_flags, ENC_BIG_ENDIAN, BMT_NO_APPEND);
      cur_offset += 2;

      rr_len = data_len - (cur_offset - initial_offset);
      proto_tree_add_item(rr_tree, hf_dns_csync_type_bitmap, tvb, cur_offset, rr_len, ENC_NA);

      dissect_type_bitmap(rr_tree, tvb, cur_offset, rr_len);
    }
    break;

    case T_ZONEMD: /* Message Digest for DNS Zones (63) */
    {
      proto_tree_add_item(rr_tree, hf_dns_zonemd_serial, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
      cur_offset += 4;
      proto_tree_add_item(rr_tree, hf_dns_zonemd_scheme, tvb, cur_offset, 1, ENC_NA);
      cur_offset += 1;
      proto_tree_add_item(rr_tree, hf_dns_zonemd_hash_algo, tvb, cur_offset, 1, ENC_NA);
      cur_offset += 1;
      proto_tree_add_item(rr_tree, hf_dns_zonemd_digest, tvb, cur_offset, data_len - 6 , ENC_NA);
    }
    break;

    case T_SVCB: /* Service binding and parameter specification (64) */
    case T_HTTPS: /* Service binding and parameter specification (65) */
    {
      guint32       priority = 0, value;
      guint32       svc_param_key;
      guint32       svc_param_offset;
      guint32       svc_param_length;
      guint32       svc_param_alpn_length;
      const gchar  *target;
      int           target_len;
      int           start_offset = cur_offset;
      proto_item   *svcb_param_ti;
      proto_tree   *svcb_param_tree;

      proto_tree_add_item_ret_uint(rr_tree, hf_dns_svcb_priority, tvb, cur_offset, 2, ENC_BIG_ENDIAN, &priority);
      cur_offset += 2;

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &target, &target_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)target, target_len);

      proto_tree_add_string(rr_tree, hf_dns_svcb_target, tvb, cur_offset, used_bytes, name_out);
      cur_offset += used_bytes;

      if (data_len > cur_offset - start_offset) {
        while (data_len > cur_offset - start_offset) {
          svcb_param_ti = proto_tree_add_item(rr_tree, hf_dns_svcb_param, tvb, cur_offset, -1, ENC_NA);
          svcb_param_tree = proto_item_add_subtree(svcb_param_ti, ett_dns_svcb);

          proto_tree_add_item_ret_uint(svcb_param_tree, hf_dns_svcb_param_key, tvb, cur_offset, 2, ENC_BIG_ENDIAN, &svc_param_key);
          cur_offset += 2;

          proto_tree_add_item_ret_uint(svcb_param_tree, hf_dns_svcb_param_length, tvb, cur_offset, 2, ENC_BIG_ENDIAN, &svc_param_length);
          cur_offset += 2;

          proto_item_append_text(svcb_param_ti, ": %s", val_to_str(svc_param_key, dns_svcb_param_key_vals, "key%u"));
          proto_item_set_len(svcb_param_ti, svc_param_length + 4);

          switch(svc_param_key) {
            case DNS_SVCB_KEY_MANDATORY:
              for (svc_param_offset = 0; svc_param_offset < svc_param_length; svc_param_offset += 2) {
                guint32 key;
                proto_tree_add_item_ret_uint(svcb_param_tree, hf_dns_svcb_param_mandatory_key, tvb, cur_offset, 2, ENC_BIG_ENDIAN, &key);
                proto_item_append_text(svcb_param_ti, "%c%s", (svc_param_offset == 0 ? '=' : ','), val_to_str(key, dns_svcb_param_key_vals, "key%u"));
                cur_offset += 2;
              }
              break;
            case DNS_SVCB_KEY_ALPN:
              for (svc_param_offset = 0; svc_param_offset < svc_param_length; ) {
                const guint8 *alpn;
                proto_tree_add_item_ret_uint(svcb_param_tree, hf_dns_svcb_param_alpn_length, tvb, cur_offset, 1, ENC_BIG_ENDIAN, &svc_param_alpn_length);
                cur_offset += 1;
                proto_tree_add_item_ret_string(svcb_param_tree, hf_dns_svcb_param_alpn, tvb, cur_offset, svc_param_alpn_length, ENC_ASCII|ENC_NA, wmem_packet_scope(), &alpn);
                cur_offset += svc_param_alpn_length;
                proto_item_append_text(svcb_param_ti, "%c%s", (svc_param_offset == 0 ? '=' : ','), alpn);
                svc_param_offset += 1 + svc_param_alpn_length;
              }
              break;
            case DNS_SVCB_KEY_NOALPN:
              break;
            case DNS_SVCB_KEY_PORT:
              proto_tree_add_item_ret_uint(svcb_param_tree, hf_dns_svcb_param_port, tvb, cur_offset, 2, ENC_BIG_ENDIAN, &value);
              proto_item_append_text(svcb_param_ti, "=%u", value);
              cur_offset += 2;
              break;
            case DNS_SVCB_KEY_IPV4HINT:
              for (svc_param_offset = 0; svc_param_offset < svc_param_length; svc_param_offset += 4) {
                proto_tree_add_item(svcb_param_tree, hf_dns_svcb_param_ipv4hint_ip, tvb, cur_offset, 4, ENC_NA);
                proto_item_append_text(svcb_param_ti, "%c%s", (svc_param_offset == 0 ? '=' : ','), tvb_ip_to_str(pinfo->pool, tvb, cur_offset));
                cur_offset += 4;
              }
              break;
            case DNS_SVCB_KEY_ECHCONFIG:
              dissect_dns_svcparam_base64(svcb_param_tree, svcb_param_ti, hf_dns_svcb_param_echconfig, tvb, cur_offset, svc_param_length);
              cur_offset += svc_param_length;
              break;
            case DNS_SVCB_KEY_IPV6HINT:
              for (svc_param_offset = 0; svc_param_offset < svc_param_length; svc_param_offset += 16) {
                proto_tree_add_item(svcb_param_tree, hf_dns_svcb_param_ipv6hint_ip, tvb, cur_offset, 16, ENC_NA);
                proto_item_append_text(svcb_param_ti, "%c%s", (svc_param_offset == 0 ? '=' : ','), tvb_ip6_to_str(pinfo->pool, tvb, cur_offset));
                cur_offset += 16;
              }
              break;
            case DNS_SVCB_KEY_ODOHCONFIG:
              dissect_dns_svcparam_base64(svcb_param_tree, svcb_param_ti, hf_dns_svcb_param_odohconfig, tvb, cur_offset, svc_param_length);
              cur_offset += svc_param_length;
              break;
            default:
              if (svc_param_length > 0) {
                proto_tree_add_item(svcb_param_tree, hf_dns_svcb_param_value, tvb, cur_offset, svc_param_length, ENC_NA);
                proto_item_append_text(svcb_param_ti, "=%s", tvb_format_text(pinfo->pool, tvb, cur_offset, svc_param_length));
                cur_offset += svc_param_length;
              }
              break;
          }
        }
      }
    }
    break;

    case T_SPF: /* Sender Policy Framework (99) */
    {
      int rr_len = data_len;
      int spf_offset;
      int spf_len;

      spf_offset = cur_offset;
      while (rr_len != 0) {
        spf_len = tvb_get_guint8(tvb, spf_offset);
        proto_tree_add_item(rr_tree, hf_dns_spf_length, tvb, spf_offset, 1, ENC_BIG_ENDIAN);
        spf_offset += 1;
        rr_len     -= 1;
        proto_tree_add_item(rr_tree, hf_dns_spf, tvb, spf_offset, spf_len, ENC_ASCII);
        spf_offset +=  spf_len;
        rr_len     -= spf_len;
      }
    }
    break;

    case T_NID: /* NodeID (104) */
    {
      proto_tree_add_item(rr_tree, hf_dns_ilnp_nodeid_preference, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      cur_offset += 2;

      proto_tree_add_item(rr_tree, hf_dns_ilnp_nodeid, tvb, cur_offset, 8, ENC_NA);
      /*cur_offset += 8;*/
    }
    break;

    case T_L32: /* Locator (105) */
    {
      proto_tree_add_item(rr_tree, hf_dns_ilnp_locator32_preference, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      cur_offset += 2;

      proto_tree_add_item(rr_tree, hf_dns_ilnp_locator32, tvb, cur_offset, 4, ENC_NA);
      /*cur_offset += 4;*/
    }
    break;

    case T_L64: /* Locator64 (106) */
    {
      proto_tree_add_item(rr_tree, hf_dns_ilnp_locator64_preference, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      cur_offset += 2;

      proto_tree_add_item(rr_tree, hf_dns_ilnp_locator64, tvb, cur_offset, 8, ENC_NA);
      /*cur_offset += 8;*/
    }
    break;

    case T_LP: /* Locator FQDN (107) */
    {
      int           lp_len;
      const gchar  *lp_str;

      proto_tree_add_item(rr_tree, hf_dns_ilnp_locatorfqdn_preference, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      cur_offset += 2;

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &lp_str, &lp_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)lp_str, lp_len);
      proto_tree_add_string(rr_tree, hf_dns_ilnp_locatorfqdn, tvb, cur_offset, used_bytes, name_out);
      /*cur_offset += used_bytes;*/
    }
    break;

    case T_EUI48: /* EUI48 (108) */
    {
      proto_tree_add_item(rr_tree, hf_dns_eui48, tvb, cur_offset, 6, ENC_NA);
      /*cur_offset += 6;*/
    }
    break;

    case T_EUI64: /* EUI64 (109) */
    {
      proto_tree_add_item(rr_tree, hf_dns_eui64, tvb, cur_offset, 8, ENC_NA);
      /*cur_offset += 8;*/
    }
    break;

    case T_TKEY: /* Transaction Key (249) */
    {
      const gchar  *tkey_algname;
      int           tkey_algname_len;
      guint16       tkey_mode, tkey_keylen, tkey_otherlen;

      proto_tree *key_tree;
      proto_item *key_item;

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &tkey_algname, &tkey_algname_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)tkey_algname, tkey_algname_len);
      proto_tree_add_string(rr_tree, hf_dns_tkey_algo_name, tvb, cur_offset, used_bytes, name_out);
      cur_offset += used_bytes;

      proto_tree_add_item(rr_tree, hf_dns_tkey_signature_inception, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
      cur_offset += 4;

      proto_tree_add_item(rr_tree, hf_dns_tkey_signature_expiration, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
      cur_offset += 4;

      proto_tree_add_item(rr_tree, hf_dns_tkey_mode, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      tkey_mode = tvb_get_ntohs(tvb, cur_offset);
      cur_offset += 2;

      proto_tree_add_item(rr_tree, hf_dns_tkey_error, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      cur_offset += 2;

      proto_tree_add_item(rr_tree, hf_dns_tkey_key_size, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      tkey_keylen = tvb_get_ntohs(tvb, cur_offset);
      cur_offset += 2;

      if (tkey_keylen != 0) {
        key_item = proto_tree_add_item(rr_tree, hf_dns_tkey_key_data, tvb, cur_offset, tkey_keylen, ENC_NA);

        key_tree = proto_item_add_subtree(key_item, ett_t_key);

        switch(tkey_mode) {
          case TKEYMODE_GSSAPI:
          {
            tvbuff_t *gssapi_tvb;

            /*
             * XXX - in at least one capture, this appears to
             * be an NTLMSSP blob, with no ASN.1 in it, in
             * a query.
             *
             * See RFC 3645 which might indicate what's going
             * on here.  (The key is an output_token from
             * GSS_Init_sec_context.)
             *
             * How the heck do we know what method is being
             * used, so we know how to decode the key?  Do we
             * have to look at the algorithm name, e.g.
             * "gss.microsoft.com"?  We currently do as the
             * the SMB dissector does in some cases, and check
             * whether the security blob begins with "NTLMSSP".
             */
            gssapi_tvb = tvb_new_subset_length(tvb, cur_offset, tkey_keylen);
            if (tvb_strneql(gssapi_tvb, 0, "NTLMSSP", 7) == 0) {
              call_dissector(ntlmssp_handle, gssapi_tvb, pinfo, key_tree);
            } else {
              call_dissector(gssapi_handle, gssapi_tvb, pinfo, key_tree);
            }
          }
          break;

          default:
            /* No dissector for this key mode */
          break;
        }

        cur_offset += tkey_keylen;
      }

      proto_tree_add_item(rr_tree, hf_dns_tkey_other_size, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      tkey_otherlen = tvb_get_ntohs(tvb, cur_offset);
      cur_offset += 2;

      if (tkey_otherlen != 0) {
        proto_tree_add_item(rr_tree, hf_dns_tkey_other_data, tvb, cur_offset, tkey_otherlen, ENC_NA);
      }
    }
    break;

    case T_TSIG: /* Transaction Signature (250) */
    {
      guint16       tsig_siglen, tsig_otherlen;
      const gchar  *tsig_algname;
      int           tsig_algname_len;
      proto_item    *ti;

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &tsig_algname, &tsig_algname_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)tsig_algname, tsig_algname_len);
      proto_tree_add_string(rr_tree, hf_dns_tsig_algorithm_name, tvb, cur_offset, used_bytes, name_out);
      cur_offset += used_bytes;

      ti = proto_tree_add_item(rr_tree, hf_dns_tsig_time_signed ,tvb, cur_offset, 6, ENC_TIME_SECS|ENC_BIG_ENDIAN);
      if(tvb_get_ntohs(tvb, cur_offset)) /* Time High */
      {
        proto_item_append_text(ti, " (high bits set)");
      }
      cur_offset += 6;

      proto_tree_add_item(rr_tree, hf_dns_tsig_fudge, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      cur_offset += 2;

      tsig_siglen = tvb_get_ntohs(tvb, cur_offset);
      proto_tree_add_item(rr_tree, hf_dns_tsig_mac_size, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      cur_offset += 2;

      if (tsig_siglen != 0) {
        proto_item *mac_item;
        proto_tree *mac_tree;
        tvbuff_t   *sub_tvb;

        mac_item = proto_tree_add_item(rr_tree, hf_dns_tsig_mac, tvb, cur_offset, tsig_siglen, ENC_NA);
        mac_tree = proto_item_add_subtree(mac_item, ett_dns_mac);

        sub_tvb=tvb_new_subset_length(tvb, cur_offset, tsig_siglen);

        if (!dissector_try_string(dns_tsig_dissector_table, tsig_algname, sub_tvb, pinfo, mac_tree, NULL)) {
          expert_add_info_format(pinfo, mac_item, &ei_dns_tsig_alg,
                "No dissector for algorithm:%s", tsig_algname);
        }

        cur_offset += tsig_siglen;
      }

      proto_tree_add_item(rr_tree, hf_dns_tsig_original_id, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      cur_offset += 2;

      proto_tree_add_item(rr_tree, hf_dns_tsig_error, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      cur_offset += 2;

      proto_tree_add_item(rr_tree, hf_dns_tsig_other_len, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
      tsig_otherlen = tvb_get_ntohs(tvb, cur_offset);
      cur_offset += 2;

      if (tsig_otherlen != 0) {
        proto_tree_add_item(rr_tree, hf_dns_tsig_other_data, tvb, cur_offset, tsig_otherlen, ENC_NA);
      }
    }
    break;

    case T_CAA: /* Certification Authority Restriction (257) */
    {
      proto_item *caa_item;
      proto_tree *caa_tree;
      guint8 tag_len;
      const char *tag;
      gushort value_len;
      const guchar *value;
      int cur_hf = -1;

      caa_item = proto_tree_add_item(rr_tree, hf_dns_caa_flags, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      caa_tree = proto_item_add_subtree(caa_item, ett_caa_flags);
      proto_tree_add_item(caa_tree, hf_dns_caa_flag_issuer_critical, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
      cur_offset++;

      tag_len = tvb_get_guint8(tvb, cur_offset);
      tag = (const char*)tvb_get_string_enc(wmem_packet_scope(), tvb, cur_offset + 1, tag_len, ENC_ASCII|ENC_NA);

      value_len = data_len - (tag_len + 2);
      value = (guchar*)tvb_get_string_enc(wmem_packet_scope(), tvb, cur_offset + 1 + tag_len, value_len, ENC_ASCII|ENC_NA);

      value = (guchar*)format_text(wmem_packet_scope(), value, value_len);

      if (strncmp(tag, "issue", tag_len) == 0) {
        cur_hf = hf_dns_caa_issue;
      } else if (strncmp(tag, "issuewild", tag_len) == 0) {
        cur_hf = hf_dns_caa_issuewild;
      } else if (strncmp(tag, "iodef", tag_len) == 0) {
        cur_hf = hf_dns_caa_iodef;
      } else {
        cur_hf = hf_dns_caa_unknown;
      }

      caa_item = proto_tree_add_string(rr_tree, cur_hf, tvb, cur_offset, 1 + tag_len + value_len, (const gchar*)value);
      caa_tree = proto_item_add_subtree(caa_item, ett_caa_data);

      proto_tree_add_uint(caa_tree, hf_dns_caa_tag_length, tvb, cur_offset, 1, tag_len);
      proto_tree_add_string(caa_tree, hf_dns_caa_tag, tvb, cur_offset + 1, tag_len, tag);
      proto_tree_add_string(caa_tree, hf_dns_caa_value, tvb, cur_offset + 1 + tag_len, value_len, (const gchar*)value);
    }
    break;

    case T_WINS:  /* Microsoft's WINS (65281)*/
    {
      int     rr_len = data_len;
      guint32 nservers;

      proto_tree_add_item(rr_tree, hf_dns_wins_local_flag, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
      cur_offset += 4;
      rr_len     -= 4;

      proto_tree_add_item(rr_tree, hf_dns_wins_lookup_timeout, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
      cur_offset += 4;
      rr_len     -= 4;

      proto_tree_add_item(rr_tree, hf_dns_wins_cache_timeout, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
      cur_offset += 4;
      rr_len     -= 4;

      proto_tree_add_item(rr_tree, hf_dns_wins_nb_wins_servers, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
      nservers = tvb_get_ntohl(tvb, cur_offset);
      cur_offset += 4;
      rr_len     -= 4;

      while (rr_len != 0 && nservers != 0) {
        proto_tree_add_item(rr_tree, hf_dns_wins_server, tvb, cur_offset, 4, ENC_NA);

        cur_offset += 4;
        rr_len     -= 4;
        nservers--;
      }
    }
    break;

    case T_WINS_R: /* Microsoft's WINS-R (65282)*/
    {
      const gchar  *dname;
      int           dname_len;

      proto_tree_add_item(rr_tree, hf_dns_winsr_local_flag, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
      cur_offset += 4;

      proto_tree_add_item(rr_tree, hf_dns_winsr_lookup_timeout, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
      cur_offset += 4;

      proto_tree_add_item(rr_tree, hf_dns_winsr_cache_timeout, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
      cur_offset += 4;

      used_bytes = get_dns_name(tvb, cur_offset, 0, dns_data_offset, &dname, &dname_len);
      name_out = format_text(wmem_packet_scope(), (const guchar*)dname, dname_len);
      proto_tree_add_string(rr_tree, hf_dns_winsr_name_result_domain, tvb, cur_offset, used_bytes, name_out);
      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name_out);
      proto_item_append_text(trr, ", name result domain %s", name_out);
    }
    break;

    case T_XPF: /* XPF draft-bellis-dnsop-xpf */
    {
      guint32 address_family;

      proto_tree_add_item_ret_uint(rr_tree, hf_dns_xpf_ip_version, tvb, cur_offset, 1, ENC_BIG_ENDIAN, &address_family);
      cur_offset++;

      switch (address_family) {
        case IP_VERSION_NUM_INET:
          proto_tree_add_item(rr_tree, hf_dns_xpf_protocol, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
          cur_offset++;
          proto_tree_add_item(rr_tree, hf_dns_xpf_source_ipv4, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
          cur_offset += 4;
          proto_tree_add_item(rr_tree, hf_dns_xpf_destination_ipv4, tvb, cur_offset, 4, ENC_BIG_ENDIAN);
          cur_offset += 4;
          proto_tree_add_item(rr_tree, hf_dns_xpf_sport, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
          cur_offset += 2;
          proto_tree_add_item(rr_tree, hf_dns_xpf_dport, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        break;
        case IP_VERSION_NUM_INET6:
          proto_tree_add_item(rr_tree, hf_dns_xpf_protocol, tvb, cur_offset, 1, ENC_BIG_ENDIAN);
          cur_offset++;
          proto_tree_add_item(rr_tree, hf_dns_xpf_source_ipv6, tvb, cur_offset, 16, ENC_NA);
          cur_offset += 16;
          proto_tree_add_item(rr_tree, hf_dns_xpf_destination_ipv6, tvb, cur_offset, 16, ENC_NA);
          cur_offset += 16;
          proto_tree_add_item(rr_tree, hf_dns_xpf_sport, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
          cur_offset += 2;
          proto_tree_add_item(rr_tree, hf_dns_xpf_dport, tvb, cur_offset, 2, ENC_BIG_ENDIAN);
        break;
        default: /* Add Expert info ? */
        break;
      }
    }


    break;

    /* TODO: parse more record types */
    default:
    {
      expert_add_info_format(pinfo, trr, &ei_dns_undecoded_option,
                                 "Dissector for DNS Type (%d)"
                                 " code not implemented, Contact Wireshark developers"
                                 " if you want this supported", dns_type);
      proto_tree_add_item(rr_tree, hf_dns_data, tvb, cur_offset, data_len, ENC_NA);
    }
    break;
  }

  data_offset += data_len;

  return data_offset - data_start;
}

static int
dissect_query_records(tvbuff_t *tvb, int cur_off, int dns_data_offset,
    int count, packet_info *pinfo, proto_tree *dns_tree, gboolean isupdate,
    gboolean is_mdns, gboolean *is_multiple_responds)
{
  int         start_off, add_off;
  proto_tree *qatree;
  proto_item *ti;
  const char *s = (isupdate ?  "Zone" : "Queries");

  start_off = cur_off;

  qatree = proto_tree_add_subtree(dns_tree, tvb, start_off, -1, ett_dns_qry, &ti, s);

  while (count-- > 0) {
    add_off = dissect_dns_query(tvb, cur_off, dns_data_offset, pinfo, qatree,
                                is_mdns, is_multiple_responds);
    cur_off += add_off;
  }
  proto_item_set_len(ti, cur_off - start_off);
  return cur_off - start_off;
}

static int
dissect_answer_records(tvbuff_t *tvb, int cur_off, int dns_data_offset,
    int count, proto_tree *dns_tree, const char *name,
    packet_info *pinfo, gboolean is_mdns)
{
  int         start_off, add_off;
  proto_tree *qatree;
  proto_item *ti;

  start_off = cur_off;
  qatree = proto_tree_add_subtree(dns_tree, tvb, start_off, -1, ett_dns_ans, &ti, name);
  while (count-- > 0) {
    add_off = dissect_dns_answer(
      tvb, cur_off, dns_data_offset, qatree, pinfo, is_mdns);
    cur_off += add_off;
  }
  proto_item_set_len(ti, cur_off - start_off);
  return cur_off - start_off;
}

static int
dissect_dso_data(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *dns_tree)
{
  proto_tree *dso_tree;
  proto_tree *dso_tlv_tree;
  proto_item *dso_ti;
  proto_item *dso_tlv_ti;
  guint16    dso_tlv_length;
  guint32    dso_tlv_type;
  int        start_offset;

  start_offset = offset;
  dso_ti = proto_tree_add_item(dns_tree, hf_dns_dso, tvb, offset, -1, ENC_NA);
  dso_tree = proto_item_add_subtree(dso_ti, ett_dns_dso);

  while(tvb_reported_length_remaining(tvb, offset) >= 4) {
    dso_tlv_length = tvb_get_ntohs(tvb, offset + 2);
    dso_tlv_ti = proto_tree_add_item(dso_tree, hf_dns_dso_tlv, tvb, offset, dso_tlv_length + 4, ENC_NA);
    dso_tlv_tree = proto_item_add_subtree(dso_tlv_ti, ett_dns_dso_tlv);

    proto_tree_add_item_ret_uint(dso_tlv_tree, hf_dns_dso_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN, &dso_tlv_type);
    offset += 2;
    proto_item_append_text(dso_tlv_ti, ": %s", rval_to_str(dso_tlv_type, dns_dso_type_rvals, "Unknown Type"));

    proto_tree_add_item(dso_tlv_tree, hf_dns_dso_tlv_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    switch(dso_tlv_type) {
      case DSO_TYPE_KEEPALIVE:
        proto_tree_add_item(dso_tlv_tree, hf_dns_dso_tlv_keepalive_inactivity, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(dso_tlv_tree, hf_dns_dso_tlv_keepalive_interval, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;
      case DSO_TYPE_RETRYDELAY:
        proto_tree_add_item(dso_tlv_tree, hf_dns_dso_tlv_retrydelay_retrydelay, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;
      case DSO_TYPE_ENCPAD:
        if (dso_tlv_length > 0) {
          proto_tree_add_item(dso_tlv_tree, hf_dns_dso_tlv_encpad_padding, tvb, offset, dso_tlv_length, ENC_NA);
          offset += dso_tlv_length;
        }
        break;
      default:
        if (dso_tlv_length > 0) {
          proto_tree_add_item(dso_tlv_tree, hf_dns_dso_tlv_data, tvb, offset, dso_tlv_length, ENC_NA);
          offset += dso_tlv_length;
        }
        break;
    }
  }

  proto_item_set_len(dso_ti, offset - start_offset);
  return offset - start_offset;
}

static void
dissect_dns_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    enum DnsTransport transport, gboolean is_mdns, gboolean is_llmnr)
{
  int                offset   = (transport == DNS_TRANSPORT_TCP || transport == DNS_TRANSPORT_QUIC) ? 2 : 0;
  int                dns_data_offset;
  proto_tree        *dns_tree, *field_tree;
  proto_item        *ti, *tf, *transaction_item;
  guint16            flags, opcode, rcode, quest, ans, auth, add;
  guint              id;
  guint32            reqresp_id = 0;
  int                cur_off;
  gboolean           isupdate;
  conversation_t    *conversation;
  dns_conv_info_t   *dns_info;
  dns_transaction_t *dns_trans = NULL;
  wmem_tree_key_t    key[3];
  struct DnsTap     *dns_stats;
  guint16            qtype = 0;
  guint16            qclass = 0;
  gboolean           retransmission = FALSE;
  const gchar       *name;
  int                name_len;
  nstime_t           delta = NSTIME_INIT_ZERO;
  gboolean           is_multiple_responds = FALSE;

  dns_data_offset = offset;

  col_clear(pinfo->cinfo, COL_INFO);

  /* To do: check for errs, etc. */
  id    = tvb_get_ntohs(tvb, offset + DNS_ID);
  flags = tvb_get_ntohs(tvb, offset + DNS_FLAGS);
  opcode = (guint16) ((flags & F_OPCODE) >> OPCODE_SHIFT);
  rcode  = (guint16)  (flags & F_RCODE);

  col_add_fstr(pinfo->cinfo, COL_INFO, "%s%s 0x%04x",
                val_to_str(opcode, opcode_vals, "Unknown operation (%u)"),
                (flags&F_RESPONSE)?" response":"", id);

  if (flags & F_RESPONSE) {
    if (rcode != RCODE_NOERROR) {
      col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
              val_to_str(rcode, rcode_vals, "Unknown error (%u)"));
    }
  }

  if (opcode == OPCODE_UPDATE) {
    isupdate = TRUE;
  } else {
    isupdate = FALSE;
  }

  if (is_llmnr) {
    ti = proto_tree_add_protocol_format(tree, proto_llmnr, tvb, 0, -1,
        "Link-local Multicast Name Resolution (%s)", (flags & F_RESPONSE) ? "response" : "query");
  } else if (is_mdns){
    ti = proto_tree_add_protocol_format(tree, proto_mdns, tvb, 0, -1,
        "Multicast Domain Name System (%s)", (flags & F_RESPONSE) ? "response" : "query");
  } else {
    ti = proto_tree_add_protocol_format(tree, proto_dns, tvb, 0, -1,
        "Domain Name System (%s)", (flags & F_RESPONSE) ? "response" : "query");
  }

  dns_tree = proto_item_add_subtree(ti, ett_dns);

  /*
   * Do we have a conversation for this connection?
   */
  conversation = find_or_create_conversation(pinfo);

  /*
   * DoH: Each DNS query-response pair is mapped into an HTTP exchange.
   * For other transports, just use the DNS transaction ID as usual.
   */
  if (transport == DNS_TRANSPORT_HTTP) {
    /* For DoH using HTTP/2, use the Stream ID if available. For HTTP/1,
     * hopefully there is no pipelining or the DNS ID is unique enough. */
    reqresp_id = http2_get_stream_id(pinfo);
  }
  if (reqresp_id == 0) {
    reqresp_id = id;
  }

  /*
   * Do we already have a state structure for this conv
   */
  dns_info = (dns_conv_info_t *)conversation_get_proto_data(conversation, proto_dns);
  if (!dns_info) {
    /* No.  Attach that information to the conversation, and add
     * it to the list of information structures.
     */
    dns_info = wmem_new(wmem_file_scope(), dns_conv_info_t);
    dns_info->pdus=wmem_tree_new(wmem_file_scope());
    conversation_add_proto_data(conversation, proto_dns, dns_info);
  }

  key[0].length = 1;
  key[0].key = &reqresp_id;
  key[1].length = 1;
  key[1].key = &pinfo->num;
  key[2].length = 0;
  key[2].key = NULL;

  if (!pinfo->flags.in_error_pkt) {
    if (!pinfo->fd->visited) {
      if (!(flags&F_RESPONSE)) {
        /* This is a request */
        gboolean new_transaction = FALSE;

        /* Check if we've seen this transaction before */
        dns_trans=(dns_transaction_t *)wmem_tree_lookup32_array_le(dns_info->pdus, key);
        if ((dns_trans == NULL) || (dns_trans->id != reqresp_id) || (dns_trans->rep_frame > 0)) {
          new_transaction = TRUE;
        } else {
          nstime_t request_delta;

          /* Has not enough time elapsed that we consider this request a retransmission? */
          nstime_delta(&request_delta, &pinfo->abs_ts, &dns_trans->req_time);
          if (nstime_to_sec(&request_delta) < (double)retransmission_timer) {
            retransmission = TRUE;
          } else {
            new_transaction = TRUE;
          }
        }

        if (new_transaction) {
          dns_trans=wmem_new(wmem_file_scope(), dns_transaction_t);
          dns_trans->req_frame=pinfo->num;
          dns_trans->rep_frame=0;
          dns_trans->req_time=pinfo->abs_ts;
          dns_trans->id = reqresp_id;
          dns_trans->multiple_responds=FALSE;
          wmem_tree_insert32_array(dns_info->pdus, key, (void *)dns_trans);
        }
      } else {
        dns_trans=(dns_transaction_t *)wmem_tree_lookup32_array_le(dns_info->pdus, key);
        if (dns_trans) {
          if (dns_trans->id != reqresp_id) {
            dns_trans = NULL;
          } else if (dns_trans->rep_frame == 0) {
            dns_trans->rep_frame=pinfo->num;
          } else if (!dns_trans->multiple_responds) {
            retransmission = TRUE;
          }
        }
      }
    } else {
      dns_trans=(dns_transaction_t *)wmem_tree_lookup32_array_le(dns_info->pdus, key);
      if (dns_trans) {
        if (dns_trans->id != reqresp_id) {
          dns_trans = NULL;
        } else if ((!(flags & F_RESPONSE)) && (dns_trans->req_frame != pinfo->num)) {
          /* This is a request retransmission, create a "fake" dns_trans structure*/
          dns_transaction_t *retrans_dns = wmem_new(wmem_packet_scope(), dns_transaction_t);
          retrans_dns->req_frame=dns_trans->req_frame;
          retrans_dns->rep_frame=0;
          retrans_dns->req_time=pinfo->abs_ts;
          dns_trans = retrans_dns;

          retransmission = TRUE;
        } else if ((flags & F_RESPONSE) && (dns_trans->rep_frame != pinfo->num) && (!dns_trans->multiple_responds)) {
          retransmission = TRUE;
        }
      }
    }
  }
  if (!dns_trans) {
    /* create a "fake" dns_trans structure */
    dns_trans=wmem_new(wmem_packet_scope(), dns_transaction_t);
    dns_trans->req_frame=0;
    dns_trans->rep_frame=0;
    dns_trans->req_time=pinfo->abs_ts;
  }

  if (transport == DNS_TRANSPORT_TCP) {
    /* Put the length indication into the tree. */
    proto_tree_add_item(dns_tree, hf_dns_length, tvb, offset - 2, 2, ENC_BIG_ENDIAN);
  }

  transaction_item = proto_tree_add_uint(dns_tree, hf_dns_transaction_id, tvb,
                offset + DNS_ID, 2, id);

  tf = proto_tree_add_item(dns_tree, hf_dns_flags, tvb,
                offset + DNS_FLAGS, 2, ENC_BIG_ENDIAN);
  proto_item_append_text(tf, " %s",
                val_to_str_const(opcode, opcode_vals, "Unknown operation"));
  if (flags & F_RESPONSE) {
    proto_item_append_text(tf, " response, %s",
                val_to_str_const(rcode, rcode_vals, "Unknown error"));
  }
  field_tree = proto_item_add_subtree(tf, ett_dns_flags);
  proto_tree_add_item(field_tree, hf_dns_flags_response,
                tvb, offset + DNS_FLAGS, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(field_tree, hf_dns_flags_opcode,
                tvb, offset + DNS_FLAGS, 2, ENC_BIG_ENDIAN);
  if (is_llmnr) {
    if (flags & F_RESPONSE) {
      proto_tree_add_item(field_tree, hf_dns_flags_conflict_response,
                tvb, offset + DNS_FLAGS, 2, ENC_BIG_ENDIAN);
    } else {
      proto_tree_add_item(field_tree, hf_dns_flags_conflict_query,
                tvb, offset + DNS_FLAGS, 2, ENC_BIG_ENDIAN);
    }
    proto_tree_add_item(field_tree, hf_dns_flags_truncated,
                tvb, offset + DNS_FLAGS, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_dns_flags_tentative,
                tvb, offset + DNS_FLAGS, 2, ENC_BIG_ENDIAN);
    if (flags & F_RESPONSE) {
      proto_tree_add_item(field_tree, hf_dns_flags_rcode,
                tvb, offset + DNS_FLAGS, 2, ENC_BIG_ENDIAN);
    }
  } else {
    if (flags & F_RESPONSE) {
      proto_tree_add_item(field_tree, hf_dns_flags_authoritative,
                tvb, offset + DNS_FLAGS, 2, ENC_BIG_ENDIAN);
    }
    proto_tree_add_item(field_tree, hf_dns_flags_truncated,
                tvb, offset + DNS_FLAGS, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(field_tree, hf_dns_flags_recdesired,
                tvb, offset + DNS_FLAGS, 2, ENC_BIG_ENDIAN);
    if (flags & F_RESPONSE) {
      proto_tree_add_item(field_tree, hf_dns_flags_recavail,
                tvb, offset + DNS_FLAGS, 2, ENC_BIG_ENDIAN);
    }
    proto_tree_add_item(field_tree, hf_dns_flags_z,
                tvb, offset + DNS_FLAGS, 2, ENC_BIG_ENDIAN);
    if (flags & F_RESPONSE) {
      proto_tree_add_item(field_tree, hf_dns_flags_authenticated,
                tvb, offset + DNS_FLAGS, 2, ENC_BIG_ENDIAN);
    } else if (flags & F_AUTHENTIC) {
      proto_tree_add_item(field_tree, hf_dns_flags_ad,
                                 tvb, offset + DNS_FLAGS, 2, ENC_BIG_ENDIAN);
    }
    proto_tree_add_item(field_tree, hf_dns_flags_checkdisable,
                tvb, offset + DNS_FLAGS, 2, ENC_BIG_ENDIAN);
    if (flags & F_RESPONSE) {
      proto_tree_add_item(field_tree, hf_dns_flags_rcode,
                tvb, offset + DNS_FLAGS, 2, ENC_BIG_ENDIAN);
    }
  }

  quest = tvb_get_ntohs(tvb, offset + DNS_QUEST);
  if (isupdate) {
    proto_tree_add_uint(dns_tree, hf_dns_count_zones, tvb,
        offset + DNS_QUEST, 2, quest);
  } else {
    proto_tree_add_uint(dns_tree, hf_dns_count_questions, tvb,
        offset + DNS_QUEST, 2, quest);
  }
  ans = tvb_get_ntohs(tvb, offset + DNS_ANS);
  if (isupdate) {
    proto_tree_add_uint(dns_tree, hf_dns_count_prerequisites, tvb,
        offset + DNS_ANS, 2, ans);
  } else {
    proto_tree_add_uint(dns_tree, hf_dns_count_answers, tvb,
        offset + DNS_ANS, 2, ans);
  }
  auth = tvb_get_ntohs(tvb, offset + DNS_AUTH);
  if (isupdate) {
    proto_tree_add_uint(dns_tree, hf_dns_count_updates, tvb,
        offset + DNS_AUTH, 2, auth);
  } else {
    proto_tree_add_uint(dns_tree, hf_dns_count_auth_rr, tvb,
        offset + DNS_AUTH, 2, auth);
  }
  add = tvb_get_ntohs(tvb, offset + DNS_ADD);
  proto_tree_add_uint(dns_tree, hf_dns_count_add_rr, tvb,
      offset + DNS_ADD, 2, add);

  cur_off = offset + DNS_HDRLEN;

  if (opcode == OPCODE_DSO && quest == 0 && ans == 0 && auth == 0 && add == 0) {
    /* DSO messages differs somewhat from the traditional DNS message format.
       the four count fields (QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT) are set to zero */
      cur_off += dissect_dso_data(tvb, cur_off, pinfo, dns_tree);
  }

  if (quest > 0) {
    /* If this is a response, don't add information about the queries
       to the summary, just add information about the answers. */
    cur_off += dissect_query_records(tvb, cur_off, dns_data_offset, quest, pinfo,
                                     dns_tree, isupdate, is_mdns, &is_multiple_responds);
    dns_trans->multiple_responds = is_multiple_responds;
  }

  if (ans > 0) {
    /* If this is a request, don't add information about the answers
       to the summary, just add information about the queries. */
    cur_off += dissect_answer_records(tvb, cur_off, dns_data_offset, ans,
                                      dns_tree,
                                      (isupdate ? "Prerequisites" : "Answers"),
                                      pinfo, is_mdns);
  }

  /* Don't add information about the authoritative name servers, or the
     additional records, to the summary. */
  if (auth > 0) {
    cur_off += dissect_answer_records(tvb, cur_off, dns_data_offset, auth, dns_tree,
                                      (isupdate ? "Updates" :
                                       "Authoritative nameservers"),
                                      pinfo, is_mdns);
  }

  if (add > 0) {
    cur_off += dissect_answer_records(tvb, cur_off, dns_data_offset, add, dns_tree, "Additional records",
                                      pinfo, is_mdns);
  }

  /* print state tracking in the tree */
  if (!(flags&F_RESPONSE)) {
    proto_item *it;
    /* This is a request */
    if ((retransmission) && (dns_trans->req_frame) && (!pinfo->flags.in_error_pkt)) {
      expert_add_info_format(pinfo, transaction_item, &ei_dns_retransmit_request, "DNS query retransmission. Original request in frame %d", dns_trans->req_frame);

      it=proto_tree_add_uint(dns_tree, hf_dns_retransmit_request_in, tvb, 0, 0, dns_trans->req_frame);
      proto_item_set_generated(it);

      it=proto_tree_add_boolean(dns_tree, hf_dns_retransmission, tvb, 0, 0, TRUE);
      proto_item_set_generated(it);
    } else if (dns_trans->rep_frame) {

      it=proto_tree_add_uint(dns_tree, hf_dns_response_in, tvb, 0, 0, dns_trans->rep_frame);
      proto_item_set_generated(it);
    }
  } else {
    /* This is a reply */
    proto_item *it;
    if (dns_trans->req_frame) {
      if ((retransmission) && (dns_trans->rep_frame) && (!pinfo->flags.in_error_pkt)) {
        expert_add_info_format(pinfo, transaction_item, &ei_dns_retransmit_response, "DNS response retransmission. Original response in frame %d", dns_trans->rep_frame);

        it=proto_tree_add_uint(dns_tree, hf_dns_retransmit_response_in, tvb, 0, 0, dns_trans->rep_frame);
        proto_item_set_generated(it);

        it=proto_tree_add_boolean(dns_tree, hf_dns_retransmission, tvb, 0, 0, TRUE);
        proto_item_set_generated(it);
      } else {
        it=proto_tree_add_uint(dns_tree, hf_dns_response_to, tvb, 0, 0, dns_trans->req_frame);
        proto_item_set_generated(it);

        nstime_delta(&delta, &pinfo->abs_ts, &dns_trans->req_time);
        it=proto_tree_add_time(dns_tree, hf_dns_time, tvb, 0, 0, &delta);
        proto_item_set_generated(it);
      }
    } else {
      if (!retransmission) {
        it=proto_tree_add_boolean(dns_tree, hf_dns_unsolicited, tvb, 0, 0, TRUE);
        proto_item_set_generated(it);
      }
    }
  }

  /* Do we have any extraneous data? */
  gint extraneous_length = tvb_reported_length_remaining(tvb, cur_off);
  if(extraneous_length > 0) {
    proto_tree *ext_tree;
    proto_item *it;

    ext_tree = proto_tree_add_subtree_format(dns_tree, tvb, cur_off, extraneous_length,
                                             ett_dns_extraneous, &it, "Extraneous Data (%d bytes)", extraneous_length);

    it = proto_tree_add_item(ext_tree, hf_dns_extraneous_data, tvb, cur_off, extraneous_length, ENC_NA);

    it = proto_tree_add_int(ext_tree, hf_dns_extraneous_length, tvb, 0, 0, extraneous_length);
    proto_item_set_generated(it);

    it = proto_tree_add_expert(ext_tree, pinfo, &ei_dns_extraneous_data, tvb, cur_off, extraneous_length);
    proto_item_set_hidden(it);
  }

  /* Collect stats */
  if (pinfo->flags.in_error_pkt) {
    return;
  }
  if (is_mdns) {
    /* TODO */
  } else if (is_llmnr) {
    /* TODO */
  } else {
    dns_stats = wmem_new0(wmem_packet_scope(), struct DnsTap);
    dns_stats->packet_rcode = rcode;
    dns_stats->packet_opcode = opcode;
    dns_stats->packet_qr = flags >> 15;
    if (quest > 0) {
      get_dns_name_type_class(tvb, offset + DNS_HDRLEN, dns_data_offset, &name, &name_len, &qtype, &qclass);
      dns_stats->packet_qtype = qtype;
      dns_stats->packet_qclass = qclass;
    }
    dns_stats->payload_size = tvb_captured_length(tvb);
    dns_stats->nquestions = quest;
    dns_stats->nanswers = ans;
    dns_stats->nauthorities = auth;
    dns_stats->nadditionals = add;
    if (quest > 0) {
      dns_stats->qname_len = name_len;
      dns_stats->qname_labels = qname_labels_count(name, name_len);
    }
    if (flags & F_RESPONSE) {
      if (dns_trans->req_frame == 0) {
        /* we don't have a request. This is an unsolicited response */
        dns_stats->unsolicited = TRUE;
      } else {
        if (retransmission)
          dns_stats->retransmission = TRUE;
        else
          dns_stats->rrt = delta;
        }
    }
    tap_queue_packet(dns_tap, pinfo, dns_stats);
  }
}

static int
dissect_dns_udp_sctp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "DNS");

  dissect_dns_common(tvb, pinfo, tree, DNS_TRANSPORT_UDP, FALSE, FALSE);
  return tvb_captured_length(tvb);
}

static int
dissect_dns_doh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "DoH");

  dissect_dns_common(tvb, pinfo, tree, DNS_TRANSPORT_HTTP, FALSE, FALSE);
  return tvb_captured_length(tvb);
}

static int
dissect_dns_doq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "DNS");

  dissect_dns_common(tvb, pinfo, tree, DNS_TRANSPORT_QUIC, FALSE, FALSE);
  return tvb_captured_length(tvb);
}

static int
dissect_mdns_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "MDNS");

  dissect_dns_common(tvb, pinfo, tree, DNS_TRANSPORT_UDP, TRUE, FALSE);
  return tvb_captured_length(tvb);
}

static int
dissect_llmnr_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LLMNR");

  dissect_dns_common(tvb, pinfo, tree, DNS_TRANSPORT_UDP, FALSE, TRUE);
  return tvb_captured_length(tvb);
}

static guint
get_dns_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  guint16 plen;

  /*
   * Get the length of the DNS packet.
   */
  plen = tvb_get_ntohs(tvb, offset);

  /*
   * That length doesn't include the length field itself; add that in.
   */
  return plen + 2;
}

static int
dissect_dns_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "DNS");

  dissect_dns_common(tvb, pinfo, tree, DNS_TRANSPORT_TCP, FALSE, FALSE);
  return tvb_reported_length(tvb);
}

static int
dissect_dns_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  tcp_dissect_pdus(tvb, pinfo, tree, dns_desegment, 2, get_dns_pdu_len,
                   dissect_dns_tcp_pdu, data);
  return tvb_reported_length(tvb);
}

static int
dissect_dns(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  /* since draft-ietf-doh-dns-over-https-07 */
  gboolean is_doh = !g_strcmp0(pinfo->match_string, "application/dns-message");

  if (is_doh) {
    return dissect_dns_doh(tvb, pinfo, tree, data);
  } else if (pinfo->ptype == PT_TCP) {
    return dissect_dns_tcp(tvb, pinfo, tree, data);
  } else {
    dissect_dns_udp_sctp(tvb, pinfo, tree, data);
    return tvb_captured_length(tvb);
  }
}

static gboolean
dissect_dns_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  /*
   * Try hard to match DNS messages while avoiding false positives. Look for:
   *
   * - Non-empty DNS messages (more than just a header).
   * - Flags: QR bit (0-Query, 1-Response); Opcode bits: Standard Query (0000)
   * - Questions: 1 (for queries), or 0 or 1 (for responses like AXFR)
   * - Answer RRs: 0 (for queries) or a low number (for responses)
   * - Authority RRs: 0 (for queries) or a low number (for responses)
   * - Additional RRs: assume a low number.
   *
   * Not implemented, but perhaps we could check for:
   * - Require that the question and answer count cannot both be zero. Perhaps
   *   some protocols have large sequences of zero bytes, this check reduces the
   *   probability of matching such payloads.
   * - Assume a valid QNAME in the question section. (Is there sufficient data
   *   for a valid name?)
   * - Assume a common QTYPE and QCLASS (IN/CH).
   * - Potentially implement heuristics for TCP by checking the length prefix?
   */
  int               offset = 0;
  guint16           flags, quest, ans, auth, add;
  /*
   * max_ans=10 was sufficient for recognizing the majority of DNS messages from
   * the rrdns test suite, but four "huge record" test cases have 100 answers.
   * The max_auth and max_add numbers were picked arbitrarily.
   */
  const guint16     max_ans = 100;
  const guint16     max_auth = 10;
  const guint16     max_add = 10;

  if (tvb_reported_length(tvb) <= DNS_HDRLEN)
    return FALSE;

  flags = tvb_get_ntohs(tvb, offset + DNS_FLAGS);
  if ((flags & F_OPCODE) != 0)
    return FALSE;

  quest = tvb_get_ntohs(tvb, offset + DNS_QUEST);
  ans = tvb_get_ntohs(tvb, offset + DNS_ANS);
  auth = tvb_get_ntohs(tvb, offset + DNS_AUTH);
  if (!(flags & F_RESPONSE)) {
    if (quest != 1 || ans != 0 || auth != 0)
      return FALSE;
  } else {
    if (quest > 1 || ans > max_ans || auth > max_auth)
      return FALSE;
  }

  add = tvb_get_ntohs(tvb, offset + DNS_ADD);
  if (add > max_add)
    return FALSE;

  dissect_dns(tvb, pinfo, tree, NULL);
  return TRUE;
}

static void dns_stats_tree_init(stats_tree* st)
{
  st_node_packets = stats_tree_create_node(st, st_str_packets, 0, STAT_DT_INT, TRUE);
  st_node_packet_qr = stats_tree_create_pivot(st, st_str_packet_qr, st_node_packets);
  st_node_packet_qtypes = stats_tree_create_pivot(st, st_str_packet_qtypes, st_node_packets);
  st_node_packet_qclasses = stats_tree_create_pivot(st, st_str_packet_qclasses, st_node_packets);
  st_node_packet_rcodes = stats_tree_create_pivot(st, st_str_packet_rcodes, st_node_packets);
  st_node_packet_opcodes = stats_tree_create_pivot(st, st_str_packet_opcodes, st_node_packets);
  st_node_packets_avg_size = stats_tree_create_node(st, st_str_packets_avg_size, 0, STAT_DT_INT, FALSE);
  st_node_query_stats = stats_tree_create_node(st, st_str_query_stats, 0, STAT_DT_INT, TRUE);
  st_node_query_qname_len = stats_tree_create_node(st, st_str_query_qname_len, st_node_query_stats, STAT_DT_INT, FALSE);
  st_node_query_domains = stats_tree_create_node(st, st_str_query_domains, st_node_query_stats, STAT_DT_INT, TRUE);
  st_node_query_domains_l1 = stats_tree_create_node(st, st_str_query_domains_l1, st_node_query_domains, STAT_DT_INT, FALSE);
  st_node_query_domains_l2 = stats_tree_create_node(st, st_str_query_domains_l2, st_node_query_domains, STAT_DT_INT, FALSE);
  st_node_query_domains_l3 = stats_tree_create_node(st, st_str_query_domains_l3, st_node_query_domains, STAT_DT_INT, FALSE);
  st_node_query_domains_lmore = stats_tree_create_node(st, st_str_query_domains_lmore, st_node_query_domains, STAT_DT_INT, FALSE);
  st_node_response_stats = stats_tree_create_node(st, st_str_response_stats, 0, STAT_DT_INT, TRUE);
  st_node_response_nquestions = stats_tree_create_node(st, st_str_response_nquestions,
    st_node_response_stats, STAT_DT_INT, FALSE);
  st_node_response_nanswers = stats_tree_create_node(st, st_str_response_nanswers,
    st_node_response_stats, STAT_DT_INT, FALSE);
  st_node_response_nauthorities = stats_tree_create_node(st, st_str_response_nauthorities,
    st_node_response_stats, STAT_DT_INT, FALSE);
  st_node_response_nadditionals = stats_tree_create_node(st, st_str_response_nadditionals,
    st_node_response_stats, STAT_DT_INT, FALSE);
  st_node_service_stats = stats_tree_create_node(st, st_str_service_stats, 0, STAT_DT_INT, TRUE);
  st_node_service_unsolicited = stats_tree_create_node(st, st_str_service_unsolicited, st_node_service_stats, STAT_DT_INT, FALSE);
  st_node_service_retransmission = stats_tree_create_node(st, st_str_service_retransmission, st_node_service_stats, STAT_DT_INT, FALSE);
  st_node_service_rrt = stats_tree_create_node(st, st_str_service_rrt, st_node_service_stats, STAT_DT_FLOAT, FALSE);
}

static tap_packet_status dns_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_, epan_dissect_t* edt _U_, const void* p, tap_flags_t flags _U_)
{
  const struct DnsTap *pi = (const struct DnsTap *)p;
  tick_stat_node(st, st_str_packets, 0, FALSE);
  stats_tree_tick_pivot(st, st_node_packet_qr,
          val_to_str(pi->packet_qr, dns_qr_vals, "Unknown qr (%d)"));
  stats_tree_tick_pivot(st, st_node_packet_qtypes,
          val_to_str(pi->packet_qtype, dns_types_description_vals, "Unknown packet type (%d)"));
  stats_tree_tick_pivot(st, st_node_packet_qclasses,
          val_to_str(pi->packet_qclass, dns_classes, "Unknown class (%d)"));
  stats_tree_tick_pivot(st, st_node_packet_rcodes,
          val_to_str(pi->packet_rcode, rcode_vals, "Unknown rcode (%d)"));
  stats_tree_tick_pivot(st, st_node_packet_opcodes,
          val_to_str(pi->packet_opcode, opcode_vals, "Unknown opcode (%d)"));
  avg_stat_node_add_value_int(st, st_str_packets_avg_size, 0, FALSE,
          pi->payload_size);

  /* split up stats for queries and responses */
  if (pi->packet_qr == 0) {
    avg_stat_node_add_value_int(st, st_str_query_qname_len, 0, FALSE, pi->qname_len);
    switch(pi->qname_labels) {
      case 1:
        tick_stat_node(st, st_str_query_domains_l1, 0, FALSE);
        break;
      case 2:
        tick_stat_node(st, st_str_query_domains_l2, 0, FALSE);
        break;
      case 3:
        tick_stat_node(st, st_str_query_domains_l3, 0, FALSE);
        break;
      default:
        tick_stat_node(st, st_str_query_domains_lmore, 0, FALSE);
        break;
    }
  } else {
    avg_stat_node_add_value_int(st, st_str_response_nquestions, 0, FALSE, pi->nquestions);
    avg_stat_node_add_value_int(st, st_str_response_nanswers, 0, FALSE, pi->nanswers);
    avg_stat_node_add_value_int(st, st_str_response_nauthorities, 0, FALSE, pi->nauthorities);
    avg_stat_node_add_value_int(st, st_str_response_nadditionals, 0, FALSE, pi->nadditionals);
    if (pi->unsolicited) {
      tick_stat_node(st, st_str_service_unsolicited, 0, FALSE);
    } else {
        avg_stat_node_add_value_int(st, st_str_response_nquestions, 0, FALSE, pi->nquestions);
        avg_stat_node_add_value_int(st, st_str_response_nanswers, 0, FALSE, pi->nanswers);
        avg_stat_node_add_value_int(st, st_str_response_nauthorities, 0, FALSE, pi->nauthorities);
        avg_stat_node_add_value_int(st, st_str_response_nadditionals, 0, FALSE, pi->nadditionals);
        if (pi->unsolicited) {
          tick_stat_node(st, st_str_service_unsolicited, 0, FALSE);
        } else {
          if (pi->retransmission)
            tick_stat_node(st, st_str_service_retransmission, 0, FALSE);
          else
            avg_stat_node_add_value_float(st, st_str_service_rrt, 0, FALSE, (gfloat)(pi->rrt.secs*1000. + pi->rrt.nsecs/1000000.0));
        }
    }
  }
  return TAP_PACKET_REDRAW;
}

void
proto_reg_handoff_dns(void)
{
  dissector_handle_t mdns_udp_handle;
  dissector_handle_t llmnr_udp_handle;
  dissector_handle_t doq_handle;

  mdns_udp_handle  = create_dissector_handle(dissect_mdns_udp, proto_mdns);
  llmnr_udp_handle = create_dissector_handle(dissect_llmnr_udp, proto_llmnr);
  doq_handle  = create_dissector_handle(dissect_dns_doq, proto_dns);
  dissector_add_uint_with_preference("udp.port", UDP_PORT_MDNS, mdns_udp_handle);
  dissector_add_uint_with_preference("udp.port", UDP_PORT_LLMNR, llmnr_udp_handle);
  dissector_add_uint("sctp.port", SCTP_PORT_DNS, dns_handle);
#if 0
  dissector_add_uint("sctp.ppi",  DNS_PAYLOAD_PROTOCOL_ID, dns_handle);
#endif
  stats_tree_register("dns", "dns", "DNS", 0, dns_stats_tree_packet, dns_stats_tree_init, NULL);
  gssapi_handle  = find_dissector_add_dependency("gssapi", proto_dns);
  ntlmssp_handle = find_dissector_add_dependency("ntlmssp", proto_dns);
  ssl_dissector_add(TCP_PORT_DNS_TLS, dns_handle);
  // RFC 7858 - registration via https://mailarchive.ietf.org/arch/msg/dns-privacy/iZ2rDIhFB2ZWsGC3PcdBVLGa8Do
  dissector_add_string("tls.alpn", "dot", dns_handle);
  dtls_dissector_add(UDP_PORT_DNS_DTLS, dns_handle);
  dissector_add_uint_range_with_preference("tcp.port", DEFAULT_DNS_TCP_PORT_RANGE, dns_handle);
  dissector_add_uint_range_with_preference("udp.port", DEFAULT_DNS_PORT_RANGE, dns_handle);
  dissector_add_string("media_type", "application/dns-message", dns_handle); /* since draft-ietf-doh-dns-over-https-07 */
  dissector_add_string("quic.proto", "doq", doq_handle); /* https://www.ietf.org/archive/id/draft-ietf-dprive-dnsoquic-03.txt */
  heur_dissector_add("udp", dissect_dns_heur, "DNS over UDP", "dns_udp", proto_dns, HEURISTIC_ENABLE);
}

void
proto_register_dns(void)
{
  static hf_register_info hf[] = {
    { &hf_dns_length,
      { "Length", "dns.length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Length of DNS-over-TCP request or response", HFILL }},

    { &hf_dns_flags,
      { "Flags", "dns.flags",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_flags_response,
      { "Response", "dns.flags.response",
        FT_BOOLEAN, 16, TFS(&tfs_flags_response), F_RESPONSE,
        "Is the message a response?", HFILL }},

    { &hf_dns_flags_opcode,
      { "Opcode", "dns.flags.opcode",
        FT_UINT16, BASE_DEC, VALS(opcode_vals), F_OPCODE,
        "Operation code", HFILL }},

    { &hf_dns_flags_authoritative,
      { "Authoritative", "dns.flags.authoritative",
        FT_BOOLEAN, 16, TFS(&tfs_flags_authoritative), F_AUTHORITATIVE,
        "Is the server is an authority for the domain?", HFILL }},

    { &hf_dns_flags_conflict_query,
      { "Conflict", "dns.flags.conflict",
        FT_BOOLEAN, 16, TFS(&tfs_flags_conflict_query), F_CONFLICT,
        "Did we receive multiple responses to a query?", HFILL }},

    { &hf_dns_flags_conflict_response,
      { "Conflict", "dns.flags.conflict",
        FT_BOOLEAN, 16, TFS(&tfs_flags_conflict_response), F_CONFLICT,
        "Is the name considered unique?", HFILL }},

    { &hf_dns_flags_truncated,
      { "Truncated", "dns.flags.truncated",
        FT_BOOLEAN, 16, TFS(&tfs_flags_truncated), F_TRUNCATED,
        "Is the message truncated?", HFILL }},

    { &hf_dns_flags_recdesired,
      { "Recursion desired", "dns.flags.recdesired",
        FT_BOOLEAN, 16, TFS(&tfs_flags_recdesired), F_RECDESIRED,
        "Do query recursively?", HFILL }},

    { &hf_dns_flags_tentative,
      { "Tentative", "dns.flags.tentative",
        FT_BOOLEAN, 16, TFS(&tfs_flags_tentative), F_TENTATIVE,
        "Is the responder authoritative for the name, but not yet verified the uniqueness?", HFILL }},

    { &hf_dns_flags_recavail,
      { "Recursion available", "dns.flags.recavail",
        FT_BOOLEAN, 16, TFS(&tfs_flags_recavail), F_RECAVAIL,
        "Can the server do recursive queries?", HFILL }},

    { &hf_dns_flags_z,
      { "Z", "dns.flags.z",
        FT_BOOLEAN, 16, TFS(&tfs_flags_z), F_Z,
        "Z flag", HFILL }},

    { &hf_dns_flags_authenticated,
      { "Answer authenticated", "dns.flags.authenticated",
        FT_BOOLEAN, 16, TFS(&tfs_flags_authenticated), F_AUTHENTIC,
        "Was the reply data authenticated by the server?", HFILL }},

    { &hf_dns_flags_ad,
      { "AD bit", "dns.flags.authenticated",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), F_AUTHENTIC,
        NULL, HFILL }},

    { &hf_dns_flags_checkdisable,
      { "Non-authenticated data", "dns.flags.checkdisable",
        FT_BOOLEAN, 16, TFS(&tfs_flags_checkdisable), F_CHECKDISABLE,
        "Is non-authenticated data acceptable?", HFILL }},

    { &hf_dns_flags_rcode,
      { "Reply code", "dns.flags.rcode",
        FT_UINT16, BASE_DEC, VALS(rcode_vals), F_RCODE,
        NULL, HFILL }},

    { &hf_dns_transaction_id,
      { "Transaction ID", "dns.id",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "Identification of transaction", HFILL }},

    { &hf_dns_qry_type,
      { "Type", "dns.qry.type",
        FT_UINT16, BASE_DEC|BASE_EXT_STRING, &dns_types_description_vals_ext, 0,
        "Query Type", HFILL }},

    { &hf_dns_qry_class,
      { "Class", "dns.qry.class",
        FT_UINT16, BASE_HEX, VALS(dns_classes), 0x0,
        "Query Class", HFILL }},

    { &hf_dns_qry_class_mdns,
      { "Class", "dns.qry.class",
        FT_UINT16, BASE_HEX, VALS(dns_classes), 0x7FFF,
        "Query Class", HFILL }},

    { &hf_dns_qry_qu,
      { "\"QU\" question", "dns.qry.qu",
        FT_BOOLEAN, 16, NULL, C_QU,
        "QU flag", HFILL }},

    { &hf_dns_qry_name,
      { "Name", "dns.qry.name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Query Name", HFILL }},

    { &hf_dns_qry_name_len,
      { "Name Length", "dns.qry.name.len",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Query Name Len", HFILL }},

    { &hf_dns_count_labels,
      { "Label Count", "dns.count.labels",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Query Label Count", HFILL }},

    { &hf_dns_rr_type,
      { "Type", "dns.resp.type",
        FT_UINT16, BASE_DEC|BASE_EXT_STRING, &dns_types_description_vals_ext, 0x0,
        "Response Type", HFILL }},

    { &hf_dns_rr_class,
      { "Class", "dns.resp.class",
        FT_UINT16, BASE_HEX, VALS(dns_classes), 0x0,
        "Response Class", HFILL }},

    { &hf_dns_rr_class_mdns,
      { "Class", "dns.resp.class",
        FT_UINT16, BASE_HEX, VALS(dns_classes), 0x7FFF,
        "Response Class", HFILL }},

    { &hf_dns_rr_cache_flush,
      { "Cache flush", "dns.resp.cache_flush",
        FT_BOOLEAN, 16, NULL, C_FLUSH,
        "Cache flush flag", HFILL }},

    { &hf_dns_rr_ext_rcode,
      { "Higher bits in extended RCODE", "dns.resp.ext_rcode",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_rr_edns0_version,
      { "EDNS0 version", "dns.resp.edns0_version",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_rr_z,
      { "Z", "dns.resp.z",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_rr_z_do,
      { "DO bit", "dns.resp.z.do",
        FT_BOOLEAN, 16, TFS(&tfs_dns_rr_z_do), 0x8000,
        "DNSSEC OK", HFILL }},

    { &hf_dns_rr_z_reserved,
      { "Reserved", "dns.resp.z.reserved",
        FT_UINT16, BASE_HEX, NULL, 0x7FFF,
        NULL, HFILL }},

    { &hf_dns_srv_service,
      { "Service", "dns.srv.service",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Desired service", HFILL }},

    { &hf_dns_srv_proto,
      { "Protocol", "dns.srv.proto",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Desired protocol", HFILL }},

    { &hf_dns_srv_name,
      { "Name", "dns.srv.name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Domain this resource record refers to", HFILL }},

    { &hf_dns_srv_priority,
      { "Priority", "dns.srv.priority",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_srv_weight,
      { "Weight", "dns.srv.weight",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_srv_port,
      { "Port", "dns.srv.port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_srv_target,
      { "Target", "dns.srv.target",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_naptr_order,
      { "Order", "dns.naptr.order",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_naptr_preference,
      { "Preference", "dns.naptr.preference",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_naptr_flags_length,
      { "Flags Length", "dns.naptr.flags_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_naptr_flags,
      { "Flags", "dns.naptr.flags",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_naptr_service_length,
      { "Service Length", "dns.naptr.service_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_naptr_service,
      { "Service", "dns.naptr.service",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_naptr_regex_length,
      { "Regex Length", "dns.naptr.regex_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_naptr_regex,
      { "Regex", "dns.naptr.regex",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_naptr_replacement_length,
      { "Replacement Length", "dns.naptr.replacement_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_naptr_replacement,
      { "Replacement", "dns.naptr.replacement",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_rr_name,
      { "Name", "dns.resp.name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Response Name", HFILL }},

    { &hf_dns_rr_ttl,
      { "Time to live", "dns.resp.ttl",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Response TTL", HFILL }},

    { &hf_dns_rr_len,
      { "Data length", "dns.resp.len",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Response Length", HFILL }},

    { &hf_dns_a,
      { "Address", "dns.a",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "Response Address", HFILL }},

    { &hf_dns_md,
      { "Mail Destination", "dns.md",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_mf,
      { "Mail Forwarder", "dns.mf",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_mb,
      { "MailBox Domaine", "dns.mb",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_mg,
      { "Mail Group member", "dns.mg",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_mr,
      { "Mail Rename domaine", "dns.mr",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_null,
      { "Null (data)", "dns.null",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_aaaa,
      { "AAAA Address", "dns.aaaa",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        "AAAA Response Address", HFILL }},

    { &hf_dns_cname,
      { "CNAME", "dns.cname",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Response Primary Name", HFILL }},

    { &hf_dns_rr_udp_payload_size_mdns,
      { "UDP payload size", "dns.rr.udp_payload_size",
        FT_UINT16, BASE_HEX, NULL, 0x7FFF,
        NULL, HFILL }},

    { &hf_dns_rr_udp_payload_size,
      { "UDP payload size", "dns.rr.udp_payload_size",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_soa_mname,
      { "Primary name server", "dns.soa.mname",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_soa_rname,
      { "Responsible authority's mailbox", "dns.soa.rname",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_soa_serial_number,
      { "Serial Number", "dns.soa.serial_number",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_soa_refresh_interval,
      { "Refresh Interval", "dns.soa.refresh_interval",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_soa_retry_interval,
      { "Retry Interval", "dns.soa.retry_interval",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_soa_expire_limit,
      { "Expire limit", "dns.soa.expire_limit",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_soa_minimum_ttl,
      { "Minimum TTL", "dns.soa.minimum_ttl",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_ptr_domain_name,
      { "Domain Name", "dns.ptr.domain_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_wks_address,
      { "Address", "dns.wks.address",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_wks_protocol,
      { "Protocol", "dns.wks.protocol",
        FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ipproto_val_ext, 0x0,
        NULL, HFILL }},

    { &hf_dns_wks_bits,
      { "Bits", "dns.wks.bits",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_hinfo_cpu_length,
      { "CPU Length", "dns.hinfo.cpu_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_hinfo_cpu,
      { "CPU", "dns.hinfo.cpu",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_hinfo_os_length,
      { "OS Length", "dns.hinfo.os_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_hinfo_os,
      { "OS", "dns.hinfo.os",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_minfo_r_mailbox,
      { "Responsible Mailbox", "dns.minfo.r",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_minfo_e_mailbox,
      { "Error Mailbox", "dns.minfo.e",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_mx_preference,
      { "Preference", "dns.mx.preference",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_mx_mail_exchange,
      { "Mail Exchange", "dns.mx.mail_exchange",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_txt_length,
      { "TXT Length", "dns.txt.length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_txt,
      { "TXT", "dns.txt",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_openpgpkey,
      { "OpenPGP Key", "dns.openpgpkey",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_csync_soa,
      { "SOA", "dns.csync.soa",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_csync_flags,
      { "Flags", "dns.csync.flags",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_csync_flags_immediate,
      { "immediate", "dns.csync.flags.immediate",
        FT_BOOLEAN, 16, NULL, 0x0001,
        NULL, HFILL }},

    { &hf_dns_csync_flags_soaminimum,
      { "soaminimum", "dns.csync.flags.soaminimum",
        FT_BOOLEAN, 16, NULL, 0x0002,
        NULL, HFILL }},

    { &hf_dns_csync_type_bitmap,
      { "Type Bitmap", "dns.csync.type_bitmap",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_zonemd_serial,
      { "Serial", "dns.zonemd.serial",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_zonemd_scheme,
      { "Scheme", "dns.zonemd.scheme",
        FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(dns_zonemd_scheme), 0x0,
        NULL, HFILL }},

    { &hf_dns_zonemd_hash_algo,
      { "Hash Algorithm", "dns.zonemd.hash_algo",
        FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(dns_zonemd_hash_algo), 0x0,
        NULL, HFILL }},

    { &hf_dns_zonemd_digest,
      { "Digest", "dns.zonemd.digest",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_svcb_priority,
      { "SvcPriority", "dns.svcb.svcpriority",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_svcb_target,
      { "TargetName", "dns.svcb.targetname",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_svcb_param_key,
      { "SvcParamKey", "dns.svcb.svcparam.key",
        FT_UINT16, BASE_DEC, VALS(dns_svcb_param_key_vals), 0x0,
        NULL, HFILL }},

    { &hf_dns_svcb_param_length,
      { "SvcParamValue length", "dns.svcb.svcparam.value.length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_svcb_param_value,
      { "SvcParamValue", "dns.svcb.svcparam.value",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_svcb_param,
      { "SvcParam", "dns.svcb.svcparam",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_svcb_param_mandatory_key,
      { "Mandatory key", "dns.svcb.svcparam.mandatory.key",
        FT_UINT16, BASE_DEC, VALS(dns_svcb_param_key_vals), 0x0,
        "Mandatory keys in this RR", HFILL }},

    { &hf_dns_svcb_param_alpn_length,
      { "ALPN length", "dns.svcb.svcparam.alpn.length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_svcb_param_alpn,
      { "ALPN", "dns.svcb.svcparam.alpn",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Additional supported protocols", HFILL }},

    { &hf_dns_svcb_param_port,
      { "Port", "dns.svcb.svcparam.port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Port for alternative endpoint", HFILL }},

    { &hf_dns_svcb_param_ipv4hint_ip,
      { "IP", "dns.svcb.svcparam.ipv4hint.ip",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "IPv4 address hints", HFILL }},

    { &hf_dns_svcb_param_echconfig,
      { "ECHConfig", "dns.svcb.svcparam.echconfig",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Encrypted ClientHello (ECH) infos", HFILL }},

    { &hf_dns_svcb_param_ipv6hint_ip,
      { "IP", "dns.svcb.svcparam.ipv6hint.ip",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        "IPv6 address hints", HFILL }},

    { &hf_dns_svcb_param_odohconfig,
      { "ODoHConfig", "dns.svcb.svcparam.odohconfig",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Oblivious DoH keys", HFILL }},

    { &hf_dns_spf_length,
      { "SPF Length", "dns.spf.length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_spf,
      { "SPF", "dns.spf",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_ilnp_nodeid_preference,
      { "Preference", "dns.ilnp.nid.preference",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_ilnp_nodeid,
      { "NodeID", "dns.ilnp.nid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_ilnp_locator32_preference,
      { "Preference", "dns.ilnp.l32.preference",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_ilnp_locator32,
      { "Locator32", "dns.ilnp.l32",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_ilnp_locator64_preference,
      { "Preference", "dns.ilnp.l64.preference",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_ilnp_locator64,
      { "Locator64", "dns.ilnp.l64",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_ilnp_locatorfqdn_preference,
      { "Preference", "dns.ilnp.lp.preference",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_ilnp_locatorfqdn,
      { "Locator FQDN", "dns.ilnp.lp",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_eui48,
      { "EUI48 Address", "dns.eui48",
        FT_ETHER, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_eui64,
      { "EUI64 Address", "dns.eui64",
        FT_EUI64, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_rrsig_type_covered,
      { "Type Covered", "dns.rrsig.type_covered",
        FT_UINT16, BASE_DEC|BASE_EXT_STRING, &dns_types_description_vals_ext, 0x0,
        "Identifies the type of the RRset that is covered by this RRSIG record", HFILL }},

    { &hf_dns_rrsig_algorithm,
      { "Algorithm", "dns.rrsig.algorithm",
        FT_UINT8, BASE_DEC, VALS(dnssec_algo_vals), 0x0,
        "Identifies the cryptographic algorithm used to create the signature", HFILL }},

    { &hf_dns_rrsig_labels,
      { "Labels", "dns.rrsig.labels",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Specifies the number of labels in the original RRSIG RR owner name", HFILL }},

    { &hf_dns_rrsig_original_ttl,
      { "Original TTL", "dns.rrsig.original_ttl",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Specifies the TTL of the covered RRset as it appears in the authoritative zone", HFILL }},

    { &hf_dns_rrsig_signature_expiration,
      { "Signature Expiration", "dns.rrsig.signature_expiration",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        "Specify a validity period for the signature", HFILL }},

    { &hf_dns_rrsig_signature_inception,
      { "Signature Inception", "dns.rrsig.signature_inception",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        "Specify a validity period for the signature", HFILL }},

    { &hf_dns_rrsig_key_tag,
      { "Key Tag", "dns.rrsig.key_tag",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Contains the key tag value of the DNSKEY RR that validates this signature", HFILL }},

    { &hf_dns_rrsig_signers_name,
      { "Signer's name", "dns.rrsig.signers_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Identifies the owner name of the DNSKEY RR that a validator is supposed to use to validate this signature", HFILL }},

    { &hf_dns_rrsig_signature,
      { "Signature", "dns.rrsig.signature",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Contains the cryptographic signature that covers the RRSIG RDATA", HFILL }},

    { &hf_dns_dnskey_flags,
      { "Flags", "dns.dnskey.flags",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_dnskey_flags_zone_key,
      { "Zone Key", "dns.dnskey.flags.zone_key",
        FT_BOOLEAN, 16, TFS(&dns_dnskey_zone_key_tfs), DNSKEY_FLAGS_ZK,
        NULL, HFILL }},

    { &hf_dns_dnskey_flags_key_revoked,
      { "Key Revoked", "dns.dnskey.flags.key_revoked",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), DNSKEY_FLAGS_KR,
        NULL, HFILL }},

    { &hf_dns_dnskey_flags_secure_entry_point,
      { "Key Signing Key", "dns.dnskey.flags.secure_entry_point",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), DNSKEY_FLAGS_SEP,
        NULL, HFILL }},

    { &hf_dns_dnskey_flags_reserved,
      { "Key Signing Key", "dns.dnskey.flags.reserved",
        FT_UINT16, BASE_HEX, NULL, DNSKEY_FLAGS_RSV,
        "Must be zero", HFILL }},

    { &hf_dns_dnskey_protocol,
      { "Protocol", "dns.dnskey.protocol",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Must be 3", HFILL }},

    { &hf_dns_dnskey_algorithm,
      { "Algorithm", "dns.dnskey.algorithm",
        FT_UINT8, BASE_DEC, VALS(dnssec_algo_vals), 0x0,
        "Identifies the public key's cryptographic algorithm and determines the format of the Public Key field", HFILL }},

    { &hf_dns_dnskey_key_id,
      { "Key id", "dns.dnskey.key_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_dnskey_public_key,
      { "Public Key", "dns.dnskey.public_key",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_key_flags,
      { "Flags", "dns.key.flags",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_key_flags_authentication,
      { "Key allowed for authentication", "dns.key.flags.authentication",
        FT_BOOLEAN, 16, TFS(&tfs_not_allowed_allowed), 0x8000,
        NULL, HFILL }},

    { &hf_dns_key_flags_confidentiality,
      { "Key allowed for confidentiality", "dns.key.flags.confidentiality",
        FT_BOOLEAN, 16, TFS(&tfs_not_allowed_allowed), 0x4000,
        NULL, HFILL }},

    { &hf_dns_key_flags_key_required,
      { "Key required", "dns.key.flags.required",
        FT_BOOLEAN, 16, TFS(&tfs_required_experimental), 0x2000,
        NULL, HFILL }},

    { &hf_dns_key_flags_associated_user,
      { "Key is associated with a user", "dns.key.flags.associated_user",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0400,
        NULL, HFILL }},

    { &hf_dns_key_flags_associated_named_entity,
      { "Key is associated with the named entity", "dns.key.flags.associated_named_entity",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0200,
        NULL, HFILL }},

    { &hf_dns_key_flags_ipsec,
      { "Key use with IPSEC", "dns.key.flags.ipsec",
        FT_BOOLEAN, 16, TFS(&tfs_valid_invalid), 0x0080,
        NULL, HFILL }},

    { &hf_dns_key_flags_mime,
      { "Key use with MIME security multiparts", "dns.key.flags.mime",
        FT_BOOLEAN, 16, TFS(&tfs_valid_invalid), 0x0040,
        NULL, HFILL }},

    { &hf_dns_key_flags_signatory,
      { "Signatory", "dns.key.flags.signatory",
        FT_UINT16, BASE_DEC, NULL, 0x000F,
        NULL, HFILL }},

    { &hf_dns_key_protocol,
      { "Protocol", "dns.key.protocol",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_key_algorithm,
      { "Algorithm", "dns.key.algorithm",
        FT_UINT8, BASE_DEC, VALS(dnssec_algo_vals), 0x0,
        NULL, HFILL }},

    { &hf_dns_key_key_id,
      { "Key ID", "dns.key.key_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_key_public_key,
      { "Public Key", "dns.key.public_key",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_px_preference,
      { "Preference", "dns.px.preference",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_px_map822,
      { "MAP822", "dns.px.map822",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_px_mapx400,
      { "MAPX400", "dns.px.map400",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_tkey_algo_name,
      { "Algorithm name", "dns.tkey.algo_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_tkey_signature_expiration,
      { "Signature Expiration", "dns.tkey.signature_expiration",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        "Specify a validity period for the signature", HFILL }},

    { &hf_dns_tkey_signature_inception,
      { "Signature Inception", "dns.tkey.signature_inception",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        "Specify a validity period for the signature", HFILL }},

    { &hf_dns_tkey_mode,
      { "Mode", "dns.tkey.mode",
        FT_UINT16, BASE_DEC, VALS(tkey_mode_vals), 0x0,
        NULL, HFILL }},

    { &hf_dns_tkey_error,
      { "Error", "dns.tkey.error",
        FT_UINT16, BASE_DEC, VALS(rcode_vals), 0x0,
        NULL, HFILL }},

    { &hf_dns_tkey_key_size,
      { "Key Size", "dns.tkey.key_size",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_tkey_key_data,
      { "Key Data", "dns.tkey.key_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_tkey_other_size,
      { "Other Size", "dns.tkey.other_size",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_tkey_other_data,
      { "Other Data", "dns.tkey.other_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_ipseckey_gateway_precedence,
      { "Gateway Precedence", "dns.ipseckey.gateway_precedence",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_ipseckey_gateway_algorithm,
      { "Gateway Algorithm", "dns.ipseckey.gateway_algorithm",
        FT_UINT8, BASE_DEC, VALS(gw_algo_vals), 0x0,
        NULL, HFILL }},

    { &hf_dns_ipseckey_gateway_type,
      { "Gateway Type", "dns.ipseckey.gateway_type",
        FT_UINT8, BASE_DEC, VALS(gw_type_vals), 0x0,
        NULL, HFILL }},

    { &hf_dns_ipseckey_gateway_ipv4,
      { "IPv4 Gateway", "dns.ipseckey.gateway_ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_ipseckey_gateway_ipv6,
      { "IPv6 Gateway", "dns.ipseckey.gateway_ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_ipseckey_gateway_dns,
      { "DNS Gateway", "dns.ipseckey.gateway_dns",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_ipseckey_public_key,
      { "Public Key", "dns.ipseckey.public_key",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_xpf_ip_version,
      { "IP Version", "dns.xpf.ip_version",
        FT_UINT16, BASE_DEC,
        VALS(ip_version_vals), 0x0,
        NULL, HFILL }},

    { &hf_dns_xpf_protocol,
      { "Protocol", "dns.xpf.protocol",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING,
        &ipproto_val_ext, 0x0,
        NULL, HFILL }},

    { &hf_dns_xpf_source_ipv4,
      { "IPv4 Source", "dns.xpf.source_ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_xpf_destination_ipv4,
      { "IPv4 Destination", "dns.xpf.destination_ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_xpf_source_ipv6,
      { "IPv6 Source", "dns.xpf.source_ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_xpf_destination_ipv6,
      { "IPv6 Destination", "dns.xpf.destination_ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_xpf_sport,
      { "Source port", "dns.xpf.sport",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_xpf_dport,
      { "Destination port", "dns.xpf.dport",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_a6_prefix_len,
      { "Prefix len", "dns.a6.prefix_len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_a6_address_suffix,
      { "Address Suffix", "dns.a6.address_suffix",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_a6_prefix_name,
      { "Prefix name", "dns.a6.prefix_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_dname,
      { "Dname", "dns.dname",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_loc_version,
      { "Version", "dns.loc.version",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_loc_size,
      { "Size", "dns.loc.size",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_loc_horizontal_precision,
      { "Horizontal Precision", "dns.loc.horizontal_precision",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_loc_vertical_precision,
      { "Vertical Precision", "dns.loc.vertical_precision",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_loc_latitude,
      { "Latitude", "dns.loc.latitude",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_loc_longitude,
      { "Longitude", "dns.loc.longitude",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_loc_altitude,
      { "Altitude", "dns.loc.altitude",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_loc_unknown_data,
      { "Unknown data", "dns.loc.unknown_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_nxt_next_domain_name,
      { "Next Domain Name", "dns.nxt.next_domain_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_kx_preference,
      { "Preference", "dns.kx.preference",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_kx_key_exchange,
      { "Key Exchange", "dns.kx.key_exchange",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_cert_type,
      { "Type", "dns.cert.type",
        FT_UINT16, BASE_DEC, VALS(dns_cert_type_vals), 0x0,
        NULL, HFILL }},

    { &hf_dns_cert_key_tag,
      { "Key Tag", "dns.cert.key_tag",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_cert_algorithm,
      { "Algorithm", "dns.cert.algorithm",
        FT_UINT8, BASE_DEC, VALS(dnssec_algo_vals), 0x0,
        NULL, HFILL }},

    { &hf_dns_cert_certificate,
      { "Certificate (or CRL)", "dns.cert.certificate",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_nsec_next_domain_name,
      { "Next Domain Name", "dns.nsec.next_domain_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_ns,
      { "Name Server", "dns.ns",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_opt,
     { "Option", "dns.opt",
        FT_NONE, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_opt_code,
      { "Option Code", "dns.opt.code",
        FT_UINT16, BASE_DEC,
        VALS(edns0_opt_code_vals), 0x0,
        NULL, HFILL }},

    { &hf_dns_opt_len,
      { "Option Length", "dns.opt.len",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_opt_data,
      { "Option Data", "dns.opt.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_opt_dau,
      { "DAU", "dns.opt.dau",
        FT_UINT8, BASE_DEC, VALS(dnssec_algo_vals), 0x0,
        "DNSSEC Algorithm Understood", HFILL }},

    { &hf_dns_opt_dhu,
      { "DHU", "dns.opt.dhu",
        FT_UINT8, BASE_DEC, VALS(dns_ds_digest_vals), 0x0,
        "DS Hash Understood", HFILL }},

    { &hf_dns_opt_n3u,
      { "N3U", "dns.opt.n3u",
        FT_UINT8, BASE_DEC, VALS(hash_algorithms), 0x0,
        "NSEC3 Hash Understood", HFILL }},

    { &hf_dns_opt_client_family,
      { "Family", "dns.opt.client.family",
        FT_UINT16, BASE_DEC,
        VALS(afamily_vals), 0x0,
        NULL, HFILL }},

    { &hf_dns_opt_client_netmask,
      { "Source Netmask", "dns.opt.client.netmask",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_opt_client_scope,
      { "Scope Netmask", "dns.opt.client.scope",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_opt_client_addr,
      { "Client Subnet", "dns.opt.client.addr",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_opt_client_addr4,
      { "Client Subnet", "dns.opt.client.addr4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_opt_client_addr6,
      { "Client Subnet", "dns.opt.client.addr6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_opt_cookie_client,
      { "Client Cookie", "dns.opt.cookie.client",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_opt_cookie_server,
      { "Server Cookie", "dns.opt.cookie.server",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_opt_edns_tcp_keepalive_timeout,
      { "Timeout", "dns.opt.edns_tcp_keepalive.timeout",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "an idle timeout value for the TCP connection, specified in units of 100 milliseconds", HFILL }},

    { &hf_dns_opt_padding,
      { "Padding", "dns.opt.padding",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "The PADDING octets SHOULD be set to 0x00", HFILL }},

    { &hf_dns_opt_chain_fqdn,
      { "Closest Trust Point", "dns.opt.chain.fqdn",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "A variable length Fully Qualified Domain Name (FQDN) in DNS wire format of the requested start point of the chain", HFILL }},

    { &hf_dns_opt_ext_error_info_code,
      { "Info Code", "dns.opt.ext_error.info_code",
        FT_UINT16, BASE_DEC | BASE_RANGE_STRING, RVALS(dns_ext_err_info_code), 0x0,
        NULL, HFILL }},

    { &hf_dns_opt_ext_error_extra_text,
      { "Extra Text", "dns.opt.ext_error.extra_text",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_count_questions,
      { "Questions", "dns.count.queries",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Number of queries in packet", HFILL }},

    { &hf_dns_count_zones,
      { "Zones", "dns.count.zones",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Number of zones in packet", HFILL }},

    { &hf_dns_count_answers,
      { "Answer RRs", "dns.count.answers",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Number of answers in packet", HFILL }},

    { &hf_dns_count_prerequisites,
      { "Prerequisites", "dns.count.prerequisites",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Number of prerequisites in packet", HFILL }},

    { &hf_dns_count_auth_rr,
      { "Authority RRs", "dns.count.auth_rr",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Number of authoritative records in packet", HFILL }},

    { &hf_dns_count_updates,
      { "Updates", "dns.count.updates",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Number of updates records in packet", HFILL }},

    { &hf_dns_nsec3_algo,
      { "Hash algorithm", "dns.nsec3.algo",
        FT_UINT8, BASE_DEC, VALS(hash_algorithms), 0,
        NULL, HFILL }},

    { &hf_dns_nsec3_flags,
      { "NSEC3 flags", "dns.nsec3.flags",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_nsec3_flag_optout,
      { "NSEC3 Opt-out flag", "dns.nsec3.flags.opt_out",
        FT_BOOLEAN, 8, TFS(&tfs_flags_nsec3_optout), NSEC3_FLAG_OPTOUT,
        NULL, HFILL }},

    { &hf_dns_nsec3_iterations,
      { "NSEC3 iterations", "dns.nsec3.iterations",
        FT_UINT16, BASE_DEC, NULL, 0,
        "Number of hashing iterations", HFILL }},

    { &hf_dns_nsec3_salt_length,
      { "Salt length", "dns.nsec3.salt_length",
        FT_UINT8, BASE_DEC, NULL, 0,
        "Length of salt in bytes", HFILL }},

    { &hf_dns_nsec3_salt_value,
      { "Salt value", "dns.nsec3.salt_value",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_nsec3_hash_length,
      { "Hash length", "dns.nsec3.hash_length",
        FT_UINT8, BASE_DEC, NULL, 0,
        "Length in bytes of next hashed owner", HFILL }},

    { &hf_dns_nsec3_hash_value,
      { "Next hashed owner", "dns.nsec3.hash_value",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_tlsa_certificate_usage,
      { "Certificate Usage", "dns.tlsa.certificate_usage",
        FT_UINT8, BASE_DEC, VALS(tlsa_certificate_usage_vals), 0,
        "Specifies the provided association that will be used to match the certificate presented in the TLS handshake", HFILL }},

    { &hf_dns_tlsa_selector,
      { "Selector", "dns.tlsa.selector",
        FT_UINT8, BASE_DEC, VALS(tlsa_selector_vals), 0,
        "Specifies which part of the TLS certificate presented by the server will be matched against the association data", HFILL }},

    { &hf_dns_tlsa_matching_type,
      { "Matching Type", "dns.tlsa.matching_type",
        FT_UINT8, BASE_DEC, VALS(tlsa_matching_type_vals), 0,
        "Specifies how the certificate association is presented", HFILL }},

    { &hf_dns_tlsa_certificate_association_data,
      { "Certificate Association Data", "dns.tlsa.certificate_association_data",
        FT_BYTES, BASE_NONE, NULL, 0,
        "The data refers to the certificate in the association", HFILL }},

    { &hf_dns_tsig_algorithm_name,
      { "Algorithm Name", "dns.tsig.algorithm_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Name of algorithm used for the MAC", HFILL }},

    { &hf_dns_tsig_time_signed,
      { "Time Signed", "dns.tsig.time_signed",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        NULL, HFILL }},


    { &hf_dns_tsig_original_id,
      { "Original Id", "dns.tsig.original_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_tsig_error,
      { "Error", "dns.tsig.error",
        FT_UINT16, BASE_DEC, VALS(rcode_vals), 0x0,
        "Expanded RCODE for TSIG", HFILL }},

    { &hf_dns_tsig_fudge,
      { "Fudge", "dns.tsig.fudge",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Number of bytes for the MAC", HFILL }},

    { &hf_dns_tsig_mac_size,
      { "MAC Size", "dns.tsig.mac_size",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Number of bytes for the MAC", HFILL }},

    { &hf_dns_tsig_other_len,
      { "Other Len", "dns.tsig.other_len",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Number of bytes for Other Data", HFILL }},

    { &hf_dns_tsig_mac,
      { "MAC", "dns.tsig.mac",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_tsig_other_data,
      { "Other Data", "dns.tsig.other_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_response_in,
      { "Response In", "dns.response_in",
        FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
        "The response to this DNS query is in this frame", HFILL }},

    { &hf_dns_response_to,
      { "Request In", "dns.response_to",
        FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
        "This is a response to the DNS query in this frame", HFILL }},

    { &hf_dns_retransmission,
      { "Retransmission", "dns.retransmission",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "This is a retransmission", HFILL }},

    { &hf_dns_retransmit_request_in,
      { "Retransmitted request. Original request in", "dns.retransmit_request_in",
        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "This is a retransmitted DNS query", HFILL }},

    { &hf_dns_retransmit_response_in,
      { "Retransmitted response. Original response in", "dns.retransmit_response_in",
        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "This is a retransmitted DNS response", HFILL }},

    { &hf_dns_time,
      { "Time", "dns.time",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "The time between the Query and the Response", HFILL }},

    { &hf_dns_unsolicited,
      { "Unsolicited", "dns.unsolicited",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        "This is an unsolicited response", HFILL }},

    { &hf_dns_count_add_rr,
      { "Additional RRs", "dns.count.add_rr",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Number of additional records in packet", HFILL }},

    { &hf_dns_sshfp_algorithm,
      { "Algorithm", "dns.sshfp.algorithm",
        FT_UINT8, BASE_DEC, VALS(sshfp_algo_vals), 0,
        NULL, HFILL }},

    { &hf_dns_sshfp_fingerprint_type,
      { "Fingerprint type", "dns.sshfp.fingerprint.type",
        FT_UINT8, BASE_DEC, VALS(sshfp_fingertype_vals), 0,
        NULL, HFILL }},

    { &hf_dns_sshfp_fingerprint,
      { "Fingerprint", "dns.sshfp.fingerprint",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_hip_hit_length,
      { "HIT length", "dns.hip.hit.length",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_hip_pk_algo,
      { "HIT length", "dns.hip.hit.pk.algo",
        FT_UINT8, BASE_DEC, VALS(hip_algo_vals), 0,
        NULL, HFILL }},

    { &hf_dns_hip_pk_length,
      { "PK length", "dns.hip.pk.length",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_hip_hit,
      { "Host Identity Tag", "dns.hip.hit",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_hip_pk,
      { "HIP Public Key", "dns.hip.pk",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_hip_rendezvous_server,
      { "Rendezvous Server", "dns.hip.rendezvous_server",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_dhcid_rdata,
      { "DHCID Data", "dns.dhcid.rdata",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_ds_key_id,
      { "Key id", "dns.ds.key_id",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_ds_algorithm,
      { "Algorithm", "dns.ds.algorithm",
        FT_UINT8, BASE_DEC, VALS(dnssec_algo_vals), 0,
        NULL, HFILL }},

    { &hf_dns_ds_digest_type,
      { "Digest Type", "dns.ds.digest_type",
        FT_UINT8, BASE_DEC, VALS(dns_ds_digest_vals), 0,
        NULL, HFILL }},

    { &hf_dns_ds_digest,
      { "Digest", "dns.ds.digest",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_apl_address_family,
      { "Address Family", "dns.apl.address_family",
        FT_UINT16, BASE_DEC, VALS(afamily_vals), 0,
        NULL, HFILL }},

    { &hf_dns_apl_coded_prefix,
      { "Prefix Length", "dns.apl.coded_prefix",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_apl_negation,
      { "Negation Flag", "dns.apl.negation",
        FT_BOOLEAN, 8, TFS(&tfs_dns_apl_negation), DNS_APL_NEGATION,
        NULL, HFILL }},

    { &hf_dns_apl_afdlength,
      { "Address Length","dns.apl.afdlength",
        FT_UINT8, BASE_DEC, NULL, DNS_APL_AFDLENGTH,
        "in octets", HFILL }},

    { &hf_dns_apl_afdpart_ipv4,
      { "Address","dns.apl.afdpart.ipv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_apl_afdpart_ipv6,
      { "Address","dns.apl.afdpart.ipv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_apl_afdpart_data,
      { "Address","dns.apl.afdpart.data",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_gpos_longitude_length,
      { "Longitude length","dns.gpos.longitude_length",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_gpos_longitude,
      { "Longitude","dns.gpos.longitude",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_gpos_latitude_length,
      { "Latitude length","dns.gpos.latitude_length",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_gpos_latitude,
      { "Latitude","dns.gpos.latitude",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_gpos_altitude_length,
      { "Altitude length","dns.gpos.altitude_length",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_gpos_altitude,
      { "Altitude","dns.gpos.altitude",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_rp_mailbox,
      { "Mailbox","dns.rp.mailbox",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_rp_txt_rr,
      { "TXT RR","dns.rp.txt_rr",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_afsdb_subtype,
      { "Subtype","dns.afsdb.subtype",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_afsdb_hostname,
      { "Hostname","dns.afsdb.hostname",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_x25_length,
      { "Length","dns.x25.length",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_x25_psdn_address,
      { "PSDN-Address","dns.x25.psdn_address",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_isdn_length,
      { "Length","dns.idsn.length",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_isdn_address,
      { "ISDN Address","dns.idsn.address",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_isdn_sa_length,
      { "Length","dns.idsn.sa.length",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_isdn_sa,
      { "Sub Address","dns.idsn.sa.address",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_rt_preference,
      { "Preference","dns.rt.subtype",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_rt_intermediate_host,
      { "Intermediate Hostname","dns.rt.intermediate_host",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_nsap_rdata,
      { "NSAP Data", "dns.nsap.rdata",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_nsap_ptr_owner,
      { "Owner", "dns.nsap_ptr.owner",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_caa_flags,
      { "CAA Flags", "dns.caa.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_caa_flag_issuer_critical,
      { "Issuer Critical", "dns.caa.flags.issuer_critical",
        FT_BOOLEAN, 8, TFS(&tfs_critical_not_critical), CAA_FLAG_ISSUER_CRITICAL,
        "Other CAs must not issue certificates", HFILL }},

    { &hf_dns_caa_issue,
      { "Issue", "dns.caa.issue",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "CA which is allowed to issue certificates", HFILL }},

    { &hf_dns_caa_issuewild,
      { "Issue Wildcard", "dns.caa.issuewild",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "CA which is allowed to issue wildcard certificates", HFILL }},

    { &hf_dns_caa_iodef,
      { "Report URL", "dns.caa.iodef",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "URL or email address for certificate issue requests and violation reports", HFILL }},

    { &hf_dns_caa_unknown,
      { "Unknown tag", "dns.caa.unknown",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_caa_tag_length,
      { "Tag length", "dns.caa.tag_length",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_dns_caa_tag,
      { "Tag", "dns.caa.tag",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_caa_value,
      { "Value", "dns.caa.value",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_extraneous_data,
      { "Extraneous Data Bytes", "dns.extraneous.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_extraneous_length,
      { "Extraneous Data Length", "dns.extraneous.length",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_wins_local_flag,
      { "Local Flag", "dns.wins.local_flag",
        FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x1,
        NULL, HFILL }},

    { &hf_dns_wins_lookup_timeout,
      { "Lookup timeout", "dns.wins.lookup_timeout",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "In seconds", HFILL }},

    { &hf_dns_wins_cache_timeout,
      { "Cache timeout", "dns.wins.cache_timeout",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "In seconds", HFILL }},

    { &hf_dns_wins_nb_wins_servers,
      { "Number of WINS servers", "dns.wins.nb_wins_servers",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_wins_server,
      { "WINS Server Address", "dns.wins.wins_server",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_winsr_local_flag,
      { "Local Flag", "dns.winsr.local_flag",
        FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x1,
        NULL, HFILL }},

    { &hf_dns_winsr_lookup_timeout,
      { "Lookup timeout", "dns.winsr.lookup_timeout",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "In seconds", HFILL }},

    { &hf_dns_winsr_cache_timeout,
      { "Cache timeout", "dns.winsr.cache_timeout",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "In seconds", HFILL }},

    { &hf_dns_winsr_name_result_domain,
      { "Name Result Domain", "dns.winsr.name_result_domain",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_data,
      { "Data", "dns.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_dns_dso,
      { "DNS Stateful Operation", "dns.dso",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dns_dso_tlv,
      { "DSO TLV", "dns.dso.tlv",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dns_dso_tlv_type,
      { "Type", "dns.dso.tlv.type",
        FT_UINT16, BASE_DEC | BASE_RANGE_STRING, RVALS(dns_dso_type_rvals), 0x0,
        NULL, HFILL }},
    { &hf_dns_dso_tlv_length,
      { "Length", "dns.dso.tlv.length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dns_dso_tlv_data,
      { "Data", "dns.dso.tlv.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dns_dso_tlv_keepalive_inactivity,
      { "Inactivity Timeout", "dns.dso.tlv.keepalive.inactivity",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Inactivity Timeout (ms)", HFILL }},
    { &hf_dns_dso_tlv_keepalive_interval,
      { "Keepalive Interval", "dns.dso.tlv.keepalive.interval",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Keepalive Interval (ms)", HFILL }},
    { &hf_dns_dso_tlv_retrydelay_retrydelay,
      { "Retry Delay", "dns.dso.tlv.retrydelay.retrydelay",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Retry Delay (ms)", HFILL }},
    { &hf_dns_dso_tlv_encpad_padding,
      { "Padding", "dns.dso.tlv.encpad.padding",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
  };

  static ei_register_info ei[] = {
    { &ei_dns_opt_bad_length, { "dns.rr.opt.bad_length", PI_MALFORMED, PI_ERROR, "Length too long for any type of IP address.", EXPFILL }},
    { &ei_dns_undecoded_option, { "dns.undecoded.type", PI_UNDECODED, PI_NOTE, "Undecoded option", EXPFILL }},
    { &ei_dns_depr_opc, { "dns.depr.opc", PI_PROTOCOL, PI_WARN, "Deprecated opcode", EXPFILL }},
    { &ei_ttl_high_bit_set, { "dns.ttl.high_bit_set", PI_PROTOCOL, PI_WARN, "The uppermost bit of the TTL is set (RFC 2181, section 8)", EXPFILL }},
    { &ei_dns_tsig_alg, { "dns.tsig.noalg", PI_UNDECODED, PI_WARN, "No dissector for algorithm", EXPFILL }},
    { &ei_dns_key_id_buffer_too_short, { "dns.key_id_buffer_too_short", PI_PROTOCOL, PI_WARN, "Buffer too short to compute a key id", EXPFILL }},
    { &ei_dns_retransmit_request, { "dns.retransmit_request", PI_PROTOCOL, PI_WARN, "DNS query retransmission", EXPFILL }},
    { &ei_dns_retransmit_response, { "dns.retransmit_response", PI_PROTOCOL, PI_WARN, "DNS response retransmission", EXPFILL }},
    { &ei_dns_extraneous_data, { "dns.extraneous", PI_UNDECODED, PI_NOTE, "Extraneous data", EXPFILL }},
  };

  static gint *ett[] = {
    &ett_dns,
    &ett_dns_qd,
    &ett_dns_rr,
    &ett_dns_qry,
    &ett_dns_ans,
    &ett_dns_flags,
    &ett_dns_opts,
    &ett_nsec3_flags,
    &ett_key_flags,
    &ett_t_key,
    &ett_dns_mac,
    &ett_caa_flags,
    &ett_caa_data,
    &ett_dns_csdync_flags,
    &ett_dns_dso,
    &ett_dns_dso_tlv,
    &ett_dns_svcb,
    &ett_dns_extraneous,
  };

  module_t *dns_module;
  expert_module_t* expert_dns;

  proto_dns = proto_register_protocol("Domain Name System", "DNS", "dns");
  proto_mdns = proto_register_protocol("Multicast Domain Name System", "mDNS", "mdns");
  proto_llmnr = proto_register_protocol("Link-local Multicast Name Resolution", "LLMNR", "llmnr");
  proto_register_field_array(proto_dns, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_dns = expert_register_protocol(proto_dns);
  expert_register_field_array(expert_dns, ei, array_length(ei));

  dns_module = prefs_register_protocol(proto_dns, NULL);

  prefs_register_bool_preference(dns_module, "desegment_dns_messages",
    "Reassemble DNS messages spanning multiple TCP segments",
    "Whether the DNS dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &dns_desegment);

  prefs_register_uint_preference(dns_module, "retransmission_timer",
                                  "Number of seconds allowed between retransmissions",
                                  "Number of seconds allowed between DNS requests with the same transaction ID to consider it a retransmission."
                                  " Otherwise its considered a new request.",
                                  10, &retransmission_timer);

  prefs_register_obsolete_preference(dns_module, "use_for_addr_resolution");

  prefs_register_static_text_preference(dns_module, "text_use_for_addr_resolution",
                                        "DNS address resolution settings can be changed in the Name Resolution preferences",
                                        "DNS address resolution settings can be changed in the Name Resolution preferences");

  dns_tsig_dissector_table = register_dissector_table("dns.tsig.mac", "DNS TSIG MAC", proto_dns, FT_STRING, BASE_NONE);

  dns_handle = register_dissector("dns", dissect_dns, proto_dns);

  dns_tap = register_tap("dns");
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
