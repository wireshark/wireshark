/* packet-uma.c
 * Routines for Unlicensed Mobile Access(UMA) dissection
 * Copyright 2005-2006,2009, Anders Broman <anders.broman[at]ericsson.com>
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
 *
 * References:
 * http://www.umatechnology.org/
 * UMA Protocols (Stage 3) R1.0.4 (5/16/2005)
 *
 * 3GPP TS 44.318 version 8.4.0 Release 8
 *
 * http://www.3gpp.org/specs/numbering.htm
 * 3GPP TS 24.008 V6.2.0 (2003-09)
 * Technical Specification
 * 3rd Generation Partnership Project;
 * Technical Specification Group Core Network;
 * Mobile radio interface Layer 3 specification;
 * Core network protocols; Stage 3
 * (Release 6)
 *
 * 3GPP TS 44.018 V6.11.0 (2005-01)
 * 3rd Generation Partnership Project;
 * Technical Specification Group GSM/EDGE Radio Access Network;
 * Mobile radio interface layer 3 specification;
 * Radio Resource Control (RRC) protocol
 * (Release 6)
 *
 * 3GPP TS 45.009 V6.1.0 (2004-02)
 * 3rd Generation Partnership Project;
 * Technical Specification Group GSM/EDGE
 * Radio Access Network;
 * Link adaptation
 * (Release 6)
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

#include <glib.h>
#include <epan/conversation.h>

#include <epan/packet.h>
#include <epan/asn1.h>

#include <epan/prefs.h>
#include "packet-bssap.h"
#include "packet-gsm_a_common.h"
#include "packet-gsm_map.h"
#include "packet-rtp.h"
#include "packet-rtcp.h"
#include "packet-e212.h"
#include "packet-tcp.h"
#include "packet-rrc.h"

/* Length field is 2 bytes and comes first */
#define UMA_HEADER_SIZE 2
static gboolean uma_desegment = TRUE;

static dissector_handle_t uma_tcp_handle;
static dissector_handle_t uma_udp_handle;
static dissector_handle_t data_handle;
static dissector_table_t  bssap_pdu_type_table;
static dissector_handle_t rtp_handle;
static dissector_handle_t rtcp_handle;
static dissector_handle_t llc_handle;

/* Initialize the protocol and registered fields */
static int proto_uma					= -1;
static int hf_uma_length_indicator			= -1;
static int hf_uma_pd					= -1;
static int hf_uma_skip_ind				= -1;
static int hf_uma_urr_msg_type				= -1;
static int hf_uma_urlc_msg_type				= -1;
static int hf_uma_urlc_TLLI				= -1;
static int hf_uma_urlc_seq_nr				= -1;
static int hf_uma_urr_IE				= -1;
static int hf_uma_urr_IE_len				= -1;
static int hf_uma_urr_mobile_identity_type		= -1;
static int hf_uma_urr_odde_even_ind			= -1;
static int hf_uma_urr_imsi				= -1;
static int hf_uma_urr_imei				= -1;
static int hf_uma_urr_imeisv				= -1;
static int hf_uma_urr_tmsi_p_tmsi			= -1;
static int hf_uma_urr_uri				= -1;
static int hf_uma_urr_radio_type_of_id	= -1;
static int hf_uma_urr_radio_id				= -1;
static int hf_uma_urr_cell_id				= -1;
static int hf_uma_urr_mcc				= -1;
static int hf_uma_urr_mnc				= -1;
static int hf_uma_urr_lac				= -1;
static int hf_uma_urr_gci				= -1;
static int hf_uma_urr_tura				= -1;
static int hf_uma_urr_gc				= -1;
static int hf_uma_urr_uc				= -1;
static int hf_uma_urr_rrs				= -1;
static int hf_uma_urr_gmsi				= -1;
static int hf_uma_urr_psho				= -1;
static int hf_uma_urr_IP_Address_type			= -1;
static int hf_uma_urr_FQDN				= -1;
static int hf_uma_urr_sgw_ipv4				= -1;
static int hf_uma_urr_redirection_counter =		 -1;
static int hf_uma_urr_dis_rej_cau			= -1;
static int hf_uma_urr_MSCR				= -1;
static int hf_uma_urr_ATT				= -1;
static int hf_uma_urr_DTM				= -1;
static int hf_uma_urr_GPRS				= -1;
static int hf_uma_urr_NMO				= -1;
static int hf_uma_urr_ECMC				= -1;
static int hf_uma_urr_T3212_timer			= -1;
static int hf_uma_urr_RAC				= -1;
static int hf_uma_urr_ap_location			= -1;
static int hf_uma_urr_SGSNR				= -1;
static int hf_uma_urr_ECMP				= -1;
static int hf_uma_urr_RE				= -1;
static int hf_uma_urr_PFCFM				= -1;
static int hf_uma_urr_3GECS				= -1;
static int hf_uma_urr_bcc				= -1;
static int hf_uma_urr_ncc				= -1;
static int hf_uma_urr_TU3907_timer			= -1;
static int hf_uma_urr_GSM_RR_state			= -1;
static int hf_uma_urr_gan_band				= -1;
static int hf_uma_urr_URR_state				= -1;
static int hf_uma_urr_register_reject_cause 		= -1;
static int hf_uma_urr_TU3906_timer			= -1;
static int hf_uma_urr_TU3910_timer			= -1;
static int hf_uma_urr_TU3902_timer			= -1;
static int hf_uma_urr_communication_port 		= -1;
static int hf_uma_urr_L3_Message			= -1;
static int hf_uma_urr_L3_protocol_discriminator 	= -1;
static int hf_uma_urr_sc				= -1;
static int hf_uma_urr_algorithm_id			= -1;
static int hf_uma_urr_GPRS_resumption			= -1;
static int hf_uma_urr_ULQI				= -1;
static int hf_uma_urr_TU3920_timer			= -1;
static int hf_uma_urr_peak_tpt_cls			= -1;
static int hf_uma_urr_radio_pri				= -1;
static int hf_uma_urr_rlc_mode				= -1;
static int hf_uma_urr_ga_psr_cause			= -1;
static int hf_uma_urr_udr				= -1;
static int hf_uma_urr_TU4001_timer			= -1;
static int hf_uma_urr_LS				= -1;
static int hf_uma_urr_cipher_res			= -1;
static int hf_uma_urr_rand_val				= -1;
static int hf_uma_urr_ciphering_command_mac 		= -1;
static int hf_uma_urr_ciphering_key_seq_num 		= -1;
static int hf_uma_urr_sapi_id				= -1;
static int hf_uma_urr_establishment_cause 		= -1;
static int hf_uma_urr_channel				= -1;
static int hf_uma_urr_PDU_in_error			= -1;
static int hf_uma_urr_sample_size			= -1;
static int hf_uma_urr_payload_type			= -1;
static int hf_uma_urr_LLC_PDU				= -1;
static int hf_uma_urr_LBLI				= -1;
static int hf_uma_urr_RI				= -1;
static int hf_uma_urr_TU4003_timer			= -1;
static int hf_uma_urr_ap_service_name_type 		= -1;
static int hf_uma_urr_ap_Service_name_value 		= -1;
static int hf_uma_urr_uma_service_zone_icon_ind 	= -1;
static int hf_uma_urr_uma_service_zone_str_len 		= -1;
static int hf_uma_urr_window_size			= -1;
static int hf_uma_urr_uma_codec_mode			= -1;
static int hf_uma_urr_UTRAN_cell_id_disc 		= -1;
static int hf_uma_urr_ms_radio_id			= -1;
static int hf_uma_urr_uma_service_zone_str 		= -1;
static int hf_uma_urr_suti				= -1;
static int hf_uma_urr_uma_mps				= -1;
static int hf_uma_urr_num_of_plms			= -1;
static int hf_uma_urr_cbs				= -1;
static int hf_uma_urr_num_of_cbs_frms			= -1;
static int hf_uma_urr_unc_ipv4				= -1;
static int hf_uma_unc_FQDN				= -1;
static int hf_uma_urr_GPRS_user_data_transport_ipv4 	= -1;
static int hf_uma_urr_GPRS_port				= -1;
static int hf_uma_urr_UNC_tcp_port			= -1;
static int hf_uma_urr_RTP_port				= -1;
static int hf_uma_urr_RTCP_port				= -1;
static int hf_uma_urr_RXLEV_NCELL			= -1;

/* Initialize the subtree pointers */
static int ett_uma     = -1;
static int ett_uma_toc = -1;
static int ett_urr_ie  = -1;

/* The dynamic payload type which will be dissected as uma */

static range_t *global_uma_tcp_port_range;

#define DEFAULT_UMA_PORT_RANGE "14001"

/* Global variables */
static	guint32		sgw_ipv4_address;
static	guint32		unc_ipv4_address;
/** static	guint32		rtp_ipv4_address; **/
static	guint32		rtcp_ipv4_address;
static	guint32		GPRS_user_data_ipv4_address;

/*
 * Protocol Discriminator (PD)
 */
static const value_string uma_pd_vals[] = {
	{ 0,		"URR_C"},
	{ 1,		"URR"},
	{ 2,		"URLC"},
	{ 0,	NULL }
};
/*
 * Message types for Unlicensed Radio Resources management
 */
static const value_string uma_urr_msg_type_vals[] = {
	{ 1,		"GA-RC DISCOVERY REQUEST"},
	{ 2,		"GA-RC DISCOVERY ACCEPT"},
	{ 3,		"GA-RC DISCOVERY REJECT"},
	{ 16,		"GA-RC REGISTER REQUEST"},
	{ 17,		"GA-RC REGISTER ACCEPT"},
	{ 18,		"GA-RC REGISTER REDIRECT"},
	{ 19,		"GA-RC REGISTER REJECT"},
	{ 20,		"GA-RC DEREGISTER"},
	{ 21,		"GA-RC REGISTER UPDATE UPLINK"},
	{ 22,		"GA-RC REGISTER UPDATE DOWNLINK"},
	{ 23,		"GA-RC CELL BROADCAST INFO"},
	{ 32,		"GA-CSR CIPHERING MODE COMMAND"},
	{ 33,		"GA-CSR CIPHERING MODE COMPLETE"},
	{ 48,		"GA-CSR ACTIVATE CHANNEL"},
	{ 49,		"GA-CSR ACTIVATE CHANNEL ACK"},
	{ 50,		"GA-CSR ACTIVATE CHANNEL COMPLETE"},
	{ 51,		"GA-CSR ACTIVATE CHANNEL FAILURE"},
	{ 52,		"GA-CSR CHANNEL MODE MODIFY"},
	{ 53,		"GA-CSR CHANNEL MODE MODIFY ACKNOWLEDGE"},
	{ 64,		"GA-CSR RELEASE"},
	{ 65,		"GA-CSR RELEASE COMPLETE"},
	{ 66,		"GA-CSR CLEAR REQUEST"},
	{ 80,		"GA-CSR HANDOVER ACCESS"},
	{ 81,		"GA-CSR HANDOVER COMPLETE"},
	{ 82,		"GA-CSR UPLINK QUALITY INDICATION"},
	{ 83,		"GA-CSR HANDOVER INFORMATION"},
	{ 84,		"GA-CSR HANDOVER COMMAND"},
	{ 85,		"GA-CSR HANDOVER FAILURE"},
	{ 96,		"GA-CSR PAGING REQUEST"},
	{ 97,		"GA-CSR PAGING RESPONSE"},
	{ 112,		"GA-CSR UPLINK DIRECT TRANSFER"},
	{ 113,		"URR INITIAL DIRECT TRANSFER"},
	{ 114,		"GA-CSR DOWNLINK DIRECT TRANSFER"},
	{ 115,		"GA-CSR STATUS"},
	{ 116,		"GA-RC KEEP ALIVE"},
	{ 117,		"GA-CSR CLASSMARK ENQUIRY"},
	{ 118,		"GA-CSR CLASSMARK CHANGE"},
	{ 119,		"GA-CSR GPRS SUSPENSION REQUEST"},
	{ 120,		"GA-RC SYNCHRONIZATION INFORMATION"},
	{ 121,		"GA-CSR UTRAN CLASSMARK CHANGE"},
	{ 128,		"GA-CSR REQUEST"},
	{ 129,		"GA-CSR REQUEST ACCEPT"},
	{ 130,		"GA-CSR REQUEST REJECT"},
	{ 0,	NULL }
};
static value_string_ext uma_urr_msg_type_vals_ext = VALUE_STRING_EXT_INIT(uma_urr_msg_type_vals);
/*
 * Message types for URLC signaling
 */
static const value_string uma_urlc_msg_type_vals[] = {
	{ 1,		"GA-PSR-DATA"},
	{ 2,		"URLC UNITDATA"},
	{ 3,		"GA-PSR-PS-PAGE"},
	{ 4,		"Unknown"},
	{ 5,		"Unknown"},
	{ 6,		"URLC-UFC-REQ"},
	{ 7,		"URLC-DFC-REQ"},
	{ 8,		"GA-PSR-ACTIVATE-UTC-REQ"},
	{ 9,		"GA-PSR-ACTIVATE-UTC-ACK"},
	{ 10,		"GA-PSR-DEACTIVATE-UTC-REQ"},
	{ 11,		"GA-PSR-DEACTIVATE-UTC-ACK"},
	{ 12,		"GA-PSR STATUS"},
	{ 13,		"GA-PSR HANDOVER COMPLETE"},
	{ 14,		"GA-PSR UPLINK QUALITY INDICATION"},
	{ 15,		"GA-PSR HANDOVER INFORMATION"},
	{ 16,		"GA-PSR HANDOVER COMMAND"},
	{ 17,		"GA-PSR HANDOVER CONTINUE"},
	{ 18,		"GA-PSR HANDOVER FAILURE"},
	{ 0,	NULL }
};
static value_string_ext uma_urlc_msg_type_vals_ext = VALUE_STRING_EXT_INIT(uma_urlc_msg_type_vals);

/*
 * IE type and identifiers for Unlicensed Radio Resources management
 */
static const value_string uma_urr_IE_type_vals[] = {
	{ 1,		"Mobile Identity"},
	{ 2,		"GAN Release Indicator"},
	{ 3,		"Radio Identity"},
	{ 4,		"GERAN Cell Identity"},
	{ 5,		"Location Area Identification"},
	{ 6,		"GERAN/UTRAN Coverage Indicator"},
	{ 7,		"GAN Classmark"},
	{ 8,		"Geographical Location"},
	{ 9,		"GANC-SEGW IP Address"},
	{ 10,		"GANC-SEGW Fully Qualified Domain/Host Name"},
	{ 11,		"Redirection Counter"},
	{ 12,		"Discovery Reject Cause"},
	{ 13,		"GAN Cell Description"},
	{ 14,		"GAN Control Channel Description"},
	{ 15,		"Cell Identifier List"},
	{ 16,		"TU3907 Timer"},
	{ 17,		"GSM RR/UTRAN RRC State"},
	{ 18,		"Routing Area Identification"},
	{ 19,		"GAN Band"},
	{ 20,		"GA-RC/GA-CSR/GA-PSR State"},
	{ 21,		"Register Reject Cause"},
	{ 22,		"TU3906 Timer"},
	{ 23,		"TU3910 Timer"},
	{ 24,		"TU3902 Timer"},
	{ 25,		"Communication Port Identity"},
	{ 26,		"L3 Message"},
	{ 27,		"Channel Mode"},
	{ 28,		"Mobile Station Classmark 2"},
	{ 29,		"RR Cause"},
	{ 30,		"Cipher Mode Setting"},
	{ 31,		"GPRS Resumption"},
	{ 32,		"Handover From GAN Command"},
	{ 33,		"UL Quality Indication"},
	{ 34,		"TLLI"},
	{ 35,		"Packet Flow Identifier"},
	{ 36,		"Suspension Cause"},
	{ 37,		"TU3920 Timer"},
	{ 38,		"QoS"},
	{ 39,		"GA-PSR Cause"},
	{ 40,		"User Data Rate"},
	{ 41,		"Routing Area Code"},
	{ 42,		"AP Location"},
	{ 43,		"TU4001 Timer"},
	{ 44,		"Location Status"},
	{ 45,		"Cipher Response"},
	{ 46,		"Ciphering Command RAND"},
	{ 47,		"Ciphering Command MAC"},
	{ 48,		"Ciphering Key Sequence Number"},
	{ 49,		"SAPI ID"},
	{ 50,		"Establishment Cause"},
	{ 51,		"Channel Needed"},
	{ 52,		"PDU in Error"},
	{ 53,		"Sample Size"},
	{ 54,		"Payload Type"},
	{ 55,		"Multi-rate Configuration"},
	{ 56,		"Mobile Station Classmark 3"},
	{ 57,		"LLC-PDU"},
	{ 58,		"Location Black List indicator"},
	{ 59,		"Reset Indicator"},
	{ 60,		"TU4003 Timer"},
	{ 61,		"AP Service Name"},
	{ 62,		"GAN Service Zone Information"},
	{ 63,		"RTP Redundancy Configuration"},
	{ 64,		"UTRAN Classmark"},
	{ 65,		"Classmark Enquiry Mask"},
	{ 66,		"UTRAN Cell Identifier List"},
	{ 67,		"Serving UNC table indicator"},
	{ 68,		"Registration indicators"},
	{ 69,		"GAN PLMN List"},
	{ 70,		"Received Signal Level List"},
	{ 71,		"Required GAN Services"},
	{ 72,		"Broadcast Container"},
	{ 73,		"3G Cell Identity"},
	{ 74,		"3G Security Capability"},			/* 11.2.108 */
	{ 75,		"NAS Synchronisation Indicator"},		/* 11.2.109 */
	{ 76,		"GANC TEID"},					/* 11.2.110 */
	{ 77,		"MS TEID"},					/* 11.2.110 */
	{ 78,		"UTRAN RRC Message"},				/* 11.2.111 */
	{ 79,		"GAN Mode Indicator"},				/* 11.2.79 */
	{ 80,		"CN Domain Identity"},				/* 11.2.80 */
	{ 81,		"GAN Iu Mode Cell Description"},		/* 11.2.81 */
	{ 82,		"3G UARFCN"},					/* 11.2.82 */
	{ 83,		"RAB ID"},					/* 11.2.83 */
	{ 84,		"RAB ID List"},					/* 11.2.84 */
	{ 85,		"GA-RRC Establishment Cause"},			/* 11.2.85 */
	{ 86,		"GA-RRC Cause"},				/* 11.2.86 */
	{ 87,		"GA-RRC Paging Cause"},				/* 11.2.87 */
	{ 88,		"Intra Domain NAS Node Selector"},		/* 11.2.88 */
	{ 89,		"CTC Activation List"},				/* 11.2.89 */
	{ 90,		"CTC Description"},				/* 11.2.90 */
	{ 91,		"CTC Activation Ack List"},			/* 11.2.91 */
	{ 92,		"CTC Activation Ack Description"},		/* 11.2.92 */
	{ 93,		"CTC Modification List"},			/* 11.2.93 */
	{ 94,		"CTC Modification Ack List"},			/* 11.2.94 */
	{ 95,		"CTC Modification Ack Description"},		/* 11.2.95 */
	{ 96,		"MS Radio Identity"},
	{ 97,		"GANC IP Address"},
	{ 98,		"GANC Fully Qualified Domain/Host Name"},
	{ 99,		"IP address for GPRS user data transport"},
	{ 100,		"UDP Port for GPRS user data transport"},
	{ 101,		"Unknown"},
	{ 102,		"Unknown"},
	{ 103,		"GANC TCP port"},
	{ 104,		"RTP UDP port"},
	{ 105,		"RTCP UDP port"},
	{ 106,		"GERAN Received Signal Level List"},
	{ 107,		"UTRAN Received Signal Level List"},
	{ 108,		"PS Handover to GERAN Command"},		/* 11.2.74 */
	{ 109,		"PS Handover to UTRAN Command"},		/* 11.2.75 */
	{ 110,		"PS Handover to GERAN PSI"},			/* 11.2.76 */
	{ 111,		"PS Handover to GERAN SI"},			/* 11.2.77 */
	{ 112,		"TU4004 Timer"},				/* 11.2.78 */
	{ 113,		"Unknown"},
	{ 114,		"Unknown"},
	{ 115,		"PTC Activation List"},				/* 11.2.96 */
	{ 116,		"PTC Description"},				/* 11.2.97 */
	{ 117,		"PTC Activation Ack List"},			/* 11.2.98 */
	{ 118,		"PTC Activation Ack Description"},		/* 11.2.99 */
	{ 119,		"PTC Modification List"},			/* 11.2.100 */
	{ 120,		"PTC Modification Ack List"},			/* 11.2.101 */
	{ 121,		"PTC Modification Ack Description"},		/* 11.2.102 */
	{ 122,		"RAB Configuration"},				/* 11.2.103 */
	{ 123,		"Multi-rate Configuration 2"},			/* 11.2.104 */
	{ 124,		"Selected Integrity Protection Algorithm"},	/* 11.2.105 */
	{ 125,		"Selected Encryption Algorithm"},		/* 11.2.106 */
	{ 126,		"CN Domains to Handover"},			/* 11.2.107 */
	{ 127,		"SRNS Relocation Info"},			/* 11.2.107 */
	{ 128,		"MS Radio Access Capability"},			/* 11.2.107 */
	{ 129,		"Handover Reporting Control"},			/* 11.2.107 */
	{ 0,	NULL }
};
static value_string_ext uma_urr_IE_type_vals_ext = VALUE_STRING_EXT_INIT(uma_urr_IE_type_vals);

static const value_string uma_urr_mobile_identity_type_vals[] = {
	{ 0,		"No Identity"},
	{ 1,		"IMSI"},
	{ 2,		"IMEI"},
	{ 3,		"IMEISV"},
	{ 4,		"TMSI/P-TMSI"},
	{ 0,	NULL }
};

static const value_string uma_urr_gan_rel_ind_vals[] = {
	{ 1,		"Release 1 (i.e. 3GPP Release-6)"},
	{ 2,		"Release 2 (i.e. 3GPP Release-7)"},
	{ 3,		"Release 3 (i.e. 3GPP Release-8)"},
	{ 0,	NULL }
};

static const value_string uma_urr_oddevenind_vals[] = {
	{ 0,		"Even number of identity digits"},
	{ 1,		"Odd number of identity digits"},
	{ 0,	NULL }
};

static const value_string radio_type_of_id_vals[] = {
	{ 0,		"IEEE MAC-address format"},
	{ 0,	NULL }
};

/* GCI, GSM Coverage Indicator (octet 3) */
static const value_string uma_gci_vals[] = {
	{ 0,		"Normal Service in the GERAN"},
	{ 1,		"Limited Service in the GERAN"},
	{ 2,		"MS has not found GSM coverage (LAI information taken from SIM, if available)"},
	{ 3,		"MS has found GSM coverage, service state unknown"},
	{ 0,	NULL }
};
/* TURA, Type of Unlicensed Radio (octet 3) */
static const value_string uma_tura_vals[] = {
	{ 0,		"No radio"},
	{ 1,		"Bluetooth"},
	{ 2,		"WLAN 802.11"},
	{ 15,		"Unspecified"},
	{ 0,	NULL }
};
/* GC, GERAN Capable (octet 3) */
static const value_string uma_gc_vals[] = {
	{ 0,		"The MS is not GERAN capable."},
	{ 1,		"The MS is GERAN capable."},
	{ 0,	NULL }
};
/* UC, UTRAN Capable (octet 3) */
static const value_string uma_uc_vals[] = {
	{ 0,		"The MS is not UTRAN  capable."},
	{ 1,		"The MS is UTRAN  capable."},
	{ 0,	NULL }
};
/*RRS, RTP Redundancy Support (octet 4)*/
static const value_string uma_rrs_vals[] = {
	{ 0,		"RTP Redundancy not supported"},
	{ 1,		"RTP Redundancy supported"},
	{ 0,	NULL }
};
/*
 * PS HO, PS Handover Capable (octet 4) Bit 2
 */
static const value_string uma_ps_ho_vals[] = {
	{ 0,		"The MS does not support PS handover to/from GAN A/Gb mode"},
	{ 1,		"The MS supports PS handover to/from GAN A/Gb mode"},
	{ 0,	NULL }
};
/*
 * GMSI, GAN Mode Support Indicator (octet 4)v Bits 4 3
 */

static const value_string uma_gmsi_vals[] = {
	{ 0,		"Unspecified"},
	{ 1,		"The MS supports GAN A/Gb mode only"},
	{ 2,		"The MS supports GAN Iu mode only"},
	{ 3,		"The MS supports GAN A/Gb mode and GAN Iu mode"},
	{ 0,	NULL }
};

/*IP address type number value (octet 3)*/
static const value_string IP_address_type_vals[] = {
	{ 0x21,		"IPv4 address"},
	{ 0x57,		"IPv6 address"},
	{ 0,	NULL }
};

/*Discovery Reject Cause (octet 3) */
static const value_string uma_discovery_reject_cause_vals[] = {
	{ 0,		"Network Congestion"},
	{ 1,		"Unspecified"},
	{ 2,		"IMSI not allowed"},
	{ 0,	NULL }
};
/*EC Emergency Call allowed (octet 3)*/
static const value_string EC_vals[] _U_ = {
	{ 0,		"Emergency call allowed in the cell to all MSs"},
	{ 1,		"Emergency call not allowed in the cell except for the MSs that belong to one of the classes between 11 to 15."},
	{ 0,	NULL }
};
/*ECMC, Early Classmark Sending Control (octet 3)*/
static const value_string ECMC_vals[] = {
	{ 0,		"Early Classmark Sending is allowed"},
	{ 1,		"Early Classmark Sending is forbidden"},
	{ 0,	NULL }
};
/*NMO, Network Mode of Operation (octet 3)*/
static const value_string NMO_vals[] = {
	{ 0,		"Network Mode of Operation I"},
	{ 1,		"Network Mode of Operation II"},
	{ 2,		"Network Mode of Operation III"},
	{ 3,		"Reserved"},
	{ 0,	NULL }
};
/*GPRS, GPRS Availability (octet 3)*/
static const value_string GPRS_avail_vals[] = {
	{ 0,		"GPRS available"},
	{ 1,		"GPRS not available"},
	{ 0,	NULL }
};
/*DTM, Dual Transfer Mode of Operation by network (octet 3)*/
static const value_string DTM_vals[] = {
	{ 0,		"Network does not support dual transfer mode"},
	{ 1,		"Network supports dual transfer mode"},
	{ 0,	NULL }
};
/*ATT, Attach-detach allowed (octet 3)*/
static const value_string ATT_vals[] = {
	{ 0,		"MSs in the cell are not allowed to apply IMSI attach and detach procedure."},
	{ 1,		"MSs in the cell shall apply IMSI attach and detach procedure."},
	{ 0,	NULL }
};
/*MSCR, MSC Release (octet 3)*/
static const value_string MSCR_vals[] = {
	{ 0,		"MSC is Release '98 or older"},
	{ 1,		"MSC is Release '99 onwards"},
	{ 0,	NULL }
};

/* SGSNR, SGSN Release (octet 6)*/
static const value_string SGSNR_vals[] = {
	{ 0,		"SGSN is Release '98 or older"},
	{ 1,		"SGSN is Release '99 onwards"},
	{ 0,	NULL }
};
/* ECMP, Emergency Call Mode Preference (octet 6)*/

static const value_string ECMP_vals[] = {
	{ 0,		"GSM GERAN is preferred for Emergency calls"},
	{ 1,		"UMAN is preferred for Emergency calls"},
	{ 0,	NULL }
};
/* RE, Call reestablishment allowed (octet 6) */
static const value_string RE_vals[] = {
	{ 0,		"Call Reestablishment allowed in the cell"},
	{ 1,		"Call Reestablishment not allowed in the cell"},
	{ 0,	NULL }
};
/* PFCFM, PFC_FEATURE_MODE (octet 6) */
static const value_string PFCFM_vals[] = {
	{ 0,		"The network does not support packet flow context procedures"},
	{ 1,		"The network supports packet flow context procedures"},
	{ 0,	NULL }
};

/* 3GECS, 3G Early Classmark Sending Restriction (octet 6) */
static const value_string Three_GECS_vals[] = {
	{ 0,		"UTRAN classmark change message shall be sent with the Early classmark sending"},
	{ 1,		"The sending of UTRAN Classmark Sending messages is controlled by the Early Classmark Sending Control parameter"},
	{ 0,	NULL }
};

/*GRS, GSM RR State (octet 3)*/
static const value_string uma_GRS_GSM_RR_State_vals[] = {
	{ 0,		"GSM RR is in IDLE state"},
	{ 1,		"GSM RR is in DEDICATED state"},
	{ 2,		"UTRAN RRC is in IDLE STATE"},
	{ 3,		"UTRAN RRC is in CELL_DCH STATE"},
	{ 4,		"UTRAN RRC is in CELL_FACH STATE"},
	{ 5,		"UTRAN RRC is in CELL_PCH STATE"},
	{ 6,		"UTRAN RRC is in URA_PCH STATE"},
	{ 7,		"Unknown"},
	{ 0,	NULL }
};
static value_string_ext uma_GRS_GSM_RR_State_vals_ext = VALUE_STRING_EXT_INIT(uma_GRS_GSM_RR_State_vals);

/* UMA Band (4 bit field) */
static const value_string uma_gan_band_vals[] = {
	{ 0,		"E-GSM is supported"},
	{ 1,		"P-GSM is supported"},
	{ 2,		"GSM 1800 is supported"},
	{ 3,		"GSM 450 is supported"},
	{ 4,		"GSM 480 is supported"},
	{ 5,		"GSM 850 is supported"},
	{ 6,		"GSM 1900 is supported"},
	{ 7,		"GSM 700 is supported"},
	{ 0,	NULL }
};
static value_string_ext uma_gan_band_vals_ext = VALUE_STRING_EXT_INIT(uma_gan_band_vals);

/*URS, URR State (octet 3) */
static const value_string URR_state_vals[] = {
	{ 0,		"GA-CSR is in GA-CSR-IDLE state"},
	{ 1,		"GA-CSR is in GA-CSR-DEDICATED state"},
	{ 2,		"GA-RC is in GA-RC-REGISTERED state while in GERAN/UTRAN mode"},
	{ 0,	NULL }
};
/*
UPS, GA-PSR State (octet 3)
Bit
3
0 GA-PSR is in GA-PSR-STANDBY state.
1 GA-PSR is in GA-PSR-ACTIVE state.
GA-RRC-CS, GA-RRC (CS) State (octet 3)
Bit
4
0 GA-RRC (CS) is in GA-RRC-IDLE state.
1 GA-RRC (CS) is in GA-RRC-CONNECTED
state.
GA-RRC-PS, GA-RRC (PS) State (octet 3)
Bit
5
0 GA-RRC (PS) is in GA-RRC-IDLE state.
1 GA-RRC (PS) is in GA-RRC-CONNECTED
state.
*/

/* Register Reject Cause (octet 3) */
static const value_string register_reject_cause_vals[] = {
	{ 0,		"Network Congestion"},
	{ 1,		"AP not allowed"},
	{ 2,		"Location not allowed"},
	{ 3,		"Invalid GANC"},
	{ 4,		"Geo Location not known"},
	{ 5,		"IMSI not allowed"},
	{ 6,		"Unspecified"},
	{ 7,		"GANC-SEGW certificate not valid"},
	{ 8,		"EAP_SIM authentication failed"},
	{ 9,		"TCP establishment failed"},
	{ 10,		"Redirection"},
	{ 11,		"EAP-AKA authentication failed"},
	/* 12 to 255 Reserved for future use. */
	{ 0,	NULL }
};
static value_string_ext register_reject_cause_vals_ext = VALUE_STRING_EXT_INIT(register_reject_cause_vals);

/* L3 Protocol discriminator values according to TS 24 007 (640)  */
#if 0  /** See packet-gms_a-dtap.c **/
static const value_string protocol_discriminator_vals[] = {
	{0x0,		"Group call control"},
	{0x1,		"Broadcast call control"},
	{0x2,		"Reserved: was allocated in earlier phases of the protocol"},
	{0x3,		"Call Control; call related SS messages"},
	{0x4,		"GPRS Transparent Transport Protocol (GTTP)"},
	{0x5,		"Mobility Management messages"},
	{0x6,		"Radio Resources Management messages"},
	{0x7,		"Unknown"},
	{0x8,		"GPRS mobility management messages"},
	{0x9,		"SMS messages"},
	{0xa,		"GPRS session management messages"},
	{0xb,		"Non call related SS messages"},
	{0xc,		"Location services specified in 3GPP TS 44.071 [8a]"},
	{0xd,		"Unknown"},
	{0xe,		"Reserved for extension of the PD to one octet length "},
	{0xf,		"Reserved for tests procedures described in 3GPP TS 44.014 [5a] and 3GPP TS 34.109 [17a]."},
	{ 0,	NULL }
};
#endif

/* algorithm identifier
 * If SC=1 then:
 * bits
 * 4 3 2
 */
static const value_string algorithm_identifier_vals[] = {
	{ 0,		"Cipher with algorithm A5/1"},
 	{ 1,		"Cipher with algorithm A5/2"},
 	{ 2,		"Cipher with algorithm A5/3"},
	{ 3,		"Cipher with algorithm A5/4"},
 	{ 4,		"Cipher with algorithm A5/5"},
 	{ 5,		"Cipher with algorithm A5/6"},
 	{ 6,		"Cipher with algorithm A5/7"},
	{ 7,		"Reserved"},
	{ 0,	NULL }
};
static value_string_ext algorithm_identifier_vals_ext = VALUE_STRING_EXT_INIT(algorithm_identifier_vals);

/*  GPRS Resumption */
static const value_string GPRS_resumption_vals[] = {
	{ 0,		"Resumption of GPRS services not successfully acknowledged"},
	{ 1,		"Resumption of GPRS services successfully acknowledged"},
	{ 0,	NULL }
};
/* SC (octet 1) */
static const value_string SC_vals[] = {
	{ 0,		"No ciphering"},
	{ 1,		"Start ciphering"},
	{ 0,	NULL }
};

/* ULQI, UL Quality Indication (octet 3) */
static const value_string uma_ulqi_vals[] = {
	{ 0,		"Quality ok"},
	{ 1,		"Radio problem"},
	{ 2,		"Network problem"},
	{ 4,		"Undetermined problem"},
	{ 0,	NULL }
};

static const value_string radio_pri_vals[] = {
	{ 0,		"Radio priority 1"},
	{ 1,		"Radio priority 2"},
	{ 2,		"Radio priority 3"},
	{ 3,		"Radio priority 4"},
	{ 0,	NULL }
};

static const value_string rlc_mode_vals[] = {
	{ 0,		"RLC acknowledged mode"},
	{ 1,		"RLC unacknowledged mode"},
	{ 0,	NULL }
};

/*URLC Cause (octet 3) */
static const value_string uma_ga_psr_cause_vals[] = {
	{ 0,		"success"},
	{ 1,		"future use"},
	{ 2,		"no available resources"},
	{ 3,		"GANC failure"},
	{ 4,		"not authorized for data service"},
	{ 5,		"message type non existent or not implemented"},
	{ 6,		"message type not compatible with the protocol state"},
	{ 7,		"invalid mandatory information"},
	{ 8,		"syntactically incorrect message"},
	{ 9,		"GPRS suspended"},
	{ 10,		"normal deactivation"},
	{ 11,		"future use"},
	{ 12,		"conditional IE error"},
	{ 13,		"semantically incorrect message"},
	{ 14,		"PS handover failure - incorrect handover command"},
	{ 15,		"PS handover failure - target RAT access failure"},
	{ 16,		"PS handover failure - missing SI/PSI information"},
	{ 17,		"PS handover failure - no uplink TBF allocation"},
	{ 0,	NULL }
};
static value_string_ext uma_ga_psr_cause_vals_ext = VALUE_STRING_EXT_INIT(uma_ga_psr_cause_vals);

/* LS, Location Status (octet 3) */
static const value_string LS_vals[] = {
	{ 0,		"MS location known"},
	{ 1,		"MS location unknown"},
	{ 0,	NULL }
};

/* CR Cipher Response (octet 1) */
static const value_string CR_vals[] = {
	{ 0,		"IMEISV shall not be included"},
	{ 1,		"IMEISV shall be included"},
	{ 0,	NULL }
};

/* SAPI ID, SAPI Identifier (octet 3) */
static const value_string sapi_id_vals[] = {
	{ 0,		"SAPI 0 (all other except SMS)"},
	{ 3,		"SAPI 3 (SMS)"},
	{ 0,	NULL }
};
/*	Sample Size (octet 3)*/
static const value_string sample_size_vals[] = {
	{ 20,		"20 ms of CS payload included in each RTP/UDP packet"},
	{ 40,		"40 ms of CS payload included in each RTP/UDP packet"},
	{ 60,		"60 ms of CS payload included in each RTP/UDP packet"},
	{ 80,		"80 ms of CS payload included in each RTP/UDP packet"},
	{ 0,	NULL }
};


/* MPS, Manual PLMN Selection indicator (octet 3) */
static const value_string mps_vals[] = {
	{ 0,		"The MS is in Automatic PLMN selection mode."},
	{ 1,		"The MS is in Manual PLMN selection mode and request the listof PLMN identities that may provide UMAN service in the current location."},
	{ 2,		"The MS is in Manual PLMN selection mode and tries to register; no PLMN list is needed."},
	{ 0,	NULL }
};

/* CBS Cell Broadcast Service (octet 3) */
static const value_string cbs_vals[] = {
	{ 0,		"CBS is not required by the Mobile station"},
	{ 1,		"CBS is required by the mobile station"},
	{ 0,	NULL }
};

/* LBLI, Location Black List indicator (octet 3) */
static const value_string LBLI_vals[] = {
	{ 0,		"MCC"},
	{ 1,		"MCC and MNC"},
	{ 2,		"MCC, MNC and LAC"},
	{ 0,	NULL }
};
/* AP Service Name type */
static const value_string ap_service_name_type_vals[] = {
	{ 0,		"SSID"},
	{ 1,		"PAN Service Name"},
	{ 0,	NULL }
};

/* UMA Service Zone Icon Indicator, octet 3 */
static const value_string uma_service_zone_icon_ind_vals[] = {
	{ 1,		"Unlimited Calls"},
	{ 0,	NULL }
};
/*Establishment Cause (octet 3)*/
static const value_string uma_establishment_cause_val[] = {
	{ 0x00,		"Location Update"},
	{ 0x10,		"Other SDCCH procedures including IMSI Detach, SMS, SS, paging response"},
/* note: Paging response for SDCCH needed is using codepoint  0001 0000 */
	{ 0x20,		"Paging response (TCH/F needed)"},
	{ 0x30,		"Paging response (TCH/F or TCH/H needed)"},
	{ 0x40,		"Originating speech call from dual-rate mobile station when TCH/H is sufficient"},
	{ 0x50,		"Originating data call from dual-rate mobile station when TCH/H is sufficient"},
	{ 0x80,		"Paging response (any channel needed)"},
	{ 0xa0,		"Emergency"},
	{ 0xc0,		"Call re-establishment"},
	{ 0xe0,		"Originating speech call and TCH/F is needed"},
	{ 0xf0,		"Originating data call and TCH/F is needed"},
	{ 0,	NULL }
};
static value_string_ext uma_establishment_cause_val_ext = VALUE_STRING_EXT_INIT(uma_establishment_cause_val);

/*CHANNEL (octet 3) */
static const value_string channel_vals[] = {
	{ 0,		"Any channel"},
	{ 1,		"SDCCH"},
	{ 2,		"TCH/F (Full rate)"},
	{ 3,		"TCH/H or TCH/F (Dual rate)"},
	{ 0,	NULL }
};

/*RI, Reset Indicator (octet 3)*/
/*CHANNEL (octet 3) */
static const value_string RI_vals[] = {
	{ 0,		"The flow control condition continues to exist"},
	{ 1,		"The flow control condition no longer exists"},
	{ 0,	NULL }
};

/* Window Size (octet 3 to octet n) */

static const value_string window_size_vals[] = {
	{ 0,		"Window size 1, No redundancy"},
	{ 1,		"Window size 2 (single redundancy)"},
	{ 2,		"Window size 3 (double redundancy)"},
	{ 0,	NULL }
};

static const value_string UTRAN_cell_id_disc_vals[] = {
	{ 0,		"PLMN-ID, LAC and a 28-bit Cell Id are used to identify the target UTRAN cell."},
	{ 0,	NULL }
};

/* SUTI, Serving UNC table indicator indicator (octet 3) */

static const value_string suti_vals[] = {
	{ 0,		"The MS is not allowed to store information in the stored Serving UNC table."},
	{ 1,		"The MS is allowed to store information in the stored Serving UNC table."},
	{ 0,	NULL }
};
	/* Code to actually dissect the packets */

static int
dissect_uma_IE(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	tvbuff_t	*l3_tvb;
	tvbuff_t	*llc_tvb;
	tvbuff_t	*new_tvb;
	int		ie_offset;
	guint8		ie_value;
	guint16		ie_len = 0;
	guint8		octet;
	proto_item	*urr_ie_item;
	proto_tree	*urr_ie_tree;
	char		*string;
	guint16		GPRS_user_data_transport_UDP_port,UNC_tcp_port,RTP_UDP_port,RTCP_UDP_port;
	guint32		udr;
	conversation_t *conversation;
	address 	dst_addr, null_addr;
	guint8		str_len;
	address		src_addr;

	ie_value = tvb_get_guint8(tvb,offset);
	urr_ie_item = proto_tree_add_text(tree,tvb,offset,-1,"%s",
		val_to_str_ext(ie_value, &uma_urr_IE_type_vals_ext, "Unknown IE (%u)"));
	urr_ie_tree = proto_item_add_subtree(urr_ie_item, ett_urr_ie);

	proto_tree_add_item(urr_ie_tree, hf_uma_urr_IE, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	/* Some IE:s might have a length field of 2 octets */
	ie_len = tvb_get_guint8(tvb,offset);
	if ( (ie_len & 0x80) == 0x80 ){
		offset++;
		ie_len = (ie_len & 0x7f) << 8;
		ie_len = ie_len | (tvb_get_guint8(tvb,offset));
		proto_item_set_len(urr_ie_item, ie_len + 3);
		proto_tree_add_uint(urr_ie_tree, hf_uma_urr_IE_len , tvb, offset-1, 2, ie_len );
		ie_offset = offset +1;
	}else{
		proto_item_set_len(urr_ie_item, ie_len + 2);
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_IE_len, tvb, offset, 1, ENC_BIG_ENDIAN);
		ie_offset = offset +1;
	}

	switch(ie_value){
	/* 11.2.1 Mobile Identity */
	case 1:
	/* Mobile Identity
	 * The rest of the IE is coded as in [TS 24.008] not including IEI and
	 * length, if present.(10.5.1.4)
	 */
		de_mid(tvb, urr_ie_tree, pinfo, ie_offset, ie_len, NULL, 0);
		break;

	case 2:
		/* UMA Release Indicator */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_uri, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		break;
	case 3:			/* Radio Identity */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_radio_type_of_id, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		octet = tvb_get_guint8(tvb,ie_offset);
		if (( octet & 0xf) == 0){ /* IEEE MAC-address format */
			ie_offset++;
			proto_tree_add_item(urr_ie_tree, hf_uma_urr_radio_id, tvb, ie_offset, ie_len, ENC_NA);
		}else{
			proto_tree_add_text(urr_ie_tree, tvb, ie_offset, ie_len,"Unknown format");
		}
		break;
	case 4:
		/* Cell Identity
		 * The rest of the IE is coded as in [TS 24.008] not including IEI and length, if present.
		 */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_cell_id, tvb, ie_offset, 2, ENC_BIG_ENDIAN);
		break;
	case 5:
		/* Location Area Identification
		 * The rest of the IE is coded as in [TS 24.008] not including IEI and
		 * length, if present.
		 */
		de_lai(tvb, urr_ie_tree, pinfo, ie_offset, ie_len, NULL, 0);
		break;
	case 6:
		/* GSM Coverage Indicator */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_gci, tvb, ie_offset, 1, FALSE);
		break;
	case 7:
		/* 11.2.7 GAN Classmark */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_tura, tvb, ie_offset, 1, FALSE);
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_gc, tvb, ie_offset, 1, FALSE);
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_uc, tvb, ie_offset, 1, FALSE);
		/* UMA Protocols (Stage 3) R1.0.3 */
		if(ie_len>1){
			ie_offset++;
			proto_tree_add_item(urr_ie_tree, hf_uma_urr_gmsi, tvb, ie_offset, 1, FALSE);
			proto_tree_add_item(urr_ie_tree, hf_uma_urr_psho, tvb, ie_offset, 1, FALSE);
			proto_tree_add_item(urr_ie_tree, hf_uma_urr_rrs, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		}
		break;
	case 8:
		/* Geographical Location
		 * The Location Estimate field is composed of 1 or more octets with an internal structure
		 * according to section 7 in [23.032].
		 */
		new_tvb = tvb_new_subset(tvb, ie_offset,ie_len, ie_len );
		dissect_geographical_description(new_tvb, pinfo, urr_ie_tree);
		break;
	case 9:
		/* UNC SGW IP Address
		 * IP Address type
		 */
		octet = tvb_get_guint8(tvb,ie_offset);
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_IP_Address_type, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		ie_offset++;
		if ( octet == 0x57 ){ /* IPv6 */

		}else{ /* All other values shall be interpreted as Ipv4 address in this version of the protocol.*/
			sgw_ipv4_address = tvb_get_ipv4(tvb, ie_offset);
			proto_tree_add_ipv4(urr_ie_tree, hf_uma_urr_sgw_ipv4, tvb, ie_offset, 4, sgw_ipv4_address);

		}
		break;
	case 10:		/* UNC SGW Fully Qualified Domain/Host Name */
		if ( ie_len > 0){
			string = (gchar*)tvb_get_ephemeral_string(tvb, ie_offset, ie_len);
			proto_tree_add_string(urr_ie_tree, hf_uma_urr_FQDN, tvb, ie_offset, ie_len, string);
		}else{
			proto_tree_add_text(urr_ie_tree,tvb,offset,1,"FQDN not present");
		}
		break;
	case 11:		/* Redirection Counter */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_redirection_counter, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		break;
	case 12:		/* 11.2.12 Discovery Reject Cause */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_dis_rej_cau, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		break;
	case 13:
		/* 11.2.13 GAN Cell Description
		 * The rest of the IE is coded as in [TS 44.018], Cell Description IE, not including IEI and length, if present
		 */
		de_rr_cell_dsc(tvb, urr_ie_tree, pinfo, ie_offset, ie_len, NULL, 0);
		break;
	case 14:
		/*
		 * 11.2.14 GAN Control Channel Description
		 */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_ECMC, tvb, ie_offset, 1, FALSE);
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_NMO, tvb, ie_offset, 1, FALSE);
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_GPRS, tvb, ie_offset, 1, FALSE);
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_DTM, tvb, ie_offset, 1, FALSE);
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_ATT, tvb, ie_offset, 1, FALSE);
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_MSCR, tvb, ie_offset, 1, FALSE);
		/* T3212 timeout value */
		ie_offset++;
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_T3212_timer, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		/* RAC, Routing Area Code (octet 5) */
		ie_offset++;
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_RAC, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		ie_offset++;
		/* SGSNR, SGSN Release (octet 6) B1*/
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_SGSNR, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_ECMP, tvb, ie_offset, 1, FALSE);
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_RE, tvb, ie_offset, 1, FALSE);
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_PFCFM, tvb, ie_offset, 1, FALSE);
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_3GECS, tvb, ie_offset, 1, FALSE);
		/* PS HO, PS Handover indicator (octet 6) Bit 6 */

		ie_offset++;
		proto_tree_add_text(urr_ie_tree,tvb,ie_offset,2,"Access Control Class N");
		/* These fields are specified and described in 3GPP TS 44.018 and 3GPP TS 22.011. */
		break;
	case 15:
		/* 11.2.15 Cell Identifier List
		 * The rest of the IE is coded as in [TS 48.008], not including IEI and length, if present
		 */
		be_cell_id_list(tvb, urr_ie_tree, pinfo, ie_offset, ie_len, NULL, 0);
		break;
	case 16:		/* TU3907 Timer */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_TU3907_timer, tvb, ie_offset, 2, ENC_BIG_ENDIAN);
		break;
	case 17:		/* 11.2.17 GSM RR/UTRAN RRC State */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_GSM_RR_state, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		break;
	case 18:		/* 11.2.18 Routing Area Identification */
		/* The rest of the IE is coded as in [TS 24.008] not including IEI and length, if present.*/
		de_gmm_rai(tvb, urr_ie_tree, pinfo, ie_offset, ie_len, NULL, 0);
		break;
	case 19:		/* 11.2.19 GAN Band */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_gan_band, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		break;
	case 20:		/* 11.2.20 GAN State */
		/* URS, GA-RC/GA-CSR State (octet 3) Bits 2-1 */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_URR_state, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		/* UPS, GA-PSR State (octet 3) Bit 3 */
		/* GA-RRC-CS, GA-RRC (CS) State (octet 3) Bit 4 */
		/* GA-RRC-PS, GA-RRC (PS) State (octet 3) Bit 5 */
		break;
	case 21:		/* 11.2.21 Register Reject Cause */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_register_reject_cause, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		break;
	case 22:		/* 11.2.22 TU3906 Timer */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_TU3906_timer, tvb, ie_offset, 2, ENC_BIG_ENDIAN);
		break;
	case 23:		/* 11.2.23 TU3910 Timer */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_TU3910_timer, tvb, ie_offset, 2, ENC_BIG_ENDIAN);
		break;
	case 24:		/* 11.2.24 TU3902 Timer */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_TU3902_timer, tvb, ie_offset, 2, ENC_BIG_ENDIAN);
		break;
	case 25:
		/* 11.2.25 Communication Port Identity */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_communication_port, tvb, ie_offset, 2, ENC_BIG_ENDIAN);
		break;

	case 26:
		/* 11.2.26 L3 Message
		 * The L3 Message information element contains the upper layer message to be transported
		 * using the GA-CSR protocol or the GA-RRC protocol between the MS and the core network.
		 */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_L3_protocol_discriminator, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_L3_Message, tvb, ie_offset, ie_len, ENC_NA);
		l3_tvb = tvb_new_subset(tvb, ie_offset,ie_len, ie_len );
		if  (!dissector_try_uint(bssap_pdu_type_table,BSSAP_PDU_TYPE_DTAP, l3_tvb, pinfo, urr_ie_tree))
		   		call_dissector(data_handle, l3_tvb, pinfo, urr_ie_tree);
		break;
	case 27:
		/* 11.2.27 Channel Mode
		 * The rest of the IE is coded as in [TS 44.018], not including IEI and length, if present
		 */
		de_rr_ch_mode(tvb, urr_ie_tree, pinfo, ie_offset, ie_len, NULL, 0);
		break;
	case 28:
		/* 11.2.28 Mobile Station Classmark 2
		 * The rest of the IE is coded as in [TS 24.008], not including IEI and length, if present
		 */
		de_ms_cm_2(tvb, urr_ie_tree, pinfo, ie_offset, ie_len, NULL, 0);
		break;
	case 29:
		/* 11.2.29 RR Cause
		 * The rest of the IE is coded as in [TS 44.018], not including IEI and length, if present
		 */
		de_rr_cause(tvb, urr_ie_tree, pinfo, ie_offset, 1, NULL, 0);
		break;
	case 30:
		/* 11.2.30 Cipher Mode Setting
		 * Note: The coding of fields SC and algorithm identifier is defined in [44.018]
		 * as part of the Cipher Mode Setting IE.
		 */
		de_rr_cip_mode_set(tvb, urr_ie_tree, pinfo, ie_offset, ie_len, NULL, 0);
		break;
	case 31:
		/* 11.2.31 GPRS Resumption
		 * The rest of the IE is coded as in [TS 44.018], not including IEI and length, if present
		 */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_GPRS_resumption, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		break;
	case 32:
		/* 11.2.32 Handover From GAN Command
		 * If the target RAT is GERAN, the rest of the IE is coded as HANDOVER COMMAND message in [TS 44.018]
		 * If the target RAT is UTRAN, the rest of the IE is coded as
		 * HANDOVER TO UTRAN COMMAND message in [TS 25.331].
		 */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_L3_protocol_discriminator, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_L3_Message, tvb, ie_offset, ie_len, ENC_NA);
		/* XXX the dissector to call should depend on the RAT type ??? */
		l3_tvb = tvb_new_subset(tvb, ie_offset,ie_len, ie_len );
		if  (!dissector_try_uint(bssap_pdu_type_table,BSSAP_PDU_TYPE_DTAP, l3_tvb, pinfo, urr_ie_tree))
		   		call_dissector(data_handle, l3_tvb, pinfo, urr_ie_tree);
		break;
	case 33:
		/* 11.2.33 UL Quality Indication */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_ULQI, tvb, ie_offset, 1, FALSE);
		break;
	case 34:
		/* 11.2.34 TLLI
		 * The rest of the IE is coded as in [TS 44.018], not including IEI and length, if present.
		 * [TS 44.018]:10.5.2.41a
		 * The TLLI is encoded as a binary number with a length of 4 octets. TLLI is defined in 3GPP TS 23.003
		 */
		de_rr_tlli(tvb, urr_ie_tree, pinfo, ie_offset, ie_len, NULL, 0);
		break;
	case 35:
		/* 11.2.35 Packet Flow Identifier
		 * The rest of the IE is coded as in [TS 24.008], not including IEI and length, if present.
		 */
		de_sm_pflow_id(tvb, urr_ie_tree, pinfo, ie_offset, ie_len, NULL, 0);
		break;
	case 36:
		/* 11.2.36 Suspension Cause
		 * The rest of the IE is coded as in [TS 44.018], not including IEI and length, if present.
		 */
		de_rr_sus_cau(tvb, urr_ie_tree, pinfo, ie_offset, ie_len, NULL, 0);
		break;
	case 37:		/* 11.2.37 TU3920 Timer */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_TU3920_timer, tvb, ie_offset, 2, ENC_BIG_ENDIAN);
		break;
		/* 11.2.38 QoS */
	case 38:
		/* QoS
		 * PEAK_THROUGHPUT_CLASS (octet 3, bits 1-4)
		 * This field is coded as PEAK_THROUGHPUT_CLASS field in
		 * the Channel Request Description information
		 * element specified in [TS 44.060]
		 */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_peak_tpt_cls, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		/* RADIO_PRIORITY (octet 3, bits 5-6) */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_radio_pri, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		/* RLC_MODE (octet 3, bit 7) */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_rlc_mode, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		/* PEAK_THROUGHPUT_CLASS (octet 3, bits 1-4)*/
		break;
	case 39:		/* 11.2.39 GA-PSR Cause */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_ga_psr_cause, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		break;
	case 40:		/* 11.2.40 User Data Rate */
		/* The R field is the binary encoding of the rate information expressed in 100 bits/sec
		 * increments, starting from 0 x 100 bits/sec until 16777215 x 100 bits/sec (1.6 Gbps).
		 */
		udr = tvb_get_ntoh24(tvb, ie_offset) * 100;
		proto_tree_add_uint(urr_ie_tree, hf_uma_urr_udr , tvb, ie_offset, 3, udr );
		break;
	case 41:
		/* 11.2.41 Routing Area Code
		 * The rest of the IE is coded as in [TS 23.003] not including IEI and length, if present.
		 */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_RAC, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		break;
	case 42:
		/* 11.2.42 AP Location
		 * The rest of the IE is coded as in [GEOPRIV], not including IEI and length, if present
		 * http://www.ietf.org/internet-drafts/draft-ietf-geopriv-dhcp-civil-05.txt
		 */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_ap_location, tvb, ie_offset, ie_len, ENC_NA);
		break;
	case 43:		/* 11.2.43 TU4001 Timer */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_TU4001_timer, tvb, ie_offset, 2, ENC_BIG_ENDIAN);
		break;
	case 44:		/* 11.2.44 Location Status */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_LS, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		break;
	case 45:		/* Cipher Response */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_cipher_res, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		break;
	case 46:		/* Ciphering Command RAND */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_rand_val, tvb, ie_offset, ie_len, ENC_NA);
		break;
	case 47:		/* Ciphering Command MAC (Message Authentication Code)*/
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_ciphering_command_mac, tvb, ie_offset, ie_len, ENC_NA);
		break;
	case 48:		/* Ciphering Key Sequence Number */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_ciphering_key_seq_num, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		break;
	case 49:		/* SAPI ID */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_sapi_id, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		break;
	case 50:		/* 11.2.50 Establishment Cause */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_establishment_cause, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		break;
	case 51:		/* Channel Needed */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_channel, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		break;
	case 52:		/* PDU in Error */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_PDU_in_error, tvb, ie_offset, ie_len, FALSE);
		break;
	case 53:
		/* Sample Size
		 */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_sample_size, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		break;
	case 54:
		/* 11.2.54 Payload Type
		 * Payload Type (octet 3) Allowed values are between 96 and 127.
		 */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_payload_type, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		break;
	/* 11.2.55 Multirate Configuration */
	case 55:
		/* Multi-rate Configuration
		 * The rest of the IE is coded as in [TS 44.018], not including IEI and length, if present
		 */
		de_rr_multirate_conf(tvb, urr_ie_tree, pinfo, ie_offset, ie_len, NULL, 0);
		break;
	case 56:
		/* 11.2.56 Mobile Station Classmark 3
		 * The rest of the IE is coded as in [TS 24.008], not including IEI and length, if present
		 */
		de_ms_cm_3(tvb, urr_ie_tree, pinfo, offset, ie_len, NULL, 0);
		break;
	case 57:
		/* 11.2.57 LLC-PDU
		 * The rest of the IE is coded as in [TS 48.018], not including IEI and length, if present
		 */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_LLC_PDU, tvb, ie_offset, ie_len, ENC_NA);
		llc_tvb = tvb_new_subset(tvb, ie_offset,ie_len, ie_len );
		  if (llc_handle) {
			col_append_str(pinfo->cinfo, COL_PROTOCOL, "/");
			col_set_fence(pinfo->cinfo, COL_PROTOCOL);
			call_dissector(llc_handle, llc_tvb, pinfo, urr_ie_tree);
		  }else{
			  if (data_handle)
				  call_dissector(data_handle, llc_tvb, pinfo, urr_ie_tree);
		  }
		break;
	case 58:		/* 11.2.58 Location Black List indicator */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_LBLI, tvb, ie_offset, 1, FALSE);
		break;
	case 59:		/* 11.2.59 Reset Indicator */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_RI, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		break;
	case 60:		/* TU4003 Timer */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_TU4003_timer, tvb, ie_offset, 2, ENC_BIG_ENDIAN);
		break;
	case 61:
		/* AP Service Name */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_ap_service_name_type, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		ie_offset++;
		/* AP Service Name value (octet 4 to octet n)
		 * The AP Service Name is coded as a string according to UTF-8 format defined in RFC
		 * 3629 [50]. This means that the 1st octet of the UTF-8 string is coded in octet 4 and the
		 * last octet of the UTF-8 string is coded in the last octet of this IE (octet n).
		 */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_ap_Service_name_value, tvb, ie_offset, ie_len -1, ENC_ASCII|ENC_NA);
		break;
	case 62:
		/* 11.2.62 GAN Service Zone Information
		 * UMA Service Zone Icon Indicator, octet 3
		 */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_uma_service_zone_icon_ind, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		ie_offset++;
		/* Length of UMA Service Zone string */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_uma_service_zone_str_len, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		str_len = tvb_get_guint8(tvb,ie_offset);
		ie_offset++;
		/* UMA Service Zone string, 1st character */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_uma_service_zone_str, tvb, ie_offset, str_len, FALSE);
		break;
	/* 11.2.63 RTP Redundancy Configuration */
	case 63:
		/* RTP Redundancy Configuration */
		/* For each mode of the AMR Active Mode Set, as signaled in the Multi-rate Configuration IE, the window size for
		 * including redundant frames is indicated. So if e.g. the Active Mode Set contains four active modes, then the
		 * Redundancy Configuration IE consists of six octets, of which four indicate the Codec Mode to Window Size mapping.
		 */
		/* XXX TODO: loop ower the octets */
		/* Window Size (octet 3 to octet n) Bits 2 1 */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_window_size, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		/* GAN A/Gb Mode Codec Mode (octet 3 to octet n) Bits 8 7
		 * The GAN A/Gb Mode Codec Mode is coded as in [47] sub-clause 3.4.1
		 */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_uma_codec_mode, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		/* GAN Iu Mode Codec Mode (octet 3 to octet n) Bits 6 5 4 3 */
		break;
	case 64:
		/* 11.2.64 UTRAN Classmark
		 * The rest of the IE is the INTER RAT HANDOVER INFO coded as in
		 * [TS 25.331], not including IEI and length, if present
		 */
		new_tvb = tvb_new_subset(tvb, ie_offset,ie_len, ie_len );
		dissect_rrc_InterRATHandoverInfo_PDU(new_tvb, pinfo, urr_ie_tree);
		break;
	case 65:
		/* 11.2.65 Classmark Enquiry Mask
		 * The rest of the IE is the Classmark Enquiry Mask coded as in [TS 44.018], not including IEI and length, if present
		 */
		de_rr_cm_enq_mask(tvb, urr_ie_tree, pinfo, offset, ie_len, NULL, 0);
		break;
	case 66:
		/* 11.2.66 UTRAN Cell Identifier List
		 * UTRAN Cell Identification Discriminator
		 */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_UTRAN_cell_id_disc, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		octet = tvb_get_guint8(tvb,ie_offset);
		ie_offset++;
		if ( octet == 0 ){
			ie_offset = dissect_e212_mcc_mnc(tvb, pinfo, urr_ie_tree, ie_offset, TRUE);
			proto_tree_add_item(urr_ie_tree, hf_uma_urr_lac, tvb, ie_offset, 2, ENC_BIG_ENDIAN);
			ie_offset = ie_offset + 2;
			/* The octets 9-12 are coded as shown in 3GPP TS 25.331, Table 'Cell identity'.
			 * 10.3.2.2 Cell identity
			 * This information element identifies a cell unambiguously within a PLMN.
			 * NOTE: This information element may carry any implementation dependent identity that unambiguously identifies a
			 * cell within a PLMN.
			 * Cell identity - bit string(28)
			 */
		}
		break;
	case 67:
		/* 11.2.67 Serving GANC table indicator */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_suti, tvb, ie_offset, 1, FALSE);
		break;
	case 68:
		/* 11.2.68 Registration indicators */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_uma_mps, tvb, ie_offset, 1, FALSE);
		break;
	case 69:
		/* 11.2.69 GAN PLMN List */
		octet = tvb_get_guint8(tvb,ie_offset);
		proto_tree_add_uint(urr_ie_tree, hf_uma_urr_num_of_plms , tvb, ie_offset, 1, octet);
		/* TODO insert while loop here */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_lac, tvb, ie_offset, 2, ENC_BIG_ENDIAN);
		break;
	case 70:
		/* 11.2.70 GERAN Received Signal Level List */
		while(ie_offset<=(offset + ie_len)){
			proto_tree_add_item(urr_ie_tree, hf_uma_urr_RXLEV_NCELL, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
			ie_offset++;
		}
		break;
	case 71:
		/* 11.2.71 Required GAN Services */
		/* CBS Cell Broadcast Service (octet 3) */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_cbs, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		break;
	case 72:
		/* 11.2.72 Broadcast Container */
		octet = tvb_get_guint8(tvb,ie_offset);
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_num_of_cbs_frms , tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		/* The coding of the page of the CBS message is defined in sub-clause 9.4.1 in TS 23.041. */
		proto_tree_add_text(urr_ie_tree, tvb, ie_offset + 1, ie_len-1,"CBS Frames - Not decoded");
		break;
	case 73:
		/* 11.2.73 3G Cell Identity */
		/* The rest of the IE is coded as in [TS 25.331] not including IEI and length, if present.
		 * See Annex F for coding
		 */
		break;
	case 79:
		/* 11.2.79 GAN Mode Indicator */
	case 80:
		/* 11.2.80 CN Domain Identity */
	case 81:
		/* 11.2.81 GAN Iu Mode Cell Description */
	case 82:
		/* 11.2.82 3G UARFCN */
	case 83:
		/* 11.2.83 RAB ID */
	case 84:
		/* 11.2.84 RAB ID List */
	case 85:
		/* 11.2.85 GA-RRC Establishment Cause */
	case 86:
		/* 11.2.86 GA-RRC Cause */
	case 87:
		/* 11.2.87 GA-RRC Paging Cause */
	case 88:
		/* 11.2.88 Intra Domain NAS Node Selector */
	case 89:
		/* 11.2.89 CTC Activation List */
	case 90:
		/* 11.2.90 CTC Description */
	case 91:
		/* 11.2.91 CTC Activation Ack List */
	case 92:
		/* 11.2.92 CTC Activation Ack Description */
	case 93:
		/* 11.2.93 CTC Modification List */
	case 94:
		/* 11.2.94 CTC Modification Ack List */
	case 95:
		/* 11.2.95 CTC Modification Ack Description */
		proto_tree_add_text(urr_ie_tree,tvb,ie_offset,ie_len,"DATA");
		break;
	case 96:		/* MS Radio Identity */
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_radio_type_of_id, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		octet = tvb_get_guint8(tvb,ie_offset);
		if (( octet & 0xf) == 0){ /* IEEE MAC-address format */
			ie_offset++;
			proto_tree_add_item(urr_ie_tree, hf_uma_urr_ms_radio_id, tvb, ie_offset, ie_len, ENC_NA);
		}else{
			proto_tree_add_text(urr_ie_tree, tvb, ie_offset, ie_len,"Unknown format");
		}
		break;

	case 97:
		/* UNC IP Address
		 * IP Address type
		 */
		octet = tvb_get_guint8(tvb,ie_offset);
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_IP_Address_type, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		if (ie_len > 4 )
		ie_offset++;
		if ( octet == 0x57 ){ /* IPv6 */

		}else{ /* All other values shall be interpreted as Ipv4 address in this version of the protocol.*/
			unc_ipv4_address = tvb_get_ipv4(tvb, ie_offset);
			proto_tree_add_ipv4(urr_ie_tree, hf_uma_urr_unc_ipv4, tvb, ie_offset, 4, unc_ipv4_address);
		}
		break;
	case 98:
		/* UNC Fully Qualified Domain/Host Name */
		if ( ie_len > 0){
			string = (gchar*)tvb_get_ephemeral_string(tvb, ie_offset, ie_len);
			proto_tree_add_string(urr_ie_tree, hf_uma_unc_FQDN, tvb, ie_offset, ie_len, string);
		}else{
			proto_tree_add_text(urr_ie_tree,tvb,offset,1,"UNC FQDN not present");
		}
		break;
	case 99:
		/* IP address for GPRS user data transport
		 * IP Address type
		 */
		octet = tvb_get_guint8(tvb,ie_offset);
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_IP_Address_type, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
		ie_offset++;
		if ( octet == 0x57 ){ /* IPv6 */

		}else{ /* All other values shall be interpreted as Ipv4 address in this version of the protocol.*/
			GPRS_user_data_ipv4_address = tvb_get_ipv4(tvb, ie_offset);
			proto_tree_add_ipv4(urr_ie_tree, hf_uma_urr_GPRS_user_data_transport_ipv4, tvb, ie_offset, 4, GPRS_user_data_ipv4_address);

		}
		break;
	case 100:		/* UDP Port for GPRS user data transport */
		GPRS_user_data_transport_UDP_port = tvb_get_ntohs(tvb,ie_offset);
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_GPRS_port, tvb, ie_offset, 2, ENC_BIG_ENDIAN);
		/*
		 * If this isn't the first time this packet has been processed,
		 * we've already done this work, so we don't need to do it
		 * again.
		 */
		if (pinfo->fd->flags.visited)
		{
			break;
		}
		SET_ADDRESS(&null_addr, AT_NONE, 0, NULL);

		dst_addr.type=AT_IPv4;
		dst_addr.len=4;
		dst_addr.data=(guint8 *)&GPRS_user_data_ipv4_address;

		conversation = find_conversation(pinfo->fd->num,&dst_addr,
			&null_addr, PT_UDP, GPRS_user_data_transport_UDP_port,
			0, NO_ADDR_B|NO_PORT_B);

		if (conversation == NULL) {
			/* It's not part of any conversation - create a new one. */
			conversation = conversation_new(pinfo->fd->num, &dst_addr,
			    &null_addr, PT_UDP,GPRS_user_data_transport_UDP_port ,
			    0, NO_ADDR2|NO_PORT2);

		/* Set dissector */
		conversation_set_dissector(conversation, uma_udp_handle);
		}

		break;
	case 103:		/* UNC TCP port */
		UNC_tcp_port = tvb_get_ntohs(tvb,ie_offset);
		proto_tree_add_uint(urr_ie_tree, hf_uma_urr_UNC_tcp_port , tvb, ie_offset, 2, UNC_tcp_port);

		/*
		 * If this isn't the first time this packet has been processed,
		 * we've already done this work, so we don't need to do it
		 * again.
		 */
		if (pinfo->fd->flags.visited)
		{
			break;
		}
		SET_ADDRESS(&null_addr, AT_NONE, 0, NULL);

		dst_addr.type=AT_IPv4;
		dst_addr.len=4;
		dst_addr.data=(guint8 *)&unc_ipv4_address;

		conversation = find_conversation(pinfo->fd->num,&dst_addr,
			&null_addr, PT_TCP, UNC_tcp_port,
			0, NO_ADDR_B|NO_PORT_B);

		if (conversation == NULL) {
			/* It's not part of any conversation - create a new one. */
			conversation = conversation_new(pinfo->fd->num, &dst_addr,
			    &null_addr, PT_TCP,UNC_tcp_port ,
			    0, NO_ADDR2|NO_PORT2);
			/* Set dissector */
			conversation_set_dissector(conversation, uma_tcp_handle);
		}

		break;
	case 104:		/* RTP UDP port */
		RTP_UDP_port = tvb_get_ntohs(tvb,ie_offset);
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_RTP_port, tvb, ie_offset, 2, ENC_BIG_ENDIAN);
		/* TODO find out exactly which element contains IP addr */
		/* Debug
		proto_tree_add_text(urr_ie_tree,tvb,ie_offset,ie_len,"IP %u, Port %u Handle %u",
			rtp_ipv4_address,RTP_UDP_port,rtp_handle);
			*/
		if(unc_ipv4_address!=0){
			src_addr.type=AT_IPv4;
			src_addr.len=4;
			src_addr.data=(guint8 *)&unc_ipv4_address;
		}else{
			/* Set Source IP = own IP */
			src_addr = pinfo->src;
		}
		if((!pinfo->fd->flags.visited) && RTP_UDP_port!=0 && rtp_handle){

			rtp_add_address(pinfo, &src_addr, RTP_UDP_port, 0, "UMA", pinfo->fd->num, FALSE, 0);
			if ((RTP_UDP_port & 0x1) == 0){ /* Even number RTP port RTCP should follow on odd number */
				RTCP_UDP_port = RTP_UDP_port + 1;
				rtcp_add_address(pinfo, &src_addr, RTCP_UDP_port, 0, "UMA", pinfo->fd->num);
			}
		}
		break;
	case 105:		/* RTCP UDP port */
		RTCP_UDP_port = tvb_get_ntohs(tvb,ie_offset);
		proto_tree_add_item(urr_ie_tree, hf_uma_urr_RTCP_port, tvb, ie_offset, 2, ENC_BIG_ENDIAN);
		/* TODO find out exactly which element contains IP addr */
		if((!pinfo->fd->flags.visited) && rtcp_ipv4_address!=0 && RTCP_UDP_port!=0 && rtcp_handle){
			src_addr.type=AT_IPv4;
			src_addr.len=4;
			src_addr.data=(guint8 *)&rtcp_ipv4_address;

			rtcp_add_address(pinfo, &src_addr, RTCP_UDP_port, 0, "UMA", pinfo->fd->num);
		}
		break;
	case 106:
		/* 11.2.70 GERAN Received Signal Level List */
		while(ie_offset<=(offset + ie_len)){
			proto_tree_add_item(urr_ie_tree, hf_uma_urr_RXLEV_NCELL, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
			ie_offset++;
		}
		break;
	case 107:
		/* 11.2.70 UTRAN Received Signal Level List */
		while(ie_offset<=(offset + ie_len)){
			proto_tree_add_item(urr_ie_tree, hf_uma_urr_RXLEV_NCELL, tvb, ie_offset, 1, ENC_BIG_ENDIAN);
			ie_offset++;
		}
		break;
	case 108:
		/* 11.2.74 PS Handover to GERAN Command */
	case 109:
		/* 11.2.75 PS Handover to UTRAN Command */
	case 110:
		/* 11.2.76 PS Handover to GERAN PSI */
	case 111:
		/* 11.2.77 PS Handover to GERAN SI */
	case 112:
		/* 11.2.78 TU4004 Timer */
	case 115:
		/* 11.2.96 PTC Activation List */
	case 116:
		/* 11.2.97 PTC Description */
	case 117:
		/* 11.2.98 PTC Activation Ack List */
	case 118:
		/* 11.2.99 PTC Activation Ack Description */
	case 119:
		/* 11.2.100 PTC Modification List */
	case 120:
		/* 11.2.101 PTC Modification Ack List */
	case 121:
		/* 11.2.102 PTC Modification Ack Description */
	case 122:
		/* 11.2.103 RAB Configuration */
	case 123:
		/* 11.2.104 Multi-rate Configuration 2 */
	case 124:
		/* 11.2.105 Selected Integrity Protection Algorithm */
	case 125:
		/* 11.2.106 Selected Encryption Algorithm */
	case 126:
		/* 11.2.107 CN Domains to Handover */
	default:
		proto_tree_add_text(urr_ie_tree,tvb,ie_offset,ie_len,"DATA");
		break;
	}
	offset = offset + ie_len;
	return offset;
}



static void
dissect_uma(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int		offset = 0;
	guint8	octet, pd;
	guint16 msg_len;

/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *uma_tree;

/* Make entries in Protocol column and Info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "UMA");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_uma, tvb, 0, -1, FALSE);
	uma_tree = proto_item_add_subtree(ti, ett_uma);

/* add an item to the subtree, see section 1.6 for more information */
	msg_len = tvb_get_ntohs(tvb,offset);
	proto_tree_add_item(uma_tree, hf_uma_length_indicator, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset = offset + 2;
	octet = tvb_get_guint8(tvb,offset);
	pd = octet & 0x0f;
	proto_tree_add_item(uma_tree, hf_uma_skip_ind, tvb, offset, 1, ENC_BIG_ENDIAN);
	if ((octet & 0xf0) != 0 ){
		proto_tree_add_text(uma_tree, tvb,offset,-1,"Skip this message");
		return;
	}

	proto_tree_add_item(uma_tree, hf_uma_pd, tvb, offset, 1, ENC_BIG_ENDIAN);
	switch  ( pd ){
	case 0: /* URR_C */
	case 1: /* URR */
		offset++;
		octet = tvb_get_guint8(tvb,offset);
		proto_tree_add_item(uma_tree, hf_uma_urr_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		col_add_str(pinfo->cinfo, COL_INFO, val_to_str_ext(octet, &uma_urr_msg_type_vals_ext, "Unknown URR (%u)"));
		while ((msg_len + 1) > offset ){
			offset++;
			offset = dissect_uma_IE(tvb, pinfo, uma_tree, offset);
		}
		break;
	case 2:	/* URLC */
		offset++;
		octet = tvb_get_guint8(tvb,offset);
		proto_tree_add_item(uma_tree, hf_uma_urlc_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		col_add_str(pinfo->cinfo, COL_INFO, val_to_str_ext(octet, &uma_urlc_msg_type_vals_ext, "Unknown URLC (%u)"));
		col_set_fence(pinfo->cinfo,COL_INFO);
		offset++;
		proto_tree_add_item(uma_tree, hf_uma_urlc_TLLI, tvb, offset, 4, ENC_NA);
		offset = offset + 3;
		while ((msg_len + 1) > offset ){
			offset++;
			offset = dissect_uma_IE(tvb, pinfo, uma_tree, offset);
		}
		break;
	default:
		proto_tree_add_text(uma_tree, tvb,offset,-1,"Unknown protocol %u",pd);
		break;
	}
}

static guint
get_uma_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	/* PDU length = Message length + length of length indicator */
	return tvb_get_ntohs(tvb,offset)+2;
}

static void
dissect_uma_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tcp_dissect_pdus(tvb, pinfo, tree, uma_desegment, UMA_HEADER_SIZE,
	    get_uma_pdu_len, dissect_uma);
}

static int
dissect_uma_urlc_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	int		offset = 0;
	guint8	octet;
	guint16 msg_len;

/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *uma_tree;

/* Make entries in Protocol column and Info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "UMA");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_uma, tvb, 0, -1, FALSE);
	uma_tree = proto_item_add_subtree(ti, ett_uma);

	octet = tvb_get_guint8(tvb,offset);
	proto_tree_add_item(uma_tree, hf_uma_urlc_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s ",val_to_str_ext(octet, &uma_urlc_msg_type_vals_ext, "Unknown URLC (%u)"));
	col_set_fence(pinfo->cinfo,COL_INFO);
	msg_len = tvb_length_remaining(tvb,offset) - 1;

	switch  ( octet ){

	case 2:	/* RLC UNITDATA */
	case 6: /* URLC-UFC-REQ */
	case 7: /* URLC-DFC-REQ only allowed message types*/
		offset++;
		proto_tree_add_item(uma_tree, hf_uma_urlc_TLLI, tvb, offset, 4, ENC_NA);
		offset = offset + 4;
		proto_tree_add_item(uma_tree, hf_uma_urlc_seq_nr, tvb, offset, 2, ENC_NA);
		offset++;
		while (msg_len > offset){
			offset++;
			offset = dissect_uma_IE(tvb, pinfo, uma_tree, offset);
		}
		return offset;
	default:
		proto_tree_add_text(uma_tree, tvb,offset,-1,"Wrong message type %u",octet);
		return tvb_length(tvb);

	}

}

static void
range_delete_callback(guint32 port)
{
    dissector_delete_uint("tcp.port", port, uma_tcp_handle);
}

static void
range_add_callback(guint32 port)
{
    dissector_add_uint("tcp.port", port, uma_tcp_handle);
}

/* Register the protocol with Wireshark */
/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_uma(void)
{
	static gboolean Initialized=FALSE;
	static range_t *uma_tcp_port_range;

	if (!Initialized) {
		uma_tcp_handle = find_dissector("umatcp");
		uma_udp_handle = find_dissector("umaudp");
		dissector_add_handle("udp.port", uma_udp_handle);  /* for "decode-as" */
		data_handle = find_dissector("data");
		rtp_handle = find_dissector("rtp");
		rtcp_handle = find_dissector("rtcp");
		llc_handle = find_dissector("llcgprs");
		bssap_pdu_type_table = find_dissector_table("bssap.pdu_type");
		Initialized=TRUE;
	} else {
		range_foreach(uma_tcp_port_range, range_delete_callback);
		g_free(uma_tcp_port_range);
	}

	uma_tcp_port_range = range_copy(global_uma_tcp_port_range);
	range_foreach(uma_tcp_port_range, range_add_callback);
}

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_uma(void)
{

	module_t *uma_module;

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_uma_length_indicator,
			{ "Length Indicator","uma.li",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_pd,
			{ "Protocol Discriminator","uma.pd",
			FT_UINT8, BASE_DEC, VALS(uma_pd_vals), 0x0f,
			NULL, HFILL }
		},
		{ &hf_uma_skip_ind,
			{ "Skip Indicator",           "uma.skip.ind",
			FT_UINT8, BASE_DEC, NULL, 0xf0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_msg_type,
			{ "URR Message Type", "uma.urr.msg.type",
			FT_UINT16, BASE_DEC|BASE_EXT_STRING, &uma_urr_msg_type_vals_ext, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urlc_msg_type,
			{ "URLC Message Type", "uma.urlc.msg.type",
			FT_UINT8, BASE_DEC|BASE_EXT_STRING, &uma_urlc_msg_type_vals_ext, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urlc_TLLI,
			{ "Temporary Logical Link Identifier","uma.urlc.tlli",
			FT_BYTES,BASE_NONE,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urlc_seq_nr,
			{ "Sequence Number","uma.urlc.seq.nr",
			FT_BYTES,BASE_NONE,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_IE,
			{ "URR Information Element","uma.urr.ie.type",
			FT_UINT8, BASE_DEC|BASE_EXT_STRING, &uma_urr_IE_type_vals_ext, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_IE_len,
			{ "URR Information Element length","uma.urr.ie.len",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_mobile_identity_type,
			{ "Mobile Identity Type","uma.urr.ie.mobileid.type",
			FT_UINT8, BASE_DEC, VALS(uma_urr_mobile_identity_type_vals), 0x07,
			NULL, HFILL }
		},
		{ &hf_uma_urr_odde_even_ind,
			{ "Odd/even indication","uma.urr.oddevenind",
			FT_UINT8, BASE_DEC, uma_urr_oddevenind_vals, 0x08,
			"Mobile Identity", HFILL }
		},
		{ &hf_uma_urr_imsi,
			{ "IMSI", "uma_urr.imsi",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_imei,
			{ "IMEI", "uma_urr.imei",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_imeisv,
			{ "IMEISV", "uma_urr.imeisv",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_tmsi_p_tmsi,
			{ "TMSI/P-TMSI", "uma_urr.tmsi_p_tmsi",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_uri,
			{ "GAN Release Indicator","uma.urr.uri",
			FT_UINT8, BASE_DEC, VALS(uma_urr_gan_rel_ind_vals), 0x07,
			"URI", HFILL }
		},
		{ &hf_uma_urr_radio_type_of_id,
			{ "Type of identity","uma.urr.radio_type_of_id",
			FT_UINT8, BASE_DEC, VALS(radio_type_of_id_vals), 0x0f,
			NULL, HFILL }
		},
		{ &hf_uma_urr_radio_id,
			{ "Radio Identity","uma.urr.radio_id",
			FT_ETHER, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},

		{ &hf_uma_urr_cell_id,
			{ "Cell Identity","uma.urr.cell_id",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			NULL, HFILL }
		},

		{ &hf_uma_urr_mcc,
			{ "Mobile Country Code","uma.urr.mcc",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_mnc,
			{ "Mobile network code","uma.urr.mnc",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_lac,
			{ "Location area code","uma.urr.lac",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_gci,
			{ "GCI, GSM Coverage Indicator","uma.urr.gci",
			FT_UINT8, BASE_DEC,  VALS(uma_gci_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_tura,
			{ "TURA, Type of Unlicensed Radio","uma.urr.tura",
			FT_UINT8,BASE_DEC,  VALS(uma_tura_vals), 0xf,
			NULL, HFILL }
		},
		{ &hf_uma_urr_gc,
			{ "GC, GERAN Capable","uma.urr.gc",
			FT_UINT8,BASE_DEC,  VALS(uma_gc_vals), 0x10,
			NULL, HFILL }
		},
		{ &hf_uma_urr_uc,
			{ "UC, UTRAN Capable","uma.urr.uc",
			FT_UINT8,BASE_DEC,  VALS(uma_uc_vals), 0x20,
			"GC, GERAN Capable", HFILL }
		},
		{ &hf_uma_urr_rrs,
			{ "RTP Redundancy Support(RRS)","uma.urr.rrs",
			FT_UINT8,BASE_DEC, VALS(uma_rrs_vals), 0x01,
			NULL, HFILL }
		},
		{ &hf_uma_urr_gmsi,
			{ "GMSI, GAN Mode Support Indicator)","uma.urr.gmsi",
			FT_UINT8,BASE_DEC, VALS(uma_gmsi_vals), 0x06,
			"GMSI, GAN Mode Support Indicator", HFILL }
		},
		{ &hf_uma_urr_psho,
			{ "PS HO, PS Handover Capable","uma.urr.psho",
			FT_UINT8,BASE_DEC, VALS(uma_ps_ho_vals), 0x02,
			NULL, HFILL }
		},
		{ &hf_uma_urr_IP_Address_type,
			{ "IP address type number value","uma.urr.ip_type",
			FT_UINT8,BASE_DEC,  VALS(IP_address_type_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_FQDN,
		       { "Fully Qualified Domain/Host Name (FQDN)", "uma.urr.fqdn",
		       FT_STRING, BASE_NONE,NULL,0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_sgw_ipv4,
			{ "SGW IPv4 address","uma.urr.sgwipv4",
			FT_IPv4,BASE_NONE,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_redirection_counter,
			{ "Redirection Counter","uma.urr.redirection_counter",
			FT_UINT8,BASE_DEC,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_dis_rej_cau,
			{ "Discovery Reject Cause","uma.urr.is_rej_cau",
			FT_UINT8,BASE_DEC,  VALS(uma_discovery_reject_cause_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_ECMC,
			{ "ECMC, Early Classmark Sending Control","uma.urr.is_rej_cau",
			FT_UINT8,BASE_DEC,  VALS(ECMC_vals), 0x2,
			NULL, HFILL }
		},
		{ &hf_uma_urr_NMO,
			{ "NMO, Network Mode of Operation","uma.urr.NMO",
			FT_UINT8,BASE_DEC,  VALS(NMO_vals), 0xc,
			NULL, HFILL }
		},
		{ &hf_uma_urr_GPRS,
			{ "GPRS, GPRS Availability","uma.urr.is_rej_cau",
			FT_UINT8,BASE_DEC,  VALS(GPRS_avail_vals), 0x10,
			NULL, HFILL }
		},
		{ &hf_uma_urr_DTM,
			{ "DTM, Dual Transfer Mode of Operation by network","uma.urr.dtm",
			FT_UINT8,BASE_DEC,  VALS(DTM_vals), 0x20,
			NULL, HFILL }
		},
		{ &hf_uma_urr_ATT,
			{ "ATT, Attach-detach allowed","uma.urr.att",
			FT_UINT8,BASE_DEC,  VALS(ATT_vals), 0x40,
			NULL, HFILL }
		},
		{ &hf_uma_urr_MSCR,
			{ "MSCR, MSC Release","uma.urr.mscr",
			FT_UINT8,BASE_DEC,  VALS(MSCR_vals), 0x80,
			NULL, HFILL }
		},
		{ &hf_uma_urr_T3212_timer,
			{ "T3212 Timer value(seconds)","uma.urr.t3212",
			FT_UINT8,BASE_DEC,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_RAC,
			{ "Routing Area Code","uma.urr.rac",
			FT_UINT8,BASE_DEC,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_ap_location,
			{ "AP Location","uma.urr.ap_location",
			FT_BYTES,BASE_NONE,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_SGSNR,
			{ "SGSN Release","uma.urr.SGSNR",
			FT_UINT8,BASE_DEC,  VALS(SGSNR_vals), 0x01,
			NULL, HFILL }
		},
		{ &hf_uma_urr_ECMP,
			{ "ECMP, Emergency Call Mode Preference","uma.urr.ECMP",
			FT_UINT8,BASE_DEC,  VALS(ECMP_vals), 0x02,
			NULL, HFILL }
		},
		{ &hf_uma_urr_RE,
			{ "RE, Call reestablishment allowed","uma.urr.RE",
			FT_UINT8,BASE_DEC,  VALS(RE_vals), 0x04,
			NULL, HFILL }
		},
		{ &hf_uma_urr_PFCFM,
			{ "PFCFM, PFC_FEATURE_MODE","uma.urr.PFCFM",
			FT_UINT8,BASE_DEC,  VALS(PFCFM_vals), 0x08,
			NULL, HFILL }
		},
		{ &hf_uma_urr_3GECS,
			{ "3GECS, 3G Early Classmark Sending Restriction","uma.urr.3GECS",
			FT_UINT8,BASE_DEC,  VALS(Three_GECS_vals), 0x10,
			NULL, HFILL }
		},
		{ &hf_uma_urr_bcc,
			{ "BCC","uma.urr.bcc",
			FT_UINT8,BASE_DEC,  NULL, 0x07,
			NULL, HFILL }
		},
		{ &hf_uma_urr_ncc,
			{ "NCC","uma.urr.ncc",
			FT_UINT8,BASE_DEC,  NULL, 0x38,
			NULL, HFILL }
		},
		{ &hf_uma_urr_TU3907_timer,
			{ "TU3907 Timer value(seconds)","uma.urr.tu3907",
			FT_UINT16,BASE_DEC,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_GSM_RR_state,
			{ "GSM RR State value","uma.urr.gsmrrstate",
			FT_UINT8,BASE_DEC|BASE_EXT_STRING,  &uma_GRS_GSM_RR_State_vals_ext, 0x7,
			NULL, HFILL }
		},
		{ &hf_uma_urr_gan_band,
			{ "UMA Band","uma.urr.umaband",
			FT_UINT8,BASE_DEC|BASE_EXT_STRING,  &uma_gan_band_vals_ext, 0x0f,
			NULL, HFILL }
		},
		{ &hf_uma_urr_URR_state,
			{ "URR State","uma.urr.state",
			FT_UINT8,BASE_DEC,  VALS(URR_state_vals), 0x03,
			NULL, HFILL }
		},
		{ &hf_uma_urr_register_reject_cause,
			{ "Register Reject Cause","uma.urr.state",
			FT_UINT8,BASE_DEC|BASE_EXT_STRING,  &register_reject_cause_vals_ext, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_TU3906_timer,
			{ "TU3907 Timer value(seconds)","uma.urr.tu3906",
			FT_UINT16,BASE_DEC,  NULL, 0x0,
			"TU3906 Timer value(seconds)", HFILL }
		},
		{ &hf_uma_urr_TU3910_timer,
			{ "TU3907 Timer value(seconds)","uma.urr.tu3910",
			FT_UINT16,BASE_DEC,  NULL, 0x0,
			"TU3910 Timer value(seconds)", HFILL }
		},
		{ &hf_uma_urr_TU3902_timer,
			{ "TU3902 Timer value(seconds)","uma.urr.tu3902",
			FT_UINT16,BASE_DEC,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_communication_port,
			{ "Communication Port","uma.urr.communication_port",
			FT_UINT16,BASE_DEC,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_L3_Message,
			{ "L3 message contents","uma.urr.l3",
			FT_BYTES,BASE_NONE,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_L3_protocol_discriminator,
			{ "Protocol discriminator","uma.urr.L3_protocol_discriminator",
			FT_UINT8,BASE_DEC,  VALS(protocol_discriminator_vals), 0x0f,
			NULL, HFILL }
		},
		{ &hf_uma_urr_sc,
			{ "SC","uma.urr.SC",
			FT_UINT8,BASE_DEC,  VALS(SC_vals), 0x1,
			NULL, HFILL }
		},
		{ &hf_uma_urr_algorithm_id,
			{ "Algorithm identifier","uma.urr.algorithm_identifier",
			FT_UINT8,BASE_DEC|BASE_EXT_STRING,  &algorithm_identifier_vals_ext, 0xe,
			"Algorithm_identifier", HFILL }
		},
		{ &hf_uma_urr_GPRS_resumption,
			{ "GPRS resumption ACK","uma.urr.GPRS_resumption",
			FT_UINT8,BASE_DEC,  VALS(GPRS_resumption_vals), 0x1,
			NULL, HFILL }
		},
		{ &hf_uma_urr_ULQI,
			{ "ULQI, UL Quality Indication","uma.urr.ULQI",
			FT_UINT8,BASE_DEC,  VALS(uma_ulqi_vals), 0x0f,
			NULL, HFILL }
		},
		{ &hf_uma_urr_TU3920_timer,
			{ "TU3920 Timer value(seconds)","uma.urr.tu3920",
			FT_UINT16,BASE_DEC,  NULL, 0x0,
			"TU3920 Timer value(hundreds of of ms)", HFILL }
		},
		{ &hf_uma_urr_peak_tpt_cls,
			{ "PEAK_THROUGHPUT_CLASS","uma.urr.peak_tpt_cls",
			FT_UINT8,BASE_DEC,  NULL, 0x0f,
			NULL, HFILL }
		},
		{ &hf_uma_urr_radio_pri,
			{ "Radio Priority","uma.urr.radio_pri",
			FT_UINT8,BASE_DEC,  VALS(radio_pri_vals), 0x30,
			"RADIO_PRIORITY", HFILL }
		},
		{ &hf_uma_urr_rlc_mode,
			{ "RLC mode","uma.urr.rrlc_mode",
			FT_UINT8,BASE_DEC,  VALS(rlc_mode_vals), 0x80,
			NULL, HFILL }
		},
		{ &hf_uma_urr_ga_psr_cause,
			{ "GA-PSR Cause","uma.urr.ga_psr_cause",
			FT_UINT8,BASE_DEC|BASE_EXT_STRING,  &uma_ga_psr_cause_vals_ext, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_udr,
			{ "User Data Rate value (bits/s)","uma.urr.URLCcause",
			FT_UINT32,BASE_DEC,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_TU4001_timer,
			{ "TU4001 Timer value(seconds)","uma.urr.tu4001",
			FT_UINT16,BASE_DEC,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_LS,
			{ "Location Status(LS)","uma.urr.LS",
			FT_UINT8,BASE_DEC,  VALS(LS_vals), 0x3,
			NULL, HFILL }
		},
		{ &hf_uma_urr_cipher_res,
			{ "Cipher Response(CR)","uma.urr.CR",
			FT_UINT8,BASE_DEC,  VALS(CR_vals), 0x3,
			NULL, HFILL }
		},
		{ &hf_uma_urr_rand_val,
			{ "Ciphering Command RAND value","uma.rand_val",
			FT_BYTES,BASE_NONE,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_ciphering_command_mac,
			{ "Ciphering Command MAC (Message Authentication Code)","uma.ciphering_command_mac",
			FT_BYTES,BASE_NONE,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_ciphering_key_seq_num,
			{ "Values for the ciphering key","uma.ciphering_key_seq_num",
			FT_UINT8,BASE_DEC,  NULL, 0x7,
			NULL, HFILL }
		},
		{ &hf_uma_urr_sapi_id,
			{ "SAPI ID","uma.sapi_id",
			FT_UINT8,BASE_DEC,  VALS(sapi_id_vals), 0x7,
			NULL, HFILL }
		},
		{ &hf_uma_urr_establishment_cause,
			{ "Establishment Cause","uma.urr.establishment_cause",
			FT_UINT8,BASE_DEC|BASE_EXT_STRING,  &uma_establishment_cause_val_ext, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_channel,
			{ "Channel","uma.urr.establishment_cause",
			FT_UINT8,BASE_DEC,  VALS(channel_vals), 0x3,
			NULL, HFILL }
		},
		{ &hf_uma_urr_PDU_in_error,
			{ "PDU in Error,","uma.urr.PDU_in_error",
			FT_BYTES,BASE_NONE,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_sample_size,
			{ "Sample Size","uma.urr.sample_size",
			FT_UINT8,BASE_DEC,  VALS(sample_size_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_payload_type,
			{ "Payload Type","uma.urr.sample_size",
			FT_UINT8,BASE_DEC,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_LLC_PDU,
			{ "LLC-PDU","uma.urr.llc_pdu",
			FT_BYTES,BASE_NONE,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_LBLI,
			{ "LBLI, Location Black List indicator","uma.urr.LBLI",
			FT_UINT8,BASE_DEC,  VALS(LBLI_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_RI,
			{ "Reset Indicator(RI)","uma.urr.RI",
			FT_UINT8,BASE_DEC,  VALS(RI_vals), 0x1,
			NULL, HFILL }
		},
		{ &hf_uma_urr_TU4003_timer,
			{ "TU4003 Timer value(seconds)","uma.urr.tu4003",
			FT_UINT16,BASE_DEC,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_ap_service_name_type,
			{ "AP Service Name type","uma.urr.ap_service_name_type",
			FT_UINT8,BASE_DEC,  VALS(ap_service_name_type_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_ap_Service_name_value,
			{ "AP Service Name Value","uma.urr.ap_service_name_value",
			FT_STRING,BASE_NONE,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_uma_service_zone_icon_ind,
			{ "UMA Service Zone Icon Indicator","uma.urr.uma_service_zone_icon_ind",
			FT_UINT8,BASE_DEC,  VALS(uma_service_zone_icon_ind_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_uma_service_zone_str_len,
			{ "Length of UMA Service Zone string","uma.urr.service_zone_str_len",
			FT_UINT8,BASE_DEC,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_window_size,
			{ "Window Size","uma.urr.uma_window_size",
			FT_UINT8,BASE_DEC,  VALS(window_size_vals), 0x03,
			NULL, HFILL }
		},
		{ &hf_uma_urr_uma_codec_mode,
			{ "GAN A/Gb Mode Codec Mode","uma.urr.uma_codec_mode",
			FT_UINT8,BASE_DEC,  NULL, 0xc0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_UTRAN_cell_id_disc,
			{ "UTRAN Cell Identification Discriminator","uma.urr.uma_UTRAN_cell_id_disc",
			FT_UINT8,BASE_DEC,  VALS(UTRAN_cell_id_disc_vals), 0x0f,
			NULL, HFILL }
		},
		{ &hf_uma_urr_suti,
			{ "SUTI, Serving GANC table indicator","uma.urr.uma_suti",
			FT_UINT8,BASE_DEC,  VALS(suti_vals), 0x01,
			NULL, HFILL }
		},
		{ &hf_uma_urr_uma_mps,
			{ "UMPS, Manual PLMN Selection indicator","uma.urr.mps",
			FT_UINT8,BASE_DEC,  VALS(mps_vals), 0x3,
			"MPS, Manual PLMN Selection indicator", HFILL }
		},
		{ &hf_uma_urr_num_of_plms,
			{ "Number of PLMN:s","uma.urr.num_of_plms",
			FT_UINT8,BASE_DEC,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_cbs,
			{ "CBS Cell Broadcast Service","uma.urr.cbs",
			FT_UINT8,BASE_DEC,  VALS(cbs_vals), 0x01,
			NULL, HFILL }
		},
		{ &hf_uma_urr_num_of_cbs_frms,
			{ "Number of CBS Frames","uma.urr.num_of_cbs_frms",
			FT_UINT8,BASE_DEC,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_ms_radio_id,
			{ "MS Radio Identity","uma.urr.ms_radio_id",
			FT_ETHER, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_uma_urr_uma_service_zone_str,
			{ "UMA Service Zone string,","uma.urr.uma_service_zone_str",
			FT_STRING,BASE_NONE,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_unc_ipv4,
			{ "UNC IPv4 address","uma.urr.uncipv4",
			FT_IPv4,BASE_NONE,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_unc_FQDN,
		       { "UNC Fully Qualified Domain/Host Name (FQDN)", "uma.urr.unc_fqdn",
		       FT_STRING, BASE_NONE,NULL,0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_GPRS_user_data_transport_ipv4,
			{ "IP address for GPRS user data transport","uma.urr.gprs_usr_data_ipv4",
			FT_IPv4,BASE_NONE,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_GPRS_port,
			{ "UDP Port for GPRS user data transport","uma.urr.gprs_port",
			FT_UINT16,BASE_DEC,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_UNC_tcp_port,
			{ "UNC TCP port","uma.urr.gprs_port",
			FT_UINT16,BASE_DEC,  NULL, 0x0,
			"UDP Port for GPRS user data transport", HFILL }
		},
		{ &hf_uma_urr_RTP_port,
			{ "RTP UDP port","uma.urr.rtp_port",
			FT_UINT16,BASE_DEC,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_RTCP_port,
			{ "RTCP UDP port","uma.urr.rtcp_port",
			FT_UINT16,BASE_DEC,  NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_uma_urr_RXLEV_NCELL,
			{ "RX Level","uma.urr.rxlevel",
			FT_UINT8,BASE_DEC,  NULL, 0x0,
			NULL, HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_uma,
		&ett_uma_toc,
		&ett_urr_ie,
	};

/* Register the protocol name and description */
	proto_uma = proto_register_protocol("Unlicensed Mobile Access","UMA", "uma");
	/* subdissector code */
	register_dissector("umatcp", dissect_uma_tcp, proto_uma);
        new_register_dissector("umaudp", dissect_uma_urlc_udp, proto_uma);

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_uma, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register a configuration option for port */
	uma_module = prefs_register_protocol(proto_uma, proto_reg_handoff_uma);

	/* Set default TCP ports */
	range_convert_str(&global_uma_tcp_port_range, DEFAULT_UMA_PORT_RANGE, MAX_UDP_PORT);

	prefs_register_bool_preference(uma_module, "desegment_ucp_messages",
		"Reassemble UMA messages spanning multiple TCP segments",
		"Whether the UMA dissector should reassemble messages spanning multiple TCP segments."
		" To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
		&uma_desegment);
	prefs_register_obsolete_preference(uma_module, "tcp.port1");
	prefs_register_obsolete_preference(uma_module, "udp.ports");
	prefs_register_range_preference(uma_module, "tcp.ports", "UMA TCP ports",
				  "TCP ports to be decoded as UMA (default: "
				  DEFAULT_UMA_PORT_RANGE ")",
				  &global_uma_tcp_port_range, MAX_UDP_PORT);

}
