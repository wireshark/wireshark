/* packet-wsp.c (c) 2000 Neil Hunter
 * Based on original work by Ben Fowler
 * Updated by Alexandre P. Ferreira (Splice IP)
 *
 * Routines to dissect WSP component of WAP traffic.
 * 
 * $Id: packet-wsp.c,v 1.16 2001/02/01 19:59:40 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Didier Jorand
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "packet-wap.h"
#include "packet-wsp.h"

/* File scoped variables for the protocol and registered fields */
static int proto_wsp 							= HF_EMPTY;
static int proto_wtls 						= HF_EMPTY;

/* These fields used by fixed part of header */
static int hf_wsp_header_tid					= HF_EMPTY;
static int hf_wsp_header_pdu_type				= HF_EMPTY;
static int hf_wsp_version_major					= HF_EMPTY;
static int hf_wsp_version_minor					= HF_EMPTY;
static int hf_wsp_capability_length				= HF_EMPTY;
static int hf_wsp_capabilities_section			= HF_EMPTY;
static int hf_wsp_header_uri_len				= HF_EMPTY;
static int hf_wsp_header_uri					= HF_EMPTY;
static int hf_wsp_server_session_id				= HF_EMPTY;
static int hf_wsp_header_status					= HF_EMPTY;
static int hf_wsp_header_length					= HF_EMPTY;
static int hf_wsp_headers_section				= HF_EMPTY;
static int hf_wsp_header						= HF_EMPTY;
static int hf_wsp_content_type					= HF_EMPTY;
static int hf_wsp_parameter_well_known_charset	= HF_EMPTY;
static int hf_wsp_reply_data					= HF_EMPTY;
static int hf_wsp_post_data						= HF_EMPTY;

static int hf_wsp_header_accept					= HF_EMPTY;
static int hf_wsp_header_accept_str				= HF_EMPTY;
static int hf_wsp_header_accept_charset			= HF_EMPTY;
static int hf_wsp_header_accept_charset_str			= HF_EMPTY;
static int hf_wsp_header_accept_language		= HF_EMPTY;
static int hf_wsp_header_accept_language_str		= HF_EMPTY;
static int hf_wsp_header_accept_ranges			= HF_EMPTY;
static int hf_wsp_header_cache_control			= HF_EMPTY;
static int hf_wsp_header_content_length			= HF_EMPTY;
static int hf_wsp_header_age					= HF_EMPTY;
static int hf_wsp_header_date					= HF_EMPTY;
static int hf_wsp_header_etag					= HF_EMPTY;
static int hf_wsp_header_expires				= HF_EMPTY;
static int hf_wsp_header_last_modified			= HF_EMPTY;
static int hf_wsp_header_location				= HF_EMPTY;
static int hf_wsp_header_if_modified_since		= HF_EMPTY;
static int hf_wsp_header_server					= HF_EMPTY;
static int hf_wsp_header_user_agent				= HF_EMPTY;
static int hf_wsp_header_application_header		= HF_EMPTY;
static int hf_wsp_header_application_value		= HF_EMPTY;
static int hf_wsp_header_x_wap_tod				= HF_EMPTY;
static int hf_wsp_header_transfer_encoding            = HF_EMPTY;
static int hf_wsp_header_transfer_encoding_str                = HF_EMPTY;
static int hf_wsp_header_via                          = HF_EMPTY;

static int hf_wtls_record                             = HF_EMPTY;
static int hf_wtls_record_type                                = HF_EMPTY;
static int hf_wtls_record_length                      = HF_EMPTY;
static int hf_wtls_record_sequence                    = HF_EMPTY;
static int hf_wtls_record_ciphered                    = HF_EMPTY;
static int hf_wtls_hands                              = HF_EMPTY;
static int hf_wtls_hands_type                 = HF_EMPTY;
static int hf_wtls_hands_length                       = HF_EMPTY;
static int hf_wtls_hands_cli_hello            = HF_EMPTY;
static int hf_wtls_hands_cli_hello_version    = HF_EMPTY;
static int hf_wtls_hands_cli_hello_gmt                = HF_EMPTY;
static int hf_wtls_hands_cli_hello_random     = HF_EMPTY;
static int hf_wtls_hands_cli_hello_session    = HF_EMPTY;
static int hf_wtls_hands_cli_hello_cli_key_id    = HF_EMPTY;
static int hf_wtls_hands_cli_hello_trust_key_id    = HF_EMPTY; 
static int hf_wtls_hands_cli_hello_key_exchange               =HF_EMPTY;
static int hf_wtls_hands_cli_hello_key_exchange_suite         =HF_EMPTY;
static int hf_wtls_hands_cli_hello_key_parameter_index                =HF_EMPTY;
static int hf_wtls_hands_cli_hello_key_parameter_set          =HF_EMPTY;
static int hf_wtls_hands_cli_hello_key_identifier_type                =HF_EMPTY;
static int hf_wtls_hands_cli_hello_cipher_suite               =HF_EMPTY;
static int hf_wtls_hands_cli_hello_cipher_suite_item  =HF_EMPTY;
static int hf_wtls_hands_cli_hello_cipher_bulk                =HF_EMPTY;
static int hf_wtls_hands_cli_hello_cipher_mac         =HF_EMPTY;
static int hf_wtls_hands_cli_hello_compression_methods                =HF_EMPTY;
static int hf_wtls_hands_cli_hello_compression                =HF_EMPTY;
static int hf_wtls_hands_cli_hello_sequence_mode      =HF_EMPTY;
static int hf_wtls_hands_cli_hello_key_refresh        =HF_EMPTY;
static int hf_wtls_hands_serv_hello           = HF_EMPTY;
static int hf_wtls_hands_serv_hello_version   = HF_EMPTY;
static int hf_wtls_hands_serv_hello_gmt               = HF_EMPTY;
static int hf_wtls_hands_serv_hello_random    = HF_EMPTY;
static int hf_wtls_hands_serv_hello_session   = HF_EMPTY;
static int hf_wtls_hands_serv_hello_cli_key_id                =HF_EMPTY;
static int hf_wtls_hands_serv_hello_cipher_suite_item =HF_EMPTY;
static int hf_wtls_hands_serv_hello_cipher_bulk               =HF_EMPTY;
static int hf_wtls_hands_serv_hello_cipher_mac                =HF_EMPTY;
static int hf_wtls_hands_serv_hello_compression               =HF_EMPTY;
static int hf_wtls_hands_serv_hello_sequence_mode     =HF_EMPTY;
static int hf_wtls_hands_serv_hello_key_refresh       =HF_EMPTY;
static int hf_wtls_hands_certificates =HF_EMPTY;
static int hf_wtls_hands_certificate 	=HF_EMPTY;
static int hf_wtls_hands_certificate_type     =HF_EMPTY;
static int hf_wtls_hands_certificate_wtls_version     =HF_EMPTY;
static int hf_wtls_hands_certificate_wtls_signature_type      =HF_EMPTY;
static int hf_wtls_hands_certificate_wtls_issuer_type =HF_EMPTY;
static int hf_wtls_hands_certificate_wtls_issuer_charset      =HF_EMPTY;
static int hf_wtls_hands_certificate_wtls_issuer_name =HF_EMPTY;
static int hf_wtls_hands_certificate_wtls_valid_not_before    =HF_EMPTY;
static int hf_wtls_hands_certificate_wtls_valid_not_after     =HF_EMPTY;
static int hf_wtls_hands_certificate_wtls_subject_type        =HF_EMPTY;
static int hf_wtls_hands_certificate_wtls_subject_charset     =HF_EMPTY;
static int hf_wtls_hands_certificate_wtls_subject_name        = HF_EMPTY;
static int hf_wtls_hands_certificate_wtls_public_key_type = HF_EMPTY;
static int hf_wtls_hands_certificate_wtls_key_parameter_index = HF_EMPTY;
static int hf_wtls_hands_certificate_wtls_key_parameter_set = HF_EMPTY;
static int hf_wtls_hands_certificate_wtls_rsa_exponent = HF_EMPTY;
static int hf_wtls_hands_certificate_wtls_rsa_modules = HF_EMPTY;
static int hf_wtls_hands_certificate_wtls_signature = HF_EMPTY;
static int hf_wtls_alert = HF_EMPTY;
static int hf_wtls_alert_level = HF_EMPTY;
static int hf_wtls_alert_description = HF_EMPTY;

/* Initialize the subtree pointers */
static gint ett_wsp 							= ETT_EMPTY;
static gint ett_header 							= ETT_EMPTY;
static gint ett_headers							= ETT_EMPTY;
static gint ett_capabilities					= ETT_EMPTY;
static gint ett_content_type					= ETT_EMPTY;
static gint ett_wtls_rec                              = ETT_EMPTY;
static gint ett_wtls_msg_type                                 = ETT_EMPTY;
static gint ett_wtls_msg_type_item                    = ETT_EMPTY;
static gint ett_wtls_msg_type_item_sub                        = ETT_EMPTY;
static gint ett_wtls_msg_type_item_sub_sub            = ETT_EMPTY;

static const value_string vals_pdu_type[] = {
	{ 0x00, "Reserved" },
	{ 0x01, "Connect" },
	{ 0x02, "ConnectReply" },
	{ 0x03, "Redirect" },
	{ 0x04, "Reply" },
	{ 0x05, "Disconnect" },
	{ 0x06, "Push" },
	{ 0x07, "ConfirmedPush" },
	{ 0x08, "Suspend" },
	{ 0x09, "Resume" },

	/* 0x10 - 0x3F Unassigned */

	{ 0x40, "Get" },
	{ 0x41, "Options" },
	{ 0x42, "Head" },
	{ 0x43, "Delete" },
	{ 0x44, "Trace" },

	/* 0x45 - 0x4F Unassigned (Get PDU) */
	/* 0x50 - 0x5F Extended method (Get PDU) */

	{ 0x60, "Post" },
	{ 0x61, "Put" },

	/* 0x62 - 0x6F Unassigned (Post PDU) */
	/* 0x70 - 0x7F Extended method (Post PDU) */
	/* 0x80 - 0xFF Reserved */

	{ 0x00, NULL }

};

static const value_string vals_status[] = {
	/* 0x00 - 0x0F Reserved */

	{ 0x10, "Continue" },
	{ 0x11, "Switching Protocols" },

	{ 0x20, "OK" },
	{ 0x21, "Created" },
	{ 0x22, "Accepted" },
	{ 0x23, "Non-Authoritative Information" },
	{ 0x24, "No Content" },
	{ 0x25, "Reset Content" },
	{ 0x26, "Partial Content" },

	{ 0x30, "Multiple Choices" },
	{ 0x31, "Moved Permanently" },
	{ 0x32, "Moved Temporarily" },
	{ 0x33, "See Other" },
	{ 0x34, "Not Modified" },
	{ 0x35, "Use Proxy" },

	{ 0x40, "Bad Request" },
	{ 0x41, "Unauthorised" },
	{ 0x42, "Payment Required" },
	{ 0x43, "Forbidden" },
	{ 0x44, "Not Found" },
	{ 0x45, "Method Not Allowed" },
	{ 0x46, "Not Acceptable" },
	{ 0x47, "Proxy Authentication Required" },
	{ 0x48, "Request Timeout" },
	{ 0x49, "Conflict" },
	{ 0x4A, "Gone" },
	{ 0x4B, "Length Required" },
	{ 0x4C, "Precondition Failed" },
	{ 0x4D, "Request Entity Too Large" },
	{ 0x4E, "Request-URI Too Large" },
	{ 0x4F, "Unsupported Media Type" },

	{ 0x60, "Internal Server Error" },
	{ 0x61, "Not Implemented" },
	{ 0x62, "Bad Gateway" },
	{ 0x63, "Service Unavailable" },
	{ 0x64, "Gateway Timeout" },
	{ 0x65, "HTTP Version Not Supported" },
	{ 0x00, NULL }
};

static const value_string vals_content_types[] = {
	{ 0x00, "*/*" },
	{ 0x01, "text/*" },
	{ 0x02, "text/html" },
	{ 0x03, "text/plain" },
	{ 0x04, "text/x-hdml" },
	{ 0x05, "text/x-ttml" },
	{ 0x06, "text/x-vCalendar" },
	{ 0x07, "text/x-vCard" },
	{ 0x08, "text/vnd.wap.wml" },
	{ 0x09, "text/vnd.wap.wmlscript" },
	{ 0x0A, "text/vnd.wap.channel" },
	{ 0x0B, "Multipart/*" },
	{ 0x0C, "Multipart/mixed" },
	{ 0x0D, "Multipart/form-data" },
	{ 0x0E, "Multipart/byteranges" },
	{ 0x0F, "Multipart/alternative" },
	{ 0x10, "application/*" },
	{ 0x11, "application/java-vm" },
	{ 0x12, "application/x-www-form-urlencoded" },
	{ 0x13, "application/x-hdmlc" },
	{ 0x14, "application/vnd.wap.wmlc" },
	{ 0x15, "application/vnd.wap.wmlscriptc" },
	{ 0x16, "application/vnd.wap.channelc" },
	{ 0x17, "application/vnd.wap.uaprof" },
	{ 0x18, "application/vnd.wap.wtls-ca-certificate" },
	{ 0x19, "application/vnd.wap.wtls-user-certificate" },
	{ 0x1A, "application/x-x509-ca-cert" },
	{ 0x1B, "application/x-x509-user-cert" },
	{ 0x1C, "image/*" },
	{ 0x1D, "image/gif" },
	{ 0x1E, "image/jpeg" },
	{ 0x1F, "image/tiff" },
	{ 0x20, "image/png" },
	{ 0x21, "image/vnd.wap.wbmp" },
	{ 0x22, "application/vnd.wap.multipart.*" },
	{ 0x23, "application/vnd.wap.multipart.mixed" },
	{ 0x24, "application/vnd.wap.multipart.form-data" },
	{ 0x25, "application/vnd.wap.multipart.byteranges" },
	{ 0x26, "application/vnd.wap.multipart.alternative" },
	{ 0x27, "application/xml" },
	{ 0x28, "text/xml" },
	{ 0x29, "application/vnd.wap.wbxml" },
	{ 0x2A, "application/x-x968-cross-cert" },
	{ 0x2B, "application/x-x968-ca-cert" },
	{ 0x2C, "application/x-x968-user-cert" },
	{ 0x2D, "text/vnd.wap.si" },
	{ 0x2E, "application/vnd.wap.sic" },
	{ 0x2F, "text/vnd.wap.sl" },
	{ 0x30, "application/vnd.wap.slc" },
	{ 0x31, "text/vnd.wap.co" },
	{ 0x32, "application/vnd.wap.coc" },
	{ 0x33, "application/vnd.wap.multipart.related" },
	{ 0x34, "application/vnd.wap.sia" },
	{ 0x00, NULL }
};

static const value_string vals_character_sets[] = {
	{ 0 ,"hz-gb-2312" },
	{ 3 ,"us-ascii" },
	{ 4 ,"iso-8859-1" },
	{ 5 ,"iso-8859-2" },
	{ 6 ,"iso-8859-3" },
	{ 7 ,"iso-8859-4" },
	{ 8 ,"iso-8859-5" },
	{ 9 ,"iso-8859-6" },
	{ 10 ,"iso-8859-7" },
	{ 11 ,"iso-8859-8" },
	{ 12 ,"iso-8859-9" },
	{ 13 ,"iso-8859-10" },
	{ 14 ,"iso_6937-2-add" },
	{ 15 ,"jis_x0201" },
	{ 16 ,"jis_encoding" },
	{ 17 ,"shift_jis" },
	{ 18 ,"euc-jp" },
	{ 19 ,"extended_unix_code_fixed_width_for_japanese" },
	{ 20 ,"bs_4730" },
	{ 21 ,"sen_850200_c" },
	{ 22 ,"it" },
	{ 23 ,"es" },
	{ 24 ,"din_66003" },
	{ 25 ,"ns_4551-1" },
	{ 26 ,"nf_z_62-010" },
	{ 27 ,"iso-10646-utf-1" },
	{ 28 ,"iso_646.basic:1983" },
	{ 29 ,"invariant" },
	{ 30 ,"iso_646.irv:1983" },
	{ 31 ,"nats-sefi" },
	{ 32 ,"nats-sefi-add" },
	{ 33 ,"nats-dano" },
	{ 34 ,"nats-dano-add" },
	{ 35 ,"sen_850200_b" },
	{ 36 ,"ks_c_5601-1987" },
	{ 37 ,"iso-2022-kr" },
	{ 38 ,"euc-kr" },
	{ 39 ,"iso-2022-jp" },
	{ 40 ,"iso-2022-jp-2" },
	{ 41 ,"jis_c6220-1969-jp" },
	{ 42 ,"jis_c6220-1969-ro" },
	{ 43 ,"pt" },
	{ 44 ,"greek7-old" },
	{ 45 ,"latin-greek" },
	{ 46 ,"nf_z_62-010_(1973)" },
	{ 47 ,"latin-greek-1" },
	{ 48 ,"iso_5427" },
	{ 49 ,"jis_c6226-1978" },
	{ 50 ,"bs_viewdata" },
	{ 51 ,"inis" },
	{ 52 ,"inis-8" },
	{ 53 ,"inis-cyrillic" },
	{ 54 ,"iso_5427:1981" },
	{ 55 ,"iso_5428:1980" },
	{ 56 ,"gb_1988-80" },
	{ 57 ,"gb_2312-80" },
	{ 58 ,"ns_4551-2" },
	{ 59 ,"videotex-suppl" },
	{ 60 ,"pt2" },
	{ 61 ,"es2" },
	{ 62 ,"msz_7795.3" },
	{ 63 ,"jis_c6226-1983" },
	{ 64 ,"greek7" },
	{ 65 ,"asmo_449" },
	{ 66 ,"iso-ir-90" },
	{ 67 ,"jis_c6229-1984-a" },
	{ 68 ,"jis_c6229-1984-b" },
	{ 69 ,"jis_c6229-1984-b-add" },
	{ 70 ,"jis_c6229-1984-hand" },
	{ 71 ,"jis_c6229-1984-hand-add" },
	{ 72 ,"jis_c6229-1984-kana" },
	{ 73 ,"iso_2033-1983" },
	{ 74 ,"ansi_x3.110-1983" },
	{ 75 ,"t.61-7bit" },
	{ 76 ,"t.61-8bit" },
	{ 77 ,"ecma-cyrillic" },
	{ 78 ,"csa_z243.4-1985-1" },
	{ 79 ,"csa_z243.4-1985-2" },
	{ 80 ,"csa_z243.4-1985-gr" },
	{ 81 ,"iso_8859-6-e" },
	{ 82 ,"iso_8859-6-i" },
	{ 83 ,"t.101-g2" },
	{ 84 ,"iso_8859-8-e" },
	{ 85 ,"iso_8859-8-i" },
	{ 86 ,"csn_369103" },
	{ 87 ,"jus_i.b1.002" },
	{ 88 ,"iec_p27-1" },
	{ 89 ,"jus_i.b1.003-serb" },
	{ 90 ,"jus_i.b1.003-mac" },
	{ 91 ,"greek-ccitt" },
	{ 92 ,"nc_nc00-10:81" },
	{ 93 ,"iso_6937-2-25" },
	{ 94 ,"gost_19768-74" },
	{ 95 ,"iso_8859-supp" },
	{ 96 ,"iso_10367-box" },
	{ 97 ,"latin-lap" },
	{ 98 ,"jis_x0212-1990" },
	{ 99 ,"ds_2089" },
	{ 100 ,"us-dk" },
	{ 101 ,"dk-us" },
	{ 102 ,"ksc5636" },
	{ 103 ,"unicode-1-1-utf-7" },
	{ 104 ,"iso-2022-cn" },
	{ 105 ,"iso-2022-cn-ext" },
	{ 106 ,"utf-8" },
	{ 109 ,"iso-8859-13" },
	{ 110 ,"iso-8859-14" },
	{ 111 ,"iso-8859-15" },
	{ 1000 ,"iso-10646-ucs-2" },
	{ 1001 ,"iso-10646-ucs-4" },
	{ 1002 ,"iso-10646-ucs-basic" },
	{ 1003 ,"iso-10646-j-1" },
	{ 1003 ,"iso-10646-unicode-latin1" },
	{ 1005 ,"iso-unicode-ibm-1261" },
	{ 1006 ,"iso-unicode-ibm-1268" },
	{ 1007 ,"iso-unicode-ibm-1276" },
	{ 1008 ,"iso-unicode-ibm-1264" },
	{ 1009 ,"iso-unicode-ibm-1265" },
	{ 1010 ,"unicode-1-1" },
	{ 1011 ,"scsu" },
	{ 1012 ,"utf-7" },
	{ 1013 ,"utf-16be" },
	{ 1014 ,"utf-16le" },
	{ 1015 ,"utf-16" },
	{ 2000 ,"iso-8859-1-windows-3.0-latin-1" },
	{ 2001 ,"iso-8859-1-windows-3.1-latin-1" },
	{ 2002 ,"iso-8859-2-windows-latin-2" },
	{ 2003 ,"iso-8859-9-windows-latin-5" },
	{ 2004 ,"hp-roman8" },
	{ 2005 ,"adobe-standard-encoding" },
	{ 2006 ,"ventura-us" },
	{ 2007 ,"ventura-international" },
	{ 2008 ,"dec-mcs" },
	{ 2009 ,"ibm850" },
	{ 2010 ,"ibm852" },
	{ 2011 ,"ibm437" },
	{ 2012 ,"pc8-danish-norwegian" },
	{ 2013 ,"ibm862" },
	{ 2014 ,"pc8-turkish" },
	{ 2015 ,"ibm-symbols" },
	{ 2016 ,"ibm-thai" },
	{ 2017 ,"hp-legal" },
	{ 2018 ,"hp-pi-font" },
	{ 2019 ,"hp-math8" },
	{ 2020 ,"adobe-symbol-encoding" },
	{ 2021 ,"hp-desktop" },
	{ 2022 ,"ventura-math" },
	{ 2023 ,"microsoft-publishing" },
	{ 2024 ,"windows-31j" },
	{ 2025 ,"gb2312" },
	{ 2026 ,"big5" },
	{ 2027 ,"macintosh" },
	{ 2028 ,"ibm037" },
	{ 2029 ,"ibm038" },
	{ 2030 ,"ibm273" },
	{ 2031 ,"ibm274" },
	{ 2032 ,"ibm275" },
	{ 2033 ,"ibm277" },
	{ 2034 ,"ibm278" },
	{ 2035 ,"ibm280" },
	{ 2036 ,"ibm281" },
	{ 2037 ,"ibm284" },
	{ 2038 ,"ibm285" },
	{ 2039 ,"ibm290" },
	{ 2040 ,"ibm297" },
	{ 2041 ,"ibm420" },
	{ 2042 ,"ibm423" },
	{ 2043 ,"ibm424" },
	{ 2044 ,"ibm500" },
	{ 2045 ,"ibm851" },
	{ 2046 ,"ibm855" },
	{ 2047 ,"ibm857" },
	{ 2048 ,"ibm860" },
	{ 2049 ,"ibm861" },
	{ 2050 ,"ibm863" },
	{ 2051 ,"ibm864" },
	{ 2052 ,"ibm865" },
	{ 2053 ,"ibm868" },
	{ 2054 ,"ibm869" },
	{ 2055 ,"ibm870" },
	{ 2056 ,"ibm871" },
	{ 2057 ,"ibm880" },
	{ 2058 ,"ibm891" },
	{ 2059 ,"ibm903" },
	{ 2060 ,"ibm904" },
	{ 2061 ,"ibm905" },
	{ 2062 ,"ibm918" },
	{ 2063 ,"ibm1026" },
	{ 2064 ,"ebcdic-at-de" },
	{ 2065 ,"ebcdic-at-de-a" },
	{ 2066 ,"ebcdic-ca-fr" },
	{ 2067 ,"ebcdic-dk-no" },
	{ 2068 ,"ebcdic-dk-no-a" },
	{ 2069 ,"ebcdic-fi-se" },
	{ 2070 ,"ebcdic-fi-se-a" },
	{ 2071 ,"ebcdic-fr" },
	{ 2072 ,"ebcdic-it" },
	{ 2073 ,"ebcdic-pt" },
	{ 2074 ,"ebcdic-es" },
	{ 2075 ,"ebcdic-es-a" },
	{ 2076 ,"ebcdic-es-s" },
	{ 2077 ,"ebcdic-uk" },
	{ 2078 ,"ebcdic-us" },
	{ 2079 ,"unknown-8bit" },
	{ 2080 ,"mnemonic" },
	{ 2081 ,"mnem" },
	{ 2082 ,"viscii" },
	{ 2083 ,"viqr" },
	{ 2084 ,"koi8-r" },
	{ 2086 ,"ibm866" },
	{ 2087 ,"ibm775" },
	{ 2088 ,"koi8-u" },
	{ 2089 ,"ibm00858" },
	{ 2090 ,"ibm00924" },
	{ 2091 ,"ibm01140" },
	{ 2092 ,"ibm01141" },
	{ 2093 ,"ibm01142" },
	{ 2094 ,"ibm01143" },
	{ 2095 ,"ibm01144" },
	{ 2096 ,"ibm01145" },
	{ 2097 ,"ibm01146" },
	{ 2098 ,"ibm01147" },
	{ 2099 ,"ibm01148" },
	{ 2100 ,"ibm01149" },
	{ 2101 ,"big5-hkscs" },
	{ 2250 ,"windows-1250" },
	{ 2251 ,"windows-1251" },
	{ 2252 ,"windows-1252" },
	{ 2253 ,"windows-1253" },
	{ 2254 ,"windows-1254" },
	{ 2255 ,"windows-1255" },
	{ 2256 ,"windows-1256" },
	{ 2257 ,"windows-1257" },
	{ 2258 ,"windows-1258" },
	{ 2259 ,"tis-620" },
	{ 0x00, NULL }
};

static const value_string vals_languages[] = {
	{ 0x01,"Afar(aa)" },
	{ 0x02,"Abkhazian(ab)" },
	{ 0x03,"Afrikaans(af)" },
	{ 0x04,"Amharic(am)" },
	{ 0x05,"Arabic(ar)" },
	{ 0x06,"Assamese(as)" },
	{ 0x07,"Aymara(ay)" },
	{ 0x08,"Azerbaijani(az)" },
	{ 0x09,"Bashkir(ba)" },
	{ 0x0A,"Byelorussian(be)" },
	{ 0x0B,"Bulgarian(bg)" },
	{ 0x0C,"Bihari(bh)" },
	{ 0x0D,"Bislama(bi)" },
	{ 0x0E,"Bengali; Bangla(bn)" },
	{ 0x0F,"Tibetan(bo)" },
	{ 0x10,"Breton(br)" },
	{ 0x11,"Catalan(ca)" },
	{ 0x12,"Corsican(co)" },
	{ 0x13,"Czech(cs)" },
	{ 0x14,"Welsh(cy)" },
	{ 0x15,"Danish(da)" },
	{ 0x16,"German(de)" },
	{ 0x17,"Bhutani(dz)" },
	{ 0x18,"Greek(el)" },
	{ 0x19,"English(en)" },
	{ 0x1A,"Esperanto(eo)" },
	{ 0x1B,"Spanish(es)" },
	{ 0x1C,"Estonian(et)" },
	{ 0x1D,"Basque(eu)" },
	{ 0x1E,"Persian(fa)" },
	{ 0x1F,"Finnish(fi)" },
	{ 0x20,"Fiji(fj)" },
	{ 0x22,"French(fr)" },
	{ 0x24,"Irish(ga)" },
	{ 0x25,"Scots Gaelic(gd)" },
	{ 0x26,"Galician(gl)" },
	{ 0x27,"Guarani(gn)" },
	{ 0x28,"Gujarati(gu)" },
	{ 0x29,"Hausa(ha)" },
	{ 0x2A,"Hebrew (formerly iw)(he)" },
	{ 0x2B,"Hindi(hi)" },
	{ 0x2C,"Croatian(hr)" },
	{ 0x2D,"Hungarian(hu)" },
	{ 0x2E,"Armenian(hy)" },
	{ 0x30,"Indonesian (formerly in)(id)" },
	{ 0x47,"Maori(mi)" },
	{ 0x48,"Macedonian(mk)" },
	{ 0x49,"Malayalam(ml)" },
	{ 0x4A,"Mongolian(mn)" },
	{ 0x4B,"Moldavian(mo)" },
	{ 0x4C,"Marathi(mr)" },
	{ 0x4D,"Malay(ms)" },
	{ 0x4E,"Maltese(mt)" },
	{ 0x4F,"Burmese(my)" },
	{ 0x51,"Nepali(ne)" },
	{ 0x52,"Dutch(nl)" },
	{ 0x53,"Norwegian(no)" },
	{ 0x54,"Occitan(oc)" },
	{ 0x55,"(Afan) Oromo(om)" },
	{ 0x56,"Oriya(or)" },
	{ 0x57,"Punjabi(pa)" },
	{ 0x58,"Polish(po)" },
	{ 0x59,"Pashto, Pushto(ps)" },
	{ 0x5A,"Portuguese(pt)" },
	{ 0x5B,"Quechua(qu)" },
	{ 0x5D,"Kirundi(rn)" },
	{ 0x5E,"Romanian(ro)" },
	{ 0x5F,"Russian(ru)" },
	{ 0x60,"Kinyarwanda(rw)" },
	{ 0x61,"Sanskrit(sa)" },
	{ 0x62,"Sindhi(sd)" },
	{ 0x63,"Sangho(sg)" },
	{ 0x64,"Serbo-Croatian(sh)" },
	{ 0x65,"Sinhalese(si)" },
	{ 0x66,"Slovak(sk)" },
	{ 0x67,"Slovenian(sl)" },
	{ 0x68,"Samoan(sm)" },
	{ 0x69,"Shona(sn)" },
	{ 0x6A,"Somali(so)" },
	{ 0x6B,"Albanian(sq)" },
	{ 0x6C,"Serbian(sr)" },
	{ 0x6D,"Siswati(ss)" },
	{ 0x6E,"Sesotho(st)" },
	{ 0x6F,"Sundanese(su)" },
	{ 0x70,"Swedish(sv)" },
	{ 0x71,"Swahili(sw)" },
	{ 0x72,"Tamil(ta)" },
	{ 0x73,"Telugu(te)" },
	{ 0x74,"Tajik(tg)" },
	{ 0x75,"Thai(th)" },
	{ 0x76,"Tigrinya(ti)" },
	{ 0x81,"Nauru(na)" },
	{ 0x82,"Faeroese(fo)" },
	{ 0x83,"Frisian(fy)" },
	{ 0x84,"Interlingua(ia)" },
	{ 0x8C,"Rhaeto-Romance(rm)" },
	{ 0x00, NULL }
};

static const value_string vals_accept_ranges[] = {
	{ 0x80, "None" },
	{ 0x81, "Bytes" },
	{ 0x00, NULL }
};

static const value_string vals_cache_control[] = {
	{ 0x80, "No-cache" },
	{ 0x81, "No-store" },
	{ 0x82, "Max-age" },
	{ 0x83, "Max-stale" },
	{ 0x84, "Min-fresh" },
	{ 0x85, "Only-if-cached" },
	{ 0x86, "Public" },
	{ 0x87, "Private" },
	{ 0x88, "No-transform" },
	{ 0x89, "Must-revalidate" },
	{ 0x8A, "Proxy-revalidate" },
	{ 0x00, NULL }
};

static const value_string vals_transfer_encoding[] = {
	{ 0x80, "Chunked" },
	{ 0x00, NULL }
};
static const value_string wtls_vals_record_type[] = {
	{ 0x01, "change_cipher_data" },
	{ 0x02, "alert" },
	{ 0x03, "handshake" },
	{ 0x04, "application_data" },
	{ 0x00, NULL }
};

static const value_string wtls_vals_cipher_bulk[] = {
	{ 0x00, "Null" },
	{ 0x01, "RC5 CBC 40" },
	{ 0x02, "RC5 CBC 56" },
	{ 0x03, "RC5 CBC" },
	{ 0x04, "DES CBC 40" },
	{ 0x05, "DES CBC" },
	{ 0x06, "3DES CBC cwEDE40" },
	{ 0x07, "IDEA CBC 40" },
	{ 0x08, "IDEA CBC 56" },
	{ 0x09, "IDEA CBC" },
	{ 0x00, NULL }
};

static const value_string wtls_vals_cipher_mac[] = {
	{ 0x00, "SHA 0" },
	{ 0x01, "SHA 40 " },
	{ 0x02, "SHA 80" },
	{ 0x03, "SHA" },
	{ 0x04, "SHA XOR 40" },
	{ 0x05, "MD5 40" },
	{ 0x06, "MD5 80" },
	{ 0x07, "MD5" },
	{ 0x00, NULL }
};

static const value_string wtls_vals_handshake_type[] = {
	{ 0, "Hello Request" },
	{ 1, "Client Hello" },
	{ 2, "Server Hello" },
	{ 11, "Certificate" },
	{ 12, "Server Key Exchange" },
	{ 13, "Certificate Request" },
	{ 14, "Server Hello Done" },
	{ 15, "Certificate Verify" },
	{ 16, "Client Key Exchange" },
	{ 20, "Finished" },
	{ 0x00, NULL }
};

static const value_string wtls_vals_key_exchange_suite[] = {
	{ 0, "NULL" },
	{ 1, "Shared Secret" },
	{ 2, "Diffie Hellman Anonymous" },
	{ 3, "Diffie Hellman Anonymous 512" },
	{ 4, "Diffie Hellman Anonymous 768" },
	{ 5, "RSA Anonymous" },
	{ 6, "RSA Anonymous 512" },
	{ 7, "RSA Anonymous 768" },
	{ 8, "RSA" },
	{ 9, "RSA 512" },
	{ 10, "RSA 768" },
	{ 11, "EC Diffie Hellman Anonymous" },
	{ 12, "EC Diffie Hellman Anonymous 113" },
	{ 13, "EC Diffie Hellman Anonymous 131" },
	{ 14, "EC Diffie Hellman ECDSA" },
	{ 15, "EC Diffie Hellman Anonymous Uncomp" },
	{ 16, "EC Diffie Hellman Anonymous Uncomp 113" },
	{ 17, "EC Diffie Hellman Anonymous Uncomp 131" },
	{ 18, "EC Diffie Hellman ECDSA Uncomp" },
	{ 0x00, NULL }
};

static const value_string wtls_vals_identifier_type[] = {
	{ 0, "No identifier" },
	{ 1, "Textual Name" },
	{ 2, "Binary Name" },
	{ 254, "SHA-1 Hash Publie Key" },
	{ 255, "x509 Distinguished Name" },
	{ 0x00, NULL }
};

static const value_string wtls_vals_certificate_type[] = {
	{ 1, "WTLS" },
	{ 2, "X509" },
	{ 3, "X968" },
	{ 4, "Url" },
	{ 0x00, NULL }
};

static const value_string wtls_vals_compression[] = {
	{ 0, "Null" },
	{ 0x00, NULL }
};

static const value_string wtls_vals_sequence_mode[] = {
	{ 0, "Off" },
	{ 1, "Implicit" },
	{ 2, "Explicit" },
	{ 0x00, NULL }
};

static const value_string wtls_vals_certificate_signature[] = {
	{ 0, "Anonymous" },
	{ 1, "ECDSA_SHA" },
	{ 2, "RSA_SHA" },
	{ 0x00, NULL }
};

static const value_string wtls_vals_public_key_type[] = {
	{ 2, "RSA" },
	{ 3, "ECDH" },
	{ 4, "ECSA" },
	{ 0x00, NULL }
};

static const value_string wtls_vals_alert_level[] = {
	{ 1, "Warning" },
	{ 2, "Critical" },
	{ 3, "Fatal" },
	{ 0x00, NULL }
};

static const value_string wtls_vals_alert_description[] = {
	{ 0,"connection_close_notify"},
	{ 1,"session_close_notify"},
	{ 5,"no_connection"},
	{ 10,"unexpected_message"},
	{ 11,"time_required"},
	{ 20,"bad_record_mac"},
	{ 21,"decryption_failed"},
	{ 22,"record_overflow"},
	{ 30,"decompression_failure"},
	{ 40,"handshake_failure"},
	{ 42,"bad_certificate"},
	{ 43,"unsupported_certificate"},
	{ 44,"certificate_revoked"},
	{ 45,"certificate_expired"},
	{ 46,"certificate_unknown"},
	{ 47,"illegal_parameter"},
	{ 48,"unknown_ca"},
	{ 49,"access_denied"},
	{ 50,"decode_error"},
	{ 51,"decrypt_error"},
	{ 52,"unknown_key_id"},
	{ 53,"disabled_key_id"},
	{ 54,"key_exchange_disabled"},
	{ 55,"session_not_ready"},
	{ 56,"unknown_parameter_index"},
	{ 57,"duplicate_finished_received"},
	{ 60,"export_restriction"},
	{ 70,"protocol_version"},
	{ 71,"insufficient_security"},
	{ 80,"internal_error"},
	{ 90,"user_canceled"},
	{ 100,"no_renegotiation"},
	{ 0x00, NULL }
};


/*
 * Windows appears to define DELETE.
 */
#ifdef DELETE
#undef DELETE
#endif

enum {
	RESERVED		= 0x00,
	CONNECT			= 0x01,
	CONNECTREPLY	= 0x02,
	REDIRECT		= 0x03,			/* No sample data */
	REPLY			= 0x04,
	DISCONNECT		= 0x05,
	PUSH			= 0x06,			/* No sample data */
	CONFIRMEDPUSH	= 0x07,			/* No sample data */
	SUSPEND			= 0x08,			/* No sample data */
	RESUME			= 0x09,			/* No sample data */

	GET				= 0x40,
	OPTIONS			= 0x41,			/* No sample data */
	HEAD			= 0x42,			/* No sample data */
	DELETE			= 0x43,			/* No sample data */
	TRACE			= 0x44,			/* No sample data */

	POST			= 0x60,
	PUT				= 0x61,			/* No sample data */
};

#define WTLS_RECORD_TYPE_LENGTH 	0x80
#define WTLS_RECORD_TYPE_SEQUENCE 	0x40
#define WTLS_RECORD_TYPE_CIPHER_CUR 	0x20
#define WTLS_RECORD_CONTENT_TYPE 	0x0f

#define WTLS_ALERT 			0x02
#define WTLS_PLAIN_HANDSHAKE 		0x03

#define WTLS_HANDSHAKE_CLIENT_HELLO	1
#define WTLS_HANDSHAKE_SERVER_HELLO	2
#define WTLS_HANDSHAKE_CERTIFICATE	11

#define CERTIFICATE_WTLS		1
#define CERTIFICATE_X509		2
#define CERTIFICATE_X968		3
#define CERTIFICATE_URL			4

#define IDENTIFIER_NULL			0
#define IDENTIFIER_TEXT			1
#define IDENTIFIER_BIN			2
#define IDENTIFIER_SHA_1		254
#define IDENTIFIER_X509			255

#define PUBLIC_KEY_RSA			2
#define PUBLIC_KEY_ECDH			3
#define PUBLIC_KEY_ECDSA		4

static void add_uri (proto_tree *, tvbuff_t *, guint, guint);
static void add_headers (proto_tree *, tvbuff_t *);
static void add_header (proto_tree *, tvbuff_t *, tvbuff_t *);
static guint get_value_length (tvbuff_t *, guint, guint *);
static guint add_content_type (proto_tree *, tvbuff_t *, guint, guint *);
static guint add_parameter (proto_tree *, tvbuff_t *, guint);
static guint add_parameter_charset (proto_tree *, tvbuff_t *, guint, guint);
static void add_post_data (proto_tree *, tvbuff_t *, guint);
static void add_post_variable (proto_tree *, tvbuff_t *, guint, guint, guint, guint);
static void dissect_wtls_handshake (proto_tree *, tvbuff_t *, guint, guint);

/* 
 * Accessor to retrieve variable length int as used in WAP protocol.
 * The value is encoded in the lower 7 bits. If the top bit is set, then the
 * value continues into the next byte.
 * The octetCount parameter holds the number of bytes read in order to return
 * the final value. Can be pre-initialised to start at offset+count.
*/
static guint
tvb_get_guintvar (tvbuff_t *tvb, guint offset, guint *octetCount)
{
	guint value = 0;
	guint octet;
	guint counter = 0;
	char cont = 1;
	
	if (octetCount == NULL)
	{
#ifdef DEBUG
		fprintf (stderr, "dissect_wsp: Starting tvb_get_guintvar at offset %d, count=NULL\n", offset);
#endif
	}
	else
	{
#ifdef DEBUG
		fprintf (stderr, "dissect_wsp: Starting tvb_get_guintvar at offset %d, count=%d\n", offset, *octetCount);
#endif
		counter = *octetCount;
	}

	while (cont != 0)
	{
		value<<=7;	/* Value only exists in 7 of the 8 bits */
		octet = tvb_get_guint8 (tvb, offset+counter);
		counter++;
		value += (octet & 0x7F);
		cont = (octet & 0x80);
#ifdef DEBUG
		fprintf (stderr, "dissect_wsp: octet is %d (0x%02x), count=%d, value=%d, cont=%d\n", octet, octet, counter, value, cont);
#endif
	}

	if (octetCount != NULL)
	{
		*octetCount = counter;
#ifdef DEBUG
		fprintf (stderr, "dissect_wsp: Leaving tvb_get_guintvar count=%d\n", *octetCount);
#endif
	}

	return (value);
}

/* Code to actually dissect the packets */
static void
dissect_wsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	frame_data *fdata = pinfo->fd;
	int offset = 0;

	guint8 pdut;
	guint count = 0;
	guint value = 0;
	guint uriLength = 0;
	guint uriStart = 0;
	guint capabilityLength = 0;
	guint capabilityStart = 0;
	guint headersLength = 0;
	guint headerLength = 0;
	guint headerStart = 0;
	guint nextOffset = 0;
	guint contentTypeStart = 0;
	guint contentType = 0;
	tvbuff_t *tmp_tvb;

/* Set up structures we will need to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *wsp_tree;
/*	proto_tree *wsp_header_fixed; */
	proto_tree *wsp_capabilities;
	
	if (check_col(fdata, COL_PROTOCOL)) 
	{
		col_set_str(fdata, COL_PROTOCOL, "WSP" );
	}
	if (check_col(fdata, COL_INFO)) {
		col_clear(fdata, COL_INFO);
	};

	/* Connection-less mode has a TID first */
	offset++;

	/* Find the PDU type */
	pdut = tvb_get_guint8 (tvb, offset);

	/* Develop the string to put in the Info column */
	if (check_col(fdata, COL_INFO)) {
		col_add_fstr(fdata, COL_INFO, "WSP %s",
			val_to_str (pdut, vals_pdu_type, "Unknown PDU type (0x%02x)"));
	};

/* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
	if (tree) {
		ti = proto_tree_add_item(tree, proto_wsp, tvb, 0,
		    tvb_length(tvb), bo_little_endian);
	        wsp_tree = proto_item_add_subtree(ti, ett_wsp);

/* Code to process the packet goes here */
/*
		wsp_header_fixed = proto_item_add_subtree(ti, ett_header);
*/

		/* Add common items: only TID and PDU Type */

		/* TID Field is always first (if it exists) */
		ti = proto_tree_add_item (wsp_tree, hf_wsp_header_tid,tvb,0,1,bo_little_endian);

		ti = proto_tree_add_item(
				wsp_tree, 		/* tree */
				hf_wsp_header_pdu_type, 	/* id */
				tvb, 
				offset++, 			/* start of high light */
				1,				/* length of high light */
				bo_little_endian				/* value */
		     );

		switch (pdut)
		{
		case CONNECT:
			ti = proto_tree_add_item (wsp_tree, hf_wsp_version_major,tvb,offset,1,bo_little_endian);
			ti = proto_tree_add_item (wsp_tree, hf_wsp_version_minor,tvb,offset,1,bo_little_endian);
			offset++;
			capabilityStart = offset;
			capabilityLength = tvb_get_guintvar (tvb, offset, &count);
			offset += count;
			ti = proto_tree_add_uint (wsp_tree, hf_wsp_capability_length,tvb,capabilityStart,count,capabilityLength);

			count = 0;
			headerStart = offset;
			headerLength = tvb_get_guintvar (tvb, offset, &count);
			offset += count;
			ti = proto_tree_add_uint (wsp_tree, hf_wsp_header_length,tvb,headerStart,count,headerLength);
			if (capabilityLength > 0)
			{
				ti = proto_tree_add_item (wsp_tree, hf_wsp_capabilities_section,tvb,offset,capabilityLength,bo_little_endian);
				wsp_capabilities = proto_item_add_subtree( ti, ett_capabilities );
				offset += capabilityLength;
			}

			if (headerLength > 0)
			{
				tmp_tvb = tvb_new_subset (tvb, offset, headerLength, headerLength);
				add_headers (wsp_tree, tmp_tvb);
			}

			break;

		case CONNECTREPLY:
			value = tvb_get_guintvar (tvb, offset, &count);
			ti = proto_tree_add_uint (wsp_tree, hf_wsp_server_session_id,tvb,offset,count,value);
			offset += count;

			count = 0;
			capabilityStart = offset;
			capabilityLength = tvb_get_guintvar (tvb, offset, &count);
			offset += count;
			ti = proto_tree_add_uint (wsp_tree, hf_wsp_capability_length,tvb,capabilityStart,count,capabilityLength);

			count = 0;
			headerStart = offset;
			headerLength = tvb_get_guintvar (tvb, offset, &count);
			offset += count;
			ti = proto_tree_add_uint (wsp_tree, hf_wsp_header_length,tvb,headerStart,count,headerLength);
			if (capabilityLength > 0)
			{
				ti = proto_tree_add_item (wsp_tree, hf_wsp_capabilities_section,tvb,offset,capabilityLength,bo_little_endian);
				wsp_capabilities = proto_item_add_subtree( ti, ett_capabilities );
				offset += capabilityLength;
			}

			if (headerLength > 0)
			{
				/*
				ti = proto_tree_add_item (wsp_tree, hf_wsp_headers_section,tvb,offset,headerLength,bo_little_endian);
				wsp_headers = proto_item_add_subtree( ti, ett_headers );
				*/
				tmp_tvb = tvb_new_subset (tvb, offset, headerLength, headerLength);
				add_headers (wsp_tree, tmp_tvb);
			}

			break;

		case DISCONNECT:
			value = tvb_get_guintvar (tvb, offset, &count);
			ti = proto_tree_add_uint (wsp_tree, hf_wsp_server_session_id,tvb,offset,count,value);
			break;

		case GET:
			/* Length of URI and size of URILen field */
			count = 0;
			value = tvb_get_guintvar (tvb, offset, &count);
			nextOffset = offset + count;
			add_uri (wsp_tree, tvb, offset, nextOffset);
			offset += (value+count);
			tmp_tvb = tvb_new_subset (tvb, offset, -1, -1);
			add_headers (wsp_tree, tmp_tvb);
			break;

		case POST:
			/* Length of URI and size of URILen field */
			uriStart = offset;
			uriLength = tvb_get_guintvar (tvb, offset, &count);
			headerStart = uriStart+count;
			count = 0;
			headersLength = tvb_get_guintvar (tvb, headerStart, &count);
			offset = headerStart + count;

			add_uri (wsp_tree, tvb, uriStart, offset);
			offset += uriLength;

			ti = proto_tree_add_item (wsp_tree, hf_wsp_header_length,tvb,headerStart,count,bo_little_endian);

			contentTypeStart = offset;
			nextOffset = add_content_type (wsp_tree, tvb, offset, &contentType);

			/* Add headers subtree that will hold the headers fields */
			/* Runs from nextOffset for value-(length of content-type field)*/
			headerLength = headersLength-(nextOffset-contentTypeStart);
			tmp_tvb = tvb_new_subset (tvb, nextOffset, headerLength, headerLength);
			add_headers (wsp_tree, tmp_tvb);

			/* TODO: Post DATA */
			/* Runs from start of headers+headerLength to END_OF_FRAME */
			offset = nextOffset+headerLength;
			tmp_tvb = tvb_new_subset (tvb, offset, tvb_reported_length (tvb)-offset, tvb_reported_length (tvb)-offset);
			add_post_data (wsp_tree, tmp_tvb, contentType);
			break;

		case REPLY:
			ti = proto_tree_add_item (wsp_tree, hf_wsp_header_status,tvb,offset,1,bo_little_endian);
			value = tvb_get_guintvar (tvb, offset+1, &count);
			nextOffset = offset + 1 + count;
			
			ti = proto_tree_add_uint (wsp_tree, hf_wsp_header_length,tvb,offset+1,count,value);

			contentTypeStart = nextOffset;
			nextOffset = add_content_type (wsp_tree, tvb, nextOffset, &contentType);

			/* Add headers subtree that will hold the headers fields */
			/* Runs from nextOffset for value-(length of content-type field)*/
			headerLength = value-(nextOffset-contentTypeStart);
			tmp_tvb = tvb_new_subset (tvb, nextOffset, headerLength, headerLength);
			add_headers (wsp_tree, tmp_tvb);
			offset += count+value+1;

			/* TODO: Data - decode WMLC */
			/* Runs from offset+1+count+value+1 to END_OF_FRAME */
			if (offset < tvb_reported_length (tvb))
			{
				ti = proto_tree_add_item (wsp_tree, hf_wsp_reply_data,tvb,offset,tvb_reported_length(tvb)-offset,bo_little_endian);
			}
			break;
		}
	}
}

/* Code to actually dissect the packets */
static void
dissect_wtls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	frame_data *fdata = pinfo->fd;
	int offset = 0;

	char pdut;
	char pdu_msg_type;
	guint count = 0;
	guint offset_wtls = 0;

/* Set up structures we will need to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *wtls_tree;
	proto_tree *wtls_rec_tree;
	proto_tree *wtls_msg_type_tree;

	if (check_col(fdata, COL_PROTOCOL)) 
	{
		col_set_str(fdata, COL_PROTOCOL, "WTLS+WSP" );
	}

	/* Develop the string to put in the Info column */
	if (check_col(fdata, COL_INFO)) {
		col_set_str(fdata, COL_INFO, "WTLS" );
	};

	/* In the interest of speed, if "tree" is NULL, don't do any work not
	necessary to generate protocol tree items. */

	if (tree) {
		ti = proto_tree_add_item(tree, proto_wtls, tvb, offset_wtls,
				 tvb_length(tvb), bo_little_endian);
		wtls_tree = proto_item_add_subtree(ti, ett_wsp);

		for (offset_wtls=0; offset_wtls < (tvb_length(tvb)-1);) {
			pdut = tvb_get_guint8 (tvb, offset_wtls);

			offset = offset_wtls+1;

			if (pdut & WTLS_RECORD_TYPE_SEQUENCE) {
				offset+=2;
			}
			if (pdut & WTLS_RECORD_TYPE_LENGTH) {
				count = tvb_get_ntohs(tvb, offset);
				offset+=2;
				count += offset-offset_wtls;
			}
			else {
				count = tvb_length (tvb)-offset_wtls;
			}
			ti = proto_tree_add_item(wtls_tree, hf_wtls_record, tvb, offset_wtls,
				 count, bo_little_endian);
			wtls_rec_tree = proto_item_add_subtree(ti, ett_wtls_rec);

			offset = offset_wtls;

			ti = proto_tree_add_item (wtls_rec_tree, hf_wtls_record_type,
					tvb,offset,1,bo_big_endian);

			offset++;

			offset_wtls += count;

			if (pdut & WTLS_RECORD_TYPE_SEQUENCE) {
				ti = proto_tree_add_item (wtls_rec_tree, hf_wtls_record_sequence,
						tvb,offset,2,bo_big_endian);
				offset+=2;
			}
			if (pdut & WTLS_RECORD_TYPE_LENGTH) {
				count = tvb_get_ntohs(tvb, offset);
				ti = proto_tree_add_item (wtls_rec_tree, hf_wtls_record_length,
						tvb,offset,2,bo_big_endian);
				offset+=2;
			}
			else {
				count = tvb_length (tvb)-offset;
			}

			if (pdut & WTLS_RECORD_TYPE_CIPHER_CUR) {
				ti = proto_tree_add_item (wtls_rec_tree, hf_wtls_record_ciphered,
						tvb,offset,count,bo_big_endian);
				continue;
			}

			switch (pdut & WTLS_RECORD_CONTENT_TYPE) {
				case WTLS_PLAIN_HANDSHAKE :
					dissect_wtls_handshake(wtls_rec_tree,tvb,offset,count);
					break;
				case WTLS_ALERT :
					ti = proto_tree_add_item(wtls_rec_tree, hf_wtls_alert, tvb, offset,
							 count, bo_little_endian);
					wtls_msg_type_tree = proto_item_add_subtree(ti, ett_wtls_msg_type);
					pdu_msg_type = tvb_get_guint8 (tvb, offset);
					ti = proto_tree_add_item (wtls_msg_type_tree, hf_wtls_alert_level,
							tvb,offset,1,bo_big_endian);
					offset+=1;
					count = tvb_get_ntohs (tvb, offset);
					ti = proto_tree_add_item (wtls_msg_type_tree, hf_wtls_alert_description,
							tvb,offset,1,bo_big_endian);
					offset+=1;
				default:
					offset+=count;
					break;
			}
		}
	}
}

static void
dissect_wtls_handshake(proto_tree *tree, tvbuff_t *tvb, guint offset, guint count)
{
	char pdu_msg_type;
	struct timeval timeValue;
	int client_size = 0;
	guint value = 0;
	int size = 0;
	guint public_key = 0;
	guint signature = 0;

	proto_item *ti;
	proto_item *cli_key_item;
	proto_tree *wtls_msg_type_tree;
	proto_tree *wtls_msg_type_item_tree;
	proto_tree *wtls_msg_type_item_sub_tree;
	proto_tree *wtls_msg_type_item_sub_sub_tree;

	ti = proto_tree_add_item(tree, hf_wtls_hands, tvb, offset,count, bo_little_endian);
	wtls_msg_type_tree = proto_item_add_subtree(ti, ett_wtls_msg_type);
	
	pdu_msg_type = tvb_get_guint8 (tvb, offset);
	ti = proto_tree_add_item (wtls_msg_type_tree, hf_wtls_hands_type,
			tvb,offset,1,bo_big_endian);
	offset+=1;
	count = tvb_get_ntohs (tvb, offset);
	ti = proto_tree_add_item (wtls_msg_type_tree, hf_wtls_hands_length,
			tvb,offset,2,bo_big_endian);
	offset+=2;
	switch(pdu_msg_type) {
		case WTLS_HANDSHAKE_CLIENT_HELLO :
			ti = proto_tree_add_item(wtls_msg_type_tree, hf_wtls_hands_cli_hello, tvb, offset,
					 count, bo_little_endian);
			wtls_msg_type_item_tree = proto_item_add_subtree(ti, ett_wtls_msg_type_item);
			ti = proto_tree_add_item (wtls_msg_type_item_tree, hf_wtls_hands_cli_hello_version,
					tvb,offset,1,bo_big_endian);
			offset++;
			timeValue.tv_sec = tvb_get_ntohl (tvb, offset);
			timeValue.tv_usec = 0;
			ti = proto_tree_add_time (wtls_msg_type_item_tree, hf_wtls_hands_cli_hello_gmt, tvb,
					offset, 4, &timeValue);
			offset+=4;
			ti = proto_tree_add_item (wtls_msg_type_item_tree, hf_wtls_hands_cli_hello_random,
					tvb,offset,12,bo_big_endian);
			offset+=12;
			count = tvb_get_guint8(tvb, offset);
			ti = proto_tree_add_item (wtls_msg_type_item_tree, hf_wtls_hands_cli_hello_session,
					tvb,offset,count+1,bo_big_endian);
			offset+=1+count;
			count = tvb_get_ntohs (tvb, offset);
			ti = proto_tree_add_item(wtls_msg_type_item_tree, 
					hf_wtls_hands_cli_hello_cli_key_id, tvb, offset,
					 count+2, bo_little_endian);
			wtls_msg_type_item_sub_tree = proto_item_add_subtree(ti, ett_wtls_msg_type_item_sub);
			offset+=2;
			for (;count > 0;count-=client_size) {
				cli_key_item = proto_tree_add_item(wtls_msg_type_item_sub_tree, 
						hf_wtls_hands_cli_hello_key_exchange, tvb, offset,1,
						bo_little_endian);
				client_size=1;
				wtls_msg_type_item_sub_sub_tree = proto_item_add_subtree(cli_key_item, 
								  ett_wtls_msg_type_item_sub_sub);
				ti = proto_tree_add_item(wtls_msg_type_item_sub_sub_tree,
						hf_wtls_hands_cli_hello_key_exchange_suite,
						tvb,offset,1,bo_big_endian);
				offset++;
				value = tvb_get_guint8 (tvb, offset);
				ti = proto_tree_add_item(wtls_msg_type_item_sub_sub_tree,
					hf_wtls_hands_cli_hello_key_parameter_index,
					tvb,offset,1,bo_big_endian);
				offset++;
				client_size++;
				if (value == 0xff) {
					size = tvb_get_ntohs (tvb, offset);
					ti = proto_tree_add_item(wtls_msg_type_item_sub_sub_tree,
						hf_wtls_hands_cli_hello_key_parameter_set,
						tvb,offset,size+2,bo_big_endian);
					offset+=size+2;
					client_size+=size+2;
				}
				value = tvb_get_guint8 (tvb, offset);
				ti = proto_tree_add_item(wtls_msg_type_item_sub_sub_tree,
						hf_wtls_hands_cli_hello_key_identifier_type,
						tvb,offset,1,bo_big_endian);
				offset++;
				client_size++;
				proto_item_set_len(cli_key_item, client_size);
			}
			count = tvb_get_ntohs (tvb, offset);
			ti = proto_tree_add_item(wtls_msg_type_item_tree, 
					hf_wtls_hands_cli_hello_trust_key_id, tvb, offset,
					 count+2, bo_little_endian);
			wtls_msg_type_item_sub_tree = proto_item_add_subtree(ti, ett_wtls_msg_type_item_sub);
			offset+=2;
			for (;count > 0;count-=client_size) {
				cli_key_item = proto_tree_add_item(wtls_msg_type_item_sub_tree, 
						hf_wtls_hands_cli_hello_key_exchange, tvb, offset,1,
						bo_little_endian);
				client_size=1;
				wtls_msg_type_item_sub_sub_tree = proto_item_add_subtree(cli_key_item, 
								  ett_wtls_msg_type_item_sub_sub);
				ti = proto_tree_add_item(wtls_msg_type_item_sub_sub_tree,
						hf_wtls_hands_cli_hello_key_exchange_suite,
						tvb,offset,1,bo_big_endian);
				offset++;
				value = tvb_get_guint8 (tvb, offset);
				ti = proto_tree_add_item(wtls_msg_type_item_sub_sub_tree,
					hf_wtls_hands_cli_hello_key_parameter_index,
					tvb,offset,1,bo_big_endian);
				offset++;
				client_size++;
				if (value == 0xff) {
					size = tvb_get_ntohs (tvb, offset);
					ti = proto_tree_add_item(wtls_msg_type_item_sub_sub_tree,
						hf_wtls_hands_cli_hello_key_parameter_set,
						tvb,offset,size+2,bo_big_endian);
					offset+=size+2;
					client_size+=size+2;
				}
				value = tvb_get_guint8 (tvb, offset);
				ti = proto_tree_add_item(wtls_msg_type_item_sub_sub_tree,
						hf_wtls_hands_cli_hello_key_identifier_type,
						tvb,offset,1,bo_big_endian);
				offset++;
				client_size++;
				proto_item_set_len(cli_key_item, client_size);
			}
			count = tvb_get_guint8 (tvb, offset);
			ti = proto_tree_add_item(wtls_msg_type_item_tree, 
					hf_wtls_hands_cli_hello_cipher_suite, tvb, offset,
					 count+1, bo_little_endian);
			wtls_msg_type_item_sub_tree = proto_item_add_subtree(ti, ett_wtls_msg_type_item_sub);
			offset+=1;
			for (;count > 0;count-=client_size) {
				cli_key_item = proto_tree_add_item(wtls_msg_type_item_sub_tree, 
						hf_wtls_hands_cli_hello_cipher_suite_item, tvb, offset,1,
						bo_little_endian);
				client_size=1;
				wtls_msg_type_item_sub_sub_tree = proto_item_add_subtree(cli_key_item, 
								  ett_wtls_msg_type_item_sub_sub);
				ti = proto_tree_add_item(wtls_msg_type_item_sub_sub_tree,
						hf_wtls_hands_cli_hello_cipher_bulk,
						tvb,offset,1,bo_big_endian);
				offset++;
				value = tvb_get_guint8 (tvb, offset);
				ti = proto_tree_add_item(wtls_msg_type_item_sub_sub_tree,
					hf_wtls_hands_cli_hello_cipher_mac,
					tvb,offset,1,bo_big_endian);
				offset++;
				client_size++;
				proto_item_set_len(cli_key_item, client_size);
			}
			count = tvb_get_guint8 (tvb, offset);
			ti = proto_tree_add_item(wtls_msg_type_item_tree, 
					hf_wtls_hands_cli_hello_compression_methods, tvb, offset,
					 count+1, bo_little_endian);
			wtls_msg_type_item_sub_tree = proto_item_add_subtree(ti, ett_wtls_msg_type_item_sub);
			offset+=1;
			for (;count > 0;count-=client_size) {
				client_size=0;
				ti = proto_tree_add_item(wtls_msg_type_item_sub_tree, 
						hf_wtls_hands_cli_hello_compression, tvb, offset,1,
						bo_little_endian);
				offset++;
				client_size++;
			}
			ti = proto_tree_add_item(wtls_msg_type_item_tree, 
					hf_wtls_hands_cli_hello_sequence_mode, tvb, offset,
					 1, bo_little_endian);
			offset++;
			ti = proto_tree_add_item(wtls_msg_type_item_tree, 
					hf_wtls_hands_cli_hello_key_refresh, tvb, offset,
					 1, bo_little_endian);
			break;
		case WTLS_HANDSHAKE_SERVER_HELLO :
			ti = proto_tree_add_item(wtls_msg_type_tree, hf_wtls_hands_serv_hello, tvb, offset,
					 count, bo_little_endian);
			wtls_msg_type_item_tree = proto_item_add_subtree(ti, ett_wtls_msg_type_item);
			ti = proto_tree_add_item (wtls_msg_type_item_tree, hf_wtls_hands_serv_hello_version,
					tvb,offset,1,bo_big_endian);
			offset++;
			timeValue.tv_sec = tvb_get_ntohl (tvb, offset);
			timeValue.tv_usec = 0;
			ti = proto_tree_add_time (wtls_msg_type_item_tree, hf_wtls_hands_serv_hello_gmt, tvb,
					offset, 4, &timeValue);
			offset+=4;
			ti = proto_tree_add_item (wtls_msg_type_item_tree, hf_wtls_hands_serv_hello_random,
					tvb,offset,12,bo_big_endian);
			offset+=12;
			count = tvb_get_guint8(tvb, offset);
			ti = proto_tree_add_item (wtls_msg_type_item_tree, hf_wtls_hands_serv_hello_session,
					tvb,offset,count+1,bo_big_endian);
			offset+=1+count;
			ti = proto_tree_add_item(wtls_msg_type_item_tree,
					hf_wtls_hands_serv_hello_cli_key_id,
					tvb,offset,1,bo_big_endian);
			offset++;
			cli_key_item = proto_tree_add_item(wtls_msg_type_item_tree, 
					hf_wtls_hands_serv_hello_cipher_suite_item, tvb, offset,2,
					bo_little_endian);
			wtls_msg_type_item_sub_tree = proto_item_add_subtree(cli_key_item, 
							  ett_wtls_msg_type_item_sub);
			ti = proto_tree_add_item(wtls_msg_type_item_sub_tree,
					hf_wtls_hands_serv_hello_cipher_bulk,
					tvb,offset,1,bo_big_endian);
			offset++;
			value = tvb_get_guint8 (tvb, offset);
			ti = proto_tree_add_item(wtls_msg_type_item_sub_tree,
				hf_wtls_hands_serv_hello_cipher_mac,
				tvb,offset,1,bo_big_endian);
			offset++;
			ti = proto_tree_add_item(wtls_msg_type_item_tree, 
					hf_wtls_hands_serv_hello_compression, tvb, offset,1,
					bo_little_endian);
			offset++;
			ti = proto_tree_add_item(wtls_msg_type_item_tree, 
					hf_wtls_hands_serv_hello_sequence_mode, tvb, offset,
					 1, bo_little_endian);
			offset++;
			ti = proto_tree_add_item(wtls_msg_type_item_tree, 
					hf_wtls_hands_serv_hello_key_refresh, tvb, offset,
					 1, bo_little_endian);
			offset++;
			break;
		case WTLS_HANDSHAKE_CERTIFICATE :
			ti = proto_tree_add_item(wtls_msg_type_tree, hf_wtls_hands_certificates,
					tvb, offset,count, bo_little_endian);
			wtls_msg_type_item_tree = proto_item_add_subtree(ti, ett_wtls_msg_type_item);
			count = tvb_get_ntohs (tvb, offset);
			offset+=2;
			for (;count > 0;count-=client_size) {
				cli_key_item = proto_tree_add_item(wtls_msg_type_item_tree, 
						hf_wtls_hands_certificate, tvb, offset,1,
						bo_little_endian);
				client_size=0;
				wtls_msg_type_item_sub_tree = proto_item_add_subtree(cli_key_item, 
								  ett_wtls_msg_type_item_sub);
				proto_item_set_len(cli_key_item, client_size);
				value =  tvb_get_guint8 (tvb, offset);
				ti = proto_tree_add_item(wtls_msg_type_item_sub_tree, 
						hf_wtls_hands_certificate_type, tvb, offset,1,
						bo_little_endian);
				offset++;
				client_size++;
				switch(value) {
					case CERTIFICATE_WTLS:
						ti = proto_tree_add_item(wtls_msg_type_item_sub_tree, 
							hf_wtls_hands_certificate_wtls_version,
							tvb, offset,1,
							bo_little_endian);
						offset++;
						client_size++;
						signature =  tvb_get_guint8 (tvb, offset);
						ti = proto_tree_add_item(wtls_msg_type_item_sub_tree, 
							hf_wtls_hands_certificate_wtls_signature_type,
							tvb, offset,1,
							bo_little_endian);
						offset++;
						client_size++;
						value =  tvb_get_guint8 (tvb, offset);
						ti = proto_tree_add_item(wtls_msg_type_item_sub_tree, 
							hf_wtls_hands_certificate_wtls_issuer_type,
							tvb, offset,1,
							bo_little_endian);
						offset++;
						client_size++;
						switch (value) {
							case IDENTIFIER_NULL :
								break;
							case IDENTIFIER_TEXT :
								ti = proto_tree_add_item(
										wtls_msg_type_item_sub_tree, 
										hf_wtls_hands_certificate_wtls_issuer_charset,
										tvb, offset,2,
										bo_big_endian);
								offset+=2;
								client_size+=2;
								value =  tvb_get_guint8 (tvb, offset);
								ti = proto_tree_add_item(
										wtls_msg_type_item_sub_tree, 
										hf_wtls_hands_certificate_wtls_issuer_name,
										tvb, offset,1+value,
										bo_big_endian);
								offset+=1+value;
								client_size+=1+value;
								break;
							case IDENTIFIER_BIN :
								break;
							case IDENTIFIER_SHA_1 :
								break;
							case IDENTIFIER_X509 :
								break;
						}
						timeValue.tv_sec = tvb_get_ntohl (tvb, offset);
						timeValue.tv_usec = 0;
						ti = proto_tree_add_time (wtls_msg_type_item_sub_tree, 
								hf_wtls_hands_certificate_wtls_valid_not_before,
								tvb, offset, 4, &timeValue);
						offset+=4;
						client_size+=4;
						timeValue.tv_sec = tvb_get_ntohl (tvb, offset);
						timeValue.tv_usec = 0;
						ti = proto_tree_add_time (wtls_msg_type_item_sub_tree, 
								hf_wtls_hands_certificate_wtls_valid_not_after,
								tvb, offset, 4, &timeValue);
						offset+=4;
						client_size+=4;
						value =  tvb_get_guint8 (tvb, offset);
						ti = proto_tree_add_item(wtls_msg_type_item_sub_tree, 
							hf_wtls_hands_certificate_wtls_subject_type,
							tvb, offset,1,
							bo_little_endian);
						offset++;
						client_size++;
						switch (value) {
							case IDENTIFIER_NULL :
								break;
							case IDENTIFIER_TEXT :
								ti = proto_tree_add_item(
										wtls_msg_type_item_sub_tree, 
										hf_wtls_hands_certificate_wtls_subject_charset,
										tvb, offset,2,
										bo_big_endian);
								offset+=2;
								client_size+=2;
								value =  tvb_get_guint8 (tvb, offset);
								ti = proto_tree_add_item(
										wtls_msg_type_item_sub_tree, 
										hf_wtls_hands_certificate_wtls_subject_name,
										tvb, offset,1+value,
										bo_big_endian);
								offset+=1+value;
								client_size+=1+value;
								break;
							case IDENTIFIER_BIN :
								break;
							case IDENTIFIER_SHA_1 :
								break;
							case IDENTIFIER_X509 :
								break;
						}
						public_key =  tvb_get_guint8 (tvb, offset);
						ti = proto_tree_add_item(wtls_msg_type_item_sub_tree, 
							hf_wtls_hands_certificate_wtls_public_key_type,
							tvb, offset,1,
							bo_little_endian);
						offset++;
						client_size++;
						value = tvb_get_guint8 (tvb, offset);
						ti = proto_tree_add_item(wtls_msg_type_item_sub_tree,
							hf_wtls_hands_certificate_wtls_key_parameter_index,
							tvb,offset,1,bo_big_endian);
						offset++;
						client_size++;
						if (value == 0xff) {
							size = tvb_get_ntohs (tvb, offset);
							ti = proto_tree_add_item(wtls_msg_type_item_sub_tree,
								hf_wtls_hands_certificate_wtls_key_parameter_set,
								tvb,offset,size+2,bo_big_endian);
							offset+=size+2;
							client_size+=size+2;
						}
						switch (public_key) {
							case PUBLIC_KEY_RSA :
								value = tvb_get_ntohs (tvb, offset);
								ti = proto_tree_add_item(wtls_msg_type_item_sub_tree,
									hf_wtls_hands_certificate_wtls_rsa_exponent,
									tvb,offset,value+2,bo_big_endian);
								offset+=2+value;
								client_size+=2+value;
								value = tvb_get_ntohs (tvb, offset);
								ti = proto_tree_add_item(wtls_msg_type_item_sub_tree,
									hf_wtls_hands_certificate_wtls_rsa_modules,
									tvb,offset,value+2,bo_big_endian);
								offset+=2+value;
								client_size+=2+value;
								break;
							case PUBLIC_KEY_ECDH :
								break;
							case PUBLIC_KEY_ECDSA :
								break;
						}
						value = tvb_get_ntohs (tvb, offset);
						ti = proto_tree_add_item(wtls_msg_type_item_sub_tree,
							hf_wtls_hands_certificate_wtls_signature,
							tvb,offset,2+value,bo_big_endian);
						offset+=2+value;
						client_size+=2+value;
						break;
					case CERTIFICATE_X509:
					case CERTIFICATE_X968:
						value =  tvb_get_ntohs (tvb, offset);
						offset+=2;
						client_size+=2;
						client_size += value;
						offset += value;
						break;
					case CERTIFICATE_URL:
						value =  tvb_get_guint8 (tvb, offset);
						offset++;
						client_size++;
						client_size += value;
						offset += value;
						break;
				}
				proto_item_set_len(cli_key_item, client_size);
			}
			break;
		default: 
			offset+=count;
			break;
	}
}

static void
add_uri (proto_tree *tree, tvbuff_t *tvb, guint URILenOffset, guint URIOffset)
{
	proto_item *ti;
	guint8 terminator = 0;
	char *newBuffer;

	guint count = 0;
	guint uriLen = tvb_get_guintvar (tvb, URILenOffset, &count);

	ti = proto_tree_add_uint (tree, hf_wsp_header_uri_len,tvb,URILenOffset,count,uriLen);

	/* If string doesn't end with a 0x00, we need to add one to be on the safe side */
	terminator = tvb_get_guint8 (tvb, URIOffset+uriLen-1);
	if (terminator != 0)
	{
		newBuffer = g_malloc (uriLen+1);
		strncpy (newBuffer, tvb_get_ptr (tvb, URIOffset, uriLen), uriLen);
		newBuffer[uriLen] = 0;
		ti = proto_tree_add_string (tree, hf_wsp_header_uri,tvb,URIOffset,uriLen,newBuffer);
		g_free (newBuffer);
	}
	else
	{
		ti = proto_tree_add_item (tree, hf_wsp_header_uri,tvb,URIOffset,uriLen,bo_little_endian);
	}
}

static void
add_headers (proto_tree *tree, tvbuff_t *tvb)
{
	proto_item *ti;
	proto_tree *wsp_headers;
	guint offset = 0;
	guint headersLen = tvb_reported_length (tvb);
	guint8 headerStart = 0;
	guint peek = 0;
	tvbuff_t *header_buff;
	tvbuff_t *value_buff;
	guint count = 0;
	guint valueStart = 0;
	guint valueEnd = 0;

#ifdef DEBUG
	fprintf (stderr, "dissect_wsp: Offset is %d, size is %d\n", offset, headersLen);
#endif

	/* End of buffer */
	if (headersLen <= 0)
	{
		return;
	}

#ifdef DEBUG
	fprintf (stderr, "dissect_wsp: Headers to process\n");
#endif

	ti = proto_tree_add_item (tree, hf_wsp_headers_section,tvb,offset,headersLen,bo_little_endian);
	wsp_headers = proto_item_add_subtree( ti, ett_headers );

	/* Parse Headers */

	while (offset < headersLen)
	{
		/* Loop round each header */
		headerStart = offset;
		peek = tvb_get_guint8 (tvb, headerStart);

		if (peek < 32)		/* Short-cut shift delimeter */
		{
			fprintf (stderr, "dissect_wsp: header: short-cut shift %d (0x%02X)\n", peek, peek);
			offset++;
		}
		else if (peek == 0x7F)	/* Shift delimeter */
		{
			fprintf (stderr, "dissect_wsp: header: shift delimeter %d (0x%02X)\n", peek, peek);
			offset++;
		}
		else if (peek < 127)
		{
#ifdef DEBUG
			fprintf (stderr, "dissect_wsp: header: application-header start %d (0x%02X)\n", peek, peek);
#endif
			while (tvb_get_guint8 (tvb, offset++)) { /* Do nothing, just look for NULL */ }
		}
		else if (peek & 0x80)	/* Well-known header */
		{
#ifdef DEBUG
			fprintf (stderr, "dissect_wsp: header: well-known %d (0x%02X)\n", peek, peek);
#endif
			offset++;
		}

		/* Get value part of header */
		valueStart = offset;
		peek = tvb_get_guint8 (tvb, valueStart);
		if (peek <= 30)
		{
#ifdef DEBUG
			fprintf (stderr, "dissect_wsp: Looking for %d octets\n", peek);
#endif
			valueEnd = offset+1+peek;
			offset += (peek+1);
		}
		else if (peek == 31)
		{
#ifdef DEBUG
			fprintf (stderr, "dissect_wsp: Looking for uintvar octets\n");
#endif
			count = 0;
			tvb_get_guintvar (tvb, valueStart, &count);
			valueEnd = offset+1+count;
			offset += (count+1);
		}
		else if (peek <= 127)
		{
#ifdef DEBUG
			fprintf (stderr, "dissect_wsp: Looking for NULL-terminated string\n");
#endif
			valueEnd = valueStart+1;
			while (tvb_get_guint8 (tvb, valueEnd++)) { /* Do nothing, just look for NULL */ }
			offset = valueEnd;
		}
		else
		{
#ifdef DEBUG
			fprintf (stderr, "dissect_wsp: Value is %d\n", (peek & 0x7F));
#endif
			valueEnd = offset+1;
			offset++;
		}
#ifdef DEBUG
		fprintf (stderr, "dissect_wsp: Creating value buffer from offset %d, size=%d\n", headerStart, (offset-headerStart));
#endif

		header_buff = tvb_new_subset (tvb, headerStart, (offset-headerStart), (offset-headerStart));
		value_buff = tvb_new_subset (tvb, valueStart, (valueEnd-valueStart), (valueEnd-valueStart));

		add_header (wsp_headers, header_buff, value_buff);
	}
}

static void
add_header (proto_tree *tree, tvbuff_t *header_buff, tvbuff_t *value_buff)
{
	guint offset = 0;
	guint8 headerType = 0;
	proto_item *ti;
	guint headerLen = tvb_reported_length (header_buff);
	guint valueLen = tvb_reported_length (value_buff);
	guint peek = 0;
	struct timeval timeValue;
	guint value = 0;
	guint valSize = 0;
	char valString[100];
	char *valMatch;
	guint q_value = 0;

	headerType = tvb_get_guint8 (header_buff, 0);
	peek = tvb_get_guint8 (value_buff, 0);
#ifdef DEBUG
	fprintf (stderr, "dissect_wsp: Got header 0x%02x\n", headerType);
	fprintf (stderr, "dissect_wsp: First value octet is 0x%02x\n", peek);
#endif

	if (headerType == 0x7F)
	{
	}
	else if (headerType < 0x1F)
	{
	}
	else if (headerType & 0x80)
	{
		headerType = headerType & 0x7F;
		switch (headerType)
		{
		case 0x00:		/* Accept */
			if (peek & 0x80)
			{
				proto_tree_add_uint (tree, hf_wsp_header_accept, header_buff, offset, headerLen, (peek & 0x7F));
			}
			else
			{
				proto_tree_add_string (tree, hf_wsp_header_accept_str,header_buff,offset,headerLen,tvb_get_ptr (value_buff, 0, valueLen));
			}
			break;

		case 0x01:		/* Accept-Charset */
			if (peek < 31)
			{
				/* Peek contains the number of octets to follow */
				valSize = tvb_get_guint8 (value_buff, 1);
				/* decode Charset */
				if (valSize & 0x80) {
					value = valSize & 0x7f;
					valSize = 1;
				}
				else if (valSize < 31) { 
					switch (valSize)
					{
						case 1:
							value = tvb_get_guint8 (value_buff, 2);
							break;
						case 2:
							value = tvb_get_ntohs (value_buff, 2);
							break;
						case 3:
							value = tvb_get_ntoh24 (value_buff, 2);
							break;
						case 4:
							value = tvb_get_ntohl (value_buff, 2);
							break;
						default:
							value = 0;
							fprintf (stderr, "dissect_wsp: accept-charset size %d NYI\n", peek);
							break;
					}
					valSize++;
				}
				else {
					fprintf (stderr, "dissect_wsp: Accept-Charset value %d (0x%02X) NYI\n", peek, value);
				}
				valMatch = match_strval(value,vals_character_sets);
				if (peek > valSize) {
					q_value = tvb_get_guintvar (value_buff, 1+valSize, NULL);
					if (q_value <= 100) {
						q_value = (q_value - 1) * 10;
					}
					else {
						q_value -= 100;
					}
				}
				else {
					q_value = 1000;
				}
				if (valMatch != NULL)  {
					snprintf(valString,100,"%s;Q=%5.3f",valMatch,q_value/1000.0);
				}
				else {
					snprintf(valString,100,"Unknow %d;Q=%5.3f",value,q_value/1000.0);
				}
				proto_tree_add_string (tree, hf_wsp_header_accept_charset_str, header_buff, offset, headerLen, valString);
			}
			else if (peek & 0x80)
			{
				proto_tree_add_uint (tree, hf_wsp_header_accept_charset, header_buff, offset, headerLen, (peek & 0x7F) );
			}
			else
			{
				fprintf (stderr, "dissect_wsp: Accept-Charset value %d (0x%02X) NYI\n", peek, peek);
			}
			break;

		case 0x03:		/* Accept-Language */
			if (peek < 31)
			{
				/* Peek contains the number of octets to follow */
				switch (peek)
				{
					case 1:
						proto_tree_add_uint (tree, hf_wsp_header_accept_language, header_buff, offset, 
								headerLen, tvb_get_guint8 (value_buff, 1) );
						break;
					case 2:
						proto_tree_add_uint (tree, hf_wsp_header_accept_language, header_buff, offset, 
								headerLen, tvb_get_ntohs (value_buff, 1) );
						break;
					case 4:
						proto_tree_add_uint (tree, hf_wsp_header_accept_language, header_buff, offset, 
								headerLen, tvb_get_ntohl (value_buff, 1) );
						break;
					default:
						fprintf (stderr, "dissect_wsp: accept-language size %d NYI\n", peek);
				}
			}
			else if (peek & 0x80)
			{
				proto_tree_add_uint (tree, hf_wsp_header_accept_language, header_buff, offset, headerLen, (peek & 0x7F) );
			}
			else
			{
				proto_tree_add_string (tree, hf_wsp_header_accept_language_str, header_buff, offset,headerLen,
						tvb_get_ptr (value_buff, 0, valueLen));
			}
			break;

		case 0x04:		/* Accept-Ranges */
			if ((peek == 128) || (peek == 129))
			{
				proto_tree_add_uint (tree, hf_wsp_header_accept_ranges, header_buff, offset, headerLen, peek);
			}
			else
			{
				fprintf (stderr, "dissect_wsp: accept-ranges NYI\n");
			}
			
			break;

		case 0x05:		/* Age */
			switch (valueLen)
			{
				case 1:
					proto_tree_add_uint (tree, hf_wsp_header_age, header_buff, offset, headerLen, tvb_get_guint8 (value_buff, 0));
					break;
				case 2:
					proto_tree_add_uint (tree, hf_wsp_header_age, header_buff, offset, headerLen, tvb_get_ntohs (value_buff, 0));
					break;
				case 3:
					proto_tree_add_uint (tree, hf_wsp_header_age, header_buff, offset, headerLen, tvb_get_ntoh24 (value_buff, 0));
					break;
				case 4:
					proto_tree_add_uint (tree, hf_wsp_header_age, header_buff, offset, headerLen, tvb_get_ntohl (value_buff, 0));
					break;
			};
			break;

		case 0x08:		/* Cache-Control */
			if (peek & 0x80)
			{
				if (valueLen == 1)	/* Well-known value */
				{
					proto_tree_add_uint (tree, hf_wsp_header_cache_control, header_buff, offset, headerLen, peek);
				}
				else
				{
					if ((peek == 0x82) || (peek == 0x83) || (peek == 0x84))	/* Delta seconds value to follow */
					{
						value = tvb_get_guint8 (value_buff, 1);
						if (value & 0x80)
						{
							proto_tree_add_text (tree,
							    header_buff, 0,
							    headerLen,
							    "Cache-Control: %s %d (0x%02X)",
							    val_to_str (peek,
							        vals_cache_control,
							        "Unknown (0x%02x)"),
							        (value & 0x7F),
							        peek);
						}
						else
						{
							fprintf (stderr, "dissect_wsp: Cache-Control integer value Delta seconds NYI\n");
						}
					}
					else if ((peek == 0x80) || (peek == 0x87))	/* Fields to follow */
					{
						fprintf (stderr, "dissect_wsp: Cache-Control field values NYI\n");
					}
					else
					{
						fprintf (stderr, "dissect_wsp: Cache-Control cache extension NYI\n");
					}
				}
			}
			else
			{
				fprintf (stderr, "dissect_wsp: Cache-Control cache extension NYI\n");
			}
			break;
				
		case 0x0D:		/* Content-Length */
			if (peek & 0x80)
			{
				proto_tree_add_uint (tree, hf_wsp_header_content_length, header_buff, offset, headerLen, (peek & 0x7F));
			}
			else if (peek < 31) {
				switch (peek)
				{
					case 1:
						proto_tree_add_uint (tree, hf_wsp_header_content_length, header_buff, offset, headerLen, 
								tvb_get_guint8 (value_buff, 1) );
						break;
					case 2:
						proto_tree_add_uint (tree, hf_wsp_header_content_length, header_buff, offset, headerLen, 
								tvb_get_ntohs (value_buff, 1) );
						break;
					case 3:
						proto_tree_add_uint (tree, hf_wsp_header_content_length, header_buff, offset, headerLen, 
								(tvb_get_ntohs (value_buff, 1) << 8) + tvb_get_guint8 (value_buff, 3) );
						break;
					case 4:
						proto_tree_add_uint (tree, hf_wsp_header_content_length, header_buff, offset, headerLen, 
								tvb_get_ntohl (value_buff, 1) );
						break;
					default:
						fprintf (stderr, "dissect_wsp: accept-charset size %d NYI\n", peek);
				}
			}
			else
			{
				fprintf (stderr, "dissect_wsp: Content-Length long-integer size NYI\n");
			}
			break;
				
		case 0x12:		/* Date */
			if (peek < 31) {
				timeValue.tv_sec=0;
				timeValue.tv_usec = 0;
				switch (peek) {
					case 1:
						timeValue.tv_sec = tvb_get_guint8 (value_buff, 1);
						break;
					case 2:
						timeValue.tv_sec = tvb_get_ntohs (value_buff, 1);
						break;
					case 3:
						timeValue.tv_sec = tvb_get_ntoh24 (value_buff, 1);
						break;
					case 4:
						timeValue.tv_sec = tvb_get_ntohl (value_buff, 1);
						break;
					default:
						fprintf (stderr, "dissect_wsp: accept-charset size %d NYI\n", peek);
						break;
				}
				ti = proto_tree_add_time (tree, hf_wsp_header_date, header_buff, offset, headerLen, &timeValue);
			}
			else {
				fprintf (stderr, "dissect_wsp: accept-charset size %d NYI\n", peek);
			}
			break;

		case 0x13:		/* Etag */
			ti = proto_tree_add_string (tree, hf_wsp_header_etag,header_buff,offset,headerLen,tvb_get_ptr (value_buff, 0, valueLen));
			break;

		case 0x14:		/* Expires */
			timeValue.tv_sec = 0;
			timeValue.tv_usec = 0;
			switch (valueLen)
			{
				case 3:
					timeValue.tv_sec = tvb_get_ntoh24 (value_buff, 1);
					break;
				case 4:
					timeValue.tv_sec = tvb_get_ntohl (value_buff, 1);
					break;
				default:
					fprintf (stderr, "dissect_wsp: Expires value length %d NYI\n", valueLen);
					break;
			}
			ti = proto_tree_add_time (tree, hf_wsp_header_expires, header_buff, offset, headerLen, &timeValue);
			break;

		case 0x17:		/* If-Modified-Since */
			timeValue.tv_sec = 0;
			timeValue.tv_usec = 0;
			switch (valueLen)
			{
				case 3:
					timeValue.tv_sec = tvb_get_ntoh24 (value_buff, 1);
					break;
				case 4:
					timeValue.tv_sec = tvb_get_ntohl (value_buff, 1);
					break;
				default:
					fprintf (stderr, "dissect_wsp: If Modified Since value length %d NYI\n", valueLen);
					break;
			}
			ti = proto_tree_add_time (tree, hf_wsp_header_if_modified_since, header_buff, offset, headerLen, &timeValue);
			break;
				
		case 0x1C:		/* Location */
			ti = proto_tree_add_string (tree, hf_wsp_header_location,header_buff,offset,headerLen,tvb_get_ptr (value_buff, 0, valueLen));
			break;

		case 0x1D:		/* Last-Modified */
			timeValue.tv_sec = 0;
			timeValue.tv_usec = 0;
			switch (valueLen)
			{
				case 3:
					timeValue.tv_sec = tvb_get_ntoh24 (value_buff, 1);
					break;
				case 4:
					timeValue.tv_sec = tvb_get_ntohl (value_buff, 1);
					break;
				default:
					timeValue.tv_sec = 0;
					fprintf (stderr, "dissect_wsp: Last Modified value length %d NYI\n", valueLen);
					break;
			}
			ti = proto_tree_add_time (tree, hf_wsp_header_last_modified, header_buff, offset, headerLen, &timeValue);
			break;
				
		case 0x1F:		/* Pragma */
			if (peek == 0x80)
			{
				proto_tree_add_text (tree, header_buff, 0, headerLen, "Pragma: No-cache");
			}
			else
			{
				proto_tree_add_text (tree, header_buff, 0, headerLen, "Unsupported Header (0x%02X)", (tvb_get_guint8 (header_buff, 0) & 0x7F));
			}
			break;
				
		case 0x26:		/* Server */
			ti = proto_tree_add_string (tree, hf_wsp_header_server,header_buff,offset,headerLen,tvb_get_ptr (value_buff, 0, valueLen));
			break;

		case 0x27:		/* Transfer encoding */
			if (peek & 0x80)
			{
				proto_tree_add_uint (tree, hf_wsp_header_transfer_encoding, header_buff, offset, headerLen, peek);
			}
			else
			{
				proto_tree_add_string (tree, hf_wsp_header_transfer_encoding_str, header_buff, offset,headerLen,tvb_get_ptr (value_buff, 0, valueLen));
			}
			break;


		case 0x29:		/* User-Agent */
			ti = proto_tree_add_string (tree, hf_wsp_header_user_agent,header_buff,offset,headerLen,tvb_get_ptr (value_buff, 0, valueLen));
			break;

		case 0x2B:		/* Via */
			ti = proto_tree_add_string (tree, hf_wsp_header_via,header_buff,offset,headerLen,tvb_get_ptr (value_buff, 0, valueLen));
			break;


		default:
			ti = proto_tree_add_text (tree, header_buff, 0, headerLen, "Unsupported Header (0x%02X)", (tvb_get_guint8 (header_buff, 0) & 0x7F));
			break;
		}
	}
	else
	{
		/* Special case header X-WAP.TOD that is sometimes followed
		 * by a 4-byte date value */
		if (strncasecmp ("x-wap.tod", tvb_get_ptr (header_buff, 0, headerLen), 9) == 0)
		{
			timeValue.tv_sec = 0;
			timeValue.tv_usec = 0;
			switch( peek) {
				case 1:
					timeValue.tv_sec = tvb_get_guint8 (value_buff, 1);
					break;
				case 2:
					timeValue.tv_sec = tvb_get_ntohs (value_buff, 1);
					break;
				case 3:
					timeValue.tv_sec = (tvb_get_ntohs (value_buff, 1) << 8) +  tvb_get_guint8 (value_buff, 3);
					break;
				case 4:
					timeValue.tv_sec = tvb_get_ntohl (value_buff, 1);
					break;
				default:
					timeValue.tv_sec = 0;
					fprintf (stderr, "dissect_wsp: x-wap-top unkown\n");
					break;
			}
			ti = proto_tree_add_time (tree, hf_wsp_header_x_wap_tod, header_buff, offset, headerLen, &timeValue);
		}
		else
		{
			ti = proto_tree_add_text (tree, header_buff, 0, headerLen, "%s: %s", tvb_get_ptr (header_buff, 0, headerLen), tvb_get_ptr (value_buff, 0, valueLen));
		}
	}

}

static guint
get_value_length (tvbuff_t *tvb, guint offset, guint *nextOffset)
{
	guint value = 0;
	guint count = 0;
	guint octet = tvb_get_guint8 (tvb, offset);

	if (octet <= 30)	/* Short length */
	{
		value = octet;
		*nextOffset = offset+1;
	}
	else if (octet == 31)
	{
		value = tvb_get_guintvar (tvb, offset+1, &count);
		*nextOffset = offset+1+count;
	}
	else
	{
		fprintf (stderr, "dissect_wsp: get_value_length: case NYI\n");
	}

	return (value);
}

static guint
add_content_type (proto_tree *tree, tvbuff_t *tvb, guint offset, guint *contentType)
{
	proto_tree *contentTypeTree;
	guint nextOffset = offset;
	guint fieldLength = 0;
	guint octet = tvb_get_guint8 (tvb, offset);
	guint totalSizeOfField = 0;

	if (octet <= 31)
	{
		fieldLength = get_value_length (tvb, offset, &nextOffset);
		totalSizeOfField = (nextOffset-offset)+fieldLength;
	}
	else if (octet & 0x80)
	{
		fieldLength = 1;
		totalSizeOfField = 1;
	}
	else
	{
		fprintf (stderr, "dissect-wsp: Content-type is un-supported\n");
	}

	*contentType = (tvb_get_guint8 (tvb, nextOffset) & 0x7F);
	contentTypeTree = proto_tree_add_uint (tree, hf_wsp_content_type, tvb, offset, totalSizeOfField, (tvb_get_guint8(tvb,nextOffset++) & 0x7F));

	while (nextOffset < (offset+totalSizeOfField))
	{
		/* add_parameter */
		nextOffset = add_parameter (contentTypeTree, tvb, nextOffset);
	}

	return (offset+totalSizeOfField);
}

static guint
add_parameter (proto_tree *tree, tvbuff_t *tvb, guint offset)
{
	guint octet = tvb_get_guint8 (tvb, offset);
	if (octet & 0x80)	/* Short integer */
	{
		offset++;
		octet = octet & 0x7F;
		switch ( octet )
		{
			case 0x01:
				offset = add_parameter_charset (tree, tvb, offset, offset-1);
				break;

			default:
				fprintf (stderr, "dissect-wsp: add_parameter octet=0x%02x\n", octet);
		};
	}
	else
	{
		fprintf (stderr, "dissect-wsp: add_parameter octet=0x%02x\n", octet);
	}

	return (offset);
}

static guint
add_parameter_charset (proto_tree *tree, tvbuff_t *tvb, guint offset, guint startOffset)
{
	guint octet = tvb_get_guint8 (tvb, offset);
	if (octet < 31)
	{
		offset += octet+1;
		proto_tree_add_item (tree, hf_wsp_parameter_well_known_charset, tvb, startOffset+1, octet, bo_big_endian);
	}
	else if (octet & 0x80)
	{
		offset++;
		proto_tree_add_uint (tree, hf_wsp_parameter_well_known_charset, tvb, startOffset, offset-startOffset, (octet & 0x7F));
	}

	return offset;
}

static void
add_post_data (proto_tree *tree, tvbuff_t *tvb, guint contentType)
{
	guint offset = 0;
	guint variableStart = 0;
	guint variableEnd = 0;
	guint valueStart = 0;
	guint valueEnd = 0;
	guint8 peek = 0;
	proto_item *ti;
	
	ti = proto_tree_add_item (tree, hf_wsp_post_data,tvb,offset,tvb_reported_length(tvb),bo_little_endian);

	if (contentType == 0x12)	/* URL Encoded data */
	{
		/* Iterate through post data */
		for (offset = 0; offset < tvb_reported_length (tvb); offset++)
		{
			peek = tvb_get_guint8 (tvb, offset);
			if (peek == '=')
			{
				variableEnd = offset-1;
				valueStart = offset+1;
			}
			else if (peek == '&')
			{
				if (variableEnd > 0)
				{
					add_post_variable (ti, tvb, variableStart, variableEnd, valueStart, offset);
				}
				variableStart = offset+1;
				variableEnd = 0;
				valueStart = 0;
				valueEnd = 0;
			}
		}

		/* See if there's outstanding data */
		if (variableEnd > 0)
		{
			add_post_variable (ti, tvb, variableStart, variableEnd, valueStart, offset);
		}
	}
}

static void
add_post_variable (proto_tree *tree, tvbuff_t *tvb, guint variableStart, guint variableEnd, guint valueStart, guint valueEnd)
{
	int variableLength = variableEnd-variableStart;
	int valueLength = 0;
	char *variableBuffer;
	char *valueBuffer;

	variableBuffer = g_malloc (variableLength+1);
	strncpy (variableBuffer, tvb_get_ptr (tvb, variableStart, variableLength), variableLength+1);
	variableBuffer[variableLength+1] = 0;

	if (valueEnd == 0)
	{
		valueBuffer = g_malloc (1);
		valueBuffer[0] = 0;
		valueEnd = valueStart;
	}
	else
	{
		valueLength = valueEnd-valueStart;
		valueBuffer = g_malloc (valueLength+1);
		strncpy (valueBuffer, tvb_get_ptr (tvb, valueStart, valueLength), valueLength);
		valueBuffer[valueLength] = 0;
	}

	/* Check for variables with no value */
	if (valueStart >= tvb_reported_length (tvb))
	{
		valueStart = tvb_reported_length (tvb);
		valueEnd = valueStart;
	}
	valueLength = valueEnd-valueStart;

	proto_tree_add_text (tree, tvb, variableStart, valueEnd-variableStart, "%s: %s", variableBuffer, valueBuffer);

	g_free (variableBuffer);
	g_free (valueBuffer);
}

/* Register the protocol with Ethereal */
void
proto_register_wsp(void)
{                 

/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_wsp_header_tid,
			{ 	"Transmission ID",           
				"wsp.TID",
				 FT_UINT8, BASE_HEX, NULL, 0x00,
				"Transmission ID" 
			}
		},
		{ &hf_wsp_header_pdu_type,
			{ 	"PDU Type",           
				"wsp.pdu-type",
				 FT_UINT8, BASE_HEX, VALS( vals_pdu_type ), 0x00,
				"PDU Type" 
			}
		},
		{ &hf_wsp_version_major,
			{ 	"Version (Major)",           
				"wsp.version.major",
				 FT_UINT8, BASE_DEC, NULL, 0xF0,
				"Version (Major)" 
			}
		},
		{ &hf_wsp_version_minor,
			{ 	"Version (Minor)",           
				"wsp.version.minor",
				 FT_UINT8, BASE_DEC, NULL, 0x0F,
				"Version (Minor)" 
			}
		},
		{ &hf_wsp_capability_length,
			{ 	"Capability Length",           
				"wsp.capability.length",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Capability Length" 
			}
		},
		{ &hf_wsp_header_length,
			{ 	"Headers Length",           
				"wsp.headers-length",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Headers Length" 
			}
		},
		{ &hf_wsp_capabilities_section,
			{ 	"Capabilities",           
				"wsp.capabilities",
				 FT_NONE, BASE_DEC, NULL, 0x00,
				"Capabilities" 
			}
		},
		{ &hf_wsp_headers_section,
			{ 	"Headers",           
				"wsp.headers",
				 FT_NONE, BASE_DEC, NULL, 0x00,
				"Headers" 
			}
		},
		{ &hf_wsp_header,
			{ 	"Header",           
				"wsp.headers.header",
				 FT_NONE, BASE_DEC, NULL, 0x00,
				"Header" 
			}
		},
		{ &hf_wsp_header_uri_len,
			{ 	"URI Length",           
				"wsp.uri-length",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"URI Length" 
			}
		},
		{ &hf_wsp_header_uri,
			{ 	"URI",           
				"wsp.uri",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"URI" 
			}
		},
		{ &hf_wsp_server_session_id,
			{ 	"Server Session ID",           
				"wsp.server.session-id",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Server Session ID" 
			}
		},
		{ &hf_wsp_header_status,
			{ 	"Status",           
				"wsp.reply.status",
				 FT_UINT8, BASE_HEX, VALS( vals_status ), 0x00,
				"Status" 
			}
		},
		{ &hf_wsp_content_type,
			{ 	"Content Type",           
				"wsp.content-type.type",
				 FT_UINT8, BASE_HEX, VALS ( vals_content_types ), 0x00,
				"Content Type" 
			}
		},
		{ &hf_wsp_parameter_well_known_charset,
			{ 	"Charset",           
				"wsp.content-type.parameter.charset",
				 FT_UINT16, BASE_HEX, VALS ( vals_character_sets ), 0x00,
				"Charset" 
			}
		},
		{ &hf_wsp_reply_data,
			{ 	"Data",           
				"wsp.reply.data",
				 FT_NONE, BASE_NONE, NULL, 0x00,
				"Data" 
			}
		},
		{ &hf_wsp_header_accept,
			{ 	"Accept",           
				"wsp.header.accept",
				 /*FT_NONE, BASE_DEC, NULL, 0x00,*/
				 FT_UINT8, BASE_HEX, VALS ( vals_content_types ), 0x00,
				"Accept" 
			}
		},
		{ &hf_wsp_header_accept_str,
			{ 	"Accept",           
				"wsp.header.accept.string",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Accept" 
			}
		},
		{ &hf_wsp_header_accept_charset,
			{ 	"Accept-Charset",           
				"wsp.header.accept-charset",
				 FT_UINT16, BASE_HEX, VALS ( vals_character_sets ), 0x00,
				"Accept-Charset" 
			}
		},
		{ &hf_wsp_header_accept_charset_str,
			{ 	"Accept-Charset",           
				"wsp.header.accept-charset.string",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Accept-Charset" 
			}
		},
		{ &hf_wsp_header_accept_language,
			{ 	"Accept-Language",           
				"wsp.header.accept-language",
				 FT_UINT8, BASE_HEX, VALS ( vals_languages ), 0x00,
				"Accept-Language" 
			}
		},
		{ &hf_wsp_header_accept_language_str,
			{ 	"Accept-Language",           
				"wsp.header.accept-language.string",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Accept-Language" 
			}
		},
		{ &hf_wsp_header_accept_ranges,
			{ 	"Accept-Ranges",           
				"wsp.header.accept-ranges",
				 FT_UINT8, BASE_HEX, VALS ( vals_accept_ranges ), 0x00,
				"Accept-Ranges" 
			}
		},
		{ &hf_wsp_header_age,
			{ 	"Age",           
				"wsp.header.age",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Age" 
			}
		},
		{ &hf_wsp_header_cache_control,
			{ 	"Cache-Control",           
				"wsp.header.cache-control",
				 FT_UINT8, BASE_HEX, VALS ( vals_cache_control ), 0x00,
				"Cache-Control" 
			}
		},
		{ &hf_wsp_header_content_length,
			{ 	"Content-Length",           
				"wsp.header.content-length",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Content-Length" 
			}
		},
		{ &hf_wsp_header_date,
			{ 	"Date",           
				"wsp.header.date",
				 FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
				"Date" 
			}
		},
		{ &hf_wsp_header_etag,
			{ 	"Etag",           
				"wsp.header.etag",
				 /*FT_NONE, BASE_DEC, NULL, 0x00,*/
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Etag" 
			}
		},
		{ &hf_wsp_header_expires,
			{ 	"Expires",           
				"wsp.header.expires",
				 FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
				"Expires" 
			}
		},
		{ &hf_wsp_header_last_modified,
			{ 	"Last-Modified",           
				"wsp.header.last-modified",
				 FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
				"Last-Modified" 
			}
		},
		{ &hf_wsp_header_location,
			{ 	"Location",           
				"wsp.header.location",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Location" 
			}
		},
		{ &hf_wsp_header_if_modified_since,
			{ 	"If-Modified-Since",           
				"wsp.header.if-modified-since",
				 FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
				"If-Modified-Since" 
			}
		},
		{ &hf_wsp_header_server,
			{ 	"Server",           
				"wsp.header.server",
				 /*FT_NONE, BASE_DEC, NULL, 0x00,*/
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Server" 
			}
		},
		{ &hf_wsp_header_user_agent,
			{ 	"User-Agent",           
				"wsp.header.user-agent",
				 /*FT_NONE, BASE_DEC, NULL, 0x00,*/
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"User-Agent" 
			}
		},
		{ &hf_wsp_header_application_header,
			{ 	"Application Header",           
				"wsp.header.application-header",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Application Header" 
			}
		},
		{ &hf_wsp_header_application_value,
			{ 	"Application Header Value",           
				"wsp.header.application-header.value",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Application Header Value" 
			}
		},
		{ &hf_wsp_header_x_wap_tod,
			{ 	"X-WAP.TOD",           
				"wsp.header.x_wap_tod",
				 FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
				"X-WAP.TOD" 
			}
		},
		{ &hf_wsp_header_transfer_encoding,
			{ 	"Transfer Encoding",           
				"wsp.header.transfer_enc",
				 /*FT_NONE, BASE_DEC, NULL, 0x00,*/
				 FT_UINT8, BASE_HEX, VALS ( vals_transfer_encoding ), 0x00,
				"Transfer Encoding" 
			}
		},
		{ &hf_wsp_header_transfer_encoding_str,
			{ 	"Transfer Encoding",           
				"wsp.header.transfer_enc_str",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Transfer Encoding" 
			}
		},
		{ &hf_wsp_header_via,
			{ 	"Via",           
				"wsp.header.via",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Via" 
			}
		},
		{ &hf_wsp_post_data,
			{ 	"Post Data",           
				"wsp.post.data",
				 FT_NONE, BASE_NONE, NULL, 0x00,
				"Post Data" 
			}
		},
		{ &hf_wtls_record,
			{ 	"Record",           
				"wsp.wtls.record",
				 FT_NONE, BASE_NONE, NULL, 0x00,
				"Record" 
			}
		},
		{ &hf_wtls_record_type,
			{ 	"Record Type",           
				"wsp.wtls.rec_type",
				 FT_UINT8, BASE_DEC, VALS ( wtls_vals_record_type ), 0x0f,
				"Record Type" 
			}
		},
		{ &hf_wtls_record_length,
			{ 	"Record Length",           
				"wsp.wtls.rec_length",
				 FT_UINT16, BASE_DEC, NULL, 0x00,
				"Record Length" 
			}
		},
		{ &hf_wtls_record_sequence,
			{ 	"Record Sequence",           
				"wsp.wtls.rec_seq",
				 FT_UINT16, BASE_DEC, NULL, 0x00,
				"Record Sequence" 
			}
		},
		{ &hf_wtls_record_ciphered,
			{ 	"Record Ciphered",           
				"wsp.wtls.rec_cipher",
				 FT_NONE, BASE_DEC, NULL, 0x00,
				"Record Ciphered" 
			}
		},
		{ &hf_wtls_hands,
			{ 	"Handshake",           
				"wsp.wtls.handshake",
				 FT_NONE, BASE_DEC, NULL, 0x00,
				"Handshake" 
			}
		},
		{ &hf_wtls_hands_type,
			{ 	"Type",           
				"wsp.wtls.handshake.type",
				 FT_UINT8, BASE_HEX, VALS ( wtls_vals_handshake_type ), 0x00,
				"Type" 
			}
		},
		{ &hf_wtls_hands_length,
			{ 	"Length",           
				"wsp.wtls.handshake.length",
				 FT_UINT16, BASE_DEC, NULL, 0x00,
				"Length" 
			}
		},
		{ &hf_wtls_hands_cli_hello,
			{ 	"Client Hello",           
				"wsp.wtls.handshake.client_hello",
				 FT_NONE, BASE_NONE,NULL, 0x00,
				"Client Hello" 
			}
		},
		{ &hf_wtls_hands_cli_hello_version,
			{ 	"Version",           
				"wsp.wtls.handshake.client_hello.version",
				 FT_UINT8, BASE_DEC, NULL, 0x00,
				"Version" 
			}
		},
		{ &hf_wtls_hands_cli_hello_gmt,
			{ 	"Time GMT",           
				"wsp.wtls.handshake.client_hello.gmt",
				 FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x00,
				"Time GMT" 
			}
		},
		{ &hf_wtls_hands_cli_hello_random,
			{ 	"Random",           
				"wsp.wtls.handshake.client_hello.random",
				 FT_NONE, BASE_DEC, NULL, 0x00,
				"Random" 
			}
		},
		{ &hf_wtls_hands_cli_hello_session,
			{ 	"Session ID",           
				"wsp.wtls.handshake.client_hello.sessionid",
				 FT_NONE, BASE_DEC, NULL, 0x00,
				"Session ID" 
			}
		},
		{ &hf_wtls_hands_cli_hello_cli_key_id,
			{ 	"Client Keys",           
				"wsp.wtls.handshake.client_hello.client_keys_id",
				 FT_NONE, BASE_DEC, NULL, 0x00,
			 	"Client Keys"           
			}
		},
		{ &hf_wtls_hands_cli_hello_trust_key_id,
			{ 	"Trusted Keys",           
				"wsp.wtls.handshake.client_hello.trusted_keys_id",
				 FT_NONE, BASE_DEC, NULL, 0x00,
			 	"Trusted Keys"           
			}
		},
		{ &hf_wtls_hands_cli_hello_key_exchange,
			{ 	"Key Exchange",           
				"wsp.wtls.handshake.client_hello.key.key_exchange",
				 FT_NONE, BASE_NONE, NULL, 0x00,
				"Key Exchange" 
			}
		},
		{ &hf_wtls_hands_cli_hello_key_exchange_suite,
			{ 	"Suite",           
				"wsp.wtls.handshake.client_hello.key.key_exchange.suite",
				 FT_UINT8, BASE_HEX, VALS ( wtls_vals_key_exchange_suite ), 0x00,
				"Suite" 
			}
		},
		{ &hf_wtls_hands_cli_hello_key_parameter_index,
			{ 	"Parameter Index",           
				"wsp.wtls.handshake.client_hello.parameter_index",
				 FT_UINT8, BASE_DEC, NULL, 0x00,
				"Parameter Index" 
			}
		},
		{ &hf_wtls_hands_cli_hello_key_parameter_set,
			{ 	"Parameter Set",           
				"wsp.wtls.handshake.client_hello.parameter",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Parameter Set" 
			}
		},
		{ &hf_wtls_hands_cli_hello_key_identifier_type,
			{ 	"Identifier Type",           
				"wsp.wtls.handshake.client_hello.ident_type",
				 FT_UINT8, BASE_HEX, VALS ( wtls_vals_identifier_type ), 0x00,
				"Identifier Type" 
			}
		},
		{ &hf_wtls_hands_cli_hello_cipher_suite,
			{ 	"Cipher Suites",           
				"wsp.wtls.handshake.client_hello.ciphers",
				 FT_NONE, BASE_DEC, NULL, 0x00,
				"Cipher Suite" 
			}
		},
		{ &hf_wtls_hands_cli_hello_cipher_suite_item,
			{ 	"Cipher",           
				"wsp.wtls.handshake.client_hello.cipher",
				 FT_NONE, BASE_DEC, NULL, 0x00,
				"Cipher" 
			}
		},
		{ &hf_wtls_hands_cli_hello_cipher_bulk,
			{ 	"Cipher Bulk",           
				"wsp.wtls.handshake.client_hello.cipher.bulk",
				 FT_UINT8, BASE_HEX, VALS ( wtls_vals_cipher_bulk ), 0x00,
				"Cipher Bulk" 
			}
		},
		{ &hf_wtls_hands_cli_hello_cipher_mac,
			{ 	"Cipher MAC",           
				"wsp.wtls.handshake.client_hello.cipher.mac",
				 FT_UINT8, BASE_HEX, VALS ( wtls_vals_cipher_mac ), 0x00,
				"Cipher MAC" 
			}
		},
		{ &hf_wtls_hands_cli_hello_compression_methods,
			{ 	"Compression Methods",           
				"wsp.wtls.handshake.client_hello.comp_methods",
				 FT_NONE, BASE_DEC, NULL, 0x00,
				"Compression Methods" 
			}
		},
		{ &hf_wtls_hands_cli_hello_compression,
			{ 	"Compression",           
				"wsp.wtls.handshake.client_hello.compression",
				 FT_UINT8, BASE_HEX, VALS ( wtls_vals_compression ), 0x00,
				"Compression" 
			}
		},
		{ &hf_wtls_hands_cli_hello_sequence_mode,
			{ 	"Sequence Mode",           
				"wsp.wtls.handshake.client_hello.sequence_mode",
				 FT_UINT8, BASE_HEX, VALS ( wtls_vals_sequence_mode ), 0x00,
				"Sequence Mode" 
			}
		},
		{ &hf_wtls_hands_cli_hello_key_refresh,
			{ 	"Refresh",           
				"wsp.wtls.handshake.client_hello.refresh",
				 FT_UINT8, BASE_DEC,NULL, 0x00,
				"Refresh" 
			}
		},
		{ &hf_wtls_hands_serv_hello,
			{ 	"Server Hello",           
				"wsp.wtls.handshake.server_hello",
				 FT_NONE, BASE_NONE,NULL, 0x00,
				"Server Hello" 
			}
		},
		{ &hf_wtls_hands_serv_hello_version,
			{ 	"Version",           
				"wsp.wtls.handshake.server_hello.version",
				 FT_UINT8, BASE_DEC, NULL, 0x00,
				"Version" 
			}
		},
		{ &hf_wtls_hands_serv_hello_gmt,
			{ 	"Time GMT",           
				"wsp.wtls.handshake.server_hello.gmt",
				 FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x00,
				"Time GMT" 
			}
		},
		{ &hf_wtls_hands_serv_hello_random,
			{ 	"Random",           
				"wsp.wtls.handshake.server_hello.random",
				 FT_NONE, BASE_DEC, NULL, 0x00,
				"Random" 
			}
		},
		{ &hf_wtls_hands_serv_hello_session,
			{ 	"Session ID",           
				"wsp.wtls.handshake.server_hello.sessionid",
				 FT_NONE, BASE_DEC, NULL, 0x00,
				"Session ID" 
			}
		},
		{ &hf_wtls_hands_serv_hello_cli_key_id,
			{ 	"Client Key ID",           
				"wsp.wtls.handshake.server_hello.key",
				 FT_UINT8, BASE_HEX, NULL, 0x00,
				"Client Key ID" 
			}
		},
		{ &hf_wtls_hands_serv_hello_cipher_suite_item,
			{ 	"Cipher",           
				"wsp.wtls.handshake.server_hello.cipher",
				 FT_NONE, BASE_DEC, NULL, 0x00,
				"Cipher" 
			}
		},
		{ &hf_wtls_hands_serv_hello_cipher_bulk,
			{ 	"Cipher Bulk",           
				"wsp.wtls.handshake.server_hello.cipher.bulk",
				 FT_UINT8, BASE_HEX, VALS ( wtls_vals_cipher_bulk ), 0x00,
				"Cipher Bulk" 
			}
		},
		{ &hf_wtls_hands_serv_hello_cipher_mac,
			{ 	"Cipher MAC",           
				"wsp.wtls.handshake.server_hello.cipher.mac",
				 FT_UINT8, BASE_HEX, VALS ( wtls_vals_cipher_mac ), 0x00,
				"Cipher MAC" 
			}
		},
		{ &hf_wtls_hands_serv_hello_compression,
			{ 	"Compression",           
				"wsp.wtls.handshake.server_hello.compression",
				 FT_UINT8, BASE_HEX, VALS ( wtls_vals_compression ), 0x00,
				"Compression" 
			}
		},
		{ &hf_wtls_hands_serv_hello_sequence_mode,
			{ 	"Sequence Mode",           
				"wsp.wtls.handshake.server_hello.sequence_mode",
				 FT_UINT8, BASE_HEX, VALS ( wtls_vals_sequence_mode ), 0x00,
				"Sequence Mode" 
			}
		},
		{ &hf_wtls_hands_serv_hello_key_refresh,
			{ 	"Refresh",           
				"wsp.wtls.handshake.server_hello.refresh",
				 FT_UINT8, BASE_DEC,NULL, 0x00,
				"Refresh" 
			}
		},
		{ &hf_wtls_hands_certificates,
			{ 	"Certificates",
				"wsp.wtls.handshake.certificates",
				 FT_NONE, BASE_DEC, NULL, 0x00,
				"Certificates" 
			}
		},
		{ &hf_wtls_hands_certificate,
			{ 	"Certificate",           
				"wsp.wtls.handshake.certificate",
				 FT_NONE, BASE_DEC, NULL, 0x00,
				"Certificate" 
			}
		},
		{ &hf_wtls_hands_certificate_type,
			{ 	"Type",           
				"wsp.wtls.handshake.certificate.type",
				 FT_UINT8, BASE_HEX, VALS ( wtls_vals_certificate_type ), 0x00,
				"Type" 
			}
		},
		{ &hf_wtls_hands_certificate_wtls_version,
			{ 	"Version",           
				"wsp.wtls.handshake.certificate.version",
				 FT_UINT8, BASE_HEX, NULL, 0x00,
				"Version" 
			}
		},
		{ &hf_wtls_hands_certificate_wtls_signature_type,
			{ 	"Signature Type",           
				"wsp.wtls.handshake.certificate.signature.type",
				 FT_UINT8, BASE_HEX, VALS ( wtls_vals_certificate_signature ), 0x00,
				"Signature Type" 
			}
		},
		{ &hf_wtls_hands_certificate_wtls_signature,
			{ 	"Signature",           
				"wsp.wtls.handshake.certificate.signature.signature",
				 FT_NONE, BASE_HEX, NULL, 0x00,
				"Signature" 
			}
		},
		{ &hf_wtls_hands_certificate_wtls_issuer_type,
			{ 	"Issuer",           
				"wsp.wtls.handshake.certificate.issuer.type",
				 FT_UINT8, BASE_HEX, VALS ( wtls_vals_identifier_type ), 0x00,
				"Issuer" 
			}
		},
		{ &hf_wtls_hands_certificate_wtls_issuer_charset,
			{ 	"Charset",           
				"wsp.wtls.handshake.certificate.issuer.charset",
				 FT_UINT16, BASE_HEX, VALS ( vals_character_sets ), 0x00,
				"Charset" 
			}
		},
		{ &hf_wtls_hands_certificate_wtls_issuer_name,
			{ 	"Name",           
				"wsp.wtls.handshake.certificate.issuer.name",
				 FT_NONE, BASE_HEX, NULL, 0x00,
				"Name" 
			}
		},
		{ &hf_wtls_hands_certificate_wtls_valid_not_before,
			{ 	"Valid not before",           
				"wsp.wtls.handshake.certificate.before",
				 FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x00,
				"Valid not before" 
			}
		},
		{ &hf_wtls_hands_certificate_wtls_valid_not_after,
			{ 	"Valid not after",           
				"wsp.wtls.handshake.certificate.after",
				 FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x00,
				"Valid not after" 
			}
		},
		{ &hf_wtls_hands_certificate_wtls_subject_type,
			{ 	"Subject",           
				"wsp.wtls.handshake.certificate.subject.type",
				 FT_UINT8, BASE_HEX, VALS ( wtls_vals_identifier_type ), 0x00,
				"Subject" 
			}
		},
		{ &hf_wtls_hands_certificate_wtls_subject_charset,
			{ 	"Charset",           
				"wsp.wtls.handshake.certificate.subject.charset",
				 FT_UINT16, BASE_HEX, VALS ( vals_character_sets ), 0x00,
				"Charset" 
			}
		},
		{ &hf_wtls_hands_certificate_wtls_subject_name,
			{ 	"Name",           
				"wsp.wtls.handshake.certificate.subject.name",
				 FT_NONE, BASE_HEX, NULL, 0x00,
				"Name" 
			}
		},
		{ &hf_wtls_hands_certificate_wtls_public_key_type,
			{ 	"Public Key Type",           
				"wsp.wtls.handshake.certificate.public.type",
				 FT_UINT8, BASE_HEX, VALS ( wtls_vals_public_key_type ), 0x00,
				"Public Key Type" 
			}
		},
		{ &hf_wtls_hands_certificate_wtls_key_parameter_index,
			{ 	"Parameter Index",           
				"wsp.wtls.handshake.certificate.parameter_index",
				 FT_UINT8, BASE_DEC, NULL, 0x00,
				"Parameter Index" 
			}
		},
		{ &hf_wtls_hands_certificate_wtls_key_parameter_set,
			{ 	"Parameter Set",           
				"wsp.wtls.handshake.certificate.parameter",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Parameter Set" 
			}
		},
		{ &hf_wtls_hands_certificate_wtls_rsa_exponent,
			{ 	"RSA Exponent",           
				"wsp.wtls.handshake.certificate.rsa.exponent",
				 FT_NONE, BASE_HEX, NULL, 0x00,
				"RSA Exponent" 
			}
		},
		{ &hf_wtls_hands_certificate_wtls_rsa_modules,
			{ 	"RSA Modulus",           
				"wsp.wtls.handshake.certificate.rsa.modulus",
				 FT_NONE, BASE_HEX, NULL, 0x00,
				"RSA Modulus" 
			}
		},
		{ &hf_wtls_alert,
			{ 	"Alert",           
				"wsp.wtls.alert",
				 FT_NONE, BASE_HEX, NULL, 0x00,
				"Alert" 
			}
		},
		{ &hf_wtls_alert_level,
			{ 	"Level",           
				"wsp.wtls.alert.level",
				 FT_UINT8, BASE_HEX, VALS ( wtls_vals_alert_level ), 0x00,
				"Level" 
			}
		},
		{ &hf_wtls_alert_description,
			{ 	"Description",           
				"wsp.wtls.alert.description",
				 FT_UINT8, BASE_HEX, VALS ( wtls_vals_alert_description ), 0x00,
				"Description" 
			}
		},
	};
	
/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_wsp,
		&ett_header,
		&ett_headers,
		&ett_capabilities,
		&ett_content_type,
		&ett_wtls_rec,
		&ett_wtls_msg_type,
		&ett_wtls_msg_type_item,
		&ett_wtls_msg_type_item_sub,
		&ett_wtls_msg_type_item_sub_sub,
	};

/* Register the protocol name and description */
	proto_wsp = proto_register_protocol(
		"Wireless Session Protocol",   	/* protocol name for use by ethereal */ 
		"WSP",                          /* short version of name */
		"wap-wsp"                    	/* Abbreviated protocol name, should Match IANA 
						    < URL:http://www.isi.edu/in-notes/iana/assignments/port-numbers/ >
						  */
	);

	proto_wtls = proto_register_protocol(
		"Wireless Transport Layer Security",   	/* protocol name for use by ethereal */ 
		"WTLS",                          /* short version of name */
		"wap-wtls"                    	/* Abbreviated protocol name, should Match IANA 
						    < URL:http://www.isi.edu/in-notes/iana/assignments/port-numbers/ >
						  */
	);

/* Required function calls to register the header fields and subtrees used  */
	proto_register_field_array(proto_wsp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("wsp", dissect_wsp, proto_wsp);
	register_dissector("wtls", dissect_wtls, proto_wtls);
};

void
proto_reg_handoff_wsp(void)
{
	/* Only connection-less WSP has no previous handler */
	dissector_add("udp.port", UDP_PORT_WSP, dissect_wsp, proto_wsp);
	/* dissector_add("udp.port", UDP_PORT_WTP_WSP, dissect_wsp, proto_wsp); */
	dissector_add("udp.port", UDP_PORT_WTLS_WSP, dissect_wtls, proto_wtls); 
	/* dissector_add("udp.port", UDP_PORT_WTLS_WTP_WSP, dissect_wsp, proto_wsp); */
}
