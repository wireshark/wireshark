/* packet-wtls.c
 *
 * Routines to dissect WTLS component of WAP traffic.
 * 
 * $Id: packet-wtls.c,v 1.3 2001/02/19 21:02:33 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Didier Jorand
 *
 * WAP dissector based on original work by Ben Fowler
 * Updated by Neil Hunter <neil.hunter@energis-squared.com>
 * WTLS support by Alexandre P. Ferreira (Splice IP)
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
#include "packet-wtls.h"

/* File scoped variables for the protocol and registered fields */
static int proto_wtls 							= HF_EMPTY;

/* These fields used by fixed part of header */
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
static gint ett_wtls 							= ETT_EMPTY;
static gint ett_wtls_rec                              = ETT_EMPTY;
static gint ett_wtls_msg_type                                 = ETT_EMPTY;
static gint ett_wtls_msg_type_item                    = ETT_EMPTY;
static gint ett_wtls_msg_type_item_sub                        = ETT_EMPTY;
static gint ett_wtls_msg_type_item_sub_sub            = ETT_EMPTY;

/* Handles for WTP and WSP dissectors */
static dissector_handle_t wtp_handle;
static dissector_handle_t wsp_handle;

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

static void dissect_wtls_handshake (proto_tree *, tvbuff_t *, guint, guint);

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
		switch ( pinfo->match_port )
		{
			case UDP_PORT_WTLS_WSP:
				col_set_str(fdata, COL_PROTOCOL, "WTLS+WSP" );
				break;
			case UDP_PORT_WTLS_WTP_WSP:
				col_set_str(fdata, COL_PROTOCOL, "WTLS+WTP+WSP" );
				break;
		}
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
		wtls_tree = proto_item_add_subtree(ti, ett_wtls);

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
			ti = proto_tree_add_uint(wtls_tree, hf_wtls_record, tvb, offset_wtls,
				 count, pdut);
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
	char valStr[1024];

	proto_item *ti;
	proto_item *cli_key_item;
	proto_tree *wtls_msg_type_tree;
	proto_tree *wtls_msg_type_item_tree;
	proto_tree *wtls_msg_type_item_sub_tree;
	proto_tree *wtls_msg_type_item_sub_sub_tree;

	pdu_msg_type = tvb_get_guint8 (tvb, offset);
	ti = proto_tree_add_uint(tree, hf_wtls_hands, tvb, offset,count, pdu_msg_type);
	wtls_msg_type_tree = proto_item_add_subtree(ti, ett_wtls_msg_type);
	
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
				value = tvb_get_guint8 (tvb, offset);
				cli_key_item = proto_tree_add_uint(wtls_msg_type_item_sub_tree, 
						hf_wtls_hands_cli_hello_key_exchange, tvb, offset,1,
						value);
				client_size=1;
				wtls_msg_type_item_sub_sub_tree = proto_item_add_subtree(cli_key_item, 
								  ett_wtls_msg_type_item_sub_sub);
				ti = proto_tree_add_uint(wtls_msg_type_item_sub_sub_tree,
						hf_wtls_hands_cli_hello_key_exchange_suite,
						tvb,offset,1,value);
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
				value = tvb_get_guint8 (tvb, offset);
				cli_key_item = proto_tree_add_uint(wtls_msg_type_item_sub_tree, 
						hf_wtls_hands_cli_hello_key_exchange, tvb, offset,1,
						value);
				client_size=1;
				wtls_msg_type_item_sub_sub_tree = proto_item_add_subtree(cli_key_item, 
								  ett_wtls_msg_type_item_sub_sub);
				ti = proto_tree_add_uint(wtls_msg_type_item_sub_sub_tree,
						hf_wtls_hands_cli_hello_key_exchange_suite,
						tvb,offset,1,value);
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
								strncpy(valStr,tvb_get_ptr (tvb, offset+1, value),value);
								valStr[value]=0;
								ti = proto_tree_add_string(
										wtls_msg_type_item_sub_tree, 
										hf_wtls_hands_certificate_wtls_issuer_name,
										tvb, offset,1+value,
										valStr);
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
								strncpy(valStr,tvb_get_ptr (tvb, offset+1, value),value);
								valStr[value]=0;
								ti = proto_tree_add_string(
										wtls_msg_type_item_sub_tree, 
										hf_wtls_hands_certificate_wtls_subject_name,
										tvb, offset,1+value,
										valStr);
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
								ti = proto_tree_add_uint(wtls_msg_type_item_sub_tree,
									hf_wtls_hands_certificate_wtls_rsa_exponent,
									tvb,offset,value+2,value*8);
								offset+=2+value;
								client_size+=2+value;
								value = tvb_get_ntohs (tvb, offset);
								ti = proto_tree_add_uint(wtls_msg_type_item_sub_tree,
									hf_wtls_hands_certificate_wtls_rsa_modules,
									tvb,offset,value+2,value*8);
								offset+=2+value;
								client_size+=2+value;
								break;
							case PUBLIC_KEY_ECDH :
								break;
							case PUBLIC_KEY_ECDSA :
								break;
						}
						value = tvb_get_ntohs (tvb, offset);
						ti = proto_tree_add_uint(wtls_msg_type_item_sub_tree,
							hf_wtls_hands_certificate_wtls_signature,
							tvb,offset,2+value,value*8);
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

/* Register the protocol with Ethereal */
void
proto_register_wtls(void)
{                 

/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_wtls_record,
			{ 	"Record",           
				"wsp.wtls.record",
				 FT_UINT8, BASE_NONE, VALS ( wtls_vals_record_type ), 0x0f,
				"Record" 
			}
		},
		{ &hf_wtls_record_type,
			{ 	"Record Type",           
				"wsp.wtls.rec_type",
				 FT_UINT8, BASE_NONE, VALS ( wtls_vals_record_type ), 0x0f,
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
				 FT_UINT8, BASE_HEX, VALS ( wtls_vals_handshake_type ), 0x00,
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
				 FT_UINT8, BASE_HEX, VALS ( wtls_vals_key_exchange_suite ), 0x00,
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
			{ 	"Signature Size",           
				"wsp.wtls.handshake.certificate.signature.signature",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Signature Size" 
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
				 FT_STRING, BASE_NONE, NULL, 0x00,
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
				 FT_STRING, BASE_NONE, NULL, 0x00,
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
			{ 	"RSA Exponent Size",           
				"wsp.wtls.handshake.certificate.rsa.exponent",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"RSA Exponent Size" 
			}
		},
		{ &hf_wtls_hands_certificate_wtls_rsa_modules,
			{ 	"RSA Modulus Size",           
				"wsp.wtls.handshake.certificate.rsa.modulus",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"RSA Modulus Size" 
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
		&ett_wtls,
		&ett_wtls_rec,
		&ett_wtls_msg_type,
		&ett_wtls_msg_type_item,
		&ett_wtls_msg_type_item_sub,
		&ett_wtls_msg_type_item_sub_sub,
	};

/* Register the protocol name and description */
	proto_wtls = proto_register_protocol(
		"Wireless Transport Layer Security",   	/* protocol name for use by ethereal */ 
		"WTLS",                          /* short version of name */
		"wap-wtls"                    	/* Abbreviated protocol name, should Match IANA 
						    < URL:http://www.isi.edu/in-notes/iana/assignments/port-numbers/ >
						  */
	);

/* Required function calls to register the header fields and subtrees used  */
	proto_register_field_array(proto_wtls, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("wtls", dissect_wtls, proto_wtls);
};

void
proto_reg_handoff_wtls(void)
{
	/*
	 * Get handles for the IP WTP and WSP dissectors
	 */
	wtp_handle = find_dissector("wtp");
	wsp_handle = find_dissector("wsp");

	dissector_add("udp.port", UDP_PORT_WTLS_WSP,     dissect_wtls, proto_wtls); 
	dissector_add("udp.port", UDP_PORT_WTLS_WTP_WSP, dissect_wtls, proto_wtls);
}
