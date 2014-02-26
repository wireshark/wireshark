/* packet-snmp.h
 * Routines for snmp packet dissection
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

#ifndef PACKET_SNMP_H
#define PACKET_SNMP_H

typedef struct _snmp_usm_key {
	guint8* data;
	guint len;
} snmp_usm_key_t;

typedef struct _snmp_ue_assoc_t snmp_ue_assoc_t;
typedef struct _snmp_usm_params_t snmp_usm_params_t;

typedef gboolean (*snmp_usm_authenticator_t)(snmp_usm_params_t*, guint8** calc_auth, guint* calc_auth_len, gchar const** error);
typedef tvbuff_t* (*snmp_usm_decoder_t)(snmp_usm_params_t*, tvbuff_t* encryptedData, gchar const** error);
typedef void (*snmp_usm_password_to_key_t)(const guint8 *password, guint passwordlen, const guint8 *engineID, guint engineLength, guint8 *key);

typedef struct _snmp_usm_auth_model_t {
	snmp_usm_password_to_key_t pass2key;
	snmp_usm_authenticator_t authenticate;
	guint key_size;
} snmp_usm_auth_model_t;

typedef struct _snmp_user_t {
	snmp_usm_key_t userName;

	snmp_usm_auth_model_t* authModel;
	snmp_usm_key_t authPassword;
	snmp_usm_key_t authKey;

	snmp_usm_decoder_t privProtocol;
	snmp_usm_key_t privPassword;
	snmp_usm_key_t privKey;
} snmp_user_t;

typedef struct {
	guint8* data;
	guint len;
} snmp_engine_id_t;

struct _snmp_ue_assoc_t {
	snmp_user_t user;
	snmp_engine_id_t engine;
	guint	auth_model;
	guint	priv_proto;
	struct _snmp_ue_assoc_t* next;
};

struct _snmp_usm_params_t {
	gboolean authenticated;
	gboolean encrypted;
	guint start_offset;
	guint auth_offset;

	guint32 boots;
	guint32 time;
	tvbuff_t* engine_tvb;
	tvbuff_t* user_tvb;
	proto_item* auth_item;
	tvbuff_t* auth_tvb;
	tvbuff_t* priv_tvb;
	tvbuff_t* msg_tvb;
	snmp_ue_assoc_t* user_assoc;

	gboolean authOK;
};

/*
 * Guts of the SNMP dissector - exported for use by protocols such as
 * ILMI.
 */
extern guint dissect_snmp_pdu(tvbuff_t *, int, packet_info *, proto_tree *tree,
    int, gint, gboolean);
extern int dissect_snmp_engineid(proto_tree *, tvbuff_t *, int, int);

/*#include "packet-snmp-exp.h"*/

#endif  /* PACKET_SNMP_H */
