/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-snmp.h                                                              */
/* asn2wrs.py -b -p snmp -c ./snmp.cnf -s ./packet-snmp-template -D . -O ../.. snmp.asn */

/* Input file: packet-snmp-template.h */

#line 1 "./asn1/snmp/packet-snmp-template.h"
/* packet-snmp.h
 * Routines for snmp packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_SNMP_H
#define PACKET_SNMP_H

#define SNMP_REQ_GET                0
#define SNMP_REQ_GETNEXT            1
#define SNMP_REQ_SET                3
#define SNMP_REQ_GETBULK            5
#define SNMP_REQ_INFORM             6

#define SNMP_RES_GET                2

#define SNMP_TRAP                   4
#define SNMP_TRAPV2                 7
#define SNMP_REPORT                 8

typedef struct _snmp_usm_key {
	guint8* data;
	guint len;
} snmp_usm_key_t;

typedef struct _snmp_ue_assoc_t snmp_ue_assoc_t;
typedef struct _snmp_usm_params_t snmp_usm_params_t;

typedef tvbuff_t* (*snmp_usm_decoder_t)(snmp_usm_params_t*, tvbuff_t* encryptedData, packet_info *pinfo, gchar const** error);

typedef enum _snmp_usm_auth_model_t {
	SNMP_USM_AUTH_MD5 = 0,
	SNMP_USM_AUTH_SHA1,
	SNMP_USM_AUTH_SHA2_224,
	SNMP_USM_AUTH_SHA2_256,
	SNMP_USM_AUTH_SHA2_384,
	SNMP_USM_AUTH_SHA2_512
} snmp_usm_auth_model_t;

typedef struct _snmp_user_t {
	snmp_usm_key_t userName;

	snmp_usm_auth_model_t authModel;
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
	guint32 snmp_time;
	tvbuff_t* engine_tvb;
	tvbuff_t* user_tvb;
	proto_item* auth_item;
	tvbuff_t* auth_tvb;
	tvbuff_t* priv_tvb;
	tvbuff_t* msg_tvb;
	snmp_ue_assoc_t* user_assoc;

	gboolean authOK;
};

typedef struct snmp_request_response {
	guint32 request_frame_id;
	guint32 response_frame_id;
	nstime_t request_time;
	guint requestId;
	guint request_procedure_id;
} snmp_request_response_t;

/*
 * Guts of the SNMP dissector - exported for use by protocols such as
 * ILMI.
 */
extern guint dissect_snmp_pdu(tvbuff_t *, int, packet_info *, proto_tree *tree,
    int, gint, gboolean);
extern int dissect_snmp_engineid(proto_tree *, packet_info *, tvbuff_t *, int, int);

/*#include "packet-snmp-exp.h"*/

#endif  /* PACKET_SNMP_H */
