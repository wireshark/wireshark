/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-h245.h                                                            */
/* ../../tools/asn2wrs.py -e -p h245 -c h245.cnf -s packet-h245-template h245.asn */

/* Input file: packet-h245-template.h */

#line 1 "packet-h245-template.h"
/* packet-h245.h
 * Routines for h245 packet dissection
 * Copyright 2005, Anders Broman <anders.broman@ericsson.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef PACKET_H245_H
#define PACKET_H245_H
typedef enum _h245_msg_type {
	H245_TermCapSet,
	H245_TermCapSetAck,
	H245_TermCapSetRjc,
	H245_TermCapSetRls,
	H245_OpenLogChn,
	H245_OpenLogChnCnf,
	H245_OpenLogChnAck,
	H245_OpenLogChnRjc,	
	H245_CloseLogChn,
	H245_CloseLogChnAck,
	H245_MastSlvDet,
	H245_MastSlvDetAck,
	H245_MastSlvDetRjc,
	H245_MastSlvDetRls,
        H245_OTHER
} h245_msg_type;

typedef struct _h245_packet_info {
        h245_msg_type msg_type;         /* type of message */
        gchar frame_label[50];          /* the Frame label used by graph_analysis, what is a abreviation of cinfo */
        gchar comment[50];                      /* the Frame Comment used by graph_analysis, what is a message desc */
} h245_packet_info;

/*
 * h223 LC info
 */

typedef enum {
	al_nonStandard,
	al1Framed,
	al1NotFramed,
	al2WithoutSequenceNumbers,
	al2WithSequenceNumbers,
	al3,
	/*...*/
	/* al?M: unimplemented annex C adaptation layers */
	al1M,
	al2M,
	al3M
} h223_al_type;

typedef struct {
	guint8 control_field_octets;
	guint32 send_buffer_size;
} h223_al3_params;

typedef struct {
	h223_al_type al_type;
	gpointer al_params;
	gboolean segmentable;
	dissector_handle_t subdissector;
} h223_lc_params;

typedef enum {
	nonStandardDataType,
	nullData,
	videoData,
	audioData,
	data,
	encryptionData,
	/*...,*/
	h235Control,
	h235Media,
	multiplexedStream,
	redundancyEncoding,
	multiplePayloadStream,
	fec
} h245_lc_data_type_enum;

typedef struct {
	h245_lc_data_type_enum data_type;
	gpointer               params;
} h245_lc_data_type;

/*
 * h223 MUX info
 */

typedef struct _h223_mux_element h223_mux_element;
struct _h223_mux_element {
    h223_mux_element* sublist; /* if NULL, use vc instead */
    guint16 vc;
    guint16 repeat_count; /* 0 == untilClosingFlag */
    h223_mux_element* next;
};

#include <epan/packet_info.h>
#include "packet-per.h"

typedef void (*h223_set_mc_handle_t) ( packet_info* pinfo, guint8 mc, h223_mux_element* me );
extern void h245_set_h223_set_mc_handle( h223_set_mc_handle_t handle );

typedef void (*h223_add_lc_handle_t) ( packet_info* pinfo, guint16 lc, h223_lc_params* params );
extern void h245_set_h223_add_lc_handle( h223_add_lc_handle_t handle );


/*--- Included file: packet-h245-exp.h ---*/
#line 1 "packet-h245-exp.h"
extern const value_string DataProtocolCapability_vals[];
int dissect_h245_DataProtocolCapability(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_h245_T38FaxProfile(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_h245_OpenLogicalChannel(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree, int hf_index);

/*--- End of included file: packet-h245-exp.h ---*/
#line 125 "packet-h245-template.h"
void dissect_h245_OpenLogicalChannelCodec(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, char *codec_str);


#endif  /* PACKET_H245_H */


