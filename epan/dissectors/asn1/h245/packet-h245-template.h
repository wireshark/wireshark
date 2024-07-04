/* packet-h245.h
 * Routines for h245 packet dissection
 * Copyright 2005, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_H245_H
#define PACKET_H245_H

#include "ws_symbol_export.h"

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
        char frame_label[50];          /* the Frame label used by graph_analysis, what is an abbreviation of cinfo */
        char comment[50];                      /* the Frame Comment used by graph_analysis, what is a message desc */
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
	uint8_t control_field_octets;
	uint32_t send_buffer_size;
} h223_al3_params;

typedef struct {
	h223_al_type al_type;
	void *al_params;
	bool segmentable;
	dissector_handle_t subdissector;
} h223_lc_params;

typedef enum {
	H245_nonStandardDataType,
	H245_nullData,
	H245_videoData,
	H245_audioData,
	H245_data,
	H245_encryptionData,
	/*...,*/
	H245_h235Control,
	H245_h235Media,
	H245_multiplexedStream,
	H245_redundancyEncoding,
	H245_multiplePayloadStream,
	H245_fec
} h245_lc_data_type_enum;

typedef struct {
	h245_lc_data_type_enum data_type;
	void *                 params;
} h245_lc_data_type;

/*
 * h223 MUX info
 */

typedef struct _h223_mux_element h223_mux_element;
struct _h223_mux_element {
    h223_mux_element* sublist; /* if NULL, use vc instead */
    uint16_t vc;
    uint16_t repeat_count; /* 0 == untilClosingFlag */
    h223_mux_element* next;
};

#include <epan/packet_info.h>
#include "packet-per.h"

typedef void (*h223_set_mc_handle_t) ( packet_info* pinfo, uint8_t mc, h223_mux_element* me);
WS_DLL_PUBLIC void h245_set_h223_set_mc_handle( h223_set_mc_handle_t handle );

typedef void (*h223_add_lc_handle_t) ( packet_info* pinfo, uint16_t lc, h223_lc_params* params);
WS_DLL_PUBLIC void h245_set_h223_add_lc_handle( h223_add_lc_handle_t handle );

#include "packet-h245-exp.h"
void dissect_h245_FastStart_OLC(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, char *codec_str);


#endif  /* PACKET_H245_H */


