/* packet-t38.h
 *
 * Routines for T38 dissection
 * 2003 Hans Viens
 * 2004 Alejandro Vaquero, add support to conversation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ws_symbol_export.h"

#define MAX_T38_DATA_ITEMS 4
#define MAX_T38_DESC 128

typedef struct _t38_packet_info {
	uint16_t seq_num;	/* UDPTLPacket sequence number */
	int32_t type_msg;	/* 0=t30-indicator    1=data */
	uint32_t t30ind_value;
	uint32_t data_value;	/* standard and speed */
	uint32_t setup_frame_number;
	uint32_t Data_Field_field_type_value;
	uint8_t	t30_Facsimile_Control;
	char    desc[MAX_T38_DESC]; /* Description used to be displayed in the frame label Graph Analysis */
	char    desc_comment[MAX_T38_DESC]; /* Description used to be displayed in the Comment Graph Analysis */
	double time_first_t4_data;
	uint32_t frame_num_first_t4_data;
} t38_packet_info;


#define MAX_T38_SETUP_METHOD_SIZE 7


/* Info to save the State to reassemble Data (e.g. HDLC) and the Setup (e.g. SDP) in T38 conversations */
typedef struct _t38_conv_info t38_conv_info;

struct _t38_conv_info {

	uint32_t reass_ID;
	int reass_start_seqnum;
	uint32_t reass_start_data_field;
	uint32_t reass_data_type;
	int32_t last_seqnum; /* used to avoid duplicated seq num shown in the Graph Analysis */
	uint32_t packet_lost;
	uint32_t burst_lost;
	double time_first_t4_data;
	uint32_t additional_hdlc_data_field_counter;
	int32_t seqnum_prev_data_field;
	t38_conv_info *next;

};

/* Info to save the State to reassemble Data (e.g. HDLC) and the Setup (e.g. SDP) in T38 conversations */
typedef struct _t38_conv
{
	char    setup_method[MAX_T38_SETUP_METHOD_SIZE + 1];
	uint32_t setup_frame_number;
	t38_conv_info src_t38_info;
	t38_conv_info dst_t38_info;
} t38_conv;

/* Add an T38 conversation with the given details */
WS_DLL_PUBLIC
void t38_add_address(packet_info *pinfo,
                     address *addr, int port,
                     int other_port,
                     const char *setup_method, uint32_t setup_frame_number);


#include "packet-t38-exp.h"



