/* packet-t38.c
 * Routines for T.38 packet dissection
 * 2003  Hans Viens
 * 2004  Alejandro Vaquero, add support Conversations for SDP
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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


/* Depending on what ASN.1 specification is used you may have to change
 * the preference setting regarding Pre-Corrigendum ASN.1 specification:
 * http://www.itu.int/ITU-T/asn1/database/itu-t/t/t38/1998/T38.html  (Pre-Corrigendum=TRUE)
 * http://www.itu.int/ITU-T/asn1/database/itu-t/t/t38/2003/T38(1998).html (Pre-Corrigendum=TRUE)
 *
 * http://www.itu.int/ITU-T/asn1/database/itu-t/t/t38/2003/T38(2002).html (Pre-Corrigendum=FALSE)
 * http://www.itu.int/ITU-T/asn1/database/itu-t/t/t38/2002/t38.html  (Pre-Corrigendum=FALSE)
 * http://www.itu.int/ITU-T/asn1/database/itu-t/t/t38/2002-Amd1/T38.html (Pre-Corrigendum=FALSE)
 */

/* TO DO:  
 * - TCP desegmentation is currently not supported for T.38 IFP directly over TCP. 
 * - H.245 dissectors should be updated to start conversations for T.38 similar to RTP.
 * - It would be nice if we could dissect the T.30 data.
 * - Sometimes the last octet is not high-lighted when selecting something in the tree. Bug in PER dissector? 
 * - Add support for RTP payload audio/t38 (draft-jones-avt-audio-t38-03.txt), i.e. T38 in RTP packets.
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-t38.h"
#include <epan/prefs.h>
#include <epan/ipproto.h>
#include "packet-per.h"
#include <epan/prefs.h>
#include "packet-tpkt.h"
#include <epan/emem.h>

#define PORT_T38 6004  
static guint global_t38_tcp_port = PORT_T38;
static guint global_t38_udp_port = PORT_T38;

/*
* Variables to allow for proper deletion of dissector registration when
* the user changes port from the gui.
*/
static guint tcp_port = 0;
static guint udp_port = 0;

/* dissect using the Pre Corrigendum T.38 ASN.1 specification (1998) */
static gboolean use_pre_corrigendum_asn1_specification = TRUE;

/* dissect packets that looks like RTP version 2 packets as RTP     */
/* instead of as T.38. This may result in that some T.38 UPTL       */
/* packets with sequence number values higher than 32767 may be     */
/* shown as RTP packets.                                            */ 
static gboolean dissect_possible_rtpv2_packets_as_rtp = FALSE;


/* Reassembly of T.38 PDUs over TPKT over TCP */
static gboolean t38_tpkt_reassembly = TRUE;


/* Preference setting whether TPKT header is used when sending T.38 over TCP.
 * The default setting is Maybe where the dissector will look on the first
 * bytes to try to determine whether TPKT header is used or not. This may not
 * work so well in some cases. You may want to change the setting to Always or
 * Newer.
 */
#define T38_TPKT_NEVER 0   /* Assume that there is never a TPKT header    */
#define T38_TPKT_ALWAYS 1  /* Assume that there is always a TPKT header   */
#define T38_TPKT_MAYBE 2   /* Assume TPKT if first octets are 03-00-xx-xx */
static gint t38_tpkt_usage = T38_TPKT_MAYBE;

static const enum_val_t t38_tpkt_options[] = {
  {"never", "Never", T38_TPKT_NEVER},
  {"always", "Always", T38_TPKT_ALWAYS},
  {"maybe", "Maybe", T38_TPKT_MAYBE},
  {NULL, NULL, -1}
};


static dissector_handle_t t38_udp_handle;
static dissector_handle_t t38_tcp_handle;
static dissector_handle_t t38_tcp_pdu_handle;
static dissector_handle_t rtp_handle;

static guint32 Type_of_msg_value;
static guint32 Data_Field_field_type_value;
static guint32 Data_value;
static guint32 T30ind_value;

static int proto_t38 = -1;
static int hf_t38_IFPPacket = -1;
static int hf_t38_Type_of_msg = -1;
static int hf_t38_t30_indicator = -1;
static int hf_t38_data = -1;
static int hf_t38_Data_Field = -1;
static int hf_t38_Data_Field_item = -1;
static int hf_t38_Data_Field_field_type = -1;
static int hf_t38_Data_Field_field_data = -1;
static int hf_t38_UDPTLPacket = -1;
static int hf_t38_seq_number = -1;
static int hf_t38_primary_ifp_packet = -1;
static int hf_t38_primary_ifp_packet_length = -1;
static int hf_t38_error_recovery = -1;
static int hf_t38_secondary_ifp_packets = -1;
static int hf_t38_secondary_ifp_packets_item = -1;
static int hf_t38_secondary_ifp_packets_item_length = -1;
static int hf_t38_fec_info = -1;
static int hf_t38_fec_npackets = -1;
static int hf_t38_fec_data = -1;
static int hf_t38_fec_data_item = -1;

/* T38 setup fields */
static int hf_t38_setup        = -1;
static int hf_t38_setup_frame  = -1;
static int hf_t38_setup_method = -1;

static gint ett_t38 = -1;
static gint ett_t38_IFPPacket = -1;
static gint ett_t38_Type_of_msg = -1;
static gint ett_t38_t30_indicator = -1;
static gint ett_t38_data = -1;
static gint ett_t38_Data_Field = -1;
static gint ett_t38_Data_Field_item = -1;
static gint ett_t38_Data_Field_field_type = -1;
static gint ett_t38_UDPTLPacket = -1;
static gint ett_t38_error_recovery = -1;
static gint ett_t38_secondary_ifp_packets = -1;
static gint ett_t38_fec_info = -1;
static gint ett_t38_fec_data = -1;
static gint ett_t38_setup = -1;

static gboolean primary_part = TRUE;
static guint32 seq_number = 0;

/* RTP Version is the first 2 bits of the first octet in the UDP payload*/
#define RTP_VERSION(octet)	((octet) >> 6)

void proto_reg_handoff_t38(void);

static void show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
/* Preferences bool to control whether or not setup info should be shown */
static gboolean global_t38_show_setup_info = TRUE;

/* Set up an T38 conversation */
void t38_add_address(packet_info *pinfo,
                     address *addr, int port,
                     int other_port,
                     const gchar *setup_method, guint32 setup_frame_number)
{
        address null_addr;
        conversation_t* p_conv;
        struct _t38_conversation_info *p_conv_data = NULL;

        /*
         * If this isn't the first time this packet has been processed,
         * we've already done this work, so we don't need to do it
         * again.
         */
        if (pinfo->fd->flags.visited)
        {
                return;
        }

        SET_ADDRESS(&null_addr, AT_NONE, 0, NULL);

        /*
         * Check if the ip address and port combination is not
         * already registered as a conversation.
         */
        p_conv = find_conversation( setup_frame_number, addr, &null_addr, PT_UDP, port, other_port,
                                NO_ADDR_B | (!other_port ? NO_PORT_B : 0));

        /*
         * If not, create a new conversation.
         */
        if ( !p_conv || p_conv->setup_frame != setup_frame_number) {
                p_conv = conversation_new( setup_frame_number, addr, &null_addr, PT_UDP,
                                           (guint32)port, (guint32)other_port,
                                                                   NO_ADDR2 | (!other_port ? NO_PORT2 : 0));
        }

        /* Set dissector */
        conversation_set_dissector(p_conv, t38_udp_handle);

        /*
         * Check if the conversation has data associated with it.
         */
        p_conv_data = conversation_get_proto_data(p_conv, proto_t38);

        /*
         * If not, add a new data item.
         */
        if ( ! p_conv_data ) {
                /* Create conversation data */
                p_conv_data = se_alloc(sizeof(struct _t38_conversation_info));

                conversation_add_proto_data(p_conv, proto_t38, p_conv_data);
        }

        /*
         * Update the conversation data.
         */
        strncpy(p_conv_data->method, setup_method, MAX_T38_SETUP_METHOD_SIZE);
        p_conv_data->method[MAX_T38_SETUP_METHOD_SIZE] = '\0';
        p_conv_data->frame_number = setup_frame_number;
}


static int
dissect_t38_NULL(tvbuff_t *tvb _U_, int offset, packet_info *pinfo _U_, proto_tree *tree _U_)
{
	return offset;
}

static const per_choice_t t30_indicator_choice[] = {
	{ 0, "no-signal", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 1, "cng", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 2, "ced", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 3, "v21-preamble", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 4, "v27-2400-training", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 5, "v27-4800-training", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 6, "v29-7200-training", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 7, "v29-9600-training", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 8, "v17-7200-short-training", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 9, "v17-7200-long-training", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 10, "v17-9600-short-training", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 11, "v17-9600-long-training", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 12, "v17-12000-short-training", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 13, "v17-12000-long-training", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 14, "v17-14400-short-training", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 15, "v17-14400-long-training", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 16, "v8-ansam", ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 17, "v8-signal", ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 18, "v34-cntl-channel-1200", ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 19, "v34-pri-channel", ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 20, "v34-CC-retrain", ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 21, "v33-12000-training", ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 22, "v33-14400-training", ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 0, NULL, 0, NULL }
};

static const value_string t30_indicator_vals[] = {
	{ 0, "no-signal" },
	{ 1, "cng" },
	{ 2, "ced" },
	{ 3, "v21-preamble" },
	{ 4, "v27-2400-training" },
	{ 5, "v27-4800-training" },
	{ 6, "v29-7200-training" },
	{ 7, "v29-9600-training" },
	{ 8, "v17-7200-short-training" },
	{ 9, "v17-7200-long-training" },
	{ 10, "v17-9600-short-training" },
	{ 11, "v17-9600-long-training" },
	{ 12, "v17-12000-short-training" },
	{ 13, "v17-12000-long-training" },
	{ 14, "v17-14400-short-training" },
	{ 15, "v17-14400-long-training" },
    { 16, "v8-ansam" },
    { 17, "v8-signal" },
    { 18, "v34-cntl-channel-1200" },
    { 19, "v34-pri-channel" },
    { 20, "v34-CC-retrain" },
    { 21, "v33-12000-training" },
    { 22, "v33-14400-training" },
	{ 0, NULL },
};

static int
dissect_t38_t30_indicator(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    offset=dissect_per_choice(tvb, offset, pinfo,
        tree, hf_t38_t30_indicator, ett_t38_t30_indicator,
        t30_indicator_choice, "T30 Indicator", &T30ind_value);

	if (check_col(pinfo->cinfo, COL_INFO) && primary_part){
        col_append_fstr(pinfo->cinfo, COL_INFO, " t30ind: %s",
         val_to_str(T30ind_value,t30_indicator_vals,"<unknown>"));
	}
	return offset;
}

static const per_choice_t data_choice[] = {
	{ 0, "v21", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 1, "v27-2400", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 2, "v27-4800", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 3, "v29-7200", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 4, "v29-9600", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 5, "v17-7200", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 6, "v17-9600", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 7, "v17-12000", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 8, "v17-14400", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 9, "v8", ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 10, "v34-pri-rate", ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 11, "v34-CC-1200", ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 12, "v34-pri-ch", ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 13, "v33-12000", ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 14, "v33-14400", ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 0, NULL, 0, NULL }
};

static const value_string data_vals[] = {
	{ 0, "v21" },
	{ 1, "v27-2400" },
	{ 2, "v27-4800" },
	{ 3, "v29-7200" },
	{ 4, "v29-9600" },
	{ 5, "v17-7200" },
	{ 6, "v17-9600" },
	{ 7, "v17-12000" },
	{ 8, "v17-14400" },
	{ 9, "v8" },
	{ 10, "v34-pri-rate" },
	{ 11, "v34-CC-1200" },
	{ 12, "v34-pri-ch" },
	{ 13, "v33-12000" },
	{ 14, "v33-14400" },
	{ 0, NULL },
};

static int
dissect_t38_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    offset=dissect_per_choice(tvb, offset, pinfo,
        tree, hf_t38_data, ett_t38_data,
        data_choice, "data", &Data_value);

    if (check_col(pinfo->cinfo, COL_INFO) && primary_part){
        col_append_fstr(pinfo->cinfo, COL_INFO, " data:%s:",
         val_to_str(Data_value,data_vals,"<unknown>"));
	}
	return offset;
}

static const per_choice_t Type_of_msg_choice[] = {
	{ 0, "t30-indicator", ASN1_NO_EXTENSIONS,
		dissect_t38_t30_indicator},
	{ 1, "data", ASN1_NO_EXTENSIONS,
		dissect_t38_data},
	{ 0, NULL, 0, NULL }
};

static const value_string Type_of_msg_vals[] = {
	{ 0, "t30-indicator" },
	{ 1, "data" },
    { 0, NULL}
};
static int
dissect_t38_Type_of_msg(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                              ett_t38_Type_of_msg, Type_of_msg_choice, "Type_of_msg",
                              &Type_of_msg_value);

  return offset;
}

static int dissect_type_of_msg(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_t38_Type_of_msg(tvb, offset, pinfo, tree, hf_t38_Type_of_msg);
}

static const per_choice_t Data_Field_field_type_PreCorrigendum_choice[] = {
	{ 0, "hdlc-data", ASN1_NO_EXTENSIONS,
		dissect_t38_NULL},
	{ 1, "hdlc-sig-end", ASN1_NO_EXTENSIONS,
		dissect_t38_NULL},
	{ 2, "hdlc-fcs-OK", ASN1_NO_EXTENSIONS,
		dissect_t38_NULL},
	{ 3, "hdlc-fcs-BAD", ASN1_NO_EXTENSIONS,
		dissect_t38_NULL},
	{ 4, "hdlc-fcs-OK-sig-end", ASN1_NO_EXTENSIONS,
		dissect_t38_NULL},
	{ 5, "hdlc-fcs-BAD-sig-end", ASN1_NO_EXTENSIONS,
		dissect_t38_NULL},
	{ 6, "t4-non-ecm-data", ASN1_NO_EXTENSIONS,
		dissect_t38_NULL},
	{ 7, "t4-non-ecm-sig-end", ASN1_NO_EXTENSIONS,
		dissect_t38_NULL},
	{ 0, NULL, 0, NULL }
};


static const per_choice_t Data_Field_field_type_choice[] = {
	{ 0, "hdlc-data", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 1, "hdlc-sig-end", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 2, "hdlc-fcs-OK", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 3, "hdlc-fcs-BAD", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 4, "hdlc-fcs-OK-sig-end", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 5, "hdlc-fcs-BAD-sig-end", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 6, "t4-non-ecm-data", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 7, "t4-non-ecm-sig-end", ASN1_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 8, "cm-message", ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 9, "jm-message", ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 10, "ci-message", ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 11, "v34-rate", ASN1_NOT_EXTENSION_ROOT,
		dissect_t38_NULL},
	{ 0, NULL, 0, NULL }
};


static const value_string Data_Field_field_type_vals[] = {
	{ 0, "hdlc-data" },
	{ 1, "hdlc-sig-end" },
	{ 2, "hdlc-fcs-OK" },
	{ 3, "hdlc-fcs-BAD" },
	{ 4, "hdlc-fcs-OK-sig-end" },
	{ 5, "hdlc-fcs-BAD-sig-end" },
	{ 6, "t4-non-ecm-data" },
	{ 7, "t4-non-ecm-sig-end" },
	{ 8, "cm-message" },
	{ 9, "jm-message" },
	{ 10, "ci-message" },
	{ 11, "v34-rate" },
	{ 0, NULL },
};

static int
dissect_t38_Data_Field_field_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	if(use_pre_corrigendum_asn1_specification){
		offset=dissect_per_choice(tvb, offset, pinfo,
			tree, hf_t38_Data_Field_field_type, ett_t38_Data_Field_field_type,
			Data_Field_field_type_PreCorrigendum_choice, "Field Type", &Data_Field_field_type_value);
	}
	else{
		offset=dissect_per_choice(tvb, offset, pinfo,
			tree, hf_t38_Data_Field_field_type, ett_t38_Data_Field_field_type,
			Data_Field_field_type_choice, "Field Type", &Data_Field_field_type_value);
	}

    if (check_col(pinfo->cinfo, COL_INFO) && primary_part){
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
         val_to_str(Data_Field_field_type_value,Data_Field_field_type_vals,"<unknown>"));
	}

    return offset;
}

static int
dissect_t38_Data_Field_field_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *value_tvb = NULL;
	guint32 value_len;

	offset=dissect_per_octet_string(tvb, offset, pinfo,
        tree, hf_t38_Data_Field_field_data, 1, 65535,
        &value_tvb);
	value_len = tvb_length(value_tvb);

	if (check_col(pinfo->cinfo, COL_INFO) && primary_part){
        if(value_len < 8){
        	col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]",
               tvb_bytes_to_str(value_tvb,0,value_len));
        }
        else {
        	col_append_fstr(pinfo->cinfo, COL_INFO, "[%s...]",
               tvb_bytes_to_str(value_tvb,0,7));
        }
	}
	return offset;
}

static const per_sequence_t Data_Field_item_sequence[] = {
	{ "field-type", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_t38_Data_Field_field_type },
	{ "field-data", ASN1_NO_EXTENSIONS, ASN1_OPTIONAL,
		dissect_t38_Data_Field_field_data },
	{ NULL, 0, 0, NULL }
};

static int
dissect_t38_Data_Field_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo,
        tree, hf_t38_Data_Field_item, ett_t38_Data_Field_item,
        Data_Field_item_sequence);
	return offset;
}

static const per_sequence_t t38_Data_Field_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t38_Data_Field_item },
};

static int
dissect_t38_Data_Field(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                      ett_t38_Data_Field, t38_Data_Field_sequence_of);

  return offset;
}
static int dissect_data_field(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_t38_Data_Field(tvb, offset, pinfo, tree, hf_t38_Data_Field);
}

static const per_sequence_t IFPPacket_sequence[] = {
  { "type-of-msg"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_type_of_msg },
  { "data-field"                  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_data_field },
  { NULL, 0, 0, NULL }
};

static int
dissect_t38_IFPPacket(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo,
        tree, hf_t38_IFPPacket, ett_t38_IFPPacket,
        IFPPacket_sequence);
	return offset;
}

static int
dissect_t38_seq_number(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_constrained_integer(tvb, offset, pinfo,
		tree, hf_t38_seq_number, 0, 65535,
		&seq_number, NULL, FALSE);

      if (check_col(pinfo->cinfo, COL_INFO)){
        col_append_fstr(pinfo->cinfo, COL_INFO, "Seq=%05u ",seq_number);
	}
	return offset;
}

static int
dissect_t38_primary_ifp_packet(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    guint32 length;
	primary_part = TRUE;

    offset=dissect_per_length_determinant(tvb, offset, pinfo,
        tree, hf_t38_primary_ifp_packet_length, &length);
    offset=dissect_t38_IFPPacket(tvb, offset, pinfo, tree);
	return offset;
}

static int
dissect_t38_secondary_ifp_packets_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    guint32 length;

    offset=dissect_per_length_determinant(tvb, offset, pinfo,
        tree, hf_t38_secondary_ifp_packets_item_length, &length);
    offset=dissect_t38_IFPPacket(tvb, offset, pinfo, tree);
	return offset;
}

static const per_sequence_t SEQUENCE_OF_t38_secondary_ifp_packets_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t38_secondary_ifp_packets_item },
};

static int
dissect_t38_secondary_ifp_packets(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    /* When the field-data is not present, we MUST offset 1 byte*/
    if((Data_Field_field_type_value != 0) &&
       (Data_Field_field_type_value != 6))
    {
        offset=offset+8;
    }

    offset=dissect_per_sequence_of(tvb, offset, pinfo,
        tree, hf_t38_secondary_ifp_packets, ett_t38_secondary_ifp_packets,
        SEQUENCE_OF_t38_secondary_ifp_packets_sequence_of);
	return offset;
}

static int
dissect_t38_fec_npackets(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    offset=dissect_per_integer(tvb, offset, pinfo,
        tree, hf_t38_fec_npackets,
        NULL, NULL);
	return offset;
}

static int
dissect_t38_fec_data_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    offset=dissect_per_octet_string(tvb, offset, pinfo,
        tree, hf_t38_fec_data_item, -1, -1,
        NULL);
	return offset;
}
static const per_sequence_t T_t38_fec_data_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_t38_fec_data_item },
};
static int
dissect_t38_fec_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    offset=dissect_per_sequence_of(tvb, offset, pinfo,
        tree, hf_t38_fec_data, ett_t38_fec_data,
        T_t38_fec_data_sequence_of);
	return offset;
}

static const per_sequence_t fec_info_sequence[] = {
	{ "fec-npackets", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_t38_fec_npackets },
	{ "fec-data", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_t38_fec_data },
	{ NULL, 0, 0, NULL }
};

static int
dissect_t38_fec_info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence(tvb, offset, pinfo,
        tree, hf_t38_fec_info, ett_t38_fec_info,
        fec_info_sequence);
	return offset;
}

static const per_choice_t error_recovery_choice[] = {
	{ 0, "secondary-ifp-packets", ASN1_NO_EXTENSIONS,
		dissect_t38_secondary_ifp_packets},
	{ 1, "fec-info", ASN1_NO_EXTENSIONS,
		dissect_t38_fec_info},
	{ 0, NULL, 0, NULL }
};

static const value_string error_recovery_vals[] = {
	{ 0, "secondary-ifp-packets" },
	{ 1, "fec-info" },
    { 0, NULL}
};

static int
dissect_t38_error_recovery(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	primary_part = FALSE;

    offset=dissect_per_choice(tvb, offset, pinfo,
        tree, hf_t38_error_recovery, ett_t38_error_recovery,
        error_recovery_choice, "Error recovery", NULL);

	primary_part = TRUE;

	return offset;
}

static const per_sequence_t UDPTLPacket_sequence[] = {
	{ "seq-number", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_t38_seq_number },
	{ "primary-ifp-packet", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_t38_primary_ifp_packet },
	{ "error-recovery", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_t38_error_recovery },
	{ NULL, 0, 0, NULL }
};

static int
dissect_t38_UDPTLPacket(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    /* Initialize to something else than data type */
    Data_Field_field_type_value = 1;

	offset=dissect_per_sequence(tvb, offset, pinfo,
        tree, hf_t38_UDPTLPacket, ett_t38_UDPTLPacket,
        UDPTLPacket_sequence);
    return offset;
}

/* Entry point for dissection */
static void
dissect_t38_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 octet1;
	proto_item *it;
	proto_tree *tr;
	guint32 offset=0;

	/*
	 * XXX - heuristic to check for misidentified packets.
	 */
	if(dissect_possible_rtpv2_packets_as_rtp){
		octet1 = tvb_get_guint8( tvb, offset );
		if(RTP_VERSION(octet1) == 2){
			call_dissector(rtp_handle,tvb,pinfo,tree);
			return;
		}
	}

	if (check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "T.38");
	}
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_clear(pinfo->cinfo, COL_INFO);
	}

	primary_part = TRUE;

	it=proto_tree_add_protocol_format(tree, proto_t38, tvb, 0, -1,
	    "ITU-T Recommendation T.38");
	tr=proto_item_add_subtree(it, ett_t38);

        /* Conversation setup info */
        if (global_t38_show_setup_info)
        {
                show_setup_info(tvb, pinfo, tr);
        }

	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, "UDP: UDPTLPacket ");
	}

	offset=dissect_t38_UDPTLPacket(tvb, offset, pinfo, tr);

	if(offset&0x07){
		offset=(offset&0xfffffff8)+8;
	}
	if(tvb_length_remaining(tvb,offset>>3)>0){
		if(tr){
			proto_tree_add_text(tr, tvb, offset, tvb_reported_length_remaining(tvb, offset),
				"[MALFORMED PACKET or wrong preference settings]");
		}
		if (check_col(pinfo->cinfo, COL_INFO)){
			col_append_fstr(pinfo->cinfo, COL_INFO, " [Malformed?]");
		}
	}
}

static void
dissect_t38_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *it;
	proto_tree *tr;
	guint32 offset=0;
	guint16 ifp_packet_number=1;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "T.38");
	}
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_clear(pinfo->cinfo, COL_INFO);
	}

	it=proto_tree_add_protocol_format(tree, proto_t38, tvb, 0, -1,
	    "ITU-T Recommendation T.38");
	tr=proto_item_add_subtree(it, ett_t38);

	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, "TCP: IFPPacket");
	}

	while(tvb_length_remaining(tvb,offset>>3)>0)
	{
		offset=dissect_t38_IFPPacket(tvb, offset, pinfo, tr);
		ifp_packet_number++;

		if(offset&0x07){
			offset=(offset&0xfffffff8)+8;
		}

		if(tvb_length_remaining(tvb,offset>>3)>0){
			if(t38_tpkt_usage == T38_TPKT_ALWAYS){
				if(tr){
					proto_tree_add_text(tr, tvb, offset, tvb_reported_length_remaining(tvb, offset),
						"[MALFORMED PACKET or wrong preference settings]");
				}
				if (check_col(pinfo->cinfo, COL_INFO)){
					col_append_fstr(pinfo->cinfo, COL_INFO, " [Malformed?]");
				}
				break;
			} 
			else {
				if (check_col(pinfo->cinfo, COL_INFO)){
					col_append_fstr(pinfo->cinfo, COL_INFO, " IFPPacket#%u",ifp_packet_number);
				}
			}
		}
	}

}

static void
dissect_t38_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	primary_part = TRUE;

	if(t38_tpkt_usage == T38_TPKT_ALWAYS){
		dissect_tpkt_encap(tvb,pinfo,tree,t38_tpkt_reassembly,t38_tcp_pdu_handle);
	} 
	else if((t38_tpkt_usage == T38_TPKT_NEVER) || (is_tpkt(tvb,1) == -1)){
		dissect_t38_tcp_pdu(tvb, pinfo, tree);
	} 
	else {
		dissect_tpkt_encap(tvb,pinfo,tree,t38_tpkt_reassembly,t38_tcp_pdu_handle);
	}
}

static void
dissect_t38(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if(pinfo->ipproto == IP_PROTO_TCP)
	{
		dissect_t38_tcp(tvb, pinfo, tree);
	}
	else if(pinfo->ipproto == IP_PROTO_UDP)
	{   
		dissect_t38_udp(tvb, pinfo, tree);
	}
}

/* Look for conversation info and display any setup info found */
void show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        /* Conversation and current data */
        conversation_t *p_conv = NULL;
        struct _t38_conversation_info *p_conv_data = NULL;

        /* Use existing packet info if available */
        p_conv_data = p_get_proto_data(pinfo->fd, proto_t38);

        if (!p_conv_data)
        {
                /* First time, get info from conversation */
                p_conv = find_conversation(pinfo->fd->num, &pinfo->net_src, &pinfo->net_dst,
                                   pinfo->ptype,
                                   pinfo->srcport, pinfo->destport, NO_ADDR_B);
                if (p_conv)
                {
                        /* Create space for packet info */
                        struct _t38_conversation_info *p_conv_packet_data;
                        p_conv_data = conversation_get_proto_data(p_conv, proto_t38);

                        if (p_conv_data) {
                                /* Save this conversation info into packet info */
                                p_conv_packet_data = se_alloc(sizeof(struct _t38_conversation_info));
                                strcpy(p_conv_packet_data->method, p_conv_data->method);
                                p_conv_packet_data->frame_number = p_conv_data->frame_number;
                                p_add_proto_data(pinfo->fd, proto_t38, p_conv_packet_data);
                        }
                }
        }

        /* Create setup info subtree with summary info. */
        if (p_conv_data)
        {
                proto_tree *t38_setup_tree;
                proto_item *ti =  proto_tree_add_string_format(tree, hf_t38_setup, tvb, 0, 0,
                                                               "",
                                                               "Stream setup by %s (frame %u)",
                                                               p_conv_data->method,
                                                               p_conv_data->frame_number);
                PROTO_ITEM_SET_GENERATED(ti);
                t38_setup_tree = proto_item_add_subtree(ti, ett_t38_setup);
                if (t38_setup_tree)
                {
                        /* Add details into subtree */
                        proto_item* item = proto_tree_add_uint(t38_setup_tree, hf_t38_setup_frame,
                                                               tvb, 0, 0, p_conv_data->frame_number);
                        PROTO_ITEM_SET_GENERATED(item);
                        item = proto_tree_add_string(t38_setup_tree, hf_t38_setup_method,
                                                     tvb, 0, 0, p_conv_data->method);
                        PROTO_ITEM_SET_GENERATED(item);
                }
        }
}



/* Ethereal Protocol Registration */
void
proto_register_t38(void)
{
	static hf_register_info hf[] =
	{
        {  &hf_t38_IFPPacket,
            { "IFPPacket", "t38.IFPPacket", FT_NONE, BASE_NONE,
		      NULL, 0, "IFPPacket sequence", HFILL }},
        {  &hf_t38_Type_of_msg,
            { "Type of msg", "t38.Type_of_msg_type", FT_UINT32, BASE_DEC,
		      VALS(Type_of_msg_vals), 0, "Type_of_msg choice", HFILL }},
        {  &hf_t38_t30_indicator,
            { "T30 indicator", "t38.t30_indicator", FT_UINT32, BASE_DEC,
              VALS(t30_indicator_vals), 0, "t30_indicator", HFILL }},
        {  &hf_t38_data,
            { "data", "t38.t38_data", FT_UINT32, BASE_DEC,
              VALS(data_vals), 0, "data", HFILL }},
        {  &hf_t38_Data_Field,
            { "Data Field", "t38.Data_Field", FT_NONE, BASE_NONE,
              NULL, 0, "Data_Field sequence of", HFILL }},
        {  &hf_t38_Data_Field_item,
            { "Data_Field_item", "t38.Data_Field_item", FT_NONE, BASE_NONE,
              NULL, 0, "Data_Field_item sequence", HFILL }},
        {  &hf_t38_Data_Field_field_type,
            { "Data_Field_field_type", "t38.Data_Field_field_type", FT_UINT32, BASE_DEC,
              VALS(Data_Field_field_type_vals), 0, "Data_Field_field_type choice", HFILL }},
        {  &hf_t38_Data_Field_field_data,
            { "Data_Field_field_data", "t38.Data_Field_field_data", FT_BYTES, BASE_HEX,
            NULL, 0, "Data_Field_field_data octet string", HFILL }},
        {  &hf_t38_UDPTLPacket,
            { "UDPTLPacket", "t38.UDPTLPacket", FT_NONE, BASE_NONE,
		      NULL, 0, "UDPTLPacket sequence", HFILL }},
        {  &hf_t38_seq_number,
            { "Sequence number", "t38.seq_number", FT_UINT32, BASE_DEC,
		      NULL, 0, "seq_number", HFILL }},
        {  &hf_t38_primary_ifp_packet,
            { "Primary IFPPacket", "t38.primary_ifp_packet", FT_BYTES, BASE_HEX,
              NULL, 0, "primary_ifp_packet octet string", HFILL }},
        {  &hf_t38_primary_ifp_packet_length,
            { "primary_ifp_packet_length", "t38.primary_ifp_packet_length", FT_UINT32, BASE_DEC,
            NULL, 0, "primary_ifp_packet_length", HFILL }},
        {  &hf_t38_error_recovery,
            { "Error recovery", "t38.error_recovery", FT_UINT32, BASE_DEC,
		      VALS(error_recovery_vals), 0, "error_recovery choice", HFILL }},
        {  &hf_t38_secondary_ifp_packets,
            { "Secondary IFPPackets", "t38.secondary_ifp_packets", FT_NONE, BASE_NONE,
              NULL, 0, "secondary_ifp_packets sequence of", HFILL }},
        {  &hf_t38_secondary_ifp_packets_item,
            { "Secondary IFPPackets item", "t38.secondary_ifp_packets_item", FT_BYTES, BASE_HEX,
              NULL, 0, "secondary_ifp_packets_item octet string", HFILL }},
        {  &hf_t38_secondary_ifp_packets_item_length,
            { "secondary_ifp_packets_item_length", "t38.secondary_ifp_packets_item_length", FT_UINT32, BASE_DEC,
            NULL, 0, "secondary_ifp_packets_item_length", HFILL }},
        {  &hf_t38_fec_info,
            { "Fec info", "t38.fec_info", FT_NONE, BASE_NONE,
		      NULL, 0, "fec_info sequence", HFILL }},
        {  &hf_t38_fec_npackets,
            { "Fec npackets", "h245.fec_npackets", FT_INT32, BASE_DEC,
              NULL, 0, "fec_npackets value", HFILL }},
        {  &hf_t38_fec_data,
            { "Fec data", "t38.fec_data", FT_NONE, BASE_NONE,
              NULL, 0, "fec_data sequence of", HFILL }},
        {  &hf_t38_fec_data_item,
            { "t38_fec_data_item", "t38.t38_fec_data_item", FT_BYTES, BASE_HEX,
            NULL, 0, "t38_fec_data_item octet string", HFILL }},
	{   &hf_t38_setup,
	    { "Stream setup", "t38.setup", FT_STRING, BASE_NONE,
	    NULL, 0x0, "Stream setup, method and frame number", HFILL }},
	{   &hf_t38_setup_frame,
            { "Stream frame", "t38.setup-frame", FT_FRAMENUM, BASE_NONE,
            NULL, 0x0, "Frame that set up this stream", HFILL }},
        {   &hf_t38_setup_method,
            { "Stream Method", "t38.setup-method", FT_STRING, BASE_NONE,
            NULL, 0x0, "Method used to set up this stream", HFILL }},
        };

	static gint *ett[] =
	{
		&ett_t38,
		&ett_t38_IFPPacket,
		&ett_t38_Type_of_msg,
		&ett_t38_t30_indicator,
		&ett_t38_data,
		&ett_t38_Data_Field,
		&ett_t38_Data_Field_item,
		&ett_t38_Data_Field_field_type,
		&ett_t38_UDPTLPacket,
		&ett_t38_error_recovery,
		&ett_t38_secondary_ifp_packets,
		&ett_t38_fec_info,
		&ett_t38_fec_data,
		&ett_t38_setup,
	};
	module_t *t38_module;

	proto_t38 = proto_register_protocol("T.38", "T.38", "t38");
	proto_register_field_array(proto_t38, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("t38", dissect_t38, proto_t38);

	t38_module = prefs_register_protocol(proto_t38, proto_reg_handoff_t38);
	prefs_register_bool_preference(t38_module, "use_pre_corrigendum_asn1_specification",
	    "Use the Pre-Corrigendum ASN.1 specification",
	    "Whether the T.38 dissector should decode using the Pre-Corrigendum T.38 "
		"ASN.1 specification (1998).",
	    &use_pre_corrigendum_asn1_specification);
	prefs_register_bool_preference(t38_module, "dissect_possible_rtpv2_packets_as_rtp",
	    "Dissect possible RTP version 2 packets with RTP dissector",
	    "Whether a UDP packet that looks like RTP version 2 packet will "
		"be dissected as RTP packet or T.38 packet. If enabled there is a risk that T.38 UDPTL "
		"packets with sequence number higher than 32767 may be dissected as RTP.",
	    &dissect_possible_rtpv2_packets_as_rtp);
	prefs_register_uint_preference(t38_module, "tcp.port",
		"T.38 TCP Port",
		"Set the TCP port for T.38 messages",
		10, &global_t38_tcp_port);
	prefs_register_uint_preference(t38_module, "udp.port",
		"T.38 UDP Port",
		"Set the UDP port for T.38 messages",
		10, &global_t38_udp_port);	
	prefs_register_bool_preference(t38_module, "reassembly",
		"Reassemble T.38 PDUs over TPKT over TCP",
		"Whether the dissector should reassemble T.38 PDUs spanning multiple TCP segments "
		"when TPKT is used over TCP. "
        "To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
		&t38_tpkt_reassembly);
	prefs_register_enum_preference(t38_module, "tpkt_usage",
		"TPKT used over TCP",
		"Whether T.38 is used with TPKT for TCP",
		(gint *)&t38_tpkt_usage,t38_tpkt_options,FALSE);

	prefs_register_bool_preference(t38_module, "show_setup_info",
                "Show stream setup information",
                "Where available, show which protocol and frame caused "
                "this T.38 stream to be created",
                &global_t38_show_setup_info);

}

void
proto_reg_handoff_t38(void)
{
	static int t38_prefs_initialized = FALSE;

	if (!t38_prefs_initialized) {
		t38_udp_handle=create_dissector_handle(dissect_t38_udp, proto_t38);
		t38_tcp_handle=create_dissector_handle(dissect_t38_tcp, proto_t38);
		t38_tcp_pdu_handle=create_dissector_handle(dissect_t38_tcp_pdu, proto_t38);
		t38_prefs_initialized = TRUE;
	}
	else {
		dissector_delete("tcp.port", tcp_port, t38_tcp_handle);
		dissector_delete("udp.port", udp_port, t38_udp_handle);
	}
	tcp_port = global_t38_tcp_port;
	udp_port = global_t38_udp_port;

	dissector_add("tcp.port", tcp_port, t38_tcp_handle);
	dissector_add("udp.port", udp_port, t38_udp_handle);

	rtp_handle = find_dissector("rtp");
}
