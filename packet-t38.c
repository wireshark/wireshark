/* packet-t38.c
 * Routines for T.38 packet dissection
 * 2003  Hans Viens
 *
 * $Id: packet-t38.c,v 1.3 2003/10/09 22:35:07 guy Exp $
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "prefs.h"
#include "ipproto.h"
#include "packet-per.h"

#define PORT_T38 6004

static dissector_handle_t t38_handle;

static guint32 Type_of_msg_value;
static guint32 Data_Field_field_type_value;

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


static int
dissect_t38_NULL(tvbuff_t *tvb _U_, int offset, packet_info *pinfo _U_, proto_tree *tree _U_)
{
	return offset;
}

static per_choice_t t30_indicator_choice[] = {
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
        t30_indicator_choice, "T30 Indicator", NULL);
	return offset;
}

static per_choice_t data_choice[] = {
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
        data_choice, "data", NULL);
	return offset;
}

static per_choice_t Type_of_msg_choice[] = {
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
dissect_t38_Type_of_msg(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_choice(tvb, offset, pinfo,
        tree, hf_t38_Type_of_msg, ett_t38_Type_of_msg,
        Type_of_msg_choice, "Type of message", &Type_of_msg_value);
	return offset;
}

static per_choice_t Data_Field_field_type_choice[] = {
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

static const value_string Data_Field_field_type_vals[] = {
	{ 0, "hdlc-data" },
	{ 1, "hdlc-sig-end" },
	{ 2, "hdlc-fcs-OK" },
	{ 3, "hdlc-fcs-BAD" },
	{ 4, "hdlc-fcs-OK-sig-end" },
	{ 5, "hdlc-fcs-BAD-sig-end" },
	{ 6, "t4-non-ecm-data" },
	{ 7, "t4-non-ecm-sig-end" },
	{ 0, NULL },
};

static int
dissect_t38_Data_Field_field_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    offset=dissect_per_choice(tvb, offset, pinfo,
        tree, hf_t38_Data_Field_field_type, ett_t38_Data_Field_field_type,
        Data_Field_field_type_choice, "Field Type", &Data_Field_field_type_value);
    return offset;
}

static int
dissect_t38_Data_Field_field_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_octet_string(tvb, offset, pinfo,
        tree, hf_t38_Data_Field_field_data, 1, 65535,
        NULL, NULL);
	return offset;
}

static per_sequence_t Data_Field_item_sequence[] = {
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

static int
dissect_t38_Data_Field(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_sequence_of(tvb, offset, pinfo,
        tree, hf_t38_Data_Field, ett_t38_Data_Field,
        dissect_t38_Data_Field_item);
	return offset;
}

static per_sequence_t IFPPacket_sequence[] = {
	{ "type-of-msg", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_t38_Type_of_msg },
	{ "data-field", ASN1_NO_EXTENSIONS, ASN1_OPTIONAL,
		dissect_t38_Data_Field },
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
		NULL, NULL, FALSE);
	return offset;
}

static int
dissect_t38_primary_ifp_packet(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    guint32 length;

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
        dissect_t38_secondary_ifp_packets_item);
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
        NULL, NULL);
	return offset;
}

static int
dissect_t38_fec_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    offset=dissect_per_sequence_of(tvb, offset, pinfo,
        tree, hf_t38_fec_data, ett_t38_fec_data,
        dissect_t38_fec_data_item);
	return offset;
}

static per_sequence_t fec_info_sequence[] = {
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

static per_choice_t error_recovery_choice[] = {
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
    offset=dissect_per_choice(tvb, offset, pinfo,
        tree, hf_t38_error_recovery, ett_t38_error_recovery,
        error_recovery_choice, "Error recovery", NULL);
	return offset;
}

static per_sequence_t UDPTLPacket_sequence[] = {
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
	proto_item *it;
	proto_tree *tr;
    guint32 offset=0;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "T.38");
	}
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_clear(pinfo->cinfo, COL_INFO);
	}

	it=proto_tree_add_protocol_format(tree, proto_t38, tvb, 0, tvb_length(tvb),
        "ITU-T Recommendation T.38");
	tr=proto_item_add_subtree(it, ett_t38);

    offset=dissect_t38_UDPTLPacket(tvb, offset, pinfo, tr);

    if (check_col(pinfo->cinfo, COL_INFO)){
        col_prepend_fstr(pinfo->cinfo, COL_INFO, "UDP: UDPTLPacket");
	}
}

static void
dissect_t38_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *it;
	proto_tree *tr;
    guint32 offset=0;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "T.38");
	}
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_clear(pinfo->cinfo, COL_INFO);
	}

	it=proto_tree_add_protocol_format(tree, proto_t38, tvb, 0, tvb_length(tvb),
        "ITU-T Recommendation T.38");
	tr=proto_item_add_subtree(it, ett_t38);

    offset=dissect_t38_IFPPacket(tvb, offset, pinfo, tr);

    if (check_col(pinfo->cinfo, COL_INFO)){
        col_prepend_fstr(pinfo->cinfo, COL_INFO, "TCP: IFPPacket");
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
	};

	proto_t38 = proto_register_protocol("T38", "T38", "t38");
	proto_register_field_array(proto_t38, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("t38", dissect_t38, proto_t38);
}

void
proto_reg_handoff_t38(void)
{
	t38_handle=create_dissector_handle(dissect_t38, proto_t38);
	dissector_add("udp.port", PORT_T38, t38_handle);
    dissector_add("tcp.port", PORT_T38, t38_handle);
}
